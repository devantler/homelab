#!/usr/bin/env bash
# Refresh the pinned KubeVirt and CDI release bundles without losing the
# repository's resource-scoped Checkov dispositions.
#
# Bump each version and SHA-256 constant below, then run this script from
# anywhere in the repository. A renamed target or a new Checkov finding is a
# hard failure: the updater never replaces the committed bundle until checksum,
# annotation, and scan validation all succeed.
set -euo pipefail

readonly cdi_version='v1.65.0'
readonly cdi_sha256='e96d59abdf358c5161cb96adcfdcc6107efc3fb608ec93ade11578c94a222015'
readonly kubevirt_version='v1.8.0'
readonly kubevirt_sha256='e9e92c15bca0531bf0b7db2c2dfc83b6b9bdbf1a6f3f96945f67d90d702193b5'
# The former render-time remotes use immutable commits as well as byte digests.
readonly origin_ca_issuer_commit='e375d9c00a66f47a15fb56457686f8629022b50d'
readonly clusteroriginissuers_sha256='cf6af6f155cd087a1ab2a4bec68cd014f05be3cf3d0240ad331ee1fe1bec574e'
readonly originissuers_sha256='d085e763718cf34e675b62f8394e20854237b3997f825d86556659585940b170'
readonly cert_approver_version='0.12.0'
readonly cert_approver_commit='b5516301e48f8e50cb18368e457779d01796119b'
readonly cert_approver_sha256='44d74b38379d96572c434290732092f577ee4835392b36922a72c406ee406139'
# The digest the cert-approver kustomization pins its image to (#3515). The vendored bytes name only a
# tag, and a tag can move; this is what production actually pulls. --render-remotes re-resolves the tag
# from the registry and refuses to refresh while this constant disagrees with it.
readonly cert_approver_image_digest='sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45'
# Keep this aligned with CI_CHECKOV_VERSION in megalinter-scan-counts.sh so a
# local vendor refresh cannot miss a rule that the non-blocking CI scan knows.
readonly checkov_version='3.3.2'
# CKV2_K8S_6 only understands networking.k8s.io NetworkPolicy. An isolated
# bundle scan cannot see that cilium-network-policy.yaml protects every CDI
# endpoint; the full-repository CI scan remains unskipped and owns graph checks.
readonly isolated_scan_skip_check='CKV2_K8S_6'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repo_root
readonly render_controllers="${repo_root}/k8s/providers/hetzner/infrastructure/controllers"
work_dir="$(mktemp -d)"
readonly work_dir
trap 'rm -rf "${work_dir}"' EXIT
readonly checkov_home="${work_dir}/checkov-home"
readonly checkov_config="${work_dir}/checkov.yaml"
readonly checkov_secrets_canary="${work_dir}/checkov-secrets-canary.txt"
mkdir -p "${checkov_home}"
printf '{}\n' >"${checkov_config}"
printf 'aws_access_key_id: AKIAQWERTYUIOPASDFGH\n' >"${checkov_secrets_canary}"

# Ignore user/home configuration and CKV_* environment overrides. The updater
# must prove its own explicit policy even when the caller normally soft-fails or
# skips checks in an interactive shell.
run_checkov() {
  env -i \
    HOME="${checkov_home}" \
    LC_ALL=C \
    PATH="${PATH}" \
    PYTHONUTF8=1 \
    checkov --config-file "${checkov_config}" --skip-download "$@"
}

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf '%s is required to update vendored operators\n' "${tool}" >&2
    exit 2
  fi
}

run_clean_framework_scan() {
  local bundle="$1"
  local phase="$2"
  local manifest="$3"
  local framework="$4"
  local report="$5"
  local checkov_rc=0
  local expected_checkov_rc=0
  local -a input_files=("${manifest}")
  local -a validator_args=(--validate-report --framework "${framework}")
  if [ "${framework}" = 'secrets' ]; then
    input_files+=("${checkov_secrets_canary}")
    expected_checkov_rc=1
    validator_args+=(--require-secrets-canary)
  fi
  local -a checkov_args=(
    --file "${input_files[@]}"
    --framework "${framework}"
    --output json
    --quiet
  )
  if [ "${framework}" = 'kubernetes' ]; then
    checkov_args+=(--skip-check "${isolated_scan_skip_check}")
  fi

  run_checkov "${checkov_args[@]}" >"${report}" || checkov_rc=$?
  if [ "${checkov_rc}" -ne "${expected_checkov_rc}" ]; then
    printf 'checkov rejected the %s %s %s scan (exit %d):\n' \
      "${phase}" "${bundle}" "${framework}" "${checkov_rc}" >&2
    while IFS= read -r line; do
      printf '%s\n' "${line}" >&2
    done <"${report}"
    exit 2
  fi
  if ! (
    cd "${repo_root}"
    go run ./scripts/annotate-vendored-checkov --bundle "${bundle}" \
      "${validator_args[@]}" <"${report}"
  ); then
    printf 'checkov report validation rejected the %s %s %s scan:\n' \
      "${phase}" "${bundle}" "${framework}" >&2
    while IFS= read -r line; do
      printf '%s\n' "${line}" >&2
    done <"${report}"
    exit 2
  fi
}

prepare_bundle() {
  local bundle="$1"
  local url="$2"
  local expected_sha256="$3"
  local downloaded="${work_dir}/${bundle}-upstream.yaml"
  local findings="${work_dir}/${bundle}-kubernetes-findings.json"
  local source_secrets_report="${work_dir}/${bundle}-source-secrets-report.json"
  local annotated="${work_dir}/${bundle}-annotated.yaml"
  local annotated_kubernetes_report="${work_dir}/${bundle}-annotated-kubernetes-report.json"
  local annotated_secrets_report="${work_dir}/${bundle}-annotated-secrets-report.json"
  local checkov_rc=0

  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 3 --retry-all-errors "${url}" --output "${downloaded}"
  printf '%s  %s\n' "${expected_sha256}" "${downloaded}" | sha256sum -c -
  (
    cd "${repo_root}"
    go run ./scripts/annotate-vendored-checkov --bundle "${bundle}" \
      --validate-source <"${downloaded}"
  )

  # Prove that every reviewed disposition is still necessary on this exact
  # upstream asset. An upstream security fix makes the update stop here until
  # the obsolete annotation is removed from the configured target list.
  run_checkov --file "${downloaded}" --framework kubernetes \
    --skip-check "${isolated_scan_skip_check}" \
    --output json --quiet >"${findings}" || checkov_rc=$?
  if [ "${checkov_rc}" -gt 1 ]; then
    printf 'checkov could not scan the unannotated %s bundle (exit %d)\n' \
      "${bundle}" "${checkov_rc}" >&2
    exit 2
  fi

  (
    cd "${repo_root}"
    go run ./scripts/annotate-vendored-checkov --bundle "${bundle}" \
      --validate-findings <"${findings}"
    go run ./scripts/annotate-vendored-checkov --bundle "${bundle}" \
      <"${downloaded}" >"${annotated}"
  )
  run_clean_framework_scan \
    "${bundle}" source "${downloaded}" secrets "${source_secrets_report}"

  # The known, reviewed dispositions must clear the current upstream bundle,
  # while any new check introduced by a vendor bump remains visible and blocks
  # replacement until it receives an explicit disposition. Run each framework
  # separately so Checkov cannot silently omit an empty framework report.
  run_clean_framework_scan \
    "${bundle}" annotated "${annotated}" kubernetes "${annotated_kubernetes_report}"
  run_clean_framework_scan \
    "${bundle}" annotated "${annotated}" secrets "${annotated_secrets_report}"
}

validate_committed_bundles() {
  (
    cd "${repo_root}"
    go run ./scripts/annotate-vendored-checkov --bundle cdi --validate-annotated \
      --source-sha256 "${cdi_sha256}" \
      --source-version "${cdi_version}" \
      <k8s/bases/infrastructure/controllers/cdi/cdi-operator.yaml
    go run ./scripts/annotate-vendored-checkov --bundle kubevirt --validate-annotated \
      --source-sha256 "${kubevirt_sha256}" \
      --source-version "${kubevirt_version}" \
      <k8s/bases/infrastructure/controllers/kubevirt/kubevirt-operator.yaml
    go run ./scripts/annotate-vendored-checkov --bundle kubelet-serving-cert-approver \
      --validate-annotated --source-sha256 "${cert_approver_sha256}" \
      --source-version "${cert_approver_version}" \
      --resources-dir "${render_controllers}/kubelet-serving-cert-approver" </dev/null
    scripts/guard-cert-approver-image-pin.sh \
      "${render_controllers}/kubelet-serving-cert-approver/kustomization.yaml" \
      "${cert_approver_version}" "${cert_approver_image_digest}"
    validate_crd "${render_controllers}/origin-ca-issuer/custom-resource-definition-clusteroriginissuers.yaml" "${clusteroriginissuers_sha256}"
    validate_crd "${render_controllers}/origin-ca-issuer/custom-resource-definition-originissuers.yaml" "${originissuers_sha256}"
  )
}

validate_crd() {
  local file="$1" digest="$2"
  printf '%s  %s\n' "${digest}" "${file}" | sha256sum -c -
  (cd "${repo_root}" && go run ./scripts/annotate-vendored-checkov \
    --bundle origin-ca-issuer --validate-source <"${file}")
}

# Resolve what the pinned cert-approver tag points at in the registry NOW, and refuse to refresh when
# it differs from cert_approver_image_digest. A refresh is the moment a new tag is adopted, so this is
# where a tag that moved, or a version bump without its digest, must stop and name the digest to review.
verify_cert_approver_image_digest() {
  local token resolved
  token="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    "https://ghcr.io/token?scope=repository:alex1989hu/kubelet-serving-cert-approver:pull&service=ghcr.io" |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  if [ -z "${token}" ]; then
    printf 'could not obtain a ghcr.io pull token for the cert-approver image\n' >&2
    exit 1
  fi
  resolved="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --head \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://ghcr.io/v2/alex1989hu/kubelet-serving-cert-approver/manifests/${cert_approver_version}" |
    tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p')"
  if [ "${resolved}" != "${cert_approver_image_digest}" ]; then
    printf 'ghcr.io/alex1989hu/kubelet-serving-cert-approver:%s resolves to %s, but cert_approver_image_digest is %s.\n' \
      "${cert_approver_version}" "${resolved:-<nothing>}" "${cert_approver_image_digest}" >&2
    printf 'Review that image, then record its digest here and in the kustomization images: pin.\n' >&2
    exit 1
  fi
}

prepare_render_remotes() {
  local name digest source
  verify_cert_approver_image_digest
  for name in clusteroriginissuers originissuers; do
    if [ "${name}" = clusteroriginissuers ]; then
      digest="${clusteroriginissuers_sha256}"
    else
      digest="${originissuers_sha256}"
    fi
    source="${work_dir}/${name}.yaml"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      --retry 3 --retry-all-errors \
      "https://raw.githubusercontent.com/cloudflare/origin-ca-issuer/${origin_ca_issuer_commit}/deploy/crds/cert-manager.k8s.cloudflare.com_${name}.yaml" \
      --output "${source}"
    validate_crd "${source}" "${digest}"
    # CRDs have no applicable Kubernetes workload/RBAC checks. Require their
    # exact CRD identity and a real secrets-framework scan with its canary.
    run_clean_framework_scan origin-ca-issuer source "${source}" secrets "${work_dir}/${name}-secrets.json"
  done
  prepare_bundle kubelet-serving-cert-approver \
    "https://raw.githubusercontent.com/alex1989hu/kubelet-serving-cert-approver/${cert_approver_commit}/deploy/ha-install.yaml" \
    "${cert_approver_sha256}"
  (cd "${repo_root}" && go run ./scripts/annotate-vendored-checkov \
    --bundle kubelet-serving-cert-approver --validate-annotated \
    --source-sha256 "${cert_approver_sha256}" --source-version "${cert_approver_version}" \
    <"${work_dir}/kubelet-serving-cert-approver-annotated.yaml")
  (cd "${repo_root}" && go run ./scripts/annotate-vendored-checkov \
    --bundle kubelet-serving-cert-approver --split-resources "${work_dir}/cert-approver" \
    <"${work_dir}/kubelet-serving-cert-approver-annotated.yaml")
  # Prove that every expected resource exists and reconstructs the source
  # before replacing any committed file, including on a vendor rename/removal.
  (cd "${repo_root}" && go run ./scripts/annotate-vendored-checkov \
    --bundle kubelet-serving-cert-approver --validate-annotated \
    --source-sha256 "${cert_approver_sha256}" --source-version "${cert_approver_version}" \
    --resources-dir "${work_dir}/cert-approver" </dev/null)
}

install_render_remotes() {
  mv "${work_dir}/clusteroriginissuers.yaml" "${render_controllers}/origin-ca-issuer/custom-resource-definition-clusteroriginissuers.yaml"
  mv "${work_dir}/originissuers.yaml" "${render_controllers}/origin-ca-issuer/custom-resource-definition-originissuers.yaml"
  local resource
  for resource in "${work_dir}/cert-approver/"*.yaml; do
    mv "${resource}" "${render_controllers}/kubelet-serving-cert-approver/"
  done
}

mode=all
if [ "$#" -ne 0 ]; then
  if [ "$#" -eq 1 ] && [ "$1" = '--validate-committed' ]; then
    require_tool go
    require_tool sha256sum
    validate_committed_bundles
    printf 'All committed vendor resources match their pinned upstream digests and versions.\n'
    exit 0
  fi
  if [ "$#" -eq 1 ] && [ "$1" = '--render-remotes' ]; then
    mode=render-remotes
  else
    printf 'usage: %s [--validate-committed|--render-remotes]\n' "$0" >&2
    exit 2
  fi
fi

require_tool curl
require_tool go
require_tool checkov
require_tool sha256sum

actual_checkov_version="$(run_checkov --version)"
readonly actual_checkov_version
if [ "${actual_checkov_version}" != "${checkov_version}" ]; then
  printf 'checkov %s is required; found %s\n' \
    "${checkov_version}" "${actual_checkov_version}" >&2
  exit 2
fi

if [ "${mode}" = all ]; then
  prepare_bundle \
    cdi \
    "https://github.com/kubevirt/containerized-data-importer/releases/download/${cdi_version}/cdi-operator.yaml" \
    "${cdi_sha256}"

  prepare_bundle \
    kubevirt \
    "https://github.com/kubevirt/kubevirt/releases/download/${kubevirt_version}/kubevirt-operator.yaml" \
    "${kubevirt_sha256}"
fi

prepare_render_remotes

# Commit both prepared outputs together only after both upstream bundles pass.
# A failed second download or scan therefore cannot leave a half-updated pair.
if [ "${mode}" = all ]; then
  mv \
    "${work_dir}/cdi-annotated.yaml" \
    "${repo_root}/k8s/bases/infrastructure/controllers/cdi/cdi-operator.yaml"
  mv \
    "${work_dir}/kubevirt-annotated.yaml" \
    "${repo_root}/k8s/bases/infrastructure/controllers/kubevirt/kubevirt-operator.yaml"
fi
install_render_remotes
validate_committed_bundles

printf 'Updated %s vendored resources; digests and applicable Checkov scans passed.\n' "${mode}"
