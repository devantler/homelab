#!/usr/bin/env bash
# Read-only guard for the first source-owned Longhorn UI baseline rollout.
# Already-configured workloads and a source rollback disarm the canary, so it
# does not freeze the chart's replica count or identity on future deployments.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
phase="${1:-}"
[[ $# -gt 0 ]] && shift
context=admin@prod
release="${root_dir}/k8s/providers/hetzner/infrastructure/controllers/longhorn/helm-release.yaml"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --context) context="${2:?context required}"; shift 2 ;;
    --release) release="${2:?release file required}"; shift 2 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "${phase}" in before-publish|after-reconcile) ;; *) exit 2 ;; esac
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
fail() { printf '::error::Longhorn UI baseline canary: %s\n' "$1" >&2; exit 1; }
output() {
  printf 'rollout_required=%s\n' "$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then printf 'rollout_required=%s\n' "$1" >>"${GITHUB_OUTPUT}"; fi
}
read_ui() {
  kubectl --context "${context}" get deployment longhorn-ui --namespace longhorn-system \
    --ignore-not-found -o json --request-timeout=20s >"${scratch}/deployment.json" || fail 'API read failed'
}
has_defaults() {
  jq -e '.spec.template.spec.securityContext.fsGroupChangePolicy == "OnRootMismatch" and
    ([.spec.template.spec.containers[] | .securityContext.seLinuxOptions] == [{}])' \
    "${scratch}/deployment.json" >/dev/null
}
invariants() {
  jq -e '.kind == "Deployment" and .metadata.name == "longhorn-ui" and
    .metadata.namespace == "longhorn-system" and
    .metadata.annotations["meta.helm.sh/release-name"] == "longhorn" and
    .metadata.annotations["meta.helm.sh/release-namespace"] == "longhorn-system" and
    ((.metadata.ownerReferences // []) | length == 0) and
    .spec.replicas == 1 and .status.observedGeneration == .metadata.generation and
    .status.replicas == 1 and .status.updatedReplicas == 1 and
    .status.readyReplicas == 1 and .status.availableReplicas == 1 and
    (.status.terminatingReplicas // 0) == 0 and
    .spec.template.spec.securityContext.fsGroup == null and
    .spec.template.spec.securityContext.runAsNonRoot == true and
    .spec.template.spec.securityContext.runAsUser == 499 and
    .spec.template.spec.securityContext.runAsGroup == 486 and
    .spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault" and
    ((.spec.template.spec.initContainers // []) | length == 0) and
    ([.spec.template.spec.volumes[] | has("emptyDir")] | all) and
    ([.spec.template.spec.containers[] | .name == "longhorn-ui" and
      .securityContext.runAsNonRoot == true and .securityContext.runAsUser == 499 and
      .securityContext.runAsGroup == 486 and .securityContext.allowPrivilegeEscalation == false and
      (.securityContext.privileged // false) == false and
      .securityContext.capabilities.drop == ["ALL"] and
      .securityContext.seccompProfile.type == "RuntimeDefault"] == [true])' \
    "${scratch}/deployment.json" >/dev/null
}

if [[ "${phase}" == before-publish ]]; then
  # A reverted desired patch must not depend on the failed workload to recover.
  yq -o=json '.spec.postRenderers // []' "${release}" >"${scratch}/renderers.json"
  yq -o=json '[.[] | .kustomize.patches[] | select(.target.kind == "Deployment" and
    .target.name == "longhorn-ui") | .patch | from_yaml]' "${scratch}/renderers.json" >"${scratch}/patches.json"
  if ! configured="$(jq -r 'any(.[]; .spec.template.spec.securityContext.fsGroupChangePolicy == "OnRootMismatch" and
      any(.spec.template.spec.containers[]?; .name == "longhorn-ui" and .securityContext.seLinuxOptions == {}))' \
    "${scratch}/patches.json")"; then
    fail 'desired canary patch is malformed'
  fi
  if [[ "${configured}" == false ]]; then
    output false
    exit 0
  fi
  read_ui
  if [[ -s "${scratch}/deployment.json" ]] && has_defaults; then
    output false
    exit 0
  fi
  # Reachable API + NotFound means initial installation. Post-proof is mandatory.
  if [[ -s "${scratch}/deployment.json" ]]; then
    invariants || fail 'existing UI is unhealthy or outside the reviewed ephemeral, non-root canary scope'
  fi
  output true
  exit 0
fi

# Flux has reported the released revision Ready. Allow bounded old-pod cleanup,
# then require consecutive stable observations of the stored, ready template.
ready=false
for ((attempt = 0; attempt < 12; attempt++)); do
  read_ui
  if [[ -s "${scratch}/deployment.json" ]] && invariants && has_defaults; then
    ready=true
    break
  fi
  sleep 5
done
[[ "${ready}" == true ]] || fail 'new UI defaults and a complete healthy rollout were not observed'
generation="$(jq -r '.metadata.generation' "${scratch}/deployment.json")"
version="$(jq -r '.metadata.resourceVersion' "${scratch}/deployment.json")"
write_changes=0
for ((sample = 0; sample < 3; sample++)); do
  sleep 10
  read_ui
  if ! invariants || ! has_defaults; then
    fail 'UI lost readiness or a security invariant during observation'
  fi
  [[ "$(jq -r '.metadata.generation' "${scratch}/deployment.json")" == "${generation}" ]] ||
    fail 'owner rewrote the UI template during observation'
  next_version="$(jq -r '.metadata.resourceVersion' "${scratch}/deployment.json")"
  if [[ "${next_version}" != "${version}" ]]; then
    write_changes=$((write_changes + 1))
    version="${next_version}"
  fi
  [[ "${write_changes}" -lt 2 ]] || fail 'repeated owner writes continued during observation'
done
printf 'PASS: Longhorn UI source defaults are stored, ready, and stable; generation=%s\n' "${generation}"
