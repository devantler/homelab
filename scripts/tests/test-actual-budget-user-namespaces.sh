#!/usr/bin/env bash

# Exercise the deployed chart and every Flux post-renderer. A HelmRelease-only
# assertion cannot detect a chart value that never reaches its pod template.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
scratch_dir="$(mktemp -d)"
readonly scratch_dir
trap 'rm -rf "${scratch_dir}"' EXIT

# Print the supplied failure message to stderr and stop the regression.
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

for tool in kubectl yq jq helm; do
  command -v "${tool}" >/dev/null || fail "${tool} is required"
done

cp -R "${root_dir}/k8s" "${scratch_dir}/k8s"
readonly apps_dir="${scratch_dir}/k8s/providers/hetzner/apps"
readonly component='actual-budget/components/user-namespaces'

# Render the overlay directory in $1 to a sorted JSON resource array at $2.
render_overlay() {
  kubectl kustomize "$1" | yq ea -o=json '[.]' | jq -S . >"$2"
}

# Write the Actual Budget HelmRelease from resource array $1 to file $2.
# Fail when the overlay does not contain the expected release.
extract_release() {
  jq -e '.[] | select(.kind == "HelmRelease" and
    .metadata.namespace == "actual-budget" and .metadata.name == "actual-budget")' "$1" >"$2"
}

render_overlay "${apps_dir}" "${scratch_dir}/off.json"
render_overlay "${scratch_dir}/k8s/providers/docker/apps" "${scratch_dir}/local-before.json"
extract_release "${scratch_dir}/off.json" "${scratch_dir}/off-release.json"
jq -e '[.[] | select(.kind == "Namespace" and .metadata.name == "actual-budget") |
  .metadata.labels["pod-security.devantler.tech/user-namespaces"]] == [null]' \
  "${scratch_dir}/off.json" >/dev/null || fail 'production must keep the pilot disabled'

COMPONENT="${component}" yq -i '.components += [strenv(COMPONENT)]' "${apps_dir}/kustomization.yaml"
render_overlay "${apps_dir}" "${scratch_dir}/on.json"
extract_release "${scratch_dir}/on.json" "${scratch_dir}/on-release.json"
jq -e '[.[] | select(.kind == "Namespace" and .metadata.name == "actual-budget") |
  .metadata.labels["pod-security.devantler.tech/user-namespaces"]] == ["enabled"]' \
  "${scratch_dir}/on.json" >/dev/null || fail 'opt-in must enable the namespace enforcement policy'

# The complete overlay may differ only by this namespace label and one appended
# post-renderer on this release. This catches collateral changes to other apps,
# storage declarations, security contexts, or existing authentication patches.
jq -S 'map(if .kind == "Namespace" and .metadata.name == "actual-budget" then
    del(.metadata.labels["pod-security.devantler.tech/user-namespaces"])
  elif .kind == "HelmRelease" and .metadata.namespace == "actual-budget" and
      .metadata.name == "actual-budget" then
    .spec.postRenderers |= .[:-1]
  else . end)' "${scratch_dir}/on.json" >"${scratch_dir}/normalized.json"
diff -u "${scratch_dir}/off.json" "${scratch_dir}/normalized.json" ||
  fail 'opt-in changes resources beyond the pod and namespace pilot settings'

render_overlay "${scratch_dir}/k8s/providers/docker/apps" "${scratch_dir}/local-after.json"
cmp "${scratch_dir}/local-before.json" "${scratch_dir}/local-after.json" ||
  fail 'production opt-in must not affect the local overlay'
COMPONENT="${component}" yq -i '.components |= map(select(. != strenv(COMPONENT)))' \
  "${apps_dir}/kustomization.yaml"
render_overlay "${apps_dir}" "${scratch_dir}/rollback.json"
cmp "${scratch_dir}/off.json" "${scratch_dir}/rollback.json" ||
  fail 'rollback must restore the original resources exactly'

chart_name="$(jq -r '.spec.chart.spec.chart' "${scratch_dir}/off-release.json")"
chart_version="$(jq -r '.spec.chart.spec.version' "${scratch_dir}/off-release.json")"
chart_repo="$(yq -r '.spec.url' "${root_dir}/k8s/bases/apps/actual-budget/helm-repository.yaml")"
helm pull "${chart_name}" --repo "${chart_repo}" --version "${chart_version}" \
  --destination "${scratch_dir}"
readonly chart_archive="${scratch_dir}/${chart_name}-${chart_version}.tgz"

# Render the off/on release named by $1 with its production replica count and
# ordered Flux post-renderers, saving the resulting workload as sorted JSON.
render_workload() {
  local mode="$1" renderer_count index replicas configured_replicas
  local release="${scratch_dir}/${mode}-release.json"
  local render_dir="${scratch_dir}/${mode}"
  mkdir -p "${render_dir}"
  # Resolve the declared default and production ConfigMap instead of forcing
  # one replica: the assertion below must catch an unsafe production increase.
  replicas="$(jq -r '.spec.values.replicaCount' "${release}")"
  if [[ "${replicas}" =~ ^\$\{actual_budget_replicas:=([0-9]+)\}$ ]]; then
    replicas="${BASH_REMATCH[1]}"
    configured_replicas="$(yq -r '.data.actual_budget_replicas // ""' \
      "${scratch_dir}/k8s/clusters/prod/bootstrap/config-map.yaml")"
    replicas="${configured_replicas:-${replicas}}"
  fi
  [[ "${replicas}" =~ ^[0-9]+$ ]] || fail 'production replica count must resolve to an integer'
  jq --arg replicas "${replicas}" '.spec.values | .replicaCount = ($replicas | tonumber)' \
    "${release}" >"${render_dir}/values.json"
  helm template actual-budget "${chart_archive}" --namespace actual-budget \
    --values "${render_dir}/values.json" >"${render_dir}/resources.yaml"
  renderer_count="$(jq '.spec.postRenderers | length' "${release}")"
  for ((index = 0; index < renderer_count; index++)); do
    jq --argjson index "${index}" '{apiVersion: "kustomize.config.k8s.io/v1beta1",
      kind: "Kustomization", resources: ["resources.yaml"]} +
      .spec.postRenderers[$index].kustomize' "${release}" >"${render_dir}/kustomization.yaml"
    kubectl kustomize "${render_dir}" >"${render_dir}/next.yaml"
    mv "${render_dir}/next.yaml" "${render_dir}/resources.yaml"
  done
  yq ea -o=json '[.]' "${render_dir}/resources.yaml" | jq -S . >"${scratch_dir}/${mode}-workload.json"
}

render_workload off
render_workload on
jq -e '[.[] | select(.kind == "Deployment") | .spec.template.spec.hostUsers] == [false]' \
  "${scratch_dir}/on-workload.json" >/dev/null || fail 'opt-in must reach the rendered Deployment'
jq -e '[.[] | select(.kind == "Deployment") | .spec.template.spec.hostUsers] == [null]' \
  "${scratch_dir}/off-workload.json" >/dev/null || fail 'disabled pilot must preserve host user namespaces'
jq -S 'map(if .kind == "Deployment" then del(.spec.template.spec.hostUsers) else . end)' \
  "${scratch_dir}/on-workload.json" >"${scratch_dir}/normalized-workload.json"
diff -u "${scratch_dir}/off-workload.json" "${scratch_dir}/normalized-workload.json" ||
  fail 'the pilot must preserve the complete workload, including PVCs and both containers'
jq -e '[.[] | select(.kind == "Deployment") |
  .spec.strategy.type == "Recreate" and .spec.replicas == 1 and
  (.spec.template.spec.containers | length) == 2 and
  ([.spec.template.spec.volumes[] | select(has("persistentVolumeClaim"))] | length) == 1] == [true]' \
  "${scratch_dir}/on-workload.json" >/dev/null || fail 'the pilot must retain its single-writer storage contract'

printf 'PASS: Actual Budget user namespaces are default-off; opt-in changes only hostUsers and enforcement, and rollback preserves storage\n'
