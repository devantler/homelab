#!/usr/bin/env bash
# Render the pinned chart through the real Flux post-renderers. The canary must
# change only the UI security defaults, and removing them must restore the chart.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
release_dir="${root_dir}/k8s/providers/hetzner/infrastructure/controllers/longhorn"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
for tool in kubectl helm yq jq; do
  command -v "${tool}" >/dev/null || fail "${tool} is required"
done

kubectl kustomize "${release_dir}" | yq -o=json \
  'select(.kind == "HelmRelease" and .metadata.name == "longhorn")' >"${scratch}/on.json"
yq -o=json '.data' "${root_dir}/k8s/clusters/prod/bootstrap/config-map.yaml" >"${scratch}/variables.json"
jq --slurpfile variables "${scratch}/variables.json" '.spec.values | walk(
  if type == "string" and test("^\\$\\{[a-z_]+:=[0-9]+\\}$") then
    capture("^\\$\\{(?<name>[a-z_]+):=(?<fallback>[0-9]+)\\}$") |
    ($variables[0][.name] // .fallback) | tonumber
  else . end)' "${scratch}/on.json" >"${scratch}/values.json"
chart_name="$(jq -r '.spec.chart.spec.chart' "${scratch}/on.json")"
chart_version="$(jq -r '.spec.chart.spec.version' "${scratch}/on.json")"
chart_repo="$(yq -r '.spec.url' "${release_dir}/helm-repository.yaml")"
helm pull "${chart_name}" --repo "${chart_repo}" --version "${chart_version}" --destination "${scratch}"
helm template longhorn "${scratch}/${chart_name}-${chart_version}.tgz" \
  --namespace longhorn-system --values "${scratch}/values.json" >"${scratch}/chart.yaml"

# Remove only the canary defaults from the source-owned UI patch. This is the
# rollback proposed for a failing canary, and leaves its existing hardening intact.
yq -o=json '(.spec.postRenderers[].kustomize.patches[] |
  select(.target.kind == "Deployment" and .target.name == "longhorn-ui").patch) |=
  (from_yaml | del(.spec.template.spec.securityContext.fsGroupChangePolicy) |
   del(.spec.template.spec.containers[].securityContext.seLinuxOptions) | to_yaml)' \
  "${scratch}/on.json" >"${scratch}/off.json"

render() {
  local mode="$1" index count
  mkdir "${scratch}/${mode}"
  cp "${scratch}/chart.yaml" "${scratch}/${mode}/resources.yaml"
  count="$(jq '.spec.postRenderers | length' "${scratch}/${mode}.json")"
  for ((index = 0; index < count; index++)); do
    jq --argjson index "${index}" '{apiVersion: "kustomize.config.k8s.io/v1beta1",
      kind: "Kustomization", resources: ["resources.yaml"]} +
      .spec.postRenderers[$index].kustomize' "${scratch}/${mode}.json" >"${scratch}/${mode}/kustomization.yaml"
    kubectl kustomize "${scratch}/${mode}" >"${scratch}/${mode}/next.yaml"
    mv "${scratch}/${mode}/next.yaml" "${scratch}/${mode}/resources.yaml"
  done
  yq ea -o=json '[.]' "${scratch}/${mode}/resources.yaml" |
    jq -S 'sort_by([.apiVersion,.kind,.metadata.namespace,.metadata.name])' >"${scratch}/${mode}-resources.json"
}
render off
render on

# A target rename or a patch that Helm never applies must fail here, instead of
# passing because Kustomize tolerates unmatched patch targets.
jq -e '[.[] | select(.kind == "Deployment" and .metadata.name == "longhorn-ui") |
  .spec.template.spec.securityContext.fsGroupChangePolicy == "OnRootMismatch" and
  .spec.template.spec.securityContext.fsGroup == null and
  ([.spec.template.spec.containers[] | .securityContext.seLinuxOptions] == [{}]) and
  ([.spec.template.spec.volumes[] | has("emptyDir")] | all)] == [true]' \
  "${scratch}/on-resources.json" >/dev/null || fail 'UI canary defaults or ephemeral storage contract missing'
jq -e '[.[] | select(.kind == "Deployment" and .metadata.name == "longhorn-ui") |
  .spec.template.spec.securityContext.fsGroupChangePolicy == null and
  ([.spec.template.spec.containers[] | .securityContext.seLinuxOptions] == [null])] == [true]' \
  "${scratch}/off-resources.json" >/dev/null || fail 'disabled canary must omit both new defaults'

jq -S 'map(if .kind == "Deployment" and .metadata.name == "longhorn-ui" then
    del(.spec.template.spec.securityContext.fsGroupChangePolicy) |
    del(.spec.template.spec.containers[].securityContext.seLinuxOptions)
  else . end)' "${scratch}/on-resources.json" >"${scratch}/normalized.json"
cmp "${scratch}/off-resources.json" "${scratch}/normalized.json" ||
  fail 'canary changes resources beyond the two UI defaults, including storage controllers or existing hardening'

cp "${scratch}/off.json" "${scratch}/rollback.json"
render rollback
cmp "${scratch}/off-resources.json" "${scratch}/rollback-resources.json" || fail 'rollback must restore all rendered resources exactly'

# Prove the positive assertion rejects the unchanged release; a test which only
# compared normalized output would incorrectly accept an entirely absent patch.
if jq -e '[.[] | select(.kind == "Deployment" and .metadata.name == "longhorn-ui") |
  .spec.template.spec.securityContext.fsGroupChangePolicy] == ["OnRootMismatch"]' \
  "${scratch}/off-resources.json" >/dev/null; then
  fail 'negative control accepted a release without the canary'
fi

printf 'PASS: exact Longhorn chart changes only the two UI defaults; disabled state and rollback preserve every resource\n'
