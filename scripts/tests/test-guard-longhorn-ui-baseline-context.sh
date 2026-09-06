#!/usr/bin/env bash
# Check decisions against API fixtures, with kubectl as the external boundary.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
mkdir "${scratch}/bin"
cat >"${scratch}/release.yaml" <<'YAML'
spec:
  postRenderers:
    - kustomize:
        patches:
          - target: {kind: Deployment, name: longhorn-ui}
            patch: |
              spec:
                template:
                  spec:
                    securityContext: {fsGroupChangePolicy: OnRootMismatch}
                    containers:
                      - name: longhorn-ui
                        securityContext: {seLinuxOptions: {}}
YAML
cat >"${scratch}/deployment.json" <<'JSON'
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"longhorn-ui","namespace":"longhorn-system","generation":7,"annotations":{"meta.helm.sh/release-name":"longhorn","meta.helm.sh/release-namespace":"longhorn-system"}},"spec":{"replicas":1,"template":{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":499,"runAsGroup":486,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"longhorn-ui","securityContext":{"runAsNonRoot":true,"runAsUser":499,"runAsGroup":486,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}}],"volumes":[{"name":"cache","emptyDir":{}},{"name":"config","emptyDir":{}},{"name":"run","emptyDir":{}}]}}},"status":{"observedGeneration":7,"replicas":1,"updatedReplicas":1,"readyReplicas":1,"availableReplicas":1}}
JSON
cat >"${scratch}/bin/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FIXTURE_DIR}/calls"
[[ "$*" == '--context fixture get deployment longhorn-ui --namespace longhorn-system --ignore-not-found -o json --request-timeout=20s' ]] || exit 99
case "${SCENARIO}" in
  api-error) exit 1 ;;
  absent) exit 0 ;;
  *) cat "${FIXTURE_DIR}/input.json" ;;
esac
SH
cat >"${scratch}/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "${scratch}/bin/kubectl" "${scratch}/bin/sleep"
export PATH="${scratch}/bin:${PATH}" FIXTURE_DIR="${scratch}"
script="${root_dir}/scripts/guard-longhorn-ui-baseline-context.sh"

check() {
  local name="$1" phase="$2" expected="$3" scenario="$4" rc=0
  : >"${scratch}/outputs"
  SCENARIO="${scenario}" GITHUB_OUTPUT="${scratch}/outputs" bash "${script}" "${phase}" \
    --context fixture --release "${scratch}/release.yaml" >"${scratch}/output" 2>&1 || rc=$?
  if [[ "${expected}" == pass && "${rc}" -ne 0 ]] || [[ "${expected}" == fail && "${rc}" -eq 0 ]]; then
    printf 'FAIL: %s (exit %s)\n' "${name}" "${rc}" >&2
    cat "${scratch}/output" >&2
    exit 1
  fi
}
cp "${scratch}/deployment.json" "${scratch}/input.json"
check 'healthy unmodified UI is an eligible canary' before-publish pass normal
grep -qx 'rollout_required=true' "${scratch}/outputs"
check 'API error is not absence' before-publish fail api-error
check 'uninstalled chart can bootstrap' before-publish pass absent
check 'post-deploy absence is failure' after-reconcile fail absent
check 'healthy old template is not rollout evidence' after-reconcile fail normal

jq '.spec.template.spec.securityContext.fsGroupChangePolicy="OnRootMismatch" |
  .spec.template.spec.containers[0].securityContext.seLinuxOptions={}' \
  "${scratch}/deployment.json" >"${scratch}/hardened.json"
cp "${scratch}/hardened.json" "${scratch}/input.json"
check 'repeated deploy accepts existing canary' before-publish pass normal
grep -qx 'rollout_required=false' "${scratch}/outputs"
check 'ready and stable hardened UI passes' after-reconcile pass normal

for mutation in \
  '.status.availableReplicas=0' \
  '.status.observedGeneration=6' \
  '.spec.template.spec.securityContext.fsGroup=1000' \
  '.spec.template.spec.volumes[0]={name:"data",persistentVolumeClaim:{claimName:"storage"}}' \
  '.spec.template.spec.containers[0].securityContext.privileged=true' \
  '.spec.template.spec.containers[0].securityContext.runAsUser=0' \
  '.spec.template.spec.initContainers=[{name:"unreviewed-init",securityContext:{runAsUser:0}}]' \
  '.metadata.ownerReferences=[{kind:"Operator",name:"rebuilding-owner"}]'; do
  jq "${mutation}" "${scratch}/deployment.json" >"${scratch}/input.json"
  check "invariant rejects ${mutation}" before-publish fail normal
  jq "${mutation}" "${scratch}/hardened.json" >"${scratch}/input.json"
  check "post-proof rejects ${mutation}" after-reconcile fail normal
done

# A post-start generation move represents an owner rewriting the template.
cat >"${scratch}/bin/sleep" <<'SH'
#!/usr/bin/env bash
jq '.metadata.generation += 1 | .status.observedGeneration += 1' "${FIXTURE_DIR}/input.json" >"${FIXTURE_DIR}/next.json"
mv "${FIXTURE_DIR}/next.json" "${FIXTURE_DIR}/input.json"
SH
cp "${scratch}/hardened.json" "${scratch}/input.json"
check 'owner rewriting during the watch fails closed' after-reconcile fail normal

cat >"${scratch}/bin/sleep" <<'SH'
#!/usr/bin/env bash
jq '.metadata.resourceVersion = ((.metadata.resourceVersion // "700" | tonumber) + 1 | tostring)' "${FIXTURE_DIR}/input.json" >"${FIXTURE_DIR}/next.json"
mv "${FIXTURE_DIR}/next.json" "${FIXTURE_DIR}/input.json"
SH
cp "${scratch}/hardened.json" "${scratch}/input.json"
check 'repeated writes without generation movement fail closed' after-reconcile fail normal

# Source rollback must disarm before accessing the failed workload.
printf 'spec: {}\n' >"${scratch}/release.yaml"
check 'rollback disarms the canary before any cluster access' before-publish pass api-error
grep -qx 'rollout_required=false' "${scratch}/outputs"

# The deployed workflow must call the same real guard on each side of the
# artifact boundary. A standalone passing checker is not an enforced rollout.
yq -o=json '.runs.steps' "${root_dir}/.github/actions/deploy-prod/action.yml" |
  jq -e '
    map(.id // "") as $ids |
    ($ids | index("longhorn_ui_baseline")) as $before |
    ($ids | index("publish_platform_manifest")) as $publish |
    ($ids | index("wait_flux_revision")) as $ready |
    to_entries | map(select(.value.run == "bash scripts/guard-longhorn-ui-baseline-context.sh after-reconcile")) as $after |
    $before != null and $publish != null and $ready != null and
    $before < $publish and ($after | length) == 1 and $after[0].key > $ready and
    $after[0].value.if == "steps.longhorn_ui_baseline.outputs.rollout_required == '\''true'\''"' >/dev/null
printf 'PASS: Longhorn UI preflight, post-proof, absent/error, drift, readiness and privilege controls\n'
