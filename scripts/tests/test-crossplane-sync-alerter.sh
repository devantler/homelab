#!/usr/bin/env bash

# Exercise the deployed sensor with paginated API responses and captured alerts.
# Only network calls and in-cluster mount paths are replaced.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="${root_dir}/k8s/providers/hetzner/infrastructure/coroot/cron-job-crossplane-sync-alerter.yaml"
config="${root_dir}/k8s/bases/infrastructure/coroot/components/crossplane-sync-exporter/config-map.yaml"
work_dir="$(mktemp -d)"
trap 'chmod -R u+w "${work_dir}"; rm -rf "${work_dir}"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

pod_path='.spec.jobTemplate.spec.template.spec'
scratch_volume="$(yq -r "${pod_path}.containers[] | select(.name == \"alerter\") | .volumeMounts[] | select(.mountPath == \"/tmp\") | .name" "${manifest}")"
[ -n "$scratch_volume" ] || fail 'the non-root sensor needs a writable scratch mount'
yq -e "${pod_path}.volumes[] | select(.name == \"${scratch_volume}\") | .emptyDir.sizeLimit == \"32Mi\"" \
  "${manifest}" >/dev/null || fail 'scratch storage must have a bounded emptyDir'
[ "$(yq -r "${pod_path}.securityContext.fsGroup" "${manifest}")" = \
  "$(yq -r "${pod_path}.securityContext.runAsUser" "${manifest}")" ] || fail 'the sensor must be able to write its scratch volume'
yq -e "${pod_path}.containers[] | select(.name == \"alerter\") | .securityContext.readOnlyRootFilesystem == true" \
  "${manifest}" >/dev/null || fail 'scratch storage must not require a writable root filesystem'

yq -r '.spec.jobTemplate.spec.template.spec.containers[] | select(.name == "alerter") | .command[2]' \
  "${manifest}" >"${work_dir}/sensor.sh"
mkdir -p "${work_dir}/config" "${work_dir}/sa" "${work_dir}/bin"
yq -r '.data."managed-resources.tsv"' "${config}" >"${work_dir}/config/managed-resources.tsv"
yq -r '.data."managed-coverage-gaps.jq"' "${config}" >"${work_dir}/config/managed-coverage-gaps.jq"
printf 'fixture-token\n' >"${work_dir}/sa/token"
printf 'fixture-ca\n' >"${work_dir}/sa/ca.crt"

cat >"${work_dir}/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
query='' cursor='' output='' payload='' limit='' url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-urlencode)
      case "$2" in
        query=*) query="${2#query=}" ;;
        continue=*) cursor="${2#continue=}" ;;
        limit=*) limit="${2#limit=}" ;;
      esac
      shift 2 ;;
    --output|-o) output="$2"; shift 2 ;;
    -d|--data) payload="$2"; shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  */api/v1/query)
    case "$query" in
      'up{'*) cat "${CASE_DIR}/up.json" ;;
      count\(*) cat "${CASE_DIR}/coverage.json" ;;
      crossplane_*) cat "${CASE_DIR}/stuck.json" ;;
      *) exit 90 ;;
    esac ;;
  */customresourcedefinitions)
    [ "$limit" = 25 ] || exit 91
    case "$cursor" in
      '') page=1 ;;
      'next+/=page') page=2 ;;
      *) exit 92 ;;
    esac
    printf '%s\n' "$page" >>"${CASE_DIR}/pages.log"
    if [ "$page" = 2 ] && [ -e "${CASE_DIR}/fail-download" ]; then
      # A partial transfer must never reuse the preceding complete page.
      [ -z "$output" ] || printf '{"kind":' >"$output"
      exit 18
    fi
    if [ -n "$output" ]; then
      cat "${CASE_DIR}/page-${page}.json" >"$output" || exit 23
    else
      cat "${CASE_DIR}/page-${page}.json"
    fi ;;
  */api/v2/alerts)
    printf '%s\n' "$payload" >"${CASE_DIR}/alerts.json"
    [ ! -e "${CASE_DIR}/reject-alerts" ] || exit 22 ;;
  *) exit 93 ;;
esac
STUB
chmod +x "${work_dir}/bin/curl"

new_case() {
  case_dir="${work_dir}/$1"
  mkdir -p "${case_dir}/tmp"
  printf '%s\n' '{"status":"success","data":{"result":[{"value":[1,"1"]}]}}' >"${case_dir}/up.json"
  cp "${case_dir}/up.json" "${case_dir}/coverage.json"
  printf '%s\n' '{"status":"success","data":{"result":[]}}' >"${case_dir}/stuck.json"
  # Large schemas have no bearing on the small identity/served-version result.
  jq -n '{kind:"CustomResourceDefinitionList",metadata:{continue:"next+/=page"},items:[{
    spec:{group:"repo.github.m.upbound.io",names:{kind:"Repository",categories:["managed"]},
      versions:[{name:"v1alpha1",served:true,schema:{description:("x" * 524288)}}]}}]}' >"${case_dir}/page-1.json"
  printf '%s\n' '{"kind":"CustomResourceDefinitionList","metadata":{},"items":[]}' >"${case_dir}/page-2.json"
  # Rewrite /tmp first so later inserted absolute fixture paths are not rewritten.
  sed -e "s#/tmp/#${case_dir}/tmp/#g" \
    -e "s#/var/run/secrets/kubernetes.io/serviceaccount#${work_dir}/sa#g" \
    -e "s#/etc/crossplane-sync-exporter#${work_dir}/config#g" \
    "${work_dir}/sensor.sh" >"${case_dir}/sensor.sh"
}

run_case() {
  result=0
  PATH="${work_dir}/bin:${PATH}" CASE_DIR="${case_dir}" \
    KUBERNETES_SERVICE_HOST=api.example.invalid KUBERNETES_SERVICE_PORT_HTTPS=443 \
    sh "${case_dir}/sensor.sh" >"${case_dir}/output.log" 2>&1 || result=$?
}

new_case healthy
run_case
[ "$result" = 0 ] || fail 'healthy complete inventory must succeed'
[ "$(cat "${case_dir}/pages.log")" = $'1\n2' ] || fail 'every continuation page must be read exactly once'
[ ! -e "${case_dir}/alerts.json" ] || fail 'healthy resources must not alert'
grep -q 'all watched managed resources are syncing' "${case_dir}/output.log" || fail 'healthy result must be explicit'

new_case coverage-gap
jq '.items = [{spec:{group:"new.example.invalid",names:{kind:"Widget",categories:["managed"]},versions:[{name:"v1",served:true}]}}]' \
  "${case_dir}/page-2.json" >"${case_dir}/replacement.json"
mv "${case_dir}/replacement.json" "${case_dir}/page-2.json"
run_case
[ "$result" = 0 ] || fail 'a coverage gap must be delivered successfully'
jq -e 'length == 1 and .[0].labels.alertname == "CrossplaneSyncExporterCoverageGap"
  and (.[0].annotations.description | contains("new.example.invalid/Widget"))' \
  "${case_dir}/alerts.json" >/dev/null || fail 'a kind on the final page must alert'

new_case exporter-down
cp "${case_dir}/stuck.json" "${case_dir}/up.json"
run_case
[ "$result" = 0 ] || fail 'exporter failure must reach alert delivery'
jq -e 'length == 1 and .[0].labels.alertname == "CrossplaneSyncExporterDown"' \
  "${case_dir}/alerts.json" >/dev/null || fail 'missing exporter samples must alert'

new_case stuck
printf '%s\n' '{"status":"success","data":{"result":[{"metric":{"name":"sample","namespace":"tenant","reason":"ReconcileError","customresource_group":"repo.github.m.upbound.io","customresource_version":"v1alpha1","customresource_kind":"Repository"},"value":[1,"0"]}]}}' >"${case_dir}/stuck.json"
run_case
[ "$result" = 0 ] || fail 'stuck-resource alert must be delivered'
jq -e 'length == 1 and .[0].labels.alertname == "CrossplaneManagedResourceNotSynced"
  and .[0].labels.resource == "sample" and .[0].labels.resource_kind == "Repository"
  and .[0].annotations.reason == "ReconcileError" and (.[0].labels | has("reason") | not)' \
  "${case_dir}/alerts.json" >/dev/null || fail 'stuck alert must retain resource identity and reason'
touch "${case_dir}/reject-alerts"
run_case
[ "$result" != 0 ] || fail 'rejected alert delivery must fail the job'

for problem in fail-download malformed-json unexpected-kind; do
  new_case "$problem"
  case "$problem" in
    fail-download) touch "${case_dir}/fail-download" ;;
    malformed-json) printf '{' >"${case_dir}/page-2.json" ;;
    unexpected-kind) printf '{"kind":"Status","items":[]}' >"${case_dir}/page-2.json" ;;
  esac
  run_case
  [ "$result" != 0 ] || fail "$problem must fail rather than claim complete coverage"
  [ ! -e "${case_dir}/alerts.json" ] || fail "$problem must not deliver partial results"
  ! grep -q 'all watched managed resources are syncing' "${case_dir}/output.log" || fail "$problem reported healthy"
done

# A full scratch volume is an I/O failure, never an empty healthy inventory.
# Use a regular file where the scratch directory should be; works even as root.
new_case unavailable-scratch
rmdir "${case_dir}/tmp"
printf 'not a directory\n' >"${case_dir}/tmp"
run_case
[ "$result" != 0 ] || fail 'unavailable scratch storage must fail discovery'
[ ! -e "${case_dir}/alerts.json" ] || fail 'scratch failure must not deliver partial results'

printf 'PASS: Crossplane sync alert delivery and paginated discovery\n'
