#!/usr/bin/env bash
# Contract for the Velero repository-maintenance OOM detector (#3437).
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly bundle_dir="${root_dir}/k8s/bases/components/coroot-velero-maintenance-oom-alert"
readonly manifest="${bundle_dir}/cron-job-velero-maintenance-oom-alert.yaml"
readonly role="${bundle_dir}/role-velero-maintenance-oom-alert.yaml"
readonly binding="${bundle_dir}/role-binding-velero-maintenance-oom-alert.yaml"
readonly kustomization="${bundle_dir}/kustomization.yaml"
readonly coroot_kustomization="${root_dir}/k8s/bases/infrastructure/controllers/coroot/kustomization.yaml"
readonly hetzner_kustomization="${root_dir}/k8s/providers/hetzner/infrastructure/controllers/kustomization.yaml"
readonly alerting_doc="${root_dir}/docs/dr/alerting.md"
readonly documented_manifest='bases/components/coroot-velero-maintenance-oom-alert/cron-job-velero-maintenance-oom-alert.yaml'
readonly real_webhook='https://hooks.test.invalid/delivery-target'
readonly placeholder_webhook='https://example.invalid/no-slack-configured'

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$1"; }

for tool in yq jq; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

[ -f "$manifest" ] || fail "manifest not found: $manifest"
[ -f "$role" ] || fail "Role not found: $role"
[ -f "$binding" ] || fail "RoleBinding not found: $binding"

container_path='.spec.jobTemplate.spec.template.spec.containers[0]'
pod_path='.spec.jobTemplate.spec.template.spec'
script_body="$(yq eval "${container_path}.command[2]" "$manifest")"
[ -n "$script_body" ] && [ "$script_body" != null ] || fail 'could not extract detector script'

[ "$(yq eval '.metadata.namespace' "$role")" = velero ] || fail 'Role must be namespaced to velero'
[ "$(yq eval '[.rules[].resources[]] | unique | join(",")' "$role")" = pods ] || fail 'Role may read only pods'
[ "$(yq eval '[.rules[].verbs[]] | sort | join(",")' "$role")" = list ] || fail 'Role verb must be exactly list'
[ "$(yq eval '.roleRef.kind' "$binding")" = Role ] || fail 'binding must reference the namespaced Role'
[ "$(yq eval '.subjects[0].namespace' "$binding")" = observability ] || fail 'binding must grant only the observability ServiceAccount'
pass 'RBAC is list-only on velero pods'

for resource in service-account secret role role-binding cron-job; do
  grep -Fq "${resource}-velero-maintenance-oom-alert.yaml" "$kustomization" ||
    fail "$resource manifest is missing from the Coroot-and-Velero component"
done
if grep -Fq 'velero-maintenance-oom-alert' "$coroot_kustomization"; then
  fail 'the independently selectable Coroot base must not require the Velero namespace'
fi
grep -Fq '../../../../bases/components/coroot-velero-maintenance-oom-alert' "$hetzner_kustomization" ||
  fail 'the Hetzner composition must enable the alert alongside Coroot and Velero'
pass 'the alert is composed only where Coroot and Velero are both enabled'
grep -Fq "\`${documented_manifest}\`" "$alerting_doc" ||
  fail 'the alerting runbook does not point at the component manifest'
[ -f "${root_dir}/k8s/${documented_manifest}" ] ||
  fail 'the alerting runbook points at a manifest that does not exist'
pass 'the alerting runbook points at the component manifest'
[ "$(yq eval '.metadata.annotations["kustomize.toolkit.fluxcd.io/substitute"]' "$manifest")" = disabled ] ||
  fail 'CronJob must disable Flux substitution for its shell variables'
grep -q 'velero-maintenance-oom-alert-webhook' <<<"$(yq eval "${pod_path}.volumes" "$manifest")" ||
  fail 'webhook Secret is not mounted'
[ "$(yq eval "${pod_path}.volumes[] | select(.name == \"webhook\") | .secret.defaultMode" "$manifest")" = 288 ] ||
  fail 'webhook Secret mode must be 0440'
if grep -q secretKeyRef <<<"$(yq eval "${container_path}.env" "$manifest")"; then
  fail 'webhook must not be exposed through an environment variable'
fi
if grep -Eq 'curl.*"\$\{?WEBHOOK_URL\}?"' <<<"$script_body"; then
  fail 'webhook URL must not appear in curl argv'
fi
grep -Fq -- '--config -' <<<"$script_body" || fail 'webhook delivery must read its URL from stdin config'
grep -Fq -- "--data-urlencode 'labelSelector=velero.io/repo-name'" <<<"$script_body" ||
  fail 'API read must select only Velero repository-maintenance pods'
[ "$(yq eval '.spec.schedule' "$manifest")" = '*/30 * * * *' ] || fail 'detector must run every 30 minutes'
[ "$(yq eval "${container_path}.env[] | select(.name == \"LOOKBACK_SECONDS\") | .value" "$manifest")" = 7200 ] ||
  fail 'detector must use the bounded two-hour lookback'
pass 'webhook is mounted 0440 and never exposed in argv or environment'

work_root="$(mktemp -d /tmp/velero-oom-alert.XXXXXXXXXX)"
trap 'rm -rf "$work_root"' EXIT
readonly now_epoch=1789200000

pod() { # name repo reason exit-code seconds-ago
  local name=$1 repo=$2 reason=$3 exit_code=$4 ago=$5
  jq -cn --arg name "$name" --arg repo "$repo" --arg reason "$reason" \
    --argjson exit_code "$exit_code" --argjson finished "$((now_epoch - ago))" '
      {metadata:{name:$name,labels:{"velero.io/repo-name":$repo}},status:{containerStatuses:[{
        name:"velero-repo-maintenance-container",
        state:{terminated:{reason:$reason,exitCode:$exit_code,finishedAt:($finished|todateiso8601)}}
      }]}}'
}

restarted_pod() { # name repo reason exit-code seconds-ago — running again after a terminated attempt
  local name=$1 repo=$2 reason=$3 exit_code=$4 ago=$5
  jq -cn --arg name "$name" --arg repo "$repo" --arg reason "$reason" \
    --argjson exit_code "$exit_code" --argjson finished "$((now_epoch - ago))" '
      {metadata:{name:$name,labels:{"velero.io/repo-name":$repo}},status:{containerStatuses:[{
        name:"velero-repo-maintenance-container",
        state:{running:{startedAt:($finished|todateiso8601)}},
        lastState:{terminated:{reason:$reason,exitCode:$exit_code,finishedAt:($finished|todateiso8601)}}
      }]}}'
}

setup_scenario() {
  local name=$1 webhook=$2
  local dir="${work_root}/${name}"
  mkdir -p "${dir}/bin" "${dir}/sa" "${dir}/webhook" "${dir}/tmp"
  printf fake-ca >"${dir}/sa/ca.crt"
  printf fake-token >"${dir}/sa/token"
  printf '%s' "$webhook" >"${dir}/webhook/url"
  printf 200 >"${dir}/api.code"
  printf '%s' '{"kind":"PodList","items":[]}' >"${dir}/api.body"
  cat >"${dir}/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
dir=${SCENARIO_DIR}
printf '%s\n' "$*" >>"${dir}/curl-argv.log"
out=''
prev=''
for arg in "$@"; do
  [ "$prev" = -o ] && out=$arg
  prev=$arg
done
if [ -n "$out" ]; then
  cp "${dir}/api.body" "$out"
  cat "${dir}/api.code"
  exit 0
fi
cat >"${dir}/curl-stdin.log"
printf delivered >"${dir}/delivered"
exit "${STUB_DELIVERY_EXIT:-0}"
STUB
  chmod +x "${dir}/bin/curl"
  printf '%s' "$dir"
}

run_scenario() {
  local dir=$1
  local patched="${dir}/script.sh"
  {
    printf 'export NOW_EPOCH=%s\n' "$now_epoch"
    printf 'export LOOKBACK_SECONDS=%s\n' 7200
    printf 'export SCENARIO_DIR=%q\n' "$dir"
    printf 'SA_OVERRIDE=%q\n' "${dir}/sa"
    # The replacement emits a literal reference into the extracted script; the
    # scenario supplies SA_OVERRIDE at runtime.
    # shellcheck disable=SC2016
    printf '%s\n' "$script_body" |
      sed -e 's#^\( *\)SA=/var/run/secrets/kubernetes.io/serviceaccount$#\1SA="$SA_OVERRIDE"#' \
        -e 's#/tmp/#'"${dir}"'/tmp/#g' \
        -e 's#/etc/velero-maintenance-oom-alert/url#'"${dir}"'/webhook/url#g'
  } >"$patched"
  PATH="${dir}/bin:${PATH}" SCENARIO_DIR="$dir" \
    STUB_DELIVERY_EXIT="${STUB_DELIVERY_EXIT:-0}" \
    bash "$patched" >"${dir}/stdout" 2>"${dir}/stderr"
}

# The original incident shape: an OOMKilled pod remains even though a later
# retry for the same repository succeeded. Final repository health must not hide it.
dir="$(setup_scenario retried "$real_webhook")"
{
  pod observability-maintenance-failed observability-default-kopia OOMKilled 137 900
  pod observability-maintenance-retry observability-default-kopia Completed 0 600
} | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "retried OOM scenario failed: $(cat "${dir}/stderr")"
[ -f "${dir}/delivered" ] || fail 'a retried-then-succeeded OOMKill produced no alert'
payload="$(jq -r .text "${dir}/tmp/payload.json")"
for needle in observability-maintenance-failed observability-default-kopia OOMKilled; do
  grep -Fq "$needle" <<<"$payload" || fail "alert payload does not name $needle"
done
pass 'a retained OOMKilled pod alerts even after the repository retry succeeds'

dir="$(setup_scenario healthy "$real_webhook")"
pod healthy-maintenance wedding-app-default-kopia Completed 0 300 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "healthy scenario failed: $(cat "${dir}/stderr")"
[ ! -f "${dir}/delivered" ] || fail 'a successful maintenance pod alerted'
pass 'successful maintenance stays quiet'

dir="$(setup_scenario old "$real_webhook")"
pod old-oom observability-default-kopia OOMKilled 137 10800 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "old scenario failed: $(cat "${dir}/stderr")"
[ ! -f "${dir}/delivered" ] || fail 'an OOMKill outside the lookback window alerted'
pass 'an expired OOMKill ages out of the alert window'

# The lookback is exclusive at its boundary: a 30-minute schedule with a two-hour
# window must alert on at most four ticks, so an event exactly LOOKBACK_SECONDS
# old has already aged out. One second younger must still alert, so the boundary
# is not over-tightened.
dir="$(setup_scenario at-cutoff "$real_webhook")"
pod at-cutoff-oom observability-default-kopia OOMKilled 137 7200 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "at-cutoff scenario failed: $(cat "${dir}/stderr")"
[ ! -f "${dir}/delivered" ] || fail 'an OOMKill exactly at the lookback cutoff alerted a fifth time'
dir="$(setup_scenario inside-cutoff "$real_webhook")"
pod inside-cutoff-oom observability-default-kopia OOMKilled 137 7199 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "inside-cutoff scenario failed: $(cat "${dir}/stderr")"
[ -f "${dir}/delivered" ] || fail 'an OOMKill one second inside the lookback did not alert'
pass 'the lookback boundary is exclusive, and one second inside still alerts'

# A container restarted in place after an OOMKill reports it only in lastState.
dir="$(setup_scenario restarted "$real_webhook")"
restarted_pod restarted-oom observability-default-kopia OOMKilled 137 600 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "restarted scenario failed: $(cat "${dir}/stderr")"
[ -f "${dir}/delivered" ] || fail 'an OOMKill recorded only in lastState produced no alert'
grep -Fq restarted-oom <<<"$(jq -r .text "${dir}/tmp/payload.json")" || fail 'lastState alert does not name its pod'
pass 'an OOMKill recorded only in lastState still alerts'

dir="$(setup_scenario malformed "$real_webhook")"
printf '%s' '{"items":{}}' >"${dir}/api.body"
if run_scenario "$dir"; then fail 'malformed API response exited zero'; fi
pass 'malformed API data fails loudly'

dir="$(setup_scenario api-error "$real_webhook")"
printf 500 >"${dir}/api.code"
if run_scenario "$dir"; then fail 'HTTP 500 API response exited zero'; fi
grep -Fq 'HTTP 500' "${dir}/stderr" || fail 'API failure does not name its HTTP status'
pass 'API failure fails loudly'

dir="$(setup_scenario delivery "$real_webhook")"
pod delivery-oom observability-default-kopia OOMKilled 137 300 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
if STUB_DELIVERY_EXIT=22 run_scenario "$dir"; then fail 'failed Slack delivery exited zero'; fi
pass 'delivery failure fails loudly'

dir="$(setup_scenario placeholder "$placeholder_webhook")"
pod placeholder-oom observability-default-kopia OOMKilled 137 300 | jq -sc '{kind:"PodList",items:.}' >"${dir}/api.body"
run_scenario "$dir" || fail "placeholder scenario failed: $(cat "${dir}/stderr")"
[ ! -f "${dir}/delivered" ] || fail 'placeholder webhook received a delivery'
grep -Fq 'not delivered' "${dir}/stdout" || fail 'placeholder skip was not logged'
pass 'local placeholder logs the finding without delivery'

printf 'PASS: Velero maintenance OOM alert detects a failed attempt even after a successful retry\n'
