#!/usr/bin/env bash

# Behaviour contract for Coroot's declarative alert auto-suppressor.
#
# Coroot attributes the kubelet's localhost health probes for the three static
# kube-schedulers and controller managers as failed outbound TCP connections.
# The live signal is deterministic: scheduler liveness + readiness yields
# 0.6/s, while controller-manager liveness yields 0.3/s. Suppression is safe
# only while those are the complete set of active upstream series. A third
# active upstream must keep the alert visible.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly manifest="${root_dir}/k8s/providers/hetzner/infrastructure/coroot/cron-job-alert-autosuppressor.yaml"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'ok — %s\n' "$1"
}

for tool in yq jq; do
  command -v "${tool}" >/dev/null 2>&1 || {
    printf '::error::%s is required to run this contract test.\n' "${tool}" >&2
    exit 64
  }
done

[ -f "${manifest}" ] || fail "manifest not found: ${manifest}"
script_body="$(yq eval '.spec.jobTemplate.spec.template.spec.containers[0].command[2]' "${manifest}")"
[ -n "${script_body}" ] && [ "${script_body}" != "null" ] ||
  fail "could not extract the autosuppressor script"

work_root="$(mktemp -d /tmp/tmp.XXXXXXXXXX)"
trap 'rm -rf "${work_root}"' EXIT

setup_scenario() {
  local name="$1" extra_upstream="$2"
  local dir="${work_root}/${name}"
  mkdir -p "${dir}/bin"

  cat >"${dir}/user.json" <<'JSON'
{"data":{"projects":[{"id":"95rsc5yp","name":"platform"}]}}
JSON
  cat >"${dir}/alerts.json" <<'JSON'
{"data":{"alerts":[{"id":"kubelet-probe-noise","suppressed":false,"resolved_at":null,"rule_id":"network-tcp-connections","application_id":"95rsc5yp:_:Unknown:kubelet"}]}}
JSON

  jq -cn --argjson extra "${extra_upstream}" '
    {data:{widgets:[{chart:{title:"Failed TCP connections, per second",series:(
      [
        {name:"→kube-scheduler",data:[0.6,0.6]},
        {name:"→kube-controller-manager",data:[0.3,0.3]},
        {name:"→coredns",data:[0,0]}
      ] + (if $extra then [{name:"→external:443",data:[0,0.1]}] else [] end)
    )}}]}}' >"${dir}/detail-kubelet-probe-noise.json"

  cat >"${dir}/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
dir="${SCENARIO_DIR}"
url=""
payload=""
prev=""
for arg in "$@"; do
  [ "${prev}" = "-d" ] && payload="${arg}"
  case "${arg}" in http://*) url="${arg}" ;; esac
  prev="${arg}"
done
case "${url}" in
  */api/user) cat "${dir}/user.json" ;;
  *'/alerts?limit=500') cat "${dir}/alerts.json" ;;
  */alerts/suppress)
    printf '%s' "${payload}" >"${dir}/suppressed.json"
    ;;
  */alerts/*)
    id="${url##*/}"
    cat "${dir}/detail-${id}.json"
    ;;
  *)
    printf 'unstubbed curl URL: %s\n' "${url}" >&2
    exit 1
    ;;
esac
STUB
  chmod +x "${dir}/bin/curl"
  printf '%s' "${dir}"
}

run_scenario() {
  local dir="$1"
  SCENARIO_DIR="${dir}" PATH="${dir}/bin:${PATH}" /bin/sh -c "${script_body}"
}

exact_dir="$(setup_scenario exact false)"
run_scenario "${exact_dir}" >/dev/null
[ -f "${exact_dir}/suppressed.json" ] ||
  fail "the exact kubelet health-probe series were not suppressed"
jq -e '.ids == ["kubelet-probe-noise"]' "${exact_dir}/suppressed.json" >/dev/null ||
  fail "the exact scenario suppressed the wrong alert set"
pass "exact kubelet scheduler/controller-manager probe noise is suppressed"

extra_dir="$(setup_scenario extra true)"
run_scenario "${extra_dir}" >/dev/null
[ ! -e "${extra_dir}/suppressed.json" ] ||
  fail "a kubelet alert with an additional active upstream was suppressed"
pass "an additional active upstream keeps the kubelet alert visible"

