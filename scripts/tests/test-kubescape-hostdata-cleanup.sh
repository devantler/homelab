#!/usr/bin/env bash

# Contract for the Kubescape host-data cleanup Job (#3686).
#
# Node-agent names every cluster-scoped host-data object after the Kubernetes
# Node it sensed, but upstream v0.3.142 assigns no owner reference and performs
# no deletion. Autoscaler churn therefore leaves stale host inventories behind.
# This test executes the script extracted from the manifest against a kubectl
# stub, so the fail-closed inventory gate and exact deletion behavior cannot
# drift independently from the deployed Job.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly base="${root_dir}/k8s/bases/infrastructure/controllers/kubescape"
readonly manifest="${base}/cron-job-hostdata-cleanup.yaml"
readonly role="${base}/cluster-role-hostdata-cleanup.yaml"
readonly binding="${base}/cluster-role-binding-hostdata-cleanup.yaml"
readonly service_account="${base}/service-account-hostdata-cleanup.yaml"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'ok: %s\n' "$1"
}

command -v yq >/dev/null 2>&1 || fail 'yq is required'
for file in "$manifest" "$role" "$binding" "$service_account"; do
  [ -f "$file" ] || fail "manifest not found: $file"
done

readonly container='.spec.jobTemplate.spec.template.spec.containers[] | select(.name == "cleanup")'
script_body="$(yq eval -r "${container}.command[2]" "$manifest")"
if [ -z "$script_body" ] || [ "$script_body" = 'null' ]; then
  fail 'cleanup script is absent'
fi

[ "$(yq eval '.spec.concurrencyPolicy' "$manifest")" = 'Forbid' ] || fail 'concurrent runs are not forbidden'
[ "$(yq eval '.spec.jobTemplate.spec.backoffLimit' "$manifest")" = '0' ] || fail 'Job retries must stay with the authored API retry loop'
[ "$(yq eval '.spec.jobTemplate.spec.template.spec.automountServiceAccountToken' "$manifest")" = 'true' ] || fail 'kubectl Job has no service-account token'
[ "$(yq eval "${container}.securityContext.readOnlyRootFilesystem" "$manifest")" = 'true' ] || fail 'cleanup filesystem is writable'
[ "$(yq eval "${container}.securityContext.allowPrivilegeEscalation" "$manifest")" = 'false' ] || fail 'cleanup permits privilege escalation'
[ "$(yq eval "${container}.env[] | select(.name == \"DRY_RUN\") | .value" "$manifest")" = 'false' ] || fail 'scheduled reconciliation is not enabled'
pass 'CronJob execution and hardening contract is present'

expected_resources='cloudproviderinfos
cniinfos
controlplaneinfos
kernelversions
kubeletinfos
kubeproxyinfos
linuxkernelvariables
linuxsecurityhardeningstatuses
openportslists
osreleasefiles'
actual_resources="$(yq eval -r '.rules[] | select(.apiGroups[] == "hostdata.kubescape.cloud") | .resources[]' "$role" | sort)"
[ "$actual_resources" = "$expected_resources" ] || fail "host-data RBAC resource set drifted: $actual_resources"
[ "$(yq eval -I=0 -o=json '.rules[] | select(.apiGroups[] == "hostdata.kubescape.cloud") | .verbs' "$role")" = '["list","delete"]' ] || fail 'host-data RBAC must be exactly list/delete'
[ "$(yq eval -I=0 -o=json '.rules[] | select(.apiGroups[] == "") | .resources' "$role")" = '["nodes"]' ] || fail 'core RBAC must target only Nodes'
[ "$(yq eval -I=0 -o=json '.rules[] | select(.apiGroups[] == "") | .verbs' "$role")" = '["list"]' ] || fail 'Node RBAC must be list-only'
[ "$(yq eval '.roleRef.name' "$binding")" = 'kubescape-hostdata-cleanup' ] || fail 'binding targets the wrong role'
[ "$(yq eval '.subjects[0].name' "$binding")" = 'kubescape-hostdata-cleanup' ] || fail 'binding targets the wrong service account'
pass 'cleanup identity has only Node list and host-data list/delete access'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '%s\n' "$script_body" >"$work/cleanup.sh"
chmod +x "$work/cleanup.sh"

cat >"$work/kubectl" <<'STUB'
#!/bin/sh
set -eu
if [ "$1" = 'get' ] && [ "$2" = 'nodes' ]; then
  case "${MODE:-healthy}" in
    node-empty) exit 0 ;;
    node-fail) exit 1 ;;
    *) printf 'active-1\nactive-2\n'; exit 0 ;;
  esac
fi
if [ "$1" = 'get' ]; then
  if [ "${MODE:-healthy}" = 'list-fail' ] && [ "$2" = 'cniinfos.hostdata.kubescape.cloud' ]; then
    exit 1
  fi
  case "$2" in
    osreleasefiles.hostdata.kubescape.cloud) printf 'active-1\nstale-1\n' ;;
    *) printf 'active-1\n' ;;
  esac
  exit 0
fi
if [ "$1" = 'delete' ]; then
  printf '%s\n' "$*" >>"${DELETE_LOG:?}"
  exit 0
fi
exit 1
STUB
cat >"$work/sleep" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$work/kubectl" "$work/sleep"

run_case() {
  local mode="$1" dry_run="$2" output="$3" deletes="$4"
  : >"$deletes"
  PATH="$work:$PATH" MODE="$mode" DRY_RUN="$dry_run" DELETE_LOG="$deletes" sh "$work/cleanup.sh" >"$output" 2>&1
}

run_case healthy true "$work/dry.out" "$work/dry.deletes"
[ ! -s "$work/dry.deletes" ] || fail 'dry-run issued a delete'
grep -q 'ORPHAN osreleasefiles.hostdata.kubescape.cloud/stale-1' "$work/dry.out" || fail 'dry-run did not classify the stale fixture'
grep -q '\[dry-run\] would delete' "$work/dry.out" || fail 'dry-run did not state its decision'
pass 'dry-run classifies the stale fixture without mutation'

run_case healthy false "$work/live.out" "$work/live.deletes"
[ "$(wc -l <"$work/live.deletes" | tr -d ' ')" = '1' ] || fail 'enabled run did not issue exactly one deletion'
grep -qx 'delete osreleasefiles.hostdata.kubescape.cloud stale-1 --ignore-not-found' "$work/live.deletes" || fail 'enabled run deleted anything beyond the exact stale fixture'
pass 'enabled run deletes only a resource whose identically named Node is absent'

for mode in node-empty node-fail list-fail; do
  : >"$work/${mode}.deletes"
  if PATH="$work:$PATH" MODE="$mode" DRY_RUN=false DELETE_LOG="$work/${mode}.deletes" sh "$work/cleanup.sh" >"$work/${mode}.out" 2>&1; then
    fail "$mode inventory fault did not stop the cleanup"
  fi
  [ ! -s "$work/${mode}.deletes" ] || fail "$mode inventory fault allowed a partial deletion"
done
grep -q 'Node list is empty' "$work/node-empty.out" || fail 'empty Node inventory has no explicit refusal'
grep -q 'failed to list Kubernetes Nodes' "$work/node-fail.out" || fail 'failed Node inventory has no explicit refusal'
grep -q 'failed to list cniinfos.hostdata.kubescape.cloud' "$work/list-fail.out" || fail 'failed host-data inventory has no explicit refusal'
pass 'all authoritative inventories are acquired before deletion and failures stop closed'

grep -qx '  - cron-job-hostdata-cleanup.yaml' "${base}/kustomization.yaml" || fail 'CronJob is absent from the Kubescape kustomization'
grep -qx '  - cluster-role-hostdata-cleanup.yaml' "${base}/kustomization.yaml" || fail 'ClusterRole is absent from the Kubescape kustomization'
grep -q 'test-kubescape-hostdata-cleanup.sh' "${root_dir}/.github/workflows/ci.yaml" || fail 'contract test is not wired into CI'
pass 'cleanup resources and contract test are wired into delivery'

printf '\nAll Kubescape host-data cleanup assertions passed.\n'
