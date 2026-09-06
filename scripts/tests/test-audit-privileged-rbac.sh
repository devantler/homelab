#!/usr/bin/env bash
# A renamed/removed rule can look Excluded to kyverno test. This gate exercises
# the actual resource census and requires non-zero, exact Audit results.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
policy="${repo_root}/k8s/bases/infrastructure/cluster-policies/best-practices/audit-privileged-rbac.yaml"
grant="${repo_root}/k8s/bases/infrastructure/controllers/kyverno/cluster-role-read-rbac.yaml"
result="$(mktemp)"
trap 'rm -f "$result"' EXIT

yq -e '.spec.validationFailureAction == "Audit" and .spec.background == true' "$policy" >/dev/null
yq -e '.metadata.annotations."policies.kyverno.io/scored" == "false"' "$policy" >/dev/null
yq -o=json "$grant" | jq -e '
  .metadata.labels."rbac.kyverno.io/aggregate-to-reports-controller" == "true" and
  (.rules | length) == 1 and
  .rules[0].apiGroups == ["rbac.authorization.k8s.io"] and
  (.rules[0].resources | sort) == ["clusterroles", "roles"] and
  (.rules[0].verbs | sort) == ["get", "list", "watch"] and
  (.rules[0].resourceNames // [] | length) == 0
' >/dev/null

kyverno apply "$policy" \
  --resource "${repo_root}/tests/audit-privileged-rbac/resources.yaml" \
  --audit-warn --warn-exit-code 0 >"$result" 2>&1
if ! grep -Fq 'pass: 15, fail: 0, warn: 21, error: 0, skip: 0' "$result"; then
  cat "$result"
  echo 'RBAC Audit fixture census did not match the expected results' >&2
  exit 1
fi
echo 'RBAC Audit: 15 ordinary or inert grants pass, 21 privileged grants warn; reporting access is read-only.'
