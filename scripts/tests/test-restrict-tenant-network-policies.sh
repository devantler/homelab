#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
policy="${repo_root}/k8s/bases/infrastructure/cluster-policies/best-practices/restrict-tenant-network-policies.yaml"
tests="${repo_root}/tests/restrict-tenant-network-policies"
output_file="$(mktemp)"
trap 'rm -f "${output_file}"' EXIT

# `kyverno test` treats a rule that matches nothing as Excluded, and an Excluded
# row satisfies `result: fail` too — so the declarative test can pass vacuously
# if a rule silently stops matching. Exercise the policy directly as a second
# gate, asserting the exact allow/deny counts rather than an exit code.
apply() {
  local resources="$1" values="$2" userinfo="$3"
  kyverno apply "${policy}" \
    --resource "${resources}" \
    --values-file "${values}" \
    --userinfo "${userinfo}" \
    --remove-color >"${output_file}" 2>&1 || true
}

expect_summary() {
  local expected="$1" what="$2"
  if ! grep -Fq "${expected}" "${output_file}"; then
    echo "::error::${what}: expected '${expected}'"
    sed -n '1,80p' "${output_file}"
    exit 1
  fi
}

# 1. The tenant fixture set: 45 boundary-dissolving shapes denied, the ordinary
#    additive allow-lists admitted. A drop in the fail count means a shape that
#    used to be refused now admits.
apply "${tests}/resources.yaml" "${tests}/values.yaml" "${tests}/user-info.yaml"
expect_summary "pass: 185, fail: 45, warn: 0, error: 0, skip: 0" \
  "tenant CiliumNetworkPolicy boundary"

# 2. Carve-out: kyverno's background controller owns the generated floor. These
#    are the verbatim generated bodies and both carry a reserved name, so a
#    regression here would block the platform from creating its own default-deny.
apply "${tests}/kyverno-author/resources.yaml" \
  "${tests}/kyverno-author/values.yaml" "${tests}/kyverno-author/user-info.yaml"
expect_summary "pass: 0, fail: 0, warn: 0, error: 0, skip: 0" \
  "generated default-deny/allow-dns must remain creatable by kyverno"

# 3. CONTROL for 2: the identical bodies, in the identical namespace, submitted
#    by the TENANT. Only the applying identity differs. Without this the zero
#    above is indistinguishable from the policy simply not matching. Both bodies
#    fail the reserved-name rule; allow-dns ALSO fails the egress rule, because
#    it reaches CoreDNS by naming kube-system through the namespace label — the
#    cross-namespace selector a tenant is refused (#3399). The generated floor
#    is exempt from that only through its applying identity, which is the point.
apply "${tests}/kyverno-author/resources.yaml" \
  "${tests}/kyverno-author/values.yaml" "${tests}/user-info.yaml"
expect_summary "pass: 7, fail: 3, warn: 0, error: 0, skip: 0" \
  "control: a tenant must NOT be able to author the reserved generated names"

# 4. Carve-out: platform-authored policies applied by flux-system's
#    kustomize-controller stay permitted even when broad.
apply "${tests}/platform-author/resources.yaml" \
  "${tests}/platform-author/values.yaml" "${tests}/platform-author/user-info.yaml"
expect_summary "pass: 0, fail: 0, warn: 0, error: 0, skip: 0" \
  "platform-authored policies must stay permitted"

# 5. CONTROL for 4: the identical broad body submitted by the TENANT is refused
#    by both the ingress and the egress rule.
apply "${tests}/platform-author/resources.yaml" \
  "${tests}/platform-author/values.yaml" "${tests}/user-info.yaml"
expect_summary "pass: 2, fail: 2, warn: 0, error: 0, skip: 0" \
  "control: a tenant must NOT be able to submit the broad platform body"

# 6. Static action guard. Every count above is a RULE result; none of them says
#    what admission actually does on a violation. Enforcement lives in each
#    rule's own `failureAction`, because the deprecated top-level
#    spec.validationFailureAction defaults an action-less rule to Audit — which
#    would admit every shape the counts above prove is "denied", with the whole
#    suite still green. Assert the action itself, not just the verdicts.
rule_count="$(yq '.spec.rules | length' "${policy}")"
enforced="$(yq '[.spec.rules[] | select(.validate.failureAction == "Enforce")] | length' "${policy}")"
top_level="$(yq '.spec.validationFailureAction // "absent"' "${policy}")"
if [[ "${rule_count}" -lt 1 ]]; then
  echo "::error::no rules found in ${policy}"
  exit 1
fi
if [[ "${enforced}" != "${rule_count}" ]]; then
  echo "::error::only ${enforced}/${rule_count} rules set validate.failureAction: Enforce"
  exit 1
fi
if [[ "${top_level}" != "absent" ]]; then
  echo "::error::spec.validationFailureAction is deprecated; enforcement must be rule-level"
  exit 1
fi

echo "Tenant CiliumNetworkPolicy policy enforced the expected boundary, and both"
echo "platform carve-outs were proven to depend on the applying identity."
