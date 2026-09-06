#!/usr/bin/env bash
set -euo pipefail

# `kyverno test` reports a rule whose namespaceSelector matches nothing as
# "Excluded", and an Excluded result satisfies an expected `skip`. That makes the
# fixture pass VACUOUSLY if the namespace labels in values.yaml ever go missing:
# measured 2026-08-29, stripping the labels left the suite reporting 6 passed /
# 0 failed while the opt-in rules never fired once. The default-off control is
# exactly the assertion that trap disguises, so it cannot be the only gate.
#
# This gate reads the mutated resources themselves and asserts all three states
# positively, so a rule that never fires fails here even when `kyverno test` is
# green.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
policy="${repo_root}/k8s/bases/infrastructure/cluster-policies/best-practices/add-security-context.yaml"
fixtures="${repo_root}/tests/add-baseline-context/resources.yaml"
values="${repo_root}/tests/add-baseline-context/values.yaml"
out_dir="$(mktemp -d)"
trap 'rm -rf "${out_dir}"' EXIT

if ! kyverno apply "${policy}" \
  --resource "${fixtures}" \
  --values-file "${values}" \
  --output "${out_dir}" \
  --remove-color >"${out_dir}/apply.log" 2>&1; then
  echo "::error::kyverno apply failed for add-security-context"
  sed -n '1,60p' "${out_dir}/apply.log"
  exit 1
fi

fail=0
check() {
  local file="$1" expr="$2" want="$3" what="$4" got
  if [ ! -f "${out_dir}/${file}" ]; then
    echo "::error::${file} was not emitted; the fixture did not render"
    fail=1
    return
  fi
  got="$(yq "select(document_index == 0) | ${expr}" "${out_dir}/${file}")"
  if [ "${got}" != "${want}" ]; then
    echo "::error::${what}: expected '${want}', got '${got}'"
    fail=1
  fi
}

# ON state — an opted-in namespace receives both fields, pod level and on every
# container and initContainer. These are the assertions the vacuity trap hides.
check plain-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in pod did not receive fsGroupChangePolicy"
check plain-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in container did not retain an empty seLinuxOptions object"
check plain-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in initContainer did not retain an empty seLinuxOptions object"

# A pod with no initContainers at all is the common shape; the foreach over
# `spec.initContainers[]` must tolerate the field being absent rather than
# erroring, which would drop the container mutation with it.
check no-init-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "pod without initContainers did not receive fsGroupChangePolicy"
check no-init-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "pod without initContainers did not retain an empty seLinuxOptions object"

# Conditional anchors — a workload that sets its own values keeps them.
check preset-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  Always "preset fsGroupChangePolicy was overwritten"
check preset-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions.level' \
  s9 "preset container seLinuxOptions was overwritten"
check preset-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions.level' \
  s9 "preset initContainer seLinuxOptions was overwritten"

# Existing container options are complete operator choices, including an unset
# level. Preserve the object so the runtime assigns the MCS categories.
check partial-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions.level' \
  null "partial container seLinuxOptions overrode runtime level selection"
check partial-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions.user' \
  system_u "partial container seLinuxOptions lost its pre-existing user"
check partial-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions.level' \
  null "partial initContainer seLinuxOptions overrode runtime level selection"
check partial-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions.user' \
  system_u "partial initContainer seLinuxOptions lost its pre-existing user"

# OFF state — a namespace without the opt-in label is untouched. The rule ships
# default-off; if this regresses, merging it silently mutates twelve namespaces.
check unlabelled-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  null "unlabelled namespace was mutated at the pod level"
check unlabelled-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "unlabelled namespace had seLinuxOptions injected"

# A pod whose POD-level securityContext already declares SELinux options, with a
# container carrying none. A container-level seLinuxOptions REPLACES the pod-level
# struct wholesale, so injecting `level` would override the operator's level AND
# drop the sibling `user` for that container. Measured 2026-08-29 without the
# foreach precondition: the pod declared `{user: system_u, level: s9}` and the
# container came back `{level: s0}`. The first assertion below is the regression;
# the fsGroupChangePolicy one proves the fixture is processed at all, so a rule
# that silently stopped matching cannot make the other three pass vacuously.
check podlevel-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "pod-level SELinux options were overridden by a container-level injection"
check podlevel-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "pod-level SELinux options were overridden by an initContainer-level injection"
check podlevel-mutated.yaml '.spec.securityContext.seLinuxOptions.level' \
  s9 "pod-level seLinuxOptions.level was not preserved"
check podlevel-mutated.yaml '.spec.securityContext.seLinuxOptions.user' \
  system_u "pod-level seLinuxOptions.user was not preserved"
check podlevel-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "pod-level rule did not fire on the podlevel fixture"


# Partial pod options remain inherited as a whole; leave level selection to the
# runtime and preserve the operator's user. The fsGroup check prevents vacuity.
check podlevel-partial-mutated.yaml '.spec.securityContext.seLinuxOptions.level' \
  null "partial pod-level seLinuxOptions overrode runtime level selection"
check podlevel-partial-mutated.yaml '.spec.securityContext.seLinuxOptions.user' \
  system_u "partial pod-level seLinuxOptions lost its pre-existing user"
check podlevel-partial-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "container-level injection replaced the partial pod-level SELinux object"
check podlevel-partial-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "initContainer-level injection replaced the partial pod-level SELinux object"
check podlevel-partial-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "pod-level rule did not fire on the podlevel-partial fixture"

# The shape the observability namespace actually presents, measured against live
# prod 2026-09-02 before it was opted in: no pod-level securityContext SELinux
# object anywhere, and no container carrying seLinuxOptions of its own. That is
# the plain shape, so both straightforward rules must fire and the pod-scope fill
# must NOT — it requires a pre-existing pod-level object, and creating one here
# would move ownership between rules and change what the `plain` case proves.
#
# Asserted on its own fixture rather than inherited from velero/plain because the
# rollout guardrail is explicit that each namespace is proven, not assumed.
check coroot-node-agent-mutated.yaml '.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "observability pod did not receive fsGroupChangePolicy"
check coroot-node-agent-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "observability container did not retain an empty seLinuxOptions object"
check coroot-node-agent-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "observability initContainer did not retain an empty seLinuxOptions object"
check coroot-node-agent-mutated.yaml '.spec.securityContext.seLinuxOptions' \
  null "pod-scope SELinux fill created an object where the author set none"

# CONTROLLER KINDS. Kubescape scores the STORED controller spec, and the pod
# rules never reach it (this policy has no autogen rules; measured 2026-09-03
# against live prod: 0 of 15 observability and 0 of 12 longhorn-system stored
# specs carried either field after the namespaces were opted in). The
# controller-kind rules close that at the object Kubescape reads. Every state
# the pod fixtures pin is asserted again here, on the kinds the residual
# population consists of. Pod-level assertions on the templates use a different
# path per kind: `spec.template.spec` and, for CronJobs, `spec.jobTemplate`.

# ON state — the plain operator-written shape receives both fields, on the
# template and on every container and initContainer.
check operator-deploy-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in Deployment template did not receive fsGroupChangePolicy"
check operator-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in Deployment container did not retain an empty seLinuxOptions object"
check operator-deploy-mutated.yaml '.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in Deployment initContainer did not retain an empty seLinuxOptions object"
check operator-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions' \
  null "controller pod-scope SELinux fill created an object where the author set none"

# A StatefulSet without initContainers: the foreach must tolerate the absent
# field rather than dropping the container mutation with it.
check server-sts-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in StatefulSet template did not receive fsGroupChangePolicy"
check server-sts-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in StatefulSet container did not retain an empty seLinuxOptions object"

# A privileged DaemonSet, the shape Longhorn actually runs: privilege is
# untouched and the two fields are supplied beside it.
check manager-ds-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in DaemonSet template did not receive fsGroupChangePolicy"
check manager-ds-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in DaemonSet container did not retain an empty seLinuxOptions object"
check manager-ds-mutated.yaml '.spec.template.spec.containers[0].securityContext.privileged' \
  true "controller rule changed a privilege field it must not touch"

# The jobTemplate path.
check nightly-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in CronJob template did not receive fsGroupChangePolicy"
check nightly-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in CronJob container did not retain an empty seLinuxOptions object"
check nightly-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in CronJob initContainer did not retain an empty seLinuxOptions object"

# OFF state — an unlabelled namespace's controllers are untouched.
check unlabelled-deploy-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  null "unlabelled namespace Deployment was mutated at the template level"
check unlabelled-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "unlabelled namespace Deployment had seLinuxOptions injected"

# Conditional anchors — a controller that sets its own values keeps them.
check preset-deploy-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  Always "preset Deployment fsGroupChangePolicy was overwritten"
check preset-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions.level' \
  s9 "preset Deployment container seLinuxOptions was overwritten"
check preset-deploy-mutated.yaml '.spec.template.spec.initContainers[0].securityContext.seLinuxOptions.level' \
  s9 "preset Deployment initContainer seLinuxOptions was overwritten"

# The wholesale-replace guard at controller scope: a complete pod-level SELinux
# object stays the only one, and fsGroupChangePolicy still lands.
check podlevel-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "Deployment pod-level SELinux options were overridden by a container-level injection"
check podlevel-deploy-mutated.yaml '.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "Deployment pod-level SELinux options were overridden by an initContainer-level injection"
check podlevel-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions.level' \
  s9 "Deployment pod-level seLinuxOptions.level was not preserved"
check podlevel-deploy-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "controller rule did not fire on the podlevel-deploy fixture"

# Partial pod options on a controller also retain runtime level selection.
check podlevel-partial-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions.level' \
  null "partial Deployment pod-level seLinuxOptions overrode runtime level selection"
check podlevel-partial-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions.user' \
  system_u "partial Deployment pod-level seLinuxOptions lost its pre-existing user"
check podlevel-partial-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "container-level injection replaced the partial Deployment pod-level SELinux object"

# A standalone Job (CREATE-only kind) takes the template path like the others.
check oneshot-job-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "opted-in Job template did not receive fsGroupChangePolicy"
check oneshot-job-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "opted-in Job container did not retain an empty seLinuxOptions object"

# Partial CronJob pod options are inherited without adding a fixed level.
check podlevel-partial-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions.level' \
  null "partial CronJob pod-level seLinuxOptions overrode runtime level selection"
check podlevel-partial-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions.user' \
  system_u "partial CronJob pod-level seLinuxOptions lost its pre-existing user"
check podlevel-partial-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "container-level injection replaced the partial CronJob pod-level SELinux object"
check podlevel-partial-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "initContainer-level injection replaced the partial CronJob pod-level SELinux object"
check podlevel-partial-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.fsGroupChangePolicy' \
  OnRootMismatch "CronJob rule did not fire on the podlevel-partial-cronjob fixture"

# A complete pod-level object on a CronJob: preserved, containers untouched.
check podlevel-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions.level' \
  s9 "CronJob pod-level seLinuxOptions.level was not preserved"
check podlevel-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "CronJob pod-level SELinux options were overridden by a container-level injection"

# The controller rules are gated by their OWN label. A namespace carrying only
# the pod-rule label (kubescape in values.yaml) must see no controller mutation,
# or the separate rollout gate is not a gate.
check podlabel-only-deploy-mutated.yaml '.spec.template.spec.securityContext.fsGroupChangePolicy' \
  null "pod-rule label alone mutated a controller template"
check podlabel-only-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "pod-rule label alone injected seLinuxOptions into a controller"

# An explicitly empty container object is a complete override. Preserve it while
# leaving siblings that inherit the pod options untouched.
check empty-override-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "empty container-level SELinux override was not preserved (pod)"
check empty-override-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "empty initContainer-level SELinux override was not preserved (pod)"
check empty-override-mutated.yaml '.spec.containers[1].securityContext.seLinuxOptions' \
  null "a container with no override was injected beside an empty-override sibling (pod)"
check empty-override-mutated.yaml '.spec.securityContext.seLinuxOptions.level' \
  s9 "pod-level level was not preserved beside an empty container override (pod)"
check empty-override-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "empty container-level SELinux override was not preserved (Deployment)"
check empty-override-deploy-mutated.yaml '.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "empty initContainer-level SELinux override was not preserved (Deployment)"
check empty-override-deploy-mutated.yaml '.spec.template.spec.containers[1].securityContext.seLinuxOptions' \
  null "a container with no override was injected beside an empty-override sibling (Deployment)"
check empty-override-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions.level' \
  s9 "pod-level level was not preserved beside an empty container override (Deployment)"

# General namespaces must retain every other security default while preserving
# whole pod options, including empty maps, on both container paths.
check general-plain-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  '{}' "general-plain containers changed SELinux defaults or inheritance"
check general-plain-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  '{}' "general-plain initContainers changed SELinux defaults or inheritance"
check general-plain-mutated.yaml '.spec.containers[0].securityContext.allowPrivilegeEscalation' \
  false "general-plain lost independent container hardening"
check general-podlevel-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "general-podlevel containers changed SELinux defaults or inheritance"
check general-podlevel-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "general-podlevel initContainers changed SELinux defaults or inheritance"
check general-podlevel-mutated.yaml '.spec.containers[0].securityContext.allowPrivilegeEscalation' \
  false "general-podlevel lost independent container hardening"
check general-partial-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  'user: system_u' "general-partial containers changed SELinux defaults or inheritance"
check general-partial-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  'user: system_u' "general-partial initContainers changed SELinux defaults or inheritance"
check general-partial-mutated.yaml '.spec.containers[0].securityContext.allowPrivilegeEscalation' \
  false "general-partial lost independent container hardening"
check general-empty-pod-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "general-empty-pod containers changed SELinux defaults or inheritance"
check general-empty-pod-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "general-empty-pod initContainers changed SELinux defaults or inheritance"
check general-empty-pod-mutated.yaml '.spec.containers[0].securityContext.allowPrivilegeEscalation' \
  false "general-empty-pod lost independent container hardening"
check general-empty-pod-mutated.yaml '.spec.securityContext.seLinuxOptions' \
  '{}' "general-empty-pod changed explicit empty pod options"
check empty-pod-mutated.yaml '.spec.containers[0].securityContext.seLinuxOptions' \
  null "empty-pod containers changed SELinux defaults or inheritance"
check empty-pod-mutated.yaml '.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "empty-pod initContainers changed SELinux defaults or inheritance"
check empty-pod-mutated.yaml '.spec.securityContext.seLinuxOptions' \
  '{}' "empty-pod changed explicit empty pod options"
check empty-pod-deploy-mutated.yaml '.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "empty-pod-deploy containers changed SELinux defaults or inheritance"
check empty-pod-deploy-mutated.yaml '.spec.template.spec.initContainers[0].securityContext.seLinuxOptions' \
  null "empty-pod-deploy initContainers changed SELinux defaults or inheritance"
check empty-pod-deploy-mutated.yaml '.spec.template.spec.securityContext.seLinuxOptions' \
  '{}' "empty-pod-deploy changed explicit empty pod options"
check empty-pod-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.containers[0].securityContext.seLinuxOptions' \
  null "empty-pod-cronjob containers changed SELinux defaults or inheritance"
check empty-pod-cronjob-mutated.yaml '.spec.jobTemplate.spec.template.spec.securityContext.seLinuxOptions' \
  '{}' "empty-pod-cronjob changed explicit empty pod options"

# ROLLOUT INVENTORY. The rules above ship default-off, so what they actually do
# in the cluster is decided entirely by which namespaces carry the opt-in label —
# a fact no mutation fixture can see. Without this gate, widening the rollout from
# one namespace to all twelve is a one-line diff with no test signal at all, and a
# dropped label silently reverts the feature while every assertion above still
# passes. Pin the inventory so each namespace is added deliberately and reviewed.
#
# Each namespace is opted in only after its live workloads are measured to still
# start; see the rationale recorded on the namespace manifest itself.
expected_optin="kubescape,longhorn-system,observability,velero"

# grep only prefilters candidate files; yq decides, so a mention in a comment or
# in the policy that DEFINES the label cannot be counted as an opted-in namespace.
actual_optin="$(
  { grep -rl 'pod-security.devantler.tech/baseline-context' --include='*.yaml' "${repo_root}/k8s" 2>/dev/null || true; } |
    while IFS= read -r f; do
      yq -N '
        select(.kind == "Namespace" and
               .metadata.labels."pod-security.devantler.tech/baseline-context" == "enabled") |
        .metadata.name
      ' "${f}" 2>/dev/null
    done | awk 'NF' | LC_ALL=C sort -u | paste -sd, -
)"

if [ "${actual_optin}" != "${expected_optin}" ]; then
  echo "::error::baseline-context opt-in inventory changed: expected '${expected_optin}', got '${actual_optin}'"
  echo "::error::add or remove a namespace here only together with its measured rollout evidence"
  fail=1
fi

# The controller-kind rules carry their OWN opt-in label, because writing the
# fields into a stored pod template rolls the workload. Nothing is opted in yet:
# this pins the default-off state, and each namespace is added here only with the
# post-rollout read-back of its workloads recorded on the namespace manifest. The
# label alone updates nothing already stored (helm-controller does not reapply an
# unchanged template), so a flip also restarts each existing controller to backfill
# the fields and watches its owner for a reconcile loop — the procedure is spelled
# out beside the rules in add-security-context.yaml.
expected_controllers_optin=""

# `grep -rl` exits 1 when nothing matches; under pipefail that would abort the assignment
# and the gate would die before comparing against the (legitimately empty) inventory,
# so the no-match case is folded into an empty list rather than an errexit.
actual_controllers_optin="$(
  { grep -rl 'pod-security.devantler.tech/baseline-context-controllers' --include='*.yaml' "${repo_root}/k8s" 2>/dev/null || true; } |
    while IFS= read -r f; do
      yq -N '
        select(.kind == "Namespace" and
               .metadata.labels."pod-security.devantler.tech/baseline-context-controllers" == "enabled") |
        .metadata.name
      ' "${f}" 2>/dev/null
    done | awk 'NF' | LC_ALL=C sort -u | paste -sd, -
)"

if [ "${actual_controllers_optin}" != "${expected_controllers_optin}" ]; then
  echo "::error::baseline-context-controllers opt-in inventory changed: expected '${expected_controllers_optin}', got '${actual_controllers_optin}'"
  echo "::error::a namespace joins the controller rollout only together with its measured post-rollout read-back"
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi

echo "Baseline-context opt-in mutation: injected when labelled, preserved when preset, inert when not — at the pod and, behind its own label, at the controller."
