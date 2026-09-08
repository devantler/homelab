#!/usr/bin/env bash
# Assert every event and deployment route invokes the nested-RGD behavioral gate. This script is
# run from the unconditional changes job, independently of the PR validation step it protects.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly CI_WORKFLOW="${RGD_WIRING_CI_WORKFLOW:-${REPO_ROOT}/.github/workflows/ci.yaml}"
readonly MAIN_WORKFLOW="${RGD_WIRING_MAIN_WORKFLOW:-${REPO_ROOT}/.github/workflows/validate-main.yaml}"
readonly CD_WORKFLOW="${RGD_WIRING_CD_WORKFLOW:-${REPO_ROOT}/.github/workflows/cd.yaml}"
readonly DR_WORKFLOW="${RGD_WIRING_DR_WORKFLOW:-${REPO_ROOT}/.github/workflows/dr-rebuild.yaml}"
readonly SETUP_TRIVY="aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567"
readonly BEHAVIORAL_RUN=$'shellcheck scripts/scan-rgd-templates.sh scripts/tests/test-rgd-template-static-scan.sh\nbash scripts/tests/test-rgd-template-static-scan.sh\n'
readonly WIRING_RUN=$'shellcheck scripts/tests/test-rgd-template-static-scan-wiring.sh\nbash scripts/tests/test-rgd-template-static-scan-wiring.sh\n'

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

command -v yq >/dev/null 2>&1 || fail "yq is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"

ci_workflow_json="$(yq -o=json -I=0 '.' "$CI_WORKFLOW")"
main_workflow_json="$(yq -o=json -I=0 '.' "$MAIN_WORKFLOW")"
cd_workflow_json="$(yq -o=json -I=0 '.' "$CD_WORKFLOW")"
dr_workflow_json="$(yq -o=json -I=0 '.' "$DR_WORKFLOW")"
k8s_filter_json="$(yq -o=json -I=0 '
  (.jobs.changes.steps[] | select(.id == "filter").with.filters) |
  from_yaml | .k8s
' "$CI_WORKFLOW")"

jq -e --arg wiring_run "$WIRING_RUN" '
  .jobs.changes as $wiring_job
  | (($wiring_job["continue-on-error"] // false) == false)
  and ($wiring_job | has("if") | not)
  and any($wiring_job.steps[];
    (.run // "") == $wiring_run
    and ((.["continue-on-error"] // false) == false)
    and (has("if") | not))
' <<<"$ci_workflow_json" >/dev/null ||
  fail "the unconditional changes job does not independently validate RGD workflow wiring"

jq -e --argjson required_inputs '[
    ".trivy/data/**",
    "scripts/scan-rgd-templates.sh",
    "scripts/rgd-template-static-scan-baseline.tsv",
    "scripts/rgd-template-static-scan-remote-resources.tsv",
    "scripts/tests/test-rgd-template-static-scan.sh",
    "scripts/tests/test-rgd-template-static-scan-wiring.sh"
  ]' '
  . as $k8s_filter
  | (($k8s_filter | type) == "array")
  and ([$required_inputs[] as $input |
    ($k8s_filter | index($input)) != null] | all)
' <<<"$k8s_filter_json" >/dev/null ||
  fail "ci.yaml does not route every RGD gate input through k8s validation"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" '
  .jobs.validate as $gate
  | (($gate.if // "") ==
      "github.event_name == '\''pull_request'\'' && (needs.changes.outputs.k8s == '\''true'\'' || needs.changes.outputs.bridge_validation == '\''true'\'')")
  and (($gate["continue-on-error"] // false) == false)
  and any($gate.steps[];
      (.uses // "") == $setup and .with.version == "v0.74.0")
  and any($gate.steps[];
      (.run // "") == $behavior_run
      and ((.["continue-on-error"] // false) == false)
      and ((.if // "") == "needs.changes.outputs.k8s == '\''true'\''"))
' <<<"$ci_workflow_json" >/dev/null ||
  fail "the pull-request validate job does not run the pinned RGD behavioral gate"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" '
  .jobs["validate-rgd-templates-merge-group"] as $gate
  | (($gate.if // "") ==
      "github.event_name == '\''merge_group'\'' && needs.changes.outputs.k8s == '\''true'\''")
  and (($gate["continue-on-error"] // false) == false)
  and (($gate.needs | if type == "array" then . else [.] end) | index("changes") != null)
  and any($gate.steps[];
      (.uses // "") == $setup and .with.version == "v0.74.0")
  and any($gate.steps[];
      (.run // "") == $behavior_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
  and ((.jobs["deploy-prod"].needs | if type == "array" then . else [.] end)
      | index("validate-rgd-templates-merge-group") != null)
  and ((.jobs["ci-required-checks"].needs | if type == "array" then . else [.] end)
      | index("validate-rgd-templates-merge-group") != null)
' <<<"$ci_workflow_json" >/dev/null ||
  fail "ci.yaml does not gate merge-group deployment on the exact RGD behavioral scan"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" '
  .jobs["heal-prod-on-failure"] as $heal
  | ($heal.steps | map(select((.uses // "") | startswith("actions/checkout@"))) | map(.with.ref // "") | index("main")) as $main_checkout
  | ($heal.steps | map(.uses // "") | index($setup)) as $setup_index
  | ($heal.steps | map(.run // "") | index($behavior_run)) as $scan_index
  | ($heal.steps | map(.uses // "") | index("./.github/actions/deploy-prod")) as $deploy_index
  | ($heal != null)
  and (($heal["continue-on-error"] // false) == false)
  and ($main_checkout != null)
  and ($setup_index != null and $scan_index != null and $deploy_index != null)
  and ($setup_index < $scan_index and $scan_index < $deploy_index)
  and ($heal.steps[$setup_index].with.version == "v0.74.0")
  and (($heal.steps[$scan_index]["continue-on-error"] // false) == false)
  and ($heal.steps[$scan_index] | has("if") | not)
' <<<"$ci_workflow_json" >/dev/null ||
  fail "ci.yaml does not rescan the current main checkout before a heal deployment"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" '
  .jobs["validate-rgd-templates"] as $gate
  | (($gate["continue-on-error"] // false) == false)
  and ($gate | has("if") | not)
  and any($gate.steps[];
      (.uses // "") == $setup and .with.version == "v0.74.0")
  and any($gate.steps[];
      (.run // "") == $behavior_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
' <<<"$main_workflow_json" >/dev/null ||
  fail "validate-main.yaml does not run the pinned RGD behavioral gate"

jq -e --arg wiring_run "$WIRING_RUN" '
  any(
    .jobs | to_entries[];
    .key != "validate-rgd-templates"
    and ((.value["continue-on-error"] // false) == false)
    and (.value | has("if") | not)
    and any(.value.steps[]?;
      (.run // "") == $wiring_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
  )
' <<<"$main_workflow_json" >/dev/null ||
  fail "the direct-main route does not independently protect the RGD gate from self-removal"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" \
  --arg wiring_run "$WIRING_RUN" '
  .jobs["validate-rgd-templates"] as $gate
  | .jobs["validate-pvc-prune-safety"] as $wiring_job
  | ($gate != null)
  and (($gate["continue-on-error"] // false) == false)
  and ($gate | has("if") | not)
  and any($gate.steps[];
      (.uses // "") == $setup and .with.version == "v0.74.0")
  and any($gate.steps[];
      (.run // "") == $behavior_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
  and (($wiring_job["continue-on-error"] // false) == false)
  and ($wiring_job | has("if") | not)
  and any($wiring_job.steps[];
      (.run // "") == $wiring_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
  and ((.jobs["validate-eks-authorization"].needs |
      if type == "array" then . else [.] end) |
    index("validate-rgd-templates") != null
    and index("validate-pvc-prune-safety") != null)
  and ((.jobs["deploy-prod"].needs |
      if type == "array" then . else [.] end) |
    index("validate-eks-authorization") != null)
' <<<"$cd_workflow_json" >/dev/null ||
  fail "cd.yaml does not gate manual production dispatches on the exact RGD behavioral scan"

jq -e --arg setup "$SETUP_TRIVY" --arg behavior_run "$BEHAVIORAL_RUN" \
  --arg wiring_run "$WIRING_RUN" '
  .jobs.rebuild as $gate
  | .jobs["supersession-gate"] as $wiring_job
  | ($gate.steps | map(.run // "") | index($behavior_run)) as $scan_index
  | ($gate.steps | map((.run // "") | contains("cluster create")) | index(true)) as $create_index
  | ($gate != null)
  and (($gate["continue-on-error"] // false) == false)
  and any($gate.steps[];
      (.uses // "") == $setup and .with.version == "v0.74.0")
  and ($scan_index != null and $create_index != null and $scan_index < $create_index)
  and (($gate.steps[$scan_index]["continue-on-error"] // false) == false)
  and ($gate.steps[$scan_index] | has("if") | not)
  and (($wiring_job["continue-on-error"] // false) == false)
  and ($wiring_job | has("if") | not)
  and any($wiring_job.steps[];
      (.run // "") == $wiring_run
      and ((.["continue-on-error"] // false) == false)
      and (has("if") | not))
' <<<"$dr_workflow_json" >/dev/null ||
  fail "dr-rebuild.yaml does not gate from-zero deployment on the exact RGD behavioral scan"

if [ "${RGD_WIRING_SKIP_ABLATIONS:-false}" != "true" ]; then
  ablation_work="$(mktemp -d)"
  trap 'rm -rf "$ablation_work"' EXIT

  suppressed_wiring_step_workflow="${ablation_work}/ci-wiring-step-continue-on-error.yaml"
  cp "$CI_WORKFLOW" "$suppressed_wiring_step_workflow"
  yq -i '(.jobs.changes.steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan-wiring.sh"))).continue-on-error = true' \
    "$suppressed_wiring_step_workflow"
  if RGD_WIRING_CI_WORKFLOW="$suppressed_wiring_step_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/wiring-step-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed independent wiring step"
  fi

  conditional_wiring_step_workflow="${ablation_work}/ci-wiring-step-false-condition.yaml"
  cp "$CI_WORKFLOW" "$conditional_wiring_step_workflow"
  yq -i '(.jobs.changes.steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan-wiring.sh"))).if = false' \
    "$conditional_wiring_step_workflow"
  if RGD_WIRING_CI_WORKFLOW="$conditional_wiring_step_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/wiring-step-false-condition.log" 2>&1; then
    fail "the wiring validator accepted a conditionally skipped independent wiring step"
  fi

  suppressed_wiring_job_workflow="${ablation_work}/ci-wiring-job-continue-on-error.yaml"
  cp "$CI_WORKFLOW" "$suppressed_wiring_job_workflow"
  yq -i '.jobs.changes.continue-on-error = true' "$suppressed_wiring_job_workflow"
  if RGD_WIRING_CI_WORKFLOW="$suppressed_wiring_job_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/wiring-job-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed independent wiring job"
  fi

  conditional_wiring_job_workflow="${ablation_work}/ci-wiring-job-false-condition.yaml"
  cp "$CI_WORKFLOW" "$conditional_wiring_job_workflow"
  yq -i '.jobs.changes.if = false' "$conditional_wiring_job_workflow"
  if RGD_WIRING_CI_WORKFLOW="$conditional_wiring_job_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/wiring-job-false-condition.log" 2>&1; then
    fail "the wiring validator accepted a conditionally skipped independent wiring job"
  fi

  suppressed_heal_scan_workflow="${ablation_work}/ci-heal-rgd-continue-on-error.yaml"
  cp "$CI_WORKFLOW" "$suppressed_heal_scan_workflow"
  yq -i '(.jobs."heal-prod-on-failure".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).continue-on-error = true' \
    "$suppressed_heal_scan_workflow"
  if RGD_WIRING_CI_WORKFLOW="$suppressed_heal_scan_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/heal-rgd-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed current-main heal scan"
  fi

  missing_heal_scan_workflow="${ablation_work}/ci-heal-rgd-missing.yaml"
  cp "$CI_WORKFLOW" "$missing_heal_scan_workflow"
  yq -i 'del(.jobs."heal-prod-on-failure".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh")))' \
    "$missing_heal_scan_workflow"
  if RGD_WIRING_CI_WORKFLOW="$missing_heal_scan_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/heal-rgd-missing.log" 2>&1; then
    fail "the wiring validator accepted removal of the current-main heal scan"
  fi

  suppressed_cd_workflow="${ablation_work}/cd-rgd-continue-on-error.yaml"
  cp "$CD_WORKFLOW" "$suppressed_cd_workflow"
  yq -i '(.jobs."validate-rgd-templates".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).continue-on-error = true' \
    "$suppressed_cd_workflow"
  if RGD_WIRING_CI_WORKFLOW="$CI_WORKFLOW" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_CD_WORKFLOW="$suppressed_cd_workflow" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/cd-rgd-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed manual-CD RGD scan"
  fi

  suppressed_cd_wiring_workflow="${ablation_work}/cd-rgd-wiring-continue-on-error.yaml"
  cp "$CD_WORKFLOW" "$suppressed_cd_wiring_workflow"
  yq -i '(.jobs."validate-pvc-prune-safety".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan-wiring.sh"))).continue-on-error = true' \
    "$suppressed_cd_wiring_workflow"
  if RGD_WIRING_CI_WORKFLOW="$CI_WORKFLOW" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_CD_WORKFLOW="$suppressed_cd_wiring_workflow" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/cd-rgd-wiring-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed manual-CD wiring check"
  fi

  detached_cd_workflow="${ablation_work}/cd-rgd-detached.yaml"
  cp "$CD_WORKFLOW" "$detached_cd_workflow"
  yq -i '.jobs."validate-eks-authorization".needs = ["validate-pvc-prune-safety"]' \
    "$detached_cd_workflow"
  if RGD_WIRING_CI_WORKFLOW="$CI_WORKFLOW" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_CD_WORKFLOW="$detached_cd_workflow" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/cd-rgd-detached.log" 2>&1; then
    fail "the wiring validator accepted a manual-CD RGD scan detached from deployment"
  fi

  suppressed_dr_workflow="${ablation_work}/dr-rgd-continue-on-error.yaml"
  cp "$DR_WORKFLOW" "$suppressed_dr_workflow"
  yq -i '(.jobs.rebuild.steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).continue-on-error = true' \
    "$suppressed_dr_workflow"
  if RGD_WIRING_DR_WORKFLOW="$suppressed_dr_workflow" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/dr-rgd-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed DR rebuild RGD scan"
  fi

  suppressed_workflow="${ablation_work}/ci-continue-on-error.yaml"
  cp "$CI_WORKFLOW" "$suppressed_workflow"
  yq -i '(.jobs."validate-rgd-templates-merge-group".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).continue-on-error = true' \
    "$suppressed_workflow"
  if RGD_WIRING_CI_WORKFLOW="$suppressed_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed merge-group RGD scan"
  fi

  suppressed_job_workflow="${ablation_work}/ci-job-continue-on-error.yaml"
  cp "$CI_WORKFLOW" "$suppressed_job_workflow"
  yq -i '.jobs."validate-rgd-templates-merge-group".continue-on-error = true' \
    "$suppressed_job_workflow"
  if RGD_WIRING_CI_WORKFLOW="$suppressed_job_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/job-continue-on-error.log" 2>&1; then
    fail "the wiring validator accepted a failure-suppressed merge-group RGD job"
  fi

  conditional_workflow="${ablation_work}/ci-false-condition.yaml"
  cp "$CI_WORKFLOW" "$conditional_workflow"
  yq -i '(.jobs."validate-rgd-templates-merge-group".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).if = false' \
    "$conditional_workflow"
  if RGD_WIRING_CI_WORKFLOW="$conditional_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/false-condition.log" 2>&1; then
    fail "the wiring validator accepted a conditionally skipped merge-group RGD scan"
  fi

  conditional_job_workflow="${ablation_work}/ci-false-job-condition.yaml"
  cp "$CI_WORKFLOW" "$conditional_job_workflow"
  yq -i '.jobs."validate-rgd-templates-merge-group".if = false' "$conditional_job_workflow"
  if RGD_WIRING_CI_WORKFLOW="$conditional_job_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/false-job-condition.log" 2>&1; then
    fail "the wiring validator accepted a conditionally skipped merge-group RGD job"
  fi

  shell_suppressed_workflow="${ablation_work}/ci-shell-suppressed.yaml"
  cp "$CI_WORKFLOW" "$shell_suppressed_workflow"
  yq -i '(.jobs."validate-rgd-templates-merge-group".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).run += " || true"' \
    "$shell_suppressed_workflow"
  if RGD_WIRING_CI_WORKFLOW="$shell_suppressed_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/shell-suppressed.log" 2>&1; then
    fail "the wiring validator accepted a shell-suppressed merge-group RGD scan"
  fi

  echoed_command_workflow="${ablation_work}/ci-echoed-command.yaml"
  cp "$CI_WORKFLOW" "$echoed_command_workflow"
  yq -i '(.jobs."validate-rgd-templates-merge-group".steps[] |
    select((.run // "") | contains("bash scripts/tests/test-rgd-template-static-scan.sh"))).run =
    "echo bash scripts/tests/test-rgd-template-static-scan.sh"' "$echoed_command_workflow"
  if RGD_WIRING_CI_WORKFLOW="$echoed_command_workflow" \
    RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
    RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/echoed-command.log" 2>&1; then
    fail "the wiring validator accepted an echoed merge-group RGD scan command"
  fi

  required_filter_inputs=(
    ".trivy/data/**"
    "scripts/scan-rgd-templates.sh"
    "scripts/rgd-template-static-scan-baseline.tsv"
    "scripts/tests/test-rgd-template-static-scan.sh"
    "scripts/tests/test-rgd-template-static-scan-wiring.sh"
  )
  filter_ablation_index=0
  for filter_input in "${required_filter_inputs[@]}"; do
    filter_ablation_index=$((filter_ablation_index + 1))
    filtered_workflow="${ablation_work}/ci-filter-${filter_ablation_index}.yaml"
    cp "$CI_WORKFLOW" "$filtered_workflow"
    FILTER_INPUT="$filter_input" yq -i \
      '(.jobs.changes.steps[] | select(.id == "filter").with.filters) |=
        (split("\n") | map(select(contains(strenv(FILTER_INPUT)) | not)) | join("\n"))' \
      "$filtered_workflow"
    if RGD_WIRING_CI_WORKFLOW="$filtered_workflow" \
      RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
      RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/filter-${filter_ablation_index}.log" 2>&1; then
      fail "the wiring validator accepted removal of required RGD filter input: $filter_input"
    fi

    relocated_workflow="${ablation_work}/ci-filter-relocated-${filter_ablation_index}.yaml"
    cp "$CI_WORKFLOW" "$relocated_workflow"
    FILTER_INPUT="$filter_input" yq -i \
      '(.jobs.changes.steps[] | select(.id == "filter").with.filters) |=
        (from_yaml |
          .k8s = (.k8s | map(select(. != strenv(FILTER_INPUT)))) |
          .bridge_validation += [strenv(FILTER_INPUT)] |
          to_yaml)' \
      "$relocated_workflow"
    if RGD_WIRING_CI_WORKFLOW="$relocated_workflow" \
      RGD_WIRING_MAIN_WORKFLOW="$MAIN_WORKFLOW" \
      RGD_WIRING_SKIP_ABLATIONS=true "$0" >"${ablation_work}/filter-relocated-${filter_ablation_index}.log" 2>&1; then
      fail "the wiring validator accepted a required RGD input outside the k8s filter: $filter_input"
    fi
  done
fi

echo "PASS: PR, merge-group, failure-heal, direct-main, manual-CD, and DR routes retain the nested-RGD behavioral gate."
