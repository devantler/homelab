#!/usr/bin/env bash

# Pin the behaviour of scripts/probe-image-signature-enforcement.sh.
#
# WHY THIS EXISTS. The probe reports on a security control, and two of its
# possible mistakes are silent:
#
#   * calling a result a PASS when nothing was actually verified — the cached-ref
#     case, where a pull that performed no verification looks like a success; and
#   * calling an ambiguous result a FAIL — an unmatched ref, or a refusal that had
#     nothing to do with signatures, reported as broken enforcement.
#
# The first is a false all-clear on supply-chain enforcement. The second is a
# false alarm that spends the "something broke" signal. So the cases below pin
# BOTH directions of every verdict, and the three exit statuses are pinned
# separately: 0 PASS, 1 FAIL (enforcement is not refusing), 3 INCONCLUSIVE
# (no statement made). A probe that can only ever say PASS is worthless, and one
# that collapses INCONCLUSIVE into either neighbour is misleading.
#
# Needs no cluster and no secrets: talosctl is faked from fixtures, so this gates
# every PR that touches the probe.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly script="${root_dir}/scripts/probe-image-signature-enforcement.sh"

work_dir="$(mktemp -d)"
readonly work_dir
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

readonly fake_bin="${work_dir}/bin"
readonly fixtures="${work_dir}/fixtures"
mkdir -p "${fake_bin}" "${fixtures}"

readonly node='10.0.0.1'
readonly owner='security.ImageVerificationConfigController'
readonly unsigned='ghcr.io/devantler-tech/probe-throwaway-unsigned:t1'
readonly signed='ghcr.io/devantler-tech/ksail:v1.2.3'

cases_run=0

fail() {
  printf '\nFAIL: %s\n' "$1" >&2
  exit 1
}

require_text() {
  local haystack="$1" needle="$2" what="$3"
  printf '%s' "${haystack}" | grep -qF -- "${needle}" ||
    fail "${what}: expected output to contain '${needle}'. Got: ${haystack}"
}

refute_text() {
  local haystack="$1" needle="$2" what="$3"
  printf '%s' "${haystack}" | grep -qF -- "${needle}" &&
    fail "${what}: expected output NOT to contain '${needle}'. Got: ${haystack}"
  return 0
}

# ---------------------------------------------------------------------------
# Fake talosctl. Mirrors the five call shapes the probe makes, and nothing else:
# `ls /` for reachability, `get <type> -o json` for the rules, and
# `image list|pull|remove --namespace cri`. Per-ref pull behaviour is staged as
# files so one case can make the negative control refuse while the positive one
# succeeds. Every removal is appended to `removed.txt`, which is how the cleanup
# cases assert that the probe removed exactly what it pulled and nothing else.
# ---------------------------------------------------------------------------
cat >"${fake_bin}/talosctl" <<'FAKE'
#!/usr/bin/env bash
set -uo pipefail
fixtures="${FAKE_FIXTURES}"

# Strip the leading `-n <node>`, which every real call carries.
if [[ "${1:-}" == "-n" ]]; then
  shift 2
fi

verb="${1:-}"
shift || true

ref_key() {
  printf '%s' "$1" | tr '/:@' '___'
}

case "${verb}" in
  ls)
    [[ -e "${fixtures}/unreachable" ]] && exit 1
    exit 0
    ;;
  get)
    [[ -e "${fixtures}/unreachable" ]] && exit 1
    [[ -e "${fixtures}/rules_query_fails" ]] && exit 1
    if [[ -e "${fixtures}/rules.json" ]]; then
      cat "${fixtures}/rules.json"
    fi
    exit 0
    ;;
  image)
    sub="${1:-}"
    shift || true
    # Drop `--namespace <ns>`.
    if [[ "${1:-}" == "--namespace" ]]; then
      shift 2
    fi
    case "${sub}" in
      list)
        [[ -e "${fixtures}/imagelist_fails" ]] && exit 1
        if [[ -e "${fixtures}/imagelist.txt" ]]; then
          cat "${fixtures}/imagelist.txt"
        fi
        exit 0
        ;;
      pull)
        ref="${1:-}"
        key="$(ref_key "${ref}")"
        printf '%s\n' "${ref}" >>"${fixtures}/pulled.txt"
        if [[ -e "${fixtures}/pullout_${key}" ]]; then
          cat "${fixtures}/pullout_${key}"
        fi
        if [[ -e "${fixtures}/pullrc_${key}" ]]; then
          exit "$(cat "${fixtures}/pullrc_${key}")"
        fi
        exit 0
        ;;
      remove)
        ref="${1:-}"
        printf '%s\n' "${ref}" >>"${fixtures}/removed.txt"
        exit 0
        ;;
    esac
    exit 64
    ;;
esac
printf 'fake talosctl: unexpected call: %s %s\n' "${verb}" "$*" >&2
exit 64
FAKE
chmod +x "${fake_bin}/talosctl"

export FAKE_FIXTURES="${fixtures}"
export PATH="${fake_bin}:${PATH}"
export TALOSCTL="${fake_bin}/talosctl"

rule_obj() {
  local pattern="$1" phase="$2" rule_owner="$3"
  cat <<EOF
{"metadata":{"id":"${pattern}","namespace":"security","owner":"${rule_owner}","phase":"${phase}","type":"ImageVerificationRules.security.talos.dev","version":1},"node":"fixture","spec":{"imagePattern":"${pattern}"}}
EOF
}

reset_fixtures() {
  rm -rf "${fixtures}"
  mkdir -p "${fixtures}"
  # The realistic default: the catch-all rule is running and owned, so the
  # throwaway ref under ghcr.io/devantler-tech/ matches.
  {
    rule_obj 'ghcr.io/devantler-tech/ksail*' 'running' "${owner}"
    rule_obj 'ghcr.io/devantler-tech/*' 'running' "${owner}"
  } >"${fixtures}/rules.json"
  : >"${fixtures}/imagelist.txt"
}

stage_pull() {
  local ref="$1" rc="$2" out="${3:-}"
  local key
  key="$(printf '%s' "${ref}" | tr '/:@' '___')"
  printf '%s' "${rc}" >"${fixtures}/pullrc_${key}"
  printf '%s\n' "${out}" >"${fixtures}/pullout_${key}"
}

# Runs the probe with the standard arguments plus any extras, capturing both
# streams and the status. Never lets a non-zero status abort the suite: the
# status is the thing under test.
run_probe() {
  local out rc=0
  set +e
  out="$("${script}" --confirm --node "${node}" \
    --unsigned-image "${unsigned}" --signed-image "${signed}" "$@" 2>&1)"
  rc=$?
  set -e
  probe_out="${out}"
  probe_rc="${rc}"
}

check() {
  cases_run=$((cases_run + 1))
  printf '  ok  %s\n' "$1"
}

printf 'test-probe-image-signature-enforcement\n'

# --- Dormancy ---------------------------------------------------------------
# The probe writes to a real node, so an invocation without --confirm must do
# nothing. Pinned in both directions: silent without it, active with it.
reset_fixtures
set +e
out="$("${script}" --node "${node}" --unsigned-image "${unsigned}" --signed-image "${signed}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 2 ]] || fail "dormant run should exit 2, got ${rc}"
require_text "${out}" 'DORMANT' 'dormant run'
[[ ! -e "${fixtures}/pulled.txt" ]] || fail 'dormant run reached the node and pulled something'
check 'refuses to run without --confirm, and pulls nothing'

# Dormancy must be decided BEFORE argument validation, or a malformed scheduled
# invocation would be reported as a usage error rather than as refused.
reset_fixtures
set +e
out="$("${script}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 2 ]] || fail "bare run should exit 2, got ${rc}"
require_text "${out}" 'DORMANT' 'bare run'
refute_text "${out}" '--node is required' 'bare run'
check 'dormancy is checked before argument validation'

# --- Usage errors -----------------------------------------------------------
reset_fixtures
set +e
out="$("${script}" --confirm --node "${node}" --unsigned-image "${unsigned}" --signed-image "${unsigned}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 2 ]] || fail "identical refs should exit 2, got ${rc}"
require_text "${out}" 'identical' 'identical refs'
check 'rejects identical unsigned and signed refs'

reset_fixtures
set +e
out="$("${script}" --confirm --node "${node}" --unsigned-image 'ghcr.io/devantler-tech/x' --signed-image "${signed}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 2 ]] || fail "untagged ref should exit 2, got ${rc}"
require_text "${out}" 'no tag or digest' 'untagged ref'
check 'rejects a ref with neither tag nor digest'

# A value beginning with '-' is read by talosctl as a FLAG, not an operand, so a
# stray leading dash from the workflow_dispatch form would surface as a
# confusing tool error rather than a clear one. Pinned for the node as well as
# for both refs, since all three are passed to talosctl as operands.
for bad_arg_case in node unsigned signed; do
  reset_fixtures
  case "${bad_arg_case}" in
    node) args=(--node '-n' --unsigned-image "${unsigned}" --signed-image "${signed}") ;;
    unsigned) args=(--node "${node}" --unsigned-image '--nodes' --signed-image "${signed}") ;;
    signed) args=(--node "${node}" --unsigned-image "${unsigned}" --signed-image '-x') ;;
  esac
  set +e
  out="$("${script}" --confirm "${args[@]}" 2>&1)"
  rc=$?
  set -e
  [[ ${rc} -eq 2 ]] || fail "leading-dash ${bad_arg_case} should exit 2, got ${rc}"
  require_text "${out}" "begins with '-'" "leading-dash ${bad_arg_case}"
  [[ ! -e "${fixtures}/pulled.txt" ]] || fail "leading-dash ${bad_arg_case} reached the node"
done
check 'rejects a leading-dash node or ref that talosctl would read as a flag'

# --- Node and query failures are INCONCLUSIVE, never PASS or FAIL -----------
reset_fixtures
: >"${fixtures}/unreachable"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "unreachable node should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'cannot reach node' 'unreachable node'
check 'unreachable node is INCONCLUSIVE'

reset_fixtures
: >"${fixtures}/rules_query_fails"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "failed rules query should exit 3, got ${probe_rc}"
check 'failed rules query is INCONCLUSIVE'

reset_fixtures
: >"${fixtures}/imagelist_fails"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "failed image list should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'could not list images' 'failed image list'
check 'failed image list is INCONCLUSIVE (absence could not be established)'

# --- Rule materialisation ---------------------------------------------------
# No running rule means nothing on the node decides anything, so neither
# outcome proves enforcement. This must NOT read as FAIL.
reset_fixtures
: >"${fixtures}/rules.json"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "no rules should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'NO running materialised verification rules' 'no rules'
check 'no materialised rules is INCONCLUSIVE, not FAIL'

# A rule that exists but is not running decides nothing either. This is the
# case a naive implementation passes by reading every rule regardless of phase.
reset_fixtures
rule_obj 'ghcr.io/devantler-tech/*' 'tearingDown' "${owner}" >"${fixtures}/rules.json"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "non-running rule should exit 3, got ${probe_rc}"
check 'a rule not in phase running is ignored (INCONCLUSIVE)'

# A rule owned by something else is not the controller's materialisation.
reset_fixtures
rule_obj 'ghcr.io/devantler-tech/*' 'running' 'some.other.Controller' >"${fixtures}/rules.json"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "foreign-owned rule should exit 3, got ${probe_rc}"
check 'a rule owned by another controller is ignored (INCONCLUSIVE)'

# An unsigned ref matching NO rule is allowed through BY DESIGN, so pulling it
# successfully is correct behaviour. Reporting FAIL here would fire the probe's
# headline alarm on a healthy cluster.
reset_fixtures
set +e
out="$("${script}" --confirm --node "${node}" \
  --unsigned-image 'ghcr.io/other-org/thing:t1' --signed-image "${signed}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 3 ]] || fail "unmatched ref should exit 3, got ${rc}"
require_text "${out}" 'matches NO declared rule' 'unmatched ref'
refute_text "${out}" 'FAIL:' 'unmatched ref'
check 'an unsigned ref matching no rule is INCONCLUSIVE, never FAIL'

# --- Cache guard ------------------------------------------------------------
# The false-PASS case: a cached ref is never re-pulled, so verification never
# runs. Pinned for BOTH refs, because the positive control is the one most
# likely to be cached already.
reset_fixtures
printf '%s sha256:abc 12MB\n' "${unsigned}" >"${fixtures}/imagelist.txt"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "cached unsigned ref should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'ALREADY in node' 'cached unsigned ref'
[[ ! -e "${fixtures}/pulled.txt" ]] || fail 'probe pulled despite a cached ref'
check 'a cached unsigned ref is INCONCLUSIVE and nothing is pulled'

reset_fixtures
printf '%s sha256:def 30MB\n' "${signed}" >"${fixtures}/imagelist.txt"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "cached signed ref should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'ALREADY in node' 'cached signed ref'
check 'a cached signed positive control is INCONCLUSIVE too'

# --- The headline FAIL: a matched unsigned ref was ACCEPTED ----------------
reset_fixtures
stage_pull "${unsigned}" 0 ''
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 1 ]] || fail "accepted unsigned ref should exit 1, got ${probe_rc}"
require_text "${probe_out}" 'ACCEPTED the unsigned ref' 'accepted unsigned ref'
check 'a matched unsigned ref that is ACCEPTED is FAIL (exit 1)'

# --- Refusal attribution ---------------------------------------------------
# A refusal for an unrelated reason must not be counted as a signature refusal,
# or a typo'd tag would manufacture a PASS.
reset_fixtures
stage_pull "${unsigned}" 1 'failed to resolve reference: not found'
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "non-verification refusal should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'does not read as a verification failure' 'non-verification refusal'
refute_text "${probe_out}" 'PASS:' 'non-verification refusal'
check 'a refusal unrelated to signatures is INCONCLUSIVE, never PASS'

# --- Positive control is what makes the negative attributable --------------
# A verifier refusing EVERYTHING produces the same negative result as a working
# one. Without this case the probe would report PASS for a wholly broken node.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature'
stage_pull "${signed}" 1 'image verification failed: no valid signature'
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "failed positive control should exit 3, got ${probe_rc}"
require_text "${probe_out}" 'was ALSO refused' 'failed positive control'
refute_text "${probe_out}" 'PASS:' 'failed positive control'
check 'a refused positive control is INCONCLUSIVE, never PASS'

# --- The PASS path ---------------------------------------------------------
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 0 ]] || fail "expected PASS (exit 0), got ${probe_rc}: ${probe_out}"
require_text "${probe_out}" 'PASS:' 'pass path'
require_text "${probe_out}" 'refused matched unsigned ref' 'pass path'
check 'unsigned refused for a verification reason + signed accepted is PASS'

# --- Cleanup --------------------------------------------------------------
# The probe must leave the node as it found it, and must remove ONLY what it
# pulled — never an image the node already had.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 0 ]] || fail "cleanup case should PASS, got ${probe_rc}"
[[ -e "${fixtures}/removed.txt" ]] || fail 'probe removed nothing on the PASS path'
require_text "$(cat "${fixtures}/removed.txt")" "${unsigned}" 'cleanup'
require_text "$(cat "${fixtures}/removed.txt")" "${signed}" 'cleanup'
removed_count="$(grep -c . "${fixtures}/removed.txt")"
[[ "${removed_count}" -eq 2 ]] || fail "expected exactly 2 removals, got ${removed_count}"
check 'by default every pulled ref is removed, and only those'

# --keep leaves them, so an operator can inspect the node afterwards.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
run_probe --keep
[[ ${probe_rc} -eq 0 ]] || fail "--keep case should PASS, got ${probe_rc}"
[[ ! -e "${fixtures}/removed.txt" ]] || fail '--keep still removed images'
check '--keep leaves pulled refs in place'

# A run that fails BEFORE pulling must remove nothing — otherwise the probe
# could delete an image the node legitimately held.
reset_fixtures
: >"${fixtures}/rules.json"
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "pre-pull failure should exit 3, got ${probe_rc}"
[[ ! -e "${fixtures}/removed.txt" ]] || fail 'probe removed an image despite never pulling one'
check 'a failure before any pull removes nothing'

printf '\nAll %d case(s) passed: probe-image-signature-enforcement.sh behaviour is pinned.\n' "${cases_run}"
