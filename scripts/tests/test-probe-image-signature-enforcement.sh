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
# The positive control must select the SAME first-match rule as the unsigned ref,
# so the default is a throwaway under the same catch-all rule — not a production
# image under a different, more specific rule.
readonly signed='ghcr.io/devantler-tech/probe-throwaway-signed:t1'

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

# Talos assigns rule ids 0000, 0001, ... in declaration order and evaluates the
# first match, so each fixture rule carries an explicit id (default 0000).
rule_obj() {
  local pattern="$1" phase="$2" rule_owner="$3" id="${4:-0000}"
  cat <<EOF
{"metadata":{"id":"${id}","namespace":"security","owner":"${rule_owner}","phase":"${phase}","type":"ImageVerificationRules.security.talos.dev","version":1},"node":"fixture","spec":{"imagePattern":"${pattern}"}}
EOF
}

reset_fixtures() {
  rm -rf "${fixtures}"
  mkdir -p "${fixtures}"
  # The realistic default, in declaration order: the specific ksail rule first,
  # then the catch-all, under which both throwaway refs fall.
  {
    rule_obj 'ghcr.io/devantler-tech/ksail*' 'running' "${owner}" '0000'
    rule_obj 'ghcr.io/devantler-tech/*' 'running' "${owner}" '0001'
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

# talosctl reads a comma-separated -n value as SEVERAL targets. Accepting one would
# fan every query, pull and cleanup out across production nodes, and a refusal on
# one node plus an acceptance on another could still combine into PASS. So the
# node must be a single target, rejected before anything reaches a node.
for node_list in '10.0.1.1,10.0.1.2' '10.0.1.1, 10.0.1.2' '10.0.1.1 10.0.1.2'; do
  reset_fixtures
  set +e
  out="$("${script}" --confirm --node "${node_list}" --unsigned-image "${unsigned}" --signed-image "${signed}" 2>&1)"
  rc=$?
  set -e
  [[ ${rc} -eq 2 ]] || fail "node list '${node_list}' should exit 2, got ${rc}: ${out}"
  require_text "${out}" 'single node' "node list '${node_list}'"
  [[ ! -e "${fixtures}/pulled.txt" ]] || fail "node list '${node_list}' reached the node"
done
check 'rejects a comma- or space-separated node list: the probe targets exactly one node'

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
require_text "${out}" 'matches NO running rule' 'unmatched ref'
refute_text "${out}" 'FAIL:' 'unmatched ref'
check 'an unsigned ref matching no rule is INCONCLUSIVE, never FAIL'

# The SIGNED positive control must match a running rule too, and this is the case
# that breaks the probe's argument if it is missing (CodeRabbit found it on review).
# An unmatched signed ref pulls successfully WITHOUT being verified at all, so its
# success stops excluding the failure mode the control exists for — a verifier that
# refuses every rule-MATCHING image. Without this gate the probe pairs a
# verification-shaped refusal with an unrelated successful pull and reports PASS: a
# false all-clear on exactly the broken state it was built to detect. Neither ref may
# be pulled in that situation.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
set +e
out="$("${script}" --confirm --node "${node}" \
  --unsigned-image "${unsigned}" --signed-image 'ghcr.io/other-org/signed-thing:v1' 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 3 ]] || fail "unmatched SIGNED control should exit 3, got ${rc}: ${out}"
require_text "${out}" 'signed positive control' 'unmatched signed control'
require_text "${out}" 'matches NO running rule' 'unmatched signed control'
refute_text "${out}" 'PASS:' 'unmatched signed control'
[[ ! -e "${fixtures}/pulled.txt" ]] || fail 'probe pulled despite an unmatched signed control'
check 'an unmatched SIGNED positive control is INCONCLUSIVE and nothing is pulled'

# Talos matches a rule's pattern against the image REPOSITORY, not the full
# reference: this repository's own `ghcr.io/devantler-tech/platform-kubescape-storage`
# rule carries no wildcard and still governs that tagged image. Matching the full
# ref here disagrees with the node in both directions, so both are pinned.
#
# A pattern that names a TAG can never match on the node. Matching it against the
# full ref would call the unsigned ref governed when Talos pulls it unverified.
reset_fixtures
{
  rule_obj "${unsigned}" 'running' "${owner}"
  rule_obj 'ghcr.io/devantler-tech/ksail*' 'running' "${owner}"
} >"${fixtures}/rules.json"
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "tag-bearing rule should exit 3, got ${probe_rc}: ${probe_out}"
require_text "${probe_out}" 'matches NO running rule' 'tag-bearing rule'
refute_text "${probe_out}" 'PASS:' 'tag-bearing rule'
[[ ! -e "${fixtures}/pulled.txt" ]] || fail 'probe pulled despite a rule that cannot match on the node'
check 'a rule pattern that names a tag does not govern the ref (INCONCLUSIVE, nothing pulled)'

# The converse: an exact-repository pattern with no wildcard DOES govern a tagged
# ref on the node, so the probe must treat it as matched rather than skip the test.
# Both controls live in that one repository, so they select the same rule.
reset_fixtures
repo_unsigned='ghcr.io/devantler-tech/probe-throwaway:unsigned-t1'
repo_signed='ghcr.io/devantler-tech/probe-throwaway:signed-t1'
rule_obj 'ghcr.io/devantler-tech/probe-throwaway' 'running' "${owner}" '0000' >"${fixtures}/rules.json"
stage_pull "${repo_unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${repo_signed}" 0 ''
set +e
out="$("${script}" --confirm --node "${node}" \
  --unsigned-image "${repo_unsigned}" --signed-image "${repo_signed}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 0 ]] || fail "exact-repository rule should reach PASS, got ${rc}: ${out}"
require_text "${out}" 'PASS:' 'exact-repository rule'
check 'an exact-repository rule governs the tagged ref, as it does on the node'

# A ref whose name is not canonical lowercase is a usage error, before anything
# reaches a node. Normalizing case in one place and not another is exactly how a
# `GHCR.IO/...` input missed its cached `ghcr.io/...` twin: the cache check saw
# no match, the pull was served from cache without verification, and the probe
# reported PASS. OCI repository names are lowercase, so requiring the canonical
# form removes the whole class instead of chasing each comparison.
for upper_case in signed unsigned; do
  reset_fixtures
  case "${upper_case}" in
    signed) u="${unsigned}" s='GHCR.IO/devantler-tech/probe-throwaway-signed:t1' ;;
    unsigned) u='ghcr.io/Devantler-Tech/probe-throwaway-unsigned:t1' s="${signed}" ;;
  esac
  # The exact false-PASS setup: the canonical twin of the upper-case ref is cached.
  printf '%s sha256:abc 12MB\n' 'ghcr.io/devantler-tech/probe-throwaway-signed:t1' >"${fixtures}/imagelist.txt"
  stage_pull "${u}" 1 'image verification failed: no valid signature found'
  stage_pull "${s}" 0 ''
  set +e
  out="$("${script}" --confirm --node "${node}" --unsigned-image "${u}" --signed-image "${s}" 2>&1)"
  rc=$?
  set -e
  [[ ${rc} -eq 2 ]] || fail "non-lowercase ${upper_case} ref should exit 2, got ${rc}: ${out}"
  require_text "${out}" 'lowercase' "non-lowercase ${upper_case} ref"
  refute_text "${out}" 'PASS:' "non-lowercase ${upper_case} ref"
  [[ ! -e "${fixtures}/pulled.txt" ]] || fail "non-lowercase ${upper_case} ref reached the node"
done
check 'a ref whose name is not canonical lowercase is a usage error and nothing is pulled'

# --- Both controls must exercise the SAME rule ------------------------------
# A signed ref under a different first-match rule cannot exclude a rule that
# rejects every image it governs: the catch-all could refuse everything while
# the ksail rule still works, and the probe would report PASS. So two different
# rules is INCONCLUSIVE, before anything is pulled.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull 'ghcr.io/devantler-tech/ksail:v1.2.3' 0 ''
set +e
out="$("${script}" --confirm --node "${node}" \
  --unsigned-image "${unsigned}" --signed-image 'ghcr.io/devantler-tech/ksail:v1.2.3' 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 3 ]] || fail "controls under different rules should exit 3, got ${rc}: ${out}"
require_text "${out}" 'different rules' 'controls under different rules'
refute_text "${out}" 'PASS:' 'controls under different rules'
[[ ! -e "${fixtures}/pulled.txt" ]] || fail 'probe pulled despite controls under different rules'
check 'controls selecting different first-match rules are INCONCLUSIVE and nothing is pulled'

# First match follows DECLARATION order (the rule id), not the order resources
# happen to arrive in. Here the stream lists the catch-all first, but ksail* is
# declared first, so it is the rule that governs the ksail-prefixed throwaway —
# and the two controls therefore select different rules.
reset_fixtures
{
  rule_obj 'ghcr.io/devantler-tech/*' 'running' "${owner}" '0001'
  rule_obj 'ghcr.io/devantler-tech/ksail*' 'running' "${owner}" '0000'
} >"${fixtures}/rules.json"
stage_pull 'ghcr.io/devantler-tech/ksail-probe-unsigned:t1' 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
set +e
out="$("${script}" --confirm --node "${node}" \
  --unsigned-image 'ghcr.io/devantler-tech/ksail-probe-unsigned:t1' --signed-image "${signed}" 2>&1)"
rc=$?
set -e
[[ ${rc} -eq 3 ]] || fail "rules out of stream order should resolve by id and exit 3, got ${rc}: ${out}"
require_text "${out}" 'different rules' 'rules out of stream order'
check 'first match follows rule id order, not resource stream order'

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

# The same unrelated refusal, but with the node ECHOING THE REF — which real pull
# errors do. The recommended negative-control name contains "unsigned", so a
# classifier that reads the whole diagnostic finds its own input and calls a
# not-found a signature refusal: PASS without verification ever rejecting anything.
# The ref must be removed before the reason is classified.
reset_fixtures
stage_pull "${unsigned}" 1 "failed to resolve reference \"${unsigned}\": not found"
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "ref-echoing non-verification refusal should exit 3, got ${probe_rc}: ${probe_out}"
require_text "${probe_out}" 'does not read as a verification failure' 'ref-echoing refusal'
refute_text "${probe_out}" 'PASS:' 'ref-echoing refusal'
check 'a refusal that merely repeats the unsigned ref is INCONCLUSIVE, never PASS'

# The ref with its tag stripped must not count either: an authorization error
# commonly names only the repository.
reset_fixtures
stage_pull "${unsigned}" 1 "denied: requested access to the resource ${unsigned%:*} is denied"
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 3 ]] || fail "repository-echoing refusal should exit 3, got ${probe_rc}: ${probe_out}"
refute_text "${probe_out}" 'PASS:' 'repository-echoing refusal'
check 'a refusal that repeats only the unsigned repository is INCONCLUSIVE, never PASS'

# Transport errors carry the same WORDS as a verifier refusal without being one:
# a TLS failure "fails to verify" a certificate and an x509 error names a
# "signature", yet neither says the image verifier rejected the unsigned image.
# Paired with a signed pull that succeeds, a word-based classifier reports PASS.
for transport_error in \
  'tls: failed to verify certificate: x509: certificate signed by unknown authority' \
  'x509: certificate signature is invalid' \
  'remote error: tls: bad certificate (untrusted issuer)'; do
  reset_fixtures
  stage_pull "${unsigned}" 1 "${transport_error}"
  stage_pull "${signed}" 0 ''
  run_probe
  [[ ${probe_rc} -eq 3 ]] || fail "transport error '${transport_error}' should exit 3, got ${probe_rc}: ${probe_out}"
  refute_text "${probe_out}" 'PASS:' "transport error '${transport_error}'"
done
check 'a TLS or x509 error is INCONCLUSIVE even though it mentions verify, signature or trust'

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
# The probe removes ONLY the unsigned throwaway it pulled — never an image the
# node already had, and never the signed control. The node stays schedulable
# during the probe, so removing a signed image could delete one a pod has just
# started using; a verified signed image left in the cache is harmless.
reset_fixtures
stage_pull "${unsigned}" 1 'image verification failed: no valid signature found'
stage_pull "${signed}" 0 ''
run_probe
[[ ${probe_rc} -eq 0 ]] || fail "cleanup case should PASS, got ${probe_rc}"
[[ -e "${fixtures}/removed.txt" ]] || fail 'probe removed nothing on the PASS path'
require_text "$(cat "${fixtures}/removed.txt")" "${unsigned}" 'cleanup'
refute_text "$(cat "${fixtures}/removed.txt")" "${signed}" 'cleanup'
removed_count="$(grep -c . "${fixtures}/removed.txt")"
[[ "${removed_count}" -eq 1 ]] || fail "expected exactly 1 removal (the unsigned ref), got ${removed_count}"
check 'by default only the unsigned throwaway is removed, never the signed control'

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
