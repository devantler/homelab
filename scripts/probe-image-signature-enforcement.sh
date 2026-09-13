#!/usr/bin/env bash

# Observe whether a matched-but-unsigned image is REFUSED at the node pull layer.
#
# WHAT IS UNPROVEN, AND WHY A NEW PROBE IS NEEDED.
# `scripts/validate-image-verifier-liveness.sh` establishes that Talos' own
# verification is LIVE on every node: every declared rule is materialised and in
# phase "running", and a TUF trust root exists. That is necessary for
# enforcement and not sufficient. Every first-party image ever pulled here has
# PASSED, so a FAILING verification decision has never been observed to block a
# pull (devantler-tech/platform#3336). This probe obtains that missing
# observation.
#
# WHY THE NODE PULL LAYER, AND NOT A POD.
# A Pod would reach containerd through the Kubernetes API, where the Kyverno
# admission layer also sits. An admission-time rejection and a node-side
# signature refusal both surface as "the workload did not start", so a Pod-based
# probe cannot attribute the refusal to the control under test. `talosctl image
# pull` talks to the node's containerd directly: the Kubernetes API is not in
# the path at all, so admission is *structurally* incapable of producing the
# result. That is the whole reason this probe is shaped the way it is — do not
# "simplify" it into applying a manifest.
#
# WHY A CACHED IMAGE WOULD FAKE A PASS.
# Verification happens at PULL. An image already in the node's content store is
# never re-pulled, so a probe that does not first establish absence can report a
# successful "pull" that performed no verification whatsoever — and it would
# report it most confidently for the positive control, which is the ref most
# likely to be cached already. Both refs are therefore asserted absent before
# use, and the run fails closed rather than probing a cached ref.
#
# WHY BOTH CONTROLS ARE REQUIRED.
# A refusal on its own is ambiguous: a verifier that refuses EVERYTHING produces
# exactly the same negative result as one correctly rejecting an unsigned image,
# and so does an unrelated failure (a typo'd tag, an auth error, a registry
# outage). The signed positive control is what makes the negative attributable
# to the signature. If the positive control does not succeed, the verdict is
# INCONCLUSIVE — never PASS — because nothing then distinguishes working
# enforcement from a broken verifier.
#
# DORMANT BY DEFAULT. Unlike the liveness checker, this probe WRITES to a real
# node: it pulls images into the container runtime. It therefore refuses to do
# anything without an explicit `--confirm`, so no scheduled job, no PR, and no
# accidental invocation can touch a node. Activation — restoring a cadence —
# is deliberately out of scope here and belongs to #3336.
#
# SECURITY: this probe reads Talos resources and the node's image list, and
# pulls the two refs it is given. It reads no node file, so no registry
# credential can reach its output. Keep it that way: its output goes to CI logs.

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: probe-image-signature-enforcement.sh --confirm --node <ip> \
         --unsigned-image <ref> --signed-image <ref> [--keep]

Observes whether the node pull layer REFUSES a matched-but-unsigned image while
ACCEPTING a correctly signed one, by pulling each directly on one node.

Required:
  --confirm               Acknowledge that this performs node-level writes
                          (image pulls) against a real cluster. Without it the
                          probe does nothing: it is dormant by design.
  --node <ip>             The single node to probe. Deliberately one node: the
                          question is whether refusal happens at all, and every
                          extra node only widens the blast radius.
  --unsigned-image <ref>  A deliberately unsigned THROWAWAY ref that MATCHES a
                          declared verification rule. Never a production
                          workload. The probe asserts the match itself.
  --signed-image <ref>    A correctly signed ref, used as the positive control,
                          that the SAME first-match rule governs as the
                          unsigned ref. Prefer a dedicated signed throwaway.
                          It is never removed afterwards.

Optional:
  --keep                  Leave the unsigned ref in the node's content store if
                          it was pulled. By default it is removed again. The
                          signed control is always left in place: removing it
                          could race a pod that has started using it.

Environment overrides: TALOSCTL

Exit status:
  0  PASS         — unsigned ref refused for a verification reason, signed ref pulled
  1  FAIL         — the unsigned ref was ACCEPTED: enforcement is not refusing
  2  usage error
  3  INCONCLUSIVE — the probe could not attribute the result (positive control
                    failed, a ref was already cached, a refusal was not a
                    verification refusal, or a node/tool error). Never read as PASS.
USAGE
}

readonly talosctl_bin="${TALOSCTL:-talosctl}"
readonly ns='cri'

# Three verdict channels, kept distinct on purpose. `fail_inconclusive` is the
# one a careless refactor tends to collapse into `fail_enforcement`, which would
# turn "we could not tell" into "enforcement is broken" — a false alarm — or, if
# collapsed the other way, into a false all-clear.
fail_usage() {
  printf 'ERROR: %s\n\n' "$1" >&2
  usage
  exit 2
}

fail_inconclusive() {
  printf 'INCONCLUSIVE: %s\n' "$1" >&2
  printf 'INCONCLUSIVE is NOT a pass: no statement about enforcement is made.\n' >&2
  exit 3
}

fail_enforcement() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

confirmed=0
node=''
unsigned_image=''
signed_image=''
keep=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm) confirmed=1 ;;
    --keep) keep=1 ;;
    --node)
      [[ $# -ge 2 ]] || fail_usage '--node requires a value'
      node="$2"
      shift
      ;;
    --unsigned-image)
      [[ $# -ge 2 ]] || fail_usage '--unsigned-image requires a value'
      unsigned_image="$2"
      shift
      ;;
    --signed-image)
      [[ $# -ge 2 ]] || fail_usage '--signed-image requires a value'
      signed_image="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) fail_usage "unknown argument: $1" ;;
  esac
  shift
done

# Dormancy is checked FIRST, before any argument is even validated, so that an
# invocation missing --confirm can never reach a node for any reason.
if ((confirmed == 0)); then
  printf 'probe-image-signature-enforcement: DORMANT — refusing to run without --confirm.\n' >&2
  printf 'This probe pulls images on a real node. Re-run with --confirm to proceed.\n' >&2
  exit 2
fi

[[ -n "${node}" ]] || fail_usage '--node is required'
# talosctl reads a comma-separated -n value as SEVERAL targets. That would fan every
# query, pull and cleanup out across production nodes, and a refusal on one node
# combined with an acceptance on another could still produce PASS. The advertised
# one-node blast radius and the verdict both depend on exactly one target.
case "${node}" in
  *,* | *[[:space:]]*) fail_usage "--node '${node}' names more than one target — pass a single node, since talosctl would fan the probe out across every listed node" ;;
esac
[[ -n "${unsigned_image}" ]] || fail_usage '--unsigned-image is required'
[[ -n "${signed_image}" ]] || fail_usage '--signed-image is required'
[[ "${unsigned_image}" != "${signed_image}" ]] ||
  fail_usage 'the unsigned and signed refs are identical — the controls would not distinguish anything'

# A value beginning with `-` is parsed by talosctl as a FLAG rather than as the
# operand it was meant to be (verified: `talosctl image pull --bogus-flag`
# answers "unknown flag"). This crosses no privilege boundary — these are CLI
# arguments, so whoever sets them can already run talosctl directly — but it
# turns a typo into a confusing tool error instead of a clear one, and on the
# `workflow_dispatch` path the value arrives from a form field where a stray
# leading dash is easy to introduce. Rejected explicitly so the message names
# the actual problem.
for value in "${node}" "${unsigned_image}" "${signed_image}"; do
  case "${value}" in
    -*) fail_usage "'${value}' begins with '-', which talosctl would read as a flag rather than a value" ;;
  esac
done

# A ref carrying no tag or digest would let containerd resolve `:latest`, so the
# probe would not be pulling the artifact it was asked about.
for ref in "${unsigned_image}" "${signed_image}"; do
  case "${ref}" in
    *@sha256:*) : ;;
    *:*[!/]*) : ;;
    *) fail_usage "ref '${ref}' names no tag or digest — refusing to let :latest be resolved for it" ;;
  esac
done

# The ref NAME — registry, namespace and repository, without its tag or digest —
# must be canonical lowercase. OCI repository names are lowercase, and registry
# domains are matched case-insensitively. Normalizing case for one comparison but
# not another is how a `GHCR.IO/...` input missed its cached `ghcr.io/...` twin:
# the cache check saw no match, the pull was served from cache without
# verification, and the probe reported PASS. Requiring the canonical form makes
# the rule match, the cache check and the pull all see one spelling, instead of
# normalizing each comparison separately. A tag may still carry upper case.
for ref in "${unsigned_image}" "${signed_image}"; do
  ref_name="${ref%@*}"
  case "${ref_name##*/}" in
    *:*) ref_name="${ref_name%:*}" ;;
  esac
  case "${ref_name}" in
    *[[:upper:]]*) fail_usage "ref '${ref}' is not canonical lowercase — write the registry and repository in lowercase so rule matching, the cache check and the pull all refer to the same image" ;;
  esac
done

command -v "${talosctl_bin}" >/dev/null 2>&1 ||
  fail_inconclusive "talosctl not found (looked for '${talosctl_bin}')"

"${talosctl_bin}" -n "${node}" ls / >/dev/null 2>&1 ||
  fail_inconclusive "cannot reach node ${node} (talosctl ls / failed) — refusing to report a probe that did not run"

# ---------------------------------------------------------------------------
# Pre-flight: the unsigned ref must MATCH a declared rule.
#
# An image that matches NO rule is allowed through by design, so pulling an
# unmatched unsigned ref successfully says nothing at all about enforcement —
# it is the expected behaviour. Without this gate the probe's headline FAIL
# would fire on a correctly-configured cluster, which is worse than no probe.
# The patterns are read from the LIVE node, not the repository, for the same
# reason the liveness checker does: the repository reads as correct whether or
# not anything on the node evaluates it.
# ---------------------------------------------------------------------------
readonly rules_type='imageverificationrules.security.talos.dev'
readonly rules_owner='security.ImageVerificationConfigController'

rules_json="$("${talosctl_bin}" -n "${node}" get "${rules_type}" -o json 2>/dev/null)" ||
  fail_inconclusive "could not read ${rules_type} on node ${node}"

# `talosctl get -o json` emits a STREAM of objects, not an array, so -s slurps
# them.
#
# The shape is one resource PER RULE carrying `.spec.imagePattern` — NOT a
# single resource holding a `rules[]` array. Getting that wrong yields an empty
# pattern set, which this script would then report as "no rules materialised" on
# a perfectly healthy cluster.
#
# Only rules the ImageVerificationConfigController OWNS and has brought to phase
# "running" actually decide anything, so a rule in any other phase is excluded:
# matching the probe ref against a rule that decides nothing would make the
# probe claim to be testing a control that is not in the path.
#
# Talos assigns rule ids 0000, 0001, ... in declaration order and applies the
# FIRST matching rule, so the patterns are emitted in id order — the same order
# scripts/validate-image-verifier-liveness.sh compares against the declaration.
# Resource stream order is not declaration order, and matching in stream order
# would name the wrong governing rule.
patterns="$(printf '%s' "${rules_json}" |
  jq -s -r --arg owner "${rules_owner}" '
    [ .[]?
      | select((.metadata?.owner // "") == $owner)
      | select((.metadata?.phase // "") == "running")
      | select((.spec?.imagePattern // "") != "")
    ] | sort_by(.metadata.id // "") | .[] | .spec.imagePattern' 2>/dev/null)" ||
  fail_inconclusive "could not parse verification rules from node ${node}"

[[ -n "${patterns}" ]] ||
  fail_inconclusive "node ${node} holds NO running materialised verification rules — nothing would be verified there, so neither a refusal nor a successful pull would prove anything"

# BOTH refs must match a running rule, and the positive control's match is the
# load-bearing one people forget (CodeRabbit caught this on review).
#
# For the UNSIGNED ref the reason is obvious: an unmatched image is allowed
# through by design, so refusing it is not what this probe observes.
#
# For the SIGNED ref it is subtler and it breaks the probe's whole argument. An
# unmatched signed ref pulls successfully WITHOUT ANY VERIFICATION HAVING
# HAPPENED. Its success then says nothing about the verifier, so it no longer
# excludes the failure mode the positive control exists for — a verifier that
# refuses every rule-MATCHING image. The probe would combine a
# verification-shaped refusal with an unrelated successful pull and report
# PASS, which is a false all-clear on exactly the broken state it was built to
# detect. Both refs are therefore matched before either is pulled.
#
# Talos matches a pattern against the image REPOSITORY, with the tag and digest
# removed — this repository's own exact-repository rule for
# `ghcr.io/devantler-tech/platform-kubescape-storage` carries no wildcard and still
# governs that tagged image. Matching the full ref would disagree with the node in
# both directions: a pattern naming a tag would look like it governs a ref Talos
# pulls unverified, and an exact-repository pattern would look like it governs
# nothing. So the ref is reduced to its repository first.
ref_repository() {
  local repo="${1%@*}" last
  last="${repo##*/}"
  if [[ "${last}" == *:* ]]; then
    repo="${repo%:*}"
  fi
  printf '%s' "${repo}"
}

# Refs are already required to be canonical lowercase (see the argument checks),
# so the repository compares directly against the live patterns.
match_rule() {
  local repo pattern
  repo="$(ref_repository "$1")"
  while IFS= read -r pattern; do
    [[ -n "${pattern}" ]] || continue
    # The rule patterns are containerd globs. `case` glob-matches with the same
    # semantics, and the pattern is deliberately UNQUOTED here so it is treated
    # as a glob rather than a literal.
    # shellcheck disable=SC2254
    case "${repo}" in
      ${pattern})
        printf '%s' "${pattern}"
        return 0
        ;;
    esac
  done <<<"${patterns}"
  return 1
}

matched_pattern="$(match_rule "${unsigned_image}")" ||
  fail_inconclusive "the unsigned ref '${unsigned_image}' matches NO running rule on node ${node} — an unmatched image is allowed by design, so refusing it is not what this probe would be observing"

signed_matched_pattern="$(match_rule "${signed_image}")" ||
  fail_inconclusive "the signed positive control '${signed_image}' matches NO running rule on node ${node} — it would pull without being verified at all, so its success could not exclude a verifier that refuses every rule-matching image, and a PASS would be unfounded"

# The positive control only excludes a verifier that refuses everything if it is
# judged by the SAME rule. A signed ref governed by a different rule proves that
# rule works and says nothing about the unsigned ref's rule, which could refuse
# every image it governs — and the probe would then report PASS on exactly that
# broken rule. Different rules is therefore INCONCLUSIVE, before anything is pulled.
[[ "${matched_pattern}" == "${signed_matched_pattern}" ]] ||
  fail_inconclusive "the unsigned ref and the signed control select different rules on node ${node} ('${matched_pattern}' and '${signed_matched_pattern}') — a signed pull under another rule cannot exclude a rule that refuses every image it governs, so a PASS would be unfounded. Use a signed control governed by the same rule"

printf 'probe: on node %s the unsigned ref matches rule %s and the signed control matches rule %s\n' \
  "${node}" "${matched_pattern}" "${signed_matched_pattern}"

# ---------------------------------------------------------------------------
# Cache guard. See the header: a cached ref is never re-pulled, so probing one
# measures nothing while looking like a success.
# ---------------------------------------------------------------------------
image_list="$("${talosctl_bin}" -n "${node}" image list --namespace "${ns}" 2>/dev/null)" ||
  fail_inconclusive "could not list images on node ${node} — cannot establish that the probe refs are absent"

ref_is_cached() {
  # Substring match on purpose: `image list` renders a ref plus its digest and
  # size, so an exact line match would miss it. The consequence of a false
  # positive here is a fail-closed INCONCLUSIVE, never a false PASS.
  printf '%s' "${image_list}" | grep -qF -- "$1"
}

for ref in "${unsigned_image}" "${signed_image}"; do
  if ref_is_cached "${ref}"; then
    fail_inconclusive "ref '${ref}' is ALREADY in node ${node}'s content store — a cached image is not re-pulled, so this probe would verify nothing. Remove it first: ${talosctl_bin} -n ${node} image remove --namespace ${ns} ${ref}"
  fi
done

printf 'probe: both refs confirmed absent from node %s content store\n' "${node}"

# ---------------------------------------------------------------------------
# Cleanup. Registered only once a pull has actually been attempted, and it
# removes ONLY the unsigned throwaway this probe pulled, so a failure cannot
# delete an image the node already had or the signed control a pod may now use. Best-effort by design: a cleanup error must not overwrite
# the probe's verdict, which is the whole point of the run.
# ---------------------------------------------------------------------------
pulled_refs=()

# The FIRST thing this does is capture the status the script is exiting with,
# and the last thing it does is return it.
#
# MEASURED SEMANTICS (bash 3.2.57, the macOS system bash this repository's
# scripts run under in developer shells): an EXIT trap that returns a NON-ZERO
# status REPLACES the script's exit status, while a zero status leaves it
# alone. `return 7` in a trap over `exit 3` yields 7; a trap ending in `false`
# yields 1.
#
# That bit this script for real during development. Before the `pulled_refs`
# recording was moved into the callers below, the array was always empty here,
# an emptiness test was the trap's last command, it returned 1, and EVERY
# INCONCLUSIVE (3) was reported as FAIL (1) — silently turning "the probe could
# not tell" into "enforcement is broken", the exact false alarm the three
# separate verdict channels exist to prevent.
#
# With that bug fixed the trap now ends on a zero status, so this line is
# currently DEFENSIVE rather than load-bearing: neutralising it does not change
# any verdict today, and the test suite therefore does not pin it. It is kept
# because the cost is one line and the failure it prevents is silent and
# directional — any future cleanup step whose last command fails would rewrite
# a verdict rather than report a cleanup problem.
cleanup() {
  local rc=$?
  local ref

  if ((keep != 0)); then
    printf 'probe: --keep given, leaving %d pulled ref(s) in place\n' "${#pulled_refs[@]}" >&2
    return "${rc}"
  fi

  for ref in ${pulled_refs[@]+"${pulled_refs[@]}"}; do
    if "${talosctl_bin}" -n "${node}" image remove --namespace "${ns}" "${ref}" >/dev/null 2>&1; then
      printf 'probe: cleaned up %s\n' "${ref}" >&2
    else
      printf 'probe: WARNING could not remove %s from node %s — remove it by hand\n' "${ref}" "${node}" >&2
    fi
  done

  return "${rc}"
}
trap cleanup EXIT

# A refusal is only evidence about signatures if the node says it is about
# verification. Anything else — an unknown tag, an auth denial, a registry
# outage — produces a failed pull for reasons this probe is not testing, and
# counting those as a refusal would manufacture a PASS out of a typo.
#
# LIMITATION, stated because it bounds what a PASS means. This is the one place
# where text the probe does not control decides a verdict: the refusal reason is
# produced by the node, and part of it can originate from the registry serving
# the ref. A registry that returned prose resembling a verification failure
# could therefore make an unrelated refusal read as a signature refusal. The
# positive control is what keeps that from being a plausible false PASS on its
# own — a crafted negative AND a genuinely succeeding signed pull are both
# required — but a PASS here is evidence about a cooperating registry, not proof
# against a hostile one. Supply refs from a registry you trust.
#
# The match is an ALLOWLIST of verifier phrases, not a list of loose words. Words
# like "verify", "signature" and "trust" also appear in TLS and x509 transport
# errors ("failed to verify certificate", "certificate signature is invalid"),
# which say nothing about the image verifier; paired with a signed pull that
# succeeds, a word match reported PASS. So a transport diagnostic is rejected
# outright, and anything else must name an image-signature decision. Wording the
# allowlist does not recognise yields INCONCLUSIVE — the safe direction for a
# probe whose job is never to report an unfounded PASS.
is_verification_refusal() {
  if printf '%s' "$1" | grep -qiE 'x509|certificate|tls:'; then
    return 1
  fi
  printf '%s' "$1" | grep -qiE 'image verification|signature verification|no valid signature|no matching signature|not signed|unsigned image|cosign|sigstore'
}

# Pull errors routinely REPEAT the ref, and the recommended negative-control name
# itself contains "unsigned" — so classifying the raw diagnostic finds the probe's
# own input and turns a not-found or an authorization denial into a "signature
# refusal", which then combines with a genuine signed pull into a false PASS.
# Both refs, and each ref's repository without its tag or digest, are removed as
# LITERAL text before classifying. Removing text can only make a match less likely,
# so this fails towards INCONCLUSIVE, never towards PASS.
without_probe_refs() {
  local text="$1" ref repo
  for ref in "${unsigned_image}" "${signed_image}"; do
    repo="$(ref_repository "${ref}")"
    text="${text//"${ref}"/}"
    text="${text//"${repo}"/}"
  done
  printf '%s' "${text}"
}

# Records the ref as pulled and then pulls it. The recording deliberately lives
# in the CALLER (see the call sites) rather than in here: this function's output
# is captured with `$(...)`, which runs it in a SUBSHELL, so an array appended
# inside it is discarded when the subshell exits and cleanup would then remove
# nothing at all — leaving the unsigned probe image on the node.
pull_ref() {
  "${talosctl_bin}" -n "${node}" image pull --namespace "${ns}" "$1" 2>&1
}

# --- Negative control: the matched, unsigned ref MUST be refused. ------------
printf '\nprobe: NEGATIVE control — pulling matched unsigned ref %s\n' "${unsigned_image}"
unsigned_output=''
unsigned_rc=0
pulled_refs+=("${unsigned_image}")
unsigned_output="$(pull_ref "${unsigned_image}")" || unsigned_rc=$?

if ((unsigned_rc == 0)); then
  fail_enforcement "node ${node} ACCEPTED the unsigned ref '${unsigned_image}' even though it matches rule '${matched_pattern}'. Signature verification is not refusing unsigned images at the pull layer."
fi

if ! is_verification_refusal "$(without_probe_refs "${unsigned_output}")"; then
  fail_inconclusive "the unsigned ref was refused, but the node's reason does not read as a verification failure, so the refusal is not attributable to the signature. Node said: ${unsigned_output}"
fi

printf 'probe: unsigned ref REFUSED for a verification reason (expected)\n'

# --- Positive control: a correctly signed ref MUST be accepted. --------------
# Without this, a verifier refusing everything is indistinguishable from one
# working correctly.
printf '\nprobe: POSITIVE control — pulling signed ref %s\n' "${signed_image}"
signed_output=''
signed_rc=0
# Deliberately NOT recorded for cleanup. The node stays schedulable during the
# probe, so removing a signed image could delete one a pod has just started
# using; a verified signed image left in the cache is harmless. Only the unsigned
# throwaway is ever removed.
signed_output="$(pull_ref "${signed_image}")" || signed_rc=$?

if ((signed_rc != 0)); then
  fail_inconclusive "the signed positive control '${signed_image}' was ALSO refused, so the negative result is not attributable to the signature — this looks like a verifier refusing everything. Node said: ${signed_output}"
fi

printf 'probe: signed ref pulled successfully (expected)\n'

printf '\nPASS: node %s refused matched unsigned ref %s for a verification reason and accepted signed ref %s.\n' \
  "${node}" "${unsigned_image}" "${signed_image}"
printf 'This is the behavioural refusal devantler-tech/platform#3336 requires. Restoring the daily schedule is that issue, not this probe.\n'
