#!/usr/bin/env bash
# RED/GREEN coverage for `report-publish-workflow-signing-revisions.sh` (#3048).
#
# WHAT IS ACTUALLY BEING PROVED
# The script answers one question per consumer: "is the revision that SIGNED what is
# deployed the same revision this consumer pins TODAY?" An allow-list built for #2818 has
# to accept both, so a DIFFERENCE must be surfaced and a MATCH must not.
#
# The script's only harmful failure mode is reporting a clean, in-sync portfolio while
# having checked nothing or the wrong thing — so most cases below are aimed at that, not
# at the happy path.
#
# WHY THERE IS A RESOLVER SEAM
# Resolving a revision needs the network. A test that depended on it would prove nothing
# repeatable: red when an unrelated repository cut a release, green when the network was
# simply unavailable. The script takes its resolver from PUBLISH_REVISION_RESOLVER and
# these fixtures supply a stub. Discovery stays REAL, against this repository's own
# manifests, because that is the half a stub could hide a regression in.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly SCRIPT="$REPO_ROOT/scripts/report-publish-workflow-signing-revisions.sh"

readonly SHA_A='1111111111111111111111111111111111111111'
readonly SHA_B='2222222222222222222222222222222222222222'
readonly SHA_C='3333333333333333333333333333333333333333'

failures=0
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}
pass() { printf 'ok: %s\n' "$*"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A stub resolver, handed <repo> <workflow> <version>, printing "<signing>\t<current>".
# Each fixture writes its answers into a table the stub reads.
make_stub() {
  local table="$1" path="$WORK/resolver-$2.sh"
  cat >"$path" <<STUB
#!/usr/bin/env bash
set -euo pipefail
while IFS=\$'\t' read -r repo workflow signing current; do
  [ -n "\$repo" ] || continue
  if [ "\$repo" = "\$1" ] && [ "\$workflow" = "\$2" ]; then
    printf '%s\t%s\n' "\$signing" "\$current"
    exit 0
  fi
done <"$table"
exit 7
STUB
  chmod +x "$path"
  printf '%s\n' "$path"
}

consumers="$("$SCRIPT" --list-consumers 2>/dev/null || true)"
if [ -z "$consumers" ]; then
  fail '--list-consumers produced nothing; every case below would pass vacuously'
  printf '\n%d failure(s)\n' "$failures" >&2
  exit 1
fi

# Derived from --list-consumers, never hard-coded: the count changes whenever a consumer is
# onboarded or decommissioned, and a literal here fails the whole suite for a reason that has
# nothing to do with what each case is testing. (Decommissioning doggy-countdown took it 5 -> 4
# and broke fourteen assertions at once, none of which was about that tenant.)
#   consumer_count  — every consumer resolves
#   expected_insync — every consumer BUT the one a case deliberately breaks
consumer_count="$(printf '%s\n' "$consumers" | grep -c .)"
expected_insync=$((consumer_count - 1))

write_table() { # <path> <special-repo|""> <special-signing> <special-current>
  local table="$1" special="$2" s_sign="$3" s_cur="$4" repo workflow
  : >"$table"
  while IFS=$'\t' read -r repo workflow _version; do
    [ -n "$repo" ] || continue
    if [ -n "$special" ] && [ "$repo" = "$special" ]; then
      printf '%s\t%s\t%s\t%s\n' "$repo" "$workflow" "$s_sign" "$s_cur" >>"$table"
    else
      printf '%s\t%s\t%s\t%s\n' "$repo" "$workflow" "$SHA_A" "$SHA_A" >>"$table"
    fi
  done <<<"$consumers"
}

first_repo="$(printf '%s\n' "$consumers" | head -1 | cut -f1)"

# ---------------------------------------------------------------------------
# 1. AGREEING: identical revisions must NOT be reported as diverged, and must be
#    positively reported — a silent no-op would otherwise look the same.
# ---------------------------------------------------------------------------
agree_table="$WORK/agree.tsv"
write_table "$agree_table" '' '' ''
agree_out="$WORK/agree.out"
if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" "$SCRIPT" >"$agree_out" 2>&1; then
  grep -q 'DIVERGED' "$agree_out" &&
    fail 'identical revisions were reported as DIVERGED — the check cannot distinguish the two states'
  grep -q 'IN-SYNC' "$agree_out" ||
    fail 'the agreeing case produced no IN-SYNC line, so a silent no-op would look identical'
  grep -q '0 unresolved' "$agree_out" ||
    fail 'the agreeing case reports unresolved consumers'
  [ "$failures" -eq 0 ] && pass 'matching revisions report IN-SYNC and never DIVERGED'
else
  fail "the script exited non-zero on the all-agreeing fixture: $(cat "$agree_out")"
fi

# ---------------------------------------------------------------------------
# 2. DIFFERING: the measured two-behind case (#3048) in miniature. Both revisions
#    must be named, because the allow-list has to accept both.
# ---------------------------------------------------------------------------
diff_table="$WORK/diff.tsv"
write_table "$diff_table" "$first_repo" "$SHA_B" "$SHA_C"
diff_out="$WORK/diff.out"
before=$failures
if PUBLISH_REVISION_RESOLVER="$(make_stub "$diff_table" diff)" "$SCRIPT" >"$diff_out" 2>&1; then
  grep -q 'DIVERGED' "$diff_out" ||
    fail 'a consumer whose signing revision differs from its current pin was NOT reported as DIVERGED'
  grep -q -- "$first_repo" "$diff_out" || fail "the diverged consumer ($first_repo) is not named"
  grep -q "$SHA_B" "$diff_out" ||
    fail 'the signing revision is missing, so an allow-list cannot be built from it'
  grep -q "$SHA_C" "$diff_out" ||
    fail 'the current pin is missing, so an allow-list cannot be built from it'
  [ "$failures" -eq "$before" ] && pass 'a diverged consumer is reported with both revisions named'
else
  fail "the script exited non-zero on the diverging fixture: $(cat "$diff_out")"
fi

# ---------------------------------------------------------------------------
# 3. DISCOVERY over a real tree that matches NOTHING. An empty result from a filtered
#    read is a claim about the FILTER. This deliberately uses a populated directory of
#    non-matching YAML rather than a missing one, so it exercises the "manifests moved,
#    were renamed, or changed spelling" path and not merely a `[ -d ]` guard.
# ---------------------------------------------------------------------------
nomatch_root="$WORK/nomatch"
mkdir -p "$nomatch_root"
cat >"$nomatch_root/unrelated.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: nothing-to-see
data:
  note: "no cosign subject here"
YAML
nomatch_out="$WORK/nomatch.out"
if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" \
PUBLISH_CONSUMER_ROOT="$nomatch_root" "$SCRIPT" >"$nomatch_out" 2>&1; then
  fail 'discovery over a tree matching nothing exited 0 — a moved manifest would report as clean'
else
  grep -q 'not discovered' "$nomatch_out" ||
    fail 'the discovery failure does not say which consumers went missing'
  pass 'a tree matching nothing fails closed instead of reporting a clean portfolio'
fi

# ---------------------------------------------------------------------------
# 4. RIGHT SIZE, WRONG MEMBERSHIP. This is why the floor is an identity check and not a
#    count: one real consumer dropping out while any other file drops in leaves the total
#    unchanged, so a count-based floor passes and the vanished consumer is never checked.
# ---------------------------------------------------------------------------
swap_root="$WORK/swap"
mkdir -p "$swap_root"
i=0
while IFS=$'\t' read -r repo workflow _version; do
  [ -n "$repo" ] || continue
  i=$((i + 1))
  # Substitute an impostor for one real consumer, keeping the total identical.
  name="$repo"
  [ "$repo" = "$first_repo" ] && name='impostor-repo'
  cat >"$swap_root/consumer-$i.yaml" <<YAML
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: c$i
spec:
  url: oci://ghcr.io/devantler-tech/$name/manifests
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\\.actions\\.githubusercontent\\.com$'
        subject: '^https://github\\.com/devantler-tech/actions/\\.github/workflows/$workflow\\.yaml@[0-9a-f]{40}\$'
YAML
done <<<"$consumers"
swap_out="$WORK/swap.out"
if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" \
PUBLISH_CONSUMER_ROOT="$swap_root" "$SCRIPT" >"$swap_out" 2>&1; then
  fail 'a discovery set of the right SIZE but wrong MEMBERSHIP passed — a consumer can vanish silently'
else
  # The set comparison runs in BOTH directions, and the unregistered side fires first here: the
  # impostor is not in EXPECTED_CONSUMERS, which is itself the stronger objection — a consumer this
  # script does not know about is one whose later disappearance it could not notice. Either half
  # naming its cause is a pass; silence is not.
  grep -qE -- "impostor-repo|$first_repo" "$swap_out" ||
    fail "the discovery failure names neither the unregistered consumer nor the missing one"
  grep -qE -- 'not registered|not discovered' "$swap_out" ||
    fail "the discovery failure does not say WHICH direction of the set comparison failed"
  pass 'a same-size discovery set with an unregistered member fails closed and names the cause'
fi

# ---------------------------------------------------------------------------
# 5. A RESOLVER ANSWER THAT IS NOT TWO SHAs. `cut -f2` without `-s` echoes the WHOLE line
#    when the delimiter is absent, so a resolver emitting one tab-free line — exactly the
#    shape of a `gh api` error body — made signing == current and reported IN-SYNC for
#    every consumer with exit 0. That is the worst failure this script can have.
# ---------------------------------------------------------------------------
junk_resolver="$WORK/resolver-junk.sh"
cat >"$junk_resolver" <<'JUNK'
#!/usr/bin/env bash
# exit 0 ON PURPOSE. A FAILING resolver is discarded by the caller (`answer=$(...) || answer=""`),
# so only a SUCCEEDING resolver reaches the tab-free-answer parsing path this case exists to test.
# With `exit 1` the case proved only that an EMPTY answer is UNRESOLVED — a different, weaker claim.
printf '%s\n' '{"message":"Not Found","status":"404"}'
exit 0
JUNK
chmod +x "$junk_resolver"
junk_out="$WORK/junk.out"
if PUBLISH_REVISION_RESOLVER="$junk_resolver" "$SCRIPT" >"$junk_out" 2>&1; then
  fail 'a resolver emitting a tab-free error body exited 0 — every consumer read as IN-SYNC'
else
  grep -q 'IN-SYNC' "$junk_out" &&
    fail 'an unparseable resolver answer was reported as IN-SYNC rather than UNRESOLVED'
  grep -q 'UNRESOLVED' "$junk_out" ||
    fail 'an unparseable resolver answer produced no UNRESOLVED line'
  grep -q 'FAILED' "$junk_out" ||
    fail 'the failure explanation is absent from stdout, so the CI step summary would end on a clean-looking tally'
  pass 'a resolver answer that is not two SHAs is UNRESOLVED, fails the run, and explains itself on stdout'
fi

# ---------------------------------------------------------------------------
# 6. ONE UNRESOLVABLE CONSUMER MUST NOT HIDE THE OTHERS. The script collects and fails at
#    the end precisely so a single lookup failure does not suppress the consumers that did
#    resolve; nothing proved that until now.
# ---------------------------------------------------------------------------
partial_table="$WORK/partial.tsv"
awk -F'\t' -v r="$first_repo" '$1 != r' "$agree_table" >"$partial_table"
partial_out="$WORK/partial.out"
if PUBLISH_REVISION_RESOLVER="$(make_stub "$partial_table" partial)" "$SCRIPT" >"$partial_out" 2>&1; then
  fail 'a consumer the resolver could not answer for did not fail the run'
else
  grep -q -- "$first_repo" "$partial_out" ||
    fail 'the unresolvable consumer is not named, so the cause is not diagnosable'
  got_insync="$(grep -c '^IN-SYNC' "$partial_out" || true)"
  [ "$got_insync" -eq "$expected_insync" ] ||
    fail "one unresolvable consumer suppressed the others: expected $expected_insync IN-SYNC, got $got_insync"
  pass 'an unresolvable consumer fails the run, is named, and does not hide the consumers that resolved'
fi

# ---------------------------------------------------------------------------
# 7. ARTIFACT NAME vs SOURCE REPOSITORY. `.github` cannot be an OCI path component, so its
#    artifact ships as `github-config`. Deriving the repository from the URL alone names a
#    repository that does not exist, so every lookup for a healthy consumer fails.
# ---------------------------------------------------------------------------
if printf '%s\n' "$consumers" | cut -f1 | grep -qxF -- '.github'; then
  pass 'the github-config artifact is attributed to its real source repository (.github)'
else
  fail 'github-config is not mapped to .github — its revisions cannot be resolved at all'
fi
if printf '%s\n' "$consumers" | cut -f1 | grep -qxF -- 'github-config'; then
  fail 'the OCI artifact name github-config leaked through as a repository name; no such repository exists'
fi

# ---------------------------------------------------------------------------
# 8. AN EXTRA, UNREGISTERED CONSUMER. This isolates the OTHER direction of the set
#    comparison: every expected consumer is present, so the "missing" check cannot fire
#    and only the unregistered check can. Without this the swap fixture above passes on
#    either direction and the unregistered half is never actually exercised — which is
#    exactly what an ablation showed before this case existed.
#
#    It matters because an unregistered consumer is one whose later disappearance this
#    script could not notice: it would drop out and every registered name would still be
#    present, so the run would exit clean.
# ---------------------------------------------------------------------------
extra_root="$WORK/extra"
mkdir -p "$extra_root"
j=0
while IFS=$'\t' read -r repo workflow _version; do
  [ -n "$repo" ] || continue
  j=$((j + 1))
  # `.github` is the artifact name `github-config` on the wire; emit the OCI name so the
  # script's own mapping reproduces the real repository, exactly as in production.
  oci="$repo"
  [ "$repo" = '.github' ] && oci='github-config'
  cat >"$extra_root/real-$j.yaml" <<YAML
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: r$j
spec:
  url: oci://ghcr.io/devantler-tech/$oci/manifests
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\\.actions\\.githubusercontent\\.com\$'
        subject: '^https://github\\.com/devantler-tech/actions/\\.github/workflows/$workflow\\.yaml@[0-9a-f]{40}\$'
YAML
done <<<"$consumers"
cat >"$extra_root/extra.yaml" <<'YAML'
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: newcomer
spec:
  url: oci://ghcr.io/devantler-tech/newcomer/manifests
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\.actions\.githubusercontent\.com$'
        subject: '^https://github\.com/devantler-tech/actions/\.github/workflows/publish-app\.yaml@[0-9a-f]{40}$'
YAML
extra_out="$WORK/extra.out"
if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" \
PUBLISH_CONSUMER_ROOT="$extra_root" "$SCRIPT" >"$extra_out" 2>&1; then
  fail 'an unregistered sixth consumer was accepted — its later disappearance could not be noticed'
else
  grep -q 'not registered' "$extra_out" ||
    fail 'the failure does not identify the unregistered direction of the set comparison'
  grep -q 'newcomer' "$extra_out" ||
    fail 'the unregistered consumer is not named, so registering it needs guesswork'
  grep -q 'not discovered' "$extra_out" &&
    fail 'the run reported a MISSING consumer; this fixture has all five, so the case is not isolating'
  pass 'an extra unregistered consumer fails closed and is named'
fi

# ---------------------------------------------------------------------------
# 9. A BOUNDED SEMVER CONSTRAINT MUST REFUSE, NOT GUESS. An unbounded `>=1.0.0` and
#    "whatever is newest" happen to agree, which is why discarding the constraint looked
#    harmless. A bounded selector (`~1.4`, `<2.0.0`) does not agree: the newest published
#    tag is one Flux would never serve, so its workflow revision would be attributed to
#    the deployed artifact and the real signer omitted from the allow-list.
#
#    Resolving such a range needs Flux-compatible semver selection this script does not
#    implement, so the honest outcome is a named refusal.
# ---------------------------------------------------------------------------
# Each selector below is bounded and must refuse BY NAME. `~1.4` is the simple form;
# `>=1.0.0 <2.0.0` is the compound one, which matters because a lower-bound-prefix
# test accepts it — the upper bound is simply not looked at — and the script would
# then treat a bounded range as unbounded and resolve it to the newest tag.
bounded_case() {
  bc_label=$1
  bc_selector=$2
  bc_expect=${3:-bounded semver constraint}
  # How the first consumer's `spec.ref` is written. `semver` is the original shape;
  # `raw` passes the selector through verbatim (for a digest), and `omit` drops the
  # `ref:` key entirely -- the unpinned case, which is a refusal with no selector at all.
  bc_ref_kind=${4:-semver}
  # For `raw`, the ref LINE and the string the refusal must NAME differ: the script
  # reports `sha256:...` while the manifest writes `digest: sha256:...`.
  bc_ref_line=${5:-}
  bc_root="$WORK/bounded-$bc_label"
  mkdir -p "$bc_root"
  k=0
  while IFS=$'\t' read -r repo workflow _version; do
    [ -n "$repo" ] || continue
    k=$((k + 1))
    oci="$repo"
    [ "$repo" = '.github' ] && oci='github-config'
    # One consumer gets the BOUNDED range; the rest keep an unbounded one, so the
    # refusal cannot be confused with a wholesale failure of the fixture.
    if [ "$k" -eq 1 ]; then
      case "$bc_ref_kind" in
        raw) ref_block="  ref:"$'\n'"    $bc_ref_line" ;;
        omit) ref_block='' ;;
        *) ref_block="  ref:"$'\n'"    semver: \"$bc_selector\"" ;;
      esac
    else
      ref_block="  ref:"$'\n'"    semver: \">=1.0.0\""
    fi
    cat >"$bc_root/c-$k.yaml" <<YAML
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: b$k
spec:
$ref_block
  url: oci://ghcr.io/devantler-tech/$oci/manifests
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\\.actions\\.githubusercontent\\.com\$'
        subject: '^https://github\\.com/devantler-tech/actions/\\.github/workflows/$workflow\\.yaml@[0-9a-f]{40}\$'
YAML
  done <<<"$consumers"
  bc_out="$WORK/bounded-$bc_label.out"
  # The stub is safe here BECAUSE the refusal is decided from the manifest, before any
  # resolver is consulted. When this check lived inside the resolver, the only way to
  # reach it was to let the real one run — which made this case hit the network and fail
  # in CI for an unrelated reason. A hermetic case that reaches the branch is strictly
  # better than a live one that does.
  if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" \
  PUBLISH_CONSUMER_ROOT="$bc_root" "$SCRIPT" >"$bc_out" 2>&1; then
    fail "a bounded semver constraint ($bc_selector) was silently resolved to the newest tag instead of refusing"
  else
    grep -q "$bc_expect" "$bc_out" ||
      fail "the run failed but not because of the bounded constraint ($bc_selector) — the case is not testing what it claims"
    grep -qF "$bc_selector" "$bc_out" ||
      fail "the refusal does not name the constraint ($bc_selector), so the cause is not diagnosable"
    pass "a bounded semver constraint refuses by name instead of guessing the newest tag: $bc_selector"
  fi
}

bounded_case simple '~1.4'
# A COMPOUND range beginning with a lower bound. The whole point: it *starts* like the
# unbounded `>=1.0.0` that is legitimately allowed, so any test looking only at the
# prefix accepts it and discards the `<2.0.0` — attributing a 2.x tag's workflow
# revision to an artifact Flux would never deploy, and omitting the real signer.
bounded_case compound '>=1.0.0 <2.0.0'

# A lower bound carrying a PRERELEASE component. Flux/Masterminds excludes prerelease
# versions from a range whose bound has none, but ADMITS them once the bound carries one
# — so `>=1.0.0-0` legitimately selects `2.0.0-rc.1`. The tag walk only ever considers
# `X.Y.Z`, so it would discard that tag, walk back to an older stable release, and
# attribute THAT release's workflow revision to the deployed artifact. It starts exactly
# like the unbounded `>=1.0.0`, so the compound-range character class does not catch it:
# every character is one a single lower bound may legitimately contain.
# THE ROW MUST NAME THE CAUSE THE RESOLVER GAVE. `effective_version` refuses for five
# distinct reasons and writes the specific one to stderr, but the report printed a fixed
# "bounded semver constraint" for all of them -- and the step summary is stdout-only, so a
# digest-pinned or unpinned consumer was not merely described elsewhere, it was described
# WRONGLY with no other copy to consult. Two causes are asserted here, one of which is not
# a semver constraint at all, so a regression to any single fixed wording fails.
bounded_case digest_pinned 'sha256:abcdef' 'digest-pinned reference' raw 'digest: sha256:abcdef'
bounded_case unpinned_ref 'spec.ref omitted' 'unpinned reference' omit

# These two refuse for the PRERELEASE reason, not the generic bounded-range one, so they
# assert that specific wording. The row used to print one fixed cause for every refusal,
# which made the default expectation match here while describing the wrong thing.
bounded_case prerelease '>=1.0.0-0' 'prerelease semver constraint'
bounded_case prerelease_named '>1.2.3-alpha.1' 'prerelease semver constraint'

# A STRICT lower bound. `>=1.0.0` admits 1.0.0, so treating it as unbounded and taking the
# newest published tag is correct. `>1.0.0` EXCLUDES 1.0.0 — so when 1.0.0 is the newest
# published tag, Flux selects nothing there while the walk would hand back 1.0.0 and
# attribute ITS workflow revision to whatever is deployed. It begins exactly like the
# unbounded `>=1.0.0`, and every character is one a legitimate single lower bound may
# contain, so no character-class check catches it.
bounded_case strict_lower '>1.0.0' 'strict lower-bound semver constraint'

# MALFORMED selectors that merely START like the inclusive lower bound. The previous
# prefix test matched any trailing text, so these were read as UNBOUNDED and the walk
# returned the newest published tag — a confident signing revision for an artifact Flux
# would never have selected, from a selector Flux itself rejects. Every character in both
# is one a legitimate single lower bound may contain, so no character class catches them.
bounded_case malformed_trailing '>=1.0.0=bad' 'malformed or unsupported semver constraint'
bounded_case malformed_second_bound '>=1.0.0>=2.0.0' 'malformed or unsupported semver constraint'

# ---------------------------------------------------------------------------
# 10. AN EMPTY MIDDLE FIELD MUST NOT SHIFT `origin` INTO `current`. (#3305 review)
#     Tab is IFS WHITESPACE, so `IFS=$'\t' read -r signing current origin` COLLAPSES
#     adjacent tabs: an answer of `SHA_A<TAB><TAB>SHA_A` assigned SHA_A to BOTH signing
#     and current and reported IN-SYNC — a confident wrong answer produced by the parser
#     rather than the network, which is the one outcome this script must never have.
#     Written without arrays or `read -d`, so it holds on the Bash 3.2 that ships on macOS.
# ---------------------------------------------------------------------------
collapse_resolver="$WORK/resolver-collapse.sh"
cat >"$collapse_resolver" <<COLLAPSE
#!/usr/bin/env bash
# exit 0 on purpose: a FAILING resolver is discarded by the caller, so only a SUCCEEDING
# one reaches the field-splitting path this case exists to test.
printf '%s\t\t%s\n' '$SHA_A' '$SHA_A'
exit 0
COLLAPSE
chmod +x "$collapse_resolver"
collapse_out="$WORK/collapse.out"
if PUBLISH_REVISION_RESOLVER="$collapse_resolver" "$SCRIPT" >"$collapse_out" 2>&1; then
  fail 'an answer with an EMPTY MIDDLE FIELD exited 0 — the collapsed field was compared as the current revision'
else
  grep -q 'IN-SYNC' "$collapse_out" &&
    fail 'SHA<TAB><TAB>SHA was reported as IN-SYNC — adjacent tabs collapsed and the origin field became the current one'
  grep -q 'UNRESOLVED' "$collapse_out" ||
    fail 'an answer with an empty middle field produced no UNRESOLVED line'
  pass 'an empty middle field is UNRESOLVED, never a comparison against the shifted field'
fi

# ---------------------------------------------------------------------------
# 11. TRAILING OUTPUT AFTER A VALID LINE MUST NOT BE ACCEPTED UNSEEN. (#3305 review)
#     `read` stops at the first line, so a resolver emitting a good line followed by
#     anything at all was accepted on the strength of the part that parsed.
# ---------------------------------------------------------------------------
extra_resolver="$WORK/resolver-extra.sh"
cat >"$extra_resolver" <<EXTRA
#!/usr/bin/env bash
printf '%s\t%s\nunexpected trailing output\n' '$SHA_A' '$SHA_A'
exit 0
EXTRA
chmod +x "$extra_resolver"
extra_out="$WORK/extra.out"
if PUBLISH_REVISION_RESOLVER="$extra_resolver" "$SCRIPT" >"$extra_out" 2>&1; then
  fail 'a multi-line resolver answer exited 0 — only its first line was ever examined'
else
  grep -q 'IN-SYNC' "$extra_out" &&
    fail 'a valid first line with trailing output was reported as IN-SYNC'
  grep -q 'UNRESOLVED' "$extra_out" ||
    fail 'a multi-line resolver answer produced no UNRESOLVED line'
  pass 'trailing output after a valid line is UNRESOLVED, not accepted on the first line alone'
fi

# ---------------------------------------------------------------------------
# 12. FLUX REFERENCE PRECEDENCE: digest > semver > tag, omitted ref emits `unpinned`.
#     (#3305 review) Reading `tag` first attributed a document carrying both a tag and a
#     digest to a tag Flux never serves; a digest or an omitted ref collapsed to the
#     meaningless `semver:`, which `effective_version` then refused as a bounded
#     constraint, so a resolvable consumer read as UNRESOLVED. Asserted against the
#     expression itself, because the selector choice is a property of the MANIFEST.
# ---------------------------------------------------------------------------
# 🔴 EXTRACTED FROM THE SCRIPT, NEVER RETYPED. A copy of the expression here would assert
# only that SOME expression is correct, and would keep passing while the one the script
# actually runs regressed — the test would pin nothing. The extraction is asserted
# non-empty below, so a rename or reformat fails the case loudly instead of silently
# testing an empty string.
# `|| true` is load-bearing: under `set -e` a no-match grep in a command substitution
# ABORTS the suite at this line, so the guard below never runs and the run dies with exit 1
# and NO diagnostic — a failure nobody can act on. Measured while ablating this case.
ref_expr="$(grep -o '(((\.spec\.ref\.digest.*"unpinned")' "$SCRIPT" || true)"
[ -n "$ref_expr" ] ||
  fail 'could not extract the reference-precedence expression from the script — the case would pass vacuously'
ref_case() { # <name> <ref-yaml-block> <expected>
  local name="$1" block="$2" expected="$3" doc="$WORK/ref-$1.yaml" got
  {
    printf 'kind: OCIRepository\nspec:\n  url: oci://ghcr.io/devantler-tech/x/manifests\n'
    [ -n "$block" ] && printf '%s\n' "$block"
  } >"$doc"
  got="$(yq eval -r "$ref_expr" "$doc" 2>&1)"
  [ "$got" = "$expected" ] ||
    fail "reference precedence ($name): expected [$expected], got [$got]"
}
ref_case tag '  ref:
    tag: v1.2.3' 'v1.2.3'
ref_case semver '  ref:
    semver: ">=1.0.0"' 'semver:>=1.0.0'
ref_case digest '  ref:
    digest: sha256:abcdef' 'digest:sha256:abcdef'
ref_case tag-and-digest '  ref:
    tag: v1.2.3
    digest: sha256:abcdef' 'digest:sha256:abcdef'
ref_case tag-and-semver '  ref:
    tag: v1.2.3
    semver: ">=1.0.0"' 'semver:>=1.0.0'
ref_case omitted '' 'unpinned'
pass 'Flux reference precedence is digest > semver > tag, and an omitted ref emits unpinned rather than a literal tag'

# ---------------------------------------------------------------------------
# 13. BUILD METADATA MUST NOT BE DISCARDED, AND A TIE MUST NOT BE GUESSED. (#3305 review)
#     SemVer ignores build metadata for precedence, so `2.0.0` and `2.0.0+build.1` rank
#     equally: a tag walk matching only the bare form silently discards the metadata tag
#     and walks back to an older release, attributing THAT release's workflow revision to
#     the deployed artifact. Both forms are candidates; a core version carrying two tags
#     refuses instead of picking one.
#
#     This is the only case that exercises the REAL resolver, so it stubs `gh` on PATH
#     rather than replacing the resolver: the behaviour under test lives inside
#     `deployed_tag`, which a resolver stub bypasses entirely.
# ---------------------------------------------------------------------------
bm_bin="$WORK/bm-bin"
mkdir -p "$bm_bin"
# Quoted delimiter: the stub's own comments mention shell syntax, and an UNQUOTED
# heredoc runs backticks and expands parameters while WRITING the file — which silently
# executed fragments of those comments. Values it needs come through the environment.
cat >"$bm_bin/gh" <<'GHSTUB'
#!/usr/bin/env bash
# Minimal forge stub. Only the five call shapes the default resolver makes are answered;
# anything else exits non-zero, so an unstubbed call surfaces as a failure rather than as
# an empty string the script might read as data.
args="$*"
# The tag must arrive as a PARAMETER, never interpolated into the query string. A tag may
# carry SemVer build metadata (v2.0.0+build.1), and a raw + in a query string is decoded as
# a SPACE on the wire, so the run for a genuinely published tag is never matched and a
# healthy consumer reports UNRESOLVED. This stub receives argv and so cannot observe
# percent-encoding itself; refusing the old call shape is what pins the fix.
case "$args" in
  *"/actions/runs?"*)
    # gh_retry discards stderr, so a message alone would be invisible and the regression
    # would surface only as unexplained unresolved consumers. Record it where the suite
    # can assert on it and name the cause.
    printf 'interpolated\n' >>"${BM_VIOLATION_LOG:-/dev/null}"
    printf 'stub: the run lookup interpolated its query string; pass the tag with --raw-field so + survives encoding\n' >&2
    exit 64
    ;;
  *"/contents/.github/workflows/cd.yaml?"*)
    # Same rule for the PIN lookup. The selected tag reaches this call too, so an
    # interpolated ref loses a + exactly as the run lookup did, and the workflow body then
    # fails to load -- reporting a healthy consumer UNRESOLVED.
    printf 'interpolated\n' >>"${BM_VIOLATION_LOG:-/dev/null}"
    printf 'stub: the pin lookup interpolated its query string; pass the ref with --raw-field so + survives encoding\n' >&2
    exit 64
    ;;
esac
case "$args" in
  *"/packages/container/"*"/versions"*)
    # Current GHCR metadata, deliberately separate from git tags and successful workflow
    # runs. A deleted package version leaves both of those historical facts behind. The
    # real publish workflows strip the source tag's v prefix for the OCI version.
    case "$args" in
      *wedding-app*) printf "${BM_WEDDING_REGISTRY_TAGS:-${BM_WEDDING_TAGS:-v1.9.0\n}}" | sed -e 's/^v//' -e 's/+/_/' ;;
      *aws*)         printf "${BM_AWS_REGISTRY_TAGS:-${BM_AWS_TAGS:-v1.9.0\n}}" | sed -e 's/^v//' -e 's/+/_/' ;;
      *)             printf '1.9.0\n' ;;
    esac
    ;;
  *"/tags?per_page=100"*)
    # Per-repo tag lists, so each case can put the interesting shape on exactly ONE
    # consumer and leave the rest clean: a refusal or divergence can then only have come
    # from that consumer.
    case "$args" in
      *wedding-app*) printf "${BM_WEDDING_TAGS:-v1.9.0\n}" ;;
      *aws*)         printf "${BM_AWS_TAGS:-v1.9.0\n}" ;;
      *)             printf 'v1.9.0\n' ;;
    esac
    ;;
  *"/commits/"*)
    # A NAMED tag whose commit lookup fails, the way a rate limit or an API outage does.
    # Nothing else about the fixture changes, so a case using it isolates the failure path.
    bm_ctag="${args##*/commits/}"
    bm_ctag="${bm_ctag%% *}"
    if [ -n "${BM_COMMIT_FAIL_TAG:-}" ] && [ "$bm_ctag" = "$BM_COMMIT_FAIL_TAG" ]; then
      printf 'API rate limit exceeded\n' >&2
      exit 1
    fi
    # A tag that lives at its OWN commit, as real tags do. The fixture otherwise resolves
    # every tag to one shared commit, which was observationally fine while the signing pin
    # was read at the tag NAME. Now that it is read at the VERIFIED COMMIT, giving a tag its
    # own commit is the only way a case can still observe which tag was selected.
    if [ -n "${BM_OWNCOMMIT_TAG:-}" ] && [ "$bm_ctag" = "$BM_OWNCOMMIT_TAG" ]; then
      printf '%s\n' "$BM_SHA_B"
      exit 0
    fi
    # The commit a tag currently resolves to. Every tag resolves to BM_TAG_SHA, so the run
    # lookup below matches by default and the existing cases keep exercising their own
    # guards rather than failing for want of this one.
    printf '%s\n' "${BM_TAG_SHA:-$BM_SHA_C}"
    ;;
  *"/actions/runs"*)
    # Echo the requested ref back so every candidate tag reads as published. Pinning this
    # to one tag would make the ablations fail for want of a published release rather than
    # for the guard under test, and the cases would stop discriminating.
    #
    # The tag now arrives as a --raw-field PARAMETER rather than interpolated into the
    # query string, so it is trailed by a SPACE rather than an &. Both are trimmed, so this
    # stub cannot silently match nothing if the call shape moves again. gh does the
    # percent-encoding on the wire, so the stub still sees the raw tag.
    bm_ref="${args#*branch=}"
    bm_ref="${bm_ref%%&*}"
    bm_ref="${bm_ref%% *}"
    # The same failure one lookup later: the runs query itself cannot be answered.
    if [ -n "${BM_RUNS_FAIL_TAG:-}" ] && [ "$bm_ref" = "$BM_RUNS_FAIL_TAG" ]; then
      printf 'API rate limit exceeded\n' >&2
      exit 1
    fi
    if [ -n "${BM_RUNS_RESPONSE_TAG:-}" ] && [ "$bm_ref" = "$BM_RUNS_RESPONSE_TAG" ]; then
      cat "$BM_RUNS_RESPONSE_FILE"
      exit 0
    fi
    # A tag that was QUERIED SUCCESSFULLY and simply never published: the run exists and
    # failed. This is the ordinary case the walk is built for, and it is what separates
    # "the answer is no" from "there is no answer".
    if [ -n "${BM_UNPUBLISHED_TAG:-}" ] && [ "$bm_ref" = "$BM_UNPUBLISHED_TAG" ]; then
      printf '{"total_count":1,"workflow_runs":[{"name":"CD","conclusion":"failure","path":".github/workflows/cd.yaml","head_branch":"%s","head_sha":"%s"}]}\n' \
        "$bm_ref" "${BM_TAG_SHA:-$BM_SHA_C}"
      exit 0
    fi
    # A MOVED TAG: the historical run still carries the commit the tag pointed at BEFORE it
    # was moved, while `/commits/<tag>` above reports where it points NOW. Naming a tag in
    # BM_MOVED_TAG reproduces exactly that, and nothing else about the fixture changes.
    bm_run_sha="${BM_TAG_SHA:-$BM_SHA_C}"
    # Its run carries that same commit, or the tag would read as MOVED and refuse.
    [ -n "${BM_OWNCOMMIT_TAG:-}" ] && [ "$bm_ref" = "$BM_OWNCOMMIT_TAG" ] && bm_run_sha="$BM_SHA_B"
    [ "$bm_ref" = "${BM_MOVED_TAG:-}" ] && bm_run_sha="$BM_SHA_A"
    printf '{"total_count":1,"workflow_runs":[{"name":"CD","conclusion":"success","path":".github/workflows/cd.yaml","head_branch":"%s","head_sha":"%s"}]}\n' "$bm_ref" "$bm_run_sha"
    ;;
  *"/contents/.github/workflows/cd.yaml"*)
    # The pin DEPENDS ON THE REF, which is what makes the walk's choice observable: the
    # report prints the signing revision and never the tag it came from, so a case can
    # only tell which tag was selected by giving that tag a distinct pin.
    bm_pinref="${args#*ref=}"
    bm_pinref="${bm_pinref%%&*}"
    # args is the whole argv joined by spaces, so the ref is trailed by the Accept-header
    # flags. Without this trim the ref never compares equal, every tag reads as the base
    # SHA, and that looks exactly like the walk having chosen the older tag.
    bm_pinref="${bm_pinref%% *}"
    bm_pinsha="$BM_SHA_A"
    # Keyed on the COMMIT, not the tag name: `pin_at_ref` is handed the verified commit for
    # the signing read and only ever a BRANCH name otherwise, so a tag-name key here would
    # never match and the case would silently stop discriminating.
    [ -n "${BM_OWNCOMMIT_TAG:-}" ] && [ "$bm_pinref" = "$BM_SHA_B" ] && bm_pinsha="$BM_SHA_B"
    # A tag that MOVES between publication verification and this lookup. Reading cd.yaml at
    # the mutable tag NAME sees the NEW commit's pin; reading it at the commit SHA that was
    # verified as published sees the pin that actually signed the artifact. Giving the two
    # refs different pins is what makes the caller's choice of ref observable at all.
    [ -n "${BM_TOCTOU_TAG:-}" ] && [ "$bm_pinref" = "$BM_TOCTOU_TAG" ] && bm_pinsha="$BM_SHA_B"
    # The over-permissiveness control: give the VERIFIED commit a pin that genuinely differs
    # from main's, so a real divergence must still be reported rather than smoothed into
    # agreement by a fix that simply reads a different ref.
    [ -n "${BM_TOCTOU_SHA_PIN:-}" ] && [ "$bm_pinref" = "${BM_TAG_SHA:-$BM_SHA_C}" ] && bm_pinsha="$BM_TOCTOU_SHA_PIN"
    # BOTH shared workflows, because the cd.yaml request carries no workflow name and the
    # five consumers split across publish-app and publish-manifests. The caller filters to
    # the one it asked about, so emitting both is exact rather than lax; a stub emitting
    # only one silently made EVERY consumer unresolvable.
    printf 'jobs:\n  app:\n    uses: devantler-tech/actions/.github/workflows/publish-app.yaml@%s\n  manifests:\n    uses: devantler-tech/actions/.github/workflows/publish-manifests.yaml@%s\n' \
      "$bm_pinsha" "$bm_pinsha"
    ;;
  *"repos/devantler-tech/"*)
    printf 'main\n'
    ;;
  *) exit 1 ;;
esac
exit 0
GHSTUB
chmod +x "$bm_bin/gh"

bm_out="$WORK/buildmeta.out"
# No PUBLISH_REVISION_RESOLVER: the default resolver must run for `deployed_tag` to be
# reached at all. Every consumer keeps an unbounded `>=1.0.0`, so the walk is entered.
bm_root="$WORK/buildmeta-root"
mkdir -p "$bm_root"
k=0
while IFS=$'\t' read -r repo workflow _version; do
  [ -n "$repo" ] || continue
  k=$((k + 1))
  oci="$repo"
  [ "$repo" = '.github' ] && oci='github-config'
  cat >"$bm_root/c-$k.yaml" <<YAML
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: bm$k
spec:
  ref:
    semver: ">=1.0.0"
  url: oci://ghcr.io/devantler-tech/$oci/manifests
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\\.actions\\.githubusercontent\\.com\$'
        subject: '^https://github\\.com/devantler-tech/actions/\\.github/workflows/$workflow\\.yaml@[0-9a-f]{40}\$'
YAML
done <<<"$consumers"

if BM_WEDDING_TAGS='v2.0.0\nv2.0.0+build.1\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$bm_root" "$SCRIPT" >"$bm_out" 2>&1; then
  fail 'a version carried by two tags was silently resolved instead of refusing'
else
  grep -q 'carried by more than one tag' "$bm_out" ||
    fail 'the run failed but not because of the build-metadata tie — the case is not testing what it claims'
  grep -qF '2.0.0+build.1' "$bm_out" ||
    fail 'the refusal does not name the tags that tie, so the cause is not diagnosable'
  # A CONTROL: the other four consumers must resolve through the same stub, or this
  # "refusal" could just be the whole fixture failing for an unrelated reason.
  #
  # 🔴 COUNT THE OUTCOME LINES; a name match is NOT a control. The report names every
  # consumer it discovered, on the UNRESOLVED line as readily as the IN-SYNC one, so
  # `grep -q wedding-app` matches just as well when ALL FIVE consumers failed — which is
  # precisely the unrelated-failure case this control exists to exclude. It asserted only
  # that the tying consumer was mentioned, which the refusal message above already proves.
  #
  # `|| true` is load-bearing on both counts: `grep -c` exits 1 when the count is zero, and
  # a command substitution's status becomes the assignment's, so under `set -e` a legitimate
  # zero would abort the suite here instead of reaching the comparison that reports it.
  bm_unresolved="$(grep -c '^UNRESOLVED' "$bm_out" || true)"
  bm_insync="$(grep -c '^IN-SYNC' "$bm_out" || true)"
  [ "$bm_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the build-metadata tie), got $bm_unresolved — a different count means the fixture failed for an unrelated reason"
  [ "$bm_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $bm_insync"
  grep -qE '^UNRESOLVED +wedding-app' "$bm_out" ||
    fail 'the unresolved consumer is not the one that ties'
  pass 'a version carried by both a bare and a build-metadata tag refuses instead of guessing'
fi

# ---------------------------------------------------------------------------
# 13b. A PARTIAL TAG TIES A STRICT ONE, AND IS INVISIBLE TO EVERY OTHER CHECK.
#
# Flux coerces `v2.0` to 2.0.0, so it stands at the SAME precedence as `v2.0.0` and may
# be the ref it selects. But `sort -V` orders `2.0.0` ABOVE `2.0`, so the partial reads
# as safely lower, and its spelling matches neither the three-component core pattern nor
# the `v`-duality fold -- so it never entered the variant set and the tie refusal never
# fired. The walk then considered only the strict tag and could report ITS signing
# revision for an artifact the partial tag produced.
partial_tie_out="$WORK/partial-tie.out"
if BM_WEDDING_TAGS='v2.0.0\nv2.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/partial-tie.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$bm_root" "$SCRIPT" >"$partial_tie_out" 2>&1; then
  fail 'a strict version tied by a PARTIAL tag was silently resolved instead of refusing'
else
  grep -q 'published as a PARTIAL tag' "$partial_tie_out" ||
    fail 'the run failed but not because of the partial-tag tie -- the case is not testing what it claims'
  grep -qF 'v2.0' "$partial_tie_out" ||
    fail 'the refusal does not name the partial tag, so the cause is not diagnosable'
  # Same control as the build-metadata tie: count the outcome lines, because the report
  # names every consumer it discovered on the UNRESOLVED line as readily as the IN-SYNC
  # one, so a name match would also pass if ALL FIVE consumers had failed.
  pt_unresolved="$(grep -c '^UNRESOLVED' "$partial_tie_out" || true)"
  pt_insync="$(grep -c '^IN-SYNC' "$partial_tie_out" || true)"
  [ "$pt_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the partial tie), got $pt_unresolved -- a different count means the fixture failed for an unrelated reason"
  [ "$pt_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $pt_insync"
  pass 'a strict version tied by a partial tag refuses instead of preferring the strict spelling'
fi

# A MIRROR, and the reason the refusal is conditioned on a trailing-zero core: `2.1.3`
# has NO partial spelling, so a repository publishing it alongside an unrelated `v2.0`
# must still resolve. Without this, "refuse when any shorter tag exists" would look
# identical on the case above while breaking ordinary repositories.
partial_ok_out="$WORK/partial-ok.out"
if BM_WEDDING_TAGS='v2.1.3\nv2.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/partial-ok.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$bm_root" "$SCRIPT" >"$partial_ok_out" 2>&1; then
  pok_insync="$(grep -c '^IN-SYNC' "$partial_ok_out" || true)"
  [ "$pok_insync" -eq "$consumer_count" ] ||
    fail "a version with no partial spelling must still resolve for all five consumers, got $pok_insync IN-SYNC"
  pass 'a version that has no partial spelling is unaffected by the partial-tie refusal'
else
  fail 'a version with no partial spelling was refused -- the partial-tie check is too broad'
fi

# ---------------------------------------------------------------------------
# 14. A VERSION PUBLISHED ONLY WITH BUILD METADATA MUST NOT BE WALKED PAST. (#3305 review)
#     `2.0.0+build.1` with no bare `2.0.0` is the newest release, and Flux selects it.
#     A walk that rebuilds the tag from the bare core version finds nothing at that
#     precedence, drops silently to `1.9.0`, and reports ITS workflow revision as the
#     signer of the deployed artifact — succeeding, which is worse than refusing.
#
#     This is the case the tie refusal alone does NOT cover: with one tag at the newest
#     precedence there is no tie, so only reading the real tag out of the tag list makes
#     the run correct here.
# ---------------------------------------------------------------------------
bm2_root="$WORK/buildmeta-only-root"
cp -R "$bm_root" "$bm2_root"
bm2_out="$WORK/buildmeta-only.out"
# Only `aws` carries the metadata-only release; every other consumer stays on a plain
# `v1.9.0`, so nothing else in this fixture can produce a refusal or a divergence.
#
# `v2.0.0+build.1` lives at its own commit (SHA_B) and everything else — including the
# default branch — resolves to SHA_A. The signing pin is read at the VERIFIED COMMIT, so
# selecting the metadata tag prints SHA_B as the signing revision and reports the consumer
# as diverged; walking silently past it prints SHA_A and reports it in sync. SHA_B in the
# output is the whole discrimination.
if BM_AWS_TAGS='v2.0.0+build.1\nv1.9.0\n' BM_OWNCOMMIT_TAG='v2.0.0+build.1' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$bm2_root" "$SCRIPT" >"$bm2_out" 2>&1; then
  grep -qF "$SHA_B" "$bm2_out" ||
    fail 'the newest release exists only as a build-metadata tag, and the report resolved an older one instead — it walked silently past it'
  pass 'a version published only with build metadata is resolved as itself, not walked past'
else
  fail "the metadata-only release exists in GHCR as 2.0.0_build.1 but did not resolve: $(grep -E '^(UNRESOLVED|could not|tag )' "$bm2_out" | tr '\n' ' ')"
fi

# The run lookup must pass the tag as a PARAMETER. Checked explicitly because the failure
# it prevents is invisible otherwise: gh_retry discards stderr, so an interpolated query
# string surfaces only as unexplained unresolved consumers, and this stub receives argv so
# it cannot observe percent-encoding itself.
if [ -s "$WORK/interpolated.log" ]; then
  fail 'the run lookup interpolated its query string — a + in a build-metadata tag decodes as a space on the wire, so a published tag reads as UNPUBLISHED'
else
  pass 'the run lookup passes the tag as a query PARAMETER, so build metadata survives encoding'
fi

# ---------------------------------------------------------------------------
# 14b. A VERSION PUBLISHED UNDER BOTH SPELLINGS MUST REFUSE. (#3305 review)
#      `2.0.0` and `v2.0.0` are two DISTINCT git refs. They can point at different
#      commits and therefore at different publish-workflow pins, but the precedence fold
#      strips the `v` before `sort -u`, so the tie check saw ONE variant and passed. The
#      loop that follows then unconditionally prefers the `v` form — reporting its
#      signing revision even when the other ref produced the deployed artifact.
#
#      This is NOT the build-metadata tie above: there the two tags differ visibly and
#      the tie check catches them. Here the fold erases the difference before the check
#      ever runs, which is why folding for precedence and folding for identity have to be
#      separated.
# ---------------------------------------------------------------------------
vd_root="$WORK/vdual-root"
cp -R "$bm_root" "$vd_root"
vd_out="$WORK/vdual.out"
# Only `wedding-app` publishes both spellings; every other consumer stays on a plain
# v1.9.0, so a refusal or divergence can only have come from that consumer.
if BM_WEDDING_TAGS='2.0.0\nv2.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$vd_root" "$SCRIPT" >"$vd_out" 2>&1; then
  fail 'a version published as both 2.0.0 and v2.0.0 was silently resolved to the v spelling instead of refusing'
else
  grep -q 'published as BOTH' "$vd_out" ||
    fail 'the run failed but not because of the v-spelling duality — the case is not testing what it claims'
  grep -qF '2.0.0' "$vd_out" ||
    fail 'the refusal does not name the version published twice, so the cause is not diagnosable'
  # The same outcome-count control the build-metadata tie uses: a name match alone would
  # pass just as well if ALL FIVE consumers had failed for an unrelated reason.
  vd_unresolved="$(grep -c '^UNRESOLVED' "$vd_out" || true)"
  vd_insync="$(grep -c '^IN-SYNC' "$vd_out" || true)"
  [ "$vd_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the v-spelling duality), got $vd_unresolved"
  [ "$vd_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $vd_insync"
  grep -qE '^UNRESOLVED +wedding-app' "$vd_out" ||
    fail 'the unresolved consumer is not the one publishing both spellings'
  pass 'a version published under both the bare and v spellings refuses instead of preferring v'
fi

# CONTROL: ONE spelling is the normal case and must still resolve. Without this the
# refusal above could be satisfied by refusing every `v` tag, which would break every
# real consumer in this repository.
vd2_root="$WORK/vdual-single-root"
cp -R "$bm_root" "$vd2_root"
vd2_out="$WORK/vdual-single.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$vd2_root" "$SCRIPT" >"$vd2_out" 2>&1; then
  pass 'a version published under only the v spelling still resolves'
else
  printf '%s\n' "$(cat "$vd2_out")" >&2
  fail 'a version published under only the v spelling was refused — the duality check is too broad'
fi

# ---------------------------------------------------------------------------
# 15. AN OMITTED `spec.ref` MUST REFUSE, NOT BE LOOKED UP. (#3305 review)
#     Flux serves the mutable `latest` tag when `spec.ref` is absent. That is a pointer,
#     not a release version, so there is nothing for the tag walk to select — the same
#     shape as the digest refusal. Emitting the literal `latest` made it an exact lookup
#     for a tag that is not a release; walking to the newest release instead would be a
#     GUESS, since `latest` need not point there, and would attribute that release's
#     workflow revision to whatever is actually deployed.
#
#     Case 12 pins the token the expression emits. This pins what the RESOLVER does with
#     it, which is the half that decides whether a consumer is misattributed.
# ---------------------------------------------------------------------------
up_root="$WORK/unpinned"
mkdir -p "$up_root"
k=0
while IFS=$'\t' read -r repo workflow _version; do
  [ -n "$repo" ] || continue
  k=$((k + 1))
  oci="$repo"
  [ "$repo" = '.github' ] && oci='github-config'
  # Consumer 1 OMITS `ref:` entirely; the rest keep an unbounded range, so the refusal
  # cannot be confused with a wholesale failure of the fixture.
  if [ "$k" -eq 1 ]; then ref_block=''; else ref_block='  ref:
    semver: ">=1.0.0"'; fi
  {
    printf 'apiVersion: source.toolkit.fluxcd.io/v1\nkind: OCIRepository\nmetadata:\n  name: u%s\nspec:\n' "$k"
    if [ -n "$ref_block" ]; then printf '%s\n' "$ref_block"; fi
    printf '  url: oci://ghcr.io/devantler-tech/%s/manifests\n' "$oci"
    printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n'
    printf "      - issuer: '^https://token\\\\.actions\\\\.githubusercontent\\\\.com\$'\n"
    printf "        subject: '^https://github\\\\.com/devantler-tech/actions/\\\\.github/workflows/%s\\\\.yaml@[0-9a-f]{40}\$'\n" "$workflow"
  } >"$up_root/c-$k.yaml"
done <<<"$consumers"

up_out="$WORK/unpinned.out"
# Hermetic for the same reason as the bounded-semver case: the refusal is decided from
# the MANIFEST, before any resolver is consulted, so the stub never has to answer.
if PUBLISH_REVISION_RESOLVER="$(make_stub "$agree_table" agree)" \
PUBLISH_CONSUMER_ROOT="$up_root" "$SCRIPT" >"$up_out" 2>&1; then
  fail 'an omitted spec.ref was silently resolved instead of refusing — a mutable latest pointer has no release version behind it'
else
  grep -q 'unpinned reference' "$up_out" ||
    fail 'the run failed but not because of the unpinned reference — the case is not testing what it claims'
  # A CONTROL, counted rather than name-matched: the other four consumers keep an
  # unbounded range and must still resolve, or this "refusal" is just the fixture dying.
  up_insync="$(grep -c '^IN-SYNC' "$up_out" || true)"
  [ "$up_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC alongside the refusal, got $up_insync"
  pass 'an omitted spec.ref refuses by name instead of being looked up as a literal tag'
fi

# ---------------------------------------------------------------------------
# 16. NEITHER ORIGIN MAY READ AS APPLIED-REVISION EVIDENCE. (#3305 review)
#     `pinned` was called `exact` and read as "this IS what is deployed". It cannot know
#     that: a version bump landing by DIRECT PUSH to main is reported by validate-main.yaml
#     before the manual CD workflow deploys it, so a previously-published tag reads as
#     deployed while the cluster still runs its predecessor — and the allow-list built from
#     that row omits the revision which actually signed the running artifact.
#
#     This script reads manifests and a registry; nothing in it reads a cluster. So BOTH
#     origins are marked, and the assertion is on the marks rather than on the token, since
#     the mark is what a human building an allow-list actually reads.
# ---------------------------------------------------------------------------
origin_stub="$WORK/resolver-origin.sh"
cat >"$origin_stub" <<STUB
#!/usr/bin/env bash
set -euo pipefail
# \$1=repo \$2=workflow \$3=version. Emit the THIRD origin field, which the two-field
# stubs above never exercise.
if [ -n "\${3:-}" ]; then
  printf '%s\t%s\t%s\n' '$SHA_A' '$SHA_A' 'pinned'
else
  printf '%s\t%s\t%s\n' '$SHA_A' '$SHA_A' 'inferred'
fi
STUB
chmod +x "$origin_stub"

origin_out="$WORK/origin.out"
if PUBLISH_REVISION_RESOLVER="$origin_stub" "$SCRIPT" >"$origin_out" 2>&1; then
  # Every row must disclaim applied-revision evidence — count them against the IN-SYNC
  # rows rather than grepping for one consumer, so a partially-marked report fails.
  origin_insync="$(grep -c '^IN-SYNC' "$origin_out" || true)"
  origin_marked="$(grep -c 'not applied-revision evidence' "$origin_out" || true)"
  [ "$origin_insync" -gt 0 ] ||
    fail 'the origin fixture produced no IN-SYNC rows, so the marks below would pass vacuously'
  [ "$origin_marked" -eq "$origin_insync" ] ||
    fail "every resolved row must disclaim applied-revision evidence: $origin_marked marked of $origin_insync rows"
  grep -q 'what the manifest PINS and was published' "$origin_out" ||
    fail 'a pinned row does not say that a pin is not proof of what is applied'
  grep -q 'inferred from newest PUBLISHED tag' "$origin_out" ||
    fail 'an inferred row lost its existing disclaimer'
  pass 'a pinned origin is disclaimed as not applied-revision evidence, exactly like an inferred one'
else
  fail "the script exited non-zero on the origin fixture: $(cat "$origin_out")"
fi

# ---------------------------------------------------------------------------
# 17. A MOVED TAG MUST NOT COUNT AS PUBLISHED. (#3305 review)
#     The run filter matched on ref NAME, path and conclusion only, so a successful run
#     from BEFORE a tag was moved or recreated still counted. `pin_at_ref` then reads
#     cd.yaml at the tag's CURRENT commit, so the report pairs a workflow revision from one
#     commit with a publish proved by another and prints it as a SHA the allow-list "must
#     accept" — two individually-true facts composed into a confident wrong answer.
#
#     It REFUSES rather than walking back: a moved tag HAS published something, just not
#     what it now points at, so stepping silently to the previous release would attribute
#     THAT release's revision to the deployed artifact — the same failure one release down.
# ---------------------------------------------------------------------------
mv_root="$WORK/moved-root"
cp -R "$bm_root" "$mv_root"
mv_out="$WORK/moved.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_MOVED_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$mv_root" "$SCRIPT" >"$mv_out" 2>&1; then
  fail 'a tag whose only successful run belongs to a DIFFERENT commit was accepted as published — the workflow pin would be read from a commit that never signed the artifact'
else
  grep -q 'moved or recreated' "$mv_out" ||
    fail 'the run failed but not because of the moved tag — the case is not testing what it claims'
  grep -qF 'v2.0.0' "$mv_out" ||
    fail 'the refusal does not name the moved tag, so the cause is not diagnosable'
  mv_unresolved="$(grep -c '^UNRESOLVED' "$mv_out" || true)"
  mv_insync="$(grep -c '^IN-SYNC' "$mv_out" || true)"
  [ "$mv_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the moved tag), got $mv_unresolved"
  [ "$mv_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $mv_insync"
  grep -qE '^UNRESOLVED +wedding-app' "$mv_out" ||
    fail 'the unresolved consumer is not the one whose tag moved'
  pass 'a tag whose successful run belongs to another commit refuses instead of being read as published'
fi

# CONTROL: the SAME tag set with nothing moved must resolve. Without this the refusal above
# would be satisfied by rejecting every tag, which would break every real consumer — and the
# only difference between the two runs is BM_MOVED_TAG, so it is the moved-ness under test.
mv2_root="$WORK/moved-control-root"
cp -R "$bm_root" "$mv2_root"
mv2_out="$WORK/moved-control.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$mv2_root" "$SCRIPT" >"$mv2_out" 2>&1; then
  mv2_insync="$(grep -c '^IN-SYNC' "$mv2_out" || true)"
  [ "$mv2_insync" -eq "$consumer_count" ] ||
    fail "the unmoved control resolved only $mv2_insync of $consumer_count consumers — the moved-tag check is too broad"
  pass 'an unmoved tag still resolves, so the moved-tag refusal is not rejecting every run'
else
  fail "the unmoved control failed outright, so the moved-tag case above proves nothing: $(cat "$mv2_out")"
fi

# ---------------------------------------------------------------------------
# 18. AN EXACT PIN MUST REFUSE BOTH SPELLINGS TOO. (#3305 review)
#     Case 14b proves the semver WALK refuses a version published as both `2.0.0` and
#     `v2.0.0`. The exact-pin branch returned on the FIRST spelling it found, so that
#     refusal was unreachable for precisely the consumers whose version is written down —
#     and the two refs can point at different commits and so at different workflow pins.
# ---------------------------------------------------------------------------
# One consumer pins an EXACT tag; the rest keep an unbounded range, so a refusal can only
# have come from that consumer.
make_exact_root() { # <dest> <pinned-tag>
  local dest="$1" pin="$2" k=0 repo workflow oci ref_block
  mkdir -p "$dest"
  while IFS=$'\t' read -r repo workflow _version; do
    [ -n "$repo" ] || continue
    k=$((k + 1))
    oci="$repo"
    [ "$repo" = '.github' ] && oci='github-config'
    if [ "$repo" = 'wedding-app' ]; then
      ref_block="    tag: \"$pin\""
    else
      ref_block='    semver: ">=1.0.0"'
    fi
    {
      printf 'apiVersion: source.toolkit.fluxcd.io/v1\nkind: OCIRepository\nmetadata:\n  name: e%s\nspec:\n  ref:\n' "$k"
      printf '%s\n' "$ref_block"
      printf '  url: oci://ghcr.io/devantler-tech/%s/manifests\n' "$oci"
      printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n'
      printf "      - issuer: '^https://token\\\\.actions\\\\.githubusercontent\\\\.com\$'\n"
      printf "        subject: '^https://github\\\\.com/devantler-tech/actions/\\\\.github/workflows/%s\\\\.yaml@[0-9a-f]{40}\$'\n" "$workflow"
    } >"$dest/c-$k.yaml"
  done <<<"$consumers"
}

ex_root="$WORK/exact-dual-root"
make_exact_root "$ex_root" '2.0.0'
ex_out="$WORK/exact-dual.out"
if BM_WEDDING_TAGS='2.0.0\nv2.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$ex_root" "$SCRIPT" >"$ex_out" 2>&1; then
  fail 'an exact pin whose version exists under BOTH spellings resolved to whichever was tried first instead of refusing'
else
  grep -q 'published as BOTH' "$ex_out" ||
    fail 'the run failed but not because of the exact-pin duality — the case is not testing what it claims'
  ex_unresolved="$(grep -c '^UNRESOLVED' "$ex_out" || true)"
  ex_insync="$(grep -c '^IN-SYNC' "$ex_out" || true)"
  [ "$ex_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the exact-pin duality), got $ex_unresolved"
  [ "$ex_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $ex_insync"
  grep -qE '^UNRESOLVED +wedding-app' "$ex_out" ||
    fail 'the unresolved consumer is not the one pinning the doubly-spelled version'
  pass 'an exact pin refuses when its version exists under both the bare and v spellings'
fi

# CONTROL: an exact pin with ONE spelling present must still resolve — the pin is written
# bare while only the `v` form exists, which is the real repository's shape.
ex2_root="$WORK/exact-single-root"
make_exact_root "$ex2_root" '2.0.0'
ex2_out="$WORK/exact-single.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$ex2_root" "$SCRIPT" >"$ex2_out" 2>&1; then
  ex2_insync="$(grep -c '^IN-SYNC' "$ex2_out" || true)"
  [ "$ex2_insync" -eq "$consumer_count" ] ||
    fail "the single-spelling exact-pin control resolved only $ex2_insync of $consumer_count consumers — the duality check is too broad"
  pass 'an exact pin resolves normally when only one spelling of its version exists'
else
  fail "the single-spelling exact-pin control failed outright, so the duality case proves nothing: $(cat "$ex2_out")"
fi

# ---------------------------------------------------------------------------
# 19. A TAG THIS SCRIPT CANNOT RANK MUST NOT BE SILENTLY OUTRANKED. (#3305 review)
#     The candidate filter was a character-class regex, so `v02.0.0` (SemVer forbids a
#     leading zero in a numeric identifier) and `v2.0.0+foo..bar` (a build identifier may
#     not be empty) were accepted, stripped and ranked. Measured: `02.0.0` sorts ABOVE
#     `1.9.0`, so such a tag could be selected and its workflow pin attributed to the
#     consumer while Flux, rejecting the tag, resolves an older artifact.
#
#     Excluding it is not enough on its own — that walks silently back to an older release,
#     which is the confident wrong answer rather than a refusal. So it refuses BY NAME, and
#     only when the unrankable tag could actually outrank the best valid candidate.
# ---------------------------------------------------------------------------
iv_root="$WORK/invalid-semver-root"
cp -R "$bm_root" "$iv_root"
iv_out="$WORK/invalid-semver.out"
if BM_WEDDING_TAGS='v02.0.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$iv_root" "$SCRIPT" >"$iv_out" 2>&1; then
  fail 'a tag that is not valid SemVer but outranks every valid candidate was resolved or silently skipped instead of refusing'
else
  grep -q 'not valid SemVer' "$iv_out" ||
    fail 'the run failed but not because of the unrankable tag — the case is not testing what it claims'
  grep -qF 'v02.0.0' "$iv_out" ||
    fail 'the refusal does not name the unrankable tag, so the cause is not diagnosable'
  iv_unresolved="$(grep -c '^UNRESOLVED' "$iv_out" || true)"
  iv_insync="$(grep -c '^IN-SYNC' "$iv_out" || true)"
  [ "$iv_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the unrankable tag), got $iv_unresolved"
  [ "$iv_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $iv_insync"
  pass 'a tag that is not valid SemVer and would outrank the best valid candidate refuses by name'
fi

# ---------------------------------------------------------------------------
# 20. A TAG FLUX ACCEPTS BUT THIS SCRIPT CANNOT RANK. (#3305 review)
#     Flux parses tags with Masterminds semver.NewVersion, which COERCES a partial
#     version: measured, v2.5 resolves to 2.5.0 and v2 to 2.0.0. Both the strict
#     candidate filter and the unrankable filter required three components, so such
#     a tag matched NEITHER -- it was silently dropped, the walk stepped to an older
#     release, and the report named THAT release's signing revision, leaving the
#     actual signer out of the allow-list.
# ---------------------------------------------------------------------------
fx_root="$WORK/flux-loose-root"
cp -R "$bm_root" "$fx_root"
fx_out="$WORK/flux-loose.out"
if BM_WEDDING_TAGS='v2.5\nv2.4.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$fx_root" "$SCRIPT" >"$fx_out" 2>&1; then
  fail 'a partial-version tag Flux resolves ABOVE every ranked candidate was silently skipped instead of refusing'
else
  grep -q 'not valid SemVer' "$fx_out" ||
    fail 'the run failed but not because of the unrankable tag — the case is not testing what it claims'
  grep -qF 'v2.5' "$fx_out" ||
    fail 'the refusal does not name the tag Flux would select, so the cause is not diagnosable'
  fx_unresolved="$(grep -c '^UNRESOLVED' "$fx_out" || true)"
  [ "$fx_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the partial-version tag), got $fx_unresolved"
  pass 'a partial version Flux would rank above the best candidate refuses by name'
fi

# CONTROL — the same narrowing as case 19: a partial version ranking BELOW the best
# candidate cannot change what Flux selects, so it must NOT refuse. Without this the
# case above would be satisfied by refusing whenever any partial tag exists.
fx2_root="$WORK/flux-loose-below-root"
cp -R "$bm_root" "$fx2_root"
fx2_out="$WORK/flux-loose-below.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.5\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$fx2_root" "$SCRIPT" >"$fx2_out" 2>&1; then
  fx2_insync="$(grep -c '^IN-SYNC' "$fx2_out" || true)"
  [ "$fx2_insync" -eq "$consumer_count" ] ||
    fail "the below-rank control resolved only $fx2_insync of $consumer_count consumers — the partial-version check refuses on mere existence, not on rank"
  pass 'a partial version ranking below the best candidate does not refuse'
else
  fail "the below-rank control failed outright — the partial-version refusal is too broad: $(cat "$fx2_out")"
fi

# ---------------------------------------------------------------------------
# 21. A FAILED LOOKUP IS NOT AN ESTABLISHED ABSENCE. (#3305 review)
#     `tag_commit` returning nonzero only broke the inner spelling loop, so the outer
#     loop walked on to an OLDER version; and `tag_was_published` returned 1 both for
#     "queried successfully, never published" and for "the query failed". Either way a
#     rate limit or a transient outage was reported as an older release's signing SHA
#     -- a confident wrong answer built from an error, where the honest answer is that
#     the question could not be answered.
# ---------------------------------------------------------------------------
lc_root="$WORK/lookup-commit-root"
cp -R "$bm_root" "$lc_root"
lc_out="$WORK/lookup-commit.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_COMMIT_FAIL_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$lc_root" "$SCRIPT" >"$lc_out" 2>&1; then
  fail 'a failed commit lookup walked back to an older release instead of refusing'
else
  grep -q 'could not resolve the commit for tag' "$lc_out" ||
    fail 'the run failed but not because the commit lookup could not be answered — the case is not testing what it claims'
  grep -qF 'v2.0.0' "$lc_out" ||
    fail 'the refusal does not name the tag whose lookup failed, so the cause is not diagnosable'
  lc_unresolved="$(grep -c '^UNRESOLVED' "$lc_out" || true)"
  [ "$lc_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the failed lookup), got $lc_unresolved"
  pass 'a commit lookup that cannot be answered refuses instead of walking backward'
fi

lr_root="$WORK/lookup-runs-root"
cp -R "$bm_root" "$lr_root"
lr_out="$WORK/lookup-runs.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_RUNS_FAIL_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$lr_root" "$SCRIPT" >"$lr_out" 2>&1; then
  fail 'a failed workflow-runs query was read as "never published" and walked back to an older release'
else
  grep -q 'could not read the workflow runs for' "$lr_out" ||
    fail 'the run failed but not because the runs query could not be answered — the case is not testing what it claims'
  grep -qF 'v2.0.0' "$lr_out" ||
    fail 'the refusal does not name the tag whose runs query failed, so the cause is not diagnosable'
  lr_unresolved="$(grep -c '^UNRESOLVED' "$lr_out" || true)"
  [ "$lr_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the failed runs query), got $lr_unresolved"
  pass 'a runs query that cannot be answered refuses instead of walking backward'
fi

# CONTROL — a tag that genuinely never published must still WALK, exactly as before.
# Without this, the two cases above would be satisfied by refusing on every non-zero
# status, which would turn every ordinary failed release into an UNRESOLVED consumer.
nw_root="$WORK/never-published-walk-root"
cp -R "$bm_root" "$nw_root"
nw_out="$WORK/never-published-walk.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='1.9.0\n' BM_UNPUBLISHED_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$nw_root" "$SCRIPT" >"$nw_out" 2>&1; then
  nw_insync="$(grep -c '^IN-SYNC' "$nw_out" || true)"
  [ "$nw_insync" -eq "$consumer_count" ] ||
    fail "the never-published control resolved only $nw_insync of $consumer_count consumers — the lookup-failure refusal swallowed the ordinary walk"
  pass 'a tag that genuinely never published still walks to the previous release'
else
  fail "the never-published control failed outright — the lookup-failure refusal is too broad: $(cat "$nw_out")"
fi

# CONTROL, and the one that pins the NARROWING: an unrankable tag that ranks BELOW the best
# valid candidate cannot change which tag is selected, so it must NOT refuse. Without this
# the case above would be satisfied by refusing on the mere existence of a malformed tag,
# which would park a repository on one ancient stray tag forever.
iv2_root="$WORK/invalid-semver-below-root"
cp -R "$bm_root" "$iv2_root"
iv2_out="$WORK/invalid-semver-below.out"
if BM_WEDDING_TAGS='v2.0.0\nv01.5.0\nv1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$iv2_root" "$SCRIPT" >"$iv2_out" 2>&1; then
  iv2_insync="$(grep -c '^IN-SYNC' "$iv2_out" || true)"
  [ "$iv2_insync" -eq "$consumer_count" ] ||
    fail "the below-rank control resolved only $iv2_insync of $consumer_count consumers — the SemVer check refuses on mere existence, not on rank"
  pass 'an unrankable tag ranking below the best valid candidate does not refuse'
else
  fail "the below-rank control failed outright — the SemVer refusal is too broad: $(cat "$iv2_out")"
fi

# ---------------------------------------------------------------------------
# 22. THE SIGNING PIN MUST BE READ AT THE VERIFIED COMMIT, NOT THE MUTABLE TAG. (#3305 review)
#     `deployed_tag` verifies publication against the SHA from `tag_commit`, then returned
#     only the tag NAME. `default_resolver` passed that name to `pin_at_ref`, so if the tag
#     moves after the publication check and before the workflow read, the script verifies
#     publication for the OLD commit and reads cd.yaml from the NEW one — two individually
#     true reads composed into a confident wrong signing revision.
#
#     Case 17 covers a tag ALREADY moved at verification time, which refuses. This is the
#     narrower race the refusal cannot see: at verification the tag was consistent.
# ---------------------------------------------------------------------------
tc_root="$WORK/toctou-root"
cp -R "$bm_root" "$tc_root"
tc_out="$WORK/toctou.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_TOCTOU_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$tc_root" "$SCRIPT" >"$tc_out" 2>&1; then
  # The signing revision must be the pin at the VERIFIED commit ($SHA_A), never the pin the
  # moved tag now resolves to ($SHA_B).
  grep -qE "^IN-SYNC +wedding-app .*signed=$SHA_A" "$tc_out" ||
    fail "the signing revision was not read at the verified commit: $(grep -E '^(IN-SYNC|DIVERGED|UNRESOLVED) +wedding-app' "$tc_out")"
  grep -qE "^(DIVERGED|IN-SYNC) +wedding-app .*signed=$SHA_B" "$tc_out" &&
    fail 'the signing revision came from the MOVED tag, so a workflow revision that never signed the artifact would enter the allow-list'
  tc_insync="$(grep -c '^IN-SYNC' "$tc_out" || true)"
  [ "$tc_insync" -eq "$consumer_count" ] ||
    fail "expected all FIVE consumers IN-SYNC through the same stub, got $tc_insync — the fixture failed for an unrelated reason"
  pass 'the signing pin is read at the commit whose publication was verified, not at the mutable tag'
else
  fail "the TOCTOU fixture failed outright, so it proves nothing: $(cat "$tc_out")"
fi

# CONTROL: a GENUINE divergence at the verified commit must still be reported. Without this
# the assertion above would be satisfied by any change that makes every consumer read
# IN-SYNC, which would hide real drift instead of fixing the race.
tc2_root="$WORK/toctou-control-root"
cp -R "$bm_root" "$tc2_root"
tc2_out="$WORK/toctou-control.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_TOCTOU_TAG='v2.0.0' BM_TOCTOU_SHA_PIN="$SHA_B" \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$tc2_root" "$SCRIPT" >"$tc2_out" 2>&1; then
  grep -qE "^DIVERGED +wedding-app .*signed=$SHA_B .*pinned=$SHA_A" "$tc2_out" ||
    fail "a real divergence at the verified commit was not reported: $(grep -E '^(IN-SYNC|DIVERGED|UNRESOLVED) +wedding-app' "$tc2_out")"
  pass 'a genuine divergence at the verified commit is still reported, so the fix is not smoothing real drift into agreement'
else
  fail "the divergence control failed outright: $(cat "$tc2_out")"
fi

# ---------------------------------------------------------------------------
# 23. A SUCCESSFUL HISTORICAL RUN IS NOT A CURRENT REGISTRY VERSION. (#3331)
#     Deleting a GHCR version leaves both its git tag and its successful cd.yaml run.
#     Walking past the missing version would be equally wrong: Flux resolves against
#     the registry, so the report must refuse by name instead of attributing either the
#     deleted version or an older fallback to what is deployed.
# ---------------------------------------------------------------------------
rg_root="$WORK/registry-deleted-root"
cp -R "$bm_root" "$rg_root"
rg_out="$WORK/registry-deleted.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$rg_root" "$SCRIPT" >"$rg_out" 2>&1; then
  fail 'a tag with a successful publish run but no current GHCR version was accepted or silently walked past'
else
  grep -q 'no longer exists in GHCR' "$rg_out" ||
    fail 'the run failed but did not name the missing current registry version'
  grep -qF 'v2.0.0' "$rg_out" ||
    fail 'the registry refusal does not name the deleted tag'
  rg_unresolved="$(grep -c '^UNRESOLVED' "$rg_out" || true)"
  rg_insync="$(grep -c '^IN-SYNC' "$rg_out" || true)"
  [ "$rg_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the deleted registry version), got $rg_unresolved"
  [ "$rg_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $rg_insync"
  pass 'a successfully published tag deleted from GHCR refuses by name instead of walking backward'
fi

# CONTROL: when the same candidate still exists in GHCR it must resolve normally.
rg2_root="$WORK/registry-present-root"
cp -R "$bm_root" "$rg2_root"
rg2_out="$WORK/registry-present.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='2.0.0\n1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$rg2_root" "$SCRIPT" >"$rg2_out" 2>&1; then
  rg2_insync="$(grep -c '^IN-SYNC' "$rg2_out" || true)"
  [ "$rg2_insync" -eq "$consumer_count" ] ||
    fail "the registry-present control resolved only $rg2_insync of $consumer_count consumers — the registry check rejects valid versions"
  pass 'a successfully published tag still present in GHCR resolves normally'
else
  fail "the registry-present control failed outright: $(cat "$rg2_out")"
fi

# A partial registry tag is a distinct OCI artifact selector even when Flux coerces it
# to the same SemVer precedence as the selected strict tag. The Git-side tie guard above
# cannot see this shape when the partial source ref was deleted after publication, so the
# current registry set must be normalized independently before comparing precedence.
rg3_root="$WORK/registry-partial-tie-root"
cp -R "$bm_root" "$rg3_root"
rg3_out="$WORK/registry-partial-tie.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='2.0.0\n2.0\n1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$rg3_root" "$SCRIPT" >"$rg3_out" 2>&1; then
  fail 'a partial registry tag tied with the selected strict tag was silently ignored'
else
  grep -q 'registry tag 2.0 has the same SemVer precedence' "$rg3_out" ||
    fail 'the registry partial-tie refusal does not name the distinct current tag and shared precedence'
  rg3_unresolved="$(grep -c '^UNRESOLVED' "$rg3_out" || true)"
  rg3_insync="$(grep -c '^IN-SYNC' "$rg3_out" || true)"
  [ "$rg3_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the registry partial tie), got $rg3_unresolved"
  [ "$rg3_insync" -eq "$expected_insync" ] ||
    fail "expected the other FOUR consumers to resolve IN-SYNC through the same stub, got $rg3_insync"
  pass 'a partial registry tag tied with the selected strict tag refuses instead of guessing'
fi

# ---------------------------------------------------------------------------
# 24. THE LIVE MAIN-BRANCH REPORT MUST RECEIVE PACKAGE-READ AUTHORITY. (#3331)
#     The hermetic PR test stubs GHCR, but validate-main runs the real resolver with
#     GITHUB_TOKEN. Without this job-level permission every package request returns 403,
#     every consumer becomes UNRESOLVED, and the report makes main red by construction.
# ---------------------------------------------------------------------------
registry_permission="$(yq eval -r '.jobs.validate-shared-publish-pin.permissions.packages // ""' \
  "$REPO_ROOT/.github/workflows/validate-main.yaml")"
if [ "$registry_permission" = 'read' ]; then
  pass 'the live main-branch report receives packages: read for current GHCR metadata'
else
  fail "validate-main gives the live report packages: ${registry_permission:-none}; GHCR metadata will return 403"
fi

# ---------------------------------------------------------------------------
# 25. REGISTRY-ONLY HIGHER VERSIONS MUST NOT BE SILENTLY OUTRANKED. (#3331 review)
#     Flux selects from registry tags. If the highest current version survives in GHCR
#     after its Git ref is deleted, a git-only walk must not fall back to an older version
#     and attribute that older release's signer to what Flux resolves.
# ---------------------------------------------------------------------------
ro_root="$WORK/registry-only-root"
cp -R "$bm_root" "$ro_root"
ro_out="$WORK/registry-only.out"
if BM_WEDDING_TAGS='v1.9.0\n' BM_WEDDING_REGISTRY_TAGS='2.0.0\n1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$ro_root" "$SCRIPT" >"$ro_out" 2>&1; then
  fail 'a higher registry-only version was silently outranked by an older Git tag'
else
  grep -q 'registry tag 2.0.0' "$ro_out" ||
    fail 'the registry-only refusal does not name the higher current version'
  grep -q 'Git tag' "$ro_out" ||
    fail 'the registry-only refusal does not explain that publication evidence cannot be mapped'
  ro_unresolved="$(grep -c '^UNRESOLVED' "$ro_out" || true)"
  [ "$ro_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the registry-only higher version), got $ro_unresolved"
  pass 'a higher registry-only version refuses instead of attributing an older release signer'
fi

# A higher registry version with a surviving Git tag is still not safe when this
# resolver cannot establish a successful publication at that tag. Registry selection
# wins; falling through to the lower candidate would remain a confident wrong answer.
rp_root="$WORK/registry-publication-gap-root"
cp -R "$bm_root" "$rp_root"
rp_out="$WORK/registry-publication-gap.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='2.0.0\n1.9.0\n' BM_UNPUBLISHED_TAG='v2.0.0' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$rp_root" "$SCRIPT" >"$rp_out" 2>&1; then
  fail 'a higher current registry version without established publication evidence was silently walked past'
else
  grep -q 'registry tag 2.0.0' "$rp_out" ||
    fail 'the publication-gap refusal does not name the higher registry version'
  grep -q 'publication' "$rp_out" ||
    fail 'the publication-gap refusal does not explain why the higher version cannot be attributed'
  pass 'a higher registry version without established publication evidence refuses instead of walking backward'
fi

# ---------------------------------------------------------------------------
# 26. AN EXACT MANIFEST TAG IS LOOKED UP EXACTLY IN THE REGISTRY. (#3331 review)
#     The publisher strips v from its source Git tag, but Flux does not rewrite an exact
#     spec.ref.tag. A manifest pinning v2.0.0 therefore cannot be cleared by GHCR tag 2.0.0.
# ---------------------------------------------------------------------------
et_root="$WORK/exact-registry-spelling-root"
make_exact_root "$et_root" 'v2.0.0'
et_out="$WORK/exact-registry-spelling.out"
if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='2.0.0\n1.9.0\n' \
  BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" BM_VIOLATION_LOG="$WORK/interpolated.log" PATH="$bm_bin:$PATH" \
  PUBLISH_CONSUMER_ROOT="$et_root" "$SCRIPT" >"$et_out" 2>&1; then
  fail 'an exact manifest pin was cleared by a differently-spelled GHCR tag'
else
  grep -q 'exact registry tag v2.0.0' "$et_out" ||
    fail 'the exact-tag refusal does not name the manifest spelling Flux requests'
  et_unresolved="$(grep -c '^UNRESOLVED' "$et_out" || true)"
  [ "$et_unresolved" -eq 1 ] ||
    fail "expected exactly ONE unresolved consumer (the exact missing tag), got $et_unresolved"
  pass 'an exact manifest tag must exist under the exact spelling Flux requests'
fi

# ---------------------------------------------------------------------------
# 29. AN HTTP-SUCCESS BODY IS NOT NECESSARILY COMPLETE PUBLICATION EVIDENCE.
#     Parse errors used to become "unpublished", and an object instead of an array
#     could even count as a successful publication. Exercise the real function with
#     only the network response replaced; its stdout must remain empty and its one
#     diagnostic line must not expose arbitrary response fields or parser errors.
# ---------------------------------------------------------------------------
# Check <name> <expected-status> <publication-classification> <response-classification> <body>.
# Runs the real publication classifier with an offline response, accumulating failures
# for the exit status, empty stdout, diagnostic classification and response-data leakage.
publication_response_case() {
  local name="$1" expected="$2" classification="$3" response="$4" body="$5" rc=0
  local fixture="$WORK/response-$name.json" out="$WORK/response-$name.out" err="$WORK/response-$name.err"
  printf '%s\n' "$body" >"$fixture"
  BM_RUNS_RESPONSE_TAG=v2.0.0 BM_RUNS_RESPONSE_FILE="$fixture" PATH="$bm_bin:$PATH" \
    bash -c 'source "$1"; tag_was_published wedding-app v2.0.0 "$2"' \
    bash "$SCRIPT" "$SHA_C" >"$out" 2>"$err" || rc=$?
  local before="$failures"
  [ "$rc" -eq "$expected" ] || fail "$name classified as $rc, expected $expected"
  [ ! -s "$out" ] || fail "$name polluted the publication result on stdout"
  grep -q "response=$response" "$err" || fail "$name omitted its response classification"
  grep -q "classification=$classification" "$err" || fail "$name omitted its publication classification"
  [ "$(wc -l <"$err" | tr -d ' ')" -eq 1 ] || fail "$name emitted more or less than one diagnostic line"
  if grep -q 'RESPONSE_ONLY_SENTINEL' "$out" "$err"; then
    fail "$name leaked arbitrary response content"
  fi
  [ "$failures" -ne "$before" ] || pass "publication response $name preserves status, stdout and safe diagnostics"
}

pr_success="$(jq -cn --arg sha "$SHA_C" '{total_count:1,workflow_runs:[{name:"RESPONSE_ONLY_SENTINEL",head_branch:"v2.0.0",path:".github/workflows/cd.yaml",head_sha:$sha,conclusion:"success"}]}')"
publication_response_case success 0 published complete "$pr_success"
publication_response_case empty 1 unpublished complete '{"total_count":0,"workflow_runs":[],"private":"RESPONSE_ONLY_SENTINEL"}'
publication_response_case failed 1 unpublished complete "$(jq '.workflow_runs[0].conclusion="failure"' <<<"$pr_success")"
publication_response_case pending 1 unpublished complete "$(jq '.workflow_runs[0].conclusion=null' <<<"$pr_success")"
publication_response_case other-workflow 1 unpublished complete "$(jq '.workflow_runs[0].path=".github/workflows/ci.yaml"' <<<"$pr_success")"
publication_response_case other-tag 1 unpublished complete "$(jq '.workflow_runs[0].head_branch="v1.0.0"' <<<"$pr_success")"
publication_response_case null-branch 1 unpublished complete "$(jq '.workflow_runs[0].head_branch=null' <<<"$pr_success")"
publication_response_case moved 2 moved-tag complete "$(jq --arg sha "$SHA_A" '.workflow_runs[0].head_sha=$sha' <<<"$pr_success")"
publication_response_case current-and-moved 0 published complete "$(jq --arg sha "$SHA_A" '.total_count=2 | .workflow_runs += [(.workflow_runs[0] | .head_sha=$sha)]' <<<"$pr_success")"
publication_response_case invalid-json 3 query-unknown invalid 'RESPONSE_ONLY_SENTINEL is not JSON'
publication_response_case multiple-documents 3 query-unknown invalid "$pr_success $pr_success"
publication_response_case null-root 3 query-unknown invalid null
publication_response_case array-root 3 query-unknown invalid "[$pr_success]"
publication_response_case null-runs 3 query-unknown invalid '{"total_count":0,"workflow_runs":null}'
publication_response_case missing-runs 3 query-unknown invalid '{"total_count":0}'
publication_response_case object-runs 3 query-unknown invalid "$(jq '.workflow_runs={wrong:.workflow_runs[0]}' <<<"$pr_success")"
publication_response_case missing-count 3 query-unknown invalid "$(jq 'del(.total_count)' <<<"$pr_success")"
publication_response_case string-count 3 query-unknown invalid "$(jq '.total_count="1"' <<<"$pr_success")"
publication_response_case negative-count 3 query-unknown invalid "$(jq '.total_count=-1' <<<"$pr_success")"
publication_response_case fractional-count 3 query-unknown invalid "$(jq '.total_count=1.5' <<<"$pr_success")"
publication_response_case oversized-count 3 query-unknown invalid "$(jq '.total_count=1e30' <<<"$pr_success")"
publication_response_case exponent-count 0 published complete "$(printf '%s' "$pr_success" | sed 's/"total_count":1/"total_count":1e0/')"
publication_response_case exponent-incomplete-count 3 query-unknown incomplete "$(printf '%s' "$pr_success" | sed 's/"total_count":1/"total_count":1e3/')"
publication_response_case inconsistent-count 3 query-unknown incomplete "$(jq '.total_count=0' <<<"$pr_success")"
publication_response_case truncated-success 3 query-unknown incomplete "$(jq '.total_count=101' <<<"$pr_success")"
publication_response_case truncated-full-page 3 query-unknown incomplete "$(jq '.total_count=101 | .workflow_runs=[range(0;100) | {head_branch:"v2.0.0",path:".github/workflows/cd.yaml",head_sha:"3333333333333333333333333333333333333333",conclusion:"failure"}]' <<<"$pr_success")"
publication_response_case null-row 3 query-unknown invalid "$(jq '.workflow_runs=[null]' <<<"$pr_success")"
publication_response_case missing-field 3 query-unknown invalid "$(jq 'del(.workflow_runs[0].conclusion)' <<<"$pr_success")"
publication_response_case malformed-sha 3 query-unknown invalid "$(jq '.workflow_runs[0].head_sha="short"' <<<"$pr_success")"
publication_response_case malformed-path 3 query-unknown invalid "$(jq '.workflow_runs[0].path=[]' <<<"$pr_success")"
publication_response_case malformed-branch 3 query-unknown invalid "$(jq '.workflow_runs[0].head_branch=123' <<<"$pr_success")"
publication_response_case malformed-conclusion 3 query-unknown invalid "$(jq '.workflow_runs[0].conclusion=false' <<<"$pr_success")"

# Count summaries preserve the distinction between unrelated runs and publications.
grep -q 'total=1 returned=1 matching=1 successful-current=1 successful-other=0' "$WORK/response-success.err" ||
  fail 'the successful response omitted the counts that explain its selection'
grep -q 'total=101 returned=100' "$WORK/response-truncated-full-page.err" ||
  fail 'the incomplete response omitted its advertised and observed counts'

# A malformed/incomplete newest candidate must stop the REAL semver walk, even when
# the registry would permit falling back. The old parser silently resolved 1.9.0.
for pr_case in null-runs truncated-full-page; do
  pr_out="$WORK/response-walk-$pr_case.out"
  if BM_WEDDING_TAGS='v2.0.0\nv1.9.0\n' BM_WEDDING_REGISTRY_TAGS='1.9.0\n' \
    BM_RUNS_RESPONSE_TAG=v2.0.0 BM_RUNS_RESPONSE_FILE="$WORK/response-$pr_case.json" \
    BM_SHA_A="$SHA_A" BM_SHA_B="$SHA_B" BM_SHA_C="$SHA_C" PATH="$bm_bin:$PATH" \
    PUBLISH_CONSUMER_ROOT="$bm_root" "$SCRIPT" >"$pr_out" 2>&1; then
    fail "$pr_case workflow response was silently walked past to an older version"
  else
    grep -q '^UNRESOLVED wedding-app' "$pr_out" || fail "$pr_case did not leave its consumer unresolved"
    grep -q 'could not read the workflow runs for tag v2.0.0' "$pr_out" || fail "$pr_case refused for an unrelated reason"
    [ "$(grep -c '^IN-SYNC' "$pr_out" || true)" -eq "$expected_insync" ] || fail "$pr_case affected other consumers"
    pass "$pr_case publication evidence stops the semver walk"
  fi
done

if [ "$failures" -ne 0 ]; then
  printf '\n%d failure(s)\n' "$failures" >&2
  exit 1
fi
printf '\nPASS: publish-workflow signing-revision report (29 groups)\n'
