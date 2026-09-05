#!/usr/bin/env bash
# Shared, read-only validation and consumer attribution for the matcher guard and writer.
# Sourcing validates the complete approved set and source tree before either caller acts.

set -euo pipefail

GUARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GUARD_DIR
readonly REPORT="$GUARD_DIR/report-publish-workflow-signing-revisions.sh"
# shellcheck source=scripts/report-publish-workflow-signing-revisions.sh
source "$REPORT"

readonly APPROVED_SET="${APPROVED_REVISIONS_FILE:-$REPO_ROOT/scripts/publish-workflow-approved-revisions.tsv}"
readonly SCAN_ROOT="${PUBLISH_CONSUMER_ROOT:-$REPO_ROOT}"
readonly ENFORCE="${APPROVED_REVISIONS_ENFORCE:-0}"
readonly HEADER=$'consumer\tworkflow\tapplied_tag\tapplied_digest\tapplied_signer_sha\tmain_pin_sha\tobserved_on'

# Relative to the scan root. Every entry must exist: a generic subject that moves or is
# renamed would otherwise become an unattributed subject with no home, and this list is
# where its absence should be noticed and the boundary redrawn on purpose.
readonly GENERIC_SUBJECT_FILES=(
  'k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml'
  'k8s/bases/infrastructure/resource-graph-definitions/tenant/resource-graph-definition.yaml'
  'talos/cluster/verify-first-party-images.yaml'
)

readonly SUBJECT_PREFIX='^https://github\.com/devantler-tech/actions/\.github/workflows/publish-'
# Used by both callers after the shared discovery completes.
# shellcheck disable=SC2034
readonly PATTERN_REF='[0-9a-f]{40}'

refuse() {
  printf 'guard-publish-workflow-approved-revisions: %s\n' "$*" >&2
  exit 1
}

case "$ENFORCE" in
  0 | 1) ;;
  *) refuse "APPROVED_REVISIONS_ENFORCE must be 0 or 1, got '$ENFORCE'" ;;
esac

# ── 1. The approved set, read strictly ──────────────────────────────────────────────────
[ -f "$APPROVED_SET" ] || refuse "approved set not found at $APPROVED_SET; run scripts/generate-publish-workflow-approved-revisions.sh"
[ "$(head -n1 "$APPROVED_SET")" = "$HEADER" ] || refuse "approved set header is not the generator's; refusing to read it"

# Records are newline-delimited "<key><TAB>…" strings rather than associative arrays: the
# maintainer's macOS ships bash 3.2, where `declare -A` is a hard error, and a guard that
# cannot run where the matchers are edited is one that gets skipped there.
# lookup <records> <key> → the record for <key> (fields after the key), or nothing.
lookup() {
  # `$1 "" == k ""` forces a STRING compare: awk compares two numeric-looking strings as
  # numbers, so `100` would match a key of `1e2`.
  printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1 "" == k "" { sub(/^[^\t]*\t/, ""); print; exit }'
}

# consumer → "workflow<TAB>signer<TAB>pin"
approved=""
line_no=1
while IFS=$'\t' read -r consumer workflow applied_tag applied_digest signer pin observed_on extra; do
  line_no=$((line_no + 1))
  [ -n "$consumer" ] || continue
  [ "$line_no" -gt 2 ] || [ "$consumer" != 'consumer' ] || continue  # the header
  [ -z "${extra:-}" ] || refuse "approved set line $line_no has more than seven fields"
  [ -n "$observed_on" ] || refuse "approved set line $line_no has fewer than seven fields"
  plausible_repo "$consumer" || refuse "approved set line $line_no names an implausible consumer '$consumer'"
  case "$workflow" in
    publish-app | publish-manifests) ;;
    *) refuse "approved set line $line_no: '$workflow' is not a shared publish workflow" ;;
  esac
  is_sha "$signer" || refuse "approved set line $line_no ($consumer): applied_signer_sha '$signer' is not a 40-hex commit"
  is_sha "$pin" || refuse "approved set line $line_no ($consumer): main_pin_sha '$pin' is not a 40-hex commit"
  [ -z "$(lookup "$approved" "$consumer")" ] || refuse "approved set names $consumer twice"
  : "$applied_tag" "$applied_digest"
  approved="${approved}${consumer}"$'\t'"${workflow}"$'\t'"${signer}"$'\t'"${pin}"$'\n'
done <"$APPROVED_SET"

# Exactly the registered consumers, both directions: a missing row is a consumer nobody
# narrowed, an extra row is a set nothing consumes.
for expected in "${EXPECTED_CONSUMERS[@]}"; do
  [ -n "$(lookup "$approved" "$expected")" ] || refuse "approved set has no row for registered consumer $expected"
done
while IFS=$'\t' read -r consumer _rest; do
  [ -n "$consumer" ] || continue
  known=0
  for expected in "${EXPECTED_CONSUMERS[@]}"; do
    [ "$expected" = "$consumer" ] && known=1 && break
  done
  [ "$known" -eq 1 ] || refuse "approved set names $consumer, which is not a registered consumer"
done <<<"$approved"

# ── 2. Every shared-workflow subject in the tree, attributed or excluded ─────────────────
[ -d "$SCAN_ROOT" ] || refuse "scan root $SCAN_ROOT is not a directory"
for generic in "${GENERIC_SUBJECT_FILES[@]}"; do
  [ -f "$SCAN_ROOT/$generic" ] || refuse "generic subject file $generic is missing from the scan root; the scope boundary has moved — redraw GENERIC_SUBJECT_FILES deliberately"
done

# `.claude/` holds nested per-session worktrees on the maintainer's checkout — whole copies of
# this tree — so descending into it reports every generic subject a second time from a path the
# exclusion list does not name, and the guard refuses a correct repository. `.git` for the same
# reason a packed ref or a stray object file must never be read as a manifest.
subject_files="$(grep -rlE "$SUBJECT_PATTERN" --include='*.yaml' --exclude-dir=.git --exclude-dir=.claude "$SCAN_ROOT" 2>/dev/null | sort -u || true)"
[ -n "$subject_files" ] || refuse "no shared-publish-workflow subject found under $SCAN_ROOT; the scan, not the tree, is the likely cause"

# consumer → "file<TAB>workflow<TAB>ref"
observed=""
while IFS= read -r file; do
  [ -n "$file" ] || continue
  rel="${file#"$SCAN_ROOT"/}"
  case "$rel" in
    scripts/*) continue ;;  # test fixtures under scripts/ carry subjects that verify nothing
  esac
  is_generic=0
  for generic in "${GENERIC_SUBJECT_FILES[@]}"; do
    [ "$rel" = "$generic" ] && is_generic=1 && break
  done
  [ "$is_generic" -eq 0 ] || continue

  # One OCIRepository document per file, with exactly one identity entry, and that entry names a
  # shared workflow — the same attribution the report makes, read the way Flux reads it. Fields:
  # url, the total number of identity entries, the number naming a shared workflow, and the
  # first of those.
  #
  # The TOTAL matters as much as the shared count: `matchOIDCIdentity` is an OR-list, so a second
  # entry beside a correct pair (`subject: '.*'`, or a first-party branch identity) admits any
  # signer while the pair reads as narrowed. Counting only the shared-workflow entries would
  # report `form=set` over exactly that widening.
  # shellcheck disable=SC2016  # `$ids`/`$shared` are yq variables, not shell ones
  docs="$(yq eval -r '
    select(.kind == "OCIRepository") |
    (.spec.verify.matchOIDCIdentity // []) as $ids |
    ($ids | map(.subject // "") | map(select(test("devantler-tech/actions/.{1,2}github/workflows/publish-(app|manifests)")))) as $shared |
    [(.spec.url // "-"), ($ids | length), ($shared | length), ($shared[0] // "-")] | @tsv
  ' "$file" 2>/dev/null)" || refuse "$rel could not be read as YAML"
  [ -n "$docs" ] || refuse "$rel carries a shared-publish-workflow subject but no OCIRepository document owns it; attribute it to a consumer or add it to GENERIC_SUBJECT_FILES"
  [ "$(printf '%s\n' "$docs" | grep -c .)" -eq 1 ] || refuse "$rel carries more than one OCIRepository document; the attribution is ambiguous"
  IFS=$'\t' read -r url identity_count subject_count subject <<<"$docs"
  case "$url" in
    oci://ghcr.io/devantler-tech/*) ;;
    *) refuse "$rel: OCIRepository url '$url' is not a devantler-tech GHCR artifact" ;;
  esac
  [ "$subject_count" = "1" ] || refuse "$rel: expected exactly one shared-publish-workflow subject on the OCIRepository, found $subject_count"
  [ "$identity_count" = "1" ] || refuse "$rel: the OCIRepository carries $identity_count matchOIDCIdentity entries; a second entry beside the pair admits any signer it names, so exactly one is allowed"
  # The line scan that discovered this file and the document read above must agree: a shared-
  # workflow subject in a SECOND document (a policy appended after `---`) is invisible to the
  # OCIRepository selection, and would otherwise pass unjudged.
  line_count="$(grep -cE "$SUBJECT_PATTERN" "$file" || true)"
  [ "$line_count" = "1" ] || refuse "$rel: $line_count shared-publish-workflow subject lines found but exactly one OCIRepository entry was read; a subject outside the OCIRepository document is unjudged"
  repo="${url#oci://ghcr.io/devantler-tech/}"; repo="${repo%%/*}"
  repo="$(oci_name_to_repo "$repo")"
  plausible_repo "$repo" || refuse "$rel: consumer name '$repo' derived from $url is implausible"
  [ -n "$(lookup "$approved" "$repo")" ] || refuse "$rel is a shared-workflow consumer ($repo) with no row in the approved set and no entry in GENERIC_SUBJECT_FILES"
  prior="$(lookup "$observed" "$repo")"
  [ -z "$prior" ] || refuse "consumer $repo has an OCIRepository in both $rel and ${prior%%$'\t'*}"

  case "$subject" in
    "$SUBJECT_PREFIX"*) ;;
    *) refuse "$rel: subject does not start with the shared-workflow identity prefix: $subject" ;;
  esac
  rest="${subject#"$SUBJECT_PREFIX"}"          # <workflow>\.yaml@<ref>$
  case "$rest" in
    *'\.yaml@'*) ;;
    *) refuse "$rel: subject has no '\\.yaml@' boundary: $subject" ;;
  esac
  workflow="publish-${rest%%\\.yaml@*}"
  ref="${rest#*\\.yaml@}"
  case "$ref" in
    *'$') ref="${ref%\$}" ;;
    *) refuse "$rel: subject is not anchored with a trailing \$: $subject" ;;
  esac
  observed="${observed}${repo}"$'\t'"${rel}"$'\t'"${workflow}"$'\t'"${ref}"$'\n'
done <<<"$subject_files"
