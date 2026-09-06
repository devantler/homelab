#!/usr/bin/env bash
# Compute, per consumer, WHICH revision of a shared devantler-tech/actions publish
# workflow signed the artifact that is currently deployed, and which revision that
# consumer pins today.
#
# WHY THIS EXISTS (#3048, under #2818)
# `guard-shared-publish-workflow-pin.sh` proves every cosign matcher pins a FIXED
# revision. It says nothing about WHICH, and it says so itself: a superseded actions SHA
# still matches `[0-9a-f]{40}`. Narrowing those matchers to approved revisions is the open
# half, and it needs the one fact nothing computed — the relationship between "what signed
# what is running" and "what we pin now".
#
# Measured on #2818, five artifacts were signed by five different revisions and TWO were
# signed by a revision their consumer no longer pins. An allow-list generated from current
# pins alone would therefore have stopped verifying two artifacts that are deployed right
# now, and the failure mode is an OCIRepository that quietly stops reconciling while every
# check in CI stays green.
#
# So this REPORTS; it does not gate. Divergence is the expected state today, and a check
# that failed on it would fail on the known-good configuration on its first run — which is
# how a control gets switched off, taking its real coverage with it. What it DOES fail on
# is not being able to SEE.
#
# EVERY FAILURE MODE HERE IS "REPORTS CLEAN WHILE HAVING CHECKED NOTHING"
# That is the only way this script can do harm, so each guard below exists against one
# measured instance of it. They are noted where they sit rather than listed here.
#
# This report reads current GHCR package metadata as well as repository and Actions data.
# The `gh` credential must therefore be allowed to list package versions for the
# devantler-tech organization (`read:packages` on a classic PAT). Without that scope the
# report fails closed: historical git tags and successful runs do not prove that an OCI
# version still exists for Flux to resolve.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

# Matches the subject spelling `guard-shared-publish-workflow-pin.sh` validates. Kept
# textually parallel to that guard: if one moves, the other should be looked at.
readonly SUBJECT_PATTERN='(subject|subjectRegex|subjectRegExp):[[:space:]]*.?\^?https://github\\?\.com/devantler-tech/actions/\\?\.github/workflows/publish-(app|manifests)\\?\.yaml@'

# 🔴 AN IDENTITY FLOOR, NOT A COUNT. A count answers "did I find five things?", which is
# not the question — "did I find THESE five?" is. With a bare count, one consumer moving
# out of the pattern while any other file moves in leaves the total at five, the floor
# passes, and the vanished consumer's revision is never checked. Verified by deleting
# wedding-app's manifest and adding an unrelated matching file: five consumers reported,
# exit 0, wedding-app silently absent. Add a name here when a consumer is genuinely added.
readonly EXPECTED_CONSUMERS=(
  '.github'
  'ascoachingogvaner'
  'aws'
  'wedding-app'
)

fail() {
  printf 'report-publish-workflow-signing-revisions: %s\n' "$*" >&2
  exit 1
}

# The OCI artifact name is USUALLY the source repository's name, but it is not the same
# thing, and one consumer proves it: `.github` has a leading dot, which is an invalid OCI
# path component, so that repository publishes its artifact as `github-config` (documented
# in k8s/bases/apps/github-config/oci-repository.yaml). Deriving the repo from the URL
# alone therefore names a repository that does not exist, and every lookup for a perfectly
# healthy consumer fails.
#
# An explicit reviewed table rather than a guess: a name that needs translating is a
# decision someone should make on purpose. An unmapped name passes through unchanged.
oci_name_to_repo() {
  case "$1" in
    github-config) printf '%s\n' '.github' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# 🔴 `gh api` WRITES ITS ERROR BODY TO STDOUT, so `2>/dev/null || true` does not make a
# failed call empty — it makes it a JSON blob every `[ -n ... ]` test reads as a good
# answer. An earlier revision resolved a healthy consumer against a ref named
# `{"message":"Not Found",...}`: nothing errored, and the report was confidently wrong.
# Exit status is therefore checked directly, and every value is shape-checked before use.
plausible_ref() {
  local ref="$1"
  [ -n "$ref" ] || return 1
  case "$ref" in
    *[[:space:]]* | *'{'* | *'}'* | *'"'*) return 1 ;;
  esac
  return 0
}

# A repository name flows into an API path, so it is shape-checked too rather than
# trusted: a manifest URL of `oci://ghcr.io/devantler-tech/../foo/manifests` would
# otherwise yield `..`.
plausible_repo() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] && [ "$1" != '.' ] && [ "$1" != '..' ]
}

# A revision is reported to a human who will build an allow-list from it, so it must be a
# commit SHA and nothing else.
is_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

# Split one resolver answer into its tab-separated fields, ONE PER LINE, PRESERVING
# EMPTY FIELDS.
#
# 🔴 `IFS=$'\t' read` CANNOT BE USED HERE: tab is IFS WHITESPACE, so bash collapses
# adjacent tabs and an empty MIDDLE field silently shifts every later field LEFT.
# Measured: an answer of `SHA<TAB><TAB>SHA` assigns the ORIGIN field to `current`, both
# halves then pass `is_sha`, and the IN-SYNC/DIVERGED comparison runs on a field that was
# never `current` at all. That is this script's one forbidden failure mode — reporting a
# confident answer having compared the wrong thing — arriving through the parser rather
# than the network. Discovery already carries a `-` placeholder for exactly this reason;
# a resolver answer has no such guarantee, so it is split explicitly instead.
answer_fields() {
  local rest="$1" field tab=$'\t'
  while :; do
    field="${rest%%"${tab}"*}"
    printf '%s\n' "$field"
    [ "$field" = "$rest" ] && break
    rest="${rest#*"${tab}"}"
  done
}

# A transient 5xx or secondary rate limit must not make main red on a REPORT: a control
# that goes red for reasons unrelated to what it checks is one people learn to ignore.
# Bounded, so a genuine outage still fails rather than hanging.
gh_retry() {
  local attempt out
  for attempt in 1 2 3; do
    if out="$(gh "$@" 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    [ "$attempt" -eq 3 ] || sleep $((attempt * 3))
  done
  return 1
}

# The GHCR package belonging to one source repository. `.github` is the one deliberate
# translation: a leading dot is not a valid OCI path component, so it publishes as
# github-config. All current consumers publish their manifests under the same suffix.
ghcr_package_for_repo() {
  case "$1" in
    .github) printf '%s\n' 'github-config/manifests' ;;
    *) printf '%s/manifests\n' "$1" ;;
  esac
}

# Current registry tags for one consumer. GitHub's package API names a nested GHCR
# package with an encoded slash. Its response is authoritative for CURRENT existence;
# git tags and workflow runs below are deliberately historical evidence.
current_registry_tags() {
  local package encoded
  package="$(ghcr_package_for_repo "$1")"
  encoded="${package//\//%2F}"
  gh_retry api --paginate \
    "orgs/devantler-tech/packages/container/${encoded}/versions?per_page=100" \
    --jq '.[].metadata.container.tags[]?'
}

# Translate the source Git ref to the OCI tag emitted by the shared publish workflows:
# they strip the conventional v prefix, and OCI tags encode SemVer's `+` build-metadata
# delimiter as `_` because `+` is not valid in an OCI tag.
registry_tag_for_git_tag() {
  local tag="${1#v}"
  printf '%s\n' "${tag//+/_}"
}

# Print "<repo>\t<workflow>\t<pinned-version-or-empty>" per consumer.
#
# 🔴 ITERATES DOCUMENTS, NOT FILES. Reading one value per FILE drops every consumer after
# the first in a multi-document manifest, and — worse — pairs fields across documents: with
# two matching documents `yq` emits `---` separators, so a first document using a semver
# range and a second carrying a tag yielded the literal `---` as the version. Emitting
# url, tag and subject together as one row per document is what keeps them from the same
# document by construction.
#
# The workflow is read from the document's own cosign SUBJECT, never from a whole-file
# grep: an unanchored grep matches prose, so a comment mentioning the other workflow
# reattributed a consumer — and where a consumer's cd.yaml calls both shared workflows
# that returns the wrong revision silently.
discover_consumers() {
  local root="$1" file url version subjects repo workflow workflows
  [ -d "$root" ] || return 0
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    while IFS=$'\t' read -r url subjects version; do
      # 🔴 TAB IS IFS WHITESPACE, so `read` COLLAPSES consecutive tabs and an empty MIDDLE
      # field silently shifts every later field left. Two consumers pin no `spec.ref.tag`,
      # so their row was `url\t\tsubject` and the subject landed in `version` — both
      # vanished from discovery. Every field is emitted with a `-` placeholder instead of
      # empty, so no field is ever blank and no collapse is possible.
      [ "$version" = "-" ] && version=""
      [ "$subjects" = "-" ] && subjects=""
      [ -n "$url" ] || continue
      case "$url" in
        oci://ghcr.io/devantler-tech/*) ;;
        *) continue ;;
      esac
      # Exactly one shared publish workflow per document, or the attribution is ambiguous
      # and a guess would be worse than a failure.
      workflows="$(printf '%s\n' "$subjects" |
        grep -oE 'publish-(app|manifests)\\?\.yaml@' | sed 's/\\\{0,1\}\.yaml@$//' | sort -u || true)"
      [ -n "$workflows" ] || continue
      if [ "$(printf '%s\n' "$workflows" | grep -c .)" -ne 1 ]; then
        printf 'ambiguous: %s names more than one shared publish workflow\n' "$url" >&2
        continue
      fi
      workflow="$workflows"
      repo="${url#oci://ghcr.io/devantler-tech/}"
      repo="${repo%%/*}"
      [ -n "$repo" ] || continue
      repo="$(oci_name_to_repo "$repo")"
      plausible_repo "$repo" || continue
      printf '%s\t%s\t%s\n' "$repo" "$workflow" "$version"
      # 🔴 FLUX RESOLVES `spec.ref` AS digest > semver > tag, AND AN OMITTED `ref` MEANS
      # the mutable `latest` tag. Reading `tag` first inverts that: a document carrying BOTH
      # a tag and a digest (or a tag and a semver) would be attributed to a tag Flux never
      # serves, and the real signer would be omitted from the proposed allow-list — a
      # confident wrong answer, which is the one outcome this report must never produce. A
      # digest or an omitted ref also collapsed to the meaningless `semver:`, which
      # `effective_version` then refused as a bounded constraint, so a resolvable consumer
      # read as UNRESOLVED.
      #
      # An omitted ref emits `unpinned`, NOT the literal `latest`, so it stays distinct from
      # a document that explicitly writes `tag: latest`. The two are different questions: an
      # explicit tag is a written-down selector this resolver can look up, while an omitted
      # ref is a mutable pointer with no release version behind it. Emitting `latest` for
      # both made the omitted case an exact lookup for a tag that is not a release, and
      # `effective_version` refuses `unpinned` by name instead.
      #
      # These live OUTSIDE the single-quoted yq program deliberately: a backtick inside it
      # reads as a command substitution to shellcheck (SC2016), so prose belongs out here.
    done < <(yq eval -r '
      select(.kind == "OCIRepository") |
      [(.spec.url // "-"),
       ((.spec.verify.matchOIDCIdentity // []) | map(.subject // "") | join(" ") | select(. != "") // "-"),
       (((.spec.ref.digest // "") | select(. != "") | "digest:" + .) // ((.spec.ref.semver // "") | select(. != "") | "semver:" + .) // ((.spec.ref.tag // "") | select(. != "")) // "unpinned")] | @tsv
    ' "$file" 2>/dev/null || true)
  done < <(grep -rlE "$SUBJECT_PATTERN" --include='*.yaml' "$root" 2>/dev/null | sort -u) | sort -u
}

# 🔴 A SEMVER RANGE IS A CONSTRAINT, NOT "WHATEVER IS NEWEST". Discovery carries the
# expression through as `semver:<expr>` instead of discarding it, because the two are
# interchangeable only for an UNBOUNDED lower bound. All three range consumers use
# `>=1.0.0` today, so the newest published tag is exactly what Flux resolves — but a
# bounded selector such as `~1.4` or `<2.0.0` would make the report pick a tag Flux would
# never serve, attribute its workflow revision to the deployed artifact, and omit the real
# signer from the proposed allow-list.
#
# Resolving a bounded range correctly needs Flux-compatible semver selection, which this
# script deliberately does not implement, so it REFUSES rather than guesses.
#
# This is decided from the MANIFEST, before any resolver is consulted — the constraint is a
# property of what is written down, not of anything the network can tell us. Keeping it out
# of `deployed_tag` is also what lets the test suite prove it without network access; when
# this lived inside the resolver, the only way to reach it was to let the real resolver run,
# which made the case non-hermetic and it failed in CI for an unrelated reason.
#
# Prints the effective version (empty means "newest published"), or fails naming the
# constraint.
effective_version() {
  local raw="$1" expr
  case "$raw" in
    '-' | '')
      printf '%s\n' ''
      return 0
      ;;
    # A digest pins an exact artifact rather than a version, so the tag-based resolver
    # cannot answer for it. Refuse by name instead of guessing — the same reasoning as
    # the bounded-semver refusal below.
    digest:*)
      printf 'digest-pinned reference "%s" needs artifact-level resolution, which this script does not implement\n' \
        "${raw#digest:}" >&2
      return 1
      ;;
    # An omitted `spec.ref` tracks the MUTABLE `latest` tag. That is a pointer, not a
    # release version, so the tag walk below has nothing to select and no published
    # release corresponds to it — the same shape as the digest refusal above. Walking to
    # the newest release instead would be a GUESS: `latest` need not point at it, and the
    # report would then attribute that release's workflow revision to whatever is actually
    # deployed. Refuse by name, so the cause is diagnosable rather than surfacing as an
    # opaque lookup miss.
    unpinned)
      printf 'unpinned reference (spec.ref omitted) tracks the mutable "latest" tag, which is not a release version this tag-based resolver can attribute; pin the consumer with a tag, semver range, or digest\n' >&2
      return 1
      ;;
    semver:*)
      expr="${raw#semver:}"
      case "$expr" in
        '*')
          printf '%s\n' ''
          return 0
          ;;
        # ANY character a single lower bound cannot contain means the range is COMPOUND,
        # and therefore bounded. This is a character class rather than a prefix because
        # the previous form was `'>='[0-9]*`, whose trailing `*` swallowed the upper
        # bound of `>=1.0.0 <2.0.0`: that selector begins exactly like the unbounded
        # `>=1.0.0` which IS legitimately allowed, so a prefix test accepted it, dropped
        # the `<2.0.0`, and would resolve to a 2.x tag Flux never serves — attributing
        # that tag's workflow revision to the deployed artifact and omitting the real
        # signer from the allow-list.
        #
        # `>` and `=` are quoted so the shell does not read them as a redirection inside
        # the pattern, and `-` is last inside the class so it stays literal.
        *[!0-9A-Za-z.+'>='-]*)
          printf 'bounded semver constraint "%s" needs Flux-compatible selection, which this script does not implement\n' \
            "$expr" >&2
          return 1
          ;;
        # A lower bound carrying a PRERELEASE component. A range whose bound has none
        # excludes prerelease versions, but one that carries a bound like `>=1.0.0-0`
        # ADMITS them, so Flux can select `2.0.0-rc.1`. The tag walk below orders only
        # release versions, and `sort -V` is not SemVer precedence for a prerelease
        # anyway, so treating this as unbounded would walk back to an older stable tag
        # and attribute ITS workflow revision to the deployed artifact.
        #
        # It is not caught by the compound-range class above, and cannot be: every
        # character in `>=1.0.0-0` is one a single lower bound may legitimately contain,
        # and it begins exactly like the unbounded `>=1.0.0` that IS allowed.
        *-*)
          printf 'prerelease semver constraint "%s" needs Flux-compatible prerelease selection, which this script does not implement\n' \
            "$expr" >&2
          return 1
          ;;
        # The WHOLE selector must BE an inclusive lower bound, not merely start like one.
        # The previous `'>='[0-9]*` matched any trailing text: `>=1.0.0=bad` and
        # `>=1.0.0>=2.0.0` were both read as UNBOUNDED, so the walk returned the newest
        # published tag and attributed its workflow revision to an artifact Flux would
        # never have selected — a confident wrong answer from a selector Flux itself
        # rejects. No character class catches them: every character in both is one a
        # legitimate single lower bound may contain, which is why this is anchored on the
        # whole string instead.
        #
        # One to three numeric components, so a legitimate `>=1.0` is not newly refused.
        # Anything richer (prerelease, build metadata, a second bound) is handled by the
        # arms above or refused here.
        '>='*)
          if [[ "$expr" =~ ^\>=[0-9]+(\.[0-9]+){0,2}$ ]]; then
            printf '%s\n' ''
            return 0
          fi
          printf 'malformed or unsupported semver constraint "%s" needs Flux-compatible selection, which this script does not implement\n' \
            "$expr" >&2
          return 1
          ;;
        # A STRICT lower bound is not the same as an inclusive one. `>=1.0.0` admits
        # 1.0.0, so treating it as unbounded and taking the newest published tag is
        # right. `>1.0.0` EXCLUDES 1.0.0 — so when 1.0.0 is the newest published tag
        # Flux selects nothing there, while the walk below would hand back 1.0.0 and
        # attribute ITS workflow revision to whatever is actually deployed. The walk
        # models no lower bound at all, so this refuses by name like every other
        # constraint whose selection this script does not implement.
        '>'[0-9]*)
          printf 'strict lower-bound semver constraint "%s" needs Flux-compatible selection, which this script does not implement\n' \
            "$expr" >&2
          return 1
          ;;
        *)
          printf 'bounded semver constraint "%s" needs Flux-compatible selection, which this script does not implement\n' \
            "$expr" >&2
          return 1
          ;;
      esac
      ;;
    *)
      printf '%s\n' "$raw"
      return 0
      ;;
  esac
}

# The `uses:` pin for one shared workflow, as it stands at one ref of one consumer.
pin_at_ref() {
  local repo="$1" workflow="$2" ref="$3" body sha
  # The ref goes through as a PARAMETER, exactly as the runs lookup does. A selected
  # tag may carry SemVer build metadata (v2.0.0+build.1), and a raw + in a query string
  # is decoded as a SPACE on the wire -- measured with GH_DEBUG=api: interpolation sends
  # `+`, --raw-field sends `%2B`. The workflow body then fails to load and a healthy
  # consumer reports UNRESOLVED.
  body="$(gh_retry api --method GET "repos/devantler-tech/${repo}/contents/.github/workflows/cd.yaml" \
    --raw-field "ref=${ref}" \
    -H "Accept: application/vnd.github.raw")" || return 1
  [ -n "$body" ] || return 1
  # 🔴 PARSE THE YAML, NOT THE TEXT. An unanchored `grep … | head -1` selects a COMMENTED-OUT
  # old call if it sits above the active one, and the SHA it yields still passes `is_sha` — so
  # both revisions get confidently misreported and the real signer is omitted from the
  # allow-list. Reading `.jobs[].uses` sees only calls that actually run.
  #
  # Exactly one DISTINCT revision, or the attribution is ambiguous. Deduplicate first: two jobs
  # calling the same shared workflow at the same revision is not ambiguity, and counting call
  # SITES rather than revisions would report a perfectly unambiguous consumer as UNRESOLVED and
  # fail the run. Zero means this consumer does not call that workflow at that ref.
  local matches count
  matches="$(printf '%s\n' "$body" | yq eval -r '.jobs[].uses // ""' - 2>/dev/null |
    grep -E "^devantler-tech/actions/\\.github/workflows/${workflow}\\.yaml@[0-9a-f]{40}$" |
    sort -u || true)"
  count="$(printf '%s' "$matches" | grep -c . || true)"
  [ "$count" -eq 1 ] || return 1
  sha="${matches##*@}"
  is_sha "$sha" || return 1
  printf '%s\n' "$sha"
}

# Did this tag's release actually PUBLISH an artifact?
#
# 🔴 A GIT TAG IS NOT A PUBLISHED ARTIFACT. For the three consumers pinning a semver RANGE
# there is no version in the manifest, so the newest tag stands in for "what is deployed" —
# and if that tag's CD run failed or was skipped, no artifact was pushed, Flux is still
# serving the PREVIOUS one, and this script would read a workflow pin from a release that
# never signed anything and print it as a SHA the allow-list "must accept". That omits the
# revision which actually signed the running artifact — the exact outage #3048 exists to
# prevent, one level in.
#
# The publish outcome is public Actions data on the consumer's own repository, so this
# needs no package read and no cluster access, which keeps the check inside the scope
# #3048 set for it.
# The commit a tag currently points at.
#
# 🔴 A TAG IS MUTABLE. `tag_was_published` matches a run by REF NAME, and `pin_at_ref` reads
# cd.yaml at the ref's CURRENT commit — two different commits whenever a release tag has been
# moved or deleted and recreated after an older successful run. The report would then pair a
# workflow revision read from the NEW commit with a publish proved by the OLD one, and print
# it as a SHA the allow-list "must accept": a confident wrong answer built from two facts that
# are individually true. Resolving the tag once and binding the run to it is what keeps the
# publish evidence and the pin evidence on the same commit.
tag_commit() {
  local repo="$1" tag="$2" sha
  sha="$(gh_retry api "repos/devantler-tech/${repo}/commits/${tag}" --jq .sha)" || return 1
  is_sha "$sha" || return 1
  printf '%s\n' "$sha"
}

# Classify publication for <repo> <tag> <expected-commit-sha> using complete Actions data.
# Returns 0 for a matching success, 1 for no success or an invalid expected SHA,
# 2 for success only at another commit, and 3 when the response cannot establish an answer.
# Keeps stdout empty; query results produce one bounded diagnostic on stderr.
tag_was_published() {
  local repo="$1" tag="$2" sha="$3" runs summary diagnostic
  # The commit is REQUIRED, never defaulted: an empty expected SHA would make the match below
  # vacuous and restore exactly the moved-tag hole this argument exists to close.
  is_sha "$sha" || return 1
  # Scoped to this tag rather than fetching the newest 100 runs of the whole repository: on a
  # repository with frequent pushes a candidate release's run falls off that first page, every
  # retry re-fetches the same incomplete page, and a healthy consumer stays UNRESOLVED until the
  # next release. Filtering by ref usually fits one page; the count check below refuses an
  # incomplete page rather than assuming that a missing run never published.
  # The tag goes in as a PARAMETER, not interpolated into the query string. A tag may
  # carry SemVer build metadata (`v2.0.0+build.1`) and this script resolves such tags as
  # themselves, so a raw `+` reaches the wire unencoded, where query parsing reads it as a
  # SPACE. The run for a genuinely published tag is then never matched and a healthy
  # consumer reports UNRESOLVED. Measured: raw interpolation sends `branch=v2.0.0+build.1`,
  # --raw-field sends `branch=v2.0.0%2Bbuild.1`.
  # 🔴 A FAILED QUERY IS NOT AN ESTABLISHED ABSENCE. Returning 1 here made a rate limit, an
  # API outage or a tag-list race indistinguishable from "this tag never published", and the
  # caller's walk then stepped BACKWARD and reported an older release's signing revision as
  # the signer of what is deployed -- a confident wrong answer built from a transient error.
  # Exit 3 says the question could not be answered, so the caller refuses instead of guessing.
  # Only bounded, escaped identifiers and fixed classifications/counts enter the log.
  # Response bodies, arbitrary fields and parser/API errors never become diagnostics.
  printf -v diagnostic 'publication-evidence repo=%q tag=%q' "${repo:0:128}" "${tag:0:128}"
  if ! runs="$(gh_retry api --method GET "repos/devantler-tech/${repo}/actions/runs" \
    --raw-field "branch=${tag}" --raw-field event=push --raw-field per_page=100)"; then
    printf '%s response=query-failed classification=query-unknown\n' "$diagnostic" >&2
    return 3
  fi
  # A successful HTTP read can still be malformed or incomplete. In a jq|grep condition,
  # parser errors used to mean "unpublished", while .workflow_runs[] also accepted object
  # values as runs. Validate one document and every classification field before selecting.
  if ! summary="$(printf '%s' "$runs" | jq -ers --arg t "$tag" --arg s "$sha" '
    if length != 1 then error("expected one response") else .[0] end
    | if type == "object"
         and has("total_count") and has("workflow_runs")
         and (.total_count | type == "number" and . >= 0 and . <= 9007199254740991 and floor == .)
         and (.workflow_runs | type == "array")
         and all(.workflow_runs[];
           type == "object"
           and has("head_branch") and has("path") and has("head_sha") and has("conclusion")
           and (.head_branch | type == "string" or type == "null")
           and (.path | type == "string")
           and (.head_sha | type == "string" and test("^[0-9a-f]{40}$"))
           and (.conclusion | type == "string" or type == "null"))
      then . else error("invalid response shape") end
    | .workflow_runs as $runs
    | [$runs[] | select(.head_branch == $t and .path == ".github/workflows/cd.yaml")] as $matching
    # Keep comparisons in jq: valid JSON integers can use exponent notation, which
    # shell integer tests reject. Arithmetic normalizes their diagnostic spelling;
    # the validation above bounds counts to integers jq can represent exactly.
    | [(.total_count == ($runs | length)), (.total_count + 0), ($runs | length), ($matching | length),
       ([$matching[] | select(.head_sha == $s and .conclusion == "success")] | length),
       ([$matching[] | select(.head_sha != $s and .conclusion == "success")] | length)]
    | @tsv' 2>/dev/null)"; then
    printf '%s response=invalid classification=query-unknown\n' "$diagnostic" >&2
    return 3
  fi
  local complete total returned matching successful_current successful_other response=complete classification rc
  IFS=$'\t' read -r complete total returned matching successful_current successful_other <<<"$summary"
  if [ "$complete" != true ]; then
    response=incomplete classification=query-unknown rc=3
  # `head_sha` binds publication to the tag current commit. Preserve successful current
  # publication precedence; only a success at another commit is a moved-tag anomaly.
  elif [ "$successful_current" -gt 0 ]; then
    classification=published rc=0
  elif [ "$successful_other" -gt 0 ]; then
    classification=moved-tag rc=2
  else
    classification=unpublished rc=1
  fi
  printf '%s response=%s total=%s returned=%s matching=%s successful-current=%s successful-other=%s classification=%s\n' \
    "$diagnostic" "$response" "$total" "$returned" "$matching" "$successful_current" "$successful_other" "$classification" >&2
  return "$rc"
}

# The tag that produced the DEPLOYED artifact.
#
# 🔴 A GitHub RELEASE is the obvious source and the WRONG one. Releases and the artifact
# stream drift apart without anything breaking: `.github` last cut a Release (`v1.4.2`) in
# June 2026 while the artifact its OCIRepository runs today is `1.23.0`, a tag with no
# Release object; `aws` publishes from tags and cuts no Releases at all. Releases are
# therefore not consulted.
#
# Prints "<tag>\t<pinned|inferred>". `pinned` means the OCIRepository names that version
# and its artifact was published; `inferred` means the consumer uses a semver RANGE, so the
# newest published tag is the closest honest answer.
#
# 🔴 NEITHER IS EVIDENCE OF WHAT IS APPLIED, and the caller marks BOTH rows for that reason.
# `pinned` was called `exact` and read as "this IS what is deployed", which it cannot know:
# a version bump landing by direct push to main is reported by validate-main.yaml before the
# manual CD workflow deploys it, so a previously-published tag reads as deployed while the
# cluster still runs its predecessor — and the proposed allow-list then omits the revision
# that actually signed the running artifact. Closing that needs an applied Flux revision,
# which means reading a cluster; this script reads manifests, git tags and Actions runs only.
deployed_tag() {
  local repo="$1" version="$2" tags registry_tags registry_package registry_version candidate bare
  # --paginate: the endpoint caps at 100 per page and these repos already carry 50+ tags.
  # Past the cap an un-paginated read returns an arbitrary subset, which either misses a
  # real tag (false UNRESOLVED) or picks the newest of a truncated page (silently wrong).
  tags="$(gh_retry api --paginate "repos/devantler-tech/${repo}/tags?per_page=100" --jq '.[].name')" || return 1
  [ -n "$tags" ] || return 1
  registry_package="$(ghcr_package_for_repo "$repo")"
  if ! registry_tags="$(current_registry_tags "$repo")"; then
    printf 'could not list current GHCR versions for %s; the gh credential needs package metadata access (read:packages on a classic PAT), and historical tags alone are not deployment evidence\n' \
      "$registry_package" >&2
    return 1
  fi
  if [ -n "$version" ]; then
    # 🔴 BOTH SPELLINGS OF ONE VERSION ARE TWO DISTINCT GIT REFS HERE TOO. The semver walk
    # below refuses that ambiguity by name, but this branch RETURNED ON THE FIRST MATCH, so
    # the refusal was unreachable for the two exact-tag consumers — precisely the consumers
    # whose version is written down and therefore most likely to be spelled either way. When
    # `1.2.3` and `v1.2.3` both exist they can point at different commits and so at different
    # publish-workflow pins, and this loop reported whichever spelling it happened to try
    # first: a confident wrong answer. Decide the ambiguity BEFORE resolving anything.
    local exact_matches exact_count exact_sha
    exact_matches=''
    for candidate in "$version" "v${version}"; do
      printf '%s\n' "$tags" | grep -qxF -- "$candidate" || continue
      exact_matches="${exact_matches}${candidate}"$'\n'
    done
    # `|| true`: `grep -c` exits 1 on a zero count, and a command substitution's status
    # becomes the assignment's, so under `set -e` the legitimate not-found case would abort
    # the run here instead of reaching the return that reports it.
    exact_count="$(printf '%s' "$exact_matches" | grep -c . || true)"
    if [ "$exact_count" -gt 1 ]; then
      printf 'version %s is published as BOTH "%s" and "v%s"; those are distinct git refs that can point at different commits and therefore different workflow pins, so choosing between them needs Flux-compatible ordering, which this script does not implement\n' \
        "$version" "$version" "$version" >&2
      return 1
    fi
    [ "$exact_count" -eq 1 ] || return 1
    candidate="$(printf '%s' "$exact_matches" | head -1)"
    # 🔴 A PINNED TAG EXISTING IS NOT THE SAME AS ITS ARTIFACT HAVING BEEN PUBLISHED. The
    # publication check was reachable only from the semver branch, so the two exact-tag
    # consumers returned as soon as the git tag existed. If that tag's cd.yaml failed, the
    # previous artifact is still applied and this would name the unpublishing tag's pin as
    # the signer of what is deployed. A pinned-but-unpublished version is an anomaly worth
    # surfacing, so it is UNRESOLVED rather than silently walked back to an older tag.
    exact_sha="$(tag_commit "$repo" "$candidate")" || return 1
    # `|| exact_pub=$?` rather than a bare call: under `set -e` a non-zero return would
    # abort the run before the exit status could be read, and the moved-tag case (2) needs
    # to be told apart from the never-published case (1).
    local exact_pub=0
    tag_was_published "$repo" "$candidate" "$exact_sha" || exact_pub=$?
    if [ "$exact_pub" -eq 3 ]; then
      printf 'could not read the workflow runs for the pinned tag %s, so whether it published cannot be established\n' \
        "$candidate" >&2
      return 1
    fi
    if [ "$exact_pub" -eq 2 ]; then
      printf 'tag %s published successfully from a DIFFERENT commit than it points at today, so it has been moved or recreated; the workflow revision read from its current commit did not sign the published artifact\n' \
        "$candidate" >&2
      return 1
    fi
    [ "$exact_pub" -eq 0 ] || return 1
    # An exact OCIRepository tag is not normalized by Flux. The source workflow may have
    # published Git tag v2.0.0 as OCI tag 2.0.0, but a manifest that literally pins
    # v2.0.0 still asks the registry for v2.0.0 and must not be cleared by the other spelling.
    registry_version="$version"
    if ! printf '%s\n' "$registry_tags" | grep -qxF -- "$registry_version"; then
      printf 'tag %s has a successful publish run but exact registry tag %s from the manifest no longer exists in GHCR package %s; it may have been deleted or published under a different spelling, and neither accepting it nor walking backward is deployment evidence\n' \
        "$candidate" "$registry_version" "$registry_package" >&2
      return 1
    fi
    # The VERIFIED commit travels with the tag. `pin_at_ref` used to be handed the tag NAME,
    # which is mutable: if the tag moves after the publication check above and before that
    # read, publication is verified for this commit while cd.yaml is read from a different
    # one, and the report emits a confident signing revision that never signed the artifact.
    printf '%s\tpinned\t%s\n' "$candidate" "$exact_sha"
    return 0
  fi
  # Strip the optional `v` before ordering: `sort -V` compares it as text, so a mixed list
  # orders `v1.23.0` above `1.24.0`. Sort on the bare version, then recover the real tag.
  #
  # Walk NEWEST-FIRST to the newest tag that actually published. Stopping at the newest tag
  # regardless of its release outcome is what would attribute a signature to a revision no
  # deployed artifact was ever signed by. Bounded, because a consumer whose last several
  # releases all failed is a different problem and should surface as UNRESOLVED rather than
  # send this walking back through its whole history.
  #
  # BUILD METADATA is part of a valid release tag and SemVer says it is IGNORED when
  # determining precedence, so `2.0.0` and `2.0.0+build.1` rank EQUALLY and there is no
  # defined answer to which one a selector picks. Matching only the bare form would
  # silently discard `2.0.0+build.1` and walk back to an older release, attributing that
  # release's workflow revision to the deployed artifact. Both forms are therefore
  # candidates, keyed on the core version they share, and a core version carrying more
  # than one distinct tag REFUSES — the same reasoning as the bounded-range refusal:
  # picking one of two equally-ranked tags is a guess, and a guess here is the confident
  # wrong answer this report must never produce.
  #
  # 🔴 A CHARACTER-CLASS REGEX IS NOT SEMVER VALIDATION. The previous pattern accepted
  # `v02.0.0` (SemVer forbids leading zeros in a numeric identifier) and `v2.0.0+foo..bar`
  # or `v2.0.0+.` (a build identifier may not be empty) — measured directly against it. It
  # then stripped the metadata and ranked what was left: `02.0.0` sorts ABOVE `1.9.0`, so an
  # invalid tag with a successful CD run could be selected and its workflow pin attributed to
  # the consumer while Flux, rejecting the tag, resolves an older artifact.
  #
  # Candidates are therefore built with a STRICT pattern. Excluding an invalid tag is not on
  # its own enough, though: silently skipping it walks back to an older release and reports
  # THAT release's pin, which is the confident wrong answer rather than a refusal. So the
  # tags this script cannot rank are also detected, and when one of them could outrank the
  # best valid candidate the run REFUSES by name — the same treatment every other ambiguity
  # here gets, and deliberately narrower than refusing on the mere existence of a stray tag,
  # which would park a repository on one ancient malformed release forever.
  local candidates checked=0
  local strict_re='^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
  # Version-like enough to be intended as a release, but not something this script ranks.
  # It must cover every form FLUX accepts, not just the malformed ones: Flux parses tags with
  # Masterminds semver.NewVersion, which COERCES a partial version -- measured, v2.5 resolves
  # to 2.5.0 and v2 to 2.0.0. A pattern requiring three components matched neither the strict
  # filter nor this one, so such a tag was dropped from BOTH sets: the walk stepped silently
  # to an older release and reported ITS signing revision, omitting the actual signer from
  # the allow-list. Four-component tags and non-numeric ones stay out: Flux rejects them too
  # (measured), so they cannot be selected and refusing on them would be noise.
  #
  # PRERELEASES stay out for the same reason, and the guarantee comes from this script:
  # `effective_version` REFUSES any constraint carrying a prerelease bound by name, so every
  # consumer that reaches this walk has a constraint with no prerelease comparator -- and
  # Masterminds excludes prereleases from exactly those. A prerelease therefore cannot be
  # selected no matter how it orders, so treating one as an unrankable ambiguity refused a
  # consumer Flux resolves unambiguously: an `v2.0.0-rc.1` above the newest stable made every
  # run red until the RC tag was deleted or a stable release was cut.
  local loose_re='^v?[0-9]+(\.[0-9]+){0,2}(\+[0-9A-Za-z.-]*)?$'
  candidates="$(printf '%s\n' "$tags" | grep -E "$strict_re" |
    sed -e 's/^v//' -e 's/+.*$//' | sort -V -r -u || true)"
  [ -n "$candidates" ] || return 1
  # Version-like enough to be intended as a release, but not valid SemVer.
  local unrankable top_valid bad bad_core highest
  unrankable="$(printf '%s\n' "$tags" | grep -E "$loose_re" | grep -Ev "$strict_re" || true)"
  if [ -n "$unrankable" ]; then
    top_valid="$(printf '%s\n' "$candidates" | head -1)"
    while IFS= read -r bad; do
      [ -n "$bad" ] || continue
      bad_core="$(printf '%s' "$bad" | sed -e 's/^v//' -e 's/+.*$//')"
      [ -n "$bad_core" ] || continue
      highest="$(printf '%s\n%s\n' "$bad_core" "$top_valid" | sort -V -r | head -1)"
      if [ "$highest" = "$bad_core" ]; then
        printf 'tag %s is not valid SemVer (a numeric identifier may not carry a leading zero and a build identifier may not be empty) yet would rank at or above %s; Flux may or may not select it, and choosing needs Flux-compatible ordering, which this script does not implement\n' \
          "$bad" "$top_valid" >&2
        return 1
      fi
    done <<<"$unrankable"
  fi
  local core_re variants variant_count candidate
  while IFS= read -r bare; do
    [ -n "$bare" ] || continue
    checked=$((checked + 1))
    [ "$checked" -le 5 ] || break
    # Every tag standing at this SemVer precedence. Build metadata is IGNORED for
    # precedence, so `2.0.0` and `2.0.0+build.1` rank equally and the set can hold more
    # than one tag. The `v` spellings are folded for PRECEDENCE, but folding them for
    # IDENTITY would hide a real ambiguity -- see the duality refusal immediately below.
    core_re="$(printf '%s' "$bare" | sed 's/[.]/\\./g')"
    # BOTH SPELLINGS OF ONE VERSION ARE TWO DISTINCT GIT REFS. Stripping the `v` before
    # `sort -u` folds `1.2.3` and `v1.2.3` into one variant, so the tie check below sees
    # no ambiguity -- but the two refs can point at different commits and therefore at
    # different publish-workflow pins, and the loop that follows unconditionally prefers
    # the `v` form. That reports the `v` ref's signing revision even when the other ref
    # produced the deployed artifact: a confident wrong answer, which is exactly what the
    # tie refusal exists to prevent one line down.
    #
    # The fold is only safe when one spelling is published. When both are, refuse by name
    # like every other ambiguity here rather than picking the one this repository happens
    # to favour.
    local raw_variants dual=""
    raw_variants="$(printf '%s\n' "$tags" | grep -E "^v?${core_re}(\+[0-9A-Za-z.-]+)?$" | sort -u || true)"
    while IFS= read -r stripped; do
      [ -n "$stripped" ] || continue
      if printf '%s\n' "$raw_variants" | grep -qxF -- "$stripped" &&
        printf '%s\n' "$raw_variants" | grep -qxF -- "v${stripped}"; then
        dual="$stripped"
        break
      fi
    done <<<"$(printf '%s\n' "$raw_variants" | sed 's/^v//' | sort -u)"
    if [ -n "$dual" ]; then
      printf 'version %s is published as BOTH "%s" and "v%s"; those are distinct git refs that can point at different commits and therefore different workflow pins, so choosing between them needs Flux-compatible ordering, which this script does not implement\n' \
        "$bare" "$dual" "$dual" >&2
      return 1
    fi
    # A PARTIAL TAG COERCES TO THIS SAME PRECEDENCE, and it is invisible to every check
    # above. Flux reads `v2.0` as 2.0.0, so it TIES `v2.0.0` and may be the ref Flux
    # selects -- but `sort -V` orders `2.0.0` ABOVE `2.0`, so the partial reads as safely
    # lower, and its spelling matches neither the three-component core pattern nor the
    # duality fold. The walk below then considers only the strict tag and can report ITS
    # signing revision for an artifact the partial tag produced: a confident wrong answer,
    # which is the same failure the build-metadata tie refusal exists to prevent.
    #
    # Only a trailing-zero core has a partial spelling: `2.0.0` can be written `2.0` (and
    # `2.0.0` also `2`), while `2.1.3` cannot be shortened at all.
    local partial_re="" p_major p_minor p_patch partial_hit
    case "$bare" in
      *.*.*)
        p_major="${bare%%.*}"
        p_patch="${bare##*.}"
        p_minor="${bare#*.}"
        p_minor="${p_minor%%.*}"
        if [ "$p_patch" = "0" ]; then
          partial_re="${p_major}\\.${p_minor}"
          if [ "$p_minor" = "0" ]; then
            partial_re="${partial_re}|${p_major}"
          fi
        fi
        ;;
    esac
    if [ -n "$partial_re" ]; then
      partial_hit="$(printf '%s\n' "$tags" | grep -E "^v?(${partial_re})$" | sort -u || true)"
      if [ -n "$partial_hit" ]; then
        printf 'version %s is also published as a PARTIAL tag (%s); Flux coerces the partial spelling to the same SemVer precedence, so the two tie and can point at different commits and therefore different workflow pins, and choosing between them needs Flux-compatible ordering, which this script does not implement\n' \
          "$bare" "$(printf '%s\n' "$partial_hit" | tr '\n' ' ')" >&2
        return 1
      fi
    fi
    variants="$(printf '%s\n' "$tags" | grep -E "^v?${core_re}(\+[0-9A-Za-z.-]+)?$" |
      sed 's/^v//' | sort -u || true)"
    variant_count="$(printf '%s\n' "$variants" | grep -c . || true)"
    if [ "$variant_count" -gt 1 ]; then
      printf 'version %s is carried by more than one tag (%s); build metadata ties their SemVer precedence, so choosing between them needs Flux-compatible ordering, which this script does not implement\n' \
        "$bare" "$(printf '%s\n' "$variants" | tr '\n' ' ')" >&2
      return 1
    fi
    # The real tag comes from the tag list, never from reconstructing `bare`: a version
    # published only as `2.0.0+build.1` has no bare spelling to rebuild, so rebuilding
    # would find nothing, walk silently back to an older release, and attribute THAT
    # release's workflow revision to the deployed artifact. The `v` form is preferred
    # only because these repositories use it.
    local walk_sha
    for candidate in "v${variants}" "$variants"; do
      printf '%s\n' "$tags" | grep -qxF -- "$candidate" || continue
      plausible_ref "$candidate" || continue
      # A `break` here would leave the OUTER loop free to step to an older version, so a
      # transient commit lookup failure was reported as that older release's signing
      # revision. The tag is known to exist -- it came from the tag list two lines up -- so
      # a failure is the query, never absence, and the run refuses by name.
      if ! walk_sha="$(tag_commit "$repo" "$candidate")"; then
        printf 'could not resolve the commit for tag %s, so whether it published cannot be established; walking past it would attribute an older release workflow revision to the deployed artifact\n' \
          "$candidate" >&2
        return 1
      fi
      local walk_pub=0
      tag_was_published "$repo" "$candidate" "$walk_sha" || walk_pub=$?
      if [ "$walk_pub" -eq 3 ]; then
        printf 'could not read the workflow runs for tag %s, so whether it published cannot be established; walking past it would attribute an older release workflow revision to the deployed artifact\n' \
          "$candidate" >&2
        return 1
      fi
      if [ "$walk_pub" -eq 0 ]; then
        registry_version="$(registry_tag_for_git_tag "$candidate")"
        if ! printf '%s\n' "$registry_tags" | grep -qxF -- "$registry_version"; then
          printf 'tag %s has a successful publish run but registry tag %s no longer exists in GHCR package %s; it may have been deleted, and walking backward would attribute an older release to what Flux resolves today\n' \
            "$candidate" "$registry_version" "$registry_package" >&2
          return 1
        fi
        # Flux chooses a semver candidate from CURRENT REGISTRY TAGS, not from Git refs.
        # A deleted Git tag can leave its GHCR version behind, and a still-present Git
        # tag can have no successful publication evidence. Either way, if the registry
        # version ranks ABOVE the candidate this Git-and-Actions walk selected, silently
        # returning the lower release would attribute the wrong signing revision. A
        # distinct registry tag at the SAME precedence is ambiguous for the same reason.
        local registry_seen registry_semver registry_core selected_core registry_high
        selected_core="${variants%%+*}"
        while IFS= read -r registry_seen; do
          [ -n "$registry_seen" ] || continue
          [ "$registry_seen" = 'latest' ] && continue
          registry_semver="${registry_seen/_/+}"
          if [[ "$registry_semver" =~ $strict_re ]] || [[ "$registry_semver" =~ $loose_re ]]; then
            registry_core="$(printf '%s' "$registry_semver" | sed -e 's/^v//' -e 's/+.*$//')"
            # Masterminds SemVer (and therefore Flux) coerces partial versions before
            # ordering: 2 == 2.0 == 2.0.0. Keep the registry tag's original spelling
            # for identity and diagnostics, but compare its normalized three-component
            # core so a distinct partial tag cannot hide a same-precedence ambiguity.
            case "$registry_core" in
              *.*.*) ;;
              *.*) registry_core="${registry_core}.0" ;;
              *) registry_core="${registry_core}.0.0" ;;
            esac
          else
            continue
          fi
          registry_high="$(printf '%s\n%s\n' "$registry_core" "$selected_core" | sort -V -r | head -1)"
          if [ "$registry_core" = "$selected_core" ]; then
            if [ "$registry_seen" != "$registry_version" ]; then
              printf 'registry tag %s has the same SemVer precedence as selected registry tag %s; Flux can select either, and choosing needs Flux-compatible ordering plus publication evidence for both\n' \
                "$registry_seen" "$registry_version" >&2
              return 1
            fi
            continue
          fi
          if [ "$registry_high" = "$registry_core" ]; then
            printf 'registry tag %s ranks above selected release %s but this resolver cannot map the higher selection to one Git tag and successful publication run; refusing instead of attributing an older release to what Flux resolves\n' \
              "$registry_seen" "$registry_version" >&2
            return 1
          fi
        done <<<"$registry_tags"
        # The early refusal above compares against the highest STRICT tag, which is not
        # necessarily the one being reported: when that tag never published, the walk steps
        # past it to an older release, and a loose tag sitting between the two was cleared
        # by a comparison against a version nobody selects. Flux coerces such a tag -- `v2.5`
        # resolves to 2.5.0 -- so it can be selected ahead of the release reported here, and
        # the run would emit the wrong signing revision. Re-check the set against the version
        # actually being returned, which is the only one the answer depends on.
        if [ -n "$unrankable" ]; then
          local late_bad late_core late_high
          while IFS= read -r late_bad; do
            [ -n "$late_bad" ] || continue
            late_core="$(printf '%s' "$late_bad" | sed -e 's/^v//' -e 's/+.*$//')"
            [ -n "$late_core" ] || continue
            late_high="$(printf '%s\n%s\n' "$late_core" "$variants" | sort -V -r | head -1)"
            if [ "$late_high" = "$late_core" ]; then
              printf 'tag %s is not valid SemVer yet Flux would coerce it to rank at or above the reported release %s, so it may be the artifact Flux selected; choosing needs Flux-compatible ordering, which this script does not implement\n' \
                "$late_bad" "$variants" >&2
              return 1
            fi
          done <<<"$unrankable"
        fi
        printf '%s\tinferred\t%s\n' "$candidate" "$walk_sha"
        return 0
      fi
      if [ "$walk_pub" -eq 2 ]; then
        printf 'tag %s published successfully from a DIFFERENT commit than it points at today, so it has been moved or recreated; walking past it would attribute an older release workflow revision to the deployed artifact\n' \
          "$candidate" >&2
        return 1
      fi
      break
    done
  done <<<"$candidates"
  return 1
}

# Default resolver: "<signing revision>\t<current pin>\t<pinned|inferred>".
default_resolver() {
  local repo="$1" workflow="$2" version="${3:-}" branch tagline tag origin tag_sha signing current
  branch="$(gh_retry api "repos/devantler-tech/${repo}" --jq .default_branch)" || return 1
  plausible_ref "$branch" || return 1
  tagline="$(deployed_tag "$repo" "$version")" || return 1
  # THREE fields: reading two would leave `origin` holding "pinned<TAB><sha>", which matches
  # neither `pinned` nor `inferred` in the disclaimer case below, so the row would silently
  # lose its not-applied-revision disclaimer.
  IFS=$'\t' read -r tag origin tag_sha <<<"$tagline"
  # Fail closed rather than fall back to the tag: an empty or malformed third field would
  # restore exactly the mutable-ref read this change exists to close.
  is_sha "${tag_sha:-}" || return 1
  current="$(pin_at_ref "$repo" "$workflow" "$branch")" || return 1
  # The COMMIT, never `$tag`. `$tag` remains the human-facing name and is what the Actions
  # run query above was scoped to; it is not a stable ref to read file content at.
  signing="$(pin_at_ref "$repo" "$workflow" "$tag_sha")" || return 1
  printf '%s\t%s\t%s\n' "$signing" "$current" "$origin"
}

main() {
  local root="${PUBLISH_CONSUMER_ROOT:-$REPO_ROOT}"
  local consumers found missing=""
  consumers="$(discover_consumers "$root")"
  found="$(printf '%s' "$consumers" | cut -f1 | sort -u)"

  local expected
  for expected in "${EXPECTED_CONSUMERS[@]}"; do
    printf '%s\n' "$found" | grep -qxF -- "$expected" || missing="${missing} ${expected}"
  done

  # Both directions. Checking only that every EXPECTED name was found accepts an unregistered
  # sixth consumer — and that one can later move or change its subject spelling, disappear, and
  # leave all five registered names present so the report exits clean. That is exactly the silent
  # disappearance this floor exists to prevent, just one consumer along. Requiring registration
  # makes adding a consumer a deliberate, reviewed act.
  local discovered unregistered=""
  while IFS= read -r discovered; do
    [ -n "$discovered" ] || continue
    local known=0 e
    for e in "${EXPECTED_CONSUMERS[@]}"; do
      [ "$e" = "$discovered" ] && known=1 && break
    done
    [ "$known" -eq 1 ] || unregistered="${unregistered} ${discovered}"
  done <<<"$found"

  if [ -n "$unregistered" ]; then
    printf 'discovered consumer(s) not registered in EXPECTED_CONSUMERS:%s\n' "$unregistered" >&2
    printf 'A consumer this script does not know about is one it cannot notice the LOSS of later.\n' >&2
    printf 'Add it to EXPECTED_CONSUMERS so its disappearance would fail this run.\n' >&2
    exit 1
  fi

  if [ -n "$missing" ]; then
    printf 'expected consumer(s) not discovered:%s\n' "$missing" >&2
    printf 'The scan, not the repository, is the likely cause: those OCIRepositories may have\n' >&2
    printf 'moved, been renamed, or adopted a subject spelling this pattern does not match.\n' >&2
    printf 'Verify by hand, then fix the pattern or amend EXPECTED_CONSUMERS with the reason.\n' >&2
    exit 1
  fi

  if [ "${1:-}" = "--list-consumers" ]; then
    printf '%s\n' "$consumers"
    return 0
  fi

  local resolver="${PUBLISH_REVISION_RESOLVER:-}"
  local repo workflow version answer signing current origin field field_count
  local diverged=0 unresolved=0 examined=0
  # Scratch for one consumer's refusal diagnostic. A file rather than a process
  # substitution so the capture works under a plain POSIX-ish shell, and so the
  # command substitution above still yields `effective_version`'s STDOUT and its exit
  # status unchanged -- `2>&1` would fold the diagnostic into the version string.
  local why why_file
  why_file="$(mktemp)" || return 1

  printf 'Shared publish-workflow revisions, per consumer (#3048)\n'
  printf '%s\n' '-------------------------------------------------------'

  while IFS=$'\t' read -r repo workflow version; do
    [ -n "$repo" ] || continue
    examined=$((examined + 1))
    # Classify from the manifest first: a bounded range is refused before any resolver is
    # consulted, because the constraint is written down rather than discovered remotely.
    #
    # REPORT THE CAUSE THE RESOLVER ACTUALLY GAVE. `effective_version` refuses for five
    # distinct reasons -- digest-pinned, omitted, prerelease bound, malformed inclusive
    # bound, strict lower bound -- and writes the specific one to stderr. Printing a fixed
    # "bounded semver constraint" for all of them told a reader of the step summary the
    # wrong thing for four of the five, and the summary is stdout-only (see the note at the
    # tally below), so the real cause was not merely elsewhere -- it was absent.
    if ! version="$(effective_version "$version" 2>"$why_file")"; then
      unresolved=$((unresolved + 1))
      # One row per consumer: fold the diagnostic to a single line, and fall back to the
      # generic wording only if the refusal was silent.
      why="$(tr '\n' ' ' <"$why_file" | sed -E 's/[[:space:]]+/ /g; s/ $//')"
      [ -n "$why" ] || why='not resolvable here (no diagnostic emitted)'
      printf 'UNRESOLVED %-22s %-18s %s\n' "$repo" "$workflow" "$why"
      continue
    fi
    if [ -n "$resolver" ]; then
      answer="$("$resolver" "$repo" "$workflow" "$version")" || answer=""
    else
      answer="$(default_resolver "$repo" "$workflow" "$version")" || answer=""
    fi
    # The one-tab-free-line case that `cut -f2` without `-s` used to accept is covered by
    # the same shape check below: fewer than two fields is UNRESOLVED, never agreement.
    # A resolver answer must be EXACTLY one line of two or three tab-separated fields,
    # each SHA field non-empty. Anything else is UNRESOLVED, never agreement.
    #
    # 🔴 `read` IS NOT SAFE HERE, on two independent counts, both measured on this exact
    # path: it stops at the FIRST LINE, so a valid line followed by trailing output was
    # accepted unseen; and tab is IFS whitespace, so `SHA<TAB><TAB>SHA` COLLAPSED to two
    # fields and assigned the ORIGIN field to `current` — both halves then passed
    # `is_sha` and the comparison ran on a field that was never `current`.
    field_count=0
    signing=''
    current=''
    origin=''
    while IFS= read -r field; do
      case "$field_count" in
        0) signing="$field" ;;
        1) current="$field" ;;
        2) origin="$field" ;;
      esac
      field_count=$((field_count + 1))
    done < <(answer_fields "$answer")
    # A multi-line answer is rejected outright rather than judged on its first line.
    case "$answer" in
      *$'\n'*) field_count=0 ;;
    esac
    if [ "$field_count" -lt 2 ] || [ "$field_count" -gt 3 ] ||
      ! is_sha "${signing:-}" || ! is_sha "${current:-}"; then
      unresolved=$((unresolved + 1))
      printf 'UNRESOLVED %-22s %-18s could not resolve both revisions to a commit SHA\n' \
        "$repo" "$workflow"
      continue
    fi
    local mark=''
    # 🔴 NEITHER ORIGIN IS A MEASUREMENT OF WHAT FLUX HAS APPLIED, and both say so. This
    # script reads manifests, git tags, Actions runs and current GHCR package metadata;
    # nothing here reads a cluster. Saying so is the difference between an allow-list built
    # on evidence and one built on a guess that reads identically.
    #
    # `pinned` was called `exact`, which overclaimed in a way that is reachable rather than
    # theoretical: a version bump landing by DIRECT PUSH to main runs validate-main.yaml
    # immediately, while that path does not deploy until the manual CD workflow runs. If
    # that tag's artifact had been published earlier, the row read `exact` — "this IS what
    # is deployed" — while the cluster was still running the PREVIOUS tag, so the proposed
    # allow-list could omit the revision that actually signed the running artifact.
    # `tag_was_published` closes "the tag exists but never published"; it cannot close
    # "published but not yet applied", and no tag-based check can.
    case "${origin:-}" in
      inferred) mark=' (deployed version inferred from newest PUBLISHED tag; not applied-revision evidence)' ;;
      pinned) mark=' (deployed version is what the manifest PINS and was published; not applied-revision evidence)' ;;
    esac
    if [ "$signing" = "$current" ]; then
      printf 'IN-SYNC    %-22s %-18s signed=%s pinned=%s%s\n' \
        "$repo" "$workflow" "$signing" "$current" "$mark"
      printf '           allow-list must accept: %s\n' "$signing"
    else
      diverged=$((diverged + 1))
      printf 'DIVERGED   %-22s %-18s signed=%s pinned=%s%s\n' \
        "$repo" "$workflow" "$signing" "$current" "$mark"
      # AC4: an allow-list narrowed to the current pin alone would stop verifying the
      # deployed artifact. Naming BOTH is the actionable output of this whole script.
      printf '           allow-list must accept: %s AND %s\n' "$signing" "$current"
    fi
  done <<<"$consumers"
  rm -f "$why_file"

  printf '%s\n' '-------------------------------------------------------'
  # `unresolved` is in the tally deliberately. The failure detail below also goes to
  # stdout: `tee` into the step summary captures stdout only, so a stderr-only diagnostic
  # left a human reading `0 diverged` as the last line of a run that had FAILED.
  printf '%d consumer(s) examined, %d diverged, %d unresolved.\n' \
    "$examined" "$diverged" "$unresolved"

  if [ "$unresolved" -gt 0 ]; then
    printf '\nFAILED: %d consumer(s) could not be resolved. A consumer whose revisions cannot\n' "$unresolved"
    printf 'be read is not evidence of agreement, so this run fails rather than reporting a\n'
    printf 'clean portfolio it could not see.\n'
    return 1
  fi

  if [ "$diverged" -gt 0 ]; then
    printf '\nDivergence is REPORTED, not failed: an allow-list on #2818 must accept both\n'
    printf 'revisions for each diverged consumer, or it will stop verifying a deployed artifact.\n'
  fi
}

# Run only as a command. `generate-publish-workflow-approved-revisions.sh` (#3550) sources
# this file for discovery, `pin_at_ref`, `tag_commit` and the shape checks, so the same
# resolution rules serve both the report and the generated approved set.
if [ "${BASH_SOURCE[0]:-}" = "$0" ]; then
  main "$@"
fi
