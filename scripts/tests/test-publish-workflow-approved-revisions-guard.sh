#!/usr/bin/env bash
# RED/GREEN coverage for `guard-publish-workflow-approved-revisions.sh` (#3551).
#
# WHAT IS ACTUALLY BEING PROVED
# The guard's one harmful failure mode is passing: a per-consumer matcher that names a revision
# outside that consumer's generated pair still verifies SOMETHING, so no schema, kubeconform
# pass or deploy notices. Every case below therefore isolates one conjunct and asserts the
# guard refuses it BY NAME — the consumer and the offending ref appear in the message — rather
# than merely exiting non-zero for some other reason. The switch is proved in both states.
#
# THE SEAMS
# The guard reads the approved set from APPROVED_REVISIONS_FILE and scans PUBLISH_CONSUMER_ROOT;
# both are pointed at a synthetic tree built here. Discovery, attribution and the registered
# consumer list are REAL (sourced from the report), so the fixture carries exactly the four
# registered consumers plus the three generic subject files the guard excludes by name.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly GUARD="$REPO_ROOT/scripts/guard-publish-workflow-approved-revisions.sh"
readonly REPORT="$REPO_ROOT/scripts/report-publish-workflow-signing-revisions.sh"

readonly PATTERN='[0-9a-f]{40}'
readonly SHA_A='1111111111111111111111111111111111111111'
readonly SHA_B='2222222222222222222222222222222222222222'
readonly SHA_C='3333333333333333333333333333333333333333'
readonly SHA_D='4444444444444444444444444444444444444444'
readonly DIGEST='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly GENERIC_KYVERNO='k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml'
readonly GENERIC_RGD='k8s/bases/infrastructure/resource-graph-definitions/tenant/resource-graph-definition.yaml'
readonly GENERIC_TALOS='talos/cluster/verify-first-party-images.yaml'

failures=0
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}
pass() { printf 'ok: %s\n' "$*"; }

[ -x "$GUARD" ] || { fail "guard not executable at $GUARD"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The registered consumers, from the report itself, so this test cannot drift from the list
# the guard enforces. Each row: <repo>\t<workflow>.
consumers="$("$REPORT" --list-consumers 2>/dev/null | cut -f1,2 || true)"
if [ -z "$consumers" ]; then
  fail '--list-consumers produced nothing; every case below would pass vacuously'
  printf '\n%d failure(s)\n' "$failures" >&2
  exit 1
fi
consumer_count="$(printf '%s\n' "$consumers" | grep -c .)"
[ "$consumer_count" -ge 2 ] || { fail "need at least two registered consumers to cross pairs, found $consumer_count"; exit 1; }
first_consumer="$(printf '%s\n' "$consumers" | sed -n 1p | cut -f1)"
first_workflow="$(printf '%s\n' "$consumers" | sed -n 1p | cut -f2)"
second_consumer="$(printf '%s\n' "$consumers" | sed -n 2p | cut -f1)"

# The artifact name is the repository name except for `.github`, which publishes as
# `github-config` — the same table the report uses.
package_for() {
  case "$1" in
    .github) printf '%s\n' 'github-config' ;;
    *) printf '%s\n' "$1" ;;
  esac
}
# Per-consumer pair: consumer N signs with SHA_A+N-ish spelled as distinct SHAs. Keep it simple:
# every consumer's signer is SHA_A except the second, whose signer is SHA_C; every pin is SHA_B.
signer_for() {
  if [ "$1" = "$second_consumer" ]; then printf '%s\n' "$SHA_C"; else printf '%s\n' "$SHA_A"; fi
}

subject_for() { # <workflow> <ref>
  printf "'^https://github\\\\.com/devantler-tech/actions/\\\\.github/workflows/%s\\\\.yaml@%s\$'" "$1" "$2"
}

# write_consumer <root> <repo> <workflow> <ref> — one OCIRepository manifest at the path the
# real tree uses for that consumer (the guard attributes by URL, not path, so the path is free).
write_consumer() {
  local root="$1" repo="$2" workflow="$3" ref="$4" dir
  dir="$root/k8s/bases/apps/$(package_for "$repo")"
  mkdir -p "$dir"
  cat >"$dir/oci-repository.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: $(package_for "$repo")
spec:
  url: oci://ghcr.io/devantler-tech/$(package_for "$repo")/manifests
  ref:
    semver: '>=1.0.0'
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\\.actions\\.githubusercontent\\.com\$'
        subject: $(subject_for "$workflow" "$ref")
EOF
}

# append_identity <root> <repo> <subject-regex> — a SECOND matchOIDCIdentity entry on the
# consumer's OCIRepository. Flux ORs the entries, so this is the shape that widens a matcher
# while its shared-workflow entry still reads as narrowed.
append_identity() {
  local root="$1" repo="$2" subject="$3"
  printf "      - issuer: '.*'\n        subject: '%s'\n" "$subject" \
    >>"$root/k8s/bases/apps/$(package_for "$repo")/oci-repository.yaml"
}

# append_document <root> <repo> <ref> — a second YAML document after the consumer's
# OCIRepository, carrying a shared-workflow subject the OCIRepository selection cannot see.
append_document() {
  local root="$1" repo="$2" ref="$3"
  cat >>"$root/k8s/bases/apps/$(package_for "$repo")/oci-repository.yaml" <<EOF
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: stray
spec:
  rules:
    - verifyImages:
        - attestors:
            - entries:
                - keyless:
                    subjectRegExp: ^https://github\\.com/devantler-tech/actions/\\.github/workflows/publish-app\\.yaml@$ref\$
EOF
}

# write_generics <root> <ref> — the three generic subject files, on the given ref form.
write_generics() {
  local root="$1" ref="$2"
  mkdir -p "$root/$(dirname "$GENERIC_KYVERNO")" "$root/$(dirname "$GENERIC_RGD")" "$root/$(dirname "$GENERIC_TALOS")"
  cat >"$root/$GENERIC_KYVERNO" <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-app-images
spec:
  rules:
    - name: x
      verifyImages:
        - attestors:
            - entries:
                - keyless:
                    subjectRegExp: ^https://github\\.com/devantler-tech/actions/\\.github/workflows/publish-app\\.yaml@$ref\$
EOF
  cat >"$root/$GENERIC_RGD" <<EOF
apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: tenant
spec:
  resources:
    - id: oci
      template:
        apiVersion: source.toolkit.fluxcd.io/v1
        kind: OCIRepository
        spec:
          verify:
            matchOIDCIdentity:
              - issuer: x
                subject: $(subject_for publish-app "$ref")
EOF
  cat >"$root/$GENERIC_TALOS" <<EOF
apiVersion: v1alpha1
kind: ImageVerificationConfig
rules:
  - subjectRegex: ^https://github\\.com/devantler-tech/actions/\\.github/workflows/publish-app\\.yaml@$ref\$
EOF
}

# write_set <path> [<omit-repo>] [<extra-row>] — the approved set for every registered consumer.
write_set() {
  local path="$1" omit="${2:-}" extra="${3:-}" repo workflow
  printf 'consumer\tworkflow\tapplied_tag\tapplied_digest\tapplied_signer_sha\tmain_pin_sha\tobserved_on\n' >"$path"
  while IFS=$'\t' read -r repo workflow; do
    [ -n "$repo" ] || continue
    [ "$repo" = "$omit" ] && continue
    printf '%s\t%s\t1.0.0\t%s\t%s\t%s\t2026-09-03\n' "$repo" "$workflow" "$DIGEST" "$(signer_for "$repo")" "$SHA_B" >>"$path"
  done <<<"$consumers"
  [ -z "$extra" ] || printf '%s\n' "$extra" >>"$path"
}

# build_tree <name> <ref-form-for-all-consumers|pair> — a complete fixture: every consumer on the
# pattern form (`pattern`) or on its own generated pair (`pair`), generics on the pattern form.
build_tree() {
  local name="$1" form="$2" root repo workflow ref
  root="$WORK/$name"
  rm -rf "$root"
  mkdir -p "$root/scripts"
  while IFS=$'\t' read -r repo workflow; do
    [ -n "$repo" ] || continue
    case "$form" in
      pattern) ref="$PATTERN" ;;
      pair) ref="($(signer_for "$repo")|$SHA_B)" ;;
      *) printf 'build_tree: unknown form %s\n' "$form" >&2; exit 1 ;;
    esac
    write_consumer "$root" "$repo" "$workflow" "$ref"
  done <<<"$consumers"
  write_generics "$root" "$PATTERN"
  write_set "$root/scripts/approved.tsv"
  printf '%s\n' "$root"
}

# run_guard <root> <enforce> — runs the guard against the fixture; prints combined output, returns its status.
run_guard() {
  local root="$1" enforce="$2"
  APPROVED_REVISIONS_FILE="$root/scripts/approved.tsv" PUBLISH_CONSUMER_ROOT="$root" \
    APPROVED_REVISIONS_ENFORCE="$enforce" bash "$GUARD" 2>&1
}

expect_pass() { # <case> <root> <enforce>
  local out
  if out="$(run_guard "$2" "$3")"; then
    pass "$1"
  else
    fail "$1 — expected exit 0, got a refusal:"; printf '%s\n' "$out" >&2
  fi
}
expect_refusal() { # <case> <root> <enforce> <must-mention>...
  local case_name="$1" root="$2" enforce="$3" out needle
  shift 3
  if out="$(run_guard "$root" "$enforce")"; then
    fail "$case_name — expected a refusal, guard exited 0:"; printf '%s\n' "$out" >&2
    return
  fi
  for needle in "$@"; do
    case "$out" in
      *"$needle"*) ;;
      *) fail "$case_name — refusal does not name '$needle':"; printf '%s\n' "$out" >&2; return ;;
    esac
  done
  pass "$case_name"
}

first_path() { printf 'k8s/bases/apps/%s/oci-repository.yaml\n' "$(package_for "$1")"; }

# ── switch OFF: pattern form accepted, set form accepted, anything else refused ─────────────
root="$(build_tree off-pattern pattern)"
expect_pass 'switch off: every consumer on the pattern form passes' "$root" 0

root="$(build_tree off-pair pair)"
expect_pass 'switch off: every consumer on its generated pair passes' "$root" 0

root="$(build_tree off-pair-reversed pair)"
write_consumer "$root" "$first_consumer" "$first_workflow" "($SHA_B|$(signer_for "$first_consumer"))"
expect_pass 'switch off: the pair in the other order is the same set and passes' "$root" 0

# AC4 of #3308: an out-of-set revision is refused whatever the switch says.
root="$(build_tree off-foreign pattern)"
write_consumer "$root" "$first_consumer" "$first_workflow" "($(signer_for "$first_consumer")|$SHA_D)"
expect_refusal 'switch off: an alternation carrying a revision outside the pair is refused by consumer and ref' \
  "$root" 0 "$first_consumer" "$SHA_D" 'not the generated pair'

root="$(build_tree off-single-foreign pattern)"
write_consumer "$root" "$first_consumer" "$first_workflow" "$SHA_D"
expect_refusal 'switch off: a single concrete revision outside the pair is refused' \
  "$root" 0 "$first_consumer" "$SHA_D"

root="$(build_tree off-half pattern)"
write_consumer "$root" "$first_consumer" "$first_workflow" "$(signer_for "$first_consumer")"
expect_refusal 'switch off: one revision where the pair needs two is refused' \
  "$root" 0 "$first_consumer" 'not the generated pair'

root="$(build_tree off-three pair)"
write_consumer "$root" "$first_consumer" "$first_workflow" "($(signer_for "$first_consumer")|$SHA_B|$SHA_D)"
expect_refusal 'switch off: a third alternative widens the set and is refused' \
  "$root" 0 "$first_consumer" "$SHA_D"

# Membership is PER CONSUMER: the second consumer's valid pair is not the first's.
root="$(build_tree off-crossed pair)"
write_consumer "$root" "$first_consumer" "$first_workflow" "($(signer_for "$second_consumer")|$SHA_B)"
expect_refusal "switch off: another consumer's pair on $first_consumer is refused" \
  "$root" 0 "$first_consumer" "$(signer_for "$second_consumer")"

root="$(build_tree off-tag pair)"
write_consumer "$root" "$first_consumer" "$first_workflow" 'refs/tags/v.+'
expect_refusal 'switch off: a tag ref is refused' "$root" 0 "$first_consumer" 'refs/tags/v.+'

# `matchOIDCIdentity` is an OR-list: a wildcard sibling beside a correct pair admits any signer.
root="$(build_tree off-wildcard-sibling pair)"
append_identity "$root" "$first_consumer" '.*'
expect_refusal 'a second matchOIDCIdentity entry beside the pair is refused (an OR-list widens the matcher)' \
  "$root" 0 "$(first_path "$first_consumer")" 'matchOIDCIdentity entries'
root="$(build_tree on-branch-sibling pair)"
append_identity "$root" "$first_consumer" '^https://github\.com/devantler-tech/platform/\.github/workflows/cd\.yaml@refs/heads/.+$'
expect_refusal 'switch on: a first-party branch identity beside the pair is refused' \
  "$root" 1 "$(first_path "$first_consumer")" 'matchOIDCIdentity entries'
root="$(build_tree off-two-shared pair)"
append_identity "$root" "$first_consumer" "^https://github\\.com/devantler-tech/actions/\\.github/workflows/$first_workflow\\.yaml@$SHA_D\$"
expect_refusal 'two shared-workflow subjects on one OCIRepository are refused' \
  "$root" 0 "$(first_path "$first_consumer")" 'found 2'

# A subject in a second document of the consumer's file is invisible to the OCIRepository read.
root="$(build_tree off-second-document pair)"
append_document "$root" "$first_consumer" "$SHA_D"
expect_refusal 'a shared-workflow subject in a second document of a consumer file is refused as unjudged' \
  "$root" 0 "$(first_path "$first_consumer")" 'unjudged'

# signer == pin: the steady state after a consumer re-releases on the revision it pins.
same_set() { # <root> — rewrite the first consumer's row with signer == pin == SHA_B
  local root="$1"
  { head -n1 "$root/scripts/approved.tsv"
    tail -n +2 "$root/scripts/approved.tsv" | awk -F'\t' -v c="$first_consumer" -v s="$SHA_B" 'BEGIN{OFS="\t"} $1 "" == c "" {$5=s} {print}'
  } >"$root/scripts/approved.tmp"
  mv "$root/scripts/approved.tmp" "$root/scripts/approved.tsv"
}
root="$(build_tree same-single pair)"; same_set "$root"
write_consumer "$root" "$first_consumer" "$first_workflow" "$SHA_B"
expect_pass 'signer == pin: the single concrete revision is the set and passes' "$root" 1
root="$(build_tree same-group pair)"; same_set "$root"
write_consumer "$root" "$first_consumer" "$first_workflow" "($SHA_B)"
expect_pass 'signer == pin: the single revision in a group passes' "$root" 1
root="$(build_tree same-doubled pair)"; same_set "$root"
write_consumer "$root" "$first_consumer" "$first_workflow" "($SHA_B|$SHA_B)"
expect_refusal 'signer == pin: a doubled alternation is not the canonical set and is refused' \
  "$root" 0 "$first_consumer" 'not the generated pair'
root="$(build_tree same-foreign pair)"; same_set "$root"
write_consumer "$root" "$first_consumer" "$first_workflow" "($SHA_B|$SHA_D)"
expect_refusal 'signer == pin: an alternation adding a foreign revision is refused' \
  "$root" 1 "$first_consumer" "$SHA_D"

# ── switch ON: the pattern form is refused for a per-consumer subject ────────────────────────
root="$(build_tree on-pair pair)"
expect_pass 'switch on: every consumer on its generated pair passes' "$root" 1

root="$(build_tree on-pattern pattern)"
expect_refusal 'switch on: the pattern form is refused and the fix names the pair' \
  "$root" 1 'pattern form' "($(signer_for "$first_consumer")|$SHA_B)"

root="$(build_tree on-one-left pair)"
write_consumer "$root" "$second_consumer" "$(printf '%s\n' "$consumers" | sed -n 2p | cut -f2)" "$PATTERN"
expect_refusal 'switch on: a single consumer left on the pattern form is refused by name' \
  "$root" 1 "$second_consumer" 'pattern form'

root="$(build_tree on-foreign pair)"
write_consumer "$root" "$first_consumer" "$first_workflow" "($(signer_for "$first_consumer")|$SHA_D)"
expect_refusal 'switch on: an out-of-set revision is refused just as it is with the switch off' \
  "$root" 1 "$first_consumer" "$SHA_D"

root="$(build_tree on-bad-switch pair)"
expect_refusal 'a switch value other than 0 or 1 is refused rather than read as off' \
  "$root" yes 'APPROVED_REVISIONS_ENFORCE'

# ── generic subjects: excluded by name, in both states ──────────────────────────────────────
root="$(build_tree generics-on pair)"
expect_pass 'switch on: the three generic subjects stay on the pattern form and are not judged' "$root" 1

root="$(build_tree generics-missing pattern)"
rm -f "$root/$GENERIC_TALOS"
expect_refusal 'a generic subject file missing from the tree is refused: the scope boundary moved' \
  "$root" 0 "$GENERIC_TALOS" 'missing from the scan root'

# The maintainer's checkout carries nested per-session worktrees under .claude/ — whole copies
# of the tree. Those must not be read as a second, unlisted set of generic subjects.
root="$(build_tree nested-worktree pattern)"
mkdir -p "$root/.claude/worktrees/session/$(dirname "$GENERIC_TALOS")" "$root/.git/objects"
cp "$root/$GENERIC_TALOS" "$root/.claude/worktrees/session/$GENERIC_TALOS"
cp "$root/$GENERIC_TALOS" "$root/.git/objects/stray.yaml"
expect_pass 'copies under .claude/ (nested worktrees) and .git/ are not scanned' "$root" 0

# A fourth kind of file naming the shared workflow that is neither a consumer nor listed.
root="$(build_tree unattributed pattern)"
mkdir -p "$root/k8s/extra"
cat >"$root/k8s/extra/policy.yaml" <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: extra
spec:
  rules:
    - verifyImages:
        - attestors:
            - entries:
                - keyless:
                    subjectRegExp: ^https://github\\.com/devantler-tech/actions/\\.github/workflows/publish-app\\.yaml@$PATTERN\$
EOF
expect_refusal 'an unlisted non-OCIRepository subject is refused rather than skipped' \
  "$root" 0 'k8s/extra/policy.yaml' 'GENERIC_SUBJECT_FILES'

# An OCIRepository for a consumer the approved set does not know.
root="$(build_tree unregistered pattern)"
write_consumer "$root" 'stranger' 'publish-app' "$PATTERN"
expect_refusal 'an OCIRepository for a consumer with no approved row is refused' \
  "$root" 0 'stranger' 'no row in the approved set'

# ── the approved set itself, read strictly ──────────────────────────────────────────────────
root="$(build_tree set-missing pattern)"
rm -f "$root/scripts/approved.tsv"
expect_refusal 'a missing approved set is refused' "$root" 0 'approved set not found'

root="$(build_tree set-no-row pattern)"
write_set "$root/scripts/approved.tsv" "$first_consumer"
expect_refusal 'an approved set missing a registered consumer is refused by name' \
  "$root" 0 "$first_consumer" 'no row'

root="$(build_tree set-extra pattern)"
write_set "$root/scripts/approved.tsv" '' "$(printf 'stranger\tpublish-app\t1.0.0\t%s\t%s\t%s\t2026-09-03' "$DIGEST" "$SHA_A" "$SHA_B")"
expect_refusal 'an approved set naming an unregistered consumer is refused' \
  "$root" 0 'stranger' 'not a registered consumer'

root="$(build_tree set-bad-sha pattern)"
write_set "$root/scripts/approved.tsv" "$first_consumer" "$(printf '%s\t%s\t1.0.0\t%s\tdeadbeef\t%s\t2026-09-03' "$first_consumer" "$first_workflow" "$DIGEST" "$SHA_B")"
expect_refusal 'an approved set with a malformed signer sha is refused' \
  "$root" 0 "$first_consumer" 'not a 40-hex commit'

root="$(build_tree set-bad-pin pattern)"
write_set "$root/scripts/approved.tsv" "$first_consumer" "$(printf '%s\t%s\t1.0.0\t%s\t%s\tdeadbeef\t2026-09-03' "$first_consumer" "$first_workflow" "$DIGEST" "$SHA_A")"
expect_refusal 'an approved set with a malformed main_pin_sha is refused' \
  "$root" 0 "$first_consumer" 'main_pin_sha'

root="$(build_tree set-duplicate pattern)"
write_set "$root/scripts/approved.tsv" '' "$(printf '%s\t%s\t1.0.0\t%s\t%s\t%s\t2026-09-03' "$first_consumer" "$first_workflow" "$DIGEST" "$SHA_A" "$SHA_B")"
expect_refusal 'an approved set naming a consumer twice is refused' \
  "$root" 0 "$first_consumer" 'twice'

root="$(build_tree set-extra-field pattern)"
write_set "$root/scripts/approved.tsv" "$first_consumer" "$(printf '%s\t%s\t1.0.0\t%s\t%s\t%s\t2026-09-03\textra' "$first_consumer" "$first_workflow" "$DIGEST" "$SHA_A" "$SHA_B")"
expect_refusal 'an approved set row with an eighth field is refused' \
  "$root" 0 'more than seven fields'

root="$(build_tree set-bad-header pattern)"
{ printf 'consumer\tworkflow\n'; tail -n +2 "$root/scripts/approved.tsv"; } >"$root/scripts/approved.tmp"
mv "$root/scripts/approved.tmp" "$root/scripts/approved.tsv"
expect_refusal "an approved set whose header is not the generator's is refused" "$root" 0 'header'

root="$(build_tree set-workflow-mismatch pair)"
other_workflow='publish-manifests'; [ "$first_workflow" = 'publish-manifests' ] && other_workflow='publish-app'
write_consumer "$root" "$first_consumer" "$other_workflow" "($(signer_for "$first_consumer")|$SHA_B)"
expect_refusal 'a consumer whose manifest names a different workflow than its row is refused' \
  "$root" 0 "$first_consumer" "$other_workflow"

# A consumer manifest that vanished: the registered list says it must exist.
root="$(build_tree consumer-missing pattern)"
rm -f "$root/$(first_path "$first_consumer")"
expect_refusal 'a registered consumer with no OCIRepository in the tree is refused' \
  "$root" 0 "$first_consumer" 'no OCIRepository under'

# ── wiring: CI reaches the guard and this test ──────────────────────────────────────────────
ci="$REPO_ROOT/.github/workflows/ci.yaml"
grep -Fq 'scripts/guard-publish-workflow-approved-revisions.sh' "$ci" ||
  fail 'ci.yaml does not run guard-publish-workflow-approved-revisions.sh'
grep -Fq 'scripts/tests/test-publish-workflow-approved-revisions-guard.sh' "$ci" ||
  fail 'ci.yaml does not run test-publish-workflow-approved-revisions-guard.sh'
# CI must apply enforcement to the step that executes the guard, not an unrelated job.
enforce="$(yq -r '.jobs[].steps[] | select(.run // "" | contains("./scripts/guard-publish-workflow-approved-revisions.sh")) | .env.APPROVED_REVISIONS_ENFORCE' "$ci")"
if [ -z "$enforce" ] || printf '%s\n' "$enforce" | grep -qv '^1$'; then
  fail 'ci.yaml must enforce the approved set in every guard step'
fi
[ "$failures" -eq 0 ] && pass 'wiring: ci.yaml enforces the approved set'

# ── the real tree: every committed consumer uses exactly its approved pair ────────────────
if out="$(APPROVED_REVISIONS_ENFORCE=1 bash "$GUARD" 2>&1)"; then
  pass 'real tree: every per-consumer matcher uses its approved pair (enforced)'
else
  fail 'real tree: guard refuses the committed state:'; printf '%s\n' "$out" >&2
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d failure(s)\n' "$failures" >&2
  exit 1
fi
printf '\nall approved-revisions guard cases passed\n'
