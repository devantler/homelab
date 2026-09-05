#!/usr/bin/env bash
# Exercise matcher regeneration against real YAML and the enforcing guard, without APIs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WRITER="$ROOT/scripts/write-publish-workflow-matchers.sh"
GUARD="$ROOT/scripts/guard-publish-workflow-approved-revisions.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TREE="$WORK/consumer tree"
SET="$TREE/scripts/approved.tsv"
A=1111111111111111111111111111111111111111
B=2222222222222222222222222222222222222222
C=3333333333333333333333333333333333333333
D=4444444444444444444444444444444444444444
GENERIC_FILES=(
  k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml
  k8s/bases/infrastructure/resource-graph-definitions/tenant/resource-graph-definition.yaml
  talos/cluster/verify-first-party-images.yaml
)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

fixture() {
  rm -rf "$TREE"
  mkdir -p "$TREE/scripts"
  printf 'consumer\tworkflow\tapplied_tag\tapplied_digest\tapplied_signer_sha\tmain_pin_sha\tobserved_on\n' >"$SET"
  local repo workflow package signer pin file
  while read -r repo workflow package signer pin; do
    file="$TREE/k8s/bases/apps/$package/oci-repository.yaml"
    mkdir -p "$(dirname "$file")"
    cat >"$file" <<EOF
# Preserve this consumer comment.
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: $package
spec:
  url: oci://ghcr.io/devantler-tech/$package/manifests
  interval: 5m
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\.actions\.githubusercontent\.com\$'
        subject: '^https://github\.com/devantler-tech/actions/\.github/workflows/$workflow\.yaml@[0-9a-f]{40}\$'
EOF
    printf '%s\t%s\t1.0.0\tsha256:%064d\t%s\t%s\t2026-09-05\n' \
      "$repo" "$workflow" 0 "$signer" "$pin" >>"$SET"
  done <<EOF
.github publish-manifests github-config $A $B
ascoachingogvaner publish-app ascoachingogvaner $C $B
aws publish-manifests aws $A $A
wedding-app publish-app wedding-app $A $B
EOF
  for file in "${GENERIC_FILES[@]}"; do
    mkdir -p "$TREE/$(dirname "$file")"
    cp "$ROOT/$file" "$TREE/$file"
  done
}

write_matchers() {
  APPROVED_REVISIONS_FILE="$SET" PUBLISH_CONSUMER_ROOT="$TREE" bash "$WRITER"
}
guard() {
  APPROVED_REVISIONS_FILE="$SET" PUBLISH_CONSUMER_ROOT="$TREE" \
    APPROVED_REVISIONS_ENFORCE=1 bash "$GUARD"
}
snapshot() {
  (cd "$TREE" && find k8s talos -type f -exec shasum -a 256 {} \; | sort)
}
expect_atomic_refusal() {
  local label="$1" needle="$2" before out
  before="$(snapshot)"
  if out="$(write_matchers 2>&1)"; then fail "$label: writer accepted an invalid input"; fi
  case "$out" in *"$needle"*) ;; *) fail "$label: wrong refusal: $out" ;; esac
  [ "$(snapshot)" = "$before" ] || fail "$label: a refused update changed a manifest"
  printf 'ok: %s refuses without changing any manifest\n' "$label"
}

fixture
if guard >"$WORK/guard.log" 2>&1; then fail 'pattern-form fixture unexpectedly passes enforcement'; fi
grep -Fq 'pattern form' "$WORK/guard.log" || fail 'baseline refusal was not caused by the broad matcher'
write_matchers >"$WORK/writer.log" 2>&1 || { cat "$WORK/writer.log" >&2; fail 'writer must narrow every registered consumer'; }
guard >"$WORK/guard.log" 2>&1 || { cat "$WORK/guard.log" >&2; fail 'rewritten tree does not pass enforcement'; }
[ "$(yq -r '.spec.verify.matchOIDCIdentity[0].subject' "$TREE/k8s/bases/apps/github-config/oci-repository.yaml")" = \
  '^https://github\.com/devantler-tech/actions/\.github/workflows/publish-manifests\.yaml@(1111111111111111111111111111111111111111|2222222222222222222222222222222222222222)$' ] || fail 'github-config did not receive its own exact pair'
[ "$(yq -r '.spec.verify.matchOIDCIdentity[0].subject' "$TREE/k8s/bases/apps/ascoachingogvaner/oci-repository.yaml")" = \
  '^https://github\.com/devantler-tech/actions/\.github/workflows/publish-app\.yaml@(3333333333333333333333333333333333333333|2222222222222222222222222222222222222222)$' ] || fail 'consumer pairs crossed'
[ "$(yq -r '.spec.verify.matchOIDCIdentity[0].subject' "$TREE/k8s/bases/apps/aws/oci-repository.yaml")" = \
  '^https://github\.com/devantler-tech/actions/\.github/workflows/publish-manifests\.yaml@1111111111111111111111111111111111111111$' ] || fail 'equal revisions were not deduplicated'
[ "$(yq -r '.spec.interval' "$TREE/k8s/bases/apps/aws/oci-repository.yaml")" = 5m ] || fail 'unrelated YAML changed'
grep -Fq '# Preserve this consumer comment.' "$TREE/k8s/bases/apps/aws/oci-repository.yaml" || fail 'consumer comment was lost'
for file in "${GENERIC_FILES[@]}"; do cmp -s "$ROOT/$file" "$TREE/$file" || fail "generic subject $file changed"; done
printf 'ok: exact consumer pairs, deduplication, unrelated fields and generic subjects\n'

before="$(snapshot)"
write_matchers >"$WORK/writer.log" 2>&1
[ "$(snapshot)" = "$before" ] || fail 'unchanged input was not byte-idempotent'
printf 'ok: unchanged input is a byte-identical no-op\n'

# The real operational trigger: generator advances a pin, then writer converges before guard.
awk -F '\t' -v OFS='\t' -v pin="$D" 'NR > 1 {$6=pin} {print}' "$SET" >"$WORK/moved.tsv"
mv "$WORK/moved.tsv" "$SET"
if guard >"$WORK/guard.log" 2>&1; then fail 'old matcher unexpectedly accepts a moved set'; fi
grep -Fq 'not the generated pair' "$WORK/guard.log" || fail 'moved-set refusal had the wrong cause'
write_matchers >"$WORK/writer.log" 2>&1
guard >"$WORK/guard.log" 2>&1 || fail 'pin bump did not converge to a guard-clean tree'
printf 'ok: a pin bump rewrites already narrowed matchers before enforcement\n'

fixture
sed '$d' "$SET" >"$WORK/incomplete.tsv"
mv "$WORK/incomplete.tsv" "$SET"
expect_atomic_refusal 'missing consumer' 'wedding-app'

fixture
yq -i '.spec.verify.matchOIDCIdentity += [{"issuer": ".*", "subject": ".*"}]' "$TREE/k8s/bases/apps/wedding-app/oci-repository.yaml"
expect_atomic_refusal 'additional identity' 'matchOIDCIdentity'

fixture
printf 'broken\n' >>"$SET"
expect_atomic_refusal 'malformed final row' 'fields'

fixture
cp "$TREE/k8s/bases/apps/wedding-app/oci-repository.yaml" "$TREE/k8s/bases/apps/duplicate.yaml"
expect_atomic_refusal 'duplicate consumer manifest' 'both'

fixture
SUBJECT='^https://github\.com/devantler-tech/actions/\.github/workflows/publish-app\.yaml@main$' \
  yq -i '.spec.verify.matchOIDCIdentity[0].subject = strenv(SUBJECT)' "$TREE/k8s/bases/apps/wedding-app/oci-repository.yaml"
expect_atomic_refusal 'unrecognised existing revision' 'revision'

fixture
cat >>"$TREE/k8s/bases/apps/wedding-app/oci-repository.yaml" <<'EOF'
---
# This document is outside the matcher's ownership.
apiVersion: v1
kind: ConfigMap
metadata:
  name: sibling
data:
  subject: untouched
EOF
write_matchers >"$WORK/writer.log" 2>&1
[ "$(yq -r 'select(.kind == "ConfigMap") | .data.subject' "$TREE/k8s/bases/apps/wedding-app/oci-repository.yaml")" = untouched ] ||
  fail 'rewriting the OCIRepository changed an unrelated YAML document'
guard >"$WORK/guard.log" 2>&1 || fail 'multi-document rewrite did not pass enforcement'
printf 'ok: unrelated YAML documents retain their content\n'

printf 'all matcher writer cases passed\n'
