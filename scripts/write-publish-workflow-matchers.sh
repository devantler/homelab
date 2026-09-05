#!/usr/bin/env bash
# Derive per-consumer cosign subjects from the generated approved revision set.
# Validate every input and staged result before replacing any consumer manifest.
# Generic multi-consumer subjects remain unchanged. Unchanged output preserves bytes.
set -euo pipefail

WRITER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/publish-workflow-approved-revisions.lib.sh
source "$WRITER_DIR/publish-workflow-approved-revisions.lib.sh"

readonly FIXED_REF_RE='^([0-9a-f]{40}|\([0-9a-f]{40}\)|\([0-9a-f]{40}\|[0-9a-f]{40}\))$'
STAGED="$(mktemp -d "${TMPDIR:-/tmp}/write-publish-workflow-matchers.XXXXXX")"
trap 'rm -rf "$STAGED"' EXIT

# Include the generic files so the ordinary guard validates the complete scope.
# The shared discovery has already rejected every unattributed source-tree subject.
for generic in "${GENERIC_SUBJECT_FILES[@]}"; do
  mkdir -p "$STAGED/$(dirname "$generic")"
  cp "$SCAN_ROOT/$generic" "$STAGED/$generic"
done

for consumer in "${EXPECTED_CONSUMERS[@]}"; do
  record="$(lookup "$observed" "$consumer")"
  [ -n "$record" ] || refuse "no OCIRepository is attributed to registered consumer $consumer"
  IFS=$'\t' read -r file workflow ref <<<"$record"
  IFS=$'\t' read -r set_workflow signer pin <<<"$(lookup "$approved" "$consumer")"
  [ "$workflow" = "$set_workflow" ] || refuse "$consumer: $file names $workflow but the approved set names $set_workflow"
  [ "$ref" = "$PATTERN_REF" ] || [[ "$ref" =~ $FIXED_REF_RE ]] ||
    refuse "$consumer: unrecognised existing revision '$ref'; review the source identity before rewriting"
  if [ -L "$SCAN_ROOT/$file" ] || [ ! -f "$SCAN_ROOT/$file" ] || [ ! -w "$SCAN_ROOT/$file" ]; then
    refuse "$consumer: source manifest must be a writable regular file, not a symlink"
  fi

  pair="$signer"
  [ "$signer" = "$pin" ] || pair="($signer|$pin)"
  subject="${SUBJECT_PREFIX}${workflow#publish-}"'\.yaml@'"$pair"'$'
  mkdir -p "$STAGED/$(dirname "$file")"
  # Select the actual OCIRepository document; unrelated documents remain unchanged.
  # shellcheck disable=SC2016
  MATCHER_SUBJECT="$subject" yq eval \
    '(. | select(.kind == "OCIRepository") | .spec.verify.matchOIDCIdentity[0].subject) = strenv(MATCHER_SUBJECT)' \
    "$SCAN_ROOT/$file" >"$STAGED/$file"
done

APPROVED_REVISIONS_FILE="$APPROVED_SET" PUBLISH_CONSUMER_ROOT="$STAGED" \
  APPROVED_REVISIONS_ENFORCE=1 bash "$WRITER_DIR/guard-publish-workflow-approved-revisions.sh"

changed=0
for consumer in "${EXPECTED_CONSUMERS[@]}"; do
  IFS=$'\t' read -r file _workflow _ref <<<"$(lookup "$observed" "$consumer")"
  if ! cmp -s "$STAGED/$file" "$SCAN_ROOT/$file"; then
    cat "$STAGED/$file" >"$SCAN_ROOT/$file"
    changed=$((changed + 1))
    printf 'updated %s\n' "$file"
  fi
done
printf 'write-publish-workflow-matchers: %d consumer matcher(s) changed\n' "$changed"
