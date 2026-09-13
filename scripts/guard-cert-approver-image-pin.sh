#!/usr/bin/env bash
#
# Fail when the kubelet-serving-cert-approver image is not pinned, in the Kustomization that deploys
# it, to the exact tag AND digest the vendor updater records (#3515).
#
# WHY THE PIN LIVES IN THE KUSTOMIZATION. The vendored `deployment.yaml` must stay the upstream bytes:
# CI binds its SHA-256 and its `image:` tag to the updater's constants, and Renovate ignores the file.
# Upstream v0.11.1 showed those bytes can name a MOVING tag (`:main`) with `imagePullPolicy: Always`,
# so vendoring alone cannot keep production on reviewed code. A Kustomize `images:` override adds the
# digest without touching the vendored bytes, and the kubelet then pulls exactly that digest whatever
# the tag points at.
#
# WHY THE TAG IS CHECKED TOO. Kustomize renders `name:<newTag>@<digest>`, and the kubelet ignores the
# tag once a digest is present. A refresh that bumps the tag but forgets the digest would render the
# NEW version while production keeps running the OLD image — a silent skew. Requiring the tag to equal
# the updater's version forces every bump through this pin.
#
# Exit codes:
#   0  exactly one entry, pinned to the expected tag and digest
#   1  the pin is missing, duplicated, renamed, or names a different tag or digest
#   2  cannot check: bad usage, missing file, missing yq, unparseable YAML, or malformed expected values

set -uo pipefail

readonly image='ghcr.io/alex1989hu/kubelet-serving-cert-approver'

die() {
  printf 'guard-cert-approver-image-pin: %s\n' "$*" >&2
  exit 2
}

defect() {
  printf 'guard-cert-approver-image-pin: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 3 ] || die "usage: $0 <kustomization.yaml> <expected-version> <expected-digest>"
file="$1"
version="$2"
digest="$3"
[ -f "$file" ] || die "kustomization '$file' does not exist"
command -v yq >/dev/null 2>&1 || die "yq is required but not installed"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "expected version '$version' is not X.Y.Z"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "expected digest '$digest' is not sha256:<64 lowercase hex>"

# Every read checks its own exit status: a parse failure must be exit 2, never an empty selection
# that reads as "no pin" (exit 1) or, worse, as a match.
select_expr='(.images // [])[] | select(.name == strenv(IMAGE))'

if ! count="$(IMAGE="$image" yq "[${select_expr}] | length" "$file" 2>&1)"; then
  die "cannot parse '$file': $count"
fi
[[ "$count" =~ ^[0-9]+$ ]] || die "unexpected entry count '$count' from '$file'"
[ "$count" -eq 1 ] || defect "expected exactly one images: entry for $image in $file, found $count"

field() { # <yq-path>
  IMAGE="$image" yq "${select_expr} | $1 // \"\"" "$file" 2>&1
}

new_name="$(field .newName)" || die "cannot read newName from '$file': $new_name"
new_tag="$(field .newTag)" || die "cannot read newTag from '$file': $new_tag"
entry_digest="$(field .digest)" || die "cannot read digest from '$file': $entry_digest"

[ -z "$new_name" ] || defect "the entry sets newName '$new_name', which replaces the image this digest was reviewed for"
[ "$new_tag" = "$version" ] || defect "the entry's newTag is '${new_tag:-<unset>}', but the updater's version is '$version'"
[ "$entry_digest" = "$digest" ] || defect "the entry's digest is '${entry_digest:-<unset>}', but the updater records '$digest'"

printf 'guard-cert-approver-image-pin: %s pinned to %s@%s\n' "$image" "$version" "$digest"
