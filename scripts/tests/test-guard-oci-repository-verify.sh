#!/usr/bin/env bash
# RED/GREEN coverage for scripts/guard-oci-repository-verify.sh (#3558).
#
# WHAT IS ACTUALLY BEING PROVED
# The guard's one harmful failure mode is passing: an OCIRepository with no
# `spec.verify` still reconciles, so no schema, kubeconform pass or deploy notices.
# Every RED case below isolates ONE conjunct and asserts the guard refuses it BY
# NAME — the OCIRepository and the specific defect appear in the message — rather
# than merely exiting non-zero for some other reason (a floor miss, a stale
# exemption, an unrenderable root). Each case is a kustomize ROOT, because the guard
# judges `kubectl kustomize` output: that is what closes the bypasses a source scan
# had — a `!!binary` tag or alias on `kind`, a `.json` or extension-less resource, a
# symlink, and a patch that strips or widens `verify` — and every one of those has a
# case here that asserts the render is what gets judged.
#
# THE SEAMS: OCI_VERIFY_ROOTS lists the fixture roots, OCI_VERIFY_EXEMPTIONS_FILE
# replaces the built-in exemption list, and OCI_VERIFY_EXPECTED_MIN lowers the floor
# so a one-root fixture is judged on its own defect.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly GUARD="$REPO_ROOT/scripts/guard-oci-repository-verify.sh"

failures=0
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}
pass() { printf 'ok: %s\n' "$*"; }

[ -x "$GUARD" ] || { fail "guard not executable at $GUARD"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
: >"$WORK/no-exemptions.tsv"

readonly ISSUER="'^https://token\\.actions\\.githubusercontent\\.com\$'"
readonly SUBJECT="'^https://github\\.com/devantler-tech/actions/\\.github/workflows/publish-app\\.yaml@[0-9a-f]{40}\$'"

good_verify() {
  printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: %s\n        subject: %s' "$ISSUER" "$SUBJECT"
}

# repo_doc <name> <url> <verify-block-or-empty> — one OCIRepository document on stdout.
repo_doc() {
  printf 'apiVersion: source.toolkit.fluxcd.io/v1\nkind: OCIRepository\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  interval: 10m\n  url: %s\n  ref:\n    semver: ">=1.0.0"\n' "$1" "$1" "$2"
  [ -z "$3" ] || printf '%s\n' "$3"
}

# add_resource <root> <file> — appends a resource entry to the root's kustomization.
add_resource() {
  printf '  - %s\n' "$2" >>"$1/kustomization.yaml"
}

# fresh_root <case> — a kustomize root holding one GOOD in-scope OCIRepository, so every
# case starts from a root the guard accepts and varies exactly one thing.
fresh_root() {
  local root="$WORK/root-$1"
  rm -rf "$root"
  mkdir -p "$root"
  printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n' >"$root/kustomization.yaml"
  repo_doc good 'oci://ghcr.io/devantler-tech/good/manifests' "$(good_verify)" >"$root/good.yaml"
  add_resource "$root" good.yaml
  printf '%s' "$root"
}

out=""
# run_guard <root> [exemptions-file]
run_guard() {
  local root="$1" exemptions="${2:-$WORK/no-exemptions.tsv}"
  if out="$(OCI_VERIFY_ROOTS="$root" OCI_VERIFY_EXEMPTIONS_FILE="$exemptions" OCI_VERIFY_EXPECTED_MIN=1 "$GUARD" 2>&1)"; then
    return 0
  fi
  return 1
}

# expect_refused <case> <root> <must-name> [exemptions-file]
# The needle is matched with `case`, never a `printf | grep -q` pipe: under pipefail a
# multi-line refusal makes grep exit early and printf take SIGPIPE, which reports a
# correct refusal as the wrong reason.
expect_refused() {
  local name="$1" root="$2" needle="$3" exemptions="${4:-}"
  if run_guard "$root" ${exemptions:+"$exemptions"}; then
    fail "$name: expected the guard to REFUSE, it passed: $out"
    return
  fi
  case "$out" in
    *"$needle"*) pass "$name" ;;
    *) fail "$name: refused, but not for the right reason (wanted '$needle'): $out" ;;
  esac
}

expect_accepted() {
  local name="$1" root="$2" exemptions="${3:-}"
  if run_guard "$root" ${exemptions:+"$exemptions"}; then
    pass "$name"
  else
    fail "$name: expected the guard to ACCEPT, it refused: $out"
  fi
}

# Confirms the fixture really renders an in-scope OCIRepository at the attack URL —
# otherwise a "refused" could be a broken fixture rather than a caught bypass.
assert_renders() {
  local root="$1" url="$2" render
  # Capture the whole render first: under pipefail a `grep -q` that closes the
  # pipe early would hand kubectl a SIGPIPE and reject a perfectly valid render.
  render="$(kubectl kustomize "$root" 2>/dev/null)" || render=""
  case "$render" in
    *"url: $url"*) return 0 ;;
  esac
  fail "fixture $root does not render an OCIRepository at $url — the case would be vacuous"
  return 1
}

# --- GREEN: the baseline root is accepted, so every RED below is attributable ---
root="$(fresh_root green)"
expect_accepted 'a verified in-scope OCIRepository with one identity is accepted' "$root"

# --- GREEN: trusted tenants may follow the platform-owned release boundary ---
root="$(fresh_root trusted-stream)"
repo_doc wedding-app 'oci://ghcr.io/devantler-tech/wedding-app/manifests' "$(good_verify)" >"$root/wedding.yaml"; add_resource "$root" wedding.yaml
expect_accepted 'a trusted tenant using the governed semver stream is accepted' "$root"

# --- RED: trusted tenant mobility must not silently regress to platform pins ---
root="$(fresh_root trusted-stream-tag)"
repo_doc wedding-app 'oci://ghcr.io/devantler-tech/wedding-app/manifests' "$(good_verify)" >"$root/wedding.yaml"; add_resource "$root" wedding.yaml
yq -i '.spec.ref = {"tag": "v1.15.11"}' "$root/wedding.yaml"
expect_refused 'a trusted tenant fixed tag is refused by name' "$root" 'OCIRepository wedding-app (oci://ghcr.io/devantler-tech/wedding-app/manifests) must follow the governed release stream with exactly spec.ref.semver: >=1.0.0'

root="$(fresh_root trusted-stream-digest)"
repo_doc ascoachingogvaner 'oci://ghcr.io/devantler-tech/ascoachingogvaner/manifests' "$(good_verify)" >"$root/ascoachingogvaner.yaml"; add_resource "$root" ascoachingogvaner.yaml
yq -i '.spec.ref = {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' "$root/ascoachingogvaner.yaml"
expect_refused 'a trusted tenant digest pin is refused by name' "$root" 'OCIRepository ascoachingogvaner (oci://ghcr.io/devantler-tech/ascoachingogvaner/manifests) must follow the governed release stream with exactly spec.ref.semver: >=1.0.0'

root="$(fresh_root templated-trusted-stream-tag)"
# shellcheck disable=SC2016 # KRO placeholder is intentionally literal.
repo_doc '${schema.spec.name}' 'oci://ghcr.io/devantler-tech/${schema.spec.name}/manifests' "$(good_verify)" >"$root/tenant-template.yaml"; add_resource "$root" tenant-template.yaml
yq -i '.spec.ref = {"tag": "v1.0.0"}' "$root/tenant-template.yaml"
# shellcheck disable=SC2016 # Expected diagnostic preserves the KRO placeholder.
expect_refused 'a templated trusted tenant fixed tag is refused by name' "$root" 'OCIRepository ${schema.spec.name} (oci://ghcr.io/devantler-tech/${schema.spec.name}/manifests) must follow the governed release stream with exactly spec.ref.semver: >=1.0.0'

# --- RED: no spec.verify at all (AC1) ---
root="$(fresh_root noverify)"
repo_doc bare 'oci://ghcr.io/devantler-tech/bare/manifests' '' >"$root/bare.yaml"; add_resource "$root" bare.yaml
expect_refused 'no spec.verify is refused by name' "$root" 'OCIRepository bare (oci://ghcr.io/devantler-tech/bare/manifests) has NO spec.verify'

# --- RED: verify with zero identity entries (AC2) ---
root="$(fresh_root zero)"
repo_doc zero 'oci://ghcr.io/devantler-tech/zero/manifests' "$(printf '  verify:\n    provider: cosign\n    matchOIDCIdentity: []')" >"$root/zero.yaml"; add_resource "$root" zero.yaml
expect_refused 'zero matchOIDCIdentity entries is refused' "$root" 'OCIRepository zero (oci://ghcr.io/devantler-tech/zero/manifests) has ZERO matchOIDCIdentity entries'

# --- RED: verify with no matchOIDCIdentity key at all ---
root="$(fresh_root nokey)"
repo_doc nokey 'oci://ghcr.io/devantler-tech/nokey/manifests' "$(printf '  verify:\n    provider: cosign')" >"$root/nokey.yaml"; add_resource "$root" nokey.yaml
expect_refused 'a verify block without matchOIDCIdentity is refused' "$root" 'OCIRepository nokey (oci://ghcr.io/devantler-tech/nokey/manifests) has no matchOIDCIdentity sequence'

# --- RED: two identity entries (Flux ORs them) ---
root="$(fresh_root two)"
repo_doc two 'oci://ghcr.io/devantler-tech/two/manifests' "$(good_verify; printf '\n      - issuer: %s\n        subject: %s' "'.*'" "'.*'")" >"$root/two.yaml"; add_resource "$root" two.yaml
expect_refused 'a second identity entry is refused as a widening' "$root" 'OCIRepository two (oci://ghcr.io/devantler-tech/two/manifests) has 2 matchOIDCIdentity entries'

# --- RED: a provider other than cosign ---
root="$(fresh_root notation)"
repo_doc notation 'oci://ghcr.io/devantler-tech/notation/manifests' "$(printf '  verify:\n    provider: notation\n    matchOIDCIdentity:\n      - issuer: %s\n        subject: %s' "$ISSUER" "$SUBJECT")" >"$root/notation.yaml"; add_resource "$root" notation.yaml
expect_refused 'a non-cosign provider is refused' "$root" "OCIRepository notation (oci://ghcr.io/devantler-tech/notation/manifests) verifies with provider 'notation'"

# --- RED: an entry with an empty subject ---
root="$(fresh_root nosubject)"
repo_doc nosubject 'oci://ghcr.io/devantler-tech/nosubject/manifests' "$(printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: %s' "$ISSUER")" >"$root/nosubject.yaml"; add_resource "$root" nosubject.yaml
expect_refused 'an identity entry without a subject is refused' "$root" 'OCIRepository nosubject (oci://ghcr.io/devantler-tech/nosubject/manifests) has a matchOIDCIdentity entry missing a non-empty issuer or subject'

# --- RED: discovery at depth — an unverified OCIRepository nested as a template ---
root="$(fresh_root nested)"
cat >"$root/rgd.yaml" <<'EOF'
apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: tenant
spec:
  resources:
    - id: ociRepository
      template:
        apiVersion: source.toolkit.fluxcd.io/v1
        kind: OCIRepository
        metadata:
          name: ${schema.spec.name}
        spec:
          url: oci://ghcr.io/devantler-tech/${schema.spec.name}/manifests
          ref:
            semver: ">=1.0.0"
EOF
add_resource "$root" rgd.yaml
# The `${schema.spec.name}` below is the kro template placeholder, quoted verbatim.
# shellcheck disable=SC2016
expect_refused 'an unverified OCIRepository nested inside a template is discovered' "$root" 'OCIRepository ${schema.spec.name} (oci://ghcr.io/devantler-tech/${schema.spec.name}/manifests) has NO spec.verify'

# --- RED: discovery across documents — the second document of a multi-doc file ---
root="$(fresh_root multidoc)"
{ printf -- 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: second\n---\n'; repo_doc second 'oci://ghcr.io/devantler-tech/second/manifests' ''; } >"$root/second.yaml"; add_resource "$root" second.yaml
expect_refused 'an unverified OCIRepository in a later YAML document is discovered' "$root" 'OCIRepository second (oci://ghcr.io/devantler-tech/second/manifests) has NO spec.verify'

# --- RED: the render is judged, not the source — bypasses a source scan had ---
root="$(fresh_root binarytag)"
repo_doc bin 'oci://ghcr.io/devantler-tech/bin/manifests' '' | sed 's/^kind: OCIRepository$/kind: !!binary T0NJUmVwb3NpdG9yeQ==/' >"$root/bin.yaml"; add_resource "$root" bin.yaml
assert_renders "$root" 'oci://ghcr.io/devantler-tech/bin/manifests' &&
  expect_refused 'a !!binary-tagged kind is resolved by the render and refused' "$root" 'OCIRepository bin (oci://ghcr.io/devantler-tech/bin/manifests) has NO spec.verify'

root="$(fresh_root alias)"
{ printf 'apiVersion: source.toolkit.fluxcd.io/v1\nmetadata:\n  name: al\n  namespace: al\n  annotations:\n    note: &k OCIRepository\nkind: *k\nspec:\n  interval: 10m\n  url: oci://ghcr.io/devantler-tech/al/manifests\n  ref:\n    semver: ">=1.0.0"\n'; } >"$root/al.yaml"; add_resource "$root" al.yaml
assert_renders "$root" 'oci://ghcr.io/devantler-tech/al/manifests' &&
  expect_refused 'an aliased kind is resolved by the render and refused' "$root" 'OCIRepository al (oci://ghcr.io/devantler-tech/al/manifests) has NO spec.verify'

root="$(fresh_root json)"
printf '{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"OCIRepository","metadata":{"name":"js","namespace":"js"},"spec":{"interval":"10m","url":"oci://ghcr.io/devantler-tech/js/manifests","ref":{"semver":">=1.0.0"}}}\n' >"$root/js.json"; add_resource "$root" js.json
assert_renders "$root" 'oci://ghcr.io/devantler-tech/js/manifests' &&
  expect_refused 'a .json resource is rendered and refused' "$root" 'OCIRepository js (oci://ghcr.io/devantler-tech/js/manifests) has NO spec.verify'

root="$(fresh_root noext)"
repo_doc noext 'oci://ghcr.io/devantler-tech/noext/manifests' '' >"$root/ocirepo"; add_resource "$root" ocirepo
assert_renders "$root" 'oci://ghcr.io/devantler-tech/noext/manifests' &&
  expect_refused 'an extension-less resource is rendered and refused' "$root" 'OCIRepository noext (oci://ghcr.io/devantler-tech/noext/manifests) has NO spec.verify'

root="$(fresh_root symlink)"
repo_doc sym 'oci://ghcr.io/devantler-tech/sym/manifests' '' >"$root/real.txt"; ln -s real.txt "$root/sym.yaml"; add_resource "$root" sym.yaml
assert_renders "$root" 'oci://ghcr.io/devantler-tech/sym/manifests' &&
  expect_refused 'a symlinked resource is rendered and refused' "$root" 'OCIRepository sym (oci://ghcr.io/devantler-tech/sym/manifests) has NO spec.verify'

root="$(fresh_root patchremove)"
repo_doc pr 'oci://ghcr.io/devantler-tech/pr/manifests' "$(good_verify)" >"$root/pr.yaml"; add_resource "$root" pr.yaml
printf 'patches:\n  - target:\n      kind: OCIRepository\n      name: pr\n    patch: |\n      - op: remove\n        path: /spec/verify\n' >>"$root/kustomization.yaml"
expect_refused 'a patch that removes spec.verify is judged on the render' "$root" 'OCIRepository pr (oci://ghcr.io/devantler-tech/pr/manifests) has NO spec.verify'

root="$(fresh_root patchappend)"
repo_doc pa 'oci://ghcr.io/devantler-tech/pa/manifests' "$(good_verify)" >"$root/pa.yaml"; add_resource "$root" pa.yaml
printf 'patches:\n  - target:\n      kind: OCIRepository\n      name: pa\n    patch: |\n      - op: add\n        path: /spec/verify/matchOIDCIdentity/-\n        value:\n          issuer: ".*"\n          subject: ".*"\n' >>"$root/kustomization.yaml"
expect_refused 'a patch that appends an identity is judged on the render' "$root" 'OCIRepository pa (oci://ghcr.io/devantler-tech/pa/manifests) has 2 matchOIDCIdentity entries'

# --- RED: the one identity must be OURS — a foreign issuer or subject passes every
# shape check and is invisible to both subject guards ---
root="$(fresh_root foreignissuer)"
repo_doc fiss 'oci://ghcr.io/devantler-tech/fiss/manifests' "$(printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: %s\n        subject: %s' "'^https://accounts\\.google\\.com\$'" "$SUBJECT")" >"$root/fiss.yaml"; add_resource "$root" fiss.yaml
expect_refused 'a foreign issuer is refused' "$root" "OCIRepository fiss (oci://ghcr.io/devantler-tech/fiss/manifests) trusts issuer '^https://accounts\\.google\\.com\$'"

root="$(fresh_root wildcard)"
repo_doc wc 'oci://ghcr.io/devantler-tech/wc/manifests' "$(printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: %s\n        subject: %s' "$ISSUER" "'.*'")" >"$root/wc.yaml"; add_resource "$root" wc.yaml
expect_refused 'a wildcard subject is refused' "$root" "OCIRepository wc (oci://ghcr.io/devantler-tech/wc/manifests) trusts subject '.*'"

root="$(fresh_root foreignorg)"
repo_doc fo 'oci://ghcr.io/devantler-tech/fo/manifests' "$(printf '  verify:\n    provider: cosign\n    matchOIDCIdentity:\n      - issuer: %s\n        subject: %s' "$ISSUER" "'^https://github\\.com/evil-org/actions/\\.github/workflows/publish-app\\.yaml@[0-9a-f]{40}\$'")" >"$root/fo.yaml"; add_resource "$root" fo.yaml
expect_refused 'a subject anchored on another organisation is refused' "$root" 'does not anchor on'

# --- RED: host case and substituted hosts ---
root="$(fresh_root upper)"
repo_doc up 'oci://GHCR.IO/devantler-tech/up/manifests' '' >"$root/up.yaml"; add_resource "$root" up.yaml
expect_refused 'an upper-cased registry host is still in scope' "$root" 'OCIRepository up (oci://ghcr.io/devantler-tech/up/manifests) has NO spec.verify'

root="$(fresh_root subst)"
# The `${REGISTRY}` below is a Flux substitution placeholder, quoted verbatim.
# shellcheck disable=SC2016
repo_doc sub 'oci://${REGISTRY}/devantler-tech/sub/manifests' '' >"$root/sub.yaml"; add_resource "$root" sub.yaml
expect_refused 'a host decided by a substitution variable is refused as undecidable' "$root" 'decides its registry or organisation through a substitution variable'

# --- CONTROLS ---
root="$(fresh_root thirdparty)"
repo_doc flux 'oci://ghcr.io/fluxcd/flux-manifests' '' >"$root/flux.yaml"; add_resource "$root" flux.yaml
expect_accepted 'a third-party OCIRepository without verify is out of scope' "$root"

root="$(fresh_root outside)"
mkdir -p "$WORK/elsewhere"; repo_doc outside 'oci://ghcr.io/devantler-tech/outside/manifests' '' >"$WORK/elsewhere/outside.yaml"
expect_accepted 'a defect in a root that is not listed is not attributed to the tree' "$root"

# --- EXEMPTIONS ---
root="$(fresh_root exempt)"
repo_doc unsigned 'oci://ghcr.io/devantler-tech/charts/unsigned' '' >"$root/unsigned.yaml"; add_resource "$root" unsigned.yaml
printf 'oci://ghcr.io/devantler-tech/charts/unsigned\tpublished unsigned; tracked by example#1\n' >"$WORK/exempt.tsv"
expect_accepted 'an exempt unverified OCIRepository is admitted' "$root" "$WORK/exempt.tsv"
expect_refused 'the same root with no exemption row is refused' "$root" 'OCIRepository unsigned (oci://ghcr.io/devantler-tech/charts/unsigned) has NO spec.verify'
printf 'oci://ghcr.io/devantler-tech/charts/unsigned\n' >"$WORK/exempt-noreason.tsv"
expect_refused 'an exemption row without a reason is refused, once' "$root" 'carries no reason' "$WORK/exempt-noreason.tsv"
case "$out" in *"has NO spec.verify"*|*"STALE"*) fail 'a reason-less row produced cascading wrong-reason messages';; esac

printf 'oci://ghcr.io/devantler-tech/charts/unsigned\t \n' >"$WORK/exempt-emptyreason.tsv"
expect_refused 'an exemption row with an empty reason is refused' "$root" 'carries an empty reason' "$WORK/exempt-emptyreason.tsv"
printf '\tsome reason\n' >"$WORK/exempt-emptyurl.tsv"
expect_refused 'an exemption row with an empty URL is refused' "$root" 'names no URL' "$WORK/exempt-emptyurl.tsv"

root="$(fresh_root stale)"
printf 'oci://ghcr.io/devantler-tech/charts/gone\tretired long ago\n' >"$WORK/stale.tsv"
expect_refused 'an exemption naming no rendered OCIRepository is STALE' "$root" 'exemption for oci://ghcr.io/devantler-tech/charts/gone is STALE' "$WORK/stale.tsv"

root="$(fresh_root stalesuffix)"
repo_doc unsigned 'oci://ghcr.io/devantler-tech/charts/unsigned' '' >"$root/unsigned.yaml"; add_resource "$root" unsigned.yaml
printf 'oci://ghcr.io/devantler-tech/charts/unsigned\treal\ntech/charts/unsigned\tdead\n' >"$WORK/stale-suffix.tsv"
expect_refused 'a row that is only a suffix of a rendered URL is STALE (exact match)' "$root" 'exemption for tech/charts/unsigned is STALE' "$WORK/stale-suffix.tsv"

root="$(fresh_root gained)"
repo_doc unsigned 'oci://ghcr.io/devantler-tech/charts/unsigned' "$(good_verify)" >"$root/unsigned.yaml"; add_resource "$root" unsigned.yaml
expect_refused 'an exempt OCIRepository that now verifies reports its exemption as stale' "$root" 'is exempt from verification but carries spec.verify' "$WORK/exempt.tsv"

# --- RED: the floor — an empty in-scope result is a claim about the discovery ---
root="$WORK/root-floor"; rm -rf "$root"; mkdir -p "$root"
printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n' >"$root/kustomization.yaml"
repo_doc flux 'oci://ghcr.io/fluxcd/flux-manifests' "$(good_verify)" >"$root/flux.yaml"; add_resource "$root" flux.yaml
expect_refused 'zero in-scope OCIRepositories fails the floor' "$root" 'found 0 in-scope OCIRepositor(y/ies)'

# --- RED: a root that does not render is UNKNOWN, never clean ---
root="$(fresh_root broken)"
add_resource "$root" missing.yaml
expect_refused 'a root kustomize cannot build is refused as unknown' "$root" 'kubectl kustomize failed, so its OCIRepositories are UNKNOWN'

# --- DISCOVERY: every descriptor kustomize accepts makes an overlay discoverable, and
# an overlay carrying none of them is UNKNOWN rather than silently skipped. ---
write_discovery_overlay() {
  local k8s="$1" cluster="$2" descriptor="$3" repo_name="$4" verify="$5"
  local overlay="$k8s/clusters/$cluster" root="$k8s/providers/$cluster/apps"
  mkdir -p "$overlay" "$root"
  printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - flux-kustomization-apps.yaml\n' >"$overlay/$descriptor"
  printf 'apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\n  namespace: flux-system\nspec:\n  interval: 10m\n  path: ./providers/%s/apps\n  prune: true\n  sourceRef:\n    kind: OCIRepository\n    name: flux-system\n' "$cluster" >"$overlay/flux-kustomization-apps.yaml"
  printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - repo.yaml\n' >"$root/kustomization.yaml"
  repo_doc "$repo_name" "oci://ghcr.io/devantler-tech/$repo_name/manifests" "$verify" >"$root/repo.yaml"
}

expect_descriptor_discovered() {
  local descriptor="$1" k8s="$WORK/k8s-$1"
  rm -rf "$k8s"
  write_discovery_overlay "$k8s" alpha "$descriptor" disc ''
  if out="$(OCI_VERIFY_K8S_DIR="$k8s" OCI_VERIFY_EXEMPTIONS_FILE="$WORK/no-exemptions.tsv" OCI_VERIFY_EXPECTED_MIN=1 "$GUARD" 2>&1)"; then
    fail "discovery: an overlay with $descriptor was not judged (guard passed): $out"
    return
  fi
  case "$out" in
    *'OCIRepository disc (oci://ghcr.io/devantler-tech/disc/manifests) has NO spec.verify'*) pass "a $descriptor cluster overlay is discovered and its Flux root judged" ;;
    *) fail "discovery: $descriptor refused, but not for the right reason: $out" ;;
  esac
}

expect_descriptor_discovered kustomization.yaml
expect_descriptor_discovered kustomization.yml
expect_descriptor_discovered Kustomization

# Keep one valid overlay in the fixture: if the guard regresses to `continue` for the
# descriptor-less one, the good root satisfies the floor and the guard would pass.
k8s="$WORK/k8s-missing-descriptor"; rm -rf "$k8s"
write_discovery_overlay "$k8s" alpha kustomization.yml good "$(good_verify)"
mkdir -p "$k8s/clusters/bravo"
if out="$(OCI_VERIFY_K8S_DIR="$k8s" OCI_VERIFY_EXEMPTIONS_FILE="$WORK/no-exemptions.tsv" OCI_VERIFY_EXPECTED_MIN=1 "$GUARD" 2>&1)"; then
  fail "discovery: a descriptor-less overlay was skipped (guard passed): $out"
else
  case "$out" in
    *'clusters/bravo/ carries no kustomization descriptor; cannot discover its Flux roots'*) pass 'a cluster overlay with no supported descriptor is refused' ;;
    *) fail "discovery: a descriptor-less overlay was refused, but not for the right reason: $out" ;;
  esac
fi

# --- WIRING: the real tree passes with the built-in exemptions and floor ---
if out="$("$GUARD" 2>&1)"; then
  pass "the real tree passes: $out"
else
  fail "the real tree is refused: $out"
fi

# --- WIRING: ci.yaml runs the guard unconditionally in the validate job ---
if grep -qF './scripts/guard-oci-repository-verify.sh' "$REPO_ROOT/.github/workflows/ci.yaml"; then
  pass 'ci.yaml invokes the guard'
else
  fail 'ci.yaml does not invoke scripts/guard-oci-repository-verify.sh'
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%d failure(s)\n' "$failures" >&2
  exit 1
fi
printf '\nall cases passed\n'
