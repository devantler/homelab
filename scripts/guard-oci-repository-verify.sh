#!/usr/bin/env bash
# Require cosign verification on every devantler-tech OCIRepository, discovered by KIND
# and URL in what Flux actually applies (#3558, under #3308).
#
# WHY THIS EXISTS
# Both cosign-subject guards (scripts/guard-shared-publish-workflow-pin.sh and
# scripts/guard-publish-workflow-approved-revisions.sh) examine a file only when it
# already carries a shared-publish-workflow subject. An OCIRepository pointed at a
# devantler-tech artifact with NO `spec.verify` at all therefore carries no subject, is
# examined by neither guard, and is refused by nothing else: validate-flux-verify covers
# the root source only, and the Kyverno cluster policies do not touch OCIRepositories.
# Flux would apply an unsigned or foreign-signed artifact with every check green. This
# guard asks the question the other way round: every OCIRepository whose URL is a
# devantler-tech GHCR artifact must verify.
#
# WHAT IT REQUIRES, PER OCIRepository UNDER oci://ghcr.io/devantler-tech/
#   - `spec.verify` present
#   - `spec.verify.provider: cosign`
#   - `spec.verify.matchOIDCIdentity` a sequence of EXACTLY ONE entry. Flux ORs the
#     entries, so a second entry widens the trusted signer set while the first still
#     reads as narrowed; alternation belongs inside the one subject regex, where the
#     subject guards judge it.
#   - that entry names a non-empty `issuer` and a non-empty `subject`.
#   - the trusted Wedding and AS Coaching tenant artifacts follow the governed
#     `>=1.0.0` semver stream. The platform owns their signer and namespace
#     boundaries; restoring a tag or digest would reintroduce a platform PR for
#     every tenant release and is therefore rejected by the rendered-tree guard.
#
# IT JUDGES THE KUSTOMIZE BUILD, NOT THE SOURCE FILES — MEASURED, NOT PREFERRED. A first
# version scanned `k8s/**/*.yaml` with yq and was bypassed five ways in one review
# session, each leaving the guard reporting "all verify" while `kubectl kustomize`
# emitted an unverified OCIRepository: a `!!binary` tag or a YAML alias on `kind`
# (yq compares the tagged/alias node, kustomize resolves it), a resource file named
# `.json`, `.YAML` or with no extension (kustomize loads whatever `resources:` lists),
# a symlink (`find -type f` skips it, kustomize follows it), and a kustomize patch that
# removes `spec.verify` or appends an identity (patch text is a string, so no source
# walk ever sees a map). Every one of those is resolved by the build, which is also the
# only thing Flux sees. So the roots are RENDERED with `kubectl kustomize` and the
# render is what is walked.
#
# WHICH ROOTS: exactly the ones Flux applies. Each cluster overlay under k8s/clusters/
# renders the Flux Kustomization objects that point at the provider layers, and their
# `spec.path` values are the roots — read from the render rather than listed here, so a
# new layer is covered the day it is wired and an unwired one is not judged. Every
# mapping in a rendered root carrying `kind: OCIRepository` is examined, at any depth: a
# top-level manifest, a later document, or a template inside a ResourceGraphDefinition.
#
# WHAT IT DOES NOT COVER, BY NAME
#   - The ROOT source `flux-system/flux-system` is not a document in this tree: the
#     FluxInstance creates it, and its `spec.verify` (a branch identity, legitimately)
#     is supplied by a kustomize patch in flux-instance.yaml. That verification is
#     asserted by scripts/validate-flux-verify against both halves of its config.
#   - OCIRepositories outside oci://ghcr.io/devantler-tech/ are out of scope; this guard
#     is about the suite's own artifacts. The host is compared case-insensitively
#     (`GHCR.IO` is the same registry to DNS and TLS), and a URL that only decides its
#     host at Flux substitution time (`${…}` before the org path) is refused as
#     undecidable rather than waved through as foreign.
#
# EXEMPTIONS ARE EXPLICIT, URL-KEYED, AND FAIL CLOSED. An OCIRepository that cannot verify
# yet is admitted only by an entry in EXEMPTIONS below, carrying its reason and the
# issue that retires it. Every exemption must still match an OCIRepository in some
# rendered root (otherwise it is STALE and the run fails), and an exempt OCIRepository
# that gains `spec.verify` fails too, so the list can only shrink as artifacts start
# signing. An exemption counts toward the floor below — the floor guards discovery, not
# the verified count, and the verified count is the floor minus the honoured exemptions.
#
# THE FLOOR. An empty result from a filtered read is a claim about the filter: if the
# roots move, the URL scheme changes, or yq stops matching, the walk returns nothing and
# — without this — the guard would report a clean tree while checking nothing. The
# in-scope count must reach EXPECTED_MIN_IN_SCOPE, raised when a consumer is genuinely
# added and lowered only after verifying by hand that the walk still finds the rest.
#
# SEAMS (for scripts/tests/test-guard-oci-repository-verify.sh)
#   OCI_VERIFY_ROOTS             kustomize roots to render, newline-separated (default:
#                                derived from every cluster overlay under <repo>/k8s/clusters)
#   OCI_VERIFY_EXEMPTIONS_FILE   exemption rows `<url>\t<reason>` (default: the list below)
#   OCI_VERIFY_EXPECTED_MIN      in-scope floor (default: EXPECTED_MIN_IN_SCOPE)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly REQUIRED_URL_PREFIX='oci://ghcr.io/devantler-tech/'
# The identity every devantler-tech artifact is signed under: GitHub Actions keyless
# signing, with a subject regex anchored on a devantler-tech GitHub path. Compared as
# the literal regex text the manifests carry (the `.` escaped), not evaluated.
readonly REQUIRED_ISSUER='^https://token\.actions\.githubusercontent\.com$'
readonly REQUIRED_SUBJECT_PREFIX='^https://github\.com/devantler-tech/'
readonly REQUIRED_TENANT_STREAM_SEMVER='>=1.0.0'
readonly WEDDING_STREAM_URL='oci://ghcr.io/devantler-tech/wedding-app/manifests'
readonly ASCOACHING_STREAM_URL='oci://ghcr.io/devantler-tech/ascoachingogvaner/manifests'
# KRO preserves this placeholder in the rendered ResourceGraphDefinition; every
# Tenant instance resolves it to its own trusted repository name at runtime.
# shellcheck disable=SC2016
readonly TEMPLATED_TENANT_STREAM_URL='oci://ghcr.io/devantler-tech/${schema.spec.name}/manifests'
# Where the cluster overlays and the Flux roots they name live (seam for the test's
# discovery fixture; the roots are resolved relative to this directory).
readonly K8S_DIR="${OCI_VERIFY_K8S_DIR:-$REPO_ROOT/k8s}"

# 5 on 2026-09-04, counted per rendered root: providers/hetzner/apps carries the aws,
# github-config, wedding-app and ascoachingogvaner manifests consumers (4) and
# providers/hetzner/infrastructure carries the tenant RGD template (1). The docker
# provider opts into no apps and renders no tenant RGD, and the staged-off
# data-product-controller chart is in no root at all. A consumer wired into both
# providers would count twice.
readonly EXPECTED_MIN_IN_SCOPE=5
readonly EXPECTED_MIN="${OCI_VERIFY_EXPECTED_MIN:-$EXPECTED_MIN_IN_SCOPE}"

# <url><TAB><reason>, one per line; `#` lines are comments. The reason names what retires
# the entry. Empty today: the one unsigned artifact in the tree — the
# data-product-controller chart, published by a bare `helm push` with no cosign step
# (devantler-tech/data-product-controller#27 adds the signing) — is staged off
# (platform#3476), so no rendered root applies it and nothing needs admitting. Re-enabling
# that app before #27 ships fails this guard by name, which is the intended order: sign
# first, or add a reasoned row here deliberately.
DEFAULT_EXEMPTIONS="$(
  cat <<'EOF'
# oci://ghcr.io/devantler-tech/<artifact>	<why it cannot verify yet, and the issue that retires this row>
EOF
)"
readonly DEFAULT_EXEMPTIONS

refuse() {
  printf 'guard: %s\n' "$*" >&2
  exit 1
}

command -v yq >/dev/null 2>&1 || refuse 'yq is required and was not found on PATH'
command -v kubectl >/dev/null 2>&1 || refuse 'kubectl is required to render the kustomize roots'

case "$EXPECTED_MIN" in
  '' | *[!0-9]*) refuse "OCI_VERIFY_EXPECTED_MIN must be a non-negative integer, got '$EXPECTED_MIN'" ;;
esac

exemptions="$DEFAULT_EXEMPTIONS"
if [ -n "${OCI_VERIFY_EXEMPTIONS_FILE:-}" ]; then
  [ -f "$OCI_VERIFY_EXEMPTIONS_FILE" ] || refuse "OCI_VERIFY_EXEMPTIONS_FILE $OCI_VERIFY_EXEMPTIONS_FILE does not exist"
  exemptions="$(cat "$OCI_VERIFY_EXEMPTIONS_FILE")"
fi

# Every exemption row is validated up front, so a malformed row is one refusal with one
# cause — not a cascade of wrong-reason messages later in the walk.
while IFS= read -r row; do
  [ -n "$row" ] || continue
  case "$row" in '#'*) continue ;; esac
  case "$row" in
    *"	"*) ;;
    *) refuse "exemption row '$row' carries no reason; every exemption names what retires it" ;;
  esac
  # Both halves must be non-empty: `<url><TAB>` would waive verification with no
  # recorded reason, and `<TAB><reason>` would key an exemption on the empty URL.
  row_url="${row%%	*}"
  row_reason="${row#*	}"
  row_reason="${row_reason#"${row_reason%%[![:space:]]*}"}"
  [ -n "$row_url" ] || refuse "exemption row '$row' names no URL"
  [ -n "$row_reason" ] || refuse "exemption row '$row' carries an empty reason; every exemption names what retires it"
done <<EOF
$exemptions
EOF

# exempt_reason <url> — prints the reason and returns 0 when the URL is exempt.
exempt_reason() {
  local url="$1" row row_url
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    case "$row" in '#'*) continue ;; esac
    row_url="${row%%	*}"
    if [ "$row_url" = "$url" ]; then
      printf '%s' "${row#*	}"
      return 0
    fi
  done <<EOF
$exemptions
EOF
  return 1
}

# normalise_url <url> — lower-cases the scheme and host so the registry compares the
# way DNS and TLS compare it; the path keeps its case (a GHCR path is case-sensitive).
normalise_url() {
  local url="$1" scheme_host rest
  case "$url" in
    */*/*/*)
      scheme_host="${url%%//*}//"
      rest="${url#*//}"
      printf '%s%s/%s' "$(printf '%s' "$scheme_host" | tr '[:upper:]' '[:lower:]')" \
        "$(printf '%s' "${rest%%/*}" | tr '[:upper:]' '[:lower:]')" "${rest#*/}"
      ;;
    *) printf '%s' "$url" ;;
  esac
}

# The roots Flux applies: every `spec.path` of every Flux Kustomization each cluster
# overlay renders. Read from the render, never listed by hand.
roots=""
if [ -n "${OCI_VERIFY_ROOTS:-}" ]; then
  roots="$OCI_VERIFY_ROOTS"
else
  [ -d "$K8S_DIR/clusters" ] || refuse "no clusters directory under $K8S_DIR"
  for overlay in "$K8S_DIR"/clusters/*/; do
    # k8s/clusters/base is the wiring TEMPLATE the real overlays consume: its Flux paths
    # are `__PROVIDER__`/`__CLUSTER__` placeholders that each cluster overlay replaces.
    # No cluster applies it as-is, so it is not a root.
    case "${overlay%/}" in */base) continue ;; esac
    # kustomize recognises all three descriptor names; an overlay using `.yml` or the
    # extensionless, case-sensitive `Kustomization` name is a root exactly like one
    # using `.yaml`, and skipping it would leave a whole cluster unjudged while the
    # floor still passed on the others.
    if [ ! -f "$overlay/kustomization.yaml" ] && [ ! -f "$overlay/kustomization.yml" ] && [ ! -f "$overlay/Kustomization" ]; then
      refuse "cluster overlay $overlay carries no kustomization descriptor; cannot discover its Flux roots"
    fi
    if ! paths="$(kubectl kustomize "$overlay" 2>/dev/null |
      yq -N -r 'select(.kind == "Kustomization" and (.apiVersion | test("^kustomize\\.toolkit\\.fluxcd\\.io/"))) | .spec.path // ""')"; then
      refuse "could not render the cluster overlay $overlay to discover its Flux roots"
    fi
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      roots="$roots$K8S_DIR/${p#./}
"
    done <<EOF
$paths
EOF
  done
fi
[ -n "$roots" ] || refuse 'no Flux Kustomization roots were discovered; nothing would be judged'

# One row per OCIRepository mapping found anywhere in the render. Fields are joined with
# a tab, and an EMPTY field is spelled `-` so consecutive tabs never collapse under
# `read`'s whitespace splitting (which shifted every column right of the first empty one
# and produced wrong-reason messages). `-` is decoded back to empty below.
#   url  name  has_verify  provider  identities_type  identities_count  incomplete_entries
#   issuer  subject  ref_type  ref_key_count  ref_semver
readonly YQ_ROWS='[.. | select(type == "!!map" and .kind == "OCIRepository")]
  | .[]
  | [
      (.spec.url // ""),
      (.metadata.name // ""),
      (((.spec // {}) | has("verify")) | tostring),
      (.spec.verify.provider // ""),
      (.spec.verify.matchOIDCIdentity | type),
      (((.spec.verify.matchOIDCIdentity | select(type == "!!seq") | length) // 0) | tostring),
      (([.spec.verify.matchOIDCIdentity | select(type == "!!seq") | .[]
          | select(((.issuer // "") == "") or ((.subject // "") == ""))] | length) | tostring),
      ((.spec.verify.matchOIDCIdentity | select(type == "!!seq") | .[0].issuer) // ""),
      ((.spec.verify.matchOIDCIdentity | select(type == "!!seq") | .[0].subject) // ""),
      (.spec.ref | type),
      ((((.spec.ref | select(type == "!!map") | keys | length) // 0)) | tostring),
      ((.spec.ref | select(type == "!!map") | .semver) // "")
    ]
  | map(sub("^$", "-"))
  | join("	")'

status=0
in_scope=0
seen_exempt=""
fail() {
  printf '%s\n' "$*" >&2
  status=1
}
decode() { [ "$1" = "-" ] && printf '' || printf '%s' "$1"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

while IFS= read -r root; do
  [ -n "$root" ] || continue
  label="${root#"$REPO_ROOT"/}"
  # FAIL CLOSED on a root that does not render: an unrenderable layer is not "no
  # OCIRepository here", it is "unknown", and unknown must not read as clean.
  if ! kubectl kustomize "$root" >"$work/render.yaml" 2>"$work/render.err"; then
    fail "$label: kubectl kustomize failed, so its OCIRepositories are UNKNOWN: $(tr '\n' ' ' <"$work/render.err")"
    continue
  fi
  if ! yq -N -r "$YQ_ROWS" "$work/render.yaml" >"$work/rows" 2>"$work/rows.err"; then
    fail "$label: yq could not read the render, so its OCIRepositories are UNKNOWN: $(tr '\n' ' ' <"$work/rows.err")"
    continue
  fi
  while IFS=$'\t' read -r url name has_verify provider ids_type ids_count incomplete issuer subject ref_type ref_key_count ref_semver; do
    [ -n "$url" ] || continue
    url="$(decode "$url")"; name="$(decode "$name")"; provider="$(decode "$provider")"
    ids_type="$(decode "$ids_type")"; issuer="$(decode "$issuer")"; subject="$(decode "$subject")"
    ref_type="$(decode "$ref_type")"; ref_semver="$(decode "$ref_semver")"
    [ -n "$url$name" ] || continue
    url="$(normalise_url "$url")"
    # The second pattern is the literal characters `${` — a Flux substitution marker,
    # deliberately not expanded by the shell.
    # shellcheck disable=SC2016
    case "$url" in
      "$REQUIRED_URL_PREFIX"*) ;;
      *'${'*)
        # The host or org is only decided at Flux substitution time; that is not
        # provably foreign, so it is not out of scope.
        in_scope=$((in_scope + 1))
        fail "$label: OCIRepository $name ($url) decides its registry or organisation through a substitution variable, so this guard cannot tell whether it is a devantler-tech artifact. Spell the registry and organisation literally."
        continue
        ;;
      *) continue ;;
    esac
    in_scope=$((in_scope + 1))
    case "$url" in
      "$WEDDING_STREAM_URL" | "$ASCOACHING_STREAM_URL" | "$TEMPLATED_TENANT_STREAM_URL")
        if [ "$ref_type" != "!!map" ] || [ "$ref_key_count" -ne 1 ] || [ "$ref_semver" != "$REQUIRED_TENANT_STREAM_SEMVER" ]; then
          fail "$label: OCIRepository $name ($url) must follow the governed release stream with exactly spec.ref.semver: $REQUIRED_TENANT_STREAM_SEMVER; tag, digest, mixed and missing selectors require a platform boundary change"
          continue
        fi
        ;;
    esac
    if reason="$(exempt_reason "$url")"; then
      seen_exempt="$seen_exempt$url
"
      if [ "$has_verify" = "true" ]; then
        fail "$label: OCIRepository $name ($url) is exempt from verification but carries spec.verify; the exemption is stale — remove it ($reason)"
      fi
      continue
    fi
    if [ "$has_verify" != "true" ]; then
      fail "$label: OCIRepository $name ($url) has NO spec.verify — Flux would apply an unsigned or foreign-signed artifact. Add provider: cosign with exactly one matchOIDCIdentity entry."
      continue
    fi
    if [ "$provider" != "cosign" ]; then
      fail "$label: OCIRepository $name ($url) verifies with provider '${provider:-<none>}', not cosign"
      continue
    fi
    if [ "$ids_type" != "!!seq" ]; then
      fail "$label: OCIRepository $name ($url) has no matchOIDCIdentity sequence (found ${ids_type:-nothing}); a verify block that names no identity admits no signer and pins none"
      continue
    fi
    if [ "$ids_count" -eq 0 ]; then
      fail "$label: OCIRepository $name ($url) has ZERO matchOIDCIdentity entries; verification with no identity is not a matcher"
      continue
    fi
    if [ "$ids_count" -ne 1 ]; then
      fail "$label: OCIRepository $name ($url) has $ids_count matchOIDCIdentity entries; Flux ORs them, so a second entry WIDENS the trusted signer set. Put any alternation inside the one subject regex."
      continue
    fi
    if [ "$incomplete" -ne 0 ]; then
      fail "$label: OCIRepository $name ($url) has a matchOIDCIdentity entry missing a non-empty issuer or subject"
      continue
    fi
    # The one identity must be OURS. A single `issuer: '.*'` / `subject: '.*'` entry
    # satisfies every shape check above and is invisible to both subject guards
    # (they examine only subjects naming the shared publish workflows), so without
    # this an OCIRepository could accept any signer with every check green. The
    # issuer is exactly GitHub Actions' token issuer and the subject regex must
    # anchor on a devantler-tech GitHub path; WHICH revision it pins is the
    # subject guards' question, not this one's.
    if [ "$issuer" != "$REQUIRED_ISSUER" ]; then
      fail "$label: OCIRepository $name ($url) trusts issuer '$issuer'; the only accepted issuer is '$REQUIRED_ISSUER' (GitHub Actions keyless signing)"
      continue
    fi
    case "$subject" in
      "$REQUIRED_SUBJECT_PREFIX"*) ;;
      *)
        fail "$label: OCIRepository $name ($url) trusts subject '$subject', which does not anchor on '$REQUIRED_SUBJECT_PREFIX' — a signer outside devantler-tech would verify"
        continue
        ;;
    esac
  done <"$work/rows"
done <<EOF
$roots
EOF

# Every exemption must still name an OCIRepository that exists, or it is a hole waiting
# for a manifest to fall into it. Exact match per line, never a substring.
while IFS= read -r row; do
  [ -n "$row" ] || continue
  case "$row" in '#'*) continue ;; esac
  row_url="${row%%	*}"
  if ! printf '%s' "$seen_exempt" | grep -qxF -- "$row_url"; then
    fail "exemption for $row_url is STALE: no rendered OCIRepository carries that URL. Remove the row."
  fi
done <<EOF
$exemptions
EOF

if [ "$in_scope" -lt "$EXPECTED_MIN" ]; then
  fail "found $in_scope in-scope OCIRepositor(y/ies) under $REQUIRED_URL_PREFIX across the rendered roots, expected at least $EXPECTED_MIN. The discovery, not the tree, is the likely cause: verify by hand, then fix it or lower the floor with the reason."
fi

if [ "$status" -eq 0 ]; then
  honoured="$(printf '%s' "$seen_exempt" | grep -c . || true)"
  printf 'guard: %d devantler-tech OCIRepositor(y/ies) in the rendered Flux roots all verify with cosign and exactly one identity (exemptions honoured: %d).\n' \
    "$in_scope" "$honoured"
fi
exit "$status"
