#!/usr/bin/env bash
#
# Pins the cert-approver image-pin guard's verdict in all THREE directions (#3515).
#
#   exit 0  exactly one images: entry, pinned to the updater's tag and digest
#   exit 1  the pin is missing, duplicated, renamed, or names another tag/digest
#   exit 2  the guard could not check
#
# The first case runs the guard against the REAL committed kustomization with the updater's own
# constants, so a revert of either half of the pin fails here. Every other case is a fixture that
# isolates one condition, so an assertion can only be satisfied by the case it belongs to.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
guard="$repo_root/scripts/guard-cert-approver-image-pin.sh"
updater="$repo_root/scripts/update-vendored-operators.sh"
committed="$repo_root/k8s/providers/hetzner/infrastructure/controllers/kubelet-serving-cert-approver/kustomization.yaml"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

failures=0
assertions=0

run_guard() { # <file> <version> <digest>
  if GUARD_OUT="$("$guard" "$@" 2>&1)"; then
    GUARD_RC=0
  else
    GUARD_RC=$?
  fi
}

assert_rc() { # <label> <expected-rc>
  assertions=$((assertions + 1))
  if [ "$2" = "$GUARD_RC" ]; then
    printf '  ok   %s (exit %s)\n' "$1" "$GUARD_RC"
  else
    printf '  FAIL %s: expected exit %s, got %s\n' "$1" "$2" "$GUARD_RC"
    printf '%s\n' "$GUARD_OUT" | sed 's/^/       | /'
    failures=$((failures + 1))
  fi
}

assert_contains() { # <label> <needle>
  assertions=$((assertions + 1))
  # A here-string, not a pipe: under pipefail an early `grep -q` match SIGPIPEs the writer and
  # inverts the verdict.
  if grep -qF -- "$2" <<<"$GUARD_OUT"; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s: output did not contain %s\n' "$1" "$2"
    printf '%s\n' "$GUARD_OUT" | sed 's/^/       | /'
    failures=$((failures + 1))
  fi
}

constant() { # <name> -> the value of `readonly <name>='…'` in the updater
  sed -n "s/^readonly $1='\\(.*\\)'\$/\\1/p" "$updater"
}

version="$(constant cert_approver_version)"
digest="$(constant cert_approver_image_digest)"
other_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'

echo "== the updater records both halves of the pin =="
assertions=$((assertions + 1))
if [ -n "$version" ] && [ -n "$digest" ]; then
  printf '  ok   updater declares cert_approver_version (%s) and cert_approver_image_digest (%s)\n' "$version" "$digest"
else
  printf '  FAIL updater must declare cert_approver_version and cert_approver_image_digest (got version=%s digest=%s)\n' "${version:-<empty>}" "${digest:-<empty>}"
  failures=$((failures + 1))
  # Without the constants the committed case below cannot assert anything meaningful.
  version="${version:-0.0.0}"
  digest="${digest:-$other_digest}"
fi

echo "== the committed kustomization is pinned to the updater's tag and digest =="
run_guard "$committed" "$version" "$digest"
assert_rc "committed kustomization" 0

fixture() { # <name> <images-block> -> echoes the file path
  local f="$scratch/$1.yaml"
  printf '%s\n' 'apiVersion: kustomize.config.k8s.io/v1beta1' 'kind: Kustomization' 'resources:' '  - deployment.yaml' >"$f"
  [ -z "$2" ] || printf '%s\n' "$2" >>"$f"
  printf '%s' "$f"
}

good='images:
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newTag: 0.12.0
    digest: sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45'
fixture_version='0.12.0'
fixture_digest='sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45'

echo "== case: pinned fixture is accepted =="
run_guard "$(fixture pinned "$good")" "$fixture_version" "$fixture_digest"
assert_rc "pinned fixture" 0

echo "== case: no images block =="
run_guard "$(fixture none "")" "$fixture_version" "$fixture_digest"
assert_rc "missing images block" 1
assert_contains "names the missing entry" "found 0"

echo "== case: only an unrelated image is pinned =="
run_guard "$(fixture unrelated 'images:
  - name: ghcr.io/example/other
    newTag: 0.12.0
    digest: sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45')" "$fixture_version" "$fixture_digest"
assert_rc "unrelated image only" 1

echo "== case: tag differs from the updater's version =="
run_guard "$(fixture tag 'images:
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newTag: 0.11.1
    digest: sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45')" "$fixture_version" "$fixture_digest"
assert_rc "stale tag" 1
assert_contains "names the tag mismatch" "newTag is '0.11.1'"

echo "== case: digest missing =="
run_guard "$(fixture nodigest 'images:
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newTag: 0.12.0')" "$fixture_version" "$fixture_digest"
assert_rc "missing digest" 1
assert_contains "names the unset digest" "digest is '<unset>'"

echo "== case: digest differs from the updater's =="
run_guard "$(fixture digest "images:
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newTag: 0.12.0
    digest: $other_digest")" "$fixture_version" "$fixture_digest"
assert_rc "different digest" 1

echo "== case: newName replaces the reviewed image =="
run_guard "$(fixture newname 'images:
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newName: ghcr.io/example/fork
    newTag: 0.12.0
    digest: sha256:534e40a0050c34bda2a7bae53aa9c11133704f23dc83fee14f3b45b0f1eabe45')" "$fixture_version" "$fixture_digest"
assert_rc "newName set" 1

echo "== case: the entry is duplicated =="
run_guard "$(fixture duplicate "$good
  - name: ghcr.io/alex1989hu/kubelet-serving-cert-approver
    newTag: 0.12.0
    digest: $other_digest")" "$fixture_version" "$fixture_digest"
assert_rc "duplicated entry" 1
assert_contains "names the duplicate" "found 2"

echo "== case: cannot check =="
run_guard "$scratch/does-not-exist.yaml" "$fixture_version" "$fixture_digest"
assert_rc "missing file" 2
printf '%s\n' 'images: [unterminated' >"$scratch/broken.yaml"
run_guard "$scratch/broken.yaml" "$fixture_version" "$fixture_digest"
assert_rc "unparseable YAML" 2
run_guard "$(fixture malformed "$good")" "$fixture_version" "sha256:not-hex"
assert_rc "malformed expected digest" 2
run_guard "$(fixture usage "$good")" "$fixture_version"
assert_rc "bad usage" 2

printf '\n%d assertion(s), %d failure(s)\n' "$assertions" "$failures"
[ "$failures" -eq 0 ]
