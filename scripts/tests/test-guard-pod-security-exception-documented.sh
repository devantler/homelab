#!/usr/bin/env bash
#
# Cover guard-pod-security-exception-documented.sh.
#
# The load-bearing case is "documented elsewhere in the file, but not in the warning
# block" — the exact shape the tree had when C-0211 was added (#3516). A guard that
# accepts a mention anywhere passes on that tree, so it is asserted directly rather
# than left implied by the happy path.
#
# Every fail-closed claim is proven by ablation: each bad input is built from the
# REAL file and mutated one way, so a case cannot pass because the fixture failed to
# build.

set -euo pipefail

cd "$(dirname "$0")/../.."
readonly GUARD='scripts/guard-pod-security-exception-documented.sh'
readonly REAL='k8s/bases/infrastructure/cluster-security-exceptions/pod-security-mutations-unscoped.yaml'

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0
ok() { printf 'ok: %s\n' "$1"; }
bad() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

# Run the guard on a file, reporting its exit status without tripping `set -e`.
run() {
  local f="$1" rc=0
  bash "${GUARD}" "${f}" >/dev/null 2>&1 || rc=$?
  printf '%s\n' "${rc}"
}
expect() { # <label> <expected-rc> <file>
  local label="$1" want="$2" f="$3" got
  got="$(run "${f}")"
  if [ "${got}" = "${want}" ]; then ok "${label} — exit ${got}"; else
    bad "${label} — expected exit ${want}, got ${got}"
  fi
}

[ -f "${REAL}" ] || {
  printf 'FAIL: fixture source %s is missing; every case below would be vacuous\n' "${REAL}" >&2
  exit 1
}

# --- the tree as it stands ------------------------------------------------------
expect 'current tree passes' 0 "${REAL}"

# --- AC1: a suppressed control absent from the block ----------------------------
f="${tmp}/undocumented.yaml"
sed 's/^      action: ignore$/      action: ignore/' "${REAL}" >"${f}"
# Append a third control that is named nowhere in the file.
printf '    - controlID: C-0999\n      action: ignore\n' >>"${f}"
grep -q 'C-0999' "${f}" || bad 'fixture build: C-0999 was not added'
expect 'a control absent from the block fails' 1 "${f}"
# Capture, then match. Under `pipefail` a `guard | grep` pipeline reports the GUARD's
# non-zero status even when grep matched, so the assertion would fail on a correct
# guard — the same status-through-a-pipe trap the guard itself guards against.
guard_out="$(bash "${GUARD}" "${f}" 2>&1 || true)"
if grep -q 'C-0999' <<<"${guard_out}"; then
  ok 'the failure names the undocumented control'
else
  bad 'the failure did not name C-0999'
fi

# --- THE HISTORICAL DEFECT: documented, but outside the block -------------------
# Move every mention of C-0211 out of the warning block, leaving it mentioned later
# in the same header. This reproduces the tree that motivated #3516.
f="${tmp}/outside-block.yaml"
awk '
  /fail-open-warning:BEGIN/ { inblock = 1 }
  /fail-open-warning:END/   { inblock = 0 }
  inblock && /C-0211/       { next }          # drop it from the block only
  { print }
' "${REAL}" >"${f}"
grep -q 'C-0211' "${f}" || bad 'fixture build: C-0211 vanished from the whole file, not just the block'
awk '/fail-open-warning:BEGIN/{i=1} /fail-open-warning:END/{i=0} i && /C-0211/{found=1} END{exit !found}' "${f}" &&
  bad 'fixture build: C-0211 is still inside the block' || true
expect 'named outside the block but not inside it fails' 1 "${f}"

# --- the marker lines are structure, not documentation --------------------------
f="${tmp}/on-marker.yaml"
awk '
  /fail-open-warning:BEGIN/ { inblock = 1 }
  /fail-open-warning:END/   { inblock = 0 }
  inblock && /C-0211/       { next }
  { print }
' "${REAL}" |
  sed 's/^# fail-open-warning:BEGIN.*$/# fail-open-warning:BEGIN — covers C-0211/' >"${f}"
expect 'a control named only on the BEGIN marker line does not count' 1 "${f}"

# --- word-boundary: a longer id must not satisfy a shorter one ------------------
f="${tmp}/superstring.yaml"
sed 's/C-0211/C-02110/g' "${REAL}" |
  sed 's/^    - controlID: C-02110$/    - controlID: C-0211/' >"${f}"
expect 'C-02110 in the block does not document C-0211' 1 "${f}"

# --- fail-closed inputs ---------------------------------------------------------
expect 'a missing file is exit 2' 2 "${tmp}/does-not-exist.yaml"

f="${tmp}/unreadable.yaml"
cp "${REAL}" "${f}"
chmod 000 "${f}"
if [ "$(id -u)" -eq 0 ]; then
  ok 'unreadable-file case skipped (running as root, which can read anyway)'
else
  expect 'an unreadable file is exit 2' 2 "${f}"
fi
chmod 644 "${f}"

f="${tmp}/no-posture.yaml"
yq 'del(.spec.posture)' "${REAL}" >"${f}"
expect 'no .spec.posture is exit 2' 2 "${f}"

f="${tmp}/empty-posture.yaml"
yq '.spec.posture = []' "${REAL}" >"${f}"
expect 'an empty .spec.posture is exit 2' 2 "${f}"

f="${tmp}/no-begin.yaml"
grep -v 'fail-open-warning:BEGIN' "${REAL}" >"${f}"
expect 'a missing BEGIN marker is exit 2' 2 "${f}"

f="${tmp}/no-end.yaml"
grep -v 'fail-open-warning:END' "${REAL}" >"${f}"
expect 'a missing END marker is exit 2' 2 "${f}"

f="${tmp}/dup-begin.yaml"
sed 's|^# fail-open-warning:END$|# fail-open-warning:BEGIN dup\n# fail-open-warning:END|' "${REAL}" >"${f}"
expect 'a duplicated BEGIN marker is exit 2' 2 "${f}"

f="${tmp}/swapped.yaml"
sed -e 's|^# fail-open-warning:BEGIN.*$|# fail-open-warning:TMPEND|' \
  -e 's|^# fail-open-warning:END$|# fail-open-warning:BEGIN swapped|' "${REAL}" |
  sed 's|^# fail-open-warning:TMPEND$|# fail-open-warning:END|' >"${f}"
expect 'markers out of order is exit 2' 2 "${f}"

f="${tmp}/empty-block.yaml"
awk '
  /fail-open-warning:BEGIN/ { print; inblock = 1; next }
  /fail-open-warning:END/   { inblock = 0 }
  inblock                   { next }
  { print }
' "${REAL}" >"${f}"
expect 'an empty warning block is exit 2' 2 "${f}"

f="${tmp}/wrong-kind.yaml"
yq '.kind = "ConfigMap"' "${REAL}" >"${f}"
expect 'a non-ClusterSecurityException is exit 2' 2 "${f}"

f="${tmp}/not-yaml.yaml"
printf 'this: is: not: valid: yaml: [\n' >"${f}"
expect 'an unparseable file is exit 2' 2 "${f}"

f="${tmp}/bad-id.yaml"
yq '.spec.posture[0].controlID = "not-a-control"' "${REAL}" >"${f}"
expect 'a malformed control id is exit 2' 2 "${f}"

# --- the id form is checked WHOLE, not just at its start ------------------------
# `C-[0-9]*` as a case glob anchors only the head: the trailing `*` accepts any
# suffix, so it admits every id below while the die message claims to require
# C-<digits>. One fixture per shape, so a pass cannot be carried by a sibling.
f="${tmp}/id-trailing-alpha.yaml"
yq '.spec.posture[0].controlID = "C-0211x"' "${REAL}" >"${f}"
expect 'a control id with a trailing non-digit is exit 2' 2 "${f}"

f="${tmp}/id-trailing-space.yaml"
yq '.spec.posture[0].controlID = "C-0211 "' "${REAL}" >"${f}"
expect 'a control id with a trailing space is exit 2' 2 "${f}"

f="${tmp}/id-embedded-punct.yaml"
yq '.spec.posture[0].controlID = "C-0211-extra"' "${REAL}" >"${f}"
expect 'a control id with a trailing segment is exit 2' 2 "${f}"

# The negative control: the fix must not start rejecting well-formed ids. It must
# name a control the REAL file still SUPPRESSES, because this guard also requires
# every posture id to appear in the fail-open warning block. A well-formed id this
# file no longer documents would fail for the WRONG reason and read as a regex
# regression. Sharing the base id the corrupted fixtures above mutate leaves
# well-formedness as the only variable between them.
f="${tmp}/id-well-formed.yaml"
yq '.spec.posture[0].controlID = "C-0211"' "${REAL}" >"${f}"
expect 'a well-formed control id is still accepted' 0 "${f}"

if [ "${failures}" -gt 0 ]; then
  printf 'FAILED: %s case(s)\n' "${failures}" >&2
  exit 1
fi
printf 'PASS: the documented-control guard holds, and fails closed on every unreadable input\n'
