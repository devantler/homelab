#!/usr/bin/env bash
#
# Proves guard-tracked-exec-bit.sh actually discriminates, in all four directions:
# it FAILS on a directly-invoked script tracked 100644, PASSES once the same file
# is tracked 100755, PASSES when the invocation moves behind an interpreter (so the
# requirement is derived from the invocation rather than pinned to a filename), and
# refuses to report success when it finds nothing to check.
#
# Each fixture is a throwaway git repository. The mode has to be set in the INDEX
# rather than on disk, because that is the only thing the guard reads and the only
# thing a fresh clone receives — a working-tree chmod would prove nothing.

set -euo pipefail

guard="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/guard-tracked-exec-bit.sh"
failures=0

# `anchor` adds a SECOND script that is directly invoked and tracked executable.
# Without it a fixture whose only script is interpreter-invoked has no direct
# invocation at all, so the guard refuses on anti-vacuity and a "relaxed" case
# would pass for the wrong reason — proving nothing about relaxation.
make_fixture() {
  local dir="$1" mode="$2" invocation="$3" anchor="${4:-no}"

  mkdir -p "$dir/scripts" "$dir/.github/workflows"
  cd "$dir"
  git init -q .
  git config user.email t@example.com
  git config user.name t

  printf '#!/usr/bin/env bash\necho hi\n' > scripts/fixture-target.sh
  printf 'jobs:\n  j:\n    steps:\n      - run: %s\n' "$invocation" > .github/workflows/w.yaml

  if [[ "$anchor" == "anchor" ]]; then
    printf '#!/usr/bin/env bash\necho anchor\n' > scripts/fixture-anchor.sh
    printf '      - run: ./scripts/fixture-anchor.sh\n' >> .github/workflows/w.yaml
  fi

  git add -A
  git update-index --chmod="$mode" scripts/fixture-target.sh
  [[ "$anchor" == "anchor" ]] && git update-index --chmod=+x scripts/fixture-anchor.sh
  git -c commit.gpgsign=false commit -qm fixture
  cd - > /dev/null
}

expect() {
  local label="$1" want_rc="$2" want_text="$3" dir="$4"

  set +e
  output="$(bash "$guard" "$dir" 2>&1)"
  rc=$?
  set -e

  if [[ "$rc" != "$want_rc" ]]; then
    echo "::error::$label: rc=$rc want=$want_rc — $output"
    failures=$((failures + 1))
    return
  fi
  if [[ "$output" != *"$want_text"* ]]; then
    echo "::error::$label: rc matched but for the wrong reason — $output"
    failures=$((failures + 1))
    return
  fi
  echo "$label ✅"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# RED: directly invoked, tracked non-executable.
make_fixture "$work/red" -x './scripts/fixture-target.sh'
expect "RED   directly-invoked 100644 is rejected" 1 "is tracked 100644, not 100755" "$work/red"

# GREEN: the same invocation, with the bit tracked.
make_fixture "$work/green" +x './scripts/fixture-target.sh'
expect "GREEN directly-invoked 100755 is accepted" 0 "exec-bit guard OK" "$work/green"

# RELAXATION: the requirement follows the invocation. The identical non-executable
# file is fine once an interpreter runs it, so the guard is not simply always-on.
make_fixture "$work/relaxed" -x 'bash ./scripts/fixture-target.sh' anchor
expect "RELAX interpreter-invoked 100644 is accepted" 0 "exec-bit guard OK" "$work/relaxed"

# ANTI-VACUITY: no direct invocation anywhere is cannot-check, never a clean pass.
make_fixture "$work/empty" -x 'echo nothing-to-see'
expect "VACUOUS no invocation at all refuses to pass" 1 "examined nothing" "$work/empty"

if ((failures > 0)); then
  echo "::error::$failures exec-bit guard assertion(s) failed"
  exit 1
fi

echo "all exec-bit guard assertions passed"
