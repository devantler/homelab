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
# `target` defaults to scripts/fixture-target.sh; pass a path under
# .github/scripts/ to cover the CI installer surface, which is invoked as the
# command of a run step rather than as ./scripts/<name>.
make_fixture() {
  local dir="$1" mode="$2" invocation="$3" anchor="${4:-no}"
  local target="${5:-scripts/fixture-target.sh}"

  mkdir -p "$dir/scripts" "$dir/.github/workflows" "$dir/$(dirname "$target")"
  cd "$dir"
  git init -q .
  git config user.email t@example.com
  git config user.name t

  printf '#!/usr/bin/env bash\necho hi\n' > "$target"
  printf 'jobs:\n  j:\n    steps:\n      - run: %s\n' "$invocation" > .github/workflows/w.yaml

  if [[ "$anchor" == "anchor" ]]; then
    printf '#!/usr/bin/env bash\necho anchor\n' > scripts/fixture-anchor.sh
    printf '      - run: ./scripts/fixture-anchor.sh\n' >> .github/workflows/w.yaml
  fi

  git add -A
  git update-index --chmod="$mode" "$target"
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


# .GITHUB/SCRIPTS COVERAGE: the CI installers live under .github/scripts and are
# invoked as the command of a run step, with no ./ in front. That surface was
# outside both the mode inventory and the detector, so a mode-only regression on
# setup-ksail.sh or setup-talosctl.sh was invisible while the guard still
# reported success over unrelated root scripts.
make_fixture "$work/dotgithub" -x '.github/scripts/fixture-target.sh' no \
  '.github/scripts/fixture-target.sh'
expect "GHDIR .github/scripts 100644 is rejected" 1 "is tracked 100644, not 100755" "$work/dotgithub"

# QUOTED INVOCATION: the shell execs a quoted path exactly as it execs a bare
# one, so it needs the bit; a delimiter class that omits quotes silently skips it.
make_fixture "$work/quoted" -x '"./scripts/fixture-target.sh"'
expect "QUOTE quoted direct invocation is rejected" 1 "is tracked 100644, not 100755" "$work/quoted"

# CONTINUATION LINE IS NOT COMMAND POSITION: recognising a run block's command by
# line-leading position must not also claim every backslash-continued ARGUMENT.
# This repository continues a shellcheck call over library files tracked 100644,
# and counting those fails the build over files nothing execs. The anchor keeps
# the sweep non-vacuous so rc=0 means "not claimed", never "nothing examined".
make_continuation_fixture() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/.github/workflows"
  cd "$dir"
  git init -q .
  git config user.email t@example.com
  git config user.name t
  printf '#!/usr/bin/env bash\necho lib\n' > scripts/fixture-target.sh
  printf '#!/usr/bin/env bash\necho anchor\n' > scripts/fixture-anchor.sh
  {
    printf 'jobs:\n  j:\n    steps:\n      - run: |\n'
    printf '          shellcheck \\\n'
    printf '            scripts/fixture-target.sh\n'
    printf '      - run: ./scripts/fixture-anchor.sh\n'
  } > .github/workflows/w.yaml
  git add -A
  git update-index --chmod=-x scripts/fixture-target.sh
  git update-index --chmod=+x scripts/fixture-anchor.sh
  git -c commit.gpgsign=false commit -qm fixture
  cd - > /dev/null
}
make_continuation_fixture "$work/continuation"
expect "CONT  continued argument is not an invocation" 0 "exec-bit guard OK" "$work/continuation"

# RUN-BLOCK COMMAND: a multi-line run block names the command on its own line
# with no ./ and no run: keyword on that line — the shape the talosctl installer
# uses. Neither the delimiter pass nor the run: pass can see it.
make_runblock_fixture() {
  local dir="$1" mode="$2"
  mkdir -p "$dir/scripts" "$dir/.github/scripts" "$dir/.github/workflows"
  cd "$dir"
  git init -q .
  git config user.email t@example.com
  git config user.name t
  printf '#!/usr/bin/env bash\necho hi\n' > .github/scripts/fixture-target.sh
  {
    printf 'jobs:\n  j:\n    steps:\n      - run: |\n'
    printf '          .github/scripts/fixture-target.sh\n'
  } > .github/workflows/w.yaml
  git add -A
  git update-index --chmod="$mode" .github/scripts/fixture-target.sh
  git -c commit.gpgsign=false commit -qm fixture
  cd - > /dev/null
}
make_runblock_fixture "$work/runblock" -x
expect "BLOCK run-block command 100644 is rejected" 1 "is tracked 100644, not 100755" "$work/runblock"
make_runblock_fixture "$work/runblock-ok" +x
expect "BLOCK run-block command 100755 is accepted" 0 "exec-bit guard OK" "$work/runblock-ok"

# QUOTED PATH FILTER IS NOT AN INVOCATION: a paths-filter entry is a quoted BARE
# path. Honouring a quote in front of a bare path would claim every such entry —
# this repository has one on a file correctly tracked 100644 — so the quote
# counts only in front of ./ . The anchor keeps the sweep non-vacuous.
make_filter_fixture() {
  local dir="$1"
  mkdir -p "$dir/scripts" "$dir/.github/workflows"
  cd "$dir"
  git init -q .
  git config user.email t@example.com
  git config user.name t
  printf '#!/usr/bin/env bash\necho lib\n' > scripts/fixture-target.sh
  printf '#!/usr/bin/env bash\necho anchor\n' > scripts/fixture-anchor.sh
  {
    printf 'on:\n  pull_request:\n    paths:\n'
    printf "      - 'scripts/fixture-target.sh'\n"
    printf 'jobs:\n  j:\n    steps:\n      - run: ./scripts/fixture-anchor.sh\n'
  } > .github/workflows/w.yaml
  git add -A
  git update-index --chmod=-x scripts/fixture-target.sh
  git update-index --chmod=+x scripts/fixture-anchor.sh
  git -c commit.gpgsign=false commit -qm fixture
  cd - > /dev/null
}
make_filter_fixture "$work/filter"
expect "FILTER quoted path-filter entry is not an invocation" 0 "exec-bit guard OK" "$work/filter"
if ((failures > 0)); then
  echo "::error::$failures exec-bit guard assertion(s) failed"
  exit 1
fi

echo "all exec-bit guard assertions passed"
