#!/usr/bin/env bash
#
# Fail when a script this repository invokes DIRECTLY is not tracked executable.
#
# THE RULE THIS ENFORCES: if anything under `.github/` or `scripts/` runs a script
# as `./scripts/<name>.sh`, that path must be tracked `100755`.
#
# Why the tracked mode and not the file on disk. CI clones from git, so the mode
# the runner receives is the one in the index. A local `chmod +x` that was never
# committed leaves the working tree executable and the clone not — which is
# precisely the broken state, and precisely the state a `test -x` check passes on.
# This guard therefore reads `git ls-files -s` and never the filesystem.
#
# Why a guard rather than the one-off fix. Caught live on #3530:
# `scripts/verify-matcher-accepts-digest.sh` was committed `100644` while a
# composite action invoked it as `run: ./scripts/verify-matcher-accepts-digest.sh`.
# On a Unix runner that step dies `permission denied` BEFORE the gate verifies
# anything — a promotion gate that is present, reviewed green, and inert. Nothing
# that runs could see it: shellcheck was clean, `bash <file>` passed, and the
# script's own 19-assertion suite passed, because none of them `exec` the file.
# The class has been introduced three separate times, twice via the
# `awk … > tmp && mv` idiom, which silently drops the bit while leaving the
# content byte-correct.
#
# 🔴 THE REQUIREMENT IS DERIVED FROM THE INVOCATION, NEVER FROM A LIST.
#
# A hard-coded list of "scripts that need the bit" goes stale in the dangerous
# direction: a script that GAINS a direct invocation is not on the list, so the
# one change that creates the exposure is the one the guard cannot see. Scanning
# for the invocation shape means a script that moves to `bash scripts/...`
# correctly stops requiring the bit, and one that moves the other way starts
# requiring it, with no list to maintain.
#
# 🔴 AN INTERPRETER PREFIX IS NOT A DIRECT INVOCATION.
#
# an interpreter-prefixed invocation (bash, sh, source) hands
# the file to an interpreter, which does not need the execute bit. Counting those
# would demand the bit on library files that are correctly non-executable — a
# false refusal on eleven files in this repository today. Only an occurrence with
# no interpreter in front of it is a direct invocation.
#
# 🔴 THE FILE-TYPE FILTER IS LOAD-BEARING, NOT TIDINESS.
#
# Only workflow/action YAML and shell scripts are scanned, because only those
# execute. Widening it to every file counts invocation shapes that appear inside
# Go test fixtures and Go comments as real invocations — measured here: three
# such paths exist in this repository today, all of them string literals in
# `*_test.go` or a comment, none of them ever run. A guard that demanded the
# execute bit on those would fail the build over files that do not exist.
#
# 🔴 A COMMENT IS NOT AN INVOCATION.
#
# This detector is a text scan over files that carry long explanatory comments —
# including this one — so prose naming an invocation shape would be counted as an
# invocation. That is not hypothetical: the first run of this guard reported a
# violation against a path that exists only in the paragraph above. Lines whose
# first non-whitespace character is `#` are therefore dropped before scanning,
# which is correct for both halves: such a line is executed neither by the shell
# nor by Actions. An inline trailing comment is not stripped, so keep any prose
# example of an invocation on its own comment line.
#
# ⚠️ FINDING NO DIRECT INVOCATION AT ALL IS CANNOT-CHECK, NEVER A CLEAN PASS.
#
# The detector is a text scan, so a change to the invocation shape — or to this
# script's own regex — could silently match nothing and report success over a tree
# it never examined. An empty sweep is the shape of a broken detector far more
# often than of a repository that stopped invoking anything, so it exits non-zero.

set -euo pipefail

repo_root="${1:-.}"
cd "$repo_root"

status=0

# Tracked mode per path, from the INDEX. `git ls-files -s` prints
# `<mode> <object> <stage>\t<path>`.
#
# Both roots are inventoried. `.github/scripts/` holds the CI installers, which
# a `run:` step executes as its command and which therefore need the bit exactly
# as much as anything under `scripts/`.
modes="$(git ls-files -s -- 'scripts/*.sh' 'scripts/**/*.sh' '.github/scripts/*.sh' '.github/scripts/**/*.sh')"
if [[ -z "$modes" ]]; then
  echo "::error::found no tracked *.sh under scripts/ or .github/scripts/; the exec-bit sweep examined nothing, so its result proves nothing"
  exit 1
fi

# 🔴 TWO INVOCATION SHAPES EXIST, AND ONE OF THEM CARRIES NO `./`.
#
# An explicitly-relative `./scripts/x.sh` can stand wherever a command can, so it
# is matched on the character in front of it. A BARE `scripts/x.sh` cannot be
# matched that way, because the identical text is also how a path filter entry
# and a shellcheck argument are written; counting those would fail the build over
# files nothing runs. `.github/scripts/kyverno-version.sh` is exactly that case —
# it appears as a filter entry and as a `bash`-prefixed call, and is correctly
# tracked 100644. The bare form is therefore recognised only as the command of a
# `run:` step, which is the position that actually execs it.
#
# 🔴 A SHELL QUOTE IS A DELIMITER ONLY IN FRONT OF `./`.
#
# `run: "./scripts/x.sh"` execs the file and needs the bit. Honouring a quote in
# front of a bare path would re-admit every quoted filter entry, so the quote is
# accepted only where a `./` follows it.
#
# BSD grep has no lookbehind, so each leading delimiter is spelled as a class.
readonly SCRIPT_PATH_RE='(\.github/)?scripts/[A-Za-z0-9_./-]+\.sh'
readonly LEADING_DELIM='(^|[[:space:]|&;("'"'"'])'

scan="$(
  grep -rhE -v '^[[:space:]]*#' --include='*.yaml' --include='*.yml' --include='*.sh' \
    -r .github scripts 2>/dev/null || true
)"

invocations="$(
  {
    printf '%s\n' "$scan" |
      grep -oE "${LEADING_DELIM}([A-Za-z0-9_.-]+[[:space:]]+)?\./${SCRIPT_PATH_RE}" || true
    printf '%s\n' "$scan" |
      grep -oE "run:[[:space:]]+([A-Za-z0-9_.-]+[[:space:]]+)?(\./)?${SCRIPT_PATH_RE}" || true
    # A run block puts the command at the START of its own line. But line-leading
    # position is command position only when the PREVIOUS line did not end in a
    # backslash: a continuation line is an ARGUMENT list, and this repository has
    # exactly that shape, continuing a shellcheck call across several lines over
    # library files correctly tracked 100644. A stateless line-leading match
    # reports those as invocations and fails the build. awk carries that one bit
    # of state. The pattern travels via ENVIRON because the -v option expands
    # escape sequences in the value and would eat the backslashes.
    GUARD_LINE_RE="^[[:space:]]*(\./)?${SCRIPT_PATH_RE}" \
      awk '!cont && $0 ~ ENVIRON["GUARD_LINE_RE"] { print }
           { cont = ($0 ~ /\\[[:space:]]*$/) }' <<<"$scan" || true
  }
)"

direct=""
while IFS= read -r occurrence; do
  [[ -n "$occurrence" ]] || continue

  # The word immediately before the path, if any. `run:` is the step keyword
  # rather than a command, so it is stripped alongside the leading delimiters.
  prefix="$(
    printf '%s' "$occurrence" |
      sed -E "s|(\./)?${SCRIPT_PATH_RE}\$||" |
      sed -E 's|^run:||' |
      tr -d '[:space:]'
  )"
  case "$prefix" in
    "" | "&&" | "||" | "|" | ";" | "(" | '"' | "'") ;;     # nothing in front: a direct invocation
    bash | sh | zsh | dash | ksh | source | .) continue ;; # handed to an interpreter
    sudo | exec | time | env | command | nohup | xargs) ;; # a wrapper that still execs the file
    *) continue ;;                                         # an argument to some other command, which does not exec it
  esac

  path="$(printf '%s' "$occurrence" | grep -oE "(\./)?${SCRIPT_PATH_RE}" | sed 's|^\./||')"
  direct="${direct}${path}"$'\n'
done <<EOF
$invocations
EOF
direct="$(printf '%s' "$direct" | sort -u | grep -v '^$' || true)"

if [[ -z "$direct" ]]; then
  echo "::error::found no directly-invoked script under .github/ or scripts/; the exec-bit sweep examined nothing, so its result proves nothing"
  exit 1
fi

checked=0
while IFS= read -r path; do
  [[ -n "$path" ]] || continue

  mode="$(printf '%s\n' "$modes" | awk -v p="$path" -F'\t' '$2 == p {split($1, a, " "); print a[1]}')"
  if [[ -z "$mode" ]]; then
    # Not tracked, so out of scope here. This is overwhelmingly a path a test
    # CONSTRUCTS as a string rather than one anything runs — a text scan cannot
    # tell `printf ./scripts/fixture.sh` from an invocation, and this repository
    # has such a test. Claiming a violation on it would fail the build over a
    # file that does not exist. A genuinely missing script is a different and
    # much louder failure: the very first run dies "no such file", with none of
    # the silence that makes the exec bit worth a guard.
    continue
  fi

  checked=$((checked + 1))

  if [[ "$mode" != "100755" ]]; then
    echo "::error file=$path::'$path' is invoked directly (./$path) but is tracked $mode, not 100755. CI clones from git, so the runner receives $mode and the step dies 'permission denied' before it checks anything. Fix with: git update-index --chmod=+x '$path'"
    status=1
  fi
done <<EOF
$direct
EOF

if ((checked == 0)); then
  echo "::error::resolved no tracked mode for any directly-invoked script; the sweep proved nothing"
  exit 1
fi

if ((status == 0)); then
  echo "exec-bit guard OK; $checked directly-invoked script(s) are tracked 100755"
fi

exit "$status"
