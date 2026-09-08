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
modes="$(git ls-files -s -- 'scripts/*.sh' 'scripts/**/*.sh' '.github/*.sh' '.github/**/*.sh')"
if [[ -z "$modes" ]]; then
  echo "::error::found no tracked *.sh under scripts/ or .github/; the exec-bit sweep examined nothing, so its result proves nothing"
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
# 🔴 TOKEN_RE MATCHES ANY WHITESPACE-DELIMITED WORD, AND THAT IS DELIBERATE.
#
# It spells what a prefix WORD may look like, never which prefixes are
# admissible — that is the classifier's job. Enumerating characters here is the
# blacklist trap the classifier comment below describes, one level up: a
# character class that omitted `"`, `$` and braces let `FOO="${BAR}" scripts/x.sh`
# escape extraction entirely, so the classifier — which reads `NAME=value` as a
# transparent assignment and would have judged it correctly — never saw it.
#
# This does not re-admit a quoted filter entry. The risk there is a quote
# ADJACENT to the path (`- 'scripts/x.sh'`), where no whitespace separates the
# two, so the quote is never a word of its own and the path never starts a match.
#
# BSD grep has no lookbehind, so each leading delimiter is spelled as a class.
readonly SCRIPT_PATH_RE='(\.github|scripts)/[A-Za-z0-9_./-]+\.sh'
readonly LEADING_DELIM='(^|[[:space:]|&;(]|(^|[[:space:]|&;(])["'"'"'])'
readonly TOKEN_RE='[^[:space:]]+'

scan="$(
  grep -rhE -v '^[[:space:]]*#' --include='*.yaml' --include='*.yml' --include='*.sh' \
    -r .github scripts 2>/dev/null || true
)"

# 🔴 SPLIT AT `&&` / `||` BEFORE EXTRACTING, NOT ONLY WHILE CLASSIFYING.
#
# Resetting the classifier at a separator fixes `echo ready && ./scripts/x.sh`,
# where the swallowed segment is the harmless one. It does NOT fix the mirror
# image, `./scripts/a.sh && bash ./scripts/b.sh`: `grep -o` takes the longest
# leftmost match, so BOTH paths land in one occurrence that ends at b.sh, the
# classifier judges it by b.sh's `bash` prefix, and a.sh — genuinely execed and
# possibly 100644 — never becomes an occurrence of its own to judge. Splitting
# first gives each command its own segment, so each path is extracted in its own
# command position.
#
# Only whitespace-delimited `&&` and `||` are split. `;` and `|` are deliberately
# NOT, because splitting is the FALSE-POSITIVE direction — every new segment
# creates a fresh command position — and those two appear inside quoted strings
# and YAML block scalars far too often to treat as separators textually.
segmented="$(printf '%s\n' "$scan" | sed -E 's/[[:space:]]+(\&\&|\|\|)[[:space:]]+/\n/g')"

invocations="$(
  {
    printf '%s\n' "$segmented" |
      grep -oE "${LEADING_DELIM}(${TOKEN_RE}[[:space:]]+)*\./${SCRIPT_PATH_RE}" || true
    printf '%s\n' "$segmented" |
      grep -oE "run:[[:space:]]+[\"']?(${TOKEN_RE}[[:space:]]+)*(\./)?${SCRIPT_PATH_RE}" || true
    # A run block puts the command at the START of its own line. But line-leading
    # position is command position only when the PREVIOUS line did not end in a
    # backslash: a continuation line is an ARGUMENT list, and this repository has
    # exactly that shape, continuing a shellcheck call across several lines over
    # library files correctly tracked 100644. A stateless line-leading match
    # reports those as invocations and fails the build. awk carries that one bit
    # of state and nothing else; the extraction is left to grep so the emitted
    # occurrence STOPS at the path instead of running to the end of the line,
    # which is what lets a trailing argument coexist with a line-leading command.
    awk '!cont { print }
         { cont = ($0 ~ /\\[[:space:]]*$/) }' <<<"$segmented" |
      grep -oE "^[[:space:]]*(${TOKEN_RE}[[:space:]]+)*(\./)?${SCRIPT_PATH_RE}" || true
  }
)"

direct=""
while IFS= read -r occurrence; do
  [[ -n "$occurrence" ]] || continue

  # Everything in front of the path. `run:` is the step keyword rather than a
  # command, so it is stripped alongside the leading delimiters.
  prefix="$(
    printf '%s' "$occurrence" |
      sed -E "s#(\./)?${SCRIPT_PATH_RE}\$##" |
      sed -E 's|^run:||'
  )"

  # 🔴 EXTRACTION IS PERMISSIVE; THIS WALK IS THE WHITELIST THAT DECIDES.
  #
  # Enumerating admissible PREFIX SHAPES in the extraction regex instead is what
  # produced repeated review rounds each finding one more spelling — a bare path
  # behind two or more words (`env FOO=1 scripts/x.sh`, `FOO=1 scripts/x.sh`,
  # `sudo -E scripts/x.sh`) escaped extraction entirely, so this classifier,
  # which would have judged all three correctly, never ran on them. Extraction
  # now captures however many words sit in front of the path and every decision
  # is made here, where a form that is not provably still an exec is discarded.
  # 🔴 `;` BINDS TO THE PRECEDING WORD, SO IT MUST BE TOKENISED, NOT JUST MATCHED.
  #
  # Bash needs no whitespace before a semicolon, so `echo ready; scripts/x.sh`
  # yields the prefix word `ready;` — which hits the catch-all and discards the
  # occurrence, while the `;` arm below never sees it. That is a fail-open: a
  # directly-execed script tracked 100644 goes unchecked whenever another
  # invocation satisfies anti-vacuity. Splitting `;` into its own word here lets
  # the existing separator arm do its job, and does it in the CLASSIFIER rather
  # than in extraction on purpose — a `;` inside a quoted string still only
  # yields a stray reset within one occurrence's prefix, where the words around
  # it are still judged, instead of manufacturing a new command position for the
  # whole line the way an extraction split would.
  prefix="${prefix//;/ ; }"
  read -ra prefix_tokens <<<"$prefix"
  reaches_path=1
  saw_wrapper=0
  for token in ${prefix_tokens+"${prefix_tokens[@]}"}; do
    case "$token" in
      # 🔴 A SEPARATOR RESETS THE WALK; IT DOES NOT MERELY PASS.
      #
      # Extraction is greedy, so one occurrence can span several commands
      # (`echo ready && ./scripts/x.sh`). Judging it by whatever came first
      # discarded it at `echo` and never reached the `&&` proving a FRESH
      # command position follows — the guard then reported success over a
      # script the step genuinely execs. State is therefore per-SEGMENT:
      # everything before the separator is spent.
      "&&" | "||" | "|" | ";" | "(")
        reaches_path=1
        saw_wrapper=0
        ;;
      if | elif | while | until | then | do | else | "!" | "{") # control keyword: likewise
        reaches_path=1
        saw_wrapper=0
        ;;
      # A quote is TRANSPARENT — never a reset. It marks a command position in
      # `run: "./scripts/x.sh"`, but in `foo "./scripts/x.sh"` the path is an
      # ARGUMENT to foo, and resetting here would resurrect exactly that.
      '"' | "'") ;;
      -*)
        # An option, admissible only as an option TO a wrapper already accepted.
        # A bare leading `-` is the YAML sequence marker, which introduces a list
        # entry — a path filter, not a command.
        if ((saw_wrapper == 0)); then
          reaches_path=0
        fi
        ;;
      *=*) ;;                                                     # NAME=value: an environment assignment is transparent
      sudo | exec | time | env | command | nohup | xargs)          # a wrapper that still execs the file
        saw_wrapper=1
        ;;
      bash | sh | zsh | dash | ksh | source | .)                   # handed to an interpreter
        reaches_path=0
        ;;
      *)                                                           # an argument to some other command, which does not exec it
        reaches_path=0
        ;;
    esac
  done
  ((reaches_path == 1)) || continue

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
