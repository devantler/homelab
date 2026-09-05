package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflowsDir is where this repository's GitHub Actions live, relative to this
// package.
const workflowsDir = "../../.github/workflows"

// validatorInvocation is the command that actually runs this gate. A workflow
// only counts as covering a trigger if it runs THIS, not merely if it mentions
// the gate by name.
const validatorInvocation = "go run ./scripts/validate-eks-ci-role-policy"

// isolatedChartNamespaceValidatorInvocation renders the reviewed staged-off
// chart and checks every child namespace. It is a separate command because the
// static Go validator runs before KSail is installed in each workflow.
const isolatedChartNamespaceValidatorInvocation = "bash scripts/tests/test-isolated-chart-namespace-rules.sh"

// prodDeployComposite is the shared publish-sign-attest-reconcile action.
// Every route that reaches production goes through it or one of its nested
// sub-actions, which is what makes it a sound proxy for "this job deploys".
const prodDeployComposite = "./.github/actions/deploy-prod"

// workflow is the narrow slice of Actions schema this contract needs.
//
// It is parsed as YAML rather than string-matched on purpose: the workflow
// files describe this very trigger in their comments, so a text search would
// pass on prose alone and keep passing after the trigger itself was deleted.
type workflow struct {
	On   triggerSet     `yaml:"on"`
	Jobs map[string]job `yaml:"jobs"`
}

// job and step are named rather than inlined so the workflow-coverage guards in
// this package share ONE parser. The kubescape baseline guard needs `uses:` and
// `with:` as well as `run:`; giving it a second, near-identical loader would
// duplicate this file's parsing logic and trip the repository's duplication
// gate for no benefit.
type job struct {
	Steps           []step `yaml:"steps"`
	Needs           any    `yaml:"needs"`
	If              string `yaml:"if"`
	ContinueOnError any    `yaml:"continue-on-error"`
}

type step struct {
	Run             string            `yaml:"run"`
	Uses            string            `yaml:"uses"`
	If              string            `yaml:"if"`
	Shell           string            `yaml:"shell"`
	TimeoutMinutes  templatableInt    `yaml:"timeout-minutes"`
	With            stepInputs        `yaml:"with"`
	Env             map[string]string `yaml:"env"`
	ContinueOnError any               `yaml:"continue-on-error"`
}

// templatableInt decodes an Actions integer field that MAY be written as an
// expression. `timeout-minutes: ${{ fromJSON(inputs.t) }}` is a YAML string,
// so decoding straight into an int fails — and because every guard in this file
// shares ONE loader, that failure aborts all of them at once rather than failing
// the single contract the offending workflow touches. A guard suite that one
// unrelated workflow edit can silently switch off is worse than no guard, so an
// expression decodes cleanly and simply satisfies no numeric contract.
type templatableInt struct {
	Value     int
	IsLiteral bool
}

func (t *templatableInt) UnmarshalYAML(node *yaml.Node) error {
	var n int
	if err := node.Decode(&n); err == nil {
		t.Value, t.IsLiteral = n, true

		return nil
	}

	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("timeout-minutes is neither an integer nor an expression: %w", err)
	}

	t.Value, t.IsLiteral = 0, false

	return nil
}

// is reports whether the field is a literal equal to want. An expression is
// never equal to a reviewed constant: its value is not knowable until the
// runner resolves it, so a contract pinning a timeout must not treat it as met.
func (t templatableInt) is(want int) bool { return t.IsLiteral && t.Value == want }

// stepInputs is the slice of an action's `with:` block these contracts read.
// Actions inputs are heterogenous, so unknown keys are simply ignored.
type stepInputs struct {
	Category string `yaml:"category"`
	// Ref is the revision an `actions/checkout` step re-points to. Its
	// ABSENCE is the meaningful state: a checkout without it takes the
	// workflow's own triggering revision, which a sibling gate job in the
	// same workflow has already validated.
	Ref string `yaml:"ref"`
}

// triggerSet is the `on:` block. GitHub accepts three spellings — a mapping
// (`on: {push: {...}}`), a sequence (`on: [push]`) and a bare scalar
// (`on: push`) — and every workflow in this repository currently uses the
// mapping. Decoding all three anyway keeps this guard failing for the ONE
// reason it exists: a genuinely missing push-to-main gate. A strict mapping-only
// decode would instead abort with a parse error the day someone adds an
// unrelated workflow in shorthand, which reads like the contract broke.
//
// The sequence and scalar forms carry no branch filter, so they yield a trigger
// with no branches — correctly not counting as main coverage on their own.
type triggerSet map[string]triggerSpec

func (t *triggerSet) UnmarshalYAML(value *yaml.Node) error {
	*t = make(triggerSet)
	switch value.Kind {
	case yaml.MappingNode:
		return value.Decode((*map[string]triggerSpec)(t))
	case yaml.SequenceNode:
		var names []string
		if err := value.Decode(&names); err != nil {
			return err
		}
		for _, name := range names {
			(*t)[name] = triggerSpec{}
		}
	case yaml.ScalarNode:
		var name string
		if err := value.Decode(&name); err != nil {
			return err
		}
		(*t)[name] = triggerSpec{}
	}
	return nil
}

// triggerSpec captures a trigger's branch filter. `on:` values are heterogenous
// (`merge_group:` is null, `push:` is a mapping), so unmarshalling is lenient
// and a null trigger simply yields no branches.
type triggerSpec struct {
	Branches []string `yaml:"branches"`
}

func (t *triggerSpec) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return nil
	}
	type rawTrigger triggerSpec
	return value.Decode((*rawTrigger)(t))
}

// endsCommand reports whether b terminates a command, so that the next word
// begins a new one. `&&` and `||` are repeats of these single bytes, so
// treating each byte independently is sufficient here.
func endsCommand(b byte) bool {
	switch b {
	case ';', '&', '|', '\n', '(', ')':
		return true
	}
	return false
}

// endsWord reports whether b terminates a word, so a needle followed by b was
// matched whole rather than as the prefix of a longer token.
func endsWord(b byte) bool {
	switch b {
	case ' ', '\t', '\n', ';', '&', '|', ')', '<', '>':
		return true
	}
	return false
}

// assignmentPrefix returns the length of a leading `NAME=value` word, or 0.
// A command may be preceded by any number of these, and the command word is
// still the one after them.
func assignmentPrefix(s string) int {
	i := 0
	for i < len(s) && (s[i] == '_' ||
		(s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
		(i > 0 && s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 || i >= len(s) || s[i] != '=' {
		return 0
	}
	for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' {
		if s[i] == '\'' || s[i] == '"' {
			return 0 // quoted value: too subtle to skip safely, so decline
		}
		i++
	}
	return i
}

// runsCommand reports whether script EXECUTES needle, rather than merely
// mentioning it.
//
// strings.Contains cannot answer that question. It matches a path named in an
// `echo`, sitting in a shell comment, or handed to a different tool as an
// argument — `shellcheck .github/scripts/setup-ksail.sh` is a live example in
// this repository's own ci.yaml. A guard built on it therefore reports a gate
// as covered when nothing runs it, which is exactly the failure this file's
// header comment says the YAML parse exists to prevent: the parse stops a
// workflow's YAML comments from satisfying the guard, but not a shell comment
// or an echo inside the `run:` block it hands back.
//
// The test is positional rather than a deny-list of inert commands: needle must
// begin at a COMMAND WORD. That admits every executable spelling without
// enumerating the text-emitting builtins (`echo`, `printf`, `:`, a heredoc),
// and it stays correct when a new one is invented. It is deliberately strict —
// an unrecognised wrapper makes a covered gate read as UNCOVERED, failing the
// build loudly, rather than passing an absent gate silently.
func runsCommand(script, needle string) bool {
	return scanCommandRuns(script, needle, nil)
}

// runsGate reports whether script runs needle AS A GATE: at a command word,
// and with its failure status still able to fail the step.
//
// runsCommand alone cannot answer that. `bash <gate>.sh || true` executes the
// gate and then throws its verdict away, so a neutralised gate reads as
// covered. That is the same hole as a gate which is merely mentioned, one
// level down: the command runs, and nothing it discovers can stop the build.
// A gate whose failure cannot fail the step is not a gate.
//
// Kept separate from runsCommand deliberately. Most callers are asking the
// plain question "does this script invoke X" — a setup step, for instance,
// where the answer is about presence rather than enforcement. Only a coverage
// assertion about a GATE needs failure propagation, so only those opt in.
// runsGate reports whether script runs needle AS A GATE: the step's exit status
// is that of needle, so a failure there fails the step.
//
// This is a POSITIVE grammar over the run block rather than a search for ways to
// defuse a gate. Seven review rounds established that the search cannot be won:
// `set +e`, then a quoted or expanded operand, then `builtin`/`command`/`eval`,
// then an alias, then `trap`/`exit`/`exec`, then a one-line function body, then
// a leading redirection, then a compound command hiding a `trap` after `then`.
// Each was real and each fix was correct, but shell offers unbounded ways to
// bind a name to a command or to hide one from a lexical scan, so every answer
// bought exactly one spelling.
//
// The grammar inverts that. A block qualifies only when EVERY line is a simple
// command written in a restricted character set, and the LAST such line is the
// gate. Anything else — an operator, a quote, an expansion, a redirection, a
// compound command, an assignment, a reserved word, or a builtin that can bind a
// name or set an exit status — falls outside the grammar and the gate reads as
// UNCOVERED. A shell feature nobody has thought of yet fails the same way, which
// is the property the previous seven rounds could not have.
//
// Soundness rests on one fact: a block's exit status is the status of its last
// command. Within this grammar nothing can reassign it, so a failing gate on the
// last line fails the step.
//
// Both gate steps in this repository already satisfy it — each is two plain
// command lines — so the grammar costs nothing real. See platform#3526.
func runsGate(script, needle string) bool {
	last := ""
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !isSimpleCommandLine(trimmed) {
			return false
		}
		last = trimmed
	}
	if last == "" {
		return false
	}
	return last == needle || strings.HasPrefix(last, needle+" ")
}

// gateGrammarRefusedWords are the leading words a simple command may not have.
//
// The reserved words introduce compound commands, whose bodies this line-based
// grammar does not read — `if true; then trap 'exit 0' ERR; fi` is refused here
// rather than parsed. The rest either assign an exit status (`exit`, `exec`,
// `trap`), or bind a name to a command that could (`eval`, `source`, `.`,
// `alias`, `shopt`, `function`, `builtin`, `command`).
//
// `command -v ksail` is refused with them, which is a real loss of precision: it
// is an ordinary lookup that cannot affect the status. Resolving through the
// wrapper is exactly the kind of special case this grammar exists to stop
// accumulating, so it is refused and the step can be written without it.
var gateGrammarRefusedWords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"case": true, "esac": true, "for": true, "select": true, "while": true,
	"until": true, "do": true, "done": true, "in": true, "time": true,
	"coproc": true, "function": true,
	"exit": true, "exec": true, "trap": true,
	"eval": true, "source": true, ".": true,
	"alias": true, "shopt": true, "builtin": true, "command": true, "set": true,
}

// isSimpleCommandLine reports whether one line is a simple command this grammar
// admits: words drawn from a restricted character set, with a leading word that
// is not refused above.
//
// The character set is the whole defence against shell syntax. It admits what
// real invocations need — letters, digits, and `_ . / : @ + , -` — and nothing
// that can quote, expand, redirect, group, background, or chain. A metacharacter
// anywhere on the line refuses it, so no part of shell grammar has to be
// modelled.
func isSimpleCommandLine(line string) bool {
	for _, r := range line {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ', r == '\t':
		case r == '_', r == '.', r == '/', r == ':', r == '@', r == '+',
			r == ',', r == '-':
		default:
			return false
		}
	}
	first := line
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		first = line[:i]
	}
	return !gateGrammarRefusedWords[first]
}

// failurePropagates reports whether the command whose word ends at i can still
// fail its step. It walks that command's remaining arguments and inspects the
// operator that terminates it.
//
// `||` discards the failure outright. A single `|` hands the step the status of
// the LAST pipeline stage instead — GitHub Actions runs a `run:` block under
// `bash -e`, without `pipefail` — so an earlier stage's failure is lost. A
// trailing `&` backgrounds the command, and its status is never waited for.
// `&&` settles nothing on its own — the AND-OR list continues, and a `||`
// reached later at the same level still discards the failure, so
// `gate && echo ok || true` exits 0 — hence the scan walks past it rather than
// accepting there. `;`, a newline, and end-of-script all leave the failure
// intact; a closing paren does not, because the subshell continues outside it.
//
// Strict in the same direction as the scanner above: a pipeline is refused
// even where the script does set pipefail, because deciding that reliably
// means tracking shell options across the block. Refusing makes a genuine gate
// read as UNCOVERED and fails the build loudly, which is recoverable; the
// other direction passes a defused gate in silence.
func failurePropagates(script string, i int) bool {
	// pending is true while an AND-OR list is waiting for its next command.
	// `&&` at the end of a line continues the list, so the newline after it is
	// NOT a terminator — and bash strips a trailing comment before evaluating
	// the list, so `gate && # note` continues too. Treating either newline as a
	// terminator accepted `gate &&\n echo ok || true`, whose `|| true` still
	// discards the gate's verdict.
	pending := false
	for i < len(script) {
		switch c := script[i]; {
		case c == '\\':
			i += 2
			pending = false
		case c == '<' && i+1 < len(script) && script[i+1] == '<':
			i = skipHeredoc(script, i)
			pending = false
		case c == '\'', c == '"':
			i = skipQuoted(script, i)
			pending = false
		case c == '|':
			// `||` swallows the failure; a lone `|` hides it behind the
			// last stage of the pipeline.
			return false
		case c == '&':
			if i+1 >= len(script) || script[i+1] != '&' {
				// A lone `&` backgrounds the command, so the step never
				// waits for its status.
				return false
			}
			// `&&` does not settle the question. The AND-OR list continues,
			// and a `||` later at this level still discards the failure:
			// `gate && echo ok || true` exits 0. Keep scanning the remainder
			// rather than accepting the gate here.
			i += 2
			pending = true
		case c == '#' && startsShellComment(script, i):
			// Bash removes the comment before evaluating the list, so it
			// settles nothing on its own. Skip its bytes and let the newline
			// that ends it be judged by `pending`, exactly as if the comment
			// were not there.
			for i < len(script) && script[i] != '\n' {
				i++
			}
		case c == ';':
			return true
		case c == '\n':
			if pending {
				// The list continues on the next line; this newline ends no
				// command. Stay pending until a command word appears.
				i++
				continue
			}
			return true
		case c == ')':
			// A subshell hands its status to whatever follows the ')', which this
			// scan has not looked at: `( gate ) || true` discards it out there.
			// Refusing keeps the strict direction — a genuinely enforcing subshell
			// reads as UNCOVERED and fails loudly.
			return false
		case c == ' ', c == '\t':
			// Blanks separate words without starting one, so they neither end
			// a pending continuation nor begin a new command.
			i++
		default:
			i++
			pending = false
		}
	}
	return true
}

// startsShellComment reports whether the '#' at i begins a comment rather than
// sitting inside a word. Bash only treats '#' as a comment at the start of a
// word, so `curl host/path#frag` and `echo a#b` carry no comment at all.
func startsShellComment(script string, i int) bool {
	if i == 0 {
		return true
	}
	switch script[i-1] {
	case ' ', '\t', '\n', ';', '&', '|', '(':
		return true
	}
	return false
}

// scanCommandRuns walks script for needle at a command word. accept, when
// non-nil, is offered the index just past each match and decides whether that
// occurrence counts; scanning continues past a rejected one, so one defused
// invocation does not mask a sound one elsewhere in the same block.
func scanCommandRuns(script, needle string, accept func(end int) bool) bool {
	if needle == "" {
		return false
	}
	atCommandStart := true
	for i := 0; i < len(script); {
		switch c := script[i]; {
		case c == '\\':
			// An escape consumes the next byte, a line continuation
			// included, and never begins a command word.
			atCommandStart = false
			i += 2
			continue
		case c == '<' && i+1 < len(script) && script[i+1] == '<':
			i = skipHeredoc(script, i)
			atCommandStart = false
			continue
		case c == '\'', c == '"':
			i = skipQuoted(script, i)
			atCommandStart = false
			continue
		case c == ' ', c == '\t':
			// Leading blanks do not end the pending command position.
			i++
			continue
		case atCommandStart && redirectionPrefix(script, i) > 0:
			// A redirection may PRECEDE the command name — `> /dev/null trap …`
			// and `2>/dev/null trap …` are both ordinary bash — so the command
			// position survives it. Clearing it here hid a status-setting
			// builtin behind a leading redirect from every scan on this walker.
			i += redirectionPrefix(script, i)
			for i < len(script) && (script[i] == ' ' || script[i] == '\t') {
				i++
			}
			for i < len(script) && !endsWord(script[i]) {
				i++
			}
			continue
		case c == '{', c == '}':
			// A group opens a new command position, so `f() { trap ... ; }`
			// puts `trap` at a command word exactly as a newline would. Without
			// this the body of a one-line function definition is invisible to
			// every scan built on this walker.
			atCommandStart = true
			i++
			continue
		case endsCommand(c):
			atCommandStart = true
			i++
			continue
		case atCommandStart && c == '#':
			// A comment runs to the newline, which then re-arms the
			// command position on the next iteration.
			for i < len(script) && script[i] != '\n' {
				i++
			}
			continue
		case atCommandStart:
			if strings.HasPrefix(script[i:], needle) {
				end := i + len(needle)
				rest := script[end:]
				if rest == "" || endsWord(rest[0]) {
					if accept == nil || accept(end) {
						return true
					}
				}
			}
			if n := assignmentPrefix(script[i:]); n > 0 {
				i += n // still at a command position
				continue
			}
		}
		atCommandStart = false
		i++
	}
	return false
}

// skipQuoted returns the index just past the quoted run starting at i. An
// unterminated quote consumes the remainder, which keeps the scan total.
func skipQuoted(script string, i int) int {
	quote := script[i]
	for i++; i < len(script); i++ {
		if quote == '"' && script[i] == '\\' {
			i++
			continue
		}
		if script[i] == quote {
			return i + 1
		}
	}
	return len(script)
}

// skipHeredoc returns the index just past a heredoc introduced at i, where
// script[i:i+2] is "<<". A heredoc body is inert text, but every line of it
// starts where a command word would, so without this the body of a
// `cat <<'EOF' ... EOF` block reads as a sequence of commands. A here-string
// ("<<<") introduces no body and is left to the ordinary scan. When the
// terminator is missing the remainder is consumed, which keeps the scan total.
func skipHeredoc(script string, i int) int {
	j := i + 2
	if j < len(script) && script[j] == '<' {
		return i + 2 // here-string, not a heredoc
	}
	stripTabs := false
	if j < len(script) && script[j] == '-' {
		stripTabs = true
		j++
	}
	for j < len(script) && (script[j] == ' ' || script[j] == '\t') {
		j++
	}
	var delim strings.Builder
	for j < len(script) {
		c := script[j]
		if c == '\'' || c == '"' {
			j++ // quoting only disables expansion; the word is the same
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || endsCommand(c) {
			break
		}
		delim.WriteByte(c)
		j++
	}
	if delim.Len() == 0 {
		return i + 2
	}
	// The body starts on the line after the one introducing the heredoc.
	for j < len(script) && script[j] != '\n' {
		j++
	}
	for j < len(script) {
		j++ // step past the newline onto the next line
		start := j
		for j < len(script) && script[j] != '\n' {
			j++
		}
		line := script[start:j]
		if stripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == delim.String() {
			return j
		}
		if j >= len(script) {
			break
		}
	}
	return len(script)
}

// shellKeepsErrexit reports whether a step's `shell:` still aborts on a failed
// command. A gate can be defused by the shell it runs under, not only by the
// operators around it: `shell: bash {0}` is a custom template with no `-e`, so a
// failing validator followed by any successful command leaves the step green.
//
// Allow-listed rather than deny-listed, and matched on the documented keywords
// GitHub maps to an errexit invocation: the default (`bash -e`), `bash`
// (`bash --noprofile --norc -eo pipefail`), and `sh` (`sh -e`). Anything else —
// another interpreter, or any custom template carrying `{0}` — reads as
// UNCOVERED and fails the build loudly, which is the same strict direction the
// rest of this file takes.
func shellKeepsErrexit(shell string) bool {
	switch shell {
	case "", "bash", "sh":
		return true
	}
	return false
}

// runsValidator reports whether any job in the workflow actually executes the
// gate.
func (w workflow) runsValidator() bool {
	for _, job := range w.Jobs {
		for _, step := range job.Steps {
			if shellKeepsErrexit(step.Shell) && runsGate(step.Run, validatorInvocation) {
				return true
			}
		}
	}
	return false
}

// runsIsolatedChartNamespaceValidator reports whether THIS job installs KSail
// before executing the rendered-child namespace gate. Keeping both steps in
// the same job matters: setup in another job does not share the runner.
func (j job) runsIsolatedChartNamespaceValidator() bool {
	ksailReady := false
	for _, step := range j.Steps {
		if runsCommand(step.Run, ".github/scripts/setup-ksail.sh") {
			ksailReady = true
		}
		if ksailReady && step.If == "" && step.TimeoutMinutes.is(10) &&
			shellKeepsErrexit(step.Shell) &&
			runsGate(step.Run, isolatedChartNamespaceValidatorInvocation) {
			return true
		}
	}
	return false
}

// deploysProd reports whether THIS job publishes to production through the
// shared deploy composite, in any of its forms. Matching the composite rather
// than a job name is what keeps the guard attached to the deployment ROUTE: a
// renamed or newly added job that reaches production still has to satisfy it.
func (j job) deploysProd() bool {
	for _, step := range j.Steps {
		if step.Uses == prodDeployComposite ||
			strings.HasPrefix(step.Uses, prodDeployComposite+"/") {
			return true
		}
	}
	return false
}

// checksOutExplicitRef reports whether THIS job re-points its checkout at a
// revision other than the one that triggered the workflow. That is the
// property deciding whether a sibling gate job can vouch for what this job
// deploys: with no explicit ref they share a revision, and with one they do
// not.
func (j job) checksOutExplicitRef() bool {
	for _, step := range j.Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With.Ref != "" {
			return true
		}
	}
	return false
}

// runsIsolatedChartNamespaceValidator reports whether ONE job installs KSail
// before executing the rendered-child namespace gate.
func (w workflow) runsIsolatedChartNamespaceValidator() bool {
	for _, job := range w.Jobs {
		if job.runsIsolatedChartNamespaceValidator() {
			return true
		}
	}
	return false
}

// triggersOnPushToMain reports whether the workflow fires on a direct push to
// main. Shared by every push-to-main coverage guard in this package.
func (w workflow) triggersOnPushToMain() bool {
	push, ok := w.On["push"]
	if !ok {
		return false
	}
	for _, branch := range push.Branches {
		if branch == "main" {
			return true
		}
	}
	return false
}

// coversPushToMain reports whether the workflow runs the gate on a direct push
// to main.
func (w workflow) coversPushToMain() bool {
	return w.triggersOnPushToMain() && w.runsValidator()
}

func loadWorkflows(t *testing.T) map[string]workflow {
	t.Helper()

	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		t.Fatalf("read workflows dir: %v", err)
	}
	loaded := make(map[string]workflow)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(workflowsDir, name)) //nolint:gosec // Fixed repository path.
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		var parsed workflow
		if err := yaml.Unmarshal(contents, &parsed); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		loaded[name] = parsed
	}
	if len(loaded) == 0 {
		t.Fatal("no workflows parsed — the guard would pass vacuously")
	}
	return loaded
}

// TestAuthorizationGateRunsOnPushToMain pins the coverage gap that let
// f89efff4 break main invisibly.
//
// ci.yaml gates on `pull_request` and `merge_group`; cd.yaml is
// `workflow_dispatch`. A direct push to main fires none of them, so main's own
// checks stayed green while the authorization surface was broken, and the
// failure surfaced only on unrelated PRs (whose CI builds the merge result and
// therefore inherits main).
func TestAuthorizationGateRunsOnPushToMain(t *testing.T) {
	workflows := loadWorkflows(t)

	covering := make([]string, 0, 1)
	for name, parsed := range workflows {
		if parsed.coversPushToMain() {
			covering = append(covering, name)
		}
	}

	if len(covering) == 0 {
		t.Fatalf("no workflow runs %q on push to main — a direct push to main can "+
			"break the authorization surface with every check on main green. "+
			"Restore a push-triggered workflow that runs the gate.", validatorInvocation)
	}
}

// TestAuthorizationGateGuardIsNotVacuous proves the guard above can actually
// fail. A coverage assertion that cannot go RED is worse than none: it reports
// the hole as closed forever.
//
// The negative controls perturb exactly the two conditions the guard depends
// on, so each must flip it to false on its own.
func TestAuthorizationGateGuardIsNotVacuous(t *testing.T) {
	covering := workflow{
		On: triggerSet{"push": {Branches: []string{"main"}}},
		Jobs: map[string]job{
			"gate": {Steps: []step{{Run: validatorInvocation + " ."}}},
		},
	}
	if !covering.coversPushToMain() {
		t.Fatal("positive control failed: a push-to-main workflow that runs the gate must count")
	}

	t.Run("wrong branch does not count", func(t *testing.T) {
		perturbed := covering
		perturbed.On = triggerSet{"push": {Branches: []string{"release"}}}
		if perturbed.coversPushToMain() {
			t.Fatal("a push trigger on another branch must not satisfy main coverage")
		}
	})

	t.Run("wrong trigger does not count", func(t *testing.T) {
		perturbed := covering
		perturbed.On = triggerSet{"pull_request": {Branches: []string{"main"}}}
		if perturbed.coversPushToMain() {
			t.Fatal("a pull_request trigger must not satisfy push-to-main coverage — " +
				"that is precisely the gap f89efff4 slipped through")
		}
	})

	t.Run("naming the gate without running it does not count", func(t *testing.T) {
		perturbed := covering
		perturbed.Jobs = map[string]job{
			"gate": {Steps: []step{{Run: "echo validate-eks-ci-role-policy"}}},
		}
		if perturbed.coversPushToMain() {
			t.Fatal("merely mentioning the validator must not count as running it")
		}
	})

	t.Run("a shell without errexit does not count", func(t *testing.T) {
		perturbed := covering
		perturbed.Jobs = map[string]job{
			"gate": {Steps: []step{{
				Run:   validatorInvocation + " .\necho continued",
				Shell: "bash {0}",
			}}},
		}
		if perturbed.coversPushToMain() {
			t.Fatal("`shell: bash {0}` is a custom template with no `-e`, so a failing " +
				"gate followed by a successful command leaves the step green")
		}
	})

	t.Run("a defused gate does not count", func(t *testing.T) {
		perturbed := covering
		perturbed.Jobs = map[string]job{
			"gate": {Steps: []step{{Run: validatorInvocation + " . || true"}}},
		}
		if perturbed.coversPushToMain() {
			t.Fatal("`|| true` discards the gate's verdict, so the step passes " +
				"however the gate rules — that must not count as coverage")
		}
	})
}

// TestIsolatedChartNamespaceGateCoversEveryDeploymentRoute prevents the
// reviewed isolated-chart allowlist from outliving the rendered-child proof it
// depends on. These four workflows cover pull requests and merge groups,
// direct pushes to main, the manual production deployment, and the
// disaster-recovery rebuild respectively. Recovery publishes and reconciles a
// revision, so omitting it left a real deployment route ungated while the test
// name claimed otherwise.
func TestIsolatedChartNamespaceGateCoversEveryDeploymentRoute(t *testing.T) {
	workflows := loadWorkflows(t)
	for _, name := range []string{"ci.yaml", "validate-main.yaml", "cd.yaml", "dr-rebuild.yaml"} {
		parsed, ok := workflows[name]
		if !ok {
			t.Errorf("required workflow %s is missing", name)
			continue
		}
		if !parsed.runsIsolatedChartNamespaceValidator() {
			t.Errorf("%s must install KSail and then run %q in the same job", name, isolatedChartNamespaceValidatorInvocation)
		}
	}
}

// sortedKeys yields map keys in a stable order so a failure names the same
// job every run rather than whichever one Go happened to visit first.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestIsolatedChartNamespaceGateCoversARepointedProdDeploy binds the gate to
// the exact checkout it certifies, which the per-workflow guard above cannot
// do.
//
// That guard is satisfied when SOME job in a workflow runs the validator, so a
// workflow holding two deployment routes on two DIFFERENT revisions passes on
// the strength of the first. `ci.yaml` is exactly that shape: the merge-group
// deploy runs on the speculative merge ref, while `heal-prod-on-failure`
// checks out `ref: main` — a revision that may have advanced since — and
// republishes it through the same composite. A chart reaching `main` by a
// route the speculative scan never saw could therefore be published by the
// heal path with its rendered children unchecked, while the per-workflow guard
// still read as covered.
//
// The discriminator is the CHECKOUT, not the job. A deploy job that takes the
// workflow's own revision is already vouched for by the sibling gate job on
// that same revision; requiring every deploy job to re-render the chart would
// duplicate an expensive render and say nothing new. A job that re-points to
// another ref has no such sibling, so it must render on its own checkout. The
// heal job already applies exactly this reasoning to the RGD scan, so this
// extends an established rule to the gate that was missing it.
func TestIsolatedChartNamespaceGateCoversARepointedProdDeploy(t *testing.T) {
	workflows := loadWorkflows(t)
	repointed := 0
	for _, name := range sortedKeys(workflows) {
		for _, jobName := range sortedKeys(workflows[name].Jobs) {
			parsedJob := workflows[name].Jobs[jobName]
			if !parsedJob.deploysProd() || !parsedJob.checksOutExplicitRef() {
				continue
			}
			repointed++
			if !parsedJob.runsIsolatedChartNamespaceValidator() {
				t.Errorf("%s job %q deploys a re-pointed checkout but does not run %q on it",
					name, jobName, isolatedChartNamespaceValidatorInvocation)
			}
		}
	}
	// Fail closed: a renamed composite, or a heal path that stopped pinning its
	// ref, would otherwise leave every assertion above vacuous while the test
	// still passed.
	if repointed == 0 {
		t.Fatalf("found no job combining %q with an explicit checkout ref — this guard is now inert", prodDeployComposite)
	}
}

// TestRepointedProdDeployGuardIsNotVacuous ablates each conjunct of the guard
// above independently, so it cannot pass for the wrong reason — and pins the
// case it must NOT flag.
func TestRepointedProdDeployGuardIsNotVacuous(t *testing.T) {
	gateSteps := []step{
		{Run: ".github/scripts/setup-ksail.sh"},
		{Run: isolatedChartNamespaceValidatorInvocation, TimeoutMinutes: templatableInt{Value: 10, IsLiteral: true}},
	}
	checkoutMain := step{Uses: "actions/checkout@v7.0.1", With: stepInputs{Ref: "main"}}
	checkoutDefault := step{Uses: "actions/checkout@v7.0.1"}
	deployStep := step{Uses: prodDeployComposite}

	covered := job{Steps: append([]step{checkoutMain, deployStep}, gateSteps...)}
	if !(covered.deploysProd() && covered.checksOutExplicitRef() && covered.runsIsolatedChartNamespaceValidator()) {
		t.Fatal("positive control failed: a re-pointed deploy job carrying the gate must satisfy all three conjuncts")
	}

	t.Run("a re-pointed deploy without the gate is caught", func(t *testing.T) {
		ablated := job{Steps: []step{checkoutMain, deployStep}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("a job with no gate step must not report the gate as run")
		}
		if !ablated.deploysProd() || !ablated.checksOutExplicitRef() {
			t.Fatal("the guard must still select this job — otherwise the gap goes unreported")
		}
	})

	// This is the over-strictness control. An earlier draft of the guard keyed
	// on deploysProd alone and flagged ci.yaml/cd.yaml `deploy-prod`, demanding
	// a duplicate render of the very revision a sibling gate job had already
	// validated. Selecting this shape is a bug, not extra safety.
	t.Run("a deploy on the workflow's own revision is not selected", func(t *testing.T) {
		sameRevision := job{Steps: []step{checkoutDefault, deployStep}}
		if sameRevision.checksOutExplicitRef() {
			t.Fatal("a checkout with no ref takes the workflow's revision and must not count as re-pointed")
		}
	})

	t.Run("a re-pointed job that does not deploy is not selected", func(t *testing.T) {
		nonDeploy := job{Steps: []step{checkoutMain, {Run: "echo hello"}}}
		if nonDeploy.deploysProd() {
			t.Fatal("a job that never uses the deploy composite must not be selected")
		}
	})

	t.Run("a nested sub-action of the composite still counts as deploying", func(t *testing.T) {
		nested := job{Steps: []step{checkoutMain, {Uses: prodDeployComposite + "/publish-platform-manifests"}}}
		if !nested.deploysProd() {
			t.Fatal("a nested sub-action reaches production too and must be selected")
		}
	})

	t.Run("a lookalike composite path does not count", func(t *testing.T) {
		lookalike := job{Steps: []step{checkoutMain, {Uses: prodDeployComposite + "-staging"}}}
		if lookalike.deploysProd() {
			t.Fatal("prefix matching must respect the path boundary, or an unrelated action would be selected")
		}
	})
}

// TestIsolatedChartNamespaceGateCoverageIsNotVacuous ablates the ordering and
// same-runner properties independently so the deployment-route guard above
// cannot pass on an inert command or setup performed in another job.
func TestIsolatedChartNamespaceGateCoverageIsNotVacuous(t *testing.T) {
	covered := workflow{Jobs: map[string]job{
		"gate": {Steps: []step{
			{Run: ".github/scripts/setup-ksail.sh"},
			{Run: isolatedChartNamespaceValidatorInvocation, TimeoutMinutes: templatableInt{Value: 10, IsLiteral: true}},
		}},
	}}
	if !covered.runsIsolatedChartNamespaceValidator() {
		t.Fatal("positive control failed: setup followed by the namespace gate in one job must count")
	}

	t.Run("missing gate", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"gate": {Steps: []step{{Run: ".github/scripts/setup-ksail.sh"}}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("KSail setup without the namespace gate must not count")
		}
	})

	t.Run("gate before setup", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"gate": {Steps: []step{
				{Run: isolatedChartNamespaceValidatorInvocation},
				{Run: ".github/scripts/setup-ksail.sh"},
			}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("the namespace gate must not count before KSail is installed")
		}
	})

	t.Run("setup in another job", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"setup": {Steps: []step{{Run: ".github/scripts/setup-ksail.sh"}}},
			"gate":  {Steps: []step{{Run: isolatedChartNamespaceValidatorInvocation}}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("KSail setup in another runner job must not count")
		}
	})

	t.Run("unbounded render", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"gate": {Steps: []step{
				{Run: ".github/scripts/setup-ksail.sh"},
				{Run: isolatedChartNamespaceValidatorInvocation},
			}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("an unbounded chart render must not satisfy the namespace gate")
		}
	})

	t.Run("shell without errexit", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"gate": {Steps: []step{
				{Run: ".github/scripts/setup-ksail.sh"},
				{
					Run:            isolatedChartNamespaceValidatorInvocation + "\necho continued",
					Shell:          "bash {0}",
					TimeoutMinutes: templatableInt{Value: 10, IsLiteral: true},
				},
			}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("a gate under a shell template without `-e` cannot fail its step, " +
				"so it must not satisfy the coverage guard")
		}
	})

	t.Run("defused gate", func(t *testing.T) {
		ablated := workflow{Jobs: map[string]job{
			"gate": {Steps: []step{
				{Run: ".github/scripts/setup-ksail.sh"},
				{
					Run:            isolatedChartNamespaceValidatorInvocation + " || true",
					TimeoutMinutes: templatableInt{Value: 10, IsLiteral: true},
				},
			}},
		}}
		if ablated.runsIsolatedChartNamespaceValidator() {
			t.Fatal("a gate whose failure is discarded by `|| true` runs but " +
				"cannot fail the step, so it must not satisfy the coverage guard")
		}
	})
}

// TestRunsCommandRejectsInertMentions is the non-vacuity proof for the
// coverage guards above. Every case here names the gate exactly as an
// executable invocation would, and none of them runs it — so a guard built on
// strings.Contains passes all of them while the gate is absent. The
// `shellcheck` case is not hypothetical: ci.yaml really does pass this script
// to shellcheck as an argument in a step that never executes it.
func TestRunsCommandRejectsInertMentions(t *testing.T) {
	const needle = ".github/scripts/setup-ksail.sh"
	for name, script := range map[string]string{
		"echoed":              "echo .github/scripts/setup-ksail.sh",
		"echoed quoted":       "echo \".github/scripts/setup-ksail.sh\"",
		"echoed single quote": "echo '.github/scripts/setup-ksail.sh'",
		"printed":             "printf '%s\\n' .github/scripts/setup-ksail.sh",
		"whole-line comment":  "# .github/scripts/setup-ksail.sh\ntrue",
		"indented comment":    "  \t# .github/scripts/setup-ksail.sh",
		"comment after cmd":   "true # .github/scripts/setup-ksail.sh",
		"comment after &&":    "true && # .github/scripts/setup-ksail.sh",
		"argument to a tool":  "shellcheck .github/scripts/setup-ksail.sh scripts/tests/test-setup-ksail.sh",
		"inside a longer arg": "cat prefix.github/scripts/setup-ksail.sh",
		"prefix of a token":   ".github/scripts/setup-ksail.sh.bak",
		"heredoc body":        "cat <<'EOF'\n.github/scripts/setup-ksail.sh\nEOF",
	} {
		if runsCommand(script, needle) {
			t.Errorf("%s: reported as executed, but %q only MENTIONS the gate", name, script)
		}
	}
}

// TestRunsCommandAcceptsExecutableForms is the other half: the guard must stay
// true for every spelling a workflow legitimately uses, or tightening it would
// simply move the failure from silent-pass to false-alarm.
func TestRunsCommandAcceptsExecutableForms(t *testing.T) {
	const needle = ".github/scripts/setup-ksail.sh"
	for name, script := range map[string]string{
		"bare":             ".github/scripts/setup-ksail.sh",
		"trailing newline": ".github/scripts/setup-ksail.sh\n",
		"with arguments":   ".github/scripts/setup-ksail.sh --verbose",
		"indented":         "  .github/scripts/setup-ksail.sh",
		"after a newline":  "set -euo pipefail\n.github/scripts/setup-ksail.sh",
		"after &&":         "true && .github/scripts/setup-ksail.sh",
		"after ||":         "false || .github/scripts/setup-ksail.sh",
		"after ;":          "true; .github/scripts/setup-ksail.sh",
		"after a pipe":     "true | .github/scripts/setup-ksail.sh",
		"after a comment":  "# install ksail\n.github/scripts/setup-ksail.sh",
		"env prefix":       "KSAIL_VERSION=1.2.3 .github/scripts/setup-ksail.sh",
		"two env prefixes": "A=1 B=2 .github/scripts/setup-ksail.sh",
		"redirected":       ".github/scripts/setup-ksail.sh >/dev/null",
		"after a subshell": "(true) && .github/scripts/setup-ksail.sh",
		"after an echo":    "echo installing\n.github/scripts/setup-ksail.sh",
	} {
		if !runsCommand(script, needle) {
			t.Errorf("%s: reported as absent, but %q EXECUTES the gate", name, script)
		}
	}
}

// TestRunsCommandMatchesTheOtherGateInvocations keeps the two multi-word
// needles honest: they contain spaces, so a whole-word check has to compare the
// needle as a phrase rather than a single token.
func TestRunsCommandMatchesTheOtherGateInvocations(t *testing.T) {
	if !runsCommand("go run ./scripts/validate-eks-ci-role-policy .", validatorInvocation) {
		t.Error("the real validator invocation was not recognised as executed")
	}
	if runsCommand("echo go run ./scripts/validate-eks-ci-role-policy", validatorInvocation) {
		t.Error("an echoed validator invocation was reported as executed")
	}
	if !runsCommand("bash scripts/tests/test-isolated-chart-namespace-rules.sh",
		isolatedChartNamespaceValidatorInvocation) {
		t.Error("the real isolated-chart invocation was not recognised as executed")
	}
	if runsCommand("# bash scripts/tests/test-isolated-chart-namespace-rules.sh",
		isolatedChartNamespaceValidatorInvocation) {
		t.Error("a commented-out isolated-chart invocation was reported as executed")
	}
}

// TestRunsGateRequiresFailurePropagation pins the grammar runsGate admits.
//
// runsCommand answers "does this block invoke the gate". This answers the
// stronger question "does the block's exit status BECOME the gate's" — and it
// answers it by admitting only a restricted shape rather than by hunting for
// ways to defuse a gate, which seven review rounds showed cannot be won.
//
// Every script in both tables RUNS the gate, so the tables separate "invoked"
// from "enforcing" and never merely "matched".
func TestRunsGateRequiresFailurePropagation(t *testing.T) {
	const gate = isolatedChartNamespaceValidatorInvocation

	enforcing := []string{
		gate,
		gate + " .",
		gate + "\n",
		"\n" + gate + "\n",
		"# lint first\nshellcheck x.sh\n" + gate,
		// The shape both real gate steps use.
		"shellcheck scripts/tests/test-isolated-chart-namespace-rules.sh\n" + gate,
		"go test ./scripts/validate-eks-ci-role-policy\n" + gate,
		"./scripts/setup.sh\n" + gate,
		"ksail version\n" + gate,
	}
	for _, script := range enforcing {
		if !runsGate(script, gate) {
			t.Errorf("a gate whose failure reaches the step must count: %q", script)
		}
	}

	defused := []string{
		// Operators that discard or replace the gate's status.
		gate + " || true",
		gate + " || :",
		gate + " || echo ignored",
		gate + " | tee gate.log",
		gate + " &",
		"( " + gate + " ) || true",
		gate + " && echo ok || true",
		// A later command supplies the step's status instead of the gate.
		gate + " ; echo done",
		gate + " && echo ok",
		gate + "\necho after",
		// Every bypass the seven review rounds produced. None is matched by a
		// rule naming it: each fails the grammar because it needs a
		// metacharacter or a refused leading word.
		"set +e\n" + gate + "\necho continued",
		"set \"+e\"\n" + gate + "\necho continued",
		"option=e\nset +${option}\n" + gate + "\necho continued",
		"builtin set +e\n" + gate + "\necho continued",
		"command set +e\n" + gate + "\necho continued",
		"eval 'set +e'\n" + gate + "\necho continued",
		"shopt -s expand_aliases\nalias d=\"set +e\"\nd\n" + gate,
		"shopt -s expand_aliases\nalias t=\"trap 'exit 0' ERR\"\nt\n" + gate,
		"f() { trap 'exit 0' ERR; }\nf\n" + gate,
		"trap 'exit 0' ERR\n" + gate,
		"trap 'exit 0' EXIT\n" + gate,
		"exit 0\n" + gate,
		"exec 2>/dev/null\n" + gate,
		"> /dev/null trap 'exit 0' ERR\n" + gate,
		"2>/dev/null trap 'exit 0' ERR\n" + gate,
		"if true; then trap 'exit 0' ERR; fi\n" + gate,
		// CONSERVATIVE REFUSALS — each of these is genuinely enforcing when run,
		// and the grammar refuses it anyway. That cost is the point: admitting
		// them means resolving `set` operands, wrappers and lookups, which is
		// the special-casing the previous seven rounds accumulated and never
		// finished. A step written without them is accepted, and both real gate
		// steps already are.
		"set -e\n" + gate,
		"set +e\n" + gate,
		"command -v ksail\n" + gate,
		"builtin echo hello\n" + gate,
		gate + " ;",
		gate + " # done",
	}
	for _, script := range defused {
		if !runsCommand(script, gate) {
			t.Fatalf("precondition: runsCommand must still see the gate run in %q — "+
				"otherwise this case proves nothing about failure propagation", script)
		}
		if runsGate(script, gate) {
			t.Errorf("a gate that cannot fail the step must not count: %q", script)
		}
	}
}

// redirectionPrefix returns the length of a redirection operator starting at i,
// including any leading file-descriptor digits, or 0 when there is none.
//
// The digits matter: `2>/dev/null trap …` puts `trap` at a command word exactly
// as `> /dev/null trap …` does, but consuming `2` as an ordinary word first
// clears the command position and hides it.
func redirectionPrefix(script string, i int) int {
	j := i
	for j < len(script) && script[j] >= '0' && script[j] <= '9' {
		j++
	}
	if j >= len(script) || (script[j] != '<' && script[j] != '>') {
		return 0
	}
	j++
	for j < len(script) && (script[j] == '<' || script[j] == '>' || script[j] == '&') {
		j++
	}
	return j - i
}
