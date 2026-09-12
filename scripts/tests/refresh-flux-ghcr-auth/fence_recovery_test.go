package refreshfluxghcrauth

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The fence report is the supported answer to "prove the prior process is dead
// before explicitly recovering". It must run when a deploy is already refusing
// to start, so it may not depend on the credential path, and it must never
// mutate: releasing a fence is the operator's explicit step, because a Talos
// write cannot be fenced and a surviving holder could still be alive.
func TestFenceReportRunsReadOnlyAndWithoutTheCredentialPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	result := f.runHelper(validConfig(), []string{"--fences"}, nil)

	requireSuccessResult(t, result)
	if !strings.Contains(result.stdout, "GHCR deploy fences") {
		t.Errorf("fence report missing its header; stdout = %q", result.stdout)
	}
	if _, err := os.Stat(f.patchCapture); !os.IsNotExist(err) {
		t.Errorf("fence report wrote the root credential patch (%v); it must not touch the credential path", err)
	}
	for _, forbidden := range []string{"::error::", "command not found"} {
		if strings.Contains(result.stdout+result.stderr, forbidden) {
			t.Errorf("fence report emitted %q; output = %q", forbidden, result.stdout+result.stderr)
		}
	}
}

func TestFenceReportRejectsUnknownFlagsAndAdvertisesItself(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	result := f.runHelper(validConfig(), []string{"--not-a-flag"}, nil)

	if result.exitCode != 64 {
		t.Errorf("unknown flag exit = %d, want 64", result.exitCode)
	}
	if !strings.Contains(result.stderr, "--fences") {
		t.Errorf("usage does not advertise --fences; stderr = %q", result.stderr)
	}
}

// A PID belongs to a runner that no longer exists, so an identity built only
// from one cannot be checked for liveness. Every fence reuses the lease holder,
// so recording the run reference once makes all of them decidable.
func TestFenceHolderIdentityCarriesTheGitHubRunReference(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	requireContains(t, script, `sync_lease_holder="${desired_revision:0:16}-$(fence_run_segment)-$$-${RANDOM}"`)
	requireContains(t, script, `printf 'gh%s.%s' "${GITHUB_RUN_ID}" "${GITHUB_RUN_ATTEMPT:-1}"`)
	// Both policy fences derive from the lease holder, so they inherit it.
	requireContains(t, script, `flux_policy_parent_owner="${sync_lease_holder}"`)
	requireContains(t, script, `flux_policy_handoff_owner="${sync_lease_holder}"`)
}

// A refusal that names no recovery route is what turned this class of stall
// into archaeology twice on 2026-08-09.
func TestFenceRefusalsPointAtTheReportAndTheRunbook(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	runbook := readRepositoryFile(t, "docs/dr/runbook.md")

	refusals := []string{
		"holds the synchronization lease",
		"already owns the image-verification policy handoff",
		// A run blocked on the PARENT fence stops before it can reach the
		// child-handoff refusal, so it needs its own pointer or the staged-fence
		// case the report exists for stays undiscoverable.
		"The parent Flux reconciliation is malformed or already suspended",
	}
	for _, refusal := range refusals {
		index := strings.Index(script, refusal)
		if index < 0 {
			t.Fatalf("refusal %q not found", refusal)
		}
		line := script[index:]
		if end := strings.Index(line, "\n"); end >= 0 {
			line = line[:end]
		}
		if !strings.Contains(line, "--fences") {
			t.Errorf("refusal %q does not name the fence report: %s", refusal, line)
		}
		if !strings.Contains(line, "runbook.md") {
			t.Errorf("refusal %q does not name the runbook: %s", refusal, line)
		}
	}

	requireContains(t, runbook, "Recover an orphaned GHCR deploy fence")
	// The recovery procedure is worthless if it does not stop the operator
	// releasing a fence that a running deploy legitimately holds.
	requireContains(t, runbook, "gh run view <run-id>")
}

// jsonPatchOps returns the {op, path} pairs of every JSON Patch operation in a
// snippet, normalized so a release command can be compared against the release
// function it must mirror.
func jsonPatchOps(snippet string) []string {
	pattern := regexp.MustCompile(`\{op:\s*"([a-z]+)",\s*path:\s*(\$?[A-Za-z_/."]+)`)
	matches := pattern.FindAllStringSubmatch(snippet, -1)
	ops := make([]string, 0, len(matches))
	for _, match := range matches {
		ops = append(ops, match[1]+" "+strings.Trim(match[2], `"`))
	}
	sort.Strings(ops)
	return ops
}

func functionBody(t *testing.T, script, name string) string {
	t.Helper()
	start := requireIndex(t, script, "\n"+name+"() {")
	rest := script[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("no closing brace for %s", name)
	}
	return rest[:end]
}

// The printed recovery command is only useful if it mirrors the release the
// script itself performs. The parent fence carries NO `reconcile: disabled` —
// only the child handoff does — so emitting that test op for the parent makes
// the whole patch fail its own precondition, and the operator cannot release
// the root Kustomization at all. Compare the op sets rather than asserting on
// substrings: the defect was a mismatch, so a mismatch is what must be caught.
func TestFenceReleaseCommandsMirrorTheReleaseTheyStandInFor(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	command := functionBody(t, script, "fence_kustomization_release_patch")
	split := strings.Index(command, "\n  else\n")
	if split < 0 {
		t.Fatal("expected fence_kustomization_release_patch to branch child vs parent")
	}
	childCommand, parentCommand := command[:split], command[split:]

	cases := []struct {
		name    string
		emitted string
		release string
	}{
		{"child handoff", childCommand, functionBody(t, script, "resume_flux_policy_handoff")},
		{"parent", parentCommand, functionBody(t, script, "resume_flux_policy_parent")},
	}
	for _, testCase := range cases {
		emitted := jsonPatchOps(testCase.emitted)
		release := jsonPatchOps(testCase.release)
		if len(emitted) == 0 || len(release) == 0 {
			t.Fatalf("%s: parsed no operations (emitted=%d release=%d)",
				testCase.name, len(emitted), len(release))
		}
		if !reflect.DeepEqual(emitted, release) {
			t.Errorf("%s: recovery command does not mirror its release function\n  command: %v\n  release: %v",
				testCase.name, emitted, release)
		}
	}
}

// Every fence outlives the runner that took it, so a node owner built from a
// PID alone is unresolvable exactly like the lease holder was. Without this the
// liveness check reports "no run reference" for precisely the fences the report
// was added to make decidable.
func TestNodeFenceOwnersCarryTheGitHubRunReference(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	for _, owner := range []string{
		`bootstrap_owner="bootstrap-${desired_revision:0:12}-$(fence_run_segment)-$$-${RANDOM}"`,
		`cordon_owner_token="${desired_revision:0:16}-$(fence_run_segment)-$$-${RANDOM}"`,
	} {
		requireContains(t, script, owner)
	}
	// No fence OWNER may be minted without it. Scoped to ownership identities —
	// a reconcile-trigger stamp also ends in PID/RANDOM but is never resolved
	// for liveness, so a blanket count would fail on an unrelated line.
	ownerAssignment := regexp.MustCompile(`(?m)^\s*(?:local\s+)?(\w*(?:owner|owner_token|holder))="([^"]*\$\$[^"]*)"`)
	found := 0
	for _, match := range ownerAssignment.FindAllStringSubmatch(script, -1) {
		found++
		if !strings.Contains(match[2], "fence_run_segment") {
			t.Errorf("fence owner %s is minted without a run reference: %s", match[1], match[2])
		}
	}
	if found != 3 {
		t.Fatalf("fence owner assignments inspected = %d, want 3", found)
	}
}

// The report prints commands an operator pastes against production. A node can
// already be cordoned for maintenance or ill health before the bridge ever
// claimed it, and the journal records that. An unconditional uncordon would
// reverse an intent this script never owned.
func TestFenceReportNeverUncordonsANodeItDidNotCordon(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// `has`, never `//`: jq's alternative treats a falsy value as empty, which
	// would misreport the one state that may safely uncordon. Checked against
	// the CODE only — the rationale comment names the anti-pattern it forbids.
	requireContains(t, report, `has("wasCordoned")`)
	requireNotContains(t, stepDirectives(report), `.wasCordoned // `)
	// All three states are answered, and only the recorded-safe one uncordons.
	requireContains(t, report, "uncordon")
	for _, state := range []string{"ALREADY cordoned", "UNRECORDED"} {
		requireContains(t, report, state)
	}

	// The branch values must match the journal's OWN schema. wasCordoned is
	// serialized with --argjson and validated as numeric `== 0 or == 1`, so a
	// switch on the booleans matches nothing and every real journal falls to
	// UNRECORDED — the safe uncordon never printed. An earlier version of this
	// test asserted against a hand-written `false` fixture that the code never
	// produces, so it passed over exactly that defect.
	schema := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	requireContains(t, schema, `($record.wasCordoned == 0 or $record.wasCordoned == 1)`)
	directives := stepDirectives(report)
	requireContains(t, directives, "\n        0)\n")
	requireContains(t, directives, "\n        1)\n")
	for _, boolean := range []string{"\n        false)\n", "\n        true)\n"} {
		requireNotContains(t, directives, boolean)
	}
}

// A journal in `active` or `retain` is not releasable by removing annotations:
// reconcile_bootstrap_recovery refuses both, because one may hold an
// interrupted pre-reboot mutation and the other crossed the reboot edge with no
// release-ready proof. Printing removals for them discards the only durable
// record of that state.
func TestFenceReportRefusesToReleasePreProofBootstrapJournals(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	requireContains(t, report, "active | retain)")
	requireContains(t, report, "NOT releasable by annotation removal")
	// Those phases must skip the release block entirely, not merely warn.
	requireContains(t, report, "\n        continue\n")
	// The phases really are the ones the reconciler refuses.
	for _, phase := range []string{`.phase == "active"`, `.phase == "retain"`} {
		requireContains(t, script, phase)
	}
}

// The Lease is the global exclusion fence. Released before the fences it
// guards, it lets a queued or newly dispatched deploy start against a
// half-recovered cluster — so the report must print it last, mirroring
// cleanup_refresh_work's own release order.
func TestFenceReportPrintsTheLeaseLast(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	nodes := requireIndex(t, report, "HELD  Node")
	lease := requireIndex(t, report, "fence_report_lease")
	requireBefore(t, nodes, lease, "node fences reported before the Lease")
	requireContains(t, script, "release LAST, after every fence above is released")
	requireContains(t, report, "Release in the order printed above")
}

// A rerun REUSES the run id and increments the attempt, so `gh run view`
// without --attempt inspects the newest attempt: an orphan from a finished
// attempt reads as live while a later one runs, blocking recovery on a holder
// that is provably dead.
func TestFenceLivenessCommandPinsTheRecordedAttempt(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	liveness := functionBody(t, script, "fence_report_liveness")

	// Assert the flag inside the printed command itself. Checking positions
	// across the whole function would match the rationale comment above it,
	// which names the flag before the command uses it.
	requireContains(t, liveness,
		`gh run view %s --repo devantler-tech/platform --attempt %s --json status,conclusion`)
}

// A failing cluster read is exactly when an operator runs this, so the failure
// path must not exit through the EXIT trap: later cleanup helpers are not
// defined yet at that point and turn the report into a secondary failure.
func TestFenceReportFailurePathStillDisablesTheCleanupTrap(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	// errexit is suspended inside an `if` condition; a bare call is not.
	requireContains(t, script, "if report_fences_now; then")
	requireNotContains(t, script, "\n  report_fences_now\n")
}

// A node whose cordon was claimed by the ordinary per-node path carries the
// OWNER annotation and no recovery journal, so keying the sweep on the journal
// reports "no fence held" while that node stays cordoned and the next run
// refuses its owner — a false all-clear, the worst failure for this tool.
func TestFenceReportSweepsCordonOwnerNotOnlyTheRecoveryJournal(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	report := functionBody(t, script, "report_fences_now")
	requireContains(t, report, "CORDON_OWNER_ANNOTATION")
	requireContains(t, report, `select($owner != "" or $recovery != "")`)

	// The ordinary path really does claim ownership with an empty journal —
	// if that ever stops being true this test should be revisited, not deleted.
	requireContains(t, script, `      "" "${was_cordoned}" "${initial_node_taints}" || return 1`)
}

// The runbook tells an operator each printed release command is CAS-guarded,
// and the Lease and Kustomization commands are. The node path was not: it
// printed a bare `uncordon` plus one `annotate … -` per annotation. Minutes can
// pass between the report and the paste, and a new transaction can claim the
// node in that window — at which point those commands strip ITS fence and
// uncordon a node it is actively draining, with no error. Test ops close it:
// the API rejects the whole patch when the UID, resourceVersion, owner, or
// journal moved, so losing that race fails loudly instead of silently.
func TestFenceReportNodeReleaseIsCASGuarded(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")
	command := functionBody(t, script, "fence_node_release_command")

	// The report delegates to the guarded builder and emits no bare mutation of
	// its own. Comments are stripped first: the rationale above the call names
	// the very anti-pattern these assertions forbid.
	requireContains(t, report, "fence_node_release_command")
	directives := stepDirectives(report)
	for _, unguarded := range []string{
		"kubectl --context %s uncordon %s",
		"annotate node %s %s-",
	} {
		requireNotContains(t, directives, unguarded)
	}

	// Every piece of state the report showed the operator is tested before any
	// mutation runs, and it is ONE patch — three separately guarded commands
	// still could not be atomic with each other.
	for _, guard := range []string{
		`{op: "test", path: "/metadata/uid", value: $uid}`,
		`{op: "test", path: "/metadata/resourceVersion", value: $resource_version}`,
		`{op: "test", path: $owner_path, value: $owner}`,
		`{op: "test", path: $recovery_path, value: $recovery}`,
	} {
		requireContains(t, command, guard)
	}
	requireContains(t, command, "patch node %s --type=json")
}

// CAS guards against a CONCURRENT change; it does not say the recorded state is
// safe to restore. reconcile_bootstrap_recovery_journals and
// restore_node_schedulability_if_needed both refuse a journal whose schema,
// owner, UID or phase is wrong. The report has to refuse on the same terms:
// otherwise a malformed record — `{"wasCordoned":0}` is enough — reaches the
// phase check as a non-active non-retain journal and earns a CAS-guarded patch
// that drops it and sets spec.unschedulable to false. The patch would apply
// cleanly, because nothing about it is concurrent; it is simply wrong.
func TestFenceReportRefusesJournalsItCannotValidate(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// The full schema, not a phase check: every field the durable journal
	// declares is pinned, so a partial object cannot pass by omission.
	for _, field := range []string{
		`"desiredRevision", "initialTaints", "owner", "phase",`,
		`and .v == 1`,
		`and (.wasCordoned == 0 or .wasCordoned == 1)`,
		`and (.initialTaints | type == "array")`,
		`test("^[0-9a-f]{64}$")`,
	} {
		requireContains(t, report, field)
	}

	// The journal must be OURS and for THIS node — a valid journal belonging to
	// another owner or node is exactly as unsafe to release as a malformed one.
	requireContains(t, report, `and .owner == $owner`)
	requireContains(t, report, `and .uid == $uid`)

	// `rollback-safe` is now the ONLY releasable phase. `active`, `retain` and
	// `release-ready` are each refused earlier with their own guidance — the
	// last because adjudicating it needs the current credential revision, which
	// this mode deliberately never loads — so anything else must not reach a
	// printed command at all. Narrowed from the earlier two-phase disjunction;
	// see TestFenceReportRoutesReleaseReadyJournalsThroughTheBridge.
	requireContains(t, report, `and .phase == "rollback-safe"`)
	requireNotContains(t, report, `or .phase == "release-ready")`)

	// Fail-closed: the refusal path prints a diagnostic and `continue`s, so no
	// release command is emitted for a journal that did not validate.
	requireContains(t, report, "NOT releasable: the recovery journal is malformed")

	// An EMPTY owner must not satisfy the match. `.owner == $owner` alone is
	// true when both sides are "", so a journal carrying `"owner": ""` on a node
	// with no cordon-owner annotation would validate — and the emitted patch
	// omits the owner test/remove while still dropping the journal and, on
	// wasCordoned 0, uncordoning. reconcile_bootstrap_recovery_journals requires
	// a non-empty owner; so does this.
	requireContains(t, report, `and (.owner | type == "string" and length > 0)`)

	// Belt and braces at the emission site: the cordon owner annotation IS the
	// fence, so a node without one gets a diagnostic and no command at all.
	requireContains(t, report, "NOT releasable: the node carries no cordon owner annotation")
}

// Tab is IFS *whitespace*, so bash collapses runs of it and drops empty fields.
// Both `owner` and `recovery` are legitimately empty here — a node claimed with
// no journal is the ordinary per-node claim, and an ownerless journal is the
// case the validation refuses — so a tab-delimited row shifted every later
// field one position left: `uid` received the resourceVersion and
// `resource_version` the deletionTimestamp. The CAS patch then tested values
// that were never read from that node, and the whole guard was inert.
func TestFenceReportNodeFeedSurvivesEmptyFields(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// Unit separator on both sides of the pipe, never a tab.
	requireContains(t, report, `join("\u001f")`)
	requireContains(t, report, `while IFS=$'\037' read -r name owner recovery`)
	requireNotContains(t, stepDirectives(report), `while IFS=$'\t' read -r name`)
	requireNotContains(t, stepDirectives(report), "| @tsv")

	// Values are sanitized of the separator and of newlines before joining, so a
	// crafted annotation cannot inject an extra field or an extra row.
	requireContains(t, report, `gsub("[\u001f\n\r]"; " ")`)
}

// The report prints kubectl commands for an operator to PASTE, and every patch
// it carries is built from values read off the cluster — the Lease holder, the
// node cordon-owner annotation, the recovery journal. Interpolating that JSON
// into `-p '…'` breaks on the first single quote in any of them: the command
// either fails to parse, or closes the quote and appends shell syntax the
// operator then executes. Exercising it is the point — the pre-fix spelling
// looks correct and is not, and a substring assertion cannot tell the two
// apart, so this runs the emitted command with kubectl stubbed and compares
// what the argument actually received.
func TestFenceReleaseCommandsSurviveAQuoteInClusterState(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	quote := functionBody(t, script, "fence_shell_quote")

	// A malicious holder, and a benign one that merely contains an apostrophe:
	// the second is the case that silently broke the command for everyone.
	for _, value := range []string{
		`runner'; touch PWNED; echo '`,
		`tick'only`,
		`plain-runner`,
		`has"double$dollar`,
		`back\slash`,
	} {
		// functionBody returns the signature line too, so the definition is
		// reused verbatim and only its closing brace is supplied.
		harness := quote + "\n}\n" +
			`printf 'kubectl --type=json -p %s' "$(fence_shell_quote "$1")"`
		command := exec.Command("/bin/bash", "-c", harness, "bash", value)
		emitted, err := command.Output()
		if err != nil {
			t.Fatalf("emit quoted command for %q: %v", value, err)
		}

		// Re-parse exactly as an operator's shell would, and print back the
		// final argument. A broken escape shows up as a parse failure or as a
		// different string — never as a silent pass.
		replay := `eval "set -- ${1#kubectl }"; printf '%s' "${@: -1}"`
		back := exec.Command("/bin/bash", "-c", replay, "bash", string(emitted))
		got, err := back.Output()
		if err != nil {
			t.Fatalf("emitted command does not re-parse for %q: %v", value, err)
		}
		if string(got) != value {
			t.Errorf("round-trip for %q returned %q", value, string(got))
		}
	}
}

// Every emission site must route through the quoter. A site that still writes
// the patch inside literal single quotes is exactly the defect above, and the
// only durable guard is that no such spelling remains.
func TestFenceReleaseCommandsNeverInterpolateAPatchIntoLiteralQuotes(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")

	for _, builder := range []string{
		"fence_lease_release_command",
		"fence_node_release_command",
		"fence_kustomization_release_command",
	} {
		body := functionBody(t, script, builder)
		requireContains(t, body, `fence_shell_quote "${patch}"`)
		requireNotContains(t, body, `-p '%s'`)
	}
}

// syncBuffer is written by the exec copier goroutine while the test reads it to
// decide when the report has started, so the two need to be serialized.
type syncBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)

	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return string(b.data)
}

// A hard kill is the case the fence report exists for, and it still runs the
// EXIT trap. The trap is armed near the top of the file, so it runs before the
// rest of the file has been parsed into functions: every helper it calls has to
// be guarded. Left unguarded, an interrupted report ends in a `command not
// found` and a false claim that durable recovery annotations remain on nodes —
// emitted during exactly the incident the operator is trying to read.
func TestInterruptedFenceReportDoesNotCallAnUndefinedCleanupHelper(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	mustWriteJSON(t, f.decryptedConfig, validConfig())
	f.clearRunStatePreservingCluster(true, false)

	// Park the first cluster read so the signal reliably lands inside the
	// report rather than after it has already exited.
	slowDir := t.TempDir()
	stub := "#!/usr/bin/env bash\nsleep 3\nexec " +
		filepath.Join(f.binDir, "kubectl") + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(slowDir, "kubectl"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write slow kubectl stub: %v", err)
	}

	env := f.baseEnvironment()
	env["PATH"] = slowDir + string(os.PathListSeparator) + env["PATH"]

	cmd := exec.Command(helperPath, "--fences")
	cmd.Dir = rootPath
	cmd.Env = environmentSlice(env)
	stdout := &syncBuffer{}
	stderr := &syncBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start fence report: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stdout.String(), "GHCR deploy fences") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("fence report never started; stdout = %q stderr = %q",
				stdout.String(), stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal fence report: %v", err)
	}
	_ = cmd.Wait()

	combined := stdout.String() + stderr.String()
	// Without the guard the trap reaches an undefined function; the message is
	// the operator-visible symptom, so assert on both.
	if strings.Contains(combined, "command not found") {
		t.Errorf("interrupted fence report called an undefined helper; output = %q", combined)
	}
	if strings.Contains(combined, "Bootstrap quarantine cleanup was incomplete") {
		t.Errorf("interrupted fence report claimed quarantine state it never created; output = %q",
			combined)
	}
}

// select_orphaned_node_fences clears a leaked fence ONLY at drain phase
// "claimed": "mutating" means a Talos write was already in flight, and a
// MISSING phase is a pre-#3070 fence of unknown depth, so absence is never read
// as innocence. The report reached the same nodes through owner and recovery
// annotations alone and never read the phase, so it printed the identical
// release for "mutating" as for "claimed". Executing it strips the owner, the
// next report reads clean, and the following bridge claims a node whose Talos
// write never completed.
func TestFenceReportRefusesNodesWhoseDrainPhaseIsNotClaimed(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// The phase has to reach the loop at all before it can be refused.
	requireContains(t, report, "CORDON_PHASE_ANNOTATION")
	requireContains(t, report, "drain_phase")
	// Only "claimed" is releasable, exactly as the reclaim path decides.
	requireContains(t, report, `"${drain_phase}" != "claimed"`)
	requireContains(t, report, "NOT releasable: the drain phase is")

	// The reference predicate really is claimed-only, and fails closed on a
	// missing phase. If that ever changes this test should be revisited.
	safety := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth-safety.sh")
	requireContains(t, safety, `select((($annotations[$phase_annotation]) // "") == "claimed")`)
}

// reconcile_bootstrap_recovery_journals groups journals by OWNER and blocks
// every node in a batch whose phases are mixed or which holds any active/retain
// member — an all-or-nothing quarantine. The report checked each node alone, so
// a release-ready node whose sibling under the same owner is still retain
// earned a printed release the reconciler would refuse, and an operator
// following the runbook stepped around the batch guard one node at a time.
func TestFenceReportPreservesOwnerWideBootstrapQuarantine(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// The blocked-owner set is computed across ALL journals, not per node.
	requireContains(t, report, "group_by(.owner)")
	requireContains(t, report, "(map(.phase) | unique | length) > 1")
	requireContains(t, report, "blocked_owners")
	requireContains(t, report, "NOT releasable: another node under bootstrap owner")

	// The refusal must precede the release print, or it refuses nothing.
	blocked := requireIndex(t, report, "blocked_owners")
	release := requireIndex(t, report, "fence_node_release_command")
	requireBefore(t, blocked, release, "owner-wide quarantine checked before the release print")

	// The reconciler's own grouping is the contract being mirrored.
	requireContains(t, script, `or .[0].phase == "retain"`)
}

// The reconciler admits a release-ready journal only when its recorded
// desiredRevision EQUALS the current one: the runtime proof and Talos marker
// cover the revision they were taken against, and a newer credential needs a
// full proof the bridge performs. --fences deliberately never loads the
// credential, so it cannot compute that equality — which makes printing a
// release for release-ready a judgement it has no evidence for. Route it to the
// bridge instead; a well-formed hash is not a current hash.
func TestFenceReportRoutesReleaseReadyJournalsThroughTheBridge(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	requireContains(t, report, "release-ready)")
	requireContains(t, report, "NOT releasable by annotation removal: this report cannot")
	// Only rollback-safe survives to the release print.
	requireContains(t, report, `.phase == "rollback-safe"`)
	requireNotContains(t, stepDirectives(report),
		`(.phase == "rollback-safe" or .phase == "release-ready")`)

	// The reconciler's revision equality is the check this cannot perform.
	requireContains(t, script, `"${recorded_revision}" != "${desired_revision}"`)
}

// restore_node_schedulability_if_needed gates every uncordon on
// node_scheduling_state_is_safe_to_reboot, which requires the CURRENT
// normalized taints and cordon state to still match the journal's captured
// intent. The report checked only that initialTaints was an array: the
// resourceVersion CAS catches a change after this read, but drift that already
// happened before it is invisible, so the printed patch could uncordon a node
// into a taint set nobody captured.
func TestFenceReportRechecksSchedulingStateBeforeRelease(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	requireContains(t, report, "scheduling_intent")
	requireContains(t, report, "NOT releasable: the node scheduling state no longer matches")
	// The SAME normalization the reference predicate uses — a different one
	// would disagree with it on exactly the taints it exists to ignore.
	requireContains(t, report, `.key == "node.kubernetes.io/unschedulable"`)
	requireContains(t, report, `sort_by([.key, .effect, (.value // ""), (.timeAdded // "")])`)

	safety := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth-safety.sh")
	requireContains(t, safety, "node_scheduling_state_is_safe_to_reboot()")
}

// The usage string presents these as ALTERNATIVE modes, and the report block
// runs first and exits 0. Supplying --fences alongside an operational mode
// therefore printed a report and reported success while the credential or proof
// work it was configured to do never ran — an automation step that looks like it
// passed and silently did nothing.
func TestFencesRejectsCombinationWithOperationalModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{
		"--check-only",
		"--allow-incomplete-fanout",
		"--record-runtime-proof",
		"--reuse-runtime-proof",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)

			other := []string{mode}
			if strings.HasSuffix(mode, "-runtime-proof") {
				// An ABSOLUTE path, or the script exits 64 on its own
				// path validation and this test passes without ever
				// reaching the combination it exists to reject.
				other = append(other, filepath.Join(t.TempDir(), "proof.json"))
			}

			result := f.runHelper(validConfig(), append([]string{"--fences"}, other...), nil)

			if strings.Contains(result.stderr, "must be absolute runner-local paths") {
				t.Fatalf("--fences %v exited on path validation, not the combination; stderr = %q",
					other, result.stderr)
			}
			if result.exitCode != 64 {
				t.Errorf("--fences %v exit = %d, want 64; stdout = %q stderr = %q",
					other, result.exitCode, result.stdout, result.stderr)
			}
			if strings.Contains(result.stdout, "GHCR deploy fences") {
				t.Errorf("--fences %v printed the report instead of rejecting the combination; stdout = %q",
					other, result.stdout)
			}
		})
	}
}

// A journal this report cannot PARSE must not vanish from the owner grouping.
// reconcile_bootstrap_recovery_journals validates every journal up front and
// refuses EVERY recovery mutation when any one is malformed, so dropping an
// unparseable record with `fromjson?` left a VALID sibling under the same owner
// looking releasable — the same all-or-nothing guard walked around from the
// other side, and the exact defect the per-owner grouping was added to close.
func TestFenceReportBlocksEveryJournalWhenAnyIsMalformed(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// `try/catch null` keeps the malformed record so it can be detected.
	// `fromjson?` yields EMPTY, which both drops it from the owner grouping and —
	// via `empty as $record` — drops the whole NODE from the report feed.
	// Checked against the DIRECTIVES only: the rationale comments name the
	// anti-pattern they forbid, so matching the raw body would fire on them.
	requireContains(t, report, "try fromjson catch null")
	requireNotContains(t, stepDirectives(report), "fromjson?")

	// An unparseable or non-string-owner/phase record raises the sentinel.
	requireContains(t, report, `then "*"`)
	requireContains(t, report, "NOT releasable: at least one recovery journal in the cluster is")

	// The sentinel gates on the journal, not on every node: a node with NO
	// journal is the ordinary per-node claim that the drain-phase guard owns.
	requireContains(t, report, `if [[ -n "${recovery}" ]] && grep -Fqx -- '*' "${blocked_owners}"`)

	// The reconciler really does refuse globally on ANY malformed journal.
	requireContains(t, script,
		"At least one durable GHCR bootstrap recovery journal is malformed")
}

// The owner-wide sentinel has to apply the reconciler's FULL journal schema.
// "Parses as an object carrying a string owner and phase" is a strictly weaker
// bar than reconcile_bootstrap_recovery_journals enforces, so a record that
// clears it while failing the reconciler — an empty owner, a non-hex
// desiredRevision, an extra key, a wasCordoned outside {0,1}, an unsupported
// phase, or a UID / owner annotation that does not match its node — stays out
// of the `*` sentinel. Both journals then group under one owner with the same
// phase, nothing blocks the batch, and the WELL-FORMED sibling earns a printed
// release the bridge refuses for the whole owner. The per-node validation
// refuses the malformed node itself and says nothing about its siblings, which
// is why the batch-level predicate is the one that has to be strict.
func TestFenceReportSentinelAppliesTheReconcilersFullJournalSchema(t *testing.T) {
	t.Parallel()
	script := readRepositoryFile(t, "scripts/refresh-flux-ghcr-auth.sh")
	report := functionBody(t, script, "report_fences_now")

	// The `.record` / `.node` shape is what distinguishes the batch-level
	// sentinel from the per-node check, which reads a flat record against jq
	// args. These two clauses exist ONLY in the sentinel.
	requireContains(t, report, "and .node.metadata.uid == .record.uid")
	requireContains(t, report,
		"and .node.metadata.annotations[$owner_annotation] == .record.owner")
	requireContains(t, report, "and .node.metadata.deletionTimestamp == null")

	// The rest of the reconciler's schema, likewise `.record`-scoped.
	requireContains(t, report, "(.record | keys | sort) == ([")
	requireContains(t, report, "and .record.v == 1")
	requireContains(t, report, `and (.record.owner | type == "string" and length > 0)`)
	requireContains(t, report, "and (.record.wasCordoned == 0 or .record.wasCordoned == 1)")
	requireContains(t, report, `and (.record.phase == "rollback-safe"`)

	// The weaker predicate must not come back. The owner grouping legitimately
	// keeps the `== "string"` form to drop records it cannot key by owner; it is
	// the `!=` sentinel test that was too permissive.
	requireNotContains(t, stepDirectives(report), `((.phase | type) != "string")`)
	requireNotContains(t, stepDirectives(report), `((.owner | type) != "string")`)

	// The sentinel is computed before the release print it is supposed to gate.
	sentinel := requireIndex(t, report, "and .node.metadata.uid == .record.uid")
	release := requireIndex(t, report, "fence_node_release_command")
	requireBefore(t, sentinel, release, "owner-wide sentinel computed before the release print")

	// The schema being mirrored is the reconciler's own up-front validation.
	requireContains(t, script, "and .node.metadata.deletionTimestamp == null")
}
