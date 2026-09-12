package refreshfluxghcrauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --recover-fences is the automated half of the fence model: it releases the
// policy fences and then the synchronization Lease when — and only when — every
// holder is PROVABLY dead.
//
// Everything here is a statement about that proof. Expiry alone must never
// release, because the script's own acquisition comment explains that an expired
// shell can resume and write stale credentials even under CAS. The API saying a
// run attempt is `completed` is different in kind, because Actions does not
// resume a completed attempt — so these tests pin the difference between the two
// and, more importantly, pin every way the proof can be UNAVAILABLE.

const deadHolderIdentity = "4384f07cc5a864b0-gh31976321946.1-2690-25297"

// seedOrphanedLease puts the cluster in the state a killed deploy leaves behind:
// a Lease held by a run reference whose heartbeat has stopped.
func seedOrphanedLease(t *testing.T, f *fixture, holder string) {
	t.Helper()
	if err := os.WriteFile(
		filepath.Join(f.syncStateDir, "sync-lease-holder"), []byte(holder), 0o600); err != nil {
		t.Fatalf("seed lease holder: %v", err)
	}
}

func seedOrphanedPolicyFences(t *testing.T, f *fixture, holder string) {
	t.Helper()
	markers := map[string]string{
		"flux-policy-handoff-owner":     holder,
		"flux-policy-handoff-suspended": "",
		"flux-policy-parent-owner":      holder,
		"flux-policy-parent-suspended":  "",
	}
	for name, value := range markers {
		if err := os.WriteFile(filepath.Join(f.syncStateDir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("seed policy fence %s: %v", name, err)
		}
	}
}

func leaseHolderNow(t *testing.T, f *fixture) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(f.syncStateDir, "sync-lease-holder"))
	if err != nil {
		t.Fatalf("read lease holder: %v", err)
	}
	return string(content)
}

// The GREEN case. Note what it asserts beyond the exit code: the holder is
// actually cleared. A mode that exits 0 having released nothing would leave the
// deploy lane wedged while reporting success, which is the failure this whole
// feature exists to prevent.
func TestRecoverFencesReleasesALeaseWhoseHolderRunIsTerminal(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{"FAKE_EXPIRED_SYNC_LEASE": "true"})

	requireSuccessResult(t, result)
	if holder := leaseHolderNow(t, f); holder != "" {
		t.Errorf("lease holder = %q, want it released", holder)
	}
	if !strings.Contains(result.stdout, "proven dead") {
		t.Errorf("recovery did not report its liveness evidence; stdout = %q", result.stdout)
	}
}

// The single most important RED case: the run is still going, so the holder can
// still write. Releasing here is the two-writer hazard the fence exists for.
func TestRecoverFencesRefusesWhileTheHolderRunIsNotTerminal(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{
			"FAKE_EXPIRED_SYNC_LEASE": "true",
			"FAKE_GH_RUN_STATUS":      "in_progress",
		})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded on a live holder; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
	if !strings.Contains(result.stdout+result.stderr, "in_progress") {
		t.Errorf("refusal does not name the status it saw; output = %q", result.stdout+result.stderr)
	}
}

// A hard-killed deploy ordinarily leaves the child and parent policy fences as
// well as the Lease. Recovery must prove every holder run is terminal before it
// mutates anything, then release child, parent, and Lease in that order.
func TestRecoverFencesReleasesTerminalPolicyFencesBeforeTheLease(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)
	seedOrphanedPolicyFences(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{"FAKE_EXPIRED_SYNC_LEASE": "true"})

	requireSuccessResult(t, result)
	for _, marker := range []string{
		"flux-policy-handoff-owner", "flux-policy-handoff-suspended",
		"flux-policy-parent-owner", "flux-policy-parent-suspended",
	} {
		if pathExists(filepath.Join(f.syncStateDir, marker)) {
			t.Errorf("policy fence marker %s remains after recovery", marker)
		}
	}
	if holder := leaseHolderNow(t, f); holder != "" {
		t.Errorf("lease holder = %q, want it released last", holder)
	}
	operations := readLines(f.operationLog)
	child := lineIndex(t, operations, "flux-policy-resume:infrastructure")
	parent := lineIndex(t, operations, "flux-policy-parent-resume:flux-system")
	if child >= parent {
		t.Errorf("policy release order = %v, want child before parent", operations)
	}
}

// A lost policy-fence CAS must leave the parent and global Lease held. That
// preserves exclusion for a fresh report/retry instead of exposing a partially
// recovered control plane to another deploy.
func TestRecoverFencesKeepsLaterFencesWhenPolicyReleaseIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)
	seedOrphanedPolicyFences(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{
			"FAKE_EXPIRED_SYNC_LEASE":               "true",
			"FAKE_FLUX_POLICY_HANDOFF_RELEASE_FAIL": "true",
		})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded after a refused child release; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it retained", holder)
	}
	for _, marker := range []string{
		"flux-policy-handoff-owner", "flux-policy-handoff-suspended",
		"flux-policy-parent-owner", "flux-policy-parent-suspended",
	} {
		if !pathExists(filepath.Join(f.syncStateDir, marker)) {
			t.Errorf("policy fence marker %s was removed after the refused first release", marker)
		}
	}
}

// Node recovery has additional Talos and scheduling proofs, so this lightweight
// preflight must still refuse before querying liveness or releasing the Lease.
func TestRecoverFencesRefusesWhileANodeFenceIsStillHeld(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)
	for name, value := range map[string]string{
		"cordon-owner-prod-worker-1": deadHolderIdentity,
		"cordon-phase-prod-worker-1": "claimed",
		"cordoned-prod-worker-1":     "",
	} {
		if err := os.WriteFile(filepath.Join(f.syncStateDir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("seed node fence %s: %v", name, err)
		}
	}

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{"FAKE_EXPIRED_SYNC_LEASE": "true"})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded with a node fence held; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
	if _, err := os.Stat(f.ghCalled); err == nil {
		t.Error("liveness query was made before the node-fence refusal")
	}
	if output := result.stdout + result.stderr; !strings.Contains(output, "node fence") {
		t.Errorf("refusal does not name the node-fence boundary; output = %q", output)
	}
}

// The CAS is the last line of defence: the holder and resourceVersion the report
// observed must BOTH still hold, or something touched the Lease in between and
// the release could be clearing a live acquisition rather than an orphan.
//
// The fixture advances the resourceVersion after the report's read, so the patch
// is refused by the fake's ordinary CAS comparison — the same one a real cluster
// applies — rather than by a recovery-specific failure switch.
func TestRecoverFencesRefusesWhenTheReleasePatchLosesTheCAS(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{
			"FAKE_EXPIRED_SYNC_LEASE":                    "true",
			"FAKE_SYNC_LEASE_TOUCHED_AFTER_FENCE_REPORT": "true",
		})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded on a refused patch; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
	if output := result.stdout + result.stderr; !strings.Contains(output, "Recovery patch was refused") {
		t.Errorf("refusal does not report the rejected patch; output = %q", output)
	}
}

// An expired heartbeat is NOT a death proof, and this is the case that says so:
// the lease is expired and the run is terminal, but the identity carries no run
// reference, so nothing can be proven. That is the shape a local
// run-ksail-prod-with-pull-auth.sh invocation leaves, and it must never be
// auto-released — there is no oracle for a laptop.
func TestRecoverFencesRefusesAHolderThatCarriesNoRunReference(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, "4384f07cc5a864b0-local-2690-25297")

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{"FAKE_EXPIRED_SYNC_LEASE": "true"})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded without a run reference; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); !strings.Contains(holder, "local") {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
}

// A failed query is UNKNOWN, never "assume dead". Without this the mode would
// release a Lease every time the API had a bad minute.
func TestRecoverFencesRefusesWhenTheLivenessQueryFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{
			"FAKE_EXPIRED_SYNC_LEASE": "true",
			"FAKE_GH_REQUEST_FAILS":   "true",
		})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded on a failed liveness query; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
}

// A response with no status is the other UNKNOWN, and it is distinct from a
// failed request: the call succeeds, so an exit-status-only check would read it
// as a usable answer and compare "" against "completed".
func TestRecoverFencesRefusesWhenTheLivenessQueryReturnsNoStatus(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{
			"FAKE_EXPIRED_SYNC_LEASE": "true",
			"FAKE_GH_RUN_STATUS":      "",
		})

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded on an empty status; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
}

// Belt and braces against a stale or cached API read. The run status here says
// terminal, but the heartbeat is still inside its duration — something is
// writing right now, and the live observation wins over the remote one.
func TestRecoverFencesRefusesWhileTheHeartbeatIsStillInsideItsDuration(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	// No FAKE_EXPIRED_SYNC_LEASE, so the fake reports a far-future renewTime.
	result := f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"}, nil)

	if result.exitCode == 0 {
		t.Fatalf("recovery succeeded against a live heartbeat; stdout = %q", result.stdout)
	}
	if holder := leaseHolderNow(t, f); holder != deadHolderIdentity {
		t.Errorf("lease holder = %q, want it untouched", holder)
	}
}

// A rerun REUSES the run id, so an unpinned query reports the newest attempt.
// Unpinned, a finished attempt 2 would vouch for an attempt 1 that is still
// running — the exact inversion that makes an automatic path dangerous.
func TestRecoverFencesPinsTheAttemptWhenProvingLiveness(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seedOrphanedLease(t, f, deadHolderIdentity)

	f.runHelperPreservingClusterState(validConfig(), []string{"--recover-fences"},
		map[string]string{"FAKE_EXPIRED_SYNC_LEASE": "true"})

	request, err := os.ReadFile(f.ghCalled)
	if err != nil {
		t.Fatalf("liveness query was never made: %v", err)
	}
	if !strings.Contains(string(request), "/attempts/1") {
		t.Errorf("liveness query did not pin the attempt; request = %q", request)
	}
	if !strings.Contains(string(request), "/runs/31976321946/") {
		t.Errorf("liveness query did not target the holder's run; request = %q", request)
	}
}

// Nothing held is a clean no-op, not an error: the pre-flight runs on EVERY
// deploy once enabled, and the overwhelmingly common case is a healthy lane.
func TestRecoverFencesIsANoOpWhenNoLeaseIsHeld(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	result := f.runHelper(validConfig(), []string{"--recover-fences"}, nil)

	requireSuccessResult(t, result)
	if !strings.Contains(result.stdout, "nothing to recover") {
		t.Errorf("no-op did not say so; stdout = %q", result.stdout)
	}
	if _, err := os.Stat(f.ghCalled); err == nil {
		t.Error("liveness query was made with no fence held; it should not have been")
	}
}

// Same hazard --fences guards against: accepting an alternative mode alongside
// an operational one makes that step exit 0 having silently skipped the work it
// was configured to do. --fences and --recover-fences are also mutually
// exclusive, because --recover-fences already prints the report.
func TestRecoverFencesIsRejectedAlongsideAnotherMode(t *testing.T) {
	t.Parallel()
	for _, extra := range []string{"--check-only", "--allow-incomplete-fanout", "--fences"} {
		t.Run(extra, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)

			result := f.runHelper(validConfig(), []string{"--recover-fences", extra}, nil)

			if result.exitCode != 64 {
				t.Errorf("exit = %d with %s, want 64", result.exitCode, extra)
			}
		})
	}
}

func TestUsageAdvertisesRecoverFences(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	result := f.runHelper(validConfig(), []string{"--not-a-flag"}, nil)

	if !strings.Contains(result.stderr, "--recover-fences") {
		t.Errorf("usage does not advertise --recover-fences; stderr = %q", result.stderr)
	}
}
