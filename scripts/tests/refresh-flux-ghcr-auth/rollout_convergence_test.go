package refreshfluxghcrauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecondFanoutVerificationBlocksRootCutover(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_CONSUMER_MISMATCH_ON_SECOND_PASS_NAMESPACE": "wedding-app"})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "did not materialise")
	operations := readLines(f.operationLog)
	requireLine(t, operations, "talos-revision:10.0.0.1")
	count := 0
	for _, operation := range operations {
		if operation == "variables-patch" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("variables patch count = %d, want 2", count)
	}
	requireNoLine(t, operations, "root-patch")
}

func TestMissingCachedImageStillPullsAndRecordsRevision(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_TALOS_IMAGE_ABSENT_NODE": "10.0.0.2"})
	requireSuccessResult(t, result)
	operations := readLines(f.talosLog)
	requireLine(t, operations, "talos-remove:10.0.0.2:"+ksailTargetImage)
	requireLine(t, operations, "talos-pull:10.0.0.2:"+ksailTargetImage)
	requireLine(t, operations, "talos-revision:10.0.0.2")
	if !pathExists(f.patchCapture) {
		t.Error("root patch missing after successful pull proof")
	}
	requireNotContains(t, result.stdout+result.stderr, "fixture-secret-token")
}

func TestCurrentTalosNodesSkipTalosAPI(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_TALOS_NODES_CURRENT": "true"})
	requireSuccessResult(t, result)
	if pathExists(f.talosLog) {
		t.Error("current nodes unexpectedly invoked Talos")
	}
	if !pathExists(f.patchCapture) {
		t.Error("root patch missing")
	}
	operations := readLines(f.operationLog)
	requireLine(t, operations, "ivpol-policy-apply:verify-app-images")
}

func TestClusterUpdateCannotEraseVerifiedRuntimeProof(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	runtimeProof := filepath.Join(f.workspace, "ghcr-runtime-proof.json")
	first := f.runHelper(validConfig(), []string{
		"--record-runtime-proof", runtimeProof,
	}, nil)
	requireSuccessResult(t, first)
	if !pathExists(runtimeProof) {
		t.Fatal("stage did not record its exact-node runtime proof")
	}

	// `ksail cluster update` re-renders Talos machine.nodeAnnotations from the
	// committed patches. That removes bridge-owned proof stored in machine
	// config, even though neither the credential nor the running Node changed.
	// Model only that destructive re-render between the production Stage and
	// Reassert invocations.
	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		if err := os.Remove(filepath.Join(f.syncStateDir, "talos-revision-"+address)); err != nil {
			t.Fatalf("simulate cluster update dropping proof on %s: %v", address, err)
		}
	}

	reassert := f.runHelperPreservingClusterState(validConfig(), []string{
		"--reuse-runtime-proof", runtimeProof,
	}, nil)
	requireSuccessResult(t, reassert)
	operations := readLines(f.operationLog)
	for _, unexpected := range []string{
		"node-drain:prod-worker-1",
		"node-drain:prod-control-plane-1",
		"talos-reboot:10.0.0.2",
		"talos-reboot:10.0.0.1",
		"talos-remove:10.0.0.2:" + ksailTargetImage,
		"talos-remove:10.0.0.1:" + ksailTargetImage,
		"talos-pull:10.0.0.2:" + ksailTargetImage,
		"talos-pull:10.0.0.1:" + ksailTargetImage,
	} {
		requireNoLine(t, operations, unexpected)
	}
	restored := readLines(f.talosLog)
	requireLinesEqual(t, restored, []string{
		"talos-revision:10.0.0.2",
		"talos-revision:10.0.0.1",
	})
}

func TestRuntimeProofCannotBeReusedForReplacementNode(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	runtimeProof := filepath.Join(f.workspace, "ghcr-runtime-proof.json")
	first := f.runHelper(validConfig(), []string{
		"--record-runtime-proof", runtimeProof,
	}, nil)
	requireSuccessResult(t, first)

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		if err := os.Remove(filepath.Join(f.syncStateDir, "talos-revision-"+address)); err != nil {
			t.Fatalf("simulate cluster update dropping proof on %s: %v", address, err)
		}
	}
	reassert := f.runHelperPreservingClusterState(validConfig(), []string{
		"--reuse-runtime-proof", runtimeProof,
	}, map[string]string{"FAKE_WORKER_UID": "replacement-worker-uid"})
	requireSuccessResult(t, reassert)

	operations := readLines(f.operationLog)
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "talos-reboot:10.0.0.2")
	// A replacement worker must not invalidate the control plane's matching proof.
	requireNoLine(t, operations, "node-drain:prod-control-plane-1")
	requireNoLine(t, operations, "talos-reboot:10.0.0.1")
	requireNoLine(t, operations, "talos-pull:10.0.0.1:"+ksailTargetImage)
}

func TestStaleRuntimeProofFallsBackToFullVerification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	runtimeProof := filepath.Join(f.workspace, "ghcr-runtime-proof.json")
	first := f.runHelper(validConfig(), []string{
		"--record-runtime-proof", runtimeProof,
	}, nil)
	requireSuccessResult(t, first)

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		if err := os.Remove(filepath.Join(f.syncStateDir, "talos-revision-"+address)); err != nil {
			t.Fatalf("simulate cluster update dropping proof on %s: %v", address, err)
		}
	}
	proof := map[string]any{}
	if err := json.Unmarshal([]byte(mustRead(runtimeProof)), &proof); err != nil {
		t.Fatalf("read runtime proof: %v", err)
	}
	proof["credentialRevision"] = strings.Repeat("0", 64)
	mustWriteJSON(t, runtimeProof, proof)

	reassert := f.runHelperPreservingClusterState(validConfig(), []string{
		"--reuse-runtime-proof", runtimeProof,
	}, nil)
	requireSuccessResult(t, reassert)
	requireContains(t, reassert.stdout+reassert.stderr, "using full per-node verification")
	operations := readLines(f.operationLog)
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "talos-reboot:10.0.0.2")
}

func TestMatchingRevisionRevalidatesChangedDeclaredImage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	previousImage := "ghcr.io/devantler-tech/ksail:v7.166.0"
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_TALOS_NODES_CURRENT":  "true",
		"FAKE_TALOS_VERIFIED_IMAGE": previousImage,
	})
	requireSuccessResult(t, result)
	if !pathExists(f.talosLog) {
		t.Fatal("matching revision incorrectly skipped changed-image proof")
	}
	operations := readLines(f.talosLog)
	requireLinesEqual(t, operations, []string{
		"talos-remove:10.0.0.2:" + ksailTargetImage,
		"talos-pull:10.0.0.2:" + ksailTargetImage,
		"talos-revision:10.0.0.2",
		"talos-remove:10.0.0.1:" + ksailTargetImage,
		"talos-pull:10.0.0.1:" + ksailTargetImage,
		"talos-revision:10.0.0.1",
	})
	operationLog := mustRead(f.operationLog)
	requireNotContains(t, operationLog, "node-drain:")
	requireNotContains(t, operationLog, "talos-reboot:")
	requireNotContains(t, strings.Join(operations, "\n"), previousImage)
}

func TestFailedImageOnlyPullKeepsNodeCordoned(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_TALOS_NODES_CURRENT":  "true",
		"FAKE_TALOS_VERIFIED_IMAGE": "ghcr.io/devantler-tech/ksail:v7.166.0",
		"FAKE_TALOS_FAIL_NODE":      "10.0.0.2",
		"FAKE_TALOS_FAIL_OPERATION": "pull",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "node-claim-cordon:prod-worker-1")
	for _, unexpected := range []string{"node-drain:prod-worker-1", "node-uncordon:prod-worker-1", "talos-reboot:10.0.0.2", "root-patch"} {
		requireNoLine(t, operations, unexpected)
	}
}

// The last image-stale target can disappear while earlier nodes are being
// verified. Its absence must not abort the remaining-node convergence, invoke
// Talos at a stale address, or manufacture a proof for the removed UID.
func TestRemovedImageTargetIsDeselectedBeforeMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	runtimeProof := filepath.Join(f.workspace, "runtime-proof.json")
	result := f.runHelper(validConfig(), []string{"--record-runtime-proof", runtimeProof}, map[string]string{
		"FAKE_TALOS_NODES_CURRENT":         "true",
		"FAKE_TALOS_VERIFIED_IMAGE":        "ghcr.io/devantler-tech/ksail:v7.166.0",
		"FAKE_NODE_REMOVED_BEFORE_PROCESS": "prod-control-plane-1",
	})
	requireSuccessResult(t, result)
	requireContains(t, result.stdout+result.stderr, "deselected")
	operations := readLines(f.operationLog)
	requireLine(t, operations, "talos-revision:10.0.0.2")
	requireLine(t, operations, "root-patch")
	for _, unexpected := range []string{
		"node-claim-cordon:prod-control-plane-1", "node-drain:prod-control-plane-1",
		"talos-reboot:10.0.0.1", "talos-revision:10.0.0.1",
		"talos-remove:10.0.0.1:" + ksailTargetImage, "talos-pull:10.0.0.1:" + ksailTargetImage,
	} {
		requireNoLine(t, operations, unexpected)
	}
	requireNotContains(t, mustRead(runtimeProof), "prod-control-plane-1-uid")
}

// A reboot target can disappear after selection but before the overlap path
// chooses a bootstrap seed. It must be removed from the pending batch before
// bootstrap preparation inspects or quarantines the remaining live targets.
func TestRemovedRebootTargetIsDeselectedBeforeBootstrapSelection(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN":   "true",
		"FAKE_ALL_TALOS_NODES_STALE":       "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":       "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":     "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":        "prod-worker-2",
		"FAKE_NODE_REMOVED_BEFORE_PROCESS": "prod-worker-1",
	})
	requireSuccessResult(t, result)
	requireContains(t, result.stdout+result.stderr, "deselected")
	operations := readLines(f.operationLog)
	for _, unexpected := range []string{
		"node-claim-cordon:prod-worker-1", "node-drain:prod-worker-1",
		"talos-reboot:10.0.0.2", "talos-revision:10.0.0.2",
	} {
		requireNoLine(t, operations, unexpected)
	}
	requireLine(t, operations, "node-claim-cordon:prod-worker-2")
	requireLine(t, operations, "root-patch")
}

func TestRemovedTargetRequiresAuthoritativeUnambiguousInventory(t *testing.T) {
	for _, mode := range []string{"forbidden", "not-found-error", "list-fails", "malformed", "empty", "same-name", "same-address", "same-uid", "still-present"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{
				"FAKE_TALOS_NODES_CURRENT":         "true",
				"FAKE_TALOS_VERIFIED_IMAGE":        "ghcr.io/devantler-tech/ksail:v7.166.0",
				"FAKE_NODE_REMOVED_BEFORE_PROCESS": "prod-worker-1",
				"FAKE_REMOVAL_CONFIRMATION":        mode,
			})
			requireFailureResult(t, result)
			operations := readLines(f.operationLog)
			for _, unexpected := range []string{"node-claim-cordon:prod-worker-1", "talos-revision:10.0.0.2", "root-patch"} {
				requireNoLine(t, operations, unexpected)
			}
		})
	}
}

func TestDeselectionCannotEmptyTheRequiredTargetSet(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_TALOS_NODES_CURRENT":         "true",
		"FAKE_TALOS_VERIFIED_IMAGE":        "ghcr.io/devantler-tech/ksail:v7.166.0",
		"FAKE_NODE_REMOVED_BEFORE_PROCESS": "prod-worker-1 prod-control-plane-1",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "empty successful rollout")
	operations := readLines(f.operationLog)
	requireNoLine(t, operations, "root-patch")
	requireNotContains(t, strings.Join(operations, "\n"), "talos-revision:")
}

func TestRemovedNodeAfterMutationStillFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_TALOS_NODES_CURRENT":         "true",
		"FAKE_TALOS_VERIFIED_IMAGE":        "ghcr.io/devantler-tech/ksail:v7.166.0",
		"FAKE_NODE_REMOVED_AFTER_UNCORDON": "prod-worker-1",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "talos-revision:10.0.0.2")
	requireNoLine(t, operations, "root-patch")
}

func TestRemovedBootstrapOwnedNodeStillFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN":     "true",
		"FAKE_ALL_TALOS_NODES_STALE":         "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":         "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":       "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":          "prod-worker-2",
		"FAKE_NODE_REMOVED_AFTER_QUARANTINE": "prod-worker-2",
	})
	requireFailureResult(t, result)
	requireNotContains(t, result.stdout+result.stderr, "deselected")
	requireContains(t, result.stdout+result.stderr, "durable recovery journal was left intact")
	operations := readLines(f.operationLog)
	for _, name := range []string{"prod-worker-1", "prod-worker-2", "prod-control-plane-1", "prod-control-plane-2", "prod-control-plane-3"} {
		requireLine(t, operations, "node-claim-cordon:"+name)
	}
	for _, unexpected := range []string{
		"talos-auth:10.0.0.5", "talos-reboot:10.0.0.5", "talos-revision:10.0.0.5",
		"node-uncordon:prod-worker-2", "node-release-cordon-owner:prod-worker-2", "root-patch",
	} {
		requireNoLine(t, operations, unexpected)
	}
	var recovery map[string]any
	if err := json.Unmarshal([]byte(mustRead(filepath.Join(f.syncStateDir, "cordon-recovery-prod-worker-2"))), &recovery); err != nil {
		t.Fatal(err)
	}
	if recovery["phase"] != "active" {
		t.Fatalf("owned recovery advanced despite missing node: %v", recovery["phase"])
	}
}

func TestNodeAddedMidRollIsProcessedBeforeRootCutover(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_NODE_APPEARS_AFTER_ROLL": "prod-worker-2"})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	for _, expected := range []string{"talos-auth:10.0.0.5", "node-drain:prod-worker-2", "talos-reboot:10.0.0.5", "talos-revision:10.0.0.5"} {
		requireLine(t, operations, expected)
	}
	if lineIndex(t, operations, "talos-revision:10.0.0.5") >= lineIndex(t, operations, "root-patch") {
		t.Error("root cutover preceded late-node proof")
	}
}

func TestNodeAddedDuringSecondFanoutIsProcessedBeforeCutover(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_NODE_APPEARS_DURING_SECOND_FANOUT": "prod-worker-2"})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	variables := lineIndices(operations, "variables-patch")
	if len(variables) < 2 {
		t.Fatalf("variables fanout passes = %d, want at least 2", len(variables))
	}
	lateRevision := lineIndex(t, operations, "talos-revision:10.0.0.5")
	rootCutover := lineIndex(t, operations, "root-patch")
	if variables[1] >= lateRevision || lateRevision >= rootCutover {
		t.Errorf("unsafe late-node ordering: fanout=%d revision=%d root=%d", variables[1], lateRevision, rootCutover)
	}
}

func TestLateNodeRollReprovesFanoutBeforeRootCutover(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_NODE_APPEARS_DURING_SECOND_FANOUT":          "prod-worker-2",
		"FAKE_CONSUMER_REVERT_DURING_LATE_NODE_NAMESPACE": "wedding-app",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	fanoutStarts := lineIndices(operations, "variables-patch")
	if len(fanoutStarts) != 3 {
		t.Fatalf("fanout pass count = %d, want 3", len(fanoutStarts))
	}
	consumerRevert := lineIndex(t, operations, "consumer-revert:wedding-app")
	rootCutover := lineIndex(t, operations, "root-patch")
	if consumerRevert >= fanoutStarts[2] || fanoutStarts[2] >= rootCutover {
		t.Errorf("unsafe re-proof ordering: revert=%d third-fanout=%d root=%d", consumerRevert, fanoutStarts[2], rootCutover)
	}
}

func lineIndices(lines []string, target string) []int {
	var result []int
	for index, line := range lines {
		if line == target {
			result = append(result, index)
		}
	}
	return result
}

func TestRevokedPreviousCredentialBootstrapsThroughEmptyWorker(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN": "true",
		"FAKE_ALL_TALOS_NODES_STALE":     "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":     "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":   "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":      "prod-worker-2",
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS": "true",
	})
	requireSuccessResult(t, result)
	output := result.stdout + result.stderr
	requireNotContains(t, output, "previous-runtime-token")
	operations := readLines(f.operationLog)
	seedDrain := lineIndex(t, operations, "node-drain:prod-worker-2")
	seedReboot := lineIndex(t, operations, "talos-reboot:10.0.0.5")
	seedPull := lineIndex(t, operations, "talos-pull:10.0.0.5:"+ksailTargetImage)
	seedDataProductProbe := lineIndex(t, operations, "runtime-probe-success:prod-worker-2:ghcr.io/devantler-tech/data-product-controller:latest")
	seedWeddingProbe := lineIndex(t, operations, "runtime-probe-success:prod-worker-2:ghcr.io/devantler-tech/wedding-app:latest")
	seedCoachingProbe := lineIndex(t, operations, "runtime-probe-success:prod-worker-2:ghcr.io/devantler-tech/ascoachingogvaner:latest")
	seedRelease := lineIndex(t, operations, "node-uncordon:prod-worker-2")
	firstWorkloadDrain := lineIndex(t, operations, "node-drain:prod-worker-1")
	if seedDrain >= seedReboot || seedReboot >= seedPull ||
		seedPull >= seedDataProductProbe || seedDataProductProbe >= seedWeddingProbe ||
		seedWeddingProbe >= seedCoachingProbe ||
		seedCoachingProbe >= seedRelease || seedRelease >= firstWorkloadDrain {
		t.Fatalf("unsafe bootstrap ordering: seed drain=%d reboot=%d Talos pull=%d runtime probes=(%d,%d,%d) release=%d workload drain=%d", seedDrain, seedReboot, seedPull, seedDataProductProbe, seedWeddingProbe, seedCoachingProbe, seedRelease, firstWorkloadDrain)
	}
	for _, nodeName := range []string{
		"prod-worker-1",
		"prod-worker-2",
		"prod-control-plane-1",
		"prod-control-plane-2",
		"prod-control-plane-3",
	} {
		claim := lineIndex(t, operations, "node-claim-cordon:"+nodeName)
		if claim >= seedDrain {
			t.Fatalf("stale node %s was not quarantined before seed drain: claim=%d drain=%d", nodeName, claim, seedDrain)
		}
		if pathExists(filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)) {
			t.Fatalf("successful bootstrap left a recovery journal on %s", nodeName)
		}
	}
	requireLine(t, operations, "root-patch")
}

func TestAllStaleRuntimesWithoutEmptyWorkerFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":   "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":   "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES": "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "no empty workload-schedulable node")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestAmbiguousRuntimePullFailureDoesNotBootstrap(t *testing.T) {
	t.Parallel()
	for name, message := range map[string]string{
		"missing message":      "__EMPTY__",
		"dns failure":          "dial tcp: lookup ghcr.io: no such host",
		"rate limit":           "unexpected status from HEAD request to https://ghcr.io/v2/private/manifests/latest: 429 Too Many Requests",
		"network timeout":      "net/http: request canceled while waiting for connection",
		"missing image":        "manifest unknown",
		"signature validation": "signature verification failed",
		"token prefix":         "dial tcp https://ghcr.io/token-proxy: 403 Forbidden",
		"compound status":      "unexpected status from GET request to https://ghcr.io/token?scope=private: 429 Too Many Requests; fallback: 403 Forbidden",
		"embedded generic":     "unauthorized: authentication required while signature verification failed",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{
				"FAKE_ALL_TALOS_NODES_STALE":        "true",
				"FAKE_BOOTSTRAP_WORKER_NAME":        "prod-worker-2",
				"FAKE_RUNTIME_PULL_FAIL_NODES":      "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
				"FAKE_RUNTIME_PULL_FAILURE_MESSAGE": message,
				"FAKE_EMPTY_WORKLOAD_NODES":         "prod-worker-2",
			})
			requireFailureResult(t, result)
			requireContains(t, result.stdout+result.stderr, "refusing to drain workloads onto peers with unproved runtime auth")
			if message != "__EMPTY__" {
				requireNotContains(t, result.stdout+result.stderr, message)
			}
			operations := readLines(f.operationLog)
			requireNotContains(t, strings.Join(operations, "\n"), "node-claim-cordon:")
			requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
			requireNoLine(t, operations, "root-patch")
		})
	}
}

func TestBootstrapRejectsUnprovedCurrentMarkedDestination(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ready := []any{map[string]any{"type": "Ready", "status": "True"}}
	inventory := map[string]any{"items": []any{
		nodeFixture("prod-worker-1", "prod-worker-1-uid", "10.0.0.2", false, ready, nil),
		nodeFixture(
			"prod-control-plane-1",
			"prod-control-plane-1-uid",
			"10.0.0.1",
			true,
			ready,
			map[string]any{
				"platform.devantler.tech/ghcr-pull-verified-revision-v2": f.expectedRevision(),
				"platform.devantler.tech/ghcr-pull-verified-image-v2":    ksailTargetImage,
			},
		),
	}}
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_NODE_JSON":               encodeJSON(inventory),
		"FAKE_RUNTIME_PULL_FAIL_NODES": "prod-control-plane-1",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "not a pending credential-reboot target")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-claim-cordon:")
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestMalformedPodInventoryCannotAuthorizeBootstrapSeed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":        "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":        "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":      "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":         "prod-worker-2",
		"FAKE_MALFORMED_POD_INVENTORY_NODE": "prod-worker-2",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "no empty workload-schedulable node")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-claim-cordon:")
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestBootstrapWaitsForSeedReleaseTaintToClear(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN":                        "true",
		"FAKE_ALL_TALOS_NODES_STALE":                            "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":                            "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":                          "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":                             "prod-worker-2",
		"FAKE_TRANSIENT_UNSCHEDULABLE_TAINT_AFTER_RELEASE_NODE": "prod-worker-2",
	})
	requireSuccessResult(t, result)
	if reads := mustRead(filepath.Join(f.syncStateDir, "post-release-node-read-count-prod-worker-2")); reads != "3" {
		t.Fatalf("post-release node reads = %q, want identity revalidation plus two bounded release checks", reads)
	}
	if !pathExists(filepath.Join(f.syncStateDir, "release-taint-cleared-prod-worker-2")) {
		t.Fatal("bootstrap continued before the lagging release taint cleared")
	}
	operations := readLines(f.operationLog)
	requireLine(t, operations, "talos-reboot:10.0.0.5")
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "root-patch")
}

func TestBootstrapAcceptsOmittedUnschedulableAfterSeedRelease(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN":             "true",
		"FAKE_ALL_TALOS_NODES_STALE":                 "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":                 "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":               "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":                  "prod-worker-2",
		"FAKE_OMIT_UNSCHEDULABLE_AFTER_RELEASE_NODE": "prod-worker-2",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "node-uncordon:prod-worker-2")
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "root-patch")
}

func TestBootstrapFailureBeforeRebootRestoresEveryOwnedCordon(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN": "true",
		"FAKE_ALL_TALOS_NODES_STALE":     "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":     "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":   "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":      "prod-worker-2",
		"FAKE_TALOS_FAIL_NODE":           "10.0.0.5",
		"FAKE_TALOS_FAIL_OPERATION":      "auth",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	requireNoLine(t, operations, "talos-reboot:10.0.0.5")
	for _, nodeName := range []string{
		"prod-worker-1",
		"prod-worker-2",
		"prod-control-plane-1",
		"prod-control-plane-2",
		"prod-control-plane-3",
	} {
		requireLine(t, operations, "node-uncordon:"+nodeName)
		if pathExists(filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName)) {
			t.Fatalf("pre-reboot bootstrap failure left %s owned-cordoned", nodeName)
		}
	}
}

func TestBootstrapPullFailureRetainsOnlyUnprovedSeedCordon(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_REVOKE_CURRENT_ROOT_TOKEN": "true",
		"FAKE_ALL_TALOS_NODES_STALE":     "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":     "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES":   "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":      "prod-worker-2",
		"FAKE_TALOS_FAIL_NODE":           "10.0.0.5",
		"FAKE_TALOS_FAIL_OPERATION":      "pull",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "talos-reboot:10.0.0.5")
	requireNoLine(t, operations, "node-uncordon:prod-worker-2")
	if !pathExists(filepath.Join(f.syncStateDir, "cordon-owner-prod-worker-2")) {
		t.Fatal("unproved bootstrap seed did not retain its owned cordon")
	}
	recoveryPath := filepath.Join(f.syncStateDir, "cordon-recovery-prod-worker-2")
	if !pathExists(recoveryPath) {
		t.Fatal("unproved bootstrap seed did not retain its durable recovery journal")
	}
	var recovery map[string]any
	if err := json.Unmarshal([]byte(mustRead(recoveryPath)), &recovery); err != nil {
		t.Fatalf("parse retained recovery journal: %v", err)
	}
	if recovery["phase"] != "retain" {
		t.Fatalf("retained recovery phase = %v, want retain", recovery["phase"])
	}
	if strings.Contains(mustRead(recoveryPath), "fixture-secret-token") {
		t.Fatal("durable recovery journal contained decrypted registry credentials")
	}
	for _, nodeName := range []string{
		"prod-worker-1",
		"prod-control-plane-1",
		"prod-control-plane-2",
		"prod-control-plane-3",
	} {
		requireLine(t, operations, "node-uncordon:"+nodeName)
		if pathExists(filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName)) {
			t.Fatalf("unprocessed stale peer %s kept a bootstrap-only cordon", nodeName)
		}
		if pathExists(filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)) {
			t.Fatalf("unprocessed stale peer %s kept a bootstrap recovery journal", nodeName)
		}
	}

	retry := f.runHelperPreservingClusterState(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":   "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":   "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES": "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":    "prod-worker-2",
	})
	requireFailureResult(t, retry)
	requireContains(t, retry.stdout+retry.stderr, "refusing to release any node in that batch")
	retryOperations := readLines(f.operationLog)
	requireNoLine(t, retryOperations, "node-uncordon:prod-worker-2")
	requireNoLine(t, retryOperations, "root-patch")
}

func TestBootstrapCleanupFailureRetainsDurableRecoveryAndNextRunReconciles(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	first := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":   "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":   "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES": "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":    "prod-worker-2",
		"FAKE_TALOS_FAIL_NODE":         "10.0.0.5",
		"FAKE_TALOS_FAIL_OPERATION":    "auth",
		"FAKE_UNCORDON_FAIL_NODE":      "prod-worker-1",
	})
	requireFailureResult(t, first)
	requireContains(t, first.stdout+first.stderr, "Bootstrap quarantine cleanup was incomplete")
	firstOperations := readLines(f.operationLog)
	requireNoLine(t, firstOperations, "root-patch")

	recoveryPath := filepath.Join(f.syncStateDir, "cordon-recovery-prod-worker-1")
	ownerPath := filepath.Join(f.syncStateDir, "cordon-owner-prod-worker-1")
	if !pathExists(ownerPath) || !pathExists(recoveryPath) {
		t.Fatal("failed cleanup did not preserve its durable owner and recovery journal")
	}
	var recovery map[string]any
	if err := json.Unmarshal([]byte(mustRead(recoveryPath)), &recovery); err != nil {
		t.Fatalf("parse durable recovery journal: %v", err)
	}
	if recovery["phase"] != "rollback-safe" {
		t.Fatalf("durable recovery phase = %v, want rollback-safe", recovery["phase"])
	}
	if strings.Contains(mustRead(recoveryPath), "fixture-secret-token") {
		t.Fatal("durable recovery journal contained decrypted registry credentials")
	}
	for _, nodeName := range []string{
		"prod-worker-2",
		"prod-control-plane-1",
		"prod-control-plane-2",
		"prod-control-plane-3",
	} {
		if pathExists(filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)) {
			t.Fatalf("cleanup stopped before releasing %s", nodeName)
		}
	}

	second := f.runHelperPreservingClusterState(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":   "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":   "prod-worker-2",
		"FAKE_RUNTIME_PULL_FAIL_NODES": "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":    "prod-worker-2",
	})
	requireSuccessResult(t, second)
	secondOperations := readLines(f.operationLog)
	reconcileRelease := lineIndex(t, secondOperations, "node-uncordon:prod-worker-1")
	firstNewClaim := lineIndex(t, secondOperations, "node-claim-cordon:prod-worker-1")
	if reconcileRelease >= firstNewClaim {
		t.Fatalf("durable recovery was not reconciled before the new rollout: release=%d claim=%d", reconcileRelease, firstNewClaim)
	}
	if pathExists(ownerPath) || pathExists(recoveryPath) {
		t.Fatal("successful retry left the reconciled owner or recovery journal behind")
	}
	requireLine(t, secondOperations, "root-patch")
}

func TestRecoveryReconciliationRejectsConcurrentPhaseAdvance(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const nodeName = "prod-worker-1"
	const owner = "previous-roll-owner"
	recoveryPath := filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)
	mustWriteJSON(t, recoveryPath, map[string]any{
		"v":               1,
		"owner":           owner,
		"uid":             nodeName + "-uid",
		"desiredRevision": f.expectedRevision(),
		"wasCordoned":     0,
		"initialTaints":   []any{},
		"phase":           "rollback-safe",
	})
	for path, contents := range map[string]string{
		filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName): owner,
		filepath.Join(f.syncStateDir, "cordoned-"+nodeName):     "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("seed recovery marker %s: %v", path, err)
		}
	}

	result := f.runHelperPreservingClusterState(validConfig(), nil, map[string]string{
		"FAKE_RECOVERY_ADVANCES_BEFORE_RELEASE_NODE": nodeName,
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "Recovery journal changed")
	operations := readLines(f.operationLog)
	requireLine(t, operations, "concurrent-recovery-phase:"+nodeName+":active")
	requireNoLine(t, operations, "node-uncordon:"+nodeName)
	requireNoLine(t, operations, "node-claim-cordon:"+nodeName)
	requireNoLine(t, operations, "root-patch")

	var recovery map[string]any
	if err := json.Unmarshal([]byte(mustRead(recoveryPath)), &recovery); err != nil {
		t.Fatalf("parse concurrently advanced recovery journal: %v", err)
	}
	if recovery["phase"] != "active" {
		t.Fatalf("concurrent recovery phase = %v, want active", recovery["phase"])
	}
}

func TestRecoveryReconciliationKeepsActiveOwnerBatchQuarantined(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const owner = "active-bootstrap-owner"
	for nodeName, phase := range map[string]string{
		"prod-worker-1":        "rollback-safe",
		"prod-control-plane-1": "active",
	} {
		recoveryPath := filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)
		mustWriteJSON(t, recoveryPath, map[string]any{
			"v":               1,
			"owner":           owner,
			"uid":             nodeName + "-uid",
			"desiredRevision": f.expectedRevision(),
			"wasCordoned":     0,
			"initialTaints":   []any{},
			"phase":           phase,
		})
		for path, contents := range map[string]string{
			filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName): owner,
			filepath.Join(f.syncStateDir, "cordoned-"+nodeName):     "",
		} {
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("seed active owner batch marker %s: %v", path, err)
			}
		}
	}

	result := f.runHelperPreservingClusterState(validConfig(), nil, nil)
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "refusing to release any node in that batch")
	operations := readLines(f.operationLog)
	for _, nodeName := range []string{"prod-worker-1", "prod-control-plane-1"} {
		requireNoLine(t, operations, "node-uncordon:"+nodeName)
		if !pathExists(filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName)) ||
			!pathExists(filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)) {
			t.Fatalf("active owner batch released durable quarantine for %s", nodeName)
		}
	}
	requireNoLine(t, operations, "root-patch")
}

func TestReleaseReadyRecoveryPreservesPreExistingCordonBeforeNewRoll(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const nodeName = "prod-worker-1"
	const owner = "completed-roll-owner"
	recoveryPath := filepath.Join(f.syncStateDir, "cordon-recovery-"+nodeName)
	ownerPath := filepath.Join(f.syncStateDir, "cordon-owner-"+nodeName)
	cordonPath := filepath.Join(f.syncStateDir, "cordoned-"+nodeName)
	mustWriteJSON(t, recoveryPath, map[string]any{
		"v":               1,
		"owner":           owner,
		"uid":             nodeName + "-uid",
		"desiredRevision": f.expectedRevision(),
		"wasCordoned":     1,
		"initialTaints":   []any{},
		"phase":           "release-ready",
	})
	for path, contents := range map[string]string{
		ownerPath:  owner,
		cordonPath: "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("seed release-ready marker %s: %v", path, err)
		}
	}

	result := f.runHelperPreservingClusterState(validConfig(), nil, nil)
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	releases := lineIndices(operations, "node-release-cordon-owner:"+nodeName)
	if len(releases) != 2 {
		t.Fatalf("pre-existing cordon owner releases = %d, want reconcile and rollout releases", len(releases))
	}
	claim := lineIndex(t, operations, "node-claim-cordon:"+nodeName)
	if releases[0] >= claim {
		t.Fatalf("release-ready journal was not reconciled before the new claim: release=%d claim=%d", releases[0], claim)
	}
	if pathExists(ownerPath) || pathExists(recoveryPath) {
		t.Fatal("successful release-ready reconciliation left owner or recovery state")
	}
	if !pathExists(cordonPath) {
		t.Fatal("release-ready reconciliation removed the pre-existing cordon")
	}
	requireLine(t, operations, "root-patch")
}

func TestTaintedPeersDoNotCountAsRuntimePullCapacity(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ready := []any{map[string]any{"type": "Ready", "status": "True"}}
	worker := nodeFixture("prod-worker-1", "prod-worker-1-uid", "10.0.0.2", false, ready, nil)
	controlPlaneOne := nodeFixture("prod-control-plane-1", "prod-control-plane-1-uid", "10.0.0.1", true, ready, nil)
	controlPlaneOne["spec"] = map[string]any{
		"unschedulable": false,
		"taints": []any{map[string]any{
			"key":    "node-role.kubernetes.io/control-plane",
			"effect": "NoSchedule",
		}},
	}
	controlPlaneTwo := nodeFixture("prod-control-plane-2", "prod-control-plane-2-uid", "10.0.0.3", true, ready, nil)
	controlPlaneTwo["spec"] = map[string]any{
		"unschedulable": false,
		"taints": []any{map[string]any{
			"key":    "node-role.kubernetes.io/control-plane",
			"effect": "NoExecute",
		}},
	}
	inventory := map[string]any{"items": []any{worker, controlPlaneOne, controlPlaneTwo}}

	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_NODE_JSON": encodeJSON(inventory),
	})

	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "No Ready schedulable peer")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestRuntimeProbeRejectsInjectedImagePullSecret(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_RUNTIME_PROBE_INJECT_PULL_SECRET_NODES": "prod-control-plane-2"})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "imagePullSecret")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestFluxPolicyHandoffSuspendsOwningReconcileAcrossRuntimeProof(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_PARENT_RECONCILING_AFTER_PAUSE": "true",
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS":           "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	parentPause := lineIndex(t, operations, "flux-policy-parent-pause:flux-system")
	parentStable := lineIndex(t, operations, "flux-policy-parent-stable:flux-system")
	pause := lineIndex(t, operations, "flux-policy-pause:infrastructure")
	firstPolicyApply := lineIndex(t, operations, "ivpol-policy-apply:verify-app-images")
	firstRuntimeProbe := lineIndex(
		t,
		operations,
		"runtime-probe-success:prod-control-plane-2:ghcr.io/devantler-tech/data-product-controller:latest",
	)
	rootPatch := lineIndex(t, operations, "root-patch")
	resume := lineIndex(t, operations, "flux-policy-resume:infrastructure")
	parentResume := lineIndex(t, operations, "flux-policy-parent-resume:flux-system")
	if parentPause >= parentStable ||
		parentStable >= pause ||
		pause >= firstPolicyApply ||
		firstPolicyApply >= firstRuntimeProbe ||
		firstRuntimeProbe >= rootPatch ||
		rootPatch >= resume ||
		resume >= parentResume {
		t.Fatalf(
			"unsafe Flux policy handoff ordering: parent pause=%d parent stable=%d child pause=%d policy=%d probe=%d root=%d child resume=%d parent resume=%d",
			parentPause,
			parentStable,
			pause,
			firstPolicyApply,
			firstRuntimeProbe,
			rootPatch,
			resume,
			parentResume,
		)
	}
	if pathExists(filepath.Join(f.syncStateDir, "flux-policy-handoff-owner")) {
		t.Fatal("successful run left Flux policy handoff ownership behind")
	}
}

func TestFluxChildReconciliationBlocksBeforePolicyHandoffAcquisition(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING": "true",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"did not quiesce before the image-verification policy handoff",
	)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-parent-pause:flux-system")
	requireNoLine(t, operations, "flux-policy-pause:infrastructure")
	requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestHandoffQuiesceTimeoutNamesTheBlockingCondition(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING":         "true",
		"FAKE_FLUX_POLICY_RECONCILING_REASON":  "ProgressingWithRetry",
		"FAKE_FLUX_POLICY_RECONCILING_MESSAGE": "Running health checks for revision latest@sha256:fixture",
		"FAKE_FLUX_POLICY_CHILD_UNHEALTHY":     "timeout waiting for: [Cluster/observability/coroot-db status: 'InProgress']",
	})
	requireFailureResult(t, result)
	output := result.stdout + result.stderr
	requireContains(t, output, "did not quiesce before the image-verification policy handoff")
	requireContains(t, output, "ProgressingWithRetry")
	requireContains(t, output, "Cluster/observability/coroot-db")
}

func TestHandoffQuiesceTimeoutNamesTheUnreadyDependency(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING":                 "true",
		"FAKE_FLUX_POLICY_CHILD_DEPENDENCY_NOT_READY":  "infrastructure-controllers",
		"FAKE_FLUX_POLICY_DEPENDENCY_BLOCKING_MESSAGE": "Running health checks for revision latest@sha256:fixture with a timeout of 25m0s",
	})
	requireFailureResult(t, result)
	output := result.stdout + result.stderr
	requireContains(t, output, "did not quiesce before the image-verification policy handoff")
	requireContains(t, output, "infrastructure-controllers")
	requireContains(t, output, "with a timeout of 25m0s")
}

func TestHandoffQuiesceDiagnosticCannotChangeTheOutcome(t *testing.T) {
	t.Parallel()
	blocked := newFixture(t)
	blockedResult := blocked.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING": "true",
	})
	broken := newFixture(t)
	brokenResult := broken.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING":                "true",
		"FAKE_FLUX_POLICY_CHILD_DEPENDENCY_NOT_READY": "infrastructure-controllers",
		"FAKE_FLUX_POLICY_DEPENDENCY_READ_FAILS":      "true",
	})
	requireFailureResult(t, brokenResult)
	requireContains(
		t,
		brokenResult.stdout+brokenResult.stderr,
		"did not quiesce before the image-verification policy handoff",
	)
	// Prove the dependency read was actually attempted and swallowed, so this
	// stays an ablation of the diagnostic rather than of the code path.
	requireContains(
		t,
		brokenResult.stdout+brokenResult.stderr,
		"Could not read dependency flux-system/infrastructure-controllers",
	)
	if brokenResult.exitCode != blockedResult.exitCode {
		t.Fatalf(
			"an unreadable dependency changed the handoff failure exit status: got %d, want %d",
			brokenResult.exitCode,
			blockedResult.exitCode,
		)
	}
	requireLine(t, readLines(broken.operationLog), "flux-policy-parent-resume:flux-system")
	requireNoLine(t, readLines(broken.operationLog), "flux-policy-pause:infrastructure")
}

func TestFluxChildQuiescesBeforePolicyHandoffAcquisition(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING_READS_BEFORE_PAUSE": "2",
		"FLUX_GHCR_SYNC_ATTEMPTS":                         "3",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	childReconciling := lineIndex(
		t,
		operations,
		"flux-policy-child-reconciling:infrastructure",
	)
	childStable := lineIndex(t, operations, "flux-policy-child-stable:infrastructure")
	pause := lineIndex(t, operations, "flux-policy-pause:infrastructure")
	firstPolicyApply := lineIndex(t, operations, "ivpol-policy-apply:verify-app-images")
	if childReconciling >= childStable ||
		childStable >= pause ||
		pause >= firstPolicyApply {
		t.Fatalf(
			"unsafe child Flux handoff ordering: reconciling=%d stable=%d pause=%d policy=%d",
			childReconciling,
			childStable,
			pause,
			firstPolicyApply,
		)
	}
}

func TestStaleFluxChildReconcilingConditionAfterPauseDoesNotBlockHandoff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RECONCILING_AFTER_PAUSE": "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-pause:infrastructure")
	requireLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
}

func TestFluxControllerRestartTerminatesPrePauseProcessesBeforePolicyStage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_LOG_FLUX_CONTROLLER_RESTART": "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	parentPause := lineIndex(t, operations, "flux-policy-parent-pause:flux-system")
	childPause := lineIndex(t, operations, "flux-policy-pause:infrastructure")
	restart := lineIndex(t, operations, "flux-controller-restart:kustomize-controller")
	oldProcessesTerminated := lineIndex(
		t,
		operations,
		"flux-controller-old-processes-terminated:kustomize-controller",
	)
	firstPolicyApply := lineIndex(t, operations, "ivpol-policy-apply:verify-app-images")
	if parentPause >= childPause ||
		childPause >= restart ||
		restart >= oldProcessesTerminated ||
		oldProcessesTerminated >= firstPolicyApply {
		t.Fatalf(
			"unsafe Flux controller handoff ordering: parent=%d child=%d restart=%d terminated=%d policy=%d",
			parentPause,
			childPause,
			restart,
			oldProcessesTerminated,
			firstPolicyApply,
		)
	}
}

func TestFluxControllerRolloutFailureBlocksPolicyMutationAndReleasesFences(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_CONTROLLER_ROLLOUT_FAIL": "true",
		"FAKE_LOG_FLUX_CONTROLLER_RESTART":  "true",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"did not complete the policy handoff restart",
	)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-parent-pause:flux-system")
	requireLine(t, operations, "flux-policy-pause:infrastructure")
	requireLine(t, operations, "flux-controller-restart:kustomize-controller")
	requireNoLine(t, operations, "flux-controller-old-processes-terminated:kustomize-controller")
	requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireNoLine(t, operations, "root-patch")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestTerminatingPrePauseFluxControllerBlocksPolicyMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING": "true",
		"FAKE_LOG_FLUX_CONTROLLER_RESTART":         "true",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"Could not prove every pre-handoff kustomize-controller process was replaced",
	)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-parent-pause:flux-system")
	requireLine(t, operations, "flux-policy-pause:infrastructure")
	requireLine(t, operations, "flux-controller-restart:kustomize-controller")
	requireLine(
		t,
		operations,
		"flux-controller-rollout-complete-with-terminating-old-pod:kustomize-controller",
	)
	requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireNoLine(t, operations, "root-patch")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

// A pre-handoff Pod inside its termination grace period is a correct rollout, not a surviving
// process: `kubectl rollout status` returns before the superseded Pod is gone. Sampling the proof
// once failed these deploys and evicted their PRs from the merge queue (#2926).
func TestTransientlyTerminatingFluxControllerPodIsAwaited(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING_SAMPLES": "1",
		"FAKE_LOG_FLUX_CONTROLLER_RESTART":                 "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-controller-restart:kustomize-controller")
	requireLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestAmbiguousFluxControllerRestartIsAdopted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_CONTROLLER_RESTART_RESPONSE_LOST": "true",
		"FAKE_LOG_FLUX_CONTROLLER_RESTART":           "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-controller-restart:kustomize-controller")
	requireLine(t, operations, "flux-controller-old-processes-terminated:kustomize-controller")
	requireLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestFluxChildResourceVersionChurnAfterPauseBlocksPolicyMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_RESOURCE_VERSION_CHURN_AFTER_PAUSE": "true",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"did not acknowledge a stable pause",
	)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-pause:infrastructure")
	requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
}

func TestFluxSyncAttemptsMustPermitTwoFenceObservations(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FLUX_GHCR_SYNC_ATTEMPTS": "1",
	})
	if result.exitCode != 64 {
		t.Fatalf(
			"command exit = %d, want 64\nstdout:\n%s\nstderr:\n%s",
			result.exitCode,
			result.stdout,
			result.stderr,
		)
	}
	requireContains(t, result.stdout+result.stderr, "must be at least 2")
	if pathExists(f.kubectlCalled) {
		t.Fatal("invalid fence observation budget reached kubectl")
	}
}

func TestFluxFenceAcquisitionCreatesMissingAnnotationMaps(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_PARENT_NO_ANNOTATIONS":  "true",
		"FAKE_FLUX_POLICY_HANDOFF_NO_ANNOTATIONS": "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	requireLine(t, operations, "flux-policy-parent-pause:flux-system")
	requireLine(t, operations, "flux-policy-pause:infrastructure")
	requireLine(t, operations, "root-patch")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestRejectedFluxParentPatchPreservesSafeDiagnostic(t *testing.T) {
	t.Parallel()
	for name, rejection := range map[string]string{
		"version test": "Error from server (Invalid): JSON patch test failed at /metadata/resourceVersion",
		"forbidden":    "Error from server (Forbidden): parent handoff permission denied",
		"untrusted text": "Error from server (Invalid): rejected\n" +
			"::error::fixture-not-a-workflow-command\ncontrol:\x01\x1b done",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{
				"FAKE_FLUX_POLICY_PARENT_PATCH_REJECTION": rejection,
			})
			requireFailureResult(t, result)
			output := result.stdout + result.stderr
			for _, line := range strings.Split(rejection, "\n") {
				printable := strings.Map(func(r rune) rune {
					if r == '\t' || (r >= 32 && r <= 126) {
						return r
					}
					return -1
				}, line)
				requireContains(t, output, "flux-policy-parent-patch: "+printable)
			}
			requireContains(t, output, "Could not atomically pause or adopt the parent Flux policy handoff")
			requireNotContains(t, output, "\n::error::fixture-not-a-workflow-command")
			requireNotContains(t, output, "\x01")
			requireNotContains(t, output, "\x1b")
			requireNotContains(t, output, "fixture-secret-token")
			operations := readLines(f.operationLog)
			if got := strings.Count(strings.Join(operations, "\n"), "flux-policy-parent-patch-rejected"); got != 1 {
				t.Fatalf("patch rejection attempts = %d, want one unchanged acquisition attempt", got)
			}
			for _, forbidden := range []string{
				"flux-policy-parent-pause:flux-system", "flux-policy-pause:infrastructure", "root-patch",
			} {
				requireNoLine(t, operations, forbidden)
			}
			for _, marker := range []string{"flux-policy-parent-owner", "flux-policy-parent-suspended"} {
				if pathExists(filepath.Join(f.syncStateDir, marker)) {
					t.Fatalf("rejected parent patch left %s", marker)
				}
			}
		})
	}
}

func TestAmbiguousFluxFenceAcquisitionIsAdoptedAndCleaned(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		environment string
		marker      string
	}{
		{
			name:        "parent",
			environment: "FAKE_FLUX_POLICY_PARENT_PATCH_RESPONSE_LOST",
			marker:      "flux-policy-parent-patch-response-lost",
		},
		{
			name:        "child",
			environment: "FAKE_FLUX_POLICY_HANDOFF_PATCH_RESPONSE_LOST",
			marker:      "flux-policy-handoff-patch-response-lost",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{
				test.environment: "true",
			})
			requireSuccessResult(t, result)
			requireNotContains(t, result.stdout+result.stderr, "flux-policy-parent-patch:")
			if !pathExists(filepath.Join(f.syncStateDir, test.marker)) {
				t.Fatal("fixture did not lose the applied fence patch response")
			}
			for _, residual := range []string{
				"flux-policy-parent-owner",
				"flux-policy-parent-suspended",
				"flux-policy-handoff-owner",
				"flux-policy-handoff-suspended",
			} {
				if pathExists(filepath.Join(f.syncStateDir, residual)) {
					t.Fatalf("ambiguous acquisition left residual fence %s", residual)
				}
			}
			operations := readLines(f.operationLog)
			requireLine(t, operations, "root-patch")
			requireLine(t, operations, "flux-policy-resume:infrastructure")
			requireLine(t, operations, "flux-policy-parent-resume:flux-system")
		})
	}
}

func TestAmbiguousFluxParentReleaseIsAdopted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_PARENT_RELEASE_RESPONSE_LOST": "true",
	})
	requireSuccessResult(t, result)
	if !pathExists(filepath.Join(f.syncStateDir, "flux-policy-parent-release-response-lost")) {
		t.Fatal("fixture did not lose the applied parent fence release response")
	}
	for _, residual := range []string{
		"flux-policy-parent-owner",
		"flux-policy-parent-suspended",
	} {
		if pathExists(filepath.Join(f.syncStateDir, residual)) {
			t.Fatalf("ambiguous parent release left residual fence %s", residual)
		}
	}
	operations := readLines(f.operationLog)
	requireLine(t, operations, "root-patch")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestAmbiguousFluxChildReleaseIsAdopted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_HANDOFF_RELEASE_RESPONSE_LOST": "true",
	})
	requireSuccessResult(t, result)
	if !pathExists(filepath.Join(f.syncStateDir, "flux-policy-handoff-release-response-lost")) {
		t.Fatal("fixture did not lose the applied child fence release response")
	}
	for _, residual := range []string{
		"flux-policy-handoff-owner",
		"flux-policy-handoff-suspended",
	} {
		if pathExists(filepath.Join(f.syncStateDir, residual)) {
			t.Fatalf("ambiguous child release left residual fence %s", residual)
		}
	}
	operations := readLines(f.operationLog)
	requireLine(t, operations, "root-patch")
	requireLine(t, operations, "flux-policy-resume:infrastructure")
	requireLine(t, operations, "flux-policy-parent-resume:flux-system")
}

func TestChildFenceReleaseFailureRetainsParentFence(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_HANDOFF_RELEASE_FAIL": "true",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	requireNoLine(t, operations, "flux-policy-resume:infrastructure")
	requireNoLine(t, operations, "flux-policy-parent-resume:flux-system")
	for _, residual := range []string{
		"flux-policy-parent-owner",
		"flux-policy-parent-suspended",
		"flux-policy-handoff-owner",
		"flux-policy-handoff-suspended",
	} {
		if !pathExists(filepath.Join(f.syncStateDir, residual)) {
			t.Fatalf("failed child release did not retain fence %s", residual)
		}
	}
}

func TestFluxPolicyHandoffResumesAfterPolicyStageFailure(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_POLICY_DRY_RUN_FAILURE": "true",
	})
	requireFailureResult(t, result)
	operations := readLines(f.operationLog)
	pause := lineIndex(t, operations, "flux-policy-pause:infrastructure")
	resume := lineIndex(t, operations, "flux-policy-resume:infrastructure")
	if pause >= resume {
		t.Fatalf("Flux policy handoff resumed before it was acquired: pause=%d resume=%d", pause, resume)
	}
	requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireNoLine(t, operations, "root-patch")
	if pathExists(filepath.Join(f.syncStateDir, "flux-policy-handoff-owner")) {
		t.Fatal("failed policy stage left Flux policy handoff ownership behind")
	}
}

func TestExistingFluxPolicyHandoffOwnerBlocksBeforeMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_FLUX_POLICY_HANDOFF_OWNED": "true",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "already owns the image-verification policy handoff")
	if pathExists(f.operationLog) {
		operations := readLines(f.operationLog)
		requireNoLine(t, operations, "flux-policy-pause:infrastructure")
		requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
		requireNoLine(t, operations, "node-claim-cordon:prod-worker-1")
		requireNoLine(t, operations, "root-patch")
	}
}

func TestStaleImageVerificationWebhookBudgetIsStagedBeforeRuntimeProbe(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_WEBHOOKS_STALE": "true",
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS":         "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	dryRun := lineIndex(t, operations, "ivpol-policy-dry-run:verify-app-images")
	appApply := lineIndex(t, operations, "ivpol-policy-apply:verify-app-images")
	consolidatedReady := lineIndex(t, operations, "ivpol-policy-consolidated-ready")
	ksailDelete := lineIndex(t, operations, "ivpol-policy-delete:verify-ksail-images")
	webhookReady := lineIndex(t, operations, "ivpol-policy-webhooks-ready")
	firstRuntimeProbe := lineIndex(
		t,
		operations,
		"runtime-probe-success:prod-control-plane-2:ghcr.io/devantler-tech/data-product-controller:latest",
	)
	if dryRun >= appApply ||
		appApply >= consolidatedReady ||
		consolidatedReady >= ksailDelete ||
		ksailDelete >= webhookReady ||
		webhookReady >= firstRuntimeProbe {
		t.Fatalf(
			"unsafe image-verification bootstrap ordering: dry-run=%d app apply=%d consolidated ready=%d ksail delete=%d webhook ready=%d runtime probe=%d",
			dryRun,
			appApply,
			consolidatedReady,
			ksailDelete,
			webhookReady,
			firstRuntimeProbe,
		)
	}
}

func TestEveryRuntimeProbeReassertsImageVerificationPolicy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS": "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	applyPositions := lineIndices(operations, "ivpol-policy-apply:verify-app-images")
	var probePositions []int
	for index, operation := range operations {
		if strings.HasPrefix(operation, "runtime-probe-success:") {
			probePositions = append(probePositions, index)
		}
	}
	if len(probePositions) == 0 {
		t.Fatal("fixture did not exercise runtime probes")
	}
	if len(applyPositions) != len(probePositions)+1 {
		t.Fatalf(
			"policy applications = %d, want one transaction stage plus %d runtime probe reassertions",
			len(applyPositions),
			len(probePositions),
		)
	}
	policyHandoff := lineIndex(t, operations, "flux-policy-pause:infrastructure")
	firstFanout := lineIndex(t, operations, "variables-patch")
	if policyHandoff >= applyPositions[0] || applyPositions[0] >= firstFanout {
		t.Fatalf(
			"transaction policy stage was outside the fenced pre-fanout window: handoff=%d apply=%d fanout=%d",
			policyHandoff,
			applyPositions[0],
			firstFanout,
		)
	}
	for index := range probePositions {
		previousProbe := -1
		if index > 0 {
			previousProbe = probePositions[index-1]
		}
		probeApply := applyPositions[index+1]
		if probeApply <= previousProbe || probeApply >= probePositions[index] {
			t.Fatalf(
				"runtime probe %d was not immediately fenced by a fresh policy reassertion: previous probe=%d apply=%d probe=%d",
				index,
				previousProbe,
				probeApply,
				probePositions[index],
			)
		}
	}
}

func TestRejectedConsolidatedImageVerificationPolicyFailsBeforeMutation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_POLICY_DRY_RUN_FAILURE": "true",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "API server rejected")
	if pathExists(f.operationLog) {
		operations := readLines(f.operationLog)
		requireNoLine(t, operations, "ivpol-policy-apply:verify-app-images")
		requireNoLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
		requireNotContains(t, strings.Join(operations, "\n"), "runtime-probe-success:")
		requireNoLine(t, operations, "root-patch")
	}
}

func TestRetiredImageVerificationPolicyDeleteFailureFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_POLICY_DELETE_FAILURE": "true",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "Could not retire")
	operations := readLines(f.operationLog)
	requireLine(t, operations, "ivpol-policy-apply:verify-app-images")
	requireNoLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
	requireNotContains(t, strings.Join(operations, "\n"), "runtime-probe-success:")
	requireNoLine(t, operations, "root-patch")
}

func TestValidationOnlyImageVerificationWebhookConverges(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS": "true",
	})
	requireSuccessResult(t, result)
	operations := readLines(f.operationLog)
	consolidatedReady := lineIndex(t, operations, "ivpol-policy-consolidated-ready")
	ksailDelete := lineIndex(t, operations, "ivpol-policy-delete:verify-ksail-images")
	webhookReady := lineIndex(t, operations, "ivpol-policy-webhooks-ready")
	firstRuntimeProbe := lineIndex(
		t,
		operations,
		"runtime-probe-success:prod-control-plane-2:ghcr.io/devantler-tech/data-product-controller:latest",
	)
	if consolidatedReady >= ksailDelete || ksailDelete >= webhookReady || webhookReady >= firstRuntimeProbe {
		t.Fatalf(
			"unsafe validating-only handoff ordering: consolidated ready=%d ksail delete=%d webhook ready=%d runtime probe=%d",
			consolidatedReady,
			ksailDelete,
			webhookReady,
			firstRuntimeProbe,
		)
	}
}

func TestNonMutatingImageVerificationPolicyRejectsUnexpectedMutatingWebhook(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_MUTATION_REQUIRED": "true",
		"FLUX_GHCR_SYNC_ATTEMPTS":                   "3",
		"FLUX_GHCR_SYNC_INTERVAL":                   "0",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"image-verification admission webhooks did not become effective before retirement",
	)
	operations := readLines(f.operationLog)
	requireNoLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
	requireNotContains(t, strings.Join(operations, "\n"), "runtime-probe-success:")
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestMutationEnabledImageVerificationPolicyRequiresBothWebhooks(t *testing.T) {
	t.Parallel()
	t.Run("missing mutating webhook", func(t *testing.T) {
		f := newFixture(t)
		result := f.runHelperWithMutationEnabled(validConfig(), nil, map[string]string{
			"FLUX_GHCR_SYNC_ATTEMPTS": "3",
			"FLUX_GHCR_SYNC_INTERVAL": "0",
		})
		requireFailureResult(t, result)
		requireContains(
			t,
			result.stdout+result.stderr,
			"image-verification admission webhooks did not become effective before retirement",
		)
		operations := readLines(f.operationLog)
		requireNoLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
		requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
		requireNoLine(t, operations, "root-patch")
	})

	t.Run("both webhooks", func(t *testing.T) {
		f := newFixture(t)
		result := f.runHelperWithMutationEnabled(validConfig(), nil, map[string]string{
			"FAKE_IMAGE_VERIFICATION_MUTATION_REQUIRED": "true",
		})
		requireSuccessResult(t, result)
		operations := readLines(f.operationLog)
		requireLine(t, operations, "ivpol-policy-consolidated-ready")
		requireLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
		requireLine(t, operations, "root-patch")
	})
}

func TestImageVerificationWebhookConvergenceFailureFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_WEBHOOKS_STALE":          "true",
		"FAKE_IMAGE_VERIFICATION_WEBHOOKS_NEVER_CONVERGE": "true",
		"FLUX_GHCR_SYNC_ATTEMPTS":                         "3",
		"FLUX_GHCR_SYNC_INTERVAL":                         "0",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"image-verification admission webhooks did not become effective before retirement",
	)
	operations := readLines(f.operationLog)
	requireNoLine(t, operations, "ivpol-policy-delete:verify-ksail-images")
	requireNotContains(t, strings.Join(operations, "\n"), "runtime-probe-success:")
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestFailOpenEffectiveImageVerificationWebhookFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_WEBHOOKS_FAIL_OPEN": "true",
		"FLUX_GHCR_SYNC_ATTEMPTS":                    "3",
		"FLUX_GHCR_SYNC_INTERVAL":                    "0",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"image-verification admission webhooks did not become effective before retirement",
	)
	if pathExists(f.operationLog) {
		operations := readLines(f.operationLog)
		requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
		requireNoLine(t, operations, "root-patch")
	}
}

func TestFailOpenValidatingImageVerificationWebhookFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_IMAGE_VERIFICATION_VALIDATING_WEBHOOK_FAIL_OPEN": "true",
		"FLUX_GHCR_SYNC_ATTEMPTS":                              "3",
		"FLUX_GHCR_SYNC_INTERVAL":                              "0",
	})
	requireFailureResult(t, result)
	requireContains(
		t,
		result.stdout+result.stderr,
		"image-verification admission webhooks did not become effective before retirement",
	)
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "runtime-probe-success:")
	requireNoLine(t, operations, "root-patch")
}

func TestRuntimeProbeRetriesTransientAdmissionTimeout(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_ONCE_NODES": "prod-control-plane-2",
		"FAKE_LOG_RUNTIME_PROBE_SUCCESS":               "true",
	})
	requireSuccessResult(t, result)
	if !pathExists(filepath.Join(
		f.syncStateDir,
		"runtime-probe-create-timeout-once-prod-control-plane-2",
	)) {
		t.Fatal("transient runtime-probe timeout was not exercised")
	}
	operations := readLines(f.operationLog)
	applyCount := len(lineIndices(operations, "ivpol-policy-apply:verify-app-images"))
	probeCount := 0
	for _, operation := range operations {
		if strings.HasPrefix(operation, "runtime-probe-success:") {
			probeCount++
		}
	}
	if applyCount != probeCount+2 {
		t.Fatalf(
			"policy applications = %d, successful probes = %d; want one transaction stage and one fresh timeout retry fence",
			applyCount,
			probeCount,
		)
	}
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "root-patch")
}

func TestRuntimeProbeSurvivesThreeConsecutiveAdmissionTimeouts(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_COUNT_NODES": "prod-control-plane-2",
		"FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_COUNT":       "3",
	})
	requireSuccessResult(t, result)
	attempts := strings.TrimSpace(mustRead(filepath.Join(
		f.syncStateDir,
		"runtime-probe-create-timeout-count-prod-control-plane-2",
	)))
	if attempts != "6" {
		t.Fatalf("runtime probe create attempts = %s, want 6", attempts)
	}
	operations := readLines(f.operationLog)
	requireLine(t, operations, "node-drain:prod-worker-1")
	requireLine(t, operations, "root-patch")
}

func TestRuntimeProbeReusesPersistedPodAfterAmbiguousAdmissionTimeout(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_RUNTIME_PROBE_CREATE_PERSIST_THEN_TIMEOUT_ONCE_NODES": "prod-control-plane-2",
	})
	requireSuccessResult(t, result)
	attempts := strings.TrimSpace(mustRead(filepath.Join(
		f.syncStateDir,
		"runtime-probe-create-attempts-prod-control-plane-2",
	)))
	// This node receives one probe per private image. A fourth create would mean
	// the first, already-persisted Pod was retried instead of reused.
	if attempts != "3" {
		t.Fatalf("persisted runtime probe create attempts = %s, want 3", attempts)
	}
	staleProbes, err := filepath.Glob(filepath.Join(
		f.syncStateDir,
		"runtime-probe-ghcr-runtime-probe-*",
	))
	if err != nil {
		t.Fatalf("find stale runtime probes: %v", err)
	}
	if len(staleProbes) != 0 {
		t.Fatalf("persisted runtime probes not cleaned up: %v", staleProbes)
	}
}

func TestRuntimeProbePersistentAdmissionTimeoutFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_RUNTIME_PROBE_CREATE_ALWAYS_FAIL_NODES": "prod-control-plane-2",
	})
	requireFailureResult(t, result)
	requireContains(t, result.stdout+result.stderr, "Could not create a kubelet/containerd GHCR pull probe")
	operations := readLines(f.operationLog)
	requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
	requireNoLine(t, operations, "root-patch")
}

func TestEachPrivateRuntimePackageACLMustPass(t *testing.T) {
	t.Parallel()
	for _, image := range []string{
		"ghcr.io/devantler-tech/data-product-controller:latest",
		"ghcr.io/devantler-tech/wedding-app:latest",
		"ghcr.io/devantler-tech/ascoachingogvaner:latest",
	} {
		t.Run(image, func(t *testing.T) {
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_RUNTIME_PULL_FAIL_IMAGES": image})
			requireFailureResult(t, result)
			requireContains(t, result.stdout+result.stderr, image)
			operations := readLines(f.operationLog)
			requireNotContains(t, strings.Join(operations, "\n"), "node-drain:")
			requireNoLine(t, operations, "root-patch")
		})
	}
}

func TestDRWithoutFanoutDoesNotDrainNodes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), []string{"--allow-incomplete-fanout"}, map[string]string{"FAKE_VARIABLES_BASE_ABSENT": "true"})
	requireSuccessResult(t, result)
	if pathExists(f.talosLog) {
		t.Error("DR without fanout invoked Talos")
	}
	if !pathExists(f.patchCapture) {
		t.Error("DR root repair patch missing")
	}
}

func TestInvalidNodeInventoryFailsClosed(t *testing.T) {
	t.Parallel()
	invalidInventories := []any{
		map[string]any{"items": []any{}},
		map[string]any{"items": []any{map[string]any{
			"metadata": map[string]any{"name": "one", "uid": "uid-one"},
			"status":   map[string]any{"addresses": []any{}},
		}}},
		map[string]any{"items": []any{map[string]any{
			"metadata": map[string]any{"name": "one", "uid": "uid-one"},
			"status": map[string]any{"addresses": []any{
				map[string]any{"type": "InternalIP", "address": "10.0.0.1"},
				map[string]any{"type": "InternalIP", "address": "10.0.0.2"},
			}},
		}}},
		map[string]any{"items": []any{
			nodeFixture("one", "uid-one", "10.0.0.1", false, nil, nil),
			nodeFixture("two", "uid-two", "10.0.0.1", false, nil, nil),
		}},
		map[string]any{"items": []any{map[string]any{
			"metadata": map[string]any{"name": "one"},
			"status": map[string]any{"addresses": []any{
				map[string]any{"type": "InternalIP", "address": "10.0.0.1"},
			}},
		}}},
		map[string]any{"items": []any{
			nodeFixture("one", "duplicate", "10.0.0.1", false, nil, nil),
			nodeFixture("two", "duplicate", "10.0.0.2", false, nil, nil),
		}},
	}
	for index, inventory := range invalidInventories {
		t.Run(string(rune('A'+index)), func(t *testing.T) {
			f := newFixture(t)
			result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_NODE_JSON": encodeJSON(inventory)})
			requireFailureResult(t, result)
			if pathExists(f.talosLog) {
				t.Error("invalid inventory invoked Talos")
			}
			if pathExists(f.patchCapture) {
				t.Error("invalid inventory changed root auth")
			}
		})
	}
}

func TestNodeDiscoveryFailureAfterSafeFanoutKeepsRootUnchanged(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{"FAKE_NODE_DISCOVERY_FAIL": "true"})
	requireFailureResult(t, result)
	if pathExists(f.talosLog) {
		t.Error("failed discovery invoked Talos")
	}
	if !pathExists(f.variablesPatchCapture) || !pathExists(f.fanoutLog) {
		t.Error("failed discovery did not occur after safe fanout")
	}
	if pathExists(f.patchCapture) {
		t.Error("failed discovery changed root auth")
	}
}

// A probe the kubelet never reports on must not present as an unproved runtime
// credential. The gate is fail-closed either way, but the emitted evidence has
// to say what was actually observed, or the next occurrence costs another
// production outage to diagnose (platform#3429).
func TestRuntimeProbeTimeoutReportsObservedPodState(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":       "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":       "prod-worker-2",
		"FAKE_RUNTIME_PROBE_STALLED_NODES": "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_EMPTY_WORKLOAD_NODES":        "prod-worker-2",
	})
	requireFailureResult(t, result)
	output := result.stdout + result.stderr
	requireContains(t, output, "Timed out proving the running containerd GHCR credential")
	// The whole point: the operator can tell a stuck probe from a bad credential.
	requireContains(t, output, "phase=Pending")
	requireContains(t, output, "containerStatus=absent")
}

// A probe the kubelet actively rejected (OutOfmemory/OutOfpods) reaches a
// terminal Failed phase. Polling it for the full budget and then blaming the
// runtime credential is both slow and wrong, so it must fail fast and say so.
func TestRuntimeProbeKubeletRejectionFailsFastAndDistinctly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	result := f.runHelper(validConfig(), nil, map[string]string{
		"FAKE_ALL_TALOS_NODES_STALE":         "true",
		"FAKE_BOOTSTRAP_WORKER_NAME":         "prod-worker-2",
		"FAKE_RUNTIME_PROBE_STALLED_NODES":   "prod-worker-1 prod-worker-2 prod-control-plane-1 prod-control-plane-2 prod-control-plane-3",
		"FAKE_RUNTIME_PROBE_STALLED_PHASE":   "Failed",
		"FAKE_RUNTIME_PROBE_STALLED_REASON":  "OutOfmemory",
		"FAKE_RUNTIME_PROBE_STALLED_MESSAGE": "Node didn't have enough resource: memory",
		"FAKE_EMPTY_WORKLOAD_NODES":          "prod-worker-2",
	})
	requireFailureResult(t, result)
	output := result.stdout + result.stderr
	requireContains(t, output, "did not run")
	requireContains(t, output, "podReason=OutOfmemory")
	// Not a credential verdict: the runtime was never exercised.
	requireNotContains(t, output, "Timed out proving the running containerd GHCR credential")
	// Kubelet's raw message can carry node detail; it must not reach the log.
	requireNotContains(t, output, "Node didn't have enough resource")
}
