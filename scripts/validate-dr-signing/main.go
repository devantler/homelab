// Command validate-dr-signing checks that the disaster-recovery rebuild can
// publish an artifact production is allowed to trust.
//
// Production's root Flux source is the whole platform: every controller, every
// tenant binding, every policy arrives through it. Signature verification on
// that source is only worth switching on if EVERY writer to the mutable tag
// signs, because Flux rejects what it cannot verify — and a disaster recovery
// rebuild is exactly the moment a rejected artifact is unrecoverable by hand.
//
// Both production paths delegate to one local action. That action pushes a
// run-unique staging reference, signs and attests its resolved digest, and only
// then promotes those exact bytes to latest. The DR job must grant the OIDC and
// attestation permissions that action needs, and its workflow identity must
// appear in the cluster's verification allow-list.
//
// None of these failures is loud at authoring time. With verification off they
// fail silently forever; with verification on they fail during an incident, at
// the one moment nobody can afford to debug a supply-chain policy. Pinning all
// here turns that into a CI failure on the pull request that breaks one.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// drIdentitySubject is the Fulcio certificate subject the DR rebuild signs
// under: the reusable workflow path at the ref it is dispatched from. It must
// be present in the cluster's matchOIDCIdentity allow-list for Flux to accept a
// DR-published artifact.
const drIdentitySubject = `^https://github\.com/devantler-tech/platform/\.github/workflows/dr-rebuild\.yaml@refs/heads/main$`

// drIdentityIssuer is the OIDC issuer half of that identity. cosign matches an
// identity on the issuer/subject PAIR, so a correct subject under a different
// issuer does not admit the DR signature and must not satisfy this gate.
const drIdentityIssuer = `^https://token\.actions\.githubusercontent\.com$`

// drIdentityIssuerLiteral and drIdentitySubjectLiteral are the CONCRETE strings
// Fulcio puts in the DR rebuild's certificate — the values cosign actually
// matches the allow-list regexes against.
//
// They exist because the allow-list can no longer carry the DR identity as its
// own entry. cosign rejects a multi-entry matchOIDCIdentity outright, so all
// three trusted signers (ci.yaml on the merge-queue ref, cd.yaml on main, and
// dr-rebuild.yaml on main) have to share ONE entry, and that entry is therefore
// an alternation which can never be string-equal to any single identity.
// Comparing regex text to regex text is the wrong question; the right one is
// whether the shipped matcher ADMITS this certificate, so the check evaluates
// the matcher against these literals instead.
const (
	drIdentityIssuerLiteral  = `https://token.actions.githubusercontent.com`
	drIdentitySubjectLiteral = `https://github.com/devantler-tech/platform/.github/workflows/dr-rebuild.yaml@refs/heads/main`
)

// drIdentitySharedSubject is the ONE subject regex that carries all three
// trusted signers: ci.yaml on the merge-queue ref, cd.yaml on main, and
// dr-rebuild.yaml on main. cosign accepts exactly one matchOIDCIdentity entry,
// so trusting three signers means one entry whose alternation is INSIDE the
// subject — there is nowhere else to put it.
const drIdentitySharedSubject = `^https://github\.com/devantler-tech/platform/\.github/workflows/(ci\.yaml@refs/heads/gh-readonly-queue/main/.+|(cd|dr-rebuild)\.yaml@refs/heads/main)$`

// permittedSubjects are the only subject regexes production may ship, compared
// EXACTLY.
//
// Exact comparison is deliberate and is the property this file refuses to give
// up. Evaluating the regex against the DR identity alone cannot replace it: a
// widened matcher such as `<real>|^https://github\.com/attacker/…$` still admits
// the DR identity, so every match-based check passes while a second signer has
// been let in. Only string equality is blind to nothing in the lengthening
// direction. What the single-entry cosign limit changed is not whether to
// compare exactly, but WHAT to compare against — a list of one identity was
// never satisfiable once three signers had to share one entry.
//
// Adding or removing a trusted signer is therefore a deliberate edit here, on a
// pull request, which is the review point a supply-chain allow-list should have.
var permittedSubjects = []string{
	// The three-signer form production ships.
	drIdentitySharedSubject,
	// The DR identity alone — the correct shape for a cluster whose only
	// publisher is the DR rebuild, and the narrowest thing that can satisfy
	// this contract.
	drIdentitySubject,
}

// untrustedSubjects are certificate subjects a permitted matcher must REFUSE.
//
// These do not replace the exact comparison above; they guard the constants
// themselves. A typo in drIdentitySharedSubject — a dot left unescaped, a
// missing anchor — would be copied verbatim into permittedSubjects and compare
// equal to itself forever, so the allow-list would be wrong and the gate would
// still pass. Evaluating the permitted form against known-bad subjects is what
// catches that. Each entry varies exactly one field of the real subject —
// owner, repo, workflow, ref — plus the two boundary escapes an unanchored or
// partially-anchored regex lets through.
var untrustedSubjects = []string{
	// A different owner, including one that merely extends the real one — the
	// case an unescaped `.` or a missing anchor waves through.
	`https://github.com/attacker/platform/.github/workflows/dr-rebuild.yaml@refs/heads/main`,
	`https://github.com/devantler-tech-attacker/platform/.github/workflows/dr-rebuild.yaml@refs/heads/main`,
	// A different repository under the real owner.
	`https://github.com/devantler-tech/attacker/.github/workflows/dr-rebuild.yaml@refs/heads/main`,
	// A different workflow in the real repository: any workflow that can be
	// added by a PR must not be able to sign a production artifact.
	`https://github.com/devantler-tech/platform/.github/workflows/attacker.yaml@refs/heads/main`,
	// The real workflow at a ref an outside contributor controls.
	`https://github.com/devantler-tech/platform/.github/workflows/dr-rebuild.yaml@refs/heads/attacker`,
	`https://github.com/devantler-tech/platform/.github/workflows/dr-rebuild.yaml@refs/pull/1/merge`,
	// Boundary escapes: an unanchored regex matches these because the real
	// subject is a substring of each.
	`https://attacker.example/https://github.com/devantler-tech/platform/.github/workflows/dr-rebuild.yaml@refs/heads/main`,
	`https://github.com/devantler-tech/platform/.github/workflows/dr-rebuild.yaml@refs/heads/main.attacker`,
}

// untrustedIssuer stands in for the wrong-issuer half of the pair. cosign
// matches issuer AND subject, so an allow-list that admits any issuer admits a
// signature minted somewhere other than GitHub's OIDC provider.
const untrustedIssuer = `https://attacker.example`

// cdContractGateJob is the cd.yaml job that runs this validator on the
// direct-push production path. Named once so the wiring check and the workflow
// cannot drift apart silently.
const cdContractGateJob = "validate-publication-contract"

// mergeQueueContractGateJob is the ci.yaml job that carries this validator on
// the merge-queue production path.
//
// It is a DEDICATED gate job, exactly like cdContractGateJob, so both routes
// carry the identical rule set. It previously rode along in `changes`, which
// also detects changed paths and runs the other contract validators — and a
// shared job cannot satisfy gateJobRunsOnlyItsValidator, because that rule
// exists to assert the job runs nothing BUT its validator. Leaving the rule off
// left the runner's $GITHUB_ENV/$GITHUB_PATH bridges open on this route: a step
// earlier in the shared job could shadow `go` for the validator step while that
// step's own run block still read as correct.
const mergeQueueContractGateJob = "validate-publication-contract"

// mergeQueueProductionJob is a ci.yaml job that reaches production, together
// with whether its PURPOSE requires it to survive a failed dependency.
type mergeQueueProductionJob struct {
	name string
	// mayOverrideDependencyStatus is true only where running after a failed
	// dependency is the job's entire reason to exist. Everywhere else a status
	// function makes a publishing job eligible after the gate before it FAILED,
	// which is the bypass this distinction exists to refuse.
	mayOverrideDependencyStatus bool
}

// mergeQueueProductionJobs are the ci.yaml jobs that reach production. Both
// must go through the checked shared action, or the ordering contract covers
// only the direct-push route.
var mergeQueueProductionJobs = []mergeQueueProductionJob{
	{name: "deploy-prod"},
	// The unsuccessful-path cleanup: it re-deploys main's signed artifact after
	// deploy-prod fails or is cancelled, so `always()` is REQUIRED here and
	// refusing it would break the healing this repo added deliberately.
	{name: "heal-prod-on-failure", mayOverrideDependencyStatus: true},
}

// dependencyStatusOverrides are the GitHub status-check functions that make a
// job eligible even when a job it `needs` has failed. Without one of them a
// job runs only if every dependency succeeded, which is the property the
// merge-queue gate relies on; `success()` is absent because it asserts that
// property rather than overriding it.
var dependencyStatusOverrides = []string{"always", "failure", "cancelled"}

// The exact action paths and command the direct-push gate must wire together.
// Named once so the checks, the workflow, and the error text cannot drift.
const (
	sharedDeployAction    = "./.github/actions/deploy-prod"
	nestedPublisherAction = "./.github/actions/deploy-prod/publish-platform-manifests"
	validatorCommand      = "go run ./scripts/validate-dr-signing .github/workflows/dr-rebuild.yaml ksail.prod.yaml"
)

// mutableProductionTagRepository is the OCI repository whose `latest` tag
// production's root Flux source follows. The registry host is deliberately NOT
// part of it: `ghcr.io/…`, a bare `devantler-tech/…`, and a mirror spelling all
// reach the same tag, and only the repository path is common to them.
const mutableProductionTagRepository = "devantler-tech/platform/manifests"

// drRebuildJob is the dr-rebuild.yaml job that reaches production.
const drRebuildJob = "rebuild"

// drRequiredPermission is a job-level grant the rebuild job must carry, together
// with what stops working without it.
type drRequiredPermission struct {
	name string
	// consequence completes "so …", naming what the DR rebuild cannot do.
	consequence string
}

// drRequiredPermissions are the three write grants the publication transaction
// needs. Matched on the PARSED key and value, so the trailing comment on each
// line is documentation rather than part of the contract.
var drRequiredPermissions = []drRequiredPermission{
	{"id-token", "keyless cosign signing cannot mint a Fulcio certificate"},
	{"packages", "the publication transaction cannot update GHCR"},
	{"attestations", "the SBOM and provenance cannot be recorded"},
}

// drPublisherCredential is an input the publisher step must receive, and the
// exact expression it must receive it from.
type drPublisherCredential struct {
	input      string
	expression string
}

// drPublisherCredentials are the two secrets the shared publication action needs.
// Asserted on the publisher STEP's `with` mapping, not anywhere in the job.
var drPublisherCredentials = []drPublisherCredential{
	{"ghcr-token", "${{ secrets.GHCR_TOKEN }}"},
	{"hcloud-token", "${{ secrets.HCLOUD_TOKEN }}"},
}

// validateDRWorkflow checks that the disaster-recovery route publishes through
// the same checked action as every other route, with the grants and credentials
// that action needs.
//
// 🔴 THE WORKFLOW IS PARSED, NOT SCANNED — the third route, and the last one to
// be converted. The two production routes were parsed in #2939; this one still
// asked `containsLine`, which is satisfied by the expected text appearing
// ANYWHERE in the job's text. Five ways that said "wired" about a DR route that
// was not, each reproduced as an ablation and each returning nil against the
// scanning version:
//
//  1. The `uses:` line survives as a COMMENT while the step invokes a different
//     action. A comment runs nothing, so the gate certified a publisher that is
//     not called.
//  2. The same text inside a BLOCK SCALAR — an `echo` in a run block — with no
//     `uses:` step anywhere.
//  3. The credentials named on a DIFFERENT step. A scan over the job text cannot
//     tell which step receives them, so the publisher could be invoked with none.
//  4. The publisher step carries `if: false`, so it never runs while the workflow
//     reads as correct.
//  5. The publisher step carries `continue-on-error: true`, so it runs, fails,
//     and the rebuild continues to promote the mutable tag anyway.
//
// (4) and (5) are the requireEnforcedStep class this file has now fixed at six
// sites; matching and enforcing are inseparable there for exactly this reason.
// A DR publish that silently skipped its evidence is unrecoverable by hand at
// the one moment nobody can afford to debug it.
func validateDRWorkflow(workflow string) error {
	document, err := decodeWorkflow(workflow)
	if err != nil {
		return fmt.Errorf(
			"disaster-recovery workflow does not parse, so its publication wiring cannot be established: %w", err,
		)
	}
	jobs, ok := document["jobs"].(map[string]any)
	if !ok {
		return errors.New("disaster-recovery workflow has no jobs mapping")
	}
	job, ok := jobs[drRebuildJob].(map[string]any)
	if !ok {
		return errors.New("missing rebuild job")
	}

	if err := requireJobPermissions(job); err != nil {
		return err
	}

	// The rebuild JOB legitimately carries `if:` — the supersession gate — so the
	// job-level condition is deliberately NOT refused here, unlike cd.yaml's
	// deploy-prod. What must hold is that the publisher STEP is neither skipped
	// nor failure-suppressed, which is requireEnforcedStep's whole contract.
	step, err := requireEnforcedStep(
		job, usesAction(nestedPublisherAction),
		errors.New(
			"rebuild job must use the shared publication action so normal and disaster-recovery delivery cannot drift",
		),
		"the publisher step in the DR rebuild job",
	)
	if err != nil {
		return err
	}

	return requirePublisherCredentials(step)
}

// requireJobPermissions proves the rebuild job grants each required permission
// as `write`, read from the parsed mapping.
//
// A `permissions` value this cannot read is REFUSED rather than skipped, for the
// reason every other shape check in this file gives: it decides whether a
// disaster-recovery publish is trusted, so a grant that cannot be established
// must not fall through to accepted. That includes the blanket `write-all`
// scalar — which does grant enough, but names none of these three, so a later
// narrowing could drop one silently while this check kept passing.
func requireJobPermissions(job map[string]any) error {
	raw, present := job["permissions"]
	if !present {
		return errors.New(
			"rebuild job declares no permissions, so it grants none of the writes the publication transaction needs",
		)
	}
	permissions, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf(
			"rebuild job declares permissions in a shape this check cannot read (%v); each of %s must be granted "+
				"explicitly as `write`, so a later narrowing cannot drop one silently",
			raw, drRequiredPermissionNames(),
		)
	}
	for _, required := range drRequiredPermissions {
		if value, _ := permissions[required.name].(string); strings.TrimSpace(value) != "write" {
			return fmt.Errorf(
				"rebuild job does not grant `%s: write`, so %s",
				required.name, required.consequence,
			)
		}
	}
	return nil
}

// requirePublisherCredentials proves the publisher step itself receives both
// secrets. Asserted on the step's own `with` mapping: the scanning version read
// them from anywhere in the job, so credentials on an unrelated step satisfied
// it while the publisher was invoked with none.
func requirePublisherCredentials(step map[string]any) error {
	with, _ := step["with"].(map[string]any)
	for _, credential := range drPublisherCredentials {
		if value, _ := with[credential.input].(string); strings.TrimSpace(value) != credential.expression {
			return fmt.Errorf(
				"the publisher step in the DR rebuild job does not pass %s: %s, so it cannot complete the "+
					"publication credentials the shared action requires",
				credential.input, credential.expression,
			)
		}
	}
	return nil
}

func drRequiredPermissionNames() string {
	names := make([]string, 0, len(drRequiredPermissions))
	for _, required := range drRequiredPermissions {
		names = append(names, required.name)
	}
	return strings.Join(names, ", ")
}

func validatePublicationAction(action string) error {
	steps, err := parsePublicationSteps(action)
	if err != nil {
		return err
	}
	installIdx, ok := runLineEqualTo(steps, ".github/scripts/setup-supply-chain-tools.sh")
	if !ok {
		return errors.New("publication action must install verified supply-chain tools before publishing")
	}
	for _, step := range steps {
		if strings.HasPrefix(step.uses, "sigstore/cosign-installer@") ||
			strings.HasPrefix(step.uses, "anchore/sbom-action@") {
			return errors.New("publication action must use verified supply-chain tools instead of unpinned binary installers")
		}
	}
	if _, ok := runLineContaining(steps, `STAGING_TAG="staging-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"`); !ok {
		return errors.New("publication action must build a unique staging reference from the SHA, run, and attempt")
	}
	if !hasEnvBinding(steps, "STAGING_OCI_REF", "${{ steps.staging_reference.outputs.oci_ref }}") {
		return errors.New("publication action must use an environment bridge for the generated staging reference")
	}
	pushIdx, ok := runLineContaining(steps, `workload push "${STAGING_OCI_REF}"`)
	if !ok {
		return errors.New("publication action must push only the allowlisted staging reference")
	}
	if !installIdx.before(pushIdx) {
		return errors.New("publication action must install verified supply-chain tools before publishing")
	}
	resolveIdx, ok := runLineContaining(steps, `docker buildx imagetools inspect "${STAGING_REF}"`)
	if !ok {
		return errors.New("publication action must resolve the staging reference to an immutable digest")
	}
	signIdx, ok := runLineContaining(steps, "cosign sign ")
	if !ok {
		return errors.New("publication action would promote the artifact without signing it")
	}
	if _, ok := runLineContaining(steps, `cosign sign --yes --recursive "ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}"`); !ok {
		return errors.New(
			"publication action must sign the resolved staging digest rather than a mutable tag",
		)
	}
	sbomIdx, ok := runLineContaining(steps, "syft scan ")
	if !ok {
		return errors.New("publication action is missing SBOM generation")
	}
	if _, ok := runLineContaining(steps, `syft scan "registry:ghcr.io/devantler-tech/platform/manifests@${STAGING_DIGEST}" --output cyclonedx-json=sbom.cdx.json`); !ok {
		return errors.New("publication action must generate the CycloneDX SBOM from the resolved staging digest")
	}
	attestSBOMIdx, ok := stepUsing(steps, "actions/attest@")
	if !ok {
		return errors.New("publication action is missing the required SBOM attestation")
	}
	provenanceIdx, ok := stepUsing(steps, "actions/attest-build-provenance@")
	if !ok {
		return errors.New("publication action is missing the required provenance attestation")
	}
	promoteIdx, ok := runLineContaining(steps, "docker buildx imagetools create --prefer-index=false")
	if !ok {
		return errors.New("publication action must use digest-preserving latest promotion")
	}

	if !pushIdx.before(resolveIdx) || !resolveIdx.before(signIdx) || !signIdx.before(sbomIdx) ||
		!sbomIdx.before(attestSBOMIdx) || !attestSBOMIdx.before(provenanceIdx) || !provenanceIdx.before(promoteIdx) {
		return errors.New("publication action must complete push, resolution, signature, SBOM, and provenance before promotion")
	}
	if digestBindings(steps, "steps.resolve_staging.outputs.digest") < 4 {
		return errors.New("publication action must bind every evidence step to the resolved staging digest")
	}
	if _, ok := runLineContaining(steps, `"${SUBJECT_NAME}@${STAGING_DIGEST}"`); !ok {
		return errors.New("publication action must promote the exact evidenced digest")
	}
	if _, ok := runLineContaining(steps, `if [[ "${LATEST_DIGEST}" != "${STAGING_DIGEST}" ]]; then`); !ok {
		return errors.New("publication action must verify latest resolves to the staged digest")
	}

	return publicationStepsAreEnforced(action)
}

// publicationStep is one parsed step of the publication action reduced to the
// fields the contract may read: the executable lines of its run block, the
// action it uses, and the env/with values that bind evidence to the digest.
//
// 🔴 THE CONTRACT READS PARSED STEPS, NEVER RAW ACTION TEXT. Every check in
// validatePublicationAction used to search the whole file line by line, so a
// YAML comment, a step name, or an env value carrying the expected text
// satisfied it while the executable step did something else — and ordering was
// compared by line number, which prose also has. Reducing each step to its
// executable fields first makes prose structurally unable to satisfy a
// requirement, and gives every ordering check a parsed step index to compare.
type publicationStep struct {
	uses string
	run  []string
	env  map[string]string
	with map[string]string
}

// stepPosition orders a match by parsed step first and executable line second,
// so two requirements met inside one step still keep their relative order.
type stepPosition struct {
	step int
	line int
}

func (p stepPosition) before(q stepPosition) bool {
	return p.step < q.step || (p.step == q.step && p.line < q.line)
}

// parsePublicationSteps decodes the action's steps into their executable fields.
func parsePublicationSteps(action string) ([]publicationStep, error) {
	rawSteps, err := publicationRawSteps(action)
	if err != nil {
		return nil, err
	}
	steps := make([]publicationStep, 0, len(rawSteps))
	for _, step := range rawSteps {
		uses, _ := step["uses"].(string)
		run, _ := step["run"].(string)
		steps = append(steps, publicationStep{
			uses: strings.TrimSpace(uses),
			run:  executableLines(run),
			env:  stringValues(step["env"]),
			with: stringValues(step["with"]),
		})
	}
	return steps, nil
}

// publicationRawSteps decodes the action and returns its step mappings, failing
// closed on every shape whose steps cannot be read.
func publicationRawSteps(action string) ([]map[string]any, error) {
	document, err := decodeWorkflow(action)
	if err != nil {
		return nil, fmt.Errorf("publication action is unreadable, so its steps cannot be proven enforced: %w", err)
	}
	runs, ok := document["runs"].(map[string]any)
	if !ok {
		return nil, errors.New("publication action has no runs mapping, so its steps cannot be proven enforced")
	}
	rawSteps, ok := runs["steps"].([]any)
	if !ok || len(rawSteps) == 0 {
		return nil, errors.New("publication action declares no steps, so nothing can be proven enforced")
	}
	steps := make([]map[string]any, 0, len(rawSteps))
	for index, raw := range rawSteps {
		step, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("publication action step %d is not a mapping, so it cannot be proven enforced", index)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// executableLines keeps the shell that runs: blank lines and whole-line
// comments are dropped, and a trailing ` #` comment is cut. The cut can only
// remove text, never add an executable line, so a quoted `#` preceded by
// whitespace loses its tail and FAILS a requirement rather than satisfying one
// — the safe direction.
func executableLines(run string) []string {
	var lines []string
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if cut := strings.Index(trimmed, " #"); cut >= 0 {
			trimmed = strings.TrimSpace(trimmed[:cut])
		}
		if cut := strings.Index(trimmed, "\t#"); cut >= 0 {
			trimmed = strings.TrimSpace(trimmed[:cut])
		}
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// stringValues returns the string-valued entries of a step mapping such as env
// or with; a missing or non-mapping node yields no entries.
func stringValues(node any) map[string]string {
	mapping, _ := node.(map[string]any)
	values := make(map[string]string, len(mapping))
	for key, raw := range mapping {
		if value, ok := raw.(string); ok {
			values[key] = value
		}
	}
	return values
}

// runLineContaining finds the first executable run line containing want.
func runLineContaining(steps []publicationStep, want string) (stepPosition, bool) {
	for stepIdx, step := range steps {
		for lineIdx, line := range step.run {
			if strings.Contains(line, want) {
				return stepPosition{step: stepIdx, line: lineIdx}, true
			}
		}
	}
	return stepPosition{}, false
}

// runLineEqualTo finds the first executable run line that is exactly want.
func runLineEqualTo(steps []publicationStep, want string) (stepPosition, bool) {
	for stepIdx, step := range steps {
		for lineIdx, line := range step.run {
			if line == want {
				return stepPosition{step: stepIdx, line: lineIdx}, true
			}
		}
	}
	return stepPosition{}, false
}

// stepUsing finds the first step whose uses reference starts with prefix.
func stepUsing(steps []publicationStep, prefix string) (stepPosition, bool) {
	for stepIdx, step := range steps {
		if strings.HasPrefix(step.uses, prefix) {
			return stepPosition{step: stepIdx}, true
		}
	}
	return stepPosition{}, false
}

// hasEnvBinding reports whether any step's env binds key to exactly value.
func hasEnvBinding(steps []publicationStep, key string, value string) bool {
	for _, step := range steps {
		if step.env[key] == value {
			return true
		}
	}
	return false
}

// digestBindings counts the env values, with values, and executable run lines
// that reference the resolved staging digest; comments and names never count.
func digestBindings(steps []publicationStep, reference string) int {
	count := 0
	for _, step := range steps {
		for _, value := range step.env {
			if strings.Contains(value, reference) {
				count++
			}
		}
		for _, value := range step.with {
			if strings.Contains(value, reference) {
				count++
			}
		}
		for _, line := range step.run {
			if strings.Contains(line, reference) {
				count++
			}
		}
	}
	return count
}

// publicationStepsAreEnforced proves every publication step's failure actually
// stops the run.
//
// 🔴 THE FIFTH SITE OF THE requireEnforcedStep MISTAKE, and the one the checks
// above cannot reach. Everything before this point is positional: it proves a
// step EXISTS and sits in the right place in the chain. Position says nothing
// about whether the step's verdict is honoured. `continue-on-error: true` on
// `verify_evidence` keeps the gate present, correctly ordered, invoked with the
// resolved digest and reading ENFORCE=true — so the ordering chain here, the
// wiring assertions in test-verify-published-evidence.sh, and the enforcement
// ratchet all still pass — while the gate's failure is discarded and
// `promote_latest` moves the mutable tag onto bytes with no usable evidence.
// That is precisely the state root verification exists to make impossible.
//
// Every step is covered rather than a named subset: this action's whole purpose
// is producing bytes production will trust, so a step whose failure does not
// stop it has no place in the chain, and an allowlist would need extending each
// time a step is added — the omission this file has already made four times.
func publicationStepsAreEnforced(action string) error {
	steps, err := publicationRawSteps(action)
	if err != nil {
		return err
	}
	for index, step := range steps {
		if err := enforcesFailure(step, describePublicationStep(step, index)); err != nil {
			return err
		}
	}
	return nil
}

// describePublicationStep names a step the way its author will recognise it, so
// the failure points at the line to change rather than an index to count to.
func describePublicationStep(step map[string]any, index int) string {
	if id, ok := step["id"].(string); ok && id != "" {
		return fmt.Sprintf("publication action step %q", id)
	}
	if name, ok := step["name"].(string); ok && name != "" {
		return fmt.Sprintf("publication action step %q", name)
	}
	return fmt.Sprintf("publication action step %d", index)
}

// clusterVerifyConfig mirrors only the fragment of the KSail cluster config this
// gate reads: the cosign allow-list at spec.workload.flux.verify, which is the
// path KSail renders onto the root OCIRepository. Decoding the exact path is
// what makes a block sitting anywhere else a failure rather than a pass, because
// such a block yields zero entries here.
//
// Decoding reads the FIRST YAML document only, which is what a KSail cluster
// config is. A verify block hidden in a later document would therefore yield no
// entries and FAIL this gate rather than satisfy it — the safe direction, and the
// same direction every other shape below fails in.
type clusterVerifyConfig struct {
	Spec struct {
		Workload struct {
			Flux struct {
				Verify struct {
					MatchOIDCIdentity []struct {
						Issuer  string `yaml:"issuer"`
						Subject string `yaml:"subject"`
					} `yaml:"matchOIDCIdentity"`
				} `yaml:"verify"`
			} `yaml:"flux"`
		} `yaml:"workload"`
	} `yaml:"spec"`
}

// validateVerifyAllowList checks that the cluster's cosign allow-list actually
// admits the DR rebuild identity.
//
// 🔴 THE CONFIG IS PARSED, NOT SCANNED, for the same reason validateCDWiring
// parses workflows rather than scanning them — this is the config half of that
// same correction. Four ways a text scan says "allowed" about an allow-list that
// is not in effect, each reproduced as an ablation in the tests:
//
//  1. The identity appears in a COMMENT. A comment has no effect on the cluster,
//     so the gate certifies an allow-list that does not exist. Measured on the
//     scanning version: removing the real matcher and re-adding the identical
//     regex as `# …` returned "contract passed", exit 0.
//  2. The whole verify block sits at a path KSail DISCARDS — spec.cluster.verify
//     is exactly the #2627 outage. The bytes are in the file, so a scan finds
//     them; KSail never renders them onto the OCIRepository.
//  3. A subject that merely CONTAINS this identity satisfies a substring match,
//     and that direction is the dangerous one: `^dr$|^attacker$` contains the DR
//     identity while also admitting a second signer.
//  4. The right subject under the WRONG ISSUER. cosign matches on the
//     issuer/subject pair, so such an entry does not admit the DR signature — but
//     a scan looking only for the subject line accepts it.
//
// An allow-list entry that is inert, discarded, over-broad, or issued by someone
// else does not make a DR-published artifact verifiable, which is the one failure
// that is unrecoverable by hand during an incident.
func validateVerifyAllowList(config string) error {
	var parsed clusterVerifyConfig
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		return fmt.Errorf(
			"cluster config does not parse, so its verification allow-list cannot be established: %w", err,
		)
	}

	entries := parsed.Spec.Workload.Flux.Verify.MatchOIDCIdentity
	if len(entries) == 0 {
		return errors.New(
			"no cosign matchOIDCIdentity entries at spec.workload.flux.verify, the path KSail renders onto the root " +
				"OCIRepository, so a DR-published artifact stays unverifiable; a verify block at any other path " +
				"(spec.cluster.verify in particular) is discarded and does not count",
		)
	}

	// cosign refuses a multi-entry matchOIDCIdentity outright — "unsupported:
	// multiple identities are not supported at this time" — and it fails CLOSED
	// for the whole list, so a second entry does not add a signer, it removes
	// every one of them. Finding a correct entry somewhere in a longer list
	// therefore says nothing about whether a DR artifact verifies, which is the
	// only question this contract asks. validate-flux-verify refuses the same
	// shape; it is repeated here because this gate is what stands between a
	// disaster recovery and an artifact production will not accept.
	if len(entries) > 1 {
		return fmt.Errorf(
			"cosign matchOIDCIdentity at spec.workload.flux.verify has %d entries, and cosign supports exactly ONE: "+
				"it rejects a multi-entry list for the whole set, so a DR-published artifact stays unverifiable even "+
				"though a correct entry is present; express several trusted signers as an alternation inside one "+
				"entry's subject regex",
			len(entries),
		)
	}

	for _, entry := range entries {
		if entry.Issuer != drIdentityIssuer || !slices.Contains(permittedSubjects, entry.Subject) {
			continue
		}

		// The entry is one of the permitted forms. Prove that form is actually
		// correct rather than merely familiar: it must admit the DR rebuild's
		// real certificate and refuse every known-bad value. This is what
		// catches a typo baked into a constant, which equality alone cannot see
		// because a wrong constant still equals itself.
		//
		// Both halves are checked because cosign matches on the PAIR: an
		// over-broad issuer admits a signature minted outside GitHub's OIDC
		// provider however tight the subject is.
		if err := verifyPermittedIssuer(entry.Issuer); err != nil {
			return err
		}

		if err := verifyPermittedSubject(entry.Subject); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf(
		"cosign matchOIDCIdentity at spec.workload.flux.verify has %d entries but none is exactly a permitted DR "+
			"rebuild matcher, so a DR-published artifact stays unverifiable; use issuer %s with subject %s (the "+
			"three-signer form) or %s (DR alone), each compared exactly — a wider regex that merely contains one of "+
			"them is not accepted. cosign supports exactly ONE entry, so a second signer belongs in the alternation "+
			"inside the subject, never in a second entry",
		len(entries), drIdentityIssuer, drIdentitySharedSubject, drIdentitySubject,
	)
}

// verifyPermittedIssuer checks the permitted issuer regex against GitHub's real
// OIDC issuer and against an issuer we must never trust.
//
// It guards the constant for the same reason verifyPermittedSubject does, and
// it matters independently: cosign matches the issuer/subject PAIR, so an
// issuer that admits anyone makes the subject's precision irrelevant.
func verifyPermittedIssuer(issuer string) error {
	compiled, err := regexp.Compile(issuer)
	if err != nil {
		return fmt.Errorf(
			"permitted issuer %s is not a valid regular expression, so cosign cannot evaluate it and it admits "+
				"nothing: %w", issuer, err,
		)
	}

	if !compiled.MatchString(drIdentityIssuerLiteral) {
		return fmt.Errorf(
			"permitted issuer %s does not match GitHub's OIDC issuer %s, so no GitHub-signed artifact verifies",
			issuer, drIdentityIssuerLiteral,
		)
	}

	if compiled.MatchString(untrustedIssuer) {
		return fmt.Errorf(
			"permitted issuer %s also admits %s, so a signature minted outside GitHub's OIDC provider would "+
				"verify; anchor the expression with ^…$ and escape every dot", issuer, untrustedIssuer,
		)
	}

	return nil
}

// verifyPermittedSubject checks a permitted subject regex against the DR
// rebuild's real certificate subject and against the known-bad subjects.
//
// It guards the CONSTANTS, not the config: an allow-list entry that compares
// equal to a mistyped permitted form is accepted by the equality check and
// still admits the wrong signers, and that mistake would survive review
// precisely because the file and the constant agree with each other.
func verifyPermittedSubject(subject string) error {
	compiled, err := regexp.Compile(subject)
	if err != nil {
		return fmt.Errorf(
			"permitted subject %s is not a valid regular expression, so cosign cannot evaluate it and it admits "+
				"nothing: %w", subject, err,
		)
	}

	if !compiled.MatchString(drIdentitySubjectLiteral) {
		return fmt.Errorf(
			"permitted subject %s does not match the DR rebuild's certificate subject %s, so a DR-published "+
				"artifact stays unverifiable", subject, drIdentitySubjectLiteral,
		)
	}

	for _, untrusted := range untrustedSubjects {
		if compiled.MatchString(untrusted) {
			return fmt.Errorf(
				"permitted subject %s also admits %s, so a signer we do not trust could publish an artifact Flux "+
					"accepts; anchor the expression with ^…$ and escape every dot", subject, untrusted,
			)
		}
	}

	return nil
}

// validateCDWiring checks that the direct-push production path cannot deploy
// without this contract having been checked first, and that the contract is
// checked against the code that route actually runs.
//
// The contract above is only as strong as the weakest route to production, and
// there are two. The merge-queue route runs this validator through ci.yaml,
// which triggers on pull_request and merge_group. cd.yaml is the documented
// direct-push recovery route and has neither event: it is dispatched manually
// after a push to main, went straight from the authorization job into the
// shared deploy action, and so reached production without the ordering contract
// being examined even once.
//
// 🔴 THE WORKFLOW IS PARSED, NOT SCANNED, and that is the whole point of this
// function rather than an implementation preference. Four ways a text scan says
// "gated" about a workflow that is not, each raised against the scanning
// version of this check and each reproduced as an ablation below:
//
//  1. The gate step ECHOES the command instead of running it. A substring match
//     on the run block accepts `echo "go run ./scripts/validate-dr-signing"`,
//     which exits 0 having validated nothing.
//  2. The dependency is read from ANY line of the job text, so a heredoc or an
//     env value containing `needs: [validate-publication-contract]` satisfies
//     it while GitHub sees no dependency at all.
//  3. `needs` is satisfied but the deploy carries `if: always()`, which
//     schedules it after the gate FAILS. Membership alone cannot see this, and
//     it is the most dangerous of the four because the workflow reads correct.
//  4. The contract is checked against the nested publisher while the top-level
//     deploy action no longer invokes it — so the validator keeps verifying an
//     unused file and reports success about code that does not run.
//
// A gate the destructive job does not depend on protects nothing; so does a
// gate it depends on but ignores, and so does a contract checked against code
// that is no longer reached.
func validateCDWiring(cd string, deployAction string) error {
	documents, err := decodeWorkflow(cd)
	if err != nil {
		return fmt.Errorf("direct-push deploy workflow does not parse, so its gating cannot be established: %w", err)
	}
	jobs, ok := documents["jobs"].(map[string]any)
	if !ok {
		return errors.New("direct-push deploy workflow has no jobs mapping")
	}
	deploy, ok := jobs["deploy-prod"].(map[string]any)
	if !ok {
		return errors.New("missing deploy-prod job in the direct-push production workflow")
	}

	// If the deploy job stops delegating to the shared action, this check is
	// aimed at the wrong thing and must be re-aimed rather than left passing.
	// Compared as a whole step value, so neither a sibling path
	// (`…/deploy-prod-canary`) nor the nested publisher satisfies it.
	if _, err := requireEnforcedStep(
		deploy, usesAction(sharedDeployAction),
		errors.New("deploy-prod job no longer uses the shared production deploy action, so this wiring check no longer covers the path it names"),
		"the deploy step in the direct-push deploy-prod job",
	); err != nil {
		return err
	}

	// The job delegates publication wholly to that action, so nothing else in
	// it may reach the tag production follows.
	if err := requireSolePublisher(
		deploy, usesAction(sharedDeployAction),
		"the deploy-prod job in the direct-push production workflow",
	); err != nil {
		return err
	}

	// (4) The contract is validated against the nested publisher. That is only
	// meaningful while the shared action still calls it — and the composite
	// action is PARSED for the same reason cd.yaml is: a YAML block scalar (a
	// heredoc inside a run block) can contain the exact `uses:` text while the
	// action invokes nothing of the sort.
	composite, err := decodeWorkflow(deployAction)
	if err != nil {
		return fmt.Errorf("shared deploy action does not parse, so its publisher link cannot be established: %w", err)
	}
	runs, _ := composite["runs"].(map[string]any)
	if runs == nil {
		return errors.New("shared deploy action has no runs mapping")
	}
	if _, err := requireEnforcedStep(
		map[string]any{"steps": runs["steps"]}, usesAction(nestedPublisherAction),
		fmt.Errorf(
			"the shared deploy action no longer invokes %s as a step, so the publication contract is being checked against code production does not run",
			nestedPublisherAction,
		),
		"the publisher step in the shared deploy action",
	); err != nil {
		return err
	}

	// …and it must be the only step in that action which reaches the tag. The
	// check above proves the publisher is invoked; this proves nothing follows
	// it onto the same tag.
	if err := requireSolePublisher(
		map[string]any{"steps": runs["steps"]}, usesAction(nestedPublisherAction),
		"the shared production deploy action",
	); err != nil {
		return err
	}

	gate, ok := jobs[cdContractGateJob].(map[string]any)
	if !ok {
		return fmt.Errorf(
			"missing %s job: the direct-push production path has no publication-contract gate",
			cdContractGateJob,
		)
	}
	// (1) The command must be a complete executable line of a run block, not
	// text that merely appears inside one — AND the step that carries it must
	// actually run and actually fail the job.
	step, err := requireEnforcedStep(
		gate, runsCommand(validatorCommand),
		fmt.Errorf(
			"%s job does not EXECUTE %q as its own command line, so the gate can report success without validating anything",
			cdContractGateJob, validatorCommand,
		),
		"the validator step in "+cdContractGateJob,
	)
	if err != nil {
		return err
	}
	if err := runBlockRunsOnlyAllowedCommands(
		documents, gate, step, cdContractGateJob, gateRunBlockCommands,
	); err != nil {
		return err
	}
	// Constraining the validator step says nothing about what ran BEFORE it in
	// the same job, and the runner's env/path bridges carry across steps.
	if err := gateJobRunsOnlyItsValidator(gate, cdContractGateJob, gateStepActions); err != nil {
		return err
	}
	// The gate JOB is the same question one level up: a skipped or
	// failure-suppressed job still satisfies a `needs` dependency.
	if err := enforcesFailure(gate, "the "+cdContractGateJob+" job"); err != nil {
		return err
	}

	// (2) Read from the parsed job, so only a real `needs` key counts.
	if !stringListContains(deploy["needs"], cdContractGateJob) {
		return fmt.Errorf(
			"deploy-prod does not require %s, so a direct-push deploy can reach production without the publication contract",
			cdContractGateJob,
		)
	}

	// (3) A job-level condition can schedule the deploy after a FAILED
	// prerequisite. Anything other than an absent condition is refused rather
	// than interpreted: this decides whether a destructive job runs, and a
	// condition expression this cannot evaluate must read as ungated.
	if condition, present := deploy["if"]; present {
		return fmt.Errorf(
			"deploy-prod declares a job-level condition (%v); a condition can schedule the deploy after the gate FAILS, "+
				"so it must be removed or this check extended to prove the condition still requires the gate to succeed",
			condition,
		)
	}
	return nil
}

// validateProductionRoutes checks the OTHER route to production.
//
// 🔴 THE PREMISE OF THIS WHOLE CONTRACT IS "the guarantee is only as strong as
// its weakest route", and until now it checked exactly one of the two. The
// merge-queue route in ci.yaml is the NORMAL path to production; replacing its
// shared-action call passed every check here, so an alternative publication
// implementation could bypass the ordering contract on ordinary deploys while
// the direct-push route stayed perfectly gated.
//
// The job-level condition rule deliberately does NOT apply here: ci.yaml gates
// its deploy on `merge_group`, which is a legitimate and necessary condition.
// What must hold is that each production job invokes the CHECKED action and
// that the invoking step is neither skipped nor failure-suppressed.
func validateProductionRoutes(ci string) error {
	documents, err := decodeWorkflow(ci)
	if err != nil {
		return fmt.Errorf("merge-queue workflow does not parse, so its production routes cannot be established: %w", err)
	}
	jobs, ok := documents["jobs"].(map[string]any)
	if !ok {
		return errors.New("merge-queue workflow has no jobs mapping")
	}
	if err := validateMergeQueueContractGate(documents, jobs); err != nil {
		return err
	}
	for _, production := range mergeQueueProductionJobs {
		jobName := production.name
		job, ok := jobs[jobName].(map[string]any)
		if !ok {
			return fmt.Errorf("merge-queue workflow is missing the %s job", jobName)
		}
		if _, err := requireEnforcedStep(
			job, usesAction(sharedDeployAction),
			fmt.Errorf(
				"merge-queue job %s no longer uses %s, so it can publish to production through logic this contract never checks",
				jobName, sharedDeployAction,
			),
			"the deploy step in merge-queue job "+jobName,
		); err != nil {
			return err
		}
		// Exclusivity on the route production normally takes. Using the checked
		// action says nothing about what else the job does beside it.
		if err := requireSolePublisher(
			job, usesAction(sharedDeployAction), "merge-queue job "+jobName,
		); err != nil {
			return err
		}
		if err := refuseDependencyStatusOverride(job, production); err != nil {
			return err
		}
		// Enforcing the gate step says nothing about whether this job WAITS for
		// it. Read from the parsed job so only a real `needs` key counts: moving
		// the validator into a job that production does not require would
		// otherwise leave every rule above satisfied and the gate unreachable.
		if !stringListContains(job["needs"], mergeQueueContractGateJob) {
			return fmt.Errorf(
				"merge-queue job %s does not require %s, so it can reach production without the job that runs the publication validator",
				jobName, mergeQueueContractGateJob,
			)
		}
	}
	return nil
}

// validateMergeQueueContractGate holds the ci.yaml validator step to the same
// enforcement rules as its cd.yaml counterpart.
//
// 🔴 THE CONTRACT CHECKED THE MERGE-QUEUE ROUTE'S DEPLOY AND NOT ITS GATE, so
// every bypass already pinned for cd.yaml was reachable on the NORMAL path to
// production while the exceptional one stayed sealed: `if: false`,
// `continue-on-error`, a here-doc, `set +e`, a shadowing shell function, a
// `defaults.run.shell` override, or a `BASH_ENV` injection. `deploy-prod` needs
// `changes`, so a `changes` job that reported success on a neutered validator
// was a green light to production.
//
// The premise of this whole file is that the guarantee is only as strong as its
// weakest route, and the weakest route was the one almost every deploy takes.
func validateMergeQueueContractGate(documents map[string]any, jobs map[string]any) error {
	gate, ok := jobs[mergeQueueContractGateJob].(map[string]any)
	if !ok {
		return fmt.Errorf(
			"merge-queue workflow is missing the %s job, so the publication validator has no home on the route production normally takes",
			mergeQueueContractGateJob,
		)
	}
	// Located by the SAME command equality cd.yaml uses, so the two routes
	// cannot drift into checking different things under one contract.
	step, err := requireEnforcedStep(
		gate, runsCommand(validatorCommand),
		fmt.Errorf(
			"%s job does not EXECUTE %q as its own command line, so the merge-queue route can reach production without validating the publication contract",
			mergeQueueContractGateJob, validatorCommand,
		),
		"the validator step in "+mergeQueueContractGateJob,
	)
	if err != nil {
		return err
	}
	// Straight-line run block, no shell override at any of the three scopes, and
	// no environment variable that could shadow `go` before the script starts.
	if err := runBlockRunsOnlyAllowedCommands(
		documents, gate, step, mergeQueueContractGateJob, gateRunBlockCommands,
	); err != nil {
		return err
	}
	// Constraining the validator step says nothing about what ran BEFORE it in
	// the same job, and the runner's env/path bridges carry across steps. This
	// is the rule the shared-job arrangement could not carry.
	if err := gateJobRunsOnlyItsValidator(gate, mergeQueueContractGateJob, gateStepActions); err != nil {
		return err
	}
	// The job is the same question one level up: a skipped or failure-suppressed
	// job still satisfies the `needs` that production depends on.
	return enforcesFailure(gate, "the "+mergeQueueContractGateJob+" job")
}

// refuseDependencyStatusOverride is the merge-queue counterpart to the
// direct-push route's flat refusal of any job-level condition.
//
// 🔴 THAT CARVE-OUT WAS TOTAL, AND THAT WAS THE BUG. This route permits a
// condition because `merge_group` gating is legitimate and necessary — but
// permitting the key permitted its CONTENTS too, so `always() && <the real
// condition>` read as correct while making the deploy eligible after the
// `changes` job, which runs the signing validator, had failed. The condition is
// therefore permitted and its status functions refused, rather than the key
// being trusted whole.
func refuseDependencyStatusOverride(job map[string]any, production mergeQueueProductionJob) error {
	if production.mayOverrideDependencyStatus {
		return nil
	}
	condition, present := job["if"]
	if !present {
		return nil
	}
	// Whitespace and case are removed rather than matched around: GitHub's
	// expression functions are case-insensitive, and a spelling this cannot
	// read must not fall through to accepted.
	normalised := strings.ToLower(strings.Join(strings.Fields(fmt.Sprintf("%v", condition)), ""))
	for _, override := range dependencyStatusOverrides {
		// The trailing paren is what distinguishes the FUNCTION `failure()` from
		// the ordinary result comparison `needs.x.result == 'failure'`, which
		// overrides nothing and must stay allowed.
		if strings.Contains(normalised, override+"(") {
			return fmt.Errorf(
				"merge-queue job %s conditions its run on %s(), which makes it eligible even when a job it "+
					"`needs` has FAILED — including the job that runs the publication validator, so it can "+
					"publish to production behind a gate that already failed (condition: %v)",
				production.name, override, condition,
			)
		}
	}
	return nil
}

// decodeWorkflow parses a workflow into a generic mapping. `on:` is famously
// decoded as the boolean true by YAML 1.1 readers; nothing here reads that key,
// and the jobs mapping is unaffected.
func decodeWorkflow(contents string) (map[string]any, error) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(contents), &document); err != nil {
		return nil, err
	}
	if document == nil {
		return nil, errors.New("empty document")
	}
	return document, nil
}

// requireEnforcedStep finds a step and proves it is enforced, in ONE call.
//
// 🔴 MATCHING AND ENFORCING ARE DELIBERATELY INSEPARABLE HERE. Every reviewed
// round of this file found the same defect at one more site: a step was matched
// and its metadata discarded, so `if: false` or `continue-on-error: true` left
// it named-but-not-run. It happened at the validator step, then the deploy
// step, then the merge-queue steps, then the nested publisher — four rounds,
// one mistake, because "find the step" and "check the step is enforced" were
// two calls and the second was easy to forget.
//
// Returning only through this function makes that omission unrepresentable:
// there is no way to obtain a matched step without its enforcement having been
// checked. That is the structural version of a rule I had been applying by
// memory, and by memory I missed it four times.
func requireEnforcedStep(
	container map[string]any,
	matches func(map[string]any) bool,
	missing error,
	description string,
) (map[string]any, error) {
	steps, _ := container["steps"].([]any)
	for _, raw := range steps {
		step, _ := raw.(map[string]any)
		if step == nil || !matches(step) {
			continue
		}
		if err := enforcesFailure(step, description); err != nil {
			return nil, err
		}
		return step, nil
	}
	return nil, missing
}

// requireSolePublisher proves the checked publication step is the ONLY step in
// `container` that names the mutable production tag's repository.
//
// 🔴 EVERY OTHER CHECK IN THIS FILE IS AN EXISTENCE PROOF, and existence is not
// exclusivity. requireEnforcedStep establishes that the checked publisher is
// present, reached, and failure-honouring — all of which stay true when a
// SECOND step writes the same tag immediately afterwards. The ordering contract
// then holds exactly as specified and is bypassed at a different point: the
// signed digest is published, and something else moves `latest` off it before
// reconciliation reads it.
//
// The rule refuses NAMING the repository rather than writing to it, and that is
// deliberate. Deciding whether a shell line writes means enumerating the verbs
// that can — `workload push`, `imagetools create`, `crane`, `oras`, `docker
// push`, whatever ships next — which is the denylist
// runBlockRunsOnlyAllowedCommands already had to replace once, for the reason
// it gives: each round of review found one more spelling. A step outside the
// checked publisher has no business naming production's mutable tag at all, so
// the allowlist here is a single step and everything else is refused.
//
// The boundary is one level deep, and stating it is part of the check: this
// reads the step, not the scripts a step invokes. `run: ./scripts/x.sh` that
// pushes internally is not caught here — `run-ksail-prod-with-pull-auth.sh`
// carries its own staging-only allowlist for exactly that reason.
func requireSolePublisher(container map[string]any, publisher func(map[string]any) bool, location string) error {
	steps, _ := container["steps"].([]any)
	publishers := 0
	for index, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok {
			// Fail closed: a shape this cannot read is a shape this cannot clear.
			return fmt.Errorf(
				"step %d of %s is not a mapping, so it cannot be shown to leave %s alone",
				index+1, location, mutableProductionTagRepository,
			)
		}
		if publisher(step) {
			// SOLE means exactly one, not at-least-one. A second matching step
			// is exempted from the naming rule below, and requireEnforcedStep
			// only ever validates the FIRST match — so a duplicate publisher is
			// checked by neither: it can carry its own `with:` inputs, an `if:`,
			// or continue-on-error and still move the tag. Verified accepted on
			// all three routes before this counter existed.
			publishers++
			if publishers > 1 {
				return fmt.Errorf(
					"step %d of %s is a SECOND step matching the checked publisher; only the first is held to the "+
						"enforcement contract, so the duplicate can publish different bytes to %s unchecked",
					index+1, location, mutableProductionTagRepository,
				)
			}

			continue
		}
		// Re-encoded whole rather than reading `run`: a `with` input, an `env`
		// value, or a `uses` path can carry the reference just as effectively,
		// and naming the keys that may not carry it is the same enumeration
		// this check exists to avoid.
		encoded, err := yaml.Marshal(step)
		if err != nil {
			return fmt.Errorf(
				"step %d of %s cannot be re-encoded, so it cannot be shown to leave %s alone: %w",
				index+1, location, mutableProductionTagRepository, err,
			)
		}
		if strings.Contains(string(encoded), mutableProductionTagRepository) {
			return fmt.Errorf(
				"step %d of %s names %s while not being the checked publication step, so it can move the "+
					"mutable production tag off the digest that was signed and attested; publication must go "+
					"through the checked step alone",
				index+1, location, mutableProductionTagRepository,
			)
		}
	}
	// Self-sufficient rather than trusting call order: every caller happens to
	// run requireEnforcedStep first today, so this is unreachable — but that is
	// a property of the callers, not of this function, and "sole" is meaningless
	// if the step is absent entirely.
	if publishers == 0 {
		return fmt.Errorf(
			"%s contains no step matching the checked publisher, so nothing establishes who writes %s",
			location, mutableProductionTagRepository,
		)
	}

	return nil
}

// usesAction matches a step whose `uses` is EXACTLY the wanted action.
func usesAction(want string) func(map[string]any) bool {
	return func(step map[string]any) bool {
		uses, _ := step["uses"].(string)
		return strings.TrimSpace(uses) == want
	}
}

// runsCommand matches a step executing `want` as a complete line of its run block.
func runsCommand(want string) func(map[string]any) bool {
	return func(step map[string]any) bool {
		run, _ := step["run"].(string)
		for _, line := range strings.Split(run, "\n") {
			if strings.TrimSpace(line) == want {
				return true
			}
		}
		return false
	}
}

// enforcesFailure rejects a step or job that can be skipped or whose failure is
// suppressed.
//
// 🔴 THE SAME CLASS AS THE JOB-LEVEL CONDITION ON deploy-prod, one level down,
// and missing it left the identical hole: a gate that runs the right command
// under `if: false` never runs it, and one under `continue-on-error: true` runs
// it and then reports success anyway. Either way the workflow reads as gated,
// `needs` is satisfied, and the deploy proceeds on an unenforced check.
//
// Both keys are REFUSED rather than interpreted, for the reason the job-level
// check gives: this decides whether a destructive job runs, so an expression
// this cannot evaluate must read as ungated.
func enforcesFailure(node map[string]any, description string) error {
	if condition, present := node["if"]; present {
		return fmt.Errorf(
			"%s declares a condition (%v); a condition can skip it entirely while the workflow still reads as gated, "+
				"so it must be removed or this check extended to prove the condition always holds",
			description, condition,
		)
	}
	if suppress, present := node["continue-on-error"]; present && suppress != false {
		return fmt.Errorf(
			"%s sets continue-on-error: %v, so it can fail the publication contract and still report success",
			description, suppress,
		)
	}
	return nil
}

// gateRunBlockCommands are the ONLY command lines the publication-contract
// gate's run block may contain. Named here so the check, the workflow, and the
// error text cannot drift apart.
var gateRunBlockCommands = []string{
	"go test ./scripts/validate-dr-signing",
	validatorCommand,
}

// runBlockRunsOnlyAllowedCommands requires every executable line of the gate
// step to be one of `allowed`, so that finding the validator line also means
// the shell reaches it and runs it as itself.
//
// 🔴 THIS REPLACED A DENYLIST, AND THE REPLACEMENT IS THE POINT. Six rounds of
// review found six ways to leave the exact validator line present while running
// nothing: quoting it inside another command, skipping the step, sitting after
// `exit 0`, printing it from a here-doc, discarding its verdict with `set +e`,
// and — reported independently by two reviewers against the previous head —
// shadowing `go` with a shell function, since bash resolves a function before
// an executable. Each round answered with another refused token.
//
// A denylist over shell syntax is an unbounded guessing game, and the sixth
// round is the evidence: `go()`, `{` and `}` carried no refused keyword and no
// refused operator, so a gate that ran neither validator was accepted. Rather
// than add a seventh token and wait for the eighth shape, the run block is
// constrained to an ALLOWLIST of exact command lines. Every bypass above needs
// a line that is not one of the two required commands, so none of them is
// expressible — including the ones nobody has thought of yet.
//
// Deliberately narrow, and narrow in the SAFE direction: a gate that grows a
// legitimate third line fails this check and has to add it here, which is a
// reviewed act, rather than a gate that runs nothing passing quietly.
func runBlockRunsOnlyAllowedCommands(
	workflow map[string]any, job map[string]any, step map[string]any, jobName string, allowed []string,
) error {
	if err := refuseShellOverride(workflow, job, step, jobName); err != nil {
		return err
	}
	if err := envAllowsOnly(workflow, job, step, jobName, gateEnvAllowedNames); err != nil {
		return err
	}
	run, _ := step["run"].(string)
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !slices.Contains(allowed, trimmed) {
			return disallowedGateCommandError(jobName, trimmed, allowed)
		}
	}
	return nil
}

// shellSetting reads the shell configured at ONE scope. A step carries it
// directly; a workflow and a job carry it under `defaults.run`.
//
// A shape this cannot read returns absent, and absent means the CALLER ACCEPTS —
// so this helper is deliberately not fail-closed the way stringListContains is,
// and the reason is specific rather than a house style. GitHub only applies
// `defaults.run.shell` when `defaults` and `run` are both mappings carrying that
// key; anything else is not a working override either, so there is no bypass for
// refusing to read it. Stated explicitly because the earlier draft of this
// comment claimed the opposite direction, and a later round would otherwise
// tighten the code against a guarantee it never made.
func shellSetting(node map[string]any, viaDefaults bool) (any, bool) {
	if node == nil {
		return nil, false
	}
	if !viaDefaults {
		shell, present := node["shell"]
		return shell, present
	}
	defaults, _ := node["defaults"].(map[string]any)
	if defaults == nil {
		return nil, false
	}
	run, _ := defaults["run"].(map[string]any)
	if run == nil {
		return nil, false
	}
	shell, present := run["shell"]
	return shell, present
}

// refuseShellOverride rejects a shell setting at ANY scope GitHub applies to
// the gate step.
//
// 🔴 THE FOURTH SHAPE OF "does the validator's verdict survive", and the third
// time this exact class has been fixed at one site while another stayed open.
// A `shell:` override replaces the default `bash -e {0}` with one that does not
// stop on error, so a failing validator no longer ends the step and a later
// succeeding line carries it to exit 0 — `set +e` by another name. Refusing
// only `steps[*].shell` left BOTH `defaults.run.shell` scopes open, and GitHub
// applies workflow defaults, then job defaults, then the step.
//
// So the scopes are a parameter LIST rather than a sequence of ifs: every
// caller must supply all three, and a fourth scope is a signature change the
// compiler enforces, not a site somebody remembers to visit.
func refuseShellOverride(workflow map[string]any, job map[string]any, step map[string]any, jobName string) error {
	for _, scope := range []struct {
		description string
		node        map[string]any
		viaDefaults bool
	}{
		{"the workflow sets defaults.run.shell", workflow, true},
		{fmt.Sprintf("the %s job sets defaults.run.shell", jobName), job, true},
		{fmt.Sprintf("the validator step in %s overrides the shell", jobName), step, false},
	} {
		if shell, present := shellSetting(scope.node, scope.viaDefaults); present {
			return fmt.Errorf(
				"%s (%v); the default already stops on error, and an override can discard "+
					"the validator failure the gate exists to surface",
				scope.description, shell,
			)
		}
	}
	return nil
}

// gateEnvAllowedNames are the environment variables the publication-contract
// gate's shell may inherit from the workflow. Deliberately EMPTY: the gate runs
// two fixed `go` commands and needs nothing configured.
//
// 🔴 THE SEVENTH SHAPE OF "present but does it run", and it is at a layer the
// run-block allowlist cannot see. `BASH_ENV` names a file bash sources before
// the script, and the runner's default `bash -e {0}` is non-interactive, so a
// `go() { true; }` defined there shadows the executable exactly as the sixth
// round's inline shadow did — while the run block still holds only the two
// permitted lines and passes every existing check.
//
// Refusing the NAME `BASH_ENV` would have been the seventh token, and `PATH`,
// `GOFLAGS` and the exported-function `BASH_FUNC_*` encoding are each another
// one behind it. So this is an allowlist for the same reason the run block is:
// every bypass needs a variable that is not on the list, so none of them is
// expressible — including the ones nobody has thought of yet. A gate that
// genuinely needs a variable adds it here, which is a reviewed act.
var gateEnvAllowedNames []string

// gateStepActions are the only `uses:` actions the gate job may run beside its
// validator step. Named WITHOUT a version so a pinned-digest bump is an
// ordinary dependency update rather than a contract change.
var gateStepActions = []string{
	"actions/checkout",
	"actions/setup-go",
}

// envAllowsOnly rejects an environment variable set at ANY scope GitHub applies
// to the gate step, unless it is named in allowed.
//
// The scopes are a parameter list for the same reason refuseShellOverride's
// are: a fourth scope must be a signature change the compiler enforces, not a
// site somebody remembers to visit.
func envAllowsOnly(
	workflow map[string]any, job map[string]any, step map[string]any, jobName string, allowed []string,
) error {
	for _, scope := range []struct {
		description string
		node        map[string]any
	}{
		{"the workflow", workflow},
		{fmt.Sprintf("the %s job", jobName), job},
		{fmt.Sprintf("the validator step in %s", jobName), step},
	} {
		if scope.node == nil {
			continue
		}
		raw, present := scope.node["env"]
		if !present {
			continue
		}
		// A shape this cannot read is REFUSED rather than skipped: an `env`
		// mapping it fails to parse still reaches the shell, so treating it as
		// absent would accept exactly the payload this check exists to stop.
		env, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf(
				"%s sets env in a shape this check cannot read (%T); the gate's shell inherits it either way, "+
					"so it must be expressed as a plain mapping or removed",
				scope.description, raw,
			)
		}
		for name := range env {
			if !slices.Contains(allowed, name) {
				return fmt.Errorf(
					"%s sets %s, which the publication-contract gate may not inherit (permitted: %s); "+
						"a variable such as BASH_ENV or PATH can shadow the validator while the run block still "+
						"reads correctly — add the name here if it genuinely belongs",
					scope.description, name, allowedNamesForMessage(allowed),
				)
			}
		}
	}
	return nil
}

// gateJobRunsOnlyItsValidator requires every OTHER step in the gate job to be
// one of a small set of setup actions.
//
// 🔴 THE SAME HOLE REACHED WITHOUT AN `env:` KEY ANYWHERE. The runner exposes
// `$GITHUB_ENV` and `$GITHUB_PATH` bridges whose writes apply to every LATER
// step, so a step earlier in this job can export BASH_ENV, or drop a fake `go`
// on PATH, and leave the validator step byte-for-byte unchanged. Both were
// accepted before this check existed: constraining the validator step says
// nothing about what ran before it.
//
// So the job may contain exactly one `run:` step — the validator, already
// constrained above — and otherwise only the named setup actions. An arbitrary
// action is refused too: `uses:` can write those same bridges.
func gateJobRunsOnlyItsValidator(job map[string]any, jobName string, allowedActions []string) error {
	steps, _ := job["steps"].([]any)
	runSteps := 0
	for index, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf(
				"step %d of %s is not a mapping this check can read, and an unreadable step still runs before the validator",
				index+1, jobName,
			)
		}
		if _, carriesRun := step["run"]; carriesRun {
			runSteps++
			if runSteps > 1 {
				return fmt.Errorf(
					"%s runs more than one command step; a step before the validator can export BASH_ENV or a fake go "+
						"through $GITHUB_ENV/$GITHUB_PATH and leave the validator step itself looking correct",
					jobName,
				)
			}
			continue
		}
		uses, _ := step["uses"].(string)
		action, _, _ := strings.Cut(strings.TrimSpace(uses), "@")
		if !slices.Contains(allowedActions, action) {
			return fmt.Errorf(
				"%s runs %q, which is not one of the setup actions this gate may contain (%s); an action can write "+
					"$GITHUB_ENV/$GITHUB_PATH and shadow the validator — add it here if it genuinely belongs",
				jobName, uses, strings.Join(allowedActions, ", "),
			)
		}
	}
	return nil
}

// allowedNamesForMessage renders an allow-list that is usually empty without
// producing a message that trails off after "permitted: ".
func allowedNamesForMessage(allowed []string) string {
	if len(allowed) == 0 {
		return "none"
	}
	return strings.Join(allowed, ", ")
}

func disallowedGateCommandError(jobName string, line string, allowed []string) error {
	return fmt.Errorf(
		"the validator step in %s runs %q, which is not one of the commands this gate may contain (%s); "+
			"an extra line can leave the validator present while the shell never runs it, so the gate is "+
			"restricted to exactly these commands — add the line here if it genuinely belongs",
		jobName, line, strings.Join(allowed, ", "),
	)
}

// stringListContains reports whether a parsed YAML value is a sequence (or a
// lone scalar) containing want. A shape it cannot read returns false, so an
// unrecognised `needs` declaration reads as ungated.
func stringListContains(value any, want string) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) == want
	case []any:
		for _, item := range typed {
			if name, ok := item.(string); ok && strings.TrimSpace(name) == want {
				return true
			}
		}
	}
	return false
}

func run(workflowPath string, configPath string, stdout io.Writer, stderr io.Writer) int {
	workflow, err := os.ReadFile(workflowPath) //nolint:gosec // The explicit CLI path is the validator input.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read workflow: %v\n", err)
		return 1
	}
	config, err := os.ReadFile(configPath) //nolint:gosec // The explicit CLI path is the validator input.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read cluster config: %v\n", err)
		return 1
	}

	if err := validateDRWorkflow(string(workflow)); err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: %v\n", err)
		return 1
	}
	publisherPath := filepath.Clean(filepath.Join(
		filepath.Dir(workflowPath), "..", "actions", "deploy-prod", "publish-platform-manifests", "action.yml",
	))
	publisher, err := os.ReadFile(publisherPath) //nolint:gosec // Derived from the explicit workflow path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read publication action: %v\n", err)
		return 1
	}
	if err := validatePublicationAction(string(publisher)); err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: %v\n", err)
		return 1
	}
	if err := validateVerifyAllowList(string(config)); err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: %v\n", err)
		return 1
	}
	// Derived from the workflow path, exactly as the publication action above
	// is — keeping the CLI at two arguments so no caller can run a partial
	// contract by passing fewer paths.
	cdPath := filepath.Clean(filepath.Join(filepath.Dir(workflowPath), "cd.yaml"))
	cd, err := os.ReadFile(cdPath) //nolint:gosec // Derived from the explicit workflow path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read direct-push deploy workflow: %v\n", err)
		return 1
	}
	deployActionPath := filepath.Clean(filepath.Join(
		filepath.Dir(workflowPath), "..", "actions", "deploy-prod", "action.yml",
	))
	deployAction, err := os.ReadFile(deployActionPath) //nolint:gosec // Derived from the explicit workflow path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read shared deploy action: %v\n", err)
		return 1
	}
	if err := validateCDWiring(string(cd), string(deployAction)); err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: %v\n", err)
		return 1
	}
	ciPath := filepath.Clean(filepath.Join(filepath.Dir(workflowPath), "ci.yaml"))
	ci, err := os.ReadFile(ciPath) //nolint:gosec // Derived from the explicit workflow path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: read merge-queue workflow: %v\n", err)
		return 1
	}
	if err := validateProductionRoutes(string(ci)); err != nil {
		_, _ = fmt.Fprintf(stderr, "dr publication contract: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(stdout, "DR publication contract passed.")
	return 0
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 2 {
		_, _ = fmt.Fprintln(stderr, "usage: validate-dr-signing <dr-workflow-path> <cluster-config-path>")
		return 2
	}
	return run(args[0], args[1], stdout, stderr)
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}
