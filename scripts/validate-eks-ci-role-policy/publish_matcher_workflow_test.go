package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const approvedSignerGuard = "./scripts/guard-publish-workflow-approved-revisions.sh"

// The fingerprint projection accepts fixed-SHA subsets of the previously
// approved broad identity. Membership in the generated approval data is a
// separate mandatory check, including on routes that publish without PR CI.
func TestApprovedSignerMembershipCoversPublicationRoutes(t *testing.T) {
	workflows := loadWorkflows(t)
	for _, route := range []struct {
		file, gate, publisher, ref string
	}{
		{"ci.yaml", "changes", "deploy-prod", ""},
		{"cd.yaml", "validate-eks-authorization", "deploy-prod", ""},
		{"validate-main.yaml", "validate-eks-authorization", "", ""},
		{"dr-rebuild.yaml", "supersession-gate", "rebuild", ""},
	} {
		t.Run(route.file+"/"+route.gate, func(t *testing.T) {
			wf, ok := workflows[route.file]
			if !ok {
				t.Fatalf("missing workflow %s", route.file)
			}
			if err := approvedSignerRoute(wf, route.gate, route.publisher, route.ref); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Recovery must use the policy shipped WITH the main checkout. During the
// first narrowing rollout, main still legitimately has broad matchers. An
// enforcing step in the speculative workflow would prevent restoring that
// last deployed revision. Putting the guard first in the checked-out action
// keeps new main strict without imposing future policy on an older revision.
func TestApprovedSignerRecoveryUsesCheckedOutPolicy(t *testing.T) {
	wf := loadWorkflows(t)["ci.yaml"]
	if !restoresMainWithCheckedOutAction(wf.Jobs["heal-prod-on-failure"]) {
		t.Error("recovery must use main's deploy action without a speculative signer-policy command")
	}
	body, err := os.ReadFile("../../.github/actions/deploy-prod/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs job `yaml:"runs"`
	}
	if err := yaml.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	if len(action.Runs.Steps) == 0 || !enforcesSignerMembership(action.Runs.Steps[0]) {
		t.Error("the checked-out deploy action must enforce membership before tooling, credentials or publication")
	}

	valid := job{Steps: []step{
		{Uses: "actions/checkout@pin", With: stepInputs{Ref: "main"}},
		{Uses: prodDeployComposite},
	}}
	if !restoresMainWithCheckedOutAction(valid) {
		t.Fatal("rejected recovery through main's versioned action")
	}
	for name, mutate := range map[string]func(*job){
		"speculative policy": func(j *job) {
			j.Steps = append(j.Steps[:1], step{Run: approvedSignerGuard}, j.Steps[1])
		},
		"no checkout":         func(j *job) { j.Steps = j.Steps[1:] },
		"wrong ref":           func(j *job) { j.Steps[0].With.Ref = "" },
		"skipped checkout":    func(j *job) { j.Steps[0].If = "false" },
		"tolerated checkout":  func(j *job) { j.Steps[0].ContinueOnError = true },
		"different publisher": func(j *job) { j.Steps[1].Uses = prodDeployComposite + "/publish-platform-manifests" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := job{Steps: append([]step(nil), valid.Steps...)}
			mutate(&candidate)
			if restoresMainWithCheckedOutAction(candidate) {
				t.Fatal("accepted a recovery route detached from main's signer policy")
			}
		})
	}
}

func restoresMainWithCheckedOutAction(j job) bool {
	checkedOut := false
	for _, s := range j.Steps {
		if strings.Contains(s.Run, approvedSignerGuard) {
			return false
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			if s.With.Ref != "main" || s.If != "" || errorIsTolerated(s.ContinueOnError) {
				return false
			}
			checkedOut = true
		}
		if s.Uses == prodDeployComposite {
			return checkedOut && s.If == "" && !errorIsTolerated(s.ContinueOnError)
		}
	}
	return false
}

func enforcesSignerMembership(s step) bool {
	return strings.TrimSpace(s.Run) == approvedSignerGuard &&
		s.Env["APPROVED_REVISIONS_ENFORCE"] == "1" && s.If == "" &&
		!errorIsTolerated(s.ContinueOnError) && (s.Shell == "" || s.Shell == "bash")
}

func approvedSignerRoute(wf workflow, gate, publisher, ref string) error {
	g, ok := wf.Jobs[gate]
	if !ok || !hasEnforcingSignerGuard(g, ref) {
		return fmt.Errorf("%s must enforce approved signer membership on the checkout being published", gate)
	}
	if publisher == gate {
		if !g.deploysProd() {
			return fmt.Errorf("%s no longer identifies a publication route", publisher)
		}
		return nil
	}
	if g.If != "" || errorIsTolerated(g.ContinueOnError) {
		return fmt.Errorf("%s must be a mandatory gate", gate)
	}
	if publisher == "" {
		return nil
	}
	p, ok := wf.Jobs[publisher]
	if !ok || !p.deploysProd() ||
		(p.Needs != gate && !stringListIncludes(p.Needs, gate)) {
		return fmt.Errorf("%s must depend on %s", publisher, gate)
	}
	// A status override could publish after the prerequisite failed or skipped.
	for _, override := range []string{"always(", "failure(", "cancelled("} {
		if strings.Contains(p.If, override) {
			return fmt.Errorf("%s must require successful prerequisites", publisher)
		}
	}
	if p.checksOutExplicitRef() {
		return fmt.Errorf("%s must publish the revision checked by %s", publisher, gate)
	}
	return nil
}

func errorIsTolerated(value any) bool {
	return value != nil && value != false
}

func hasEnforcingSignerGuard(j job, ref string) bool {
	checkedOut, guarded := false, false
	for _, s := range j.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			if guarded || s.With.Ref != ref || s.If != "" || errorIsTolerated(s.ContinueOnError) {
				return false
			}
			checkedOut = true
		}
		if checkedOut && enforcesSignerMembership(s) {
			guarded = true
		}
		if (s.Uses == prodDeployComposite || strings.HasPrefix(s.Uses, prodDeployComposite+"/")) && !guarded {
			return false
		}
	}
	return guarded && !errorIsTolerated(j.ContinueOnError)
}

func TestApprovedSignerRouteRejectsBypasses(t *testing.T) {
	fixture := func() workflow {
		return workflow{Jobs: map[string]job{
			"gate": {Steps: []step{
				{Uses: "actions/checkout@pin"},
				{Run: approvedSignerGuard, Env: map[string]string{"APPROVED_REVISIONS_ENFORCE": "1"}},
			}},
			"publish": {Needs: []any{"gate"}, Steps: []step{
				{Uses: "actions/checkout@pin"}, {Uses: prodDeployComposite},
			}},
		}}
	}
	if err := approvedSignerRoute(fixture(), "gate", "publish", ""); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*job, *job){
		"missing guard":         func(g, _ *job) { g.Steps = g.Steps[:1] },
		"audit only":            func(g, _ *job) { g.Steps[1].Env["APPROVED_REVISIONS_ENFORCE"] = "0" },
		"comment":               func(g, _ *job) { g.Steps[1].Run = "# " + approvedSignerGuard },
		"echo":                  func(g, _ *job) { g.Steps[1].Run = "echo " + approvedSignerGuard },
		"masked failure":        func(g, _ *job) { g.Steps[1].Run += " || true" },
		"conditional step":      func(g, _ *job) { g.Steps[1].If = "false" },
		"tolerated step":        func(g, _ *job) { g.Steps[1].ContinueOnError = true },
		"conditional gate":      func(g, _ *job) { g.If = "false" },
		"tolerated gate":        func(g, _ *job) { g.ContinueOnError = "${{ true }}" },
		"no checkout":           func(g, _ *job) { g.Steps = g.Steps[1:] },
		"different gate ref":    func(g, _ *job) { g.Steps[0].With.Ref = "main" },
		"checkout after guard":  func(g, _ *job) { g.Steps = append(g.Steps, g.Steps[0]) },
		"missing dependency":    func(_, p *job) { p.Needs = nil },
		"failed prerequisite":   func(_, p *job) { p.If = "always()" },
		"different publish ref": func(_, p *job) { p.Steps[0].With.Ref = "main" },
	} {
		t.Run(name, func(t *testing.T) {
			wf := fixture()
			g, p := wf.Jobs["gate"], wf.Jobs["publish"]
			mutate(&g, &p)
			wf.Jobs["gate"], wf.Jobs["publish"] = g, p
			if err := approvedSignerRoute(wf, "gate", "publish", ""); err == nil {
				t.Fatal("accepted a route that can bypass signer approval")
			}
		})
	}
	// The restore job checks out main rather than the speculative merge ref.
	// Its guard must precede publication inside that very same job.
	g := fixture().Jobs["gate"]
	g.Steps[0].With.Ref = "main"
	g.Steps = append(g.Steps, step{Uses: prodDeployComposite})
	if !hasEnforcingSignerGuard(g, "main") {
		t.Fatal("rejected guarded restoration of main")
	}
	g.Steps[1], g.Steps[2] = g.Steps[2], g.Steps[1]
	if hasEnforcingSignerGuard(g, "main") {
		t.Fatal("accepted a guard that runs after publication")
	}
}
