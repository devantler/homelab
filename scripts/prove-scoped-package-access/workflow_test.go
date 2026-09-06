package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This credentialed experiment must never become a PR-triggered job or inherit
// the App installation's write permissions when its workflow is edited.
func TestWorkflowKeepsTheProofManualAndTheCandidateReadOnly(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/prove-scoped-package-access.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		On          map[string]any    `yaml:"on"`
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			If          string            `yaml:"if"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if len(workflow.On) != 1 {
		t.Fatal("proof must have one manual trigger")
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok {
		t.Fatal("proof must require manual dispatch")
	}
	if len(workflow.Permissions) != 0 {
		t.Fatal("root token permissions must be empty")
	}
	if len(workflow.Jobs) != 1 {
		t.Fatal("additional credentialed jobs require review of this boundary")
	}
	job := workflow.Jobs["prove"]
	if job.If != "github.ref == 'refs/heads/main'" {
		t.Fatal("proof must be restricted to reviewed main")
	}
	if len(job.Permissions) != 1 || job.Permissions["contents"] != "read" {
		t.Fatal("workflow token must only read contents")
	}
	mints := 0
	for _, step := range job.Steps {
		if !strings.HasPrefix(step.Uses, "actions/create-github-app-token@") {
			continue
		}
		mints++
		if step.With["owner"] != "devantler-tech" || step.With["repositories"] != "wedding-app" {
			t.Fatal("candidate repository scope widened")
		}
		if step.With["permission-packages"] != "read" {
			t.Fatal("candidate needs explicit packages read only")
		}
		for key := range step.With {
			if strings.HasPrefix(key, "permission-") && key != "permission-packages" {
				t.Fatalf("unexpected App grant %s", key)
			}
		}
		if step.With["skip-token-revoke"] == "true" {
			t.Fatal("candidate must be revoked by the action's cleanup")
		}
	}
	if mints != 1 {
		t.Fatal("exactly one candidate token is required")
	}
}
