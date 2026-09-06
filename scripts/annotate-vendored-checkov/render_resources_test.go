package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderCRDSourceRejectsWorkloads(t *testing.T) {
	valid := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: originissuers.cert-manager.k8s.cloudflare.com\nspec: {}\n"
	_, stderr, err := runAnnotator(t, "origin-ca-issuer", valid, "--validate-source")
	if err != nil {
		t.Fatalf("declared CRD source rejected: %v: %s", err, stderr)
	}
	for _, invalid := range []string{"", strings.Replace(valid, "CustomResourceDefinition", "Deployment", 1), valid + "---\n" + valid} {
		if _, _, err := runAnnotator(t, "origin-ca-issuer", invalid, "--validate-source"); err == nil {
			t.Fatal("CRD source accepted an empty, workload, or duplicate resource")
		}
	}
}

func TestSplitRenderBundlePreservesEveryByteAndIdentity(t *testing.T) {
	input := "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: kubelet-serving-cert-approver\n---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: kubelet-serving-cert-approver\n"
	dir := t.TempDir()
	_, stderr, err := runAnnotator(t, "kubelet-serving-cert-approver", input, "--split-resources", dir)
	if err != nil {
		t.Fatalf("split rejected: %v: %s", err, stderr)
	}
	first, err := os.ReadFile(filepath.Join(dir, "namespace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "service-account.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first)+string(second) != input {
		t.Fatal("splitting changed upstream bytes")
	}
	if _, _, err := runAnnotator(t, "kubelet-serving-cert-approver", strings.Replace(input, "ServiceAccount", "Secret", 1), "--split-resources", t.TempDir()); err == nil {
		t.Fatal("split accepted an unreviewed resource identity")
	}
	if _, _, err := runAnnotator(t, "kubelet-serving-cert-approver", input+"---\n"+string(first), "--split-resources", t.TempDir()); err == nil {
		t.Fatal("split accepted duplicate resource identity")
	}
}

func TestCommittedCertApproverRejectsChangedSourceAndVersion(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join("..", "..", "k8s", "providers", "hetzner", "infrastructure", "controllers", "kubelet-serving-cert-approver")
	for _, resource := range certApproverResources {
		data, err := os.ReadFile(filepath.Join(source, resource.file))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, resource.file), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Published v0.12.0 source digest, independently checked before vendoring.
	args := []string{"--validate-annotated", "--resources-dir", dir, "--source-sha256", "44d74b38379d96572c434290732092f577ee4835392b36922a72c406ee406139", "--source-version", "0.12.0"}
	if _, stderr, err := runAnnotator(t, "kubelet-serving-cert-approver", "", args...); err != nil {
		t.Fatalf("exact committed source rejected: %v: %s", err, stderr)
	}
	args[len(args)-1] = "0.13.0"
	if _, _, err := runAnnotator(t, "kubelet-serving-cert-approver", "", args...); err == nil {
		t.Fatal("version-only update accepted without refreshing the manifest")
	}
	args[len(args)-1] = "0.12.0"
	file := filepath.Join(dir, "deployment.yaml")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(data, []byte("# changed outside updater\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runAnnotator(t, "kubelet-serving-cert-approver", "", args...); err == nil {
		t.Fatal("manual source rewrite accepted without a new reviewed digest")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runAnnotator(t, "kubelet-serving-cert-approver", "", args...); err == nil {
		t.Fatal("missing vendored workload accepted")
	}
}
