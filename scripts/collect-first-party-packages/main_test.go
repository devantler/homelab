package main

import (
	"strings"
	"testing"
)

// TestCollectProposedPackagesIncludingListsAndAllPackageKinds checks supported
// package kinds, nested Lists, deduplication, ordering, and unrelated-object exclusion.
func TestCollectProposedPackagesIncludingListsAndAllPackageKinds(t *testing.T) {
	input := `apiVersion: pkg.crossplane.io/v1
kind: Provider
spec:
  package: ghcr.io/devantler-tech/provider-upjet-unifi:v1.0.0
---
apiVersion: v1
kind: List
items:
  - apiVersion: pkg.crossplane.io/v1beta1
    kind: Function
    spec:
      package: ghcr.io/devantler-tech/function-test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  - apiVersion: pkg.crossplane.io/v1
    kind: Configuration
    spec:
      package: ghcr.io/devantler-tech/config-test:v2
  - apiVersion: pkg.crossplane.io/v1
    kind: Provider
    spec:
      package: ghcr.io/devantler-tech/provider-upjet-unifi:v1.0.0
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
spec:
  package: xpkg.upbound.io/crossplane/provider-example:v1
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
spec:
  url: oci://ghcr.io/devantler-tech/platform/manifests
---
apiVersion: example.io/v1
kind: Provider
spec:
  package: ghcr.io/devantler-tech/not-crossplane:v1
`
	got, err := collect(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := "ghcr.io/devantler-tech/config-test:v2\nghcr.io/devantler-tech/function-test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nghcr.io/devantler-tech/provider-upjet-unifi:v1.0.0"
	if strings.Join(got, "\n") != want {
		t.Fatalf("package inventory = %q, want %q", got, want)
	}
}

// TestCollectRefusesUnmeasurablePackageInventory rejects missing, malformed, or
// unresolved references and inputs that cannot prove a first-party inventory.
func TestCollectRefusesUnmeasurablePackageInventory(t *testing.T) {
	for name, input := range map[string]string{
		"empty render":            "",
		"invalid YAML":            "spec: [",
		"no first-party packages": "apiVersion: v1\nkind: ConfigMap\n",
		"missing package":         "apiVersion: pkg.crossplane.io/v1\nkind: Provider\nspec: {}\n",
		"unresolved substitution": "apiVersion: pkg.crossplane.io/v1\nkind: Provider\nspec:\n  package: ghcr.io/devantler-tech/provider:${version}\n",
		"non-string package":      "apiVersion: pkg.crossplane.io/v1\nkind: Provider\nspec:\n  package: [bad]\n",
		"whitespace in reference": "apiVersion: pkg.crossplane.io/v1\nkind: Provider\nspec:\n  package: 'ghcr.io/devantler-tech/provider:bad tag'\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := collect(strings.NewReader(input)); err == nil {
				t.Fatal("unmeasurable inventory accepted")
			}
		})
	}
}
