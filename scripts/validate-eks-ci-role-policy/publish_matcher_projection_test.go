package main

import (
	"strings"
	"testing"
)

// TestPublishMatcherProjectionAllowsOnlyNarrowerSignerSets proves that rotating
// exact signer pairs preserves the existing approval without hiding other edits.
func TestPublishMatcherProjectionAllowsOnlyNarrowerSignerSets(t *testing.T) {
	const manifest = `apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: consumer
  namespace: consumer
spec:
  url: oci://ghcr.io/devantler-tech/github-config/manifests
  ref:
    semver: ">=1.0.0"
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: '^https://token\.actions\.githubusercontent\.com$'
        subject: '^https://github\.com/devantler-tech/actions/\.github/workflows/publish-manifests\.yaml@[0-9a-f]{40}$'
`
	entry := func(contents string) string {
		t.Helper()
		documents, err := decodeDocuments([]byte(contents))
		if err != nil || len(documents) != 1 {
			t.Fatalf("decode OCIRepository: documents=%d error=%v", len(documents), err)
		}
		before, err := canonicalFingerprint(documents[0])
		if err != nil {
			t.Fatal(err)
		}
		actual, err := authorizationSurfaceEntry(identityOf(documents[0]), documents[0])
		if err != nil {
			t.Fatal(err)
		}
		after, err := canonicalFingerprint(documents[0])
		if err != nil || after != before {
			t.Fatalf("projection mutated its input: before=%s after=%s error=%v", before, after, err)
		}
		return actual
	}

	a, b, c := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	consumers := []struct{ name, workflow string }{
		{"github-config", "publish-manifests"},
		{"ascoachingogvaner", "publish-app"},
		{"aws", "publish-manifests"},
		{"wedding-app", "publish-app"},
	}
	for _, consumer := range consumers {
		t.Run(consumer.name, func(t *testing.T) {
			original := strings.ReplaceAll(manifest, "github-config", consumer.name)
			original = strings.ReplaceAll(original, "publish-manifests", consumer.workflow)
			baseline := entry(original)
			for _, ref := range []string{a, "(" + a + ")", "(" + a + "|" + b + ")", "(" + b + "|" + c + ")"} {
				if entry(strings.Replace(original, "[0-9a-f]{40}", ref, 1)) != baseline {
					t.Errorf("exact signer subset %q moved the approval fingerprint", ref)
				}
			}
		})
	}

	baseline := entry(manifest)
	narrowed := strings.Replace(manifest, "[0-9a-f]{40}", "("+a+"|"+b+")", 1)
	mutations := []struct{ name, old, new string }{
		{"different consumer", "github-config/manifests", "unregistered/manifests"},
		{"different artifact", "github-config/manifests", "github-config/other"},
		{"different workflow", "publish-manifests", "publish-app"},
		{"different organization", "devantler-tech/actions", "untrusted/actions"},
		{"different issuer", "token\\.actions\\.githubusercontent\\.com", ".*"},
		{"different verifier", "provider: cosign", "provider: notation"},
		{"different API", "source.toolkit.fluxcd.io/v1", "source.toolkit.fluxcd.io/v1beta2"},
		{"different kind", "kind: OCIRepository", "kind: ConfigMap"},
		{"floating tag", "semver: \">=1.0.0\"", "tag: latest"},
		{"different namespace", "namespace: consumer", "namespace: privileged"},
		{"additional identity", "    matchOIDCIdentity:\n", "    matchOIDCIdentity:\n      - issuer: '.*'\n        subject: '.*'\n"},
		{"unanchored subject", "subject: '^https", "subject: 'https"},
		{"unanchored suffix", b + ")$'", b + ")'"},
		{"regex injection", "(" + a + "|" + b + ")", "(" + a + "|.*)"},
		{"too many signers", "(" + a + "|" + b + ")", "(" + a + "|" + b + "|" + c + ")"},
		{"branch signer", "(" + a + "|" + b + ")", "main"},
		{"uppercase signer", "(" + a + "|" + b + ")", strings.Repeat("A", 40)},
		{"wider character class", "(" + a + "|" + b + ")", "[0-9a-z]{40}"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(narrowed, mutation.old, mutation.new, 1)
			if changed == narrowed {
				t.Fatal("mutation did not change the fixture")
			}
			if entry(changed) == baseline {
				t.Fatal("a change beyond the exact signer subset escaped the approval fingerprint")
			}
		})
	}
}
