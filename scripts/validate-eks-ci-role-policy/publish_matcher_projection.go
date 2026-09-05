package main

import "strings"

// publishMatcherSurfaceDocument recognizes only strict subsets of the shared
// 40-hex signer pattern already covered by the authorization approval. The
// required approved-revisions guard separately enforces each consumer's exact
// generated pair. Issuer, workflow, artifact, identity count and all other
// resource fields remain fingerprinted, so regeneration needs no hash refresh.
func publishMatcherSurfaceDocument(identity resourceIdentity, document map[string]any) map[string]any {
	if identity.apiVersion != "source.toolkit.fluxcd.io/v1" || identity.kind != "OCIRepository" {
		return document
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return document
	}
	var workflow string
	switch spec["url"] {
	case "oci://ghcr.io/devantler-tech/github-config/manifests", "oci://ghcr.io/devantler-tech/aws/manifests":
		workflow = "publish-manifests"
	case "oci://ghcr.io/devantler-tech/ascoachingogvaner/manifests", "oci://ghcr.io/devantler-tech/wedding-app/manifests":
		workflow = "publish-app"
	default:
		return document
	}
	verify, ok := spec["verify"].(map[string]any)
	if !ok || verify["provider"] != "cosign" {
		return document
	}
	identities, ok := verify["matchOIDCIdentity"].([]any)
	if !ok || len(identities) != 1 {
		return document
	}
	matcher, ok := identities[0].(map[string]any)
	if !ok || matcher["issuer"] != `^https://token\.actions\.githubusercontent\.com$` {
		return document
	}
	subject, ok := matcher["subject"].(string)
	prefix := `^https://github\.com/devantler-tech/actions/\.github/workflows/` + workflow + `\.yaml@`
	if !ok || !strings.HasPrefix(subject, prefix) || !strings.HasSuffix(subject, "$") {
		return document
	}
	ref := strings.TrimSuffix(strings.TrimPrefix(subject, prefix), "$")
	if !isExactPublishRevisionSet(ref) {
		return document
	}

	projected := cloneStringAnyMap(document)
	projectedSpec := cloneStringAnyMap(spec)
	projectedVerify := cloneStringAnyMap(verify)
	projectedMatcher := cloneStringAnyMap(matcher)
	projectedMatcher["subject"] = prefix + `[0-9a-f]{40}$`
	projectedVerify["matchOIDCIdentity"] = []any{projectedMatcher}
	projectedSpec["verify"] = projectedVerify
	projected["spec"] = projectedSpec
	return projected
}

// isExactPublishRevisionSet accepts one concrete SHA or one parenthesized pair;
// regular expressions, floating refs, and additional alternatives stay exact.
func isExactPublishRevisionSet(ref string) bool {
	if exactGitCommit.MatchString(ref) {
		return true
	}
	if !strings.HasPrefix(ref, "(") || !strings.HasSuffix(ref, ")") {
		return false
	}
	revisions := strings.Split(ref[1:len(ref)-1], "|")
	if len(revisions) > 2 {
		return false
	}
	for _, revision := range revisions {
		if !exactGitCommit.MatchString(revision) {
			return false
		}
	}
	return true
}
