package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writeCSE writes a CR file into a temp dir and returns the dir.
func writeCSE(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "exception.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write CR: %v", err)
	}

	return dir
}

// TestGenerateResourcesMatch verifies resource matches become anchored designators.
func TestGenerateResourcesMatch(t *testing.T) {
	dir := writeCSE(t, `
apiVersion: security.devantler.tech/v1alpha1
kind: ClusterSecurityException
metadata:
  name: exec-into-container-rbac
spec:
  reason: |
    Flux impersonates the tenant
    service account.
  posture:
    - controlID: C-0002
      action: ignore
  match:
    resources:
      - apiGroup: rbac.authorization.k8s.io
        kind: ClusterRole
        name: ^flux-operator$
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("want 1 policy, got %d", len(policies))
	}

	got := policies[0]
	if got.Name != "exec-into-container-rbac" {
		t.Errorf("name = %q", got.Name)
	}

	if got.PolicyType != "postureExceptionPolicy" {
		t.Errorf("policyType = %q", got.PolicyType)
	}

	// Native alertOnly now acknowledges a finding without suppressing it.
	// The CR's ignore action must retain its exclusion from the scanner's score.
	if len(got.Actions) != 1 || got.Actions[0] != "disable" {
		t.Errorf("ignore must emit the native suppression action [disable], got %v", got.Actions)
	}

	// controlID is a plain value => anchored; an already-anchored name is kept.
	if got.PosturePolicies[0].ControlID != "^C-0002$" {
		t.Errorf("controlID = %q, want ^C-0002$", got.PosturePolicies[0].ControlID)
	}

	attrs := got.Resources[0].Attributes
	if attrs["kind"] != "^ClusterRole$" {
		t.Errorf("kind = %q, want ^ClusterRole$", attrs["kind"])
	}

	if attrs["name"] != "^flux-operator$" {
		t.Errorf("name = %q, want ^flux-operator$ (explicit anchors preserved)", attrs["name"])
	}

	// apiGroup is intentionally dropped (no such designator attribute).
	if _, ok := attrs["apiGroup"]; ok {
		t.Error("apiGroup must not be emitted as a designator attribute")
	}

	// Reason is whitespace-collapsed onto one line.
	if got.Reason != "Flux impersonates the tenant service account." {
		t.Errorf("reason = %q", got.Reason)
	}
}

// TestGenerateNamespaceSelector verifies namespace values become one exact-match regex.
func TestGenerateNamespaceSelector(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: privileged-system-namespaces
spec:
  posture:
    - controlID: C-0013
      action: ignore
  match:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: [kube-system, cilium-secrets]
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	got := policies[0].Resources[0].Attributes["namespace"]
	if got != "^(kube-system|cilium-secrets)$" {
		t.Errorf("namespace = %q, want ^(kube-system|cilium-secrets)$", got)
	}
}

// TestGenerateNamespaceSelectorNotIn verifies a complementary selector keeps
// newly introduced namespaces covered while rejecting only the declared
// exclusions. It exercises the generated designator rather than its source
// spelling because Kubescape consumes the regex behavior.
func TestGenerateNamespaceSelectorNotIn(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: mutation-enabled-namespaces
spec:
  posture:
    - controlID: C-0013
      action: ignore
  match:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: [kube-system, cilium-secrets, edge.test]
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	pattern := policies[0].Resources[0].Attributes["namespace"]
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile generated namespace pattern %q: %v", pattern, err)
	}

	tests := map[string]bool{
		"":                     false,
		"kube-system":          false,
		"cilium-secrets":       false,
		"edge.test":            false,
		"edgeXtest":            true,
		"kube-syste":           true,
		"kube-system-extra":    true,
		"new-tenant-namespace": true,
	}

	for namespace, want := range tests {
		if got := matcher.MatchString(namespace); got != want {
			t.Errorf("namespace %q matched = %t, want %t (pattern %q)", namespace, got, want, pattern)
		}
	}
}

// TestGenerateNoMatchIsClusterWide verifies a DECLARED cluster-wide exception
// targets every resource, including cluster-scoped resources that have no
// namespace.
func TestGenerateNoMatchIsClusterWide(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: cluster-wide
  annotations:
    platform.devantler.tech/cluster-wide: declared
spec:
  posture:
    - controlID: C-0034
      action: ignore
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	attributes := policies[0].Resources[0].Attributes
	if got := attributes["kind"]; got != ".*" {
		t.Errorf("kind = %q, want .* (resource-wide default)", got)
	}

	if _, ok := attributes["namespace"]; ok {
		t.Error("cluster-wide default must not require a namespace")
	}
}

// TestUndeclaredClusterWideScopeFailsClosed is the guard: an exception with no
// spec.match suppresses its controls for EVERY workload, and until this fired
// that scope was reached by writing nothing at all. An author who forgot to
// scope an exception and one who deliberately chose cluster-wide produced byte
// for byte the same CR, so review had no signal to catch the first.
func TestUndeclaredClusterWideScopeFailsClosed(t *testing.T) {
	_, err := generate(writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: undeclared
spec:
  posture:
    - controlID: C-0013
      action: ignore
`))
	if err == nil {
		t.Fatal("undeclared cluster-wide scope must fail closed, got nil error")
	}

	if !strings.Contains(err.Error(), clusterWideAnnotation) {
		t.Errorf("error %q must name %s so the fix is obvious", err, clusterWideAnnotation)
	}
}

// TestClusterWideAnnotationFailsClosed covers the marker's own malformed
// shapes. A typo'd value must not be read as a declaration.
//
// Each case asserts WHICH error it got, not merely that it got one. Every
// fixture here also has no spec.match, so a regression that ignored this
// annotation entirely would still be rejected — by the undeclared-scope guard —
// and a bare `err != nil` check would stay green while the marker did nothing.
func TestClusterWideAnnotationFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		annotation string
		want       string
	}{
		"wrong value": {
			annotation: `platform.devantler.tech/cluster-wide: "true"`,
			want:       `unsupported platform.devantler.tech/cluster-wide value "true"`,
		},
		"empty value": {
			annotation: `platform.devantler.tech/cluster-wide: ""`,
			want:       `unsupported platform.devantler.tech/cluster-wide value ""`,
		},
		"non-string": {
			annotation: `platform.devantler.tech/cluster-wide: true`,
			want:       "platform.devantler.tech/cluster-wide must be a string",
		},
		"capitalised": {
			annotation: `platform.devantler.tech/cluster-wide: Declared`,
			want:       `unsupported platform.devantler.tech/cluster-wide value "Declared"`,
		},
		"padded value": {
			annotation: `platform.devantler.tech/cluster-wide: " declared "`,
			want:       `unsupported platform.devantler.tech/cluster-wide value " declared "`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := generate(writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: malformed-marker
  annotations:
    `+tc.annotation+`
spec:
  posture:
    - controlID: C-0013
      action: ignore
`))
			if err == nil {
				t.Fatalf("malformed cluster-wide marker must fail closed, want an error containing %q, got none", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestDeclaredClusterWideWithMatchFailsClosed rejects a CR that both declares
// cluster-wide scope and scopes itself. The two statements contradict, and
// silently honouring the match would leave a marker on file claiming a scope
// the generated exception does not have — the same invisible-scope problem one
// level up.
func TestDeclaredClusterWideWithMatchFailsClosed(t *testing.T) {
	_, err := generate(writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: contradictory
  annotations:
    platform.devantler.tech/cluster-wide: declared
spec:
  posture:
    - controlID: C-0013
      action: ignore
  match:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values:
            - flux-system
`))
	if err == nil {
		t.Fatal("declaring cluster-wide scope alongside a match must fail closed, got nil error")
	}
}

// TestGenerateFrameworkScopedPosture verifies a CSE framework constraint is
// preserved in Kubescape's native posture policy instead of being widened.
func TestGenerateFrameworkScopedPosture(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: nsa-only
  annotations:
    platform.devantler.tech/cluster-wide: declared
spec:
  posture:
    - frameworkName: NSA
      controlID: C-0030
      action: ignore
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	rendered, err := render(policies)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var got []struct {
		PosturePolicies []map[string]string `json:"posturePolicies"`
	}
	if err := json.Unmarshal(rendered, &got); err != nil {
		t.Fatalf("unmarshal rendered policy: %v", err)
	}

	if framework := got[0].PosturePolicies[0]["frameworkName"]; framework != "^NSA$" {
		t.Errorf("frameworkName = %q, want ^NSA$", framework)
	}
}

// TestGenerateSkipsNonExceptionDocumentsAndSorts verifies filtering and deterministic order.
func TestGenerateSkipsNonExceptionDocumentsAndSorts(t *testing.T) {
	dir := writeCSE(t, `
kind: ConfigMap
metadata:
  name: not-an-exception
---
kind: ClusterSecurityException
metadata:
  name: zzz-last
  annotations:
    platform.devantler.tech/cluster-wide: declared
spec:
  posture:
    - controlID: C-0002
      action: ignore
---
kind: ClusterSecurityException
metadata:
  name: aaa-first
  annotations:
    platform.devantler.tech/cluster-wide: declared
spec:
  posture:
    - controlID: C-0002
      action: ignore
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(policies) != 2 {
		t.Fatalf("want 2 policies (ConfigMap skipped), got %d", len(policies))
	}

	if policies[0].Name != "aaa-first" || policies[1].Name != "zzz-last" {
		t.Errorf("policies not sorted by name: %q, %q", policies[0].Name, policies[1].Name)
	}
}

// TestGenerateFailsClosed pins the fail-closed contract: every unrecognised CR
// shape aborts instead of silently dropping or widening an exception.
func TestGenerateFailsClosed(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		body string
		want string
	}{
		"partially anchored value": {
			body: `
kind: ClusterSecurityException
metadata: {name: partial}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    resources: [{kind: ClusterRole, name: ^open-ended}]
`,
			want: "partially anchored",
		},
		"unsupported posture action": {
			body: `
kind: ClusterSecurityException
metadata: {name: bad-action}
spec:
  posture: [{controlID: C-0002, action: alert}]
`,
			want: "unsupported posture action",
		},
		"expiration cannot be silently dropped": {
			body: `
kind: ClusterSecurityException
metadata: {name: temporary}
spec:
  expiresAt: "2026-12-01T00:00:00Z"
  posture: [{controlID: C-0002, action: ignore}]
`,
			want: "spec.expiresAt cannot be preserved",
		},
		"unknown match key": {
			body: `
kind: ClusterSecurityException
metadata: {name: bad-match-key}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match: {labelSelector: {app: web}}
`,
			want: "unsupported match keys",
		},
		"unknown resources key": {
			body: `
kind: ClusterSecurityException
metadata: {name: bad-resource-key}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    resources: [{kind: Pod, namespace: kube-system}]
`,
			want: "unsupported match.resources keys",
		},
		"both resources and namespaceSelector": {
			body: `
kind: ClusterSecurityException
metadata: {name: both}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    resources: [{kind: Pod}]
    namespaceSelector:
      matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [x]}]
`,
			want: "both match.resources and match.namespaceSelector set",
		},
		"empty match is not coerced to cluster-wide": {
			body: `
kind: ClusterSecurityException
metadata: {name: empty-match}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match: {}
`,
			want: "spec.match must be a non-empty mapping",
		},
		"resource without kind": {
			body: `
kind: ClusterSecurityException
metadata: {name: no-kind}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    resources: [{apiGroup: apps}]
`,
			want: "match.resources entry without a kind",
		},
		"unsupported matchExpression operator": {
			body: `
kind: ClusterSecurityException
metadata: {name: bad-operator}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    namespaceSelector:
      matchExpressions: [{key: kubernetes.io/metadata.name, operator: Exists, values: [x]}]
`,
			want: "matchExpressions are supported",
		},
		"NotIn requires exclusions": {
			body: `
kind: ClusterSecurityException
metadata: {name: empty-not-in}
spec:
  posture: [{controlID: C-0002, action: ignore}]
  match:
    namespaceSelector:
      matchExpressions: [{key: kubernetes.io/metadata.name, operator: NotIn, values: []}]
`,
			want: "matchExpression has no values",
		},
		"empty posture": {
			body: `
kind: ClusterSecurityException
metadata: {name: no-posture}
spec:
  posture: []
`,
			want: "spec.posture is empty",
		},
		"missing metadata.name": {
			body: `
kind: ClusterSecurityException
spec:
  posture: [{controlID: C-0002, action: ignore}]
`,
			want: "missing metadata.name",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := generate(writeCSE(t, tc.body))
			if err == nil {
				t.Fatalf("want a fail-closed error containing %q, got none", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGenerateRejectsDuplicateNames verifies duplicate policy identities fail closed.
func TestGenerateRejectsDuplicateNames(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata: {name: dupe}
spec:
  match: {namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [flux-system]}]}}
  posture: [{controlID: C-0002, action: ignore}]
---
kind: ClusterSecurityException
metadata: {name: dupe}
spec:
  match: {namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [flux-system]}]}}
  posture: [{controlID: C-0013, action: ignore}]
`)

	_, err := generate(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate exception name") {
		t.Fatalf("want duplicate-name error, got %v", err)
	}
}

// TestGenerateRejectsEmptyDirectory verifies an empty source cannot produce a permissive file.
func TestGenerateRejectsEmptyDirectory(t *testing.T) {
	_, err := generate(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no ClusterSecurityException documents found") {
		t.Fatalf("want empty-directory error, got %v", err)
	}
}

// mirrorNames returns the policy names the Headlamp mirror would carry.
func mirrorNames(t *testing.T, dir string) []string {
	t.Helper()

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	names := make([]string, 0, len(policies))
	for _, kept := range mirrored(policies) {
		names = append(names, kept.Name)
	}

	return names
}

// TestMirrorExcludesAnnotatedException verifies the annotation keeps a
// host-scanner exception out of the Headlamp mirror while leaving it in the
// Kubescape scan input — the two consumers must not be conflated.
func TestMirrorExcludesAnnotatedException(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: host-only
  annotations:
    platform.devantler.tech/headlamp-mirror: exclude
    platform.devantler.tech/cluster-wide: declared
spec:
  posture: [{controlID: C-0092, action: ignore}]
---
kind: ClusterSecurityException
metadata:
  name: workload-scoped
spec:
  match: {namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [flux-system]}]}}
  posture: [{controlID: C-0002, action: ignore}]
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// The offline CI scan must still receive BOTH: excluding a host exception
	// from the scan would make its controls fail the compliance gate.
	if len(policies) != 2 {
		t.Fatalf("Kubescape output must keep every exception, got %d", len(policies))
	}

	names := mirrorNames(t, dir)
	if len(names) != 1 || names[0] != "workload-scoped" {
		t.Errorf("mirror = %v, want only [workload-scoped]", names)
	}
}

// TestMirrorDefaultsToIncluded verifies an unannotated CR is mirrored: dropping
// an exception makes the dashboard report an excepted workload as failing.
func TestMirrorDefaultsToIncluded(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata: {name: no-annotations}
spec:
  match: {namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [flux-system]}]}}
  posture: [{controlID: C-0002, action: ignore}]
`)

	if names := mirrorNames(t, dir); len(names) != 1 {
		t.Errorf("mirror = %v, want the unannotated exception to be mirrored", names)
	}
}

// TestMirrorAnnotationFailsClosed verifies a marker this converter does not
// recognise aborts instead of being read as "include" — a typo must never push
// a cluster-wide host exception into the workload dashboard.
func TestMirrorAnnotationFailsClosed(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		value string
		want  string
	}{
		"unknown value":          {value: "excluded", want: "unsupported platform.devantler.tech/headlamp-mirror value"},
		"list not string":        {value: "[exclude]", want: "must be a string"},
		"include is not a value": {value: "include", want: "unsupported platform.devantler.tech/headlamp-mirror value"},
		"empty value":            {value: `""`, want: "unsupported platform.devantler.tech/headlamp-mirror value"},
		"boolean not string":     {value: "true", want: "must be a string"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := generate(writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: marked
  annotations:
    platform.devantler.tech/headlamp-mirror: `+tc.value+`
spec:
  posture: [{controlID: C-0002, action: ignore}]
`))
			if err == nil {
				t.Fatalf("want a fail-closed error containing %q, got none", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestMirrorMalformedAnnotationsFailClosed verifies a malformed annotations
// block aborts instead of being read as "no marker". Reading it as absent would
// silently drop the exclusion and mirror a host-scanner exception, whose
// cluster-wide designator then excepts that control for every workload.
func TestMirrorMalformedAnnotationsFailClosed(t *testing.T) {
	_, err := generate(writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: malformed-annotations
  annotations: "platform.devantler.tech/headlamp-mirror=exclude"
spec:
  posture: [{controlID: C-0092, action: ignore}]
`))
	if err == nil || !strings.Contains(err.Error(), "metadata.annotations must be a mapping") {
		t.Fatalf("want a fail-closed annotations error, got %v", err)
	}
}

// TestMirrorEmptyAnnotationsAreNotAMarker verifies an explicitly-empty
// annotations block is still just "no marker", so the fail-closed check above
// does not reject ordinary CRs.
func TestMirrorEmptyAnnotationsAreNotAMarker(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: empty-annotations
  annotations:
spec:
  match: {namespaceSelector: {matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [flux-system]}]}}
  posture: [{controlID: C-0002, action: ignore}]
`)

	if names := mirrorNames(t, dir); len(names) != 1 {
		t.Errorf("mirror = %v, want the CR mirrored (empty annotations are not a marker)", names)
	}
}

// TestMirrorRefusesEmptyResult verifies an all-excluded set fails closed rather
// than writing a ConfigMap that silently shows the dashboard no exceptions.
func TestMirrorRefusesEmptyResult(t *testing.T) {
	dir := writeCSE(t, `
kind: ClusterSecurityException
metadata:
  name: host-only
  annotations:
    platform.devantler.tech/headlamp-mirror: exclude
    platform.devantler.tech/cluster-wide: declared
spec:
  posture: [{controlID: C-0092, action: ignore}]
`)

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := renderHeadlampConfigMap(policies); err == nil {
		t.Fatal("want an error when every exception is excluded from the mirror")
	}
}

// TestCommittedMirrorIsUpToDate is the drift gate. The Headlamp mirror used to
// be hand-maintained and drifted in the direction that HIDES findings — it once
// excepted C-0017 for every workload in the cluster while the CRs excepted it in
// three narrow places (platform#2586, fixed by #2837). Regenerating here means a
// CR change that is not mirrored fails CI instead of silently desynchronising
// the dashboard from the exceptions actually in force.
func TestCommittedMirrorIsUpToDate(t *testing.T) {
	dir := filepath.Join("..", "..", defaultDir)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("exceptions dir not present: %v", err)
	}

	committedPath := filepath.Join("..", "..", mirrorConfigMapPath)

	committed, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed mirror: %v", err)
	}

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	regenerated, err := renderHeadlampConfigMap(policies)
	if err != nil {
		t.Fatalf("render mirror: %v", err)
	}

	if string(committed) != string(regenerated) {
		t.Errorf("%s is out of date.\n\nRegenerate it with:\n"+
			"  go run ./scripts/generate-kubescape-exceptions -format %s -o %s\n",
			mirrorConfigMapPath, formatConfigMap, mirrorConfigMapPath)
	}
}

// TestGenerateAgainstRealExceptions is the behavioural check: the committed CRs
// must actually convert, and the rendered file must be the JSON array of
// PostureExceptionPolicy objects that `ksail workload scan --exceptions` reads.
func TestGenerateAgainstRealExceptions(t *testing.T) {
	dir := filepath.Join("..", "..", defaultDir)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("exceptions dir not present: %v", err)
	}

	policies, err := generate(dir)
	if err != nil {
		t.Fatalf("the committed ClusterSecurityException CRs must convert: %v", err)
	}

	if len(policies) == 0 {
		t.Fatal("want at least one policy from the committed CRs")
	}

	rendered, err := render(policies)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var roundTripped []map[string]any
	if err := json.Unmarshal(rendered, &roundTripped); err != nil {
		t.Fatalf("rendered exceptions must be a JSON array: %v", err)
	}

	for i, got := range roundTripped {
		if got["policyType"] != "postureExceptionPolicy" {
			t.Errorf("policy %d: policyType = %v", i, got["policyType"])
		}

		if got["name"] == "" || got["name"] == nil {
			t.Errorf("policy %d: missing name", i)
		}

		if resources, ok := got["resources"].([]any); !ok || len(resources) == 0 {
			t.Errorf("policy %d: must carry at least one designator", i)
		}
	}
}
