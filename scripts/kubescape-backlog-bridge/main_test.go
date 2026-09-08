package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Fixtures are written as RAW JSON rather than marshalled from Go structs, so
// they stay byte-faithful to what `kubectl get -o json` actually emits. The
// stripped shapes below were measured against prod on 2026-08-01:
// 2215/2215 posture LIST objects carried `controls: null`, and 121/121 CVE LIST
// objects carried a blanked `vulnerabilitiesRef`.

func labels(ns, kind, name string) string {
	return fmt.Sprintf(`"labels":{"kubescape.io/workload-namespace":%q,`+
		`"kubescape.io/workload-kind":%q,"kubescape.io/workload-name":%q}`, ns, kind, name)
}

// postureDoc builds a hydrated workloadconfigurationscansummary object.
func postureDoc(ns, kind, name string, controls map[string]string) string {
	return postureDocSev(ns, kind, name, controls, "High")
}

func postureDocSev(ns, kind, name string, controls map[string]string, severity string) string {
	ids := make([]string, 0, len(controls))
	for id := range controls {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(
			`%q:{"controlID":%q,"severity":{"severity":%q},"status":{"status":%q}}`,
			id, id, severity, controls[id]))
	}

	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,%s},`+
		`"spec":{"controls":{%s},"severities":{"critical":0,"high":0}}}`,
		name, ns, labels(ns, kind, name), strings.Join(parts, ","))
}

// strippedPostureDoc is the spec-stripped shape a posture LIST returns.
func strippedPostureDoc(ns, kind, name string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,%s},`+
		`"spec":{"controls":null,"severities":{"critical":0,"high":0,"low":0,"medium":0,"unknown":0}}}`,
		name, ns, labels(ns, kind, name))
}

// cveDoc builds a hydrated vulnerabilitymanifestsummary object, using the
// {"all": N} spelling the real objects use and naming a real manifest.
func cveDoc(ns, name string, counts map[string]int) string {
	// A genuine response carries ALL the buckets, zero-valued when clean, so
	// fixtures do too — otherwise they exercise a shape the parser rejects.
	classes := append([]string(nil), cveSeverityBuckets...)
	for class := range counts {
		if !slices.Contains(classes, class) {
			classes = append(classes, class)
		}
	}

	sort.Strings(classes)

	parts := make([]string, 0, len(classes))
	for _, class := range classes {
		parts = append(parts, fmt.Sprintf(`%q:{"all":%d,"relevant":%d}`, class, counts[class], counts[class]))
	}

	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,%s},`+
		`"spec":{"severities":{%s},`+
		`"vulnerabilitiesRef":{"all":{"kind":"vulnerabilitymanifests","name":"registry-image-%s","namespace":%q},`+
		`"relevant":{"kind":"vulnerabilitymanifests","name":"replicaset-%s","namespace":%q}}}}`,
		name, ns, labels(ns, "Deployment", name), strings.Join(parts, ","), name, ns, name, ns)
}

// strippedCVEDoc is the spec-stripped shape a CVE LIST returns: severities
// present but zero, and the manifest reference blanked.
func strippedCVEDoc(ns, name string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,%s},`+
		`"spec":{"severities":{"critical":{"all":0},"high":{"all":0},"low":{"all":0},`+
		`"medium":{"all":0},"negligible":{"all":0},"unknown":{"all":0}},`+
		`"vulnerabilitiesRef":{"all":{"kind":"","name":"","namespace":""},`+
		`"relevant":{"kind":"","name":"","namespace":""}}}}`,
		name, ns, labels(ns, "Deployment", name))
}

func itemOf(t *testing.T, doc string) item {
	t.Helper()

	var it item
	if err := json.Unmarshal([]byte(doc), &it); err != nil {
		t.Fatalf("fixture does not decode: %v\n%s", err, doc)
	}

	return it
}

func itemsOf(t *testing.T, docs ...string) []item {
	t.Helper()

	out := make([]item, 0, len(docs))
	for _, d := range docs {
		out = append(out, itemOf(t, d))
	}

	return out
}

// writeDocs writes a `kubectl get -A -o json` style list.
func writeDocs(t *testing.T, path string, docs ...string) {
	t.Helper()
	writeRaw(t, path, fmt.Sprintf(`{"items":[%s]}`, strings.Join(docs, ",")))
}

// writeBare writes a single-object `kubectl get <name> -o json` document.
func writeBare(t *testing.T, path, doc string) {
	t.Helper()
	writeRaw(t, path, doc)
}

func writeRaw(t *testing.T, path, raw string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mustDeriveCVE(t *testing.T, items []item) []theme {
	t.Helper()

	got, err := deriveCVE(items)
	if err != nil {
		t.Fatalf("deriveCVE: %v", err)
	}

	return got
}

func mustDerivePosture(t *testing.T, items []item, exceptions []exception) []theme {
	t.Helper()

	got, _, _, err := derivePosture(items, exceptions)
	if err != nil {
		t.Fatalf("derivePosture: %v", err)
	}

	return got
}

func TestOnlyFailedControlsBecomeThemes(t *testing.T) {
	items := itemsOf(t, postureDoc("app", "Deployment", "api", map[string]string{
		"C-0016": "failed",
		"C-0266": "passed",
		"C-0034": "skipped",
	}))

	got := mustDerivePosture(t, items, nil)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 theme (the failed control), got %d: %+v", len(got), got)
	}

	if got[0].Key != "C-0016" {
		t.Errorf("want the failed control C-0016, got %q", got[0].Key)
	}
}

func TestThemesGroupAcrossResourcesNotPerResource(t *testing.T) {
	items := itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
		postureDoc("app", "Deployment", "web", map[string]string{"C-0016": "failed"}),
		postureDoc("data", "StatefulSet", "db", map[string]string{"C-0016": "failed"}),
	)

	got := mustDerivePosture(t, items, nil)
	if len(got) != 1 {
		t.Fatalf("3 resources failing ONE control must yield 1 theme, got %d", len(got))
	}

	if got[0].Count != 3 {
		t.Errorf("want 3 affected components, got %d (%v)", got[0].Count, got[0].Components)
	}
}

// The anti-churn guarantee: identical state must re-derive an identical
// fingerprint. Input order is shuffled to prove the result does not depend on
// map iteration or slice order.
func TestFingerprintIsStableAcrossRunsAndInputOrder(t *testing.T) {
	base := itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
		postureDoc("app", "Deployment", "web", map[string]string{"C-0016": "failed"}),
		postureDoc("data", "StatefulSet", "db", map[string]string{"C-0016": "failed"}),
	)
	want := mustDerivePosture(t, base, nil)[0].Fingerprint()

	rng := rand.New(rand.NewSource(1))

	for i := range 50 {
		shuffled := append([]item(nil), base...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })

		got := mustDerivePosture(t, shuffled, nil)[0].Fingerprint()
		if got != want {
			t.Fatalf("shuffle %d changed the fingerprint: want %s got %s", i, want, got)
		}
	}
}

// A changing severity COUNT must update the existing theme, not mint a new
// identity — otherwise every scan re-files.
func TestFingerprintIgnoresCounts(t *testing.T) {
	few := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 1})))
	many := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 999})))

	if len(few) != 1 || len(many) != 1 {
		t.Fatalf("want one theme each, got %d and %d", len(few), len(many))
	}

	if few[0].Fingerprint() != many[0].Fingerprint() {
		t.Errorf("count change must not alter the fingerprint: %s vs %s",
			few[0].Fingerprint(), many[0].Fingerprint())
	}
}

// TestTitleIsStableAcrossAComponentCountChange holds Title to the promise its own doc comment
// makes — "Stable for a given theme so a search-before-create can match on it". It rendered
// pluralComponents(len(t.Components)), so a workload joining or leaving an otherwise unchanged
// theme flipped "1 workload" to "2 workloads". The write half searches on the title, so that
// search misses and the theme is re-filed as a duplicate — the same churn the fingerprint
// deliberately avoids by excluding the count.
//
// The count is not lost: report() already renders total= and components= as their own fields.
func TestTitleIsStableAcrossAComponentCountChange(t *testing.T) {
	one := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 1})))
	two := mustDeriveCVE(t, itemsOf(t,
		cveDoc("app", "api", map[string]int{"critical": 1}),
		cveDoc("app", "web", map[string]int{"critical": 1})))

	if len(one) != 1 || len(two) != 1 {
		t.Fatalf("want one theme each, got %d and %d", len(one), len(two))
	}

	if len(one[0].Components) == len(two[0].Components) {
		t.Fatalf("fixture does not exercise a count change: both have %d components",
			len(one[0].Components))
	}

	if one[0].Title() != two[0].Title() {
		t.Errorf("a component-count change must not alter the title a search-before-create matches on:\n"+
			" 1 component: %q\n%d components: %q",
			one[0].Title(), len(two[0].Components), two[0].Title())
	}
}

// TestDuplicateInputObjectIsRejected covers double counting. add() dedupes the component SET but
// the severity total was summed unconditionally, so passing the same object twice — the same file
// twice, or the same object present in two files — rendered total=2 for a single critical while
// components= still listed one workload. The report then overstates the platform's exposure, and
// the two fields contradict each other.
//
// Distinct image summaries for one workload are NOT duplicates and must still aggregate: they are
// separate objects with separate names that legitimately sum.
func TestDuplicateInputObjectIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cve.json")
	writeDocs(t, path, cveDoc("app", "api", map[string]int{"critical": 1}))

	var out bytes.Buffer

	err := run([]string{"-cve", path, "-cve", path}, &out)
	if err == nil {
		t.Fatalf("the same object passed twice must be rejected, not double counted; got: %s", out.String())
	}

	// The classification is part of the fix. Reported as errUnrecognisedDocument this reads as
	// "your file is unparseable" and sends an operator to inspect the document, when the document
	// is fine and the arguments are what repeated.
	if !errors.Is(err, errDuplicateObject) {
		t.Errorf("a duplicate must report errDuplicateObject, not a parse failure; got: %v", err)
	}
}

// TestDistinctImageSummariesForOneWorkloadStillAggregate is the over-tightening control for the
// rule above. Two DIFFERENT objects that resolve to the same workload are the normal CVE shape —
// one summary per image — and their counts must still sum.
func TestDistinctImageSummariesForOneWorkloadStillAggregate(t *testing.T) {
	got := mustDeriveCVE(t, itemsOf(t,
		cveDoc("app", "api-image-a", map[string]int{"critical": 2}),
		cveDoc("app", "api-image-b", map[string]int{"critical": 3})))

	if len(got) != 1 {
		t.Fatalf("want one critical theme, got %d", len(got))
	}

	if got[0].Total != 5 {
		t.Errorf("distinct image summaries must still sum: total = %d, want 5", got[0].Total)
	}
}

// The counterpart to the rule above: excluding the count from the IDENTITY is
// correct, but the count must still be carried, or an update to an existing
// entry cannot show 1 critical becoming 999 and the update is pointless.
func TestTotalIsAccumulatedEvenThoughItIsNotFingerprinted(t *testing.T) {
	few := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 1})))
	many := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 999})))

	if few[0].Total != 1 || many[0].Total != 999 {
		t.Fatalf("totals must reflect the real counts, got %d and %d", few[0].Total, many[0].Total)
	}

	var a, b bytes.Buffer
	if err := report(few, []surface{surfaceCVE}, true, 0, &a); err != nil {
		t.Fatalf("report: %v", err)
	}

	if err := report(many, []surface{surfaceCVE}, true, 0, &b); err != nil {
		t.Fatalf("report: %v", err)
	}

	if a.String() == b.String() {
		t.Errorf("1 and 999 criticals must not render identically: %q", a.String())
	}
}

// Totals are summed across workloads, not overwritten by the last one seen.
func TestTotalSumsAcrossWorkloads(t *testing.T) {
	got := mustDeriveCVE(t, itemsOf(t,
		cveDoc("app", "api", map[string]int{"critical": 2}),
		cveDoc("app", "web", map[string]int{"critical": 5}),
	))
	if len(got) != 1 {
		t.Fatalf("want 1 theme, got %d", len(got))
	}

	if got[0].Total != 7 {
		t.Errorf("want the summed total 7, got %d", got[0].Total)
	}
}

// A changing component SET must NOT change the identity. Which workloads
// exhibit a theme is mutable state about it, not part of what it IS — so a
// workload joining or leaving updates the existing entry instead of minting a
// new one and stranding the old.
func TestFingerprintIsStableWhenTheComponentSetChanges(t *testing.T) {
	one := mustDerivePosture(t, itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
	), nil)
	two := mustDerivePosture(t, itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
		postureDoc("app", "Deployment", "web", map[string]string{"C-0016": "failed"}),
	), nil)

	if one[0].Fingerprint() != two[0].Fingerprint() {
		t.Errorf("a workload joining a theme must not change its identity: %s vs %s",
			one[0].Fingerprint(), two[0].Fingerprint())
	}

	if one[0].Count == two[0].Count {
		t.Error("guard: the component sets must actually differ, or the test is vacuous")
	}
}

// The converse control: a DIFFERENT theme must have a different identity, without
// which the test above would pass for a constant fingerprint.
func TestFingerprintDiffersByKeyAndSurface(t *testing.T) {
	a := mustDerivePosture(t, itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
	), nil)
	b := mustDerivePosture(t, itemsOf(t,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0087": "failed"}),
	), nil)

	if a[0].Fingerprint() == b[0].Fingerprint() {
		t.Error("different controls must have different identities")
	}

	// Assert the theme EXISTS rather than guarding on it: `len(cve) > 0 &&`
	// makes the comparison skip silently if derivation ever returns nothing,
	// which is the vacuity this control exists to rule out.
	cve := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"C-0016": 1})))
	if len(cve) != 1 {
		t.Fatalf("want exactly 1 cve theme to compare against, got %d", len(cve))
	}

	if cve[0].Fingerprint() == a[0].Fingerprint() {
		t.Error("the same key on a different surface must have a different identity")
	}
}

func TestZeroCountSeveritiesRaiseNoTheme(t *testing.T) {
	got := mustDeriveCVE(t, itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 0, "high": 0})))
	if len(got) != 0 {
		t.Errorf("all-zero severities must raise no theme, got %+v", got)
	}
}

func TestSeverityCountAcceptsBothSpellings(t *testing.T) {
	if got, ok := severityCount(json.RawMessage(`7`)); !ok || got != 7 {
		t.Errorf("bare integer: want 7, got %d", got)
	}

	if got, ok := severityCount(json.RawMessage(`{"all":7}`)); !ok || got != 7 {
		t.Errorf(`{"all":N} form: want 7, got %d`, got)
	}
}

// The stripped-skeleton guard, at the size where the previous SIZE heuristic
// silently gave up: a single stripped object. `critical: 0` here is not a clean
// cluster, it is an unread one, and the two must not be conflated.
func TestSingleStrippedCVEObjectFailsClosed(t *testing.T) {
	err := checkExamined(itemsOf(t, strippedCVEDoc("app", "api")))
	if err == nil {
		t.Fatal("a stripped object must fail closed regardless of input size")
	}

	if !errors.Is(err, errStrippedList) {
		t.Errorf("want errStrippedList, got %v", err)
	}
}

func TestSingleStrippedPostureObjectFailsClosed(t *testing.T) {
	err := checkExamined(itemsOf(t, strippedPostureDoc("app", "Deployment", "api")))
	if err == nil {
		t.Fatal("a posture object with `controls: null` must fail closed")
	}

	if !errors.Is(err, errStrippedList) {
		t.Errorf("want errStrippedList, got %v", err)
	}
}

// The control that makes the two tests above meaningful: an EXAMINED object
// with nothing to report must pass. Measured on prod, a genuinely clean image
// still names its manifest and a genuinely compliant workload still carries its
// control map — so "examined and empty" is distinguishable from "never read".
func TestExaminedButEmptyInputPasses(t *testing.T) {
	if err := checkExamined(itemsOf(t, cveDoc("app", "api", map[string]int{"critical": 0}))); err != nil {
		t.Errorf("a clean-but-examined CVE object must pass, got %v", err)
	}

	allPassed := postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "passed"})
	if err := checkExamined(itemsOf(t, allPassed)); err != nil {
		t.Errorf("an all-passed posture object must pass, got %v", err)
	}
}

// A posture object carrying an empty-but-present control map is an answer, not
// a silence.
func TestEmptyControlMapIsExaminedNotStripped(t *testing.T) {
	doc := `{"metadata":{"name":"api","namespace":"app"},"spec":{"controls":{},"severities":{}}}`
	if err := checkExamined(itemsOf(t, doc)); err != nil {
		t.Errorf("`controls: {}` is examined-and-empty, must pass, got %v", err)
	}
}

// One stripped object among hydrated ones still fails closed: it contributes
// silent zeros to the derived themes.
func TestOneStrippedObjectAmongHydratedOnesFailsClosed(t *testing.T) {
	items := itemsOf(t,
		cveDoc("app", "api", map[string]int{"critical": 3}),
		strippedCVEDoc("app", "web"),
	)
	if err := checkExamined(items); err == nil {
		t.Error("a stripped object must fail closed even alongside hydrated ones")
	}
}

// Sanitization: the rendered component carries namespace/kind/name and none of
// the reachability evidence that must stay out of a public issue.
func TestComponentCarriesOnlyTheSanitizedMinimum(t *testing.T) {
	it := itemOf(t, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	got := it.component().String()
	if got != "app/Deployment/api" {
		t.Fatalf("want app/Deployment/api, got %q", got)
	}

	for _, leak := range []string{"10.244.", "wlid://", "sha256:", "prod-worker"} {
		if strings.Contains(got, leak) {
			t.Errorf("component leaked %q: %s", leak, got)
		}
	}
}

// Feature-flag-first: BOTH states are exercised. Report is the default-on
// half; write is refused while the flag is off.
func TestModeReportIsTheDefaultAndProducesOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeDocs(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("report mode must succeed, got %v", err)
	}

	if !strings.Contains(out.String(), "C-0016") {
		t.Errorf("report must name the control, got %q", out.String())
	}
}

func TestModeWriteNeedsARepository(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{"-mode", "write"}, &out)
	if err == nil {
		t.Fatal("write mode without -repo must be refused")
	}

	if !errors.Is(err, errWritesNotEnabled) {
		t.Errorf("want errWritesNotEnabled, got %v", err)
	}
}

// TestUnknownModeIsRefused keeps a typo from silently selecting the default.
// `-mode=wrote` reporting instead of writing is a failure that looks like
// success, which is this command's whole subject matter.
func TestUnknownModeIsRefused(t *testing.T) {
	var out bytes.Buffer

	err := run([]string{"-mode", "wrote"}, &out)
	if err == nil {
		t.Fatal("an unknown -mode must be refused")
	}

	// This invocation ALSO carries no input, and run refuses that too, so
	// "some error came back" passes for whichever check happens to run first
	// and would keep passing if the mode check stopped firing entirely. Both
	// halves are needed: the sentinel proves it is an invocation refusal rather
	// than an unrelated failure, and the message proves it is THIS one.
	if !errors.Is(err, errInvalidInvocation) {
		t.Errorf("want errInvalidInvocation, got %v", err)
	}

	if !strings.Contains(err.Error(), "unknown -mode") {
		t.Errorf("the refusal does not name the mode check: %v", err)
	}

	// CONTROL — the same invocation with a VALID mode must get past this gate,
	// so the assertion above is attributable to the mode and not to the missing
	// input it also carries.
	var ctrl bytes.Buffer

	ctrlErr := run([]string{"-mode", "report"}, &ctrl)
	if ctrlErr != nil && strings.Contains(ctrlErr.Error(), "unknown -mode") {
		t.Fatalf("control did not flip: a valid mode was still refused, got %v", ctrlErr)
	}
}

// TestInputsCompleteIsRefusedInReportMode stops the close gate from being
// carried around as a harmless-looking habit. The flag does nothing in report
// mode, so accepting it teaches an operator it is safe to leave set — and the
// next write run then closes on partial input.
func TestInputsCompleteIsRefusedInReportMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeDocs(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer

	if err := run([]string{"-posture", path, "-inputs-complete"}, &out); err == nil {
		t.Fatal("-inputs-complete must be refused outside write mode")
	}

	// CONTROL — the same invocation without the flag must succeed, so the
	// refusal above is attributable to the flag and not to the input.
	var ctrl bytes.Buffer
	if err := run([]string{"-posture", path}, &ctrl); err != nil {
		t.Fatalf("control run must succeed, got %v", err)
	}
}

// Two consecutive runs on unchanged state must be byte-identical. This is the
// issue's stated acceptance check, asserted directly.
func TestConsecutiveRunsOnUnchangedStateAreByteIdentical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeDocs(t, path,
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}),
		postureDoc("data", "StatefulSet", "db", map[string]string{"C-0087": "failed"}),
	)

	var first, second bytes.Buffer
	if err := run([]string{"-posture", path}, &first); err != nil {
		t.Fatalf("first run: %v", err)
	}

	if err := run([]string{"-posture", path}, &second); err != nil {
		t.Fatalf("second run: %v", err)
	}

	if first.String() != second.String() {
		t.Errorf("consecutive runs differ:\n1: %q\n2: %q", first.String(), second.String())
	}

	if first.Len() == 0 {
		t.Error("guard: the comparison above is vacuous if both runs are empty")
	}
}

// One control can be reported at different severities by different workloads.
// The theme must keep the HIGHEST, independently of input order.
func TestThemeSeverityIsTheHighestAndOrderIndependent(t *testing.T) {
	low := postureDocSev("app", "Deployment", "a", map[string]string{"C-0016": "failed"}, "Low")
	high := postureDocSev("app", "Deployment", "b", map[string]string{"C-0016": "failed"}, "Critical")

	for _, order := range [][]string{{low, high}, {high, low}} {
		got := mustDerivePosture(t, itemsOf(t, order...), nil)
		if len(got) != 1 {
			t.Fatalf("want 1 theme, got %d", len(got))
		}

		if got[0].Severity != "Critical" {
			t.Errorf("want the highest severity (Critical), got %q", got[0].Severity)
		}
	}
}

func TestSeverityRankPutsUnknownLowest(t *testing.T) {
	if severityRank("some-future-severity") >= severityRank("Negligible") {
		t.Error("an unrecognised severity must not outrank a known one")
	}

	if severityRank("Critical") <= severityRank("High") {
		t.Error("Critical must outrank High")
	}
}

// An invocation with no input must not answer "nothing to file".
func TestNoInputIsAnErrorNotACleanBillOfHealth(t *testing.T) {
	var out bytes.Buffer

	err := run(nil, &out)
	if err == nil {
		t.Fatal("an empty invocation must be an error, not a clean report")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for missing input, got %q", out.String())
	}
}

// A per-object `kubectl get <crd> <name> -n <ns> -o json` emits a BARE object
// with no "items" key — exactly what this command's own documentation tells the
// operator to produce.
func TestBareSingleObjectInputIsParsedNotSilentlyEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bare.json")
	writeBare(t, path, cveDoc("app", "api", map[string]int{"critical": 18}))

	var out bytes.Buffer
	if err := run([]string{"-cve", path}, &out); err != nil {
		t.Fatalf("a bare per-object document must be accepted, got %v", err)
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Fatalf("bare object with critical=18 reported an all-clear: %q", out.String())
	}

	if !strings.Contains(out.String(), "critical") {
		t.Errorf("want the critical theme, got %q", out.String())
	}
}

func TestUnrecognisedDocumentShapeIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.json")
	writeRaw(t, path, `{"unrelated":true}`)

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("an unrecognised document shape must be rejected, not reported clean")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for junk input, got %q", out.String())
	}
}

// An empty list is genuinely empty about its COUNT but says nothing about its
// SURFACE, and this command reports the surface it was ASKED for. checkSurface
// decides the surface by inspecting objects, so an empty list gives it nothing
// to judge and it passed vacuously — the guard was present and inert rather
// than absent. The command then reported the requested surface as clean on a
// document that never identified itself as belonging to it.
//
// The top-level `kind` cannot rescue this. `kubectl get <crd> -o json` emits a
// GENERIC `apiVersion: v1, kind: List` for BOTH surfaces — measured against
// prod 2026-08-01: 2215 posture objects and 359 CVE objects, `kind: List` in
// every case, for both `-A` and a single namespace — so a real list carries no
// surface marker to check. Refusing an input whose surface cannot be
// established is therefore the only fail-closed reading available.
func TestEmptyListCannotEstablishItsSurfaceAndIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	writeRaw(t, path, `{"items":[]}`)

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("an empty list establishes no surface and must be rejected")
	}

	if !errors.Is(err, errSurfaceNotEstablished) {
		t.Errorf("want errSurfaceNotEstablished, got %v", err)
	}

	// The sentinel must not overstate what is known. An empty list is not a
	// surface MISMATCH (we cannot tell which surface it is), not malformed
	// CONTENT (there is no object), and not an unrecognised DOCUMENT (kubectl
	// emits exactly this shape), so reporting it as any of those would send the
	// operator to inspect something that is not wrong.
	for _, wrong := range []error{errSurfaceMismatch, errMalformedScanContent, errUnrecognisedDocument} {
		if errors.Is(err, wrong) {
			t.Errorf("must not report an unestablished surface as %v", wrong)
		}
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for a surfaceless input, got %q", out.String())
	}
}

// The exact document the reviewer reproduced with: a CVE list, empty, handed to
// -posture. It exited 0 reporting the posture input clean.
func TestEmptyCVEListPassedToPostureDoesNotReportPostureClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-cve.json")
	writeRaw(t, path, `{"kind":"VulnerabilityManifestSummaryList","items":[]}`)

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("an empty CVE list must not report the posture surface clean")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// A document handed to the wrong surface must be an error. Before this, a CVE
// file passed to -posture satisfied every guard, derived no controls, and
// exited 0 with "nothing to file" — a false all-clear reached by a typo.
func TestCVEDocumentPassedToPostureIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cve.json")
	writeBare(t, path, cveDoc("app", "api", map[string]int{"critical": 18}))

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("a CVE document passed to -posture must be rejected")
	}

	if !errors.Is(err, errSurfaceMismatch) {
		t.Errorf("want errSurfaceMismatch, got %v", err)
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for a swapped file, got %q", out.String())
	}
}

func TestPostureDocumentPassedToCVEIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeBare(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("a posture document passed to -cve must be rejected")
	}

	if !errors.Is(err, errSurfaceMismatch) {
		t.Errorf("want errSurfaceMismatch, got %v", err)
	}
}

// A cluster-wide run produces one per-object GET per workload, so the surface
// flags must be repeatable. A single-valued flag made the promised cluster-wide
// grouping unreachable: the second -posture silently replaced the first.
func TestSurfaceFlagsAreRepeatableAndAllInputsAreRead(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeBare(t, a, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))
	writeBare(t, b, postureDoc("data", "StatefulSet", "db", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", a, "-posture", b}, &out); err != nil {
		t.Fatalf("repeated -posture must be accepted, got %v", err)
	}

	for _, want := range []string{"app/Deployment/api", "data/StatefulSet/db"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("every repeated input must be read; %q missing from %q", want, out.String())
		}
	}

	if themeLines(out.String()) != 1 {
		t.Errorf("both workloads failing one control must group into ONE theme, got %q", out.String())
	}
}

func TestRepeatedCVEFlagsAreAllRead(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeBare(t, a, cveDoc("app", "api", map[string]int{"critical": 2}))
	writeBare(t, b, cveDoc("data", "db", map[string]int{"critical": 5}))

	var out bytes.Buffer
	if err := run([]string{"-cve", a, "-cve", b}, &out); err != nil {
		t.Fatalf("repeated -cve must be accepted, got %v", err)
	}

	if !strings.Contains(out.String(), "total=7") {
		t.Errorf("want the summed total across both inputs, got %q", out.String())
	}
}

// `items: null` decodes into a nil slice WITHOUT error, so every guard passes
// vacuously and the command reports a clean cluster at exit 0 — the same false
// all-clear as the stripped skeleton, reached by a different shape. An
// explicitly empty list is `items: []`, and only that stays a legitimate pass.
func TestItemsNullIsRejectedNotTreatedAsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "null.json")
	writeRaw(t, path, `{"items":null}`)

	for _, flag := range []string{"-cve", "-posture"} {
		var out bytes.Buffer

		err := run([]string{flag, path}, &out)
		if err == nil {
			t.Fatalf("%s: `items: null` must be rejected, not reported clean", flag)
		}

		if !errors.Is(err, errUnrecognisedDocument) {
			t.Errorf("%s: want errUnrecognisedDocument, got %v", flag, err)
		}

		if strings.Contains(out.String(), "nothing to file") {
			t.Errorf("%s: must not print an all-clear, got %q", flag, out.String())
		}
	}
}

// A bare object whose spec is null carries no payload structure and must not be
// credited either.
func TestSpecNullIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "specnull.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app"},"spec":null}`)

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("`spec: null` must be rejected, not reported clean")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// clusterScopedDoc is the shape a cluster-scoped object really has: the
// workload-namespace label is ABSENT (not empty), while the summary CR itself is
// stored in the scanner's namespace. Measured on the live cluster — all 407
// posture summaries lacking that label were cluster-scoped kinds.
func clusterScopedDoc(kind, name, storedIn string, controls map[string]string) string {
	ids := make([]string, 0, len(controls))
	for id := range controls {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf(
			`%q:{"controlID":%q,"severity":{"severity":"High"},"status":{"status":%q}}`,
			id, id, controls[id]))
	}

	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,`+
		`"labels":{"kubescape.io/workload-kind":%q,"kubescape.io/workload-name":%q}},`+
		`"spec":{"controls":{%s},"severities":{"critical":0}}}`,
		name, storedIn, kind, name, strings.Join(parts, ","))
}

// A cluster-scoped object has no namespace. Taking the summary CR's own
// metadata.namespace invents one — the scanner's — and a namespace-scoped
// exception then matches it.
func TestClusterScopedComponentHasNoFabricatedNamespace(t *testing.T) {
	it := itemOf(t, clusterScopedDoc("ClusterRoleBinding", "some-binding", "kubescape",
		map[string]string{"C-0016": "failed"}))

	got := it.component()
	if got.Namespace != "" {
		t.Errorf("a cluster-scoped object must have no namespace, got %q", got.Namespace)
	}

	if strings.Contains(got.String(), "kubescape") {
		t.Errorf("the scanner's storage namespace must not appear in the component: %s", got)
	}
}

// The consequence, end to end: a namespace-only ClusterSecurityException must
// NOT suppress a cluster-scoped finding. The live `controller-rbac` policy is
// namespace-only and lists `kubescape`, so fabricating that namespace hid real
// cluster-scoped RBAC findings.
func TestNamespaceOnlyExceptionDoesNotSuppressClusterScopedFindings(t *testing.T) {
	exceptions := loadFixture(t, exceptionsDoc(
		policyDoc("controller-rbac", []string{"C-0016"}, `{"namespace":"^(flux-system|kubescape)$"}`)))

	items := itemsOf(t, clusterScopedDoc("ClusterRoleBinding", "some-binding", "kubescape",
		map[string]string{"C-0016": "failed"}))

	got := mustDerivePosture(t, items, exceptions)
	if len(got) != 1 {
		t.Fatalf("a cluster-scoped finding must survive a namespace-only exception, got %+v", got)
	}

	// Control: the same exception MUST still suppress a genuinely namespaced
	// workload in one of the listed namespaces, or this test would pass simply
	// because exceptions stopped working.
	nsScoped := mustDerivePosture(t, itemsOf(t,
		postureDoc("flux-system", "Deployment", "controller", map[string]string{"C-0016": "failed"}),
	), exceptions)
	if len(nsScoped) != 0 {
		t.Errorf("control: the namespaced workload must still be excepted, got %+v", nsScoped)
	}
}

// A severity count in an unrecognised shape must be an error, not zero: zero
// makes corrupt scanner output indistinguishable from a clean result.
func TestSeverityCountRejectsUnrecognisedShapes(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `{"foo":1}`, `"7"`, `{"all":null}`, `[]`} {
		if got, ok := severityCount(json.RawMessage(raw)); ok {
			t.Errorf("%s must be rejected, got %d ok=true", raw, got)
		}
	}
}

func TestUnrecognisedSeverityShapeFailsTheRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app"},`+
		`"spec":{"severities":{"critical":{"foo":1}},`+
		`"vulnerabilitiesRef":{"all":{"kind":"vulnerabilitymanifests","name":"img","namespace":"app"}}}}`)

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("an unrecognised severity shape must fail the run, not report clean")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// A clean report must say WHICH surfaces it examined. Each surface flag is
// optional, so a bare "no live-only findings" claims a clean bill of health for
// a surface this invocation never looked at.
func TestAllClearNamesOnlyTheExaminedSurfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeBare(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "passed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(out.String(), "posture") {
		t.Errorf("the all-clear must name the examined surface, got %q", out.String())
	}

	if strings.Contains(out.String(), "cve") {
		t.Errorf("must not claim anything about the unexamined cve surface, got %q", out.String())
	}
}

// themeLines counts rendered theme rows, ignoring advisory lines such as the
// unfiltered-report note. The point of the assertion is how many THEMES were
// emitted, which a raw newline count conflates with commentary.
func themeLines(out string) int {
	n := 0

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, "\t"+string(surfacePosture)+"\t") ||
			strings.Contains(line, "\t"+string(surfaceCVE)+"\t") {
			n++
		}
	}

	return n
}

// A posture report derived WITHOUT the declared exceptions includes controls the
// platform has already accepted. That is a legitimate view, but it must announce
// itself so it is not mistaken for a drainable backlog.
func TestUnfilteredPostureReportSaysSo(t *testing.T) {
	dir := t.TempDir()
	posture := filepath.Join(dir, "posture.json")
	writeBare(t, posture, postureDoc("app", "Deployment", "api", map[string]string{"C-0036": "failed"}))

	var without bytes.Buffer
	if err := run([]string{"-posture", posture}, &without); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(without.String(), "-exceptions") {
		t.Errorf("an unfiltered posture report must say the exceptions were not applied, got %q", without.String())
	}

	// Control: supplying exceptions removes the note.
	exceptions := filepath.Join(dir, "exceptions.json")
	writeRaw(t, exceptions, exceptionsDoc(policyDoc("other", []string{"C-0999"}, `{"kind":".*"}`)))

	var with bytes.Buffer
	if err := run([]string{"-posture", posture, "-exceptions", exceptions}, &with); err != nil {
		t.Fatalf("run with exceptions: %v", err)
	}

	if strings.Contains(with.String(), "were NOT applied") {
		t.Errorf("a filtered report must not carry the note, got %q", with.String())
	}

	if themeLines(with.String()) != 1 {
		t.Errorf("control: the finding itself must still be reported, got %q", with.String())
	}
}

// A CVE-only run carries no posture note — the exceptions artifact is posture-only.
func TestCVEOnlyRunHasNoExceptionsNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cve.json")
	writeBare(t, path, cveDoc("app", "api", map[string]int{"critical": 3}))

	var out bytes.Buffer
	if err := run([]string{"-cve", path}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if strings.Contains(out.String(), "were NOT applied") {
		t.Errorf("a cve-only run must not carry the posture-exceptions note, got %q", out.String())
	}
}

// A control whose status is missing or unrecognised must fail closed. Treating
// "not failed" as "fine" silently absorbs malformed scanner output into a clean
// report — measured live, every real control carries a recognised status.
func TestUnrecognisedControlStatusFailsClosed(t *testing.T) {
	for _, status := range []string{"", "  ", "weird-new-status"} {
		items := itemsOf(t, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": status}))

		_, _, _, err := derivePosture(items, nil)
		if err == nil {
			t.Errorf("status %q must fail closed, got no error", status)
		}
	}
}

// The control: every recognised non-failure status is still silently skipped,
// so the guard above does not simply reject everything.
func TestRecognisedNonFailureStatusesAreSkipped(t *testing.T) {
	for _, status := range []string{"passed", "skipped", "irrelevant", "excluded", "ignored", "PASSED"} {
		items := itemsOf(t, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": status}))

		got, _, _, err := derivePosture(items, nil)
		if err != nil {
			t.Errorf("status %q must be accepted, got %v", status, err)
		}

		if len(got) != 0 {
			t.Errorf("status %q must raise no theme, got %+v", status, got)
		}
	}
}

// A real per-object CVE response always carries its severity buckets, zero-valued
// when clean. An absent map is malformed input, and iterating it zero times would
// report exactly the clean result it is not.
func TestCVEDocumentWithoutSeverityBucketsIsRejected(t *testing.T) {
	for _, spec := range []string{
		`"spec":{"vulnerabilitiesRef":{"all":{"kind":"vulnerabilitymanifests","name":"img","namespace":"app"}}}`,
		`"spec":{"severities":{},"vulnerabilitiesRef":{"all":{"kind":"vulnerabilitymanifests","name":"img","namespace":"app"}}}`,
	} {
		path := filepath.Join(t.TempDir(), "nobuckets.json")
		writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app"},`+spec+`}`)

		var out bytes.Buffer

		err := run([]string{"-cve", path}, &out)
		if err == nil {
			t.Errorf("a CVE document with no severity buckets must be rejected: %s", spec)
		}

		if strings.Contains(out.String(), "nothing to file") {
			t.Errorf("must not print an all-clear, got %q", out.String())
		}
	}
}

// A framework-scoped exception cannot be honoured: the scan summaries carry no
// framework. Applying it anyway would widen a deliberately narrow exception
// across every framework, so it is refused rather than silently widened.
func TestFrameworkScopedExceptionIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.json")
	writeRaw(t, path, `[{"name":"fw","policyType":"postureExceptionPolicy","actions":["disable"],`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":".*"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$","frameworkName":"^nsa$"}]}]`)

	_, err := loadExceptions(path)
	if err == nil {
		t.Fatal("a framework-scoped exception must be refused, not applied across every framework")
	}

	if !errors.Is(err, errBadExceptions) {
		t.Errorf("want errBadExceptions, got %v", err)
	}
}

// The control: an unscoped policy — the shape every current CSE uses — still loads.
func TestUnscopedExceptionStillLoads(t *testing.T) {
	got := loadFixture(t, exceptionsDoc(policyDoc("ok", []string{"C-0016"}, `{"kind":".*"}`)))
	if len(got) != 1 {
		t.Fatalf("an unscoped policy must still load, got %d", len(got))
	}
}

// The clean report must not claim anything about the cluster — this command has
// no inventory, so it can only speak for the objects it was handed.
func TestAllClearDoesNotClaimClusterWideCoverage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeBare(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "passed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", path, "-exceptions", filepath.Join(t.TempDir(), "none")}, &out); err == nil {
		t.Fatal("guard: a missing exceptions file must error, keeping this test honest")
	}

	out.Reset()

	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Key on text unique to the all-clear line. Asserting on "supplied" alone
	// was VACUOUS: the unfiltered-exceptions note also contains that word, so
	// the assertion passed through unrelated output (caught by ablation).
	if !strings.Contains(out.String(), "only the objects passed on the command line") {
		t.Errorf("the all-clear must scope itself to the supplied inputs, got %q", out.String())
	}

	if strings.Contains(out.String(), "surface(s) — nothing to file") {
		t.Errorf("the all-clear must not claim whole-surface coverage, got %q", out.String())
	}
}

// A real namespace may legitimately be called "cluster", so the cluster-scope
// marker must not be a bare word a namespace could equal — otherwise two
// distinct components render identically.
func TestNamespaceNamedClusterDoesNotCollideWithClusterScope(t *testing.T) {
	namespaced := component{Namespace: "cluster", Kind: "Deployment", Name: "api"}
	clusterScoped := component{Kind: "Deployment", Name: "api"}

	if namespaced.String() == clusterScoped.String() {
		t.Errorf("a namespace called %q must not render as cluster scope: both are %q",
			"cluster", namespaced.String())
	}
}

// A negative severity count is not a finding count, it is malformed input.
func TestNegativeSeverityCountIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "neg.json")
	// Every required bucket must be present, or missingSeverityBuckets rejects the
	// document first and the negative-count guard is never reached — the test would
	// then pass with that guard deleted.
	writeBare(t, path, cveDoc("app", "api", map[string]int{"critical": -3}))

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("a negative severity count must be rejected")
	}

	if !strings.Contains(err.Error(), "cannot be negative") {
		t.Errorf("want the negative-count error, got %v", err)
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// A response retaining one bucket while truncating another passes a mere
// length check, and the omitted bucket's findings are never seen.
func TestPartialSeverityBucketSetIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.json")
	writeRaw(t, path, fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",%s},`+
		`"spec":{"severities":{"low":{"all":0}},`+
		`"vulnerabilitiesRef":{"all":{"kind":"vulnerabilitymanifests","name":"img","namespace":"app"}}}}`,
		labels("app", "Deployment", "api")))

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("a truncated severity bucket set must be rejected")
	}

	if !strings.Contains(err.Error(), "critical") {
		t.Errorf("the error should name a missing bucket, got %v", err)
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// Go stops flag parsing at the first non-flag argument, so a second path
// written without repeating its flag silently drops that path AND every flag
// after it — reproduced on live data, where the whole -cve input vanished and
// the command still exited 0.
func TestLeftoverPositionalArgumentIsRejected(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeBare(t, a, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))
	writeBare(t, b, postureDoc("data", "StatefulSet", "db", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer

	err := run([]string{"-posture", a, b}, &out)
	if err == nil {
		t.Fatal("a leftover positional argument must be rejected, not silently ignored")
	}

	if !strings.Contains(err.Error(), "b.json") {
		t.Errorf("the error should name the ignored argument, got %v", err)
	}

	// Control: the correct form is accepted and reads both inputs.
	out.Reset()

	if err := run([]string{"-posture", a, "-posture", b}, &out); err != nil {
		t.Fatalf("control: the repeated-flag form must work, got %v", err)
	}

	if themeLines(out.String()) != 1 {
		t.Errorf("control: both inputs must be read and grouped, got %q", out.String())
	}
}

// A control keyed as one ID while embedding another makes exception matching
// ambiguous: a failed C-9999 carrying controlID C-0036 would be suppressed by
// a declared C-0036 exception.
func TestControlIDMismatchIsRejected(t *testing.T) {
	doc := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-namespace":"app","kubescape.io/workload-kind":"Deployment",` +
		`"kubescape.io/workload-name":"api"}},` +
		`"spec":{"controls":{"C-9999":{"controlID":"C-0036","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0}}}`

	_, _, _, err := derivePosture(itemsOf(t, doc), nil)
	if err == nil {
		t.Fatal("a key/controlID mismatch must be rejected")
	}
}

// The control: an EMPTY embedded ID still falls back to the map key, which is
// the pre-existing behaviour the guard must not break.
func TestEmptyEmbeddedControlIDFallsBackToTheKey(t *testing.T) {
	doc := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-namespace":"app","kubescape.io/workload-kind":"Deployment",` +
		`"kubescape.io/workload-name":"api"}},` +
		`"spec":{"controls":{"C-0016":{"controlID":"","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0}}}`

	got, _, _, err := derivePosture(itemsOf(t, doc), nil)
	if err != nil {
		t.Fatalf("an empty embedded controlID must still fall back, got %v", err)
	}

	if len(got) != 1 || got[0].Key != "C-0016" {
		t.Errorf("want the map key C-0016, got %+v", got)
	}
}

// Equal ranks still need a deterministic winner, or identical findings render
// differently depending on input order.
func TestEqualSeverityRanksAreOrderIndependent(t *testing.T) {
	upper := postureDocSev("app", "Deployment", "a", map[string]string{"C-0016": "failed"}, "HIGH")
	title := postureDocSev("app", "Deployment", "b", map[string]string{"C-0016": "failed"}, "High")

	forward := mustDerivePosture(t, itemsOf(t, upper, title), nil)
	reverse := mustDerivePosture(t, itemsOf(t, title, upper), nil)

	if forward[0].Severity != reverse[0].Severity {
		t.Errorf("equal-ranked severities must not depend on input order: %q vs %q",
			forward[0].Severity, reverse[0].Severity)
	}
}

// A summary with no workload kind must be refused BEFORE exceptions are
// applied: a generated cluster-wide designator uses `kind: ".*"`, which
// full-matches the empty string, so the finding would be suppressed against an
// identity that was never established.
func TestPostureSummaryWithoutWorkloadIdentityIsRejected(t *testing.T) {
	raw := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-name":"api","kubescape.io/workload-namespace":"app"}},` +
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0}}}`

	items := itemsOf(t, raw)

	if _, _, _, err := derivePosture(items, nil); !errors.Is(err, errMalformedScanContent) {
		t.Fatalf("want errMalformedScanContent for a summary with no workload kind, got %v", err)
	}
}

// WHITESPACE is the same hole as an empty value, one step over: an `== ""`
// identity check accepts `" "`, and the generated cluster-wide `kind: ".*"`
// designator then matches it — so a failed control is suppressed by a broad
// exception against an identity that was never established, and the run exits
// successfully with nothing to file. That is the false all-clear this command
// exists to prevent, so the check trims before deciding.
func TestWhitespaceOnlyWorkloadIdentityIsRejected(t *testing.T) {
	for _, tc := range []struct{ name, kind, workload string }{
		{"blank kind", " ", "api"},
		{"blank name", "Deployment", "  "},
		{"tab kind", "\t", "api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",`+
				`"labels":{"kubescape.io/workload-kind":%q,"kubescape.io/workload-name":%q,`+
				`"kubescape.io/workload-namespace":"app"}},`+
				`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
				`"status":{"status":"failed"}}},"severities":{"critical":0,"high":1}}}`,
				tc.kind, tc.workload)

			items := itemsOf(t, raw)

			if _, _, _, err := derivePosture(items, nil); !errors.Is(err, errMalformedScanContent) {
				t.Fatalf("want errMalformedScanContent for a whitespace-only identity, got %v", err)
			}
		})
	}
}

// BOTH derive paths, or the guard covers one of two. deriveCVE consumes the same
// identity and the code says so in its own comment, so a trim applied only to the
// posture path leaves the CVE path emitting a valid-looking theme for an
// unidentified component (`components=app/ /api`) — and several blank identities
// collapse into one another in the component set.
func TestWhitespaceOnlyWorkloadIdentityIsRejectedOnTheCVEPathToo(t *testing.T) {
	for _, tc := range []struct{ name, kind, workload string }{
		{"blank kind", " ", "api"},
		{"blank name", "Deployment", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",`+
				`"labels":{"kubescape.io/workload-kind":%q,"kubescape.io/workload-name":%q,`+
				`"kubescape.io/workload-namespace":"app"}},`+
				`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},`+
				`"severities":{"critical":1,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0}}}`,
				tc.kind, tc.workload)

			if _, err := deriveCVE(itemsOf(t, raw)); !errors.Is(err, errMalformedScanContent) {
				t.Fatalf("want errMalformedScanContent on the CVE path, got %v", err)
			}
		})
	}
}

// The harm the check above prevents, asserted end to end rather than argued: a
// whitespace identity plus the generated cluster-wide designator must not
// silently swallow a FAILED control and report a clean run.
func TestWhitespaceIdentityIsNotSuppressedByAClusterWideException(t *testing.T) {
	exceptions := loadFixture(t, exceptionsDoc(
		policyDoc("cluster-wide", []string{"C-0016"}, `{"kind":".*"}`)))

	raw := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-kind":" ","kubescape.io/workload-name":"api",` +
		`"kubescape.io/workload-namespace":"app"}},` +
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":1}}}`

	items := itemsOf(t, raw)

	themes, _, _, err := derivePosture(items, exceptions)
	if err == nil {
		t.Fatalf("a whitespace identity must be refused, not silently excepted; got %d theme(s)", len(themes))
	}

	if !errors.Is(err, errMalformedScanContent) {
		t.Fatalf("want errMalformedScanContent, got %v", err)
	}
}

// A document identifying as BOTH scan surfaces is not decidable. surface()
// returns on the first key it finds, so without this a CVE summary carrying an
// empty `controls: {}` would pass -posture and report an all-clear from the
// empty control map.
func TestDocumentCarryingBothSurfacesIsRejected(t *testing.T) {
	raw := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-kind":"Deployment","kubescape.io/workload-name":"api",` +
		`"kubescape.io/workload-namespace":"app"}},` +
		`"spec":{"controls":{},"vulnerabilitiesRef":{"all":{"name":"manifest-x"}},` +
		`"severities":{"critical":0,"high":0}}}`

	items := itemsOf(t, raw)

	for _, want := range []surface{surfacePosture, surfaceCVE} {
		if err := checkSurface(items, want); !errors.Is(err, errMalformedScanContent) {
			t.Fatalf("want errMalformedScanContent for -%s, got %v", want, err)
		}
	}
}

// A failed control with no severity must not render as `severity=`: that is
// malformed scanner output presented as a valid, prioritisable report.
func TestFailedControlWithoutSeverityIsRejected(t *testing.T) {
	items := itemsOf(t, postureDocSev("app", "Deployment", "api",
		map[string]string{"C-0016": "failed"}, ""))

	if _, _, _, err := derivePosture(items, nil); !errors.Is(err, errMalformedScanContent) {
		t.Fatalf("want errMalformedScanContent for a failed control with no severity, got %v", err)
	}
}

// An unknown but NONEMPTY severity stays tolerated, so a future severity name
// does not become a hard failure.
func TestFailedControlWithUnknownSeverityIsAccepted(t *testing.T) {
	items := itemsOf(t, postureDocSev("app", "Deployment", "api",
		map[string]string{"C-0016": "failed"}, "Catastrophic"))

	if got := mustDerivePosture(t, items, nil); len(got) != 1 {
		t.Fatalf("want the control reported, got %+v", got)
	}
}

// A document that PARSED as a Kubescape object but whose content is unusable
// must not be reported under errUnrecognisedDocument. That sentinel says the
// input is "neither a kubectl list nor a Kubescape object", which sends an
// operator to inspect the file's shape — when the file's shape is fine and the
// problem is a missing label, a blank severity, or a bad count. The code
// already states this rule: errDuplicateObject exists as its own sentinel for
// exactly this reason. These guards were added under the wrong one.
//
// The discriminator is structural: a message that can name the COMPONENT has
// necessarily decoded the object, so it is content that is wrong, not shape.
func TestWellFormedDocumentWithUnusableContentIsNotReportedAsUnrecognised(t *testing.T) {
	noKind := `{"metadata":{"name":"api","namespace":"app",` +
		`"labels":{"kubescape.io/workload-namespace":"app","kubescape.io/workload-name":"api"}},` +
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":1}}}`

	bothSurfaces := fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",%s},`+
		`"spec":{"controls":{},"vulnerabilitiesRef":{"all":{"name":"m"}},`+
		`"severities":{"critical":0,"high":0}}}`, labels("app", "Deployment", "api"))

	neitherSurface := fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",%s},`+
		`"spec":{"severities":{"critical":0,"high":0}}}`, labels("app", "Deployment", "api"))

	cases := []struct {
		name string
		flag string
		doc  string
	}{
		{"missing workload identity", "-posture", noKind},
		{"carries both surface keys", "-posture", bothSurfaces},
		{"carries neither surface key", "-posture", neitherSurface},
		{"blank severity", "-posture", postureDocSev(
			"app", "Deployment", "api", map[string]string{"C-0016": "failed"}, "")},
		{"unrecognised control status", "-posture", postureDoc(
			"app", "Deployment", "api", map[string]string{"C-0016": "banana"})},
		{"missing severity buckets", "-cve", fmt.Sprintf(
			`{"metadata":{"name":"api","namespace":"app",%s},`+
				`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},`+
				`"severities":{"critical":{"all":1}}}}`, labels("app", "Deployment", "api"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "doc.json")
			writeRaw(t, path, tc.doc)

			var out bytes.Buffer

			err := run([]string{tc.flag, path}, &out)
			if err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}

			if !errors.Is(err, errMalformedScanContent) {
				t.Errorf("want errMalformedScanContent, got %v", err)
			}

			if errors.Is(err, errUnrecognisedDocument) {
				t.Errorf("a parsed document must not be reported as unrecognised: %v", err)
			}
		})
	}
}

// A document carrying BOTH `items` and a single-object `spec` is malformed, and
// the items branch returned first without ever looking at spec. An empty or
// partial `items` alongside a real `spec` therefore reported a clean cluster —
// the same false all-clear as `items: null`, reached by a different shape.
func TestDocumentCarryingBothItemsAndSpecIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "both.json")
	writeRaw(t, path, fmt.Sprintf(`{"items":[],"spec":{"controls":{"C-0016":`+
		`{"controlID":"C-0016","severity":{"severity":"High"},"status":{"status":"failed"}}},`+
		`"severities":{"critical":0,"high":1}},"metadata":{"name":"api","namespace":"app",%s}}`,
		labels("app", "Deployment", "api")))

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("a document carrying both `items` and `spec` must be rejected")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear, got %q", out.String())
	}
}

// The posture path rejects a summary with no workload kind/name, because a
// cluster-wide exception designator matches an empty value. The CVE path read
// the same identity and did not check it, so the guard covered one of two
// paths — and CVE entries could render against an identity never established.
func TestCVESummaryWithoutWorkloadIdentityIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cve.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		`"labels":{"kubescape.io/workload-namespace":"app"}},`+
		`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},"severities":{"critical":{"all":3},`+
		`"high":{"all":0},"medium":{"all":0},"low":{"all":0},"negligible":{"all":0},`+
		`"unknown":{"all":0}}}}`)

	var out bytes.Buffer

	err := run([]string{"-cve", path}, &out)
	if err == nil {
		t.Fatal("a CVE summary with no workload identity must be rejected")
	}

	if !errors.Is(err, errMalformedScanContent) {
		t.Errorf("want errMalformedScanContent, got %v", err)
	}
}

// With both the control map key and the embedded controlID empty, the fallback
// left the key empty and the tool emitted "security(posture):  fails" with a
// stable fingerprint for a blank control — a backlog entry naming nothing.
func TestFailedControlWithEmptyIdentifierIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank.json")
	writeRaw(t, path, fmt.Sprintf(`{"metadata":{"name":"api","namespace":"app",%s},`+
		`"spec":{"controls":{"":{"controlID":"","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":1}}}`,
		labels("app", "Deployment", "api")))

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatalf("a failed control with an empty identifier must be rejected, got: %s", out.String())
	}

	if !errors.Is(err, errMalformedScanContent) {
		t.Errorf("want errMalformedScanContent, got %v", err)
	}
}

// An unknown policyType was silently skipped, so a stale or schema-changed
// exceptions artifact quietly narrowed what counts as accepted. The generator
// emits exactly one type, so anything else means the artifact and this reader
// disagree — which must be loud, not silently dropped.
func TestUnknownExceptionPolicyTypeIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.json")
	writeRaw(t, path, `[{"name":"x","policyType":"postureExceptionPolicyV2",`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":"^Deployment$"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$"}],"reason":"stale artifact"}]`)

	if _, err := loadExceptions(path); err == nil {
		t.Fatal("an unknown policyType must be rejected, not silently discarded")
	}
}

// The workload NAME must come only from the label, exactly as the namespace
// already does. Falling back to the summary CR's own metadata.name fabricates
// an identity: the CR is the scanner's object, not the workload, so the
// substituted value is a different thing that merely looks populated.
//
// That fabrication defeats the identity guards on BOTH derivation paths, since
// each inspects the assembled component — a summary that lost its label passes
// as identified, and a broad generated designator such as `kind: ".*"` can then
// suppress its finding against an identity never established.
//
// Measured over the live cluster: 2215/2215 posture summaries and 117/117 CVE
// summaries carry the label, and in EVERY one of those 2332 the label differs
// from metadata.name. So the fallback never fired legitimately, and wherever it
// would fire it could only substitute a wrong name.
func TestMissingWorkloadNameLabelIsRejectedNotSubstituted(t *testing.T) {
	// metadata.name is present and plausible; only the label is gone.
	doc := `{"metadata":{"name":"scan-summary-abc123","namespace":"kubescape",` +
		`"labels":{"kubescape.io/workload-namespace":"app","kubescape.io/workload-kind":"Deployment"}},` +
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},` +
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0}}}`

	_, _, _, err := derivePosture(itemsOf(t, doc), nil)
	if err == nil {
		t.Fatal("a summary with no workload-name label must be rejected, not renamed to the CR's own name")
	}

	if !errors.Is(err, errMalformedScanContent) {
		t.Errorf("want errMalformedScanContent, got %v", err)
	}

	if strings.Contains(err.Error(), "scan-summary-abc123") {
		t.Errorf("the CR's own name must not be presented as the workload identity: %v", err)
	}
}

// The same guarantee on the CVE path, which reads the same two labels.
func TestMissingWorkloadNameLabelIsRejectedOnCVEPath(t *testing.T) {
	doc := `{"metadata":{"name":"vuln-summary-def456","namespace":"kubescape",` +
		`"labels":{"kubescape.io/workload-namespace":"app","kubescape.io/workload-kind":"Deployment"}},` +
		`"spec":{"vulnerabilitiesRef":{"name":"m"},"severities":{"critical":{"all":1},"high":{"all":0},` +
		`"low":{"all":0},"medium":{"all":0},"negligible":{"all":0},"unknown":{"all":0}}}}`

	if _, err := deriveCVE(itemsOf(t, doc)); err == nil {
		t.Fatal("a CVE summary with no workload-name label must be rejected")
	}
}

// The over-tightening control: a summary that DOES carry the label still
// derives normally, so the guard above cannot be satisfied by refusing
// everything.
func TestLabelledSummaryStillDerives(t *testing.T) {
	items := itemsOf(t, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	got := mustDerivePosture(t, items, nil)
	if len(got) != 1 {
		t.Fatalf("a correctly labelled summary must still derive, got %+v", got)
	}

	if got[0].Components[0] != "app/Deployment/api" {
		t.Errorf("want the LABEL's workload name, got %v", got[0].Components)
	}
}

// An all-clear produced by FILTERING must not read like an all-clear produced
// by a clean input. When every failed control is accepted by a declared
// exception, "no live-only findings in the supplied posture input(s)" is
// literally false about the input: the findings were there and were excepted.
//
// This is the command's own core thesis turned inward. It exists because a
// broken scanner and a compliant cluster read identically; an exceptions-
// filtered result reading identically to a finding-free one is the same defect
// one layer up, and it is the reading that would let a policy quietly widen
// until it accepted everything without the report ever changing.
func TestFilteredAllClearSaysTheFindingsWereExcepted(t *testing.T) {
	dir := t.TempDir()

	exc := filepath.Join(dir, "exceptions.json")
	writeRaw(t, exc, `[{"name":"accepted","policyType":"postureExceptionPolicy","actions":["disable"],`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":"^Deployment$"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$"}]}]`)

	in := filepath.Join(dir, "posture.json")
	writeBare(t, in, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-exceptions", exc, "-posture", in}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "nothing to file") {
		t.Errorf("must still say nothing to file, got %q", got)
	}

	if !strings.Contains(got, "except") {
		t.Errorf("a filtered all-clear must say the findings were excepted, got %q", got)
	}
}

// The control: a genuinely finding-free input must NOT claim anything was
// excepted, or the new wording would be just as undiscriminating in the other
// direction.
func TestGenuineAllClearDoesNotClaimExceptions(t *testing.T) {
	dir := t.TempDir()

	in := filepath.Join(dir, "posture.json")
	writeBare(t, in, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "passed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", in}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if strings.Contains(out.String(), "excepted by") {
		t.Errorf("a genuinely clean input must not claim exceptions were applied, got %q", out.String())
	}
}

// The all-clear branch states its provenance, but the MIXED case — some
// findings excepted, some surviving — is the one that actually occurs, and it
// rendered the survivors with no indication that anything had been filtered.
//
// That is this command's own thesis turned inward, exactly as the all-clear
// case was: a heavily-filtered report and a lightly-filtered one are
// byte-indistinguishable, so an exception policy can widen until it accepts
// almost everything and the output never says so. Fixing only the empty branch
// fixed the rarer half.
func TestMixedFilteredReportDisclosesSuppression(t *testing.T) {
	dir := t.TempDir()

	exc := filepath.Join(dir, "exceptions.json")
	writeRaw(t, exc, `[{"name":"accepted","policyType":"postureExceptionPolicy","actions":["disable"],`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":"^Deployment$"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$"}]}]`)

	in := filepath.Join(dir, "posture.json")
	writeBare(t, in, postureDoc("app", "Deployment", "api",
		map[string]string{"C-0016": "failed", "C-0017": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-exceptions", exc, "-posture", in}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()

	// The surviving theme must still be reported — the note is additional
	// provenance, never a replacement for the work list.
	if !strings.Contains(got, "C-0017") {
		t.Errorf("the unexcepted finding must still be reported, got %q", got)
	}

	if !strings.Contains(got, "except") {
		t.Errorf("a partially filtered report must disclose that findings were excepted, got %q", got)
	}
}

// The control, and it is the same one the all-clear branch needed: the
// disclosure must key on findings ACTUALLY suppressed, not on -exceptions
// having been supplied. A run whose declared exceptions match nothing has
// filtered nothing, and claiming otherwise is undiscriminating in the opposite
// direction.
func TestFilteredReportThatSuppressedNothingMakesNoSuppressionClaim(t *testing.T) {
	dir := t.TempDir()

	exc := filepath.Join(dir, "exceptions.json")
	writeRaw(t, exc, `[{"name":"accepted","policyType":"postureExceptionPolicy","actions":["disable"],`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":"^Deployment$"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$"}]}]`)

	in := filepath.Join(dir, "posture.json")
	writeBare(t, in, postureDoc("app", "Deployment", "api", map[string]string{"C-0017": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-exceptions", exc, "-posture", in}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "C-0017") {
		t.Fatalf("the unexcepted finding must still be reported, got %q", got)
	}

	if strings.Contains(got, "except") {
		t.Errorf("nothing was suppressed, so the report must make no exception claim, got %q", got)
	}
}

// Exceptions are evaluated by derivePosture ONLY — deriveCVE never sees them.
// So a run carrying both surfaces, with a posture control suppressed and a CVE
// theme surviving, must not describe every entry below as the unexcepted
// remainder: the CVE entries were never checked against exception policy at
// all, and saying otherwise credits them with a filtering that did not happen.
//
// This is the same misleading-shared-sentinel class already fixed twice on this
// branch: one message written for one caller, then applied to a set that
// includes another.
func TestSuppressionNoteDoesNotClaimCVEEntriesWereFiltered(t *testing.T) {
	dir := t.TempDir()

	exc := filepath.Join(dir, "exceptions.json")
	writeRaw(t, exc, `[{"name":"accepted","policyType":"postureExceptionPolicy","actions":["disable"],`+
		`"resources":[{"designatorType":"Attributes","attributes":{"kind":"^Deployment$"}}],`+
		`"posturePolicies":[{"controlID":"^C-0016$"}]}]`)

	post := filepath.Join(dir, "posture.json")
	writeBare(t, post, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	cve := filepath.Join(dir, "cve.json")
	writeBare(t, cve, cveDoc("app", "api", map[string]int{
		"critical": 1, "high": 0, "low": 0, "medium": 0, "negligible": 0, "unknown": 0,
	}))

	var out bytes.Buffer
	if err := run([]string{"-exceptions", exc, "-posture", post, "-cve", cve}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "cve") {
		t.Fatalf("the CVE theme must still be reported, got %q", got)
	}

	// The disclosure must scope itself to posture rather than to "the entries
	// below", which would include CVE themes exceptions never touched.
	//
	// Assert the text report actually emits. An earlier form asserted the ABSENCE
	// of an upper-case "the entries below are the UNEXCEPTED remainder" that no
	// code path produces, so it could not fail whatever the scoping did; and a
	// bare Contains(got, "posture") is satisfied by the posture theme line alone.
	if !strings.Contains(got, "the posture entries below are the unexcepted remainder") {
		t.Errorf("the note must scope its claim to the posture surface, got %q", got)
	}

	// With a CVE surface examined, the note must say outright that CVE entries
	// were not filtered, rather than leave the reader assuming symmetry.
	if !strings.Contains(got, "(CVE entries are not filtered by exception policy)") {
		t.Errorf("the note must carry the CVE caveat when a CVE surface is present, got %q", got)
	}
}

// The unfiltered-posture note tells the reader the list below includes controls
// the platform has already accepted. When the posture input is CLEAN there is
// no such list, so the note contradicts the all-clear printed immediately after
// it — and it does the same when the only themes are CVE ones, which the note
// does not describe.
func TestUnfilteredNoteIsNotPrintedWhenNoPostureThemeFollows(t *testing.T) {
	dir := t.TempDir()

	in := filepath.Join(dir, "posture.json")
	writeBare(t, in, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "passed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", in}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "included below") {
		t.Errorf("nothing is included below a clean posture input, got %q", got)
	}

	if !strings.Contains(got, "nothing to file") {
		t.Errorf("the all-clear must still be printed, got %q", got)
	}
}

// The six required buckets can all be present while an EXTRA key is blank.
// Extra buckets are tolerated on purpose (an upstream addition must not break
// the run), so the completeness check passes and a blank class with a positive
// count became a theme titled `security(cve): -severity findings` — carrying a
// stable fingerprint, so it would be filed and then kept up to date forever.
func TestBlankCVESeverityClassIsRejected(t *testing.T) {
	doc := `{"metadata":{"name":"api","namespace":"app",` + labels("app", "Deployment", "api") + `},` +
		`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},"severities":{` +
		`"critical":0,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0,"   ":3}}}`

	if _, err := deriveCVE(itemsOf(t, doc)); err == nil {
		t.Fatal("a blank severity class name must be rejected")
	}
}

// Each per-bucket count is validated nonnegative, but the AGGREGATE is not:
// summing two valid counts past MaxInt wraps to a negative total, which then
// renders as a nonsensical `total=-N` on a successful exit. The per-bucket
// guard cannot see this because it fires before any addition.
func TestCVETotalOverflowIsRejected(t *testing.T) {
	huge := fmt.Sprintf("%d", math.MaxInt)

	docs := make([]string, 0, 2)
	for _, name := range []string{"api", "web"} {
		docs = append(docs, `{"metadata":{"name":"`+name+`","namespace":"app",`+
			labels("app", "Deployment", name)+`},`+
			`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},"severities":{`+
			`"critical":`+huge+`,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0}}}`)
	}

	if _, err := deriveCVE(itemsOf(t, docs...)); err == nil {
		t.Fatal("an aggregate that overflows must be rejected, not wrapped to a negative total")
	}
}

// The control: ordinary counts must still aggregate.
func TestOrdinaryCVETotalsStillAggregate(t *testing.T) {
	docs := []string{
		`{"metadata":{"name":"api","namespace":"app",` + labels("app", "Deployment", "api") + `},` +
			`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},"severities":{"critical":18,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0}}}`,
		`{"metadata":{"name":"web","namespace":"app",` + labels("app", "Deployment", "web") + `},` +
			`"spec":{"vulnerabilitiesRef":{"all":{"name":"m"}},"severities":{"critical":4,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0}}}`,
	}

	got, err := deriveCVE(itemsOf(t, docs...))
	if err != nil {
		t.Fatalf("deriveCVE: %v", err)
	}

	if len(got) != 1 || got[0].Total != 22 {
		t.Fatalf("want one theme totalling 22, got %+v", got)
	}
}

// The duplicate-key ambiguity is not confined to the exceptions artifact: a
// SCAN document repeating `spec.controls` decodes to the last value, so a real
// failed-control map followed by `"controls":{}` exits 0 with "no live-only
// findings". That is a false all-clear produced by a corrupted or hand-packaged
// document, which is the exact class this command exists to refuse.
func TestDuplicateKeysInScanInputAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		labels("app", "Deployment", "api")+`},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0},"controls":{}}}`)

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("a scan document repeating spec.controls is ambiguous and must be rejected")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for an ambiguous document, got %q", out.String())
	}
}

// Case folding is how encoding/json binds STRUCT FIELDS, and it is not how it
// decodes MAPS: `{"team":"a","Team":"b"}` unmarshals into a map[string]string
// with BOTH keys, so there is no ambiguity and nothing to refuse.
//
// A scan document is full of user-controlled maps — labels and annotations,
// and the `f:`-prefixed mirrors of them inside managedFields — so folding every
// object in it rejects ordinary Kubernetes objects outright. Measured on the
// live cluster: a real posture summary reports 10 themes, and the same document
// with one extra `Team` label alongside `team` aborts the whole run.
//
// The exceptions artifact keeps folded detection (see the exceptions tests):
// it is our own generated file, its aliasable keys are struct fields, and that
// is where the Unicode alias case was found.
func TestScanDocumentAcceptsCaseDistinctMapKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app","labels":{`+
		`"kubescape.io/workload-kind":"Deployment","kubescape.io/workload-name":"api",`+
		`"kubescape.io/workload-namespace":"app","team":"a","Team":"b"}},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},`+
		`"severities":{"critical":0,"high":0,"low":0,"medium":0,"negligible":0,"unknown":0}}}`)

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("case-distinct map keys are legitimate and must not be rejected: %v", err)
	}

	if !strings.Contains(out.String(), "C-0016") {
		t.Errorf("the document must still be processed, got %q", out.String())
	}
}

// The other half of the same rule, and the reason folding cannot simply be
// turned off for scan documents: `spec.controls` binds to a STRUCT FIELD, so a
// failed control map followed by `"Controls":{}` decodes to the empty map and
// exits 0 with "no live-only findings".
//
// Reproduced on a real cluster document carrying 9 failed controls: adding that
// one aliased key turned it into a clean all-clear. A case variant is
// legitimate in `metadata.labels` and fatal here, which is why the walker keys
// on what each object decodes into rather than on the document or the caller.
func TestScanDocumentRejectsCaseAliasedStructField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		labels("app", "Deployment", "api")+`},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0},"Controls":{}}}`)

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("a case-aliased spec.controls is ambiguous and must be rejected")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for an aliased document, got %q", out.String())
	}
}

// One level deeper, and the reason the scope reverts inside a map: the KEYS of
// `spec.controls` are control IDs and must be compared exactly, but each of its
// VALUES is a control struct again. An aliased `Status` there overwrites the
// failed status and drops the finding — the same hiding this refuses at the
// `controls` level, one layer down.
//
// Without this the revert is unpinned: removing it reddens nothing, which is
// how the gap was found.
func TestScanDocumentRejectsCaseAliasWithinAControl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		labels("app", "Deployment", "api")+`},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"},"Status":{"status":"passed"}}},`+
		`"severities":{"critical":0,"high":0}}}`)

	var out bytes.Buffer

	err := run([]string{"-posture", path}, &out)
	if err == nil {
		t.Fatal("a case-aliased status inside a control is ambiguous and must be rejected")
	}

	if strings.Contains(out.String(), "nothing to file") {
		t.Errorf("must not print an all-clear for an aliased control, got %q", out.String())
	}
}

// The control for the pair above: two DISTINCT control IDs differing only by
// case are map keys, not struct fields, so they stay legitimate.
func TestScanDocumentAcceptsCaseDistinctControlIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		labels("app", "Deployment", "api")+`},`+
		`"spec":{"controls":{"c-0016":{"controlID":"c-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}},`+
		`"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},`+
		`"severities":{"critical":0,"high":0}}}`)

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("case-distinct control IDs are map keys and must be accepted: %v", err)
	}
}

// The scope of a value has to be resolved the way the DECODER binds it, not by
// exact key match: `"Status"` binds to the `Status` field just as `"status"`
// does. Matching the child key exactly dropped an aliased parent to
// scopeOpaque, so folded collisions BELOW it stopped being checked.
//
// The pair below differs only in the parent's case, and that alone decided
// whether a nested alias overwriting `failed` with `passed` was caught: the
// canonical spelling rejected the document, the aliased spelling exited 0 with
// "nothing to file".
func TestScanDocumentRejectsNestedAliasUnderAnAliasedParent(t *testing.T) {
	for _, parent := range []string{"status", "Status", "STATUS"} {
		t.Run(parent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "posture.json")
			writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
				labels("app", "Deployment", "api")+`},`+
				`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
				`"`+parent+`":{"status":"failed","Status":"passed"}}},`+
				`"severities":{"critical":0,"high":0}}}`)

			var out bytes.Buffer

			err := run([]string{"-posture", path}, &out)
			if err == nil {
				t.Fatalf("a nested alias under a %q parent must be rejected", parent)
			}

			if strings.Contains(out.String(), "nothing to file") {
				t.Errorf("must not print an all-clear, got %q", out.String())
			}
		})
	}
}

// The control: case-insensitive resolution must not reach into MAP keys. A
// label spelled `Spec` or `Metadata` is a map entry, not a struct field, so it
// must not acquire a struct scope and start folding its contents.
func TestCaseInsensitiveScopeDoesNotReachIntoMapKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app","labels":{`+
		`"kubescape.io/workload-kind":"Deployment","kubescape.io/workload-name":"api",`+
		`"kubescape.io/workload-namespace":"app","Spec":"a","spec":"b"}},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0}}}`)

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("case-distinct label keys stay legitimate: %v", err)
	}

	if !strings.Contains(out.String(), "C-0016") {
		t.Errorf("the document must still be processed, got %q", out.String())
	}
}

// Case-insensitive resolution must not escape into a subtree this command does
// not decode. `annotations` is a map and is never read, so an object sitting
// under it — whatever its keys happen to be named — must stay exact-only; a
// key called `spec` there is an annotation name, not the spec field.
//
// This pins the property the walker's default rests on: unrecognised fields
// cannot acquire struct semantics, so an upstream addition cannot start
// producing false rejections. Without it, letting a map parent fall through to
// the key switch reddens nothing today, because no map in the current shapes
// holds object values — the guarantee is real but was untested.
func TestUndecodedSubtreeNeverAcquiresStructScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeRaw(t, path, `{"metadata":{"name":"api","namespace":"app",`+
		labels("app", "Deployment", "api")+`,`+
		`"annotations":{"spec":{"Status":"a","status":"b"}}},`+
		`"spec":{"controls":{"C-0016":{"controlID":"C-0016","severity":{"severity":"High"},`+
		`"status":{"status":"failed"}}},"severities":{"critical":0,"high":0}}}`)

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("an undecoded subtree must not be folded: %v", err)
	}

	if !strings.Contains(out.String(), "C-0016") {
		t.Errorf("the document must still be processed, got %q", out.String())
	}
}

// The control: an ordinary scan document with no repeated key still parses.
func TestOrdinaryScanInputStillParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.json")
	writeBare(t, path, postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed"}))

	var out bytes.Buffer
	if err := run([]string{"-posture", path}, &out); err != nil {
		t.Fatalf("a well-formed document must still parse: %v", err)
	}

	if !strings.Contains(out.String(), "C-0016") {
		t.Errorf("want the finding reported, got %q", out.String())
	}
}

// TestWriteModeRequiresExceptionsForPosture keeps the two modes' claims
// consistent. Report mode already announces that an unfiltered posture
// derivation is not a drainable backlog; write mode turns that same derivation
// into real GitHub issues, so accepting the flagless invocation would file —
// and reopen — work for every risk the platform has already accepted.
func TestWriteModeRequiresExceptionsForPosture(t *testing.T) {
	dir := t.TempDir()
	posture := filepath.Join(dir, "posture.json")
	writeBare(t, posture, postureDoc("app", "Deployment", "api", map[string]string{"C-0036": "failed"}))

	var out bytes.Buffer

	err := run([]string{"-mode", "write", "-repo", "owner/name", "-posture", posture}, &out)
	if err == nil {
		t.Fatal("a posture write without -exceptions must be refused")
	}

	if !errors.Is(err, errWritesNotEnabled) || !strings.Contains(err.Error(), "-exceptions") {
		t.Errorf("want an errWritesNotEnabled naming -exceptions, got %v", err)
	}

	// CONTROL — the same invocation carrying the flag must get PAST this gate.
	// It is pointed at a path that does not exist so the run stops at the
	// exceptions loader instead of reaching the network: any error is fine so
	// long as it is no longer this one. Without this the assertion above would
	// hold for a build that refuses every write invocation.
	var ctrl bytes.Buffer

	ctrlErr := run([]string{
		"-mode", "write", "-repo", "owner/name", "-posture", posture,
		"-exceptions", filepath.Join(dir, "absent.json"),
	}, &ctrl)

	// Matched with the SAME discriminator the CVE control below uses. The
	// substring "-exceptions requires" reversed the words of the real message
	// ("... requires -exceptions ..."), so it could never match: the control
	// reported success unconditionally and left the assertion above unablated.
	if ctrlErr != nil && errors.Is(ctrlErr, errWritesNotEnabled) &&
		strings.Contains(ctrlErr.Error(), "-exceptions") {
		t.Fatalf("control did not flip: still refused by the same gate, got %v", ctrlErr)
	}

	// CONTROL — a CVE-only write never reaches the posture derivation, so the
	// gate must not fire for it either. This is what scopes the refusal to the
	// surface that actually consumes exceptions.
	//
	// Pointed at an ABSENT path for the same reason as the control above: a
	// loadable CVE document passes validation, and `run` then hands the plan to
	// reconcile with a real ghStore, so the test would shell out to `gh` against
	// the -repo argument. The gate under test fires during validation, strictly
	// before the loader, so stopping there costs the assertion nothing.
	cve := filepath.Join(dir, "absent-cve.json")

	var cveOut bytes.Buffer

	cveErr := run([]string{"-mode", "write", "-repo", "owner/name", "-cve", cve}, &cveOut)
	if cveErr != nil && errors.Is(cveErr, errWritesNotEnabled) &&
		strings.Contains(cveErr.Error(), "-exceptions") {
		t.Errorf("the posture gate fired on a CVE-only write: %v", cveErr)
	}
}

// TestDerivePostureNamesFullySuppressedControls is what lets the write path
// tell an accepted finding from a remediated one. Both are absent from the
// derived themes; only this set says which.
func TestDerivePostureNamesFullySuppressedControls(t *testing.T) {
	// C-0036 is excepted cluster-wide, so nothing survives for it.
	// C-0016 is excepted on Jobs only, so its Deployment occurrence remains and
	// it is NOT accepted — the discriminating half of this test.
	exceptions := loadFixture(t, exceptionsDoc(
		policyDoc("admission", []string{"C-0036"}, `{"kind":".*"}`),
		policyDoc("batch", []string{"C-0016"}, `{"kind":"^Job$"}`)))

	items := itemsOf(t,
		postureDoc("app", "Job", "nightly", map[string]string{"C-0016": "failed", "C-0036": "failed"}),
		postureDoc("app", "Deployment", "api", map[string]string{"C-0016": "failed", "C-0036": "failed"}))

	themes, suppressed, accepted, err := derivePosture(items, exceptions)
	if err != nil {
		t.Fatalf("derivePosture: %v", err)
	}

	if len(accepted) != 1 || accepted[0] != "C-0036" {
		t.Fatalf("want exactly C-0036 accepted, got %v", accepted)
	}

	if len(themes) != 1 || themes[0].Key != "C-0016" {
		t.Fatalf("want C-0016 to survive as a theme, got %+v", themes)
	}

	if suppressed != 3 {
		t.Errorf("want 3 suppressed (control,component) pairs, got %d", suppressed)
	}
}

// A Node is the one kind whose NAME is itself the reachability evidence that
// doc.go, renderBody and the component type all promise is withheld from these
// public issues. For every other kind the name is a workload identity; for a
// Node, `kubescape.io/workload-name` IS the hostname.
//
// TestComponentCarriesOnlyTheSanitizedMinimum already greps a rendered
// component for "prod-worker", but it builds a *Deployment*, where a node name
// could never have appeared — so it pinned the shape of the guarantee without
// being able to fail on the path that actually breaks it. This exercises that
// path.
func TestNodeIdentityIsPseudonymizedInPublicComponents(t *testing.T) {
	const nodeName = "worker-7.example.invalid"

	it := itemOf(t, clusterScopedDoc("Node", nodeName, "kubescape",
		map[string]string{"C-0016": "failed"}))

	got := it.component().String()

	if strings.Contains(got, nodeName) {
		t.Fatalf("node hostname reached a public component: %s", got)
	}

	// A partial leak is still a leak: the domain alone maps a cluster.
	for _, fragment := range []string{"worker-7", "example", "invalid"} {
		if strings.Contains(got, fragment) {
			t.Errorf("component leaked node-name fragment %q: %s", fragment, got)
		}
	}

	// It must still SAY it is a Node, and still be recognisably a pseudonym —
	// redacting to a constant would hide how many nodes are affected.
	if want := "<cluster>/Node/" + nodeIdentityPrefix; !strings.HasPrefix(got, want) {
		t.Errorf("want a pseudonymized node component starting %q, got %s", want, got)
	}
}

// Pseudonymizing must not collapse two nodes into one entry, and must render
// identical bytes across runs or every run rewrites the issue.
func TestPseudonymizedNodesStayDistinctAndStable(t *testing.T) {
	first := component{Kind: "Node", Name: "worker-1.example.invalid"}
	second := component{Kind: "Node", Name: "worker-2.example.invalid"}

	if first.String() == second.String() {
		t.Errorf("two distinct nodes collapsed to one component: %s", first)
	}

	if first.String() != (component{Kind: "Node", Name: "worker-1.example.invalid"}).String() {
		t.Error("the same node must render identical bytes, or every run churns the issue")
	}
}

// The control for the two tests above: pseudonymization is scoped to Node and
// must leave every other kind byte-identical, including a workload whose name
// merely looks host-like.
func TestNonNodeComponentsAreNotPseudonymized(t *testing.T) {
	cases := map[string]component{
		"app/Deployment/api":               {Namespace: "app", Kind: "Deployment", Name: "api"},
		"app/Pod/worker-7.example.invalid": {Namespace: "app", Kind: "Pod", Name: "worker-7.example.invalid"},
		"<cluster>/ClusterRole/some-role":  {Kind: "ClusterRole", Name: "some-role"},
	}

	for want, c := range cases {
		if got := c.String(); got != want {
			t.Errorf("want %q, got %q", want, got)
		}
	}
}

// TestAssembleSortsEveryCollection pins the anti-churn guarantee where it is
// actually provided. Go randomises map iteration, so assemble is the single
// place that turns the accumulator's unordered sets into a canonical order;
// renderBody downstream merely preserves what it is handed.
//
// Without this, nothing asserted the sort at all: TestRenderIsDeterministic
// feeds one already-ordered slice twice, so it stays green against an assemble
// that emitted components in iteration order — and the resulting body would
// differ run to run on identical input, turning every run into an update.
//
// Enough entries that an unsorted map iteration is overwhelmingly unlikely to
// come out ordered by chance, and the check runs over repeated assembles so a
// single lucky ordering cannot pass it.
func TestAssembleSortsEveryCollection(t *testing.T) {
	components := map[string]struct{}{}
	for _, c := range []string{
		"zz/Deployment/web", "aa/StatefulSet/pg", "mm/DaemonSet/log",
		"bb/Deployment/api", "yy/Job/batch", "cc/CronJob/prune",
		"nn/Deployment/edge", "dd/StatefulSet/cache",
	} {
		components[c] = struct{}{}
	}

	for i := range 16 {
		themes := assemble(surfacePosture, map[string]*acc{
			"C-0055": {severity: "High", components: components, total: 3},
			"C-0016": {severity: "High", components: components, total: 1},
			"C-0034": {severity: "Low", components: components, total: 2},
		})

		if !sort.SliceIsSorted(themes, func(a, b int) bool { return themes[a].Key < themes[b].Key }) {
			t.Fatalf("run %d: themes are not ordered by key: %v", i, themes)
		}

		for _, th := range themes {
			if !sort.StringsAreSorted(th.Components) {
				t.Fatalf("run %d: theme %s components are not sorted: %v", i, th.Key, th.Components)
			}
		}
	}
}

// whitespaceMarkerCVEDoc is strippedCVEDoc with the payload marker set to a
// single space rather than empty. Everything else is identical, so the only
// variable is the marker's content.
func whitespaceMarkerCVEDoc(ns, name string) string {
	return fmt.Sprintf(`{"metadata":{"name":%q,"namespace":%q,%s},`+
		`"spec":{"severities":{"critical":{"all":0},"high":{"all":0},"low":{"all":0},`+
		`"medium":{"all":0},"negligible":{"all":0},"unknown":{"all":0}},`+
		`"vulnerabilitiesRef":{"all":{"kind":"","name":" ","namespace":""},`+
		`"relevant":{"kind":"","name":"","namespace":""}}}}`,
		name, ns, labels(ns, "Deployment", name))
}

// A marker containing only whitespace names no manifest, so the document is as
// stripped as one carrying "". Accepting it lets a document that evaluated
// nothing pass as hydrated, and with every severity bucket at zero the run then
// derives no CVE themes at all — which under -inputs-complete is read as "every
// tracked CVE issue is resolved" and closes all of them.
func TestWhitespaceOnlyCVEMarkerFailsClosed(t *testing.T) {
	err := checkExamined(itemsOf(t, whitespaceMarkerCVEDoc("app", "api")))
	if err == nil {
		t.Fatal("a whitespace-only payload marker must fail closed like an empty one")
	}

	if !errors.Is(err, errStrippedList) {
		t.Errorf("want errStrippedList, got %v", err)
	}
}
