// This file applies the platform's declared ClusterSecurityExceptions.
//
// A declared ClusterSecurityException records a control the platform has
// deliberately accepted — runtime-enforced elsewhere (Kyverno mutation, a
// CiliumNetworkPolicy) or irreducible. Queueing one as backlog work recreates
// exactly the noise the exception pipeline exists to remove.
//
// The CRs under k8s/bases/infrastructure/cluster-security-exceptions/ are the
// single source of truth, and scripts/generate-kubescape-exceptions already
// converts them to Kubescape's native format for the CI scan. This command
// consumes THAT artifact rather than re-parsing the CRs, so the two consumers
// cannot drift apart in what they consider accepted.
//
// In that format both the control IDs and the resource attributes are anchored
// REGEXES (`^C-0036$`, `kind: ^Job$`, `kind: .*`), which is why matching here
// compiles them rather than comparing strings.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

// errBadExceptions reports an exceptions document this command cannot apply.
// It is a hard error: silently ignoring a malformed exceptions file would
// re-file accepted controls, and silently WIDENING one would hide real
// findings.
var errBadExceptions = errors.New("cannot read the generated Kubescape exceptions")

// errMalformedJSON stops the duplicate-key walk on a token error.
//
// The walk deliberately does NOT report parse errors itself — Unmarshal gives
// far better context — but it cannot simply return nil either. Returning nil
// without consuming a token leaves dec.More() reporting true forever, so the
// enclosing object and array loops spin: a malformed artifact hung the whole
// command instead of being rejected. This sentinel unwinds the recursion, and
// rejectDuplicateKeys swallows it so Unmarshal still produces the message.
var errMalformedJSON = errors.New("malformed JSON")

// posturePolicyType is the only policy type this command applies. The
// generator emits others for surfaces this bridge does not derive.
const posturePolicyType = "postureExceptionPolicy"

// exceptionActionDisable is the generator's native suppression action.
// alertOnly acknowledges a finding without removing it from actionable results.
const exceptionActionDisable = "disable"

// attributesDesignator is the only resource designator type this command
// implements; the generator emits no other today.
const attributesDesignator = "Attributes"

// exception is one compiled exception policy.
type exception struct {
	name string
	// controls are the anchored control-ID patterns this policy accepts.
	controls []*regexp.Regexp
	// resources are the designators it is scoped to. A policy with no
	// designators matches nothing, so an unscoped-by-accident policy cannot
	// silently suppress the whole cluster.
	resources []designator
}

// designator matches a component's structured fields. Every attribute must
// match for the designator to apply.
type designator map[string]*regexp.Regexp

// matches reports whether this designator covers the component.
//
// An UNKNOWN attribute key never matches. That is deliberate and conservative:
// an attribute this command does not model must not be treated as satisfied,
// because doing so would widen the exception and hide a real finding.
// matchableAttributes is the SINGLE definition of which designator attributes
// this command can match on, mapping each to the component field it reads.
//
// The loader's validation and the matcher both resolve through this map, so
// there is no second list to fall out of step with it: an attribute is
// rejected at load precisely when the matcher could not have honoured it.
var matchableAttributes = map[string]func(component) string{
	"kind":      func(c component) string { return c.Kind },
	"name":      func(c component) string { return c.Name },
	"namespace": func(c component) string { return c.Namespace },
}

// matchableAttributeNames lists the supported keys for error messages, derived
// from the map itself and sorted so the message is deterministic.
func matchableAttributeNames() []string {
	names := make([]string, 0, len(matchableAttributes))
	for key := range matchableAttributes {
		names = append(names, key)
	}

	sort.Strings(names)

	return names
}

func (d designator) matches(c component) bool {
	if len(d) == 0 {
		return false
	}

	for key, re := range d {
		read, ok := matchableAttributes[key]
		if !ok {
			return false
		}

		if !re.MatchString(read(c)) {
			return false
		}
	}

	return true
}

// covers reports whether this policy accepts the given control on the given
// component. Both halves must match: the control ID AND the resource scope.
func (e exception) covers(controlID string, c component) bool {
	matchedControl := false

	for _, re := range e.controls {
		if re.MatchString(controlID) {
			matchedControl = true

			break
		}
	}

	if !matchedControl {
		return false
	}

	for _, d := range e.resources {
		if d.matches(c) {
			return true
		}
	}

	return false
}

// matchingExceptionNames reports every declared policy that accepts this
// finding. The names make the match explainable for oracle mode.
func matchingExceptionNames(exceptions []exception, controlID string, c component) []string {
	var names []string

	for _, e := range exceptions {
		if e.covers(controlID, c) {
			names = append(names, e.name)
		}
	}

	sort.Strings(names)

	return names
}

// excepted reports whether any declared exception accepts this finding.
func excepted(exceptions []exception, controlID string, c component) bool {
	for _, e := range exceptions {
		if e.covers(controlID, c) {
			return true
		}
	}

	return false
}

// rawPolicy mirrors the generator's output shape.
type rawPolicy struct {
	Name       string `json:"name"`
	PolicyType string `json:"policyType"`
	// Actions is what the policy asks Kubescape to DO with a matched control.
	// The generator emits exactly ["disable"]; discarding the field would let
	// an artifact declaring some other action still act as a full suppressor
	// here — see compilePolicy, which requires it rather than assuming it.
	Actions   []string `json:"actions"`
	Resources []struct {
		DesignatorType string            `json:"designatorType"`
		Attributes     map[string]string `json:"attributes"`
	} `json:"resources"`
	PosturePolicies []struct {
		ControlID string `json:"controlID"`
		// FrameworkName scopes an exception to one framework. The generator
		// supports it, so it must be read even though no current policy uses it
		// — see compilePolicy, which refuses rather than silently widening.
		FrameworkName string `json:"frameworkName"`
	} `json:"posturePolicies"`
}

// loadExceptions reads and compiles the generated exceptions document.
//
// An empty path means no exceptions were supplied, which is a legitimate
// configuration — the bridge then reports every failed control. Anything
// present but unreadable, unparseable, or carrying a pattern that does not
// compile is a hard error rather than a silent skip.
func loadExceptions(path string) ([]exception, error) {
	if path == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied generator output path; a CLI argument by design
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", errBadExceptions, path, err)
	}

	// encoding/json resolves a REPEATED key by silently keeping the last value,
	// so `{"kind":"^Job$","kind":".*"}` decodes as the wildcard and a
	// Job-scoped exception is widened across every kind — the document is
	// ambiguous and Go picks the broader reading. Resolving an ambiguity toward
	// "excepts more" is the one direction this loader must never take, so the
	// ambiguity is refused before anything is compiled.
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %w; a repeated key here can WIDEN an exception rather than "+
			"narrow it", errBadExceptions, path, err)
	}

	var policies []rawPolicy
	if err := json.Unmarshal(raw, &policies); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %w", errBadExceptions, path, err)
	}

	// A SUPPLIED artifact holding no policies disables all filtering silently:
	// accepted controls reappear as backlog work, and because `filtered` is
	// derived from the policy count the report then claims no -exceptions was
	// supplied at all. That is a different statement from omitting the flag,
	// which stays legitimate and is handled above.
	//
	// The generator never emits this — it errors with "no ClusterSecurityException
	// documents found" when it resolves zero — so refusing cannot fire on a
	// generated file.
	if len(policies) == 0 {
		return nil, fmt.Errorf("%w: %s declares no exception policies; the generator refuses to emit "+
			"an empty artifact, so this one is truncated or replaced. Applying it would silently "+
			"disable all filtering and re-file every accepted control",
			errBadExceptions, path)
	}

	out := make([]exception, 0, len(policies))

	for _, p := range policies {
		if p.PolicyType != posturePolicyType {
			// Silently skipping meant a stale or schema-changed artifact
			// quietly narrowed what counts as accepted: controls it was meant
			// to cover reappear as backlog work, and the write path would
			// re-file findings the platform has already accepted. The
			// generator emits exactly one type, so anything else means the
			// artifact and this reader disagree.
			return nil, fmt.Errorf("%w: %s declares policy %q with unknown policyType %q; "+
				"expected %q — regenerate the artifact rather than reading it partially",
				errBadExceptions, path, p.Name, p.PolicyType, posturePolicyType)
		}

		compiled, err := compilePolicy(p, path)
		if err != nil {
			return nil, err
		}

		out = append(out, compiled)
	}

	return out, nil
}

// rejectDuplicateKeys fails on any object in the document carrying the same key
// twice. encoding/json cannot report this — Unmarshal keeps the last value and
// a map[string]… loses the evidence — so the raw token stream is walked
// instead.
//
// Keys that differ only by CASE are additionally rejected, but only where that
// difference can actually change the decoded value. json matches STRUCT FIELDS
// case-insensitively, so `Controls` overwrites `controls`; MAP keys are kept
// verbatim, so `Team` beside `team` is two legitimate entries. Applying either
// rule everywhere is wrong in one direction or the other:
//
//   - folding everything rejects ordinary Kubernetes objects — a real posture
//     summary reporting 10 themes aborts once a `Team` label sits beside a
//     `team` one;
//   - folding nothing accepts a failed `"controls":{…}` followed by
//     `"Controls":{}`, which decodes to the empty map and exits 0 with "no
//     live-only findings" — the false all-clear this command exists to refuse,
//     reproduced on a real document.
//
// So the walker tracks what the object it is scanning decodes INTO, and folds
// only where keys bind to struct fields. Anything this command does not decode
// is scanned exact-only: an alias there cannot hide a finding or widen an
// exception, so refusing it would be pure false positives.
func rejectDuplicateKeys(raw []byte) error {
	err := scanForDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), scopeStruct)
	if errors.Is(err, errMalformedJSON) {
		// Deliberately not surfaced here: the caller's Unmarshal reports the
		// parse error with position and context. The walk only had to stop.
		return nil
	}

	return err
}

// foldScope is what the object currently being scanned decodes into. It is the
// only thing that decides whether a case-variant key pair is ambiguous.
type foldScope int

const (
	// scopeStruct: keys bind to Go struct fields, matched case-insensitively,
	// so a case variant silently overwrites and must be refused.
	scopeStruct foldScope = iota
	// scopeMap: keys are map entries, kept verbatim, so a case variant is two
	// distinct entries and is legitimate.
	scopeMap
	// scopeMapOfStruct: the map itself — arbitrary keys, so exact-only — whose
	// VALUES are structs, so folding resumes one level down.
	scopeMapOfStruct
	// scopeOpaque: not decoded by this command at all.
	scopeOpaque
)

// folds reports whether a case-variant collision is ambiguous in this scope.
func (s foldScope) folds() bool { return s == scopeStruct }

// child returns the scope of the value stored under key. Array elements keep
// their key's scope, so `items`, `resources` and `posturePolicies` carry it
// through to the objects inside them.
//
// The default is scopeOpaque, which is what keeps this safe as the documents
// grow: an unrecognised field — `managedFields` and the `f:`-prefixed trees
// under it, annotations, anything upstream adds later — is scanned exact-only
// rather than being folded on a guess.
func (s foldScope) child(key string) foldScope {
	if s == scopeMapOfStruct {
		return scopeStruct
	}

	if s != scopeStruct {
		return scopeOpaque
	}

	// Resolved with the DECODER's semantics, not by exact match: json binds
	// `"Status"` to the `Status` field exactly as `"status"` does. Matching
	// exactly dropped an aliased parent to scopeOpaque and stopped checking the
	// collisions BELOW it — `"Status":{"status":"failed","Status":"passed"}`
	// then decoded to passed and exited 0 with "nothing to file", while the
	// identical document spelled `"status"` was refused.
	//
	// This reaches only struct-bound keys: a scopeMap or scopeOpaque parent has
	// already returned above, so a label spelled `Spec` stays a map entry.
	switch {
	case equalsAnyFold(key, "labels", "annotations", "attributes", "severities"):
		return scopeMap
	case strings.EqualFold(key, "controls"):
		return scopeMapOfStruct
	case equalsAnyFold(key, "metadata", "spec", "severity", "status", "vulnerabilitiesRef",
		"all", "items", "resources", "posturePolicies"):
		return scopeStruct
	default:
		return scopeOpaque
	}
}

// equalsAnyFold reports whether key matches any name under the same simple case
// folding encoding/json uses to bind struct fields.
func equalsAnyFold(key string, names ...string) bool {
	for _, name := range names {
		if strings.EqualFold(key, name) {
			return true
		}
	}

	return false
}

// scanForDuplicateKeys consumes exactly one JSON value from dec, recursing
// through objects and arrays.
func scanForDuplicateKeys(dec *json.Decoder, scope foldScope) error {
	tok, err := dec.Token()
	if err != nil {
		// A malformed document is left to Unmarshal, which reports it with far
		// better context than a token-level error would — but the walk must
		// still STOP, because returning without consuming a token leaves the
		// caller's dec.More() loop spinning forever.
		return errMalformedJSON
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		// Keys are compared with the SAME folding encoding/json uses to bind
		// struct fields, because that is what decides which value survives:
		// `Attributes` and `attributes` reach the same field and the later one
		// wins, so an exact-string check misses the alias and the wildcard
		// still lands.
		//
		// strings.ToLower is NOT that folding, and the gap is reachable rather
		// than theoretical — verified on the toolchain in use: `attributeſ`
		// (U+017F LONG S) binds to the `attributes` field and overwrites it,
		// while ToLower leaves the two strings distinct. strings.EqualFold
		// implements the simple case folding json's field matcher uses, so the
		// keys already seen are compared with it directly. Objects here carry a
		// handful of keys, so the quadratic comparison is irrelevant.
		//
		// Folding costs nothing on real input — measured across the generated
		// artifact and every live scan document (2215 posture + 117 CVE
		// objects), there are zero case-variant sibling keys — and a map key
		// differing only in case is separately rejected downstream as an
		// unsupported attribute name.
		var seen []string

		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return errMalformedJSON
			}

			key, ok := keyTok.(string)
			if !ok {
				return nil
			}

			first, dup := "", false

			for _, prior := range seen {
				if prior == key || (scope.folds() && strings.EqualFold(prior, key)) {
					first, dup = prior, true

					break
				}
			}

			if dup {
				// The consequence differs by caller — a duplicate widens an
				// exception in the artifact and hides findings in a scan
				// document — so this states only the ambiguity, and each caller
				// wraps it with the sentinel that carries the meaning.
				if first == key {
					return fmt.Errorf("object key %q appears more than once, so the document is "+
						"ambiguous and JSON decoding would silently keep the LAST value", key)
				}

				return fmt.Errorf("object keys %q and %q collide, so the document is ambiguous and "+
					"JSON decoding would silently keep the LAST value (field names are matched "+
					"case-insensitively)", first, key)
			}

			seen = append(seen, key)

			// The VALUE under this key may decode into something else entirely
			// — a map of labels, a map of controls whose values are structs, or
			// a subtree this command never reads — so the scope is recomputed
			// per key rather than inherited.
			if err := scanForDuplicateKeys(dec, scope.child(key)); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := scanForDuplicateKeys(dec, scope); err != nil {
				return err
			}
		}
	}

	// Consume the matching closing delimiter.
	if _, err := dec.Token(); err != nil {
		return errMalformedJSON
	}

	return nil
}

// compileFullMatch compiles a declared pattern so it can only ever match a WHOLE value.
//
// Both consumers match with MatchString, which succeeds on a substring, and validating the text for
// leading ^ and trailing $ is not sufficient on its own: those anchors bind to the individual
// alternation branch they sit in, so `^C-001|C-002$` reads as `(^C-001)|(C-002$)` — it passes a
// prefix/suffix check while branch one stays open at the end (matching C-0016) and branch two open
// at the start (matching XC-002).
//
// Wrapping in a non-capturing group makes full-match semantics a property of the compiled pattern
// rather than of its spelling, so no internal structure can widen it. Already-anchored values stay
// correct — the anchors are zero-width and still match at the same positions.
func compileFullMatch(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return nil, err
	}

	// A pattern that cannot match any NON-EMPTY string is vacuous here, because
	// the identity guards make kind, name and controlID non-empty. The
	// generator produces exactly this from an empty CR value: its anchor()
	// wraps the raw value, so "" becomes `^$` — a non-empty STRING, which slips
	// past every empty-value guard and compiles cleanly.
	//
	// Left alone it is worse than useless. `filtered` is derived from the policy
	// COUNT, so one vacuous policy suppresses the "no -exceptions supplied"
	// caveat while suppressing no finding: every accepted control renders as an
	// ordinary work list with no note, the same shape a genuinely filtered run
	// produces.
	ok, err := canMatchNonEmpty(re.String())
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("pattern %q can only ever match the empty string, and kind, name and "+
			"controlID are never empty, so it can suppress nothing while still counting as an "+
			"applied exception", pattern)
	}

	return re, nil
}

// canMatchNonEmpty reports whether pattern can match at least one non-empty
// string.
//
// It deliberately FAILS TOWARD TRUE: it answers false only when no part of the
// expression can consume input at all. A false rejection breaks real artifacts,
// which is the failure this branch has already made twice; a missed exotic
// pattern only leaves the gap that existed before.
//
// Note that "matches the empty string" is NOT the question — `^(a|)$` matches
// "" and also matches "a", and `^.*$` matches everything.
func canMatchNonEmpty(pattern string) (bool, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false, fmt.Errorf("parse %q: %w", pattern, err)
	}

	_, consumes := analyse(parsed.Simplify())

	return consumes, nil
}

// analyse reports two independent properties of an expression: whether it can
// match ANYTHING at all, and whether it can match something NON-EMPTY.
//
// They have to be tracked together, because consuming input is not sufficient
// on its own. `^a[^\x00-\x{10FFFF}]$` contains a literal that plainly consumes,
// yet the empty character class beside it makes the whole concatenation
// unmatchable — so the pattern matches nothing, which is just as vacuous as
// matching only "". An empty character class is `OpCharClass` with no runes and
// is exactly how an impossible class reaches here.
//
// The bias is unchanged and deliberate: uncertainty resolves toward MATCHABLE,
// so a pattern is called vacuous only when the structure proves it. A false
// rejection breaks real artifacts; a missed vacuous pattern only leaves the gap
// that existed before.
func analyse(r *syntax.Regexp) (matchable, consumes bool) {
	switch r.Op {
	case syntax.OpNoMatch:
		return false, false

	case syntax.OpLiteral:
		return true, len(r.Rune) > 0

	case syntax.OpCharClass:
		// No runes means no character satisfies it, so it matches nothing —
		// neither empty nor non-empty.
		return len(r.Rune) > 0, len(r.Rune) > 0

	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return true, true

	case syntax.OpCapture:
		return analyse(r.Sub[0])

	case syntax.OpStar, syntax.OpQuest:
		// Zero repetitions always match, so these match even when the sub
		// cannot; they consume only if the sub is reachable AND consuming.
		subMatchable, subConsumes := analyse(r.Sub[0])

		return true, subMatchable && subConsumes

	case syntax.OpPlus:
		subMatchable, subConsumes := analyse(r.Sub[0])

		return subMatchable, subMatchable && subConsumes

	case syntax.OpRepeat:
		subMatchable, subConsumes := analyse(r.Sub[0])
		if r.Min == 0 {
			return true, subMatchable && subConsumes
		}

		return subMatchable, subMatchable && subConsumes

	case syntax.OpConcat:
		// Every element must match, so one unmatchable element makes the whole
		// concatenation unmatchable however much the others consume.
		//
		// Position matters too, and individually-matchable elements can still
		// contradict each other: `^a^$` has a literal and two anchors that are
		// each fine alone, yet nothing can be at the start of the text after
		// consuming an `a`. `^$a$` is the mirror. Both match no string at all.
		//
		// Only the whole-text anchors are treated this way. Under `(?m)` the
		// parser produces OpBeginLine/OpEndLine, which legitimately match
		// mid-string, so they are left alone — accepting is the safe direction.
		anyConsumes := false
		endSeen := false

		for _, sub := range r.Sub {
			switch sub.Op {
			case syntax.OpBeginText:
				if anyConsumes {
					return false, false
				}
			case syntax.OpEndText:
				endSeen = true
			default:
			}

			subMatchable, subConsumes := analyse(sub)
			if !subMatchable {
				return false, false
			}

			if subConsumes && endSeen {
				return false, false
			}

			anyConsumes = anyConsumes || subConsumes
		}

		return true, anyConsumes

	case syntax.OpAlternate:
		for _, sub := range r.Sub {
			subMatchable, subConsumes := analyse(sub)
			matchable = matchable || subMatchable
			consumes = consumes || (subMatchable && subConsumes)
		}

		return matchable, consumes

	default:
		// OpEmptyMatch and the zero-width assertions: OpBeginLine, OpEndLine,
		// OpBeginText, OpEndText, OpWordBoundary, OpNoWordBoundary.
		return true, false
	}
}

func compilePolicy(p rawPolicy, path string) (exception, error) {
	e := exception{name: p.Name}
	if strings.TrimSpace(p.Name) == "" {
		return exception{}, fmt.Errorf("%w: %s: a policy has no name; an exception match without "+
			"an audit identity cannot be explained or safely ablated", errBadExceptions, path)
	}

	// The action is what makes a policy an exception at all. The generator emits
	// exactly ["disable"] for every policy it writes, so anything else did not
	// come from it — a stale, hand-edited or schema-changed artifact. Applying it
	// anyway would suppress findings under semantics this command never checked,
	// which is the same silent-widening direction the anchoring rules below guard.
	//
	// Regenerate legacy alertOnly artifacts: current Kubescape acknowledges
	// those findings but keeps them failing, so suppressing them here would drift.
	if len(p.Actions) != 1 || p.Actions[0] != exceptionActionDisable {
		return exception{}, fmt.Errorf("%w: %s: policy %q declares actions %v, but this command only "+
			"understands exactly [%q]; a policy carrying any other action would be applied as a full "+
			"suppressor under semantics that were never validated",
			errBadExceptions, path, p.Name, p.Actions, exceptionActionDisable)
	}

	for _, pp := range p.PosturePolicies {
		// Skipping a malformed entry applied the artifact PARTIALLY: with one
		// valid sibling the nonempty-controls check below still passed, so a
		// truncated or schema-changed policy quietly accepted fewer controls
		// than it names while the report continued to claim exceptions were
		// applied — an accepted control reappearing as backlog work.
		//
		// The generator rejects entries without a control ID and emits none
		// (0 of 93 measured), so refusing is fail-closed.
		if pp.ControlID == "" {
			return exception{}, fmt.Errorf("%w: %s: policy %q carries a posturePolicies entry with no "+
				"controlID; applying the rest would accept fewer controls than the policy names "+
				"while still counting as filtering applied",
				errBadExceptions, path, p.Name)
		}

		// A framework-scoped exception accepts a control only within one
		// framework. The scan summaries this command reads carry no framework,
		// so the scope cannot be honoured — and applying the policy anyway
		// would widen a deliberately narrow exception across every framework,
		// suppressing controls the platform never accepted.
		//
		// Refusing is the fail-closed half of that choice: it is a loud, fixable
		// error, where widening is silent. No current policy uses the field
		// (0 of 93 measured), so this cannot fire on today's artifact.
		if pp.FrameworkName != "" {
			return exception{}, fmt.Errorf("%w: %s: policy %q scopes control %q to framework %q, "+
				"but the scan input carries no framework to match it against; "+
				"applying it would widen the exception across every framework",
				errBadExceptions, path, p.Name, pp.ControlID, pp.FrameworkName)
		}

		// covers() matches with MatchString, which succeeds on a SUBSTRING. An
		// unanchored "C-001" therefore suppresses C-0016 as well — widening a
		// deliberately narrow exception onto controls the platform never
		// accepted, silently, and in the one direction this loader must never be
		// wrong in.
		//
		// The generator that produces these artifacts already anchors every value
		// and rejects partial anchoring for exactly this reason. Enforcing the
		// same contract here means a hand-edited or otherwise ungenerated artifact
		// fails loudly instead of quietly excepting more than it names. A value
		// anchored at only one end is still substring-matchable at the open end,
		// so it is refused too rather than silently completed.
		if !strings.HasPrefix(pp.ControlID, "^") || !strings.HasSuffix(pp.ControlID, "$") {
			return exception{}, fmt.Errorf("%w: %s: policy %q: controlID %q is not fully anchored; "+
				"controls are matched as substrings, so it would also suppress every control whose ID "+
				"contains it. Anchor it as ^…$",
				errBadExceptions, path, p.Name, pp.ControlID)
		}

		re, err := compileFullMatch(pp.ControlID)
		if err != nil {
			return exception{}, fmt.Errorf("%w: %s: policy %q: controlID %q: %w",
				errBadExceptions, path, p.Name, pp.ControlID, err)
		}

		e.controls = append(e.controls, re)
	}

	for _, r := range p.Resources {
		// The discriminator must be honoured, not discarded. An unknown
		// designator type whose attributes happen to parse would compile into a
		// working attribute matcher and could suppress real controls under
		// semantics this command does not implement.
		if r.DesignatorType != attributesDesignator {
			return exception{}, fmt.Errorf("%w: %s: policy %q uses designator type %q, "+
				"but this command only implements %q",
				errBadExceptions, path, p.Name, r.DesignatorType, attributesDesignator)
		}

		if len(r.Attributes) == 0 {
			return exception{}, fmt.Errorf("%w: %s: policy %q carries a resource designator with no "+
				"attributes, which names no workload and can never match; a policy that cannot "+
				"cover anything still counts as filtering applied and would suppress the "+
				"unfiltered-report caveat",
				errBadExceptions, path, p.Name)
		}

		d := designator{}

		for key, pattern := range r.Attributes {
			// An attribute this command does not model can never be satisfied —
			// designator.matches returns false for an unknown key — so a
			// designator built only from such keys is non-empty yet covers
			// nothing, passing the guard below while still counting as
			// filtering applied. Refusing the key is the fail-closed reading,
			// and it keeps the loader honest about what it can actually
			// enforce rather than accepting a scope it will silently ignore.
			//
			// The generator emits only these three (measured across the real 21
			// policies: kind=115, name=104, namespace=6, and zero designators
			// made solely of anything else), so this cannot fire on today's
			// artifact.
			if _, ok := matchableAttributes[key]; !ok {
				return exception{}, fmt.Errorf("%w: %s: policy %q: designator attribute %q is not one "+
					"this command matches on (%s); a designator resting on it can never apply, yet it "+
					"would still count as filtering applied",
					errBadExceptions, path, p.Name, key, strings.Join(matchableAttributeNames(), ", "))
			}

			re, err := compileFullMatch(pattern)
			if err != nil {
				return exception{}, fmt.Errorf("%w: %s: policy %q: attribute %s=%q: %w",
					errBadExceptions, path, p.Name, key, pattern, err)
			}

			// A cluster-scoped component deliberately carries an EMPTY
			// namespace — that is component()'s stated invariant, and the reason
			// its namespace fallback was removed. But the invariant claims more
			// than it can deliver: "no namespace designator matches" is false
			// for any pattern accepting the empty string (`.*`, `^$`, or the
			// `^()$` an empty namespace selector generates). Such a policy
			// reaches cluster-scoped findings — ClusterRoleBinding,
			// PersistentVolume, Node, webhook configurations — and suppresses
			// them, which is exactly the class removing that fallback prevented.
			//
			// Deliberately namespace-ONLY. An empty kind or name is impossible
			// now that the identity guards reject it, and `kind: ".*"` is real
			// generator output (115 uses), so refusing every empty-matching
			// pattern would break today's artifact. Namespace is the one field
			// where empty is LEGITIMATE rather than malformed, so it is the one
			// that needs checking at the pattern level.
			//
			// Fail-closed on today's artifact: all 6 generated namespace
			// patterns are explicit alternations of named namespaces, none of
			// which matches the empty string.
			if key == "namespace" && re.MatchString("") {
				return exception{}, fmt.Errorf("%w: %s: policy %q: namespace pattern %q also matches the "+
					"EMPTY namespace, which is how a cluster-scoped resource is represented; it would "+
					"silently suppress cluster-scoped findings. Name the namespaces explicitly",
					errBadExceptions, path, p.Name, pattern)
			}

			d[key] = re
		}

		e.resources = append(e.resources, d)
	}

	// A policy needs BOTH halves to cover anything: covers() requires a control
	// match AND a designator match. Missing either, it suppresses nothing — so
	// the suppression direction is already safe and this guard is not about
	// hidden findings.
	//
	// The damage is to the REPORT. run() passes `len(exceptions) > 0` as proof
	// that filtering occurred, so a single vacuous policy suppresses the
	// "declared exceptions were NOT applied" caveat while accepted controls
	// still render as ordinary backlog work. The operator is told the output is
	// a filed-work list with accepted controls removed, when nothing was
	// removed — a report that misstates its own provenance.
	//
	// Both halves are fail-closed and cannot fire on today's artifact: every one
	// of the generator's 21 policies names at least one control and one
	// designator.
	if len(e.controls) == 0 {
		return exception{}, fmt.Errorf("%w: %s: policy %q resolves to no control patterns, so it can "+
			"never cover a finding, yet it would still count as filtering applied",
			errBadExceptions, path, p.Name)
	}

	if len(e.resources) == 0 {
		return exception{}, fmt.Errorf("%w: %s: policy %q names no resource designators, so it can "+
			"never cover a finding, yet it would still count as filtering applied",
			errBadExceptions, path, p.Name)
	}

	return e, nil
}
