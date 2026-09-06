// Command annotate-vendored-checkov adds the repository's reviewed Checkov
// dispositions to pinned upstream operator bundles without reformatting them.
//
// The upstream files are deliberately kept byte-for-byte apart from these
// annotations. The updater can therefore replace a bundle, run this command,
// and fail closed when a target resource is renamed or removed.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	clusterRoleReason = "Vendored upstream operator RBAC; changes must go through the pinned vendor update path tracked by platform issue 2899."
	deploymentReason  = "Pinned upstream operator deployment; changes must go through the vendor update path tracked by platform issue 2899."
)

type targetSpec struct {
	kind                string
	name                string
	checks              []string
	reason              string
	resourceFingerprint string
	imageRepository     string
}

type manifestIdentity struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
}

type checkovReport struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []struct {
			CheckID     string  `json:"check_id"`
			Resource    string  `json:"resource"`
			FilePath    string  `json:"file_path"`
			CodeBlock   [][]any `json:"code_block"`
			CheckResult struct {
				EvaluatedKeys []string `json:"evaluated_keys"`
			} `json:"check_result"`
		} `json:"failed_checks"`
	} `json:"results"`
	Summary checkovSummary `json:"summary"`
}

type checkovSummary struct {
	Failed        *int `json:"failed"`
	ParsingErrors *int `json:"parsing_errors"`
}

// resourceFingerprint hashes Checkov's resource code_block without its source
// line numbers. A vendor refresh must therefore re-review any target change,
// including a known check moving to a different container or field.
var bundleTargets = map[string][]targetSpec{
	"origin-ca-issuer": {}, // CRDs only: no workload/RBAC dispositions apply.
	"kubelet-serving-cert-approver": {
		{kind: "ClusterRole", name: "certificates:kubelet-serving-cert-approver", checks: []string{"CKV_K8S_156"}, reason: "Certificate approval is the purpose of this pinned upstream controller; signer permission is restricted to kubernetes.io/kubelet-serving.", resourceFingerprint: "3e3382b9d85d7f16926202613a3e6247e375a30f08eab5de4e3fa94ba235d8ce"},
		{kind: "RoleBinding", name: "events:kubelet-serving-cert-approver", checks: []string{"CKV_K8S_21"}, reason: "Pinned upstream binding permits only event creation and patching in default; the controller workload runs in its dedicated namespace.", resourceFingerprint: "f76f09dcd9d0f3f71e2e8325d8f2fc9cb742898d637e0c539a9c284bb7d4bb5a"},
		{kind: "Deployment", name: "kubelet-serving-cert-approver", checks: []string{"CKV_K8S_38", "CKV_K8S_43"}, reason: "Pinned upstream certificate approver requires its service-account token; preserve the release image while the full manifest is SHA-256 verified through the vendor updater.", resourceFingerprint: "e7cadbfb581bff5eedf687034a489860521ff33fb6cd647157d4fd2160353231", imageRepository: "ghcr.io/alex1989hu/kubelet-serving-cert-approver"},
	},
	"cdi": {
		{kind: "ClusterRole", name: "cdi-operator-cluster", checks: []string{"CKV_K8S_155"}, reason: clusterRoleReason, resourceFingerprint: "df06bcec640e27ea586a8d12bffa509558eb8a244978a0de46c35743ec85341e"},
		{kind: "Deployment", name: "cdi-operator", checks: deploymentChecks(), reason: deploymentReason, resourceFingerprint: "f81c6d025990a3a550fbe12e38033c8c0c4e3d4397dc14c357c7c6dc601abe07", imageRepository: "quay.io/kubevirt/cdi-operator"},
	},
	"kubevirt": {
		{kind: "ClusterRole", name: "kubevirt-operator", checks: []string{"CKV_K8S_155"}, reason: clusterRoleReason, resourceFingerprint: "6eb8526d222f837be3a38f82c18710be5f64aa10e27cbe741b7707198b3df842"},
		{kind: "Deployment", name: "virt-operator", checks: deploymentChecks(), reason: deploymentReason, resourceFingerprint: "a983d7303c2daf4c74e806ddfe9caf3eb1f25c6238798716d6c80e124016b51e", imageRepository: "quay.io/kubevirt/virt-operator"},
	},
}

var inlineCheckovSkip = regexp.MustCompile(`(?i)checkov\s*:\s*skip\s*=`)
var sha256Digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var yamlDocumentMarker = regexp.MustCompile(`^---(?:[ \t]+(?:#.*)?)?$`)

var workloadKinds = map[string]struct{}{
	"CronJob":               {},
	"DaemonSet":             {},
	"Deployment":            {},
	"Job":                   {},
	"Pod":                   {},
	"ReplicaSet":            {},
	"ReplicationController": {},
	"StatefulSet":           {},
}

func deploymentChecks() []string {
	return []string{
		"CKV_K8S_11",
		"CKV_K8S_13",
		"CKV_K8S_15",
		"CKV_K8S_22",
		"CKV_K8S_38",
		"CKV_K8S_40",
		"CKV_K8S_43",
	}
}

func expectedEvaluatedKeys(check string) ([]string, bool) {
	switch check {
	case "CKV_K8S_11":
		return []string{"spec/template/spec/containers/[0]/resources/limits/cpu"}, true
	case "CKV_K8S_13":
		return []string{"spec/template/spec/containers/[0]/resources/limits/memory"}, true
	case "CKV_K8S_15":
		return []string{
			"spec/template/spec/containers/[0]/image",
			"spec/template/spec/containers/[0]/imagePullPolicy",
		}, true
	case "CKV_K8S_22":
		return []string{"spec/template/spec/containers/[0]/securityContext/readOnlyRootFilesystem"}, true
	case "CKV_K8S_43":
		return []string{"spec/template/spec/containers/[0]/image"}, true
	case "CKV_K8S_21", "CKV_K8S_38", "CKV_K8S_40", "CKV_K8S_155", "CKV_K8S_156":
		return []string{}, true
	default:
		return nil, false
	}
}

func main() {
	bundle := flag.String("bundle", "", "declared vendored bundle")
	splitResources := flag.String("split-resources", "", "split cert-approver resources into this directory without changing bytes")
	resourcesDir := flag.String("resources-dir", "", "read split cert-approver resources for --validate-annotated")
	validateFindings := flag.Bool(
		"validate-findings",
		false,
		"validate that every configured disposition still matches a Checkov JSON finding",
	)
	validateReport := flag.Bool(
		"validate-report",
		false,
		"validate that a Checkov JSON report contains no parsing errors or failed checks",
	)
	validateSource := flag.Bool(
		"validate-source",
		false,
		"validate that an upstream bundle contains no Checkov suppressions",
	)
	validateAnnotated := flag.Bool(
		"validate-annotated",
		false,
		"validate that a committed bundle is the pinned source plus exactly the configured dispositions",
	)
	sourceSHA256 := flag.String(
		"source-sha256",
		"",
		"expected SHA-256 of the annotation-free upstream source for --validate-annotated",
	)
	sourceVersion := flag.String(
		"source-version",
		"",
		"expected release version in the pinned operator image for --validate-annotated",
	)
	framework := flag.String(
		"framework",
		"",
		"expected Checkov framework for --validate-report: kubernetes or secrets",
	)
	requireSecretsCanary := flag.Bool(
		"require-secrets-canary",
		false,
		"require the updater's exact synthetic secrets finding in a secrets report",
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}

	targets, ok := bundleTargets[*bundle]
	if !ok {
		fail("unsupported bundle %q", *bundle)
	}
	modeCount := 0
	for _, enabled := range []bool{*validateFindings, *validateReport, *validateSource, *validateAnnotated} {
		if enabled {
			modeCount++
		}
	}
	if modeCount > 1 {
		fail("validation modes are mutually exclusive")
	}
	if *splitResources != "" && (modeCount != 0 || *bundle != "kubelet-serving-cert-approver") {
		fail("--split-resources requires the cert-approver bundle and no validation mode")
	}
	if *resourcesDir != "" && (!*validateAnnotated || *bundle != "kubelet-serving-cert-approver") {
		fail("--resources-dir requires the cert-approver bundle and --validate-annotated")
	}
	if *validateReport && *framework != "kubernetes" && *framework != "secrets" {
		fail("--validate-report requires --framework kubernetes or --framework secrets")
	}
	if *requireSecretsCanary && (!*validateReport || *framework != "secrets") {
		fail("--require-secrets-canary requires --validate-report --framework secrets")
	}
	if *validateAnnotated && *sourceSHA256 == "" {
		fail("--validate-annotated requires --source-sha256")
	}
	if *validateAnnotated && *sourceVersion == "" {
		fail("--validate-annotated requires --source-version")
	}
	if !*validateAnnotated && (*sourceSHA256 != "" || *sourceVersion != "") {
		fail("--source-sha256 and --source-version require --validate-annotated")
	}

	input, err := io.ReadAll(os.Stdin)
	if *resourcesDir != "" {
		input, err = joinCertApproverResources(*resourcesDir)
	}
	if err != nil {
		fail("read bundle: %v", err)
	}
	if *splitResources != "" {
		if err := splitCertApproverResources(input, *splitResources); err != nil {
			fail("split bundle: %v", err)
		}
		return
	}
	if *validateFindings {
		if err := validateCheckovFindings(input, targets); err != nil {
			fail("validate %s findings: %v", *bundle, err)
		}
		return
	}
	if *validateReport {
		if _, err := decodeCheckovReports(input, *framework, !*requireSecretsCanary, *requireSecretsCanary); err != nil {
			fail("validate %s report: %v", *bundle, err)
		}
		return
	}
	if *validateSource {
		if err := validateVendorSource(input, *bundle); err != nil {
			fail("validate %s source: %v", *bundle, err)
		}
		return
	}
	if *validateAnnotated {
		if err := validatePinnedSource(input, targets, *sourceSHA256, *sourceVersion); err != nil {
			fail("validate %s annotated bundle: %v", *bundle, err)
		}
		return
	}
	output, err := annotateBundle(string(input), targets)
	if err != nil {
		fail("annotate %s bundle: %v", *bundle, err)
	}
	if _, err := io.WriteString(os.Stdout, output); err != nil {
		fail("write bundle: %v", err)
	}
}

func validateCheckovFindings(input []byte, targets []targetSpec) error {
	for _, target := range targets {
		for _, check := range target.checks {
			if _, known := expectedEvaluatedKeys(check); !known {
				return fmt.Errorf("%s has no reviewed evaluated keys", check)
			}
		}
	}
	reports, err := decodeCheckovReports(input, "kubernetes", false, false)
	if err != nil {
		return err
	}

	found := make(map[string]int)
	for _, report := range reports {
		if report.CheckType != "kubernetes" {
			continue
		}
		for _, failed := range report.Results.FailedChecks {
			for _, target := range targets {
				if !strings.HasPrefix(failed.Resource, target.kind+".") ||
					!strings.HasSuffix(failed.Resource, "."+target.name) {
					continue
				}
				for _, check := range target.checks {
					if failed.CheckID == check {
						expectedKeys, known := expectedEvaluatedKeys(check)
						if !known {
							return fmt.Errorf("%s has no reviewed evaluated keys", check)
						}
						if !slices.Equal(failed.CheckResult.EvaluatedKeys, expectedKeys) {
							return fmt.Errorf(
								"%s finding for %s/%s evaluated keys changed: found %v, want %v",
								check,
								target.kind,
								target.name,
								failed.CheckResult.EvaluatedKeys,
								expectedKeys,
							)
						}
						fingerprint, err := codeBlockFingerprint(failed.CodeBlock)
						if err != nil {
							return fmt.Errorf("fingerprint %s finding for %s/%s: %w", check, target.kind, target.name, err)
						}
						if fingerprint != target.resourceFingerprint {
							return fmt.Errorf(
								"%s finding for %s/%s resource fingerprint changed: found %s, want %s",
								check,
								target.kind,
								target.name,
								fingerprint,
								target.resourceFingerprint,
							)
						}
						found[target.kind+"/"+target.name+"/"+check]++
					}
				}
			}
		}
	}

	for _, target := range targets {
		for _, check := range target.checks {
			key := target.kind + "/" + target.name + "/" + check
			if found[key] != 1 {
				return fmt.Errorf(
					"configured disposition %s for %s/%s no longer matches exactly one current finding (found %d)",
					check,
					target.kind,
					target.name,
					found[key],
				)
			}
		}
	}
	return nil
}

func codeBlockFingerprint(codeBlock [][]any) (string, error) {
	if len(codeBlock) == 0 {
		return "", errors.New("checkov finding omits code_block")
	}
	hash := sha256.New()
	for index, line := range codeBlock {
		if len(line) != 2 {
			return "", fmt.Errorf("code_block line %d has %d fields", index, len(line))
		}
		text, ok := line[1].(string)
		if !ok {
			return "", fmt.Errorf("code_block line %d text is %T", index, line[1])
		}
		if err := binary.Write(hash, binary.BigEndian, uint64(len(text))); err != nil {
			return "", fmt.Errorf("hash code_block line %d length: %w", index, err)
		}
		if _, err := hash.Write([]byte(text)); err != nil {
			return "", fmt.Errorf("hash code_block line %d: %w", index, err)
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func decodeCheckovReports(
	input []byte,
	expectedFramework string,
	rejectFindings bool,
	requireSecretsCanary bool,
) ([]checkovReport, error) {
	trimmed := strings.TrimSpace(string(input))
	if trimmed == "" {
		return nil, errors.New("checkov report is empty")
	}

	var reports []checkovReport
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(input, &reports); err != nil {
			return nil, fmt.Errorf("decode Checkov reports: %w", err)
		}
	} else {
		var report checkovReport
		if err := json.Unmarshal(input, &report); err != nil {
			return nil, fmt.Errorf("decode Checkov report: %w", err)
		}
		reports = []checkovReport{report}
	}
	matching := 0
	for _, report := range reports {
		if report.CheckType == expectedFramework {
			matching++
		}
	}
	if len(reports) != 1 || matching != 1 {
		return nil, fmt.Errorf(
			"expected exactly one %s report, found %d among %d framework result(s)",
			expectedFramework,
			matching,
			len(reports),
		)
	}
	for _, report := range reports {
		if report.Summary.ParsingErrors == nil {
			return nil, fmt.Errorf("%s report omits summary.parsing_errors", report.CheckType)
		}
		if report.Summary.Failed == nil {
			return nil, fmt.Errorf("%s report omits summary.failed", report.CheckType)
		}
		if *report.Summary.ParsingErrors != 0 {
			return nil, fmt.Errorf(
				"%s report reported %d parsing error(s)",
				report.CheckType,
				*report.Summary.ParsingErrors,
			)
		}
		failedCount := *report.Summary.Failed
		if len(report.Results.FailedChecks) > failedCount {
			failedCount = len(report.Results.FailedChecks)
		}
		if rejectFindings && failedCount != 0 {
			return nil, fmt.Errorf("%s report reported %d failed check(s)", report.CheckType, failedCount)
		}
		if requireSecretsCanary {
			if err := validateSecretsCanary(report, failedCount); err != nil {
				return nil, err
			}
		}
	}
	return reports, nil
}

func validateSecretsCanary(report checkovReport, failedCount int) error {
	if report.CheckType != "secrets" || failedCount != 1 || len(report.Results.FailedChecks) != 1 {
		return fmt.Errorf("secrets report must contain exactly one synthetic canary finding, found %d", failedCount)
	}
	finding := report.Results.FailedChecks[0]
	if finding.CheckID != "CKV_SECRET_2" || path.Base(finding.FilePath) != "checkov-secrets-canary.txt" {
		return fmt.Errorf(
			"secrets report contains unexpected canary identity %s in %s",
			finding.CheckID,
			finding.FilePath,
		)
	}
	if len(finding.CodeBlock) != 1 || len(finding.CodeBlock[0]) != 2 {
		return errors.New("secrets canary finding has an unexpected code_block")
	}
	line, ok := finding.CodeBlock[0][1].(string)
	if !ok || line != "aws_access_key_id: AKIAQ**********\n" {
		return errors.New("secrets canary finding does not contain the masked synthetic key")
	}
	return nil
}

func validateVendorSource(input []byte, bundle string) error {
	if bundle == "origin-ca-issuer" {
		if err := validateOriginCRD(input); err != nil {
			return err
		}
	}
	if inlineCheckovSkip.Match(input) {
		return errors.New("source contains inline Checkov suppression")
	}
	protectedNamespace := map[string]string{
		"cdi":                           "cdi",
		"kubevirt":                      "kubevirt",
		"kubelet-serving-cert-approver": "kubelet-serving-cert-approver",
	}[bundle]
	decoder := yaml.NewDecoder(strings.NewReader(string(input)))
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("parse vendor document %d: %w", documentIndex, err)
		}
		if len(document.Content) == 0 || document.Content[0].Kind == 0 {
			continue
		}
		if err := rejectInlineCheckovSuppression(&document); err != nil {
			return fmt.Errorf("vendor document %d contains %w", documentIndex, err)
		}
		if err := rejectYAMLAlias(&document); err != nil {
			return fmt.Errorf("vendor document %d contains %w", documentIndex, err)
		}
		if err := rejectYAMLMergeKey(&document); err != nil {
			return fmt.Errorf("vendor document %d contains %w", documentIndex, err)
		}
		if err := rejectDuplicateYAMLMappingKeys(&document); err != nil {
			return fmt.Errorf("vendor document %d contains %w", documentIndex, err)
		}
		root := document.Content[0]
		if root.Kind != yaml.MappingNode {
			return fmt.Errorf("vendor document %d must contain a top-level mapping", documentIndex)
		}
		if err := validateVendorResource(root, protectedNamespace); err != nil {
			return fmt.Errorf("vendor document %d: %w", documentIndex, err)
		}
	}
}

func validateVendorResource(root *yaml.Node, protectedNamespace string) error {
	kind := mappingScalar(root, "kind")
	metadata := mappingValue(root, "metadata")
	_, workload := workloadKinds[kind]
	if workload && metadata == nil {
		return fmt.Errorf("%s metadata is missing", kind)
	}
	if metadata != nil {
		if metadata.Kind != yaml.MappingNode {
			return errors.New("metadata must be a mapping")
		}
		if workload {
			name := mappingScalar(metadata, "name")
			namespace := mappingScalar(metadata, "namespace")
			if namespace != protectedNamespace {
				return fmt.Errorf(
					"%s/%s uses namespace %s, want %s before CKV2_K8S_6 can be excluded",
					kind,
					name,
					namespace,
					protectedNamespace,
				)
			}
		}
		annotations := mappingValue(metadata, "annotations")
		if annotations != nil {
			if annotations.Kind != yaml.MappingNode {
				return errors.New("metadata.annotations must be a mapping")
			}
			for index := 0; index+1 < len(annotations.Content); index += 2 {
				key := annotations.Content[index].Value
				if strings.HasPrefix(key, "checkov.io/skip") {
					return fmt.Errorf("contains upstream Checkov suppression %s", key)
				}
			}
		}
	}

	if kind != "List" && !strings.HasSuffix(kind, "List") {
		return nil
	}
	items := mappingValue(root, "items")
	if items == nil {
		return nil
	}
	if items.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s items must be a sequence", kind)
	}
	for index, item := range items.Content {
		if item.Kind != yaml.MappingNode {
			return fmt.Errorf("%s item %d must be a mapping", kind, index+1)
		}
		if err := validateVendorResource(item, protectedNamespace); err != nil {
			return fmt.Errorf("%s item %d: %w", kind, index+1, err)
		}
	}
	return nil
}

func validateAnnotatedBundle(input []byte, targets []targetSpec) error {
	if inlineCheckovSkip.Match(input) {
		return errors.New("committed bundle contains inline Checkov suppression")
	}
	targetsByIdentity := make(map[string]targetSpec, len(targets))
	expectedByIdentity := make(map[string]map[string]string, len(targets))
	for _, target := range targets {
		identity := target.kind + "/" + target.name
		targetsByIdentity[identity] = target
		expected := make(map[string]string, len(target.checks))
		for index, check := range target.checks {
			expected["checkov.io/skip"+strconv.Itoa(index+1)] = check + "=" + target.reason
		}
		expectedByIdentity[identity] = expected
	}

	seenTargets := make(map[string]int, len(targets))
	seenDispositions := make(map[string]int)
	decoder := yaml.NewDecoder(strings.NewReader(string(input)))
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("parse committed document %d: %w", documentIndex, err)
		}
		if len(document.Content) == 0 || document.Content[0].Kind == 0 {
			continue
		}
		if err := rejectInlineCheckovSuppression(&document); err != nil {
			return fmt.Errorf("committed document %d contains %w", documentIndex, err)
		}
		if err := rejectYAMLAlias(&document); err != nil {
			return fmt.Errorf("committed document %d contains %w", documentIndex, err)
		}
		root := document.Content[0]
		if root.Kind != yaml.MappingNode {
			return fmt.Errorf("committed document %d must contain a top-level mapping", documentIndex)
		}
		if err := walkManifestResources(root, func(resource *yaml.Node) error {
			return validateAnnotatedResource(
				resource,
				targetsByIdentity,
				expectedByIdentity,
				seenTargets,
				seenDispositions,
			)
		}); err != nil {
			return fmt.Errorf("committed document %d: %w", documentIndex, err)
		}
	}

	for identity, expected := range expectedByIdentity {
		if seenTargets[identity] != 1 {
			return fmt.Errorf("expected exactly one committed %s, found %d", identity, seenTargets[identity])
		}
		for annotationKey := range expected {
			if seenDispositions[identity+"/"+annotationKey] != 1 {
				return fmt.Errorf("expected exactly one configured %s on %s", annotationKey, identity)
			}
		}
	}
	return nil
}

func validateAnnotatedResource(
	root *yaml.Node,
	targetsByIdentity map[string]targetSpec,
	expectedByIdentity map[string]map[string]string,
	seenTargets map[string]int,
	seenDispositions map[string]int,
) error {
	kind := mappingScalar(root, "kind")
	metadata := mappingValue(root, "metadata")
	if metadata == nil {
		return nil
	}
	if metadata.Kind != yaml.MappingNode {
		return errors.New("metadata must be a mapping")
	}
	name := mappingScalar(metadata, "name")
	identity := kind + "/" + name
	if _, configured := targetsByIdentity[identity]; configured {
		seenTargets[identity]++
	}

	annotations := mappingValue(metadata, "annotations")
	if annotations == nil {
		return nil
	}
	if annotations.Kind != yaml.MappingNode {
		return errors.New("metadata.annotations must be a mapping")
	}
	for index := 0; index+1 < len(annotations.Content); index += 2 {
		annotationKey := annotations.Content[index].Value
		if !strings.HasPrefix(annotationKey, "checkov.io/skip") {
			continue
		}
		expected, configuredTarget := expectedByIdentity[identity]
		expectedValue, configuredDisposition := expected[annotationKey]
		if !configuredTarget || !configuredDisposition {
			return fmt.Errorf("unexpected Checkov disposition %s on %s", annotationKey, identity)
		}
		annotationValue := annotations.Content[index+1]
		if annotationValue.Kind != yaml.ScalarNode || annotationValue.Value != expectedValue {
			return fmt.Errorf(
				"%s on %s does not match the configured disposition",
				annotationKey,
				identity,
			)
		}
		seenDispositions[identity+"/"+annotationKey]++
	}
	return nil
}

func validatePinnedSource(input []byte, targets []targetSpec, expectedSHA256, expectedVersion string) error {
	if !sha256Digest.MatchString(expectedSHA256) {
		return fmt.Errorf("source SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if err := validateAnnotatedBundle(input, targets); err != nil {
		return err
	}
	source, err := stripConfiguredDispositions(string(input), targets)
	if err != nil {
		return err
	}
	actualSHA256 := fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
	if actualSHA256 != expectedSHA256 {
		return fmt.Errorf("source SHA-256 is %s, want %s", actualSHA256, expectedSHA256)
	}
	if err := validateOperatorImageVersion([]byte(source), targets, expectedVersion); err != nil {
		return err
	}
	return nil
}

func validateOperatorImageVersion(input []byte, targets []targetSpec, expectedVersion string) error {
	if expectedVersion == "" {
		return errors.New("source version must not be empty")
	}
	expectedByIdentity := make(map[string]targetSpec)
	for _, target := range targets {
		if target.imageRepository != "" {
			expectedByIdentity[target.kind+"/"+target.name] = target
		}
	}
	if len(expectedByIdentity) == 0 {
		return errors.New("no operator image is configured for the bundle")
	}

	seen := make(map[string]int, len(expectedByIdentity))
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("parse pinned source document %d: %w", documentIndex, err)
		}
		if len(document.Content) == 0 || document.Content[0].Kind == 0 {
			continue
		}
		if err := validateOperatorImageResource(
			document.Content[0],
			expectedByIdentity,
			expectedVersion,
			seen,
		); err != nil {
			return fmt.Errorf("pinned source document %d: %w", documentIndex, err)
		}
	}
	for identity := range expectedByIdentity {
		if seen[identity] != 1 {
			return fmt.Errorf("expected exactly one operator image resource %s, found %d", identity, seen[identity])
		}
	}
	return nil
}

func validateOperatorImageResource(
	root *yaml.Node,
	expectedByIdentity map[string]targetSpec,
	expectedVersion string,
	seen map[string]int,
) error {
	if root.Kind != yaml.MappingNode {
		return errors.New("operator image resource must be a mapping")
	}
	kind := mappingScalar(root, "kind")
	metadata := mappingValue(root, "metadata")
	if metadata != nil && metadata.Kind == yaml.MappingNode {
		identity := kind + "/" + mappingScalar(metadata, "name")
		if target, configured := expectedByIdentity[identity]; configured {
			seen[identity]++
			expectedImage := target.imageRepository + ":" + expectedVersion
			images, err := deploymentContainerImages(root)
			if err != nil {
				return fmt.Errorf("inspect operator image on %s: %w", identity, err)
			}
			repositoryReferences := 0
			exactReferences := 0
			for _, image := range images {
				if strings.HasPrefix(image, target.imageRepository+":") ||
					strings.HasPrefix(image, target.imageRepository+"@") {
					repositoryReferences++
				}
				if image == expectedImage {
					exactReferences++
				}
			}
			if repositoryReferences != 1 || exactReferences != 1 {
				return fmt.Errorf("%s operator image must be exactly %s", identity, expectedImage)
			}
		}
	}

	if kind != "List" && !strings.HasSuffix(kind, "List") {
		return nil
	}
	items := mappingValue(root, "items")
	if items == nil {
		return nil
	}
	if items.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s items must be a sequence", kind)
	}
	for index, item := range items.Content {
		if err := validateOperatorImageResource(item, expectedByIdentity, expectedVersion, seen); err != nil {
			return fmt.Errorf("%s item %d: %w", kind, index+1, err)
		}
	}
	return nil
}

func deploymentContainerImages(root *yaml.Node) ([]string, error) {
	spec := mappingValue(root, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode {
		return nil, errors.New("spec must be a mapping")
	}
	template := mappingValue(spec, "template")
	if template == nil || template.Kind != yaml.MappingNode {
		return nil, errors.New("spec.template must be a mapping")
	}
	podSpec := mappingValue(template, "spec")
	if podSpec == nil || podSpec.Kind != yaml.MappingNode {
		return nil, errors.New("spec.template.spec must be a mapping")
	}
	containers := mappingValue(podSpec, "containers")
	if containers == nil || containers.Kind != yaml.SequenceNode {
		return nil, errors.New("spec.template.spec.containers must be a sequence")
	}
	images := make([]string, 0, len(containers.Content))
	for index, container := range containers.Content {
		if container.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("container %d must be a mapping", index+1)
		}
		image := mappingScalar(container, "image")
		if image == "" {
			return nil, fmt.Errorf("container %d image must be a scalar", index+1)
		}
		images = append(images, image)
	}
	return images, nil
}

func stripConfiguredDispositions(input string, targets []targetSpec) (string, error) {
	hasTrailingNewline := strings.HasSuffix(input, "\n")
	trimmed := strings.TrimSuffix(input, "\n")
	lines := strings.Split(trimmed, "\n")
	targetsByIdentity := make(map[string]targetSpec, len(targets))
	for _, target := range targets {
		targetsByIdentity[target.kind+"/"+target.name] = target
	}
	removeLines := make(map[int]struct{})
	decoder := yaml.NewDecoder(strings.NewReader(input))
	for documentIndex := 1; ; documentIndex++ {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", fmt.Errorf("parse annotated document %d for stripping: %w", documentIndex, err)
		}
		if len(document.Content) == 0 || document.Content[0].Kind == 0 {
			continue
		}
		if err := walkManifestResources(document.Content[0], func(resource *yaml.Node) error {
			kind := mappingScalar(resource, "kind")
			_, metadata := mappingEntry(resource, "metadata")
			if metadata == nil || metadata.Kind != yaml.MappingNode {
				return nil
			}
			target, configured := targetsByIdentity[kind+"/"+mappingScalar(metadata, "name")]
			if !configured {
				return nil
			}
			annotationsKey, annotations := mappingEntry(metadata, "annotations")
			if annotations == nil || annotations.Kind != yaml.MappingNode {
				return errors.New("configured target annotations mapping is missing")
			}
			for index, check := range target.checks {
				annotationKey := "checkov.io/skip" + strconv.Itoa(index+1)
				key, value := mappingEntry(annotations, annotationKey)
				if key == nil || value == nil {
					return fmt.Errorf("configured disposition %s is missing", annotationKey)
				}
				expectedValue := check + "=" + target.reason
				expectedLine := fmt.Sprintf(
					"%s%s: %q",
					strings.Repeat(" ", key.Column-1),
					annotationKey,
					expectedValue,
				)
				if key.Line < 1 || key.Line > len(lines) || lines[key.Line-1] != expectedLine {
					return fmt.Errorf("configured disposition line %q is missing", expectedLine)
				}
				removeLines[key.Line-1] = struct{}{}
			}
			if len(annotations.Content)/2 == len(target.checks) {
				if annotationsKey.Line < 1 || annotationsKey.Line > len(lines) ||
					strings.TrimSpace(lines[annotationsKey.Line-1]) != "annotations:" {
					return errors.New("introduced annotations mapping line is missing")
				}
				removeLines[annotationsKey.Line-1] = struct{}{}
			}
			return nil
		}); err != nil {
			return "", fmt.Errorf("strip annotated document %d: %w", documentIndex, err)
		}
	}

	output := make([]string, 0, len(lines)-len(removeLines))
	for index, line := range lines {
		if _, remove := removeLines[index]; remove {
			continue
		}
		output = append(output, line)
	}
	result := strings.Join(output, "\n")
	if hasTrailingNewline {
		result += "\n"
	}
	return result, nil
}

func rejectInlineCheckovSuppression(node *yaml.Node) error {
	for _, comment := range []string{node.HeadComment, node.LineComment, node.FootComment} {
		if inlineCheckovSkip.MatchString(comment) {
			return errors.New("inline Checkov suppression")
		}
	}
	for _, child := range node.Content {
		if err := rejectInlineCheckovSuppression(child); err != nil {
			return err
		}
	}
	return nil
}

func rejectYAMLAlias(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode {
		return errors.New("YAML alias")
	}
	for _, child := range node.Content {
		if err := rejectYAMLAlias(child); err != nil {
			return err
		}
	}
	return nil
}

func rejectYAMLMergeKey(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Value == "<<" || key.Tag == "!!merge" {
				return errors.New("YAML merge key")
			}
		}
	}
	for _, child := range node.Content {
		if err := rejectYAMLMergeKey(child); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateYAMLMappingKeys(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return errors.New("non-scalar YAML mapping key")
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("duplicate YAML mapping key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := rejectDuplicateYAMLMappingKeys(child); err != nil {
			return err
		}
	}
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "annotate-vendored-checkov: "+format+"\n", args...)
	os.Exit(1)
}

func annotateBundle(input string, targets []targetSpec) (string, error) {
	if input == "" {
		return "", errors.New("bundle is empty")
	}

	hasTrailingNewline := strings.HasSuffix(input, "\n")
	trimmed := strings.TrimSuffix(input, "\n")
	lines := strings.Split(trimmed, "\n")
	documents := splitDocuments(lines)
	found := make(map[string]int, len(targets))
	output := make([]string, 0, len(lines)+len(targets)*10)

	for _, document := range documents {
		identity, err := readIdentity(document)
		if err != nil {
			return "", err
		}

		annotated := document
		if identity.Kind == "List" || strings.HasSuffix(identity.Kind, "List") {
			annotated, err = annotateListDocument(document, targets, found)
			if err != nil {
				return "", err
			}
			output = append(output, annotated...)
			continue
		}
		for _, target := range targets {
			if identity.Kind != target.kind || identity.Metadata.Name != target.name {
				continue
			}
			key := target.kind + "/" + target.name
			found[key]++
			annotated, err = annotateDocument(annotated, target)
			if err != nil {
				return "", fmt.Errorf("%s: %w", key, err)
			}
		}
		output = append(output, annotated...)
	}

	for _, target := range targets {
		key := target.kind + "/" + target.name
		if found[key] != 1 {
			return "", fmt.Errorf("expected exactly one %s, found %d", key, found[key])
		}
	}

	result := strings.Join(output, "\n")
	if hasTrailingNewline {
		result += "\n"
	}
	return result, nil
}

type lineInsertion struct {
	index int
	lines []string
}

func annotateListDocument(lines []string, targets []targetSpec, found map[string]int) ([]string, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &document); err != nil {
		return nil, fmt.Errorf("parse vendor List document: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("vendor List document must contain a top-level mapping")
	}
	var insertions []lineInsertion
	err := walkManifestResources(document.Content[0], func(resource *yaml.Node) error {
		kind := mappingScalar(resource, "kind")
		metadata := mappingValue(resource, "metadata")
		if metadata == nil || metadata.Kind != yaml.MappingNode {
			return nil
		}
		name := mappingScalar(metadata, "name")
		for _, target := range targets {
			if kind != target.kind || name != target.name {
				continue
			}
			identity := target.kind + "/" + target.name
			found[identity]++
			insertion, err := annotationInsertion(lines, resource, target)
			if err != nil {
				return fmt.Errorf("%s: %w", identity, err)
			}
			if len(insertion.lines) != 0 {
				insertions = append(insertions, insertion)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(insertions, func(left, right int) bool {
		return insertions[left].index > insertions[right].index
	})
	for _, insertion := range insertions {
		lines = insertLines(lines, insertion.index, insertion.lines)
	}
	return lines, nil
}

func annotationInsertion(lines []string, resource *yaml.Node, target targetSpec) (lineInsertion, error) {
	metadataKey, metadata := mappingEntry(resource, "metadata")
	if metadata == nil || metadata.Kind != yaml.MappingNode || metadata.Style&yaml.FlowStyle != 0 {
		return lineInsertion{}, errors.New("metadata must use block mapping style")
	}
	annotationsKey, annotations := mappingEntry(metadata, "annotations")
	if annotations == nil {
		metadataIndent := strings.Repeat(" ", metadataKey.Column-1+2)
		dispositionIndent := metadataIndent + "  "
		additions := []string{metadataIndent + "annotations:"}
		for index, check := range target.checks {
			value := check + "=" + target.reason
			additions = append(
				additions,
				fmt.Sprintf("%scheckov.io/skip%d: %q", dispositionIndent, index+1, value),
			)
		}
		return lineInsertion{index: metadataKey.Line, lines: additions}, nil
	}
	if annotations.Kind != yaml.MappingNode || annotations.Style&yaml.FlowStyle != 0 {
		return lineInsertion{}, errors.New("metadata.annotations must use block mapping style")
	}
	existing, highest, err := existingCheckovAnnotationNodes(annotations)
	if err != nil {
		return lineInsertion{}, err
	}
	indent := strings.Repeat(" ", annotationsKey.Column-1+2)
	additions := make([]string, 0, len(target.checks))
	for _, check := range target.checks {
		value := check + "=" + target.reason
		if existingValue, ok := existing[check]; ok {
			if existingValue != value {
				return lineInsertion{}, fmt.Errorf("%s already has a different disposition", check)
			}
			continue
		}
		highest++
		additions = append(additions, fmt.Sprintf("%scheckov.io/skip%d: %q", indent, highest, value))
	}
	insertAt, err := blockMappingEnd(lines, annotationsKey)
	if err != nil {
		return lineInsertion{}, err
	}
	return lineInsertion{index: insertAt, lines: additions}, nil
}

func existingCheckovAnnotationNodes(annotations *yaml.Node) (map[string]string, int, error) {
	existing := make(map[string]string)
	highest := 0
	for index := 0; index+1 < len(annotations.Content); index += 2 {
		key := annotations.Content[index]
		if !strings.HasPrefix(key.Value, "checkov.io/skip") {
			continue
		}
		number, err := strconv.Atoi(strings.TrimPrefix(key.Value, "checkov.io/skip"))
		if err != nil || number < 1 {
			return nil, 0, fmt.Errorf("invalid Checkov annotation key %q", key.Value)
		}
		if number > highest {
			highest = number
		}
		value := annotations.Content[index+1]
		if value.Kind != yaml.ScalarNode {
			return nil, 0, fmt.Errorf("%s value must be a scalar", key.Value)
		}
		parts := strings.SplitN(value.Value, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, 0, fmt.Errorf("%s has an invalid disposition", key.Value)
		}
		if _, duplicate := existing[parts[0]]; duplicate {
			return nil, 0, fmt.Errorf("duplicate disposition for %s", parts[0])
		}
		existing[parts[0]] = value.Value
	}
	return existing, highest, nil
}

func blockMappingEnd(lines []string, key *yaml.Node) (int, error) {
	if key.Line < 1 || key.Line > len(lines) || key.Column < 1 {
		return 0, errors.New("mapping key source position is invalid")
	}
	parentIndent := key.Column - 1
	end := key.Line
	for end < len(lines) {
		line := lines[end]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			end++
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent <= parentIndent {
			break
		}
		end++
	}
	return end, nil
}

func splitDocuments(lines []string) [][]string {
	starts := []int{0}
	for index, line := range lines {
		if index > 0 && yamlDocumentMarker.MatchString(line) {
			starts = append(starts, index)
		}
	}

	documents := make([][]string, 0, len(starts))
	for index, start := range starts {
		end := len(lines)
		if index+1 < len(starts) {
			end = starts[index+1]
		}
		documents = append(documents, append([]string(nil), lines[start:end]...))
	}
	return documents
}

func readIdentity(lines []string) (manifestIdentity, error) {
	var identity manifestIdentity
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &identity); err != nil {
		return identity, fmt.Errorf("parse vendor document: %w", err)
	}
	return identity, nil
}

func annotateDocument(lines []string, target targetSpec) ([]string, error) {
	if err := validateAnnotationStyle(lines); err != nil {
		return nil, err
	}

	metadataIndex := -1
	metadataEnd := len(lines)
	for index, line := range lines {
		if isBlockMappingLine(line, "metadata:") {
			if metadataIndex != -1 {
				return nil, errors.New("multiple top-level metadata mappings")
			}
			metadataIndex = index
			continue
		}
		if metadataIndex != -1 && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			metadataEnd = index
			break
		}
	}
	if metadataIndex == -1 {
		return nil, errors.New("top-level metadata mapping is missing")
	}

	annotationsIndex := -1
	annotationsEnd := metadataEnd
	for index := metadataIndex + 1; index < metadataEnd; index++ {
		if isBlockMappingLine(lines[index], "  annotations:") {
			if annotationsIndex != -1 {
				return nil, errors.New("multiple metadata.annotations mappings")
			}
			annotationsIndex = index
			continue
		}
		if annotationsIndex != -1 && lines[index] != "" && !strings.HasPrefix(lines[index], "    ") && !strings.HasPrefix(strings.TrimSpace(lines[index]), "#") {
			annotationsEnd = index
			break
		}
	}

	var insertAt int
	if annotationsIndex == -1 {
		annotationsIndex = metadataIndex + 1
		insertAt = annotationsIndex + 1
		lines = insertLines(lines, annotationsIndex, []string{"  annotations:"})
	} else {
		insertAt = annotationsEnd
	}

	existing, highest, err := existingCheckovAnnotations(lines, annotationsIndex+1, insertAt)
	if err != nil {
		return nil, err
	}
	additions := make([]string, 0, len(target.checks))
	for _, check := range target.checks {
		value := check + "=" + target.reason
		if existingValue, ok := existing[check]; ok {
			if existingValue != value {
				return nil, fmt.Errorf("%s already has a different disposition", check)
			}
			continue
		}
		highest++
		additions = append(additions, fmt.Sprintf("    checkov.io/skip%d: %q", highest, value))
	}
	if len(additions) == 0 {
		return lines, nil
	}

	return insertLines(lines, insertAt, additions), nil
}

func isBlockMappingLine(line, prefix string) bool {
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	remainder := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	return remainder == "" || strings.HasPrefix(remainder, "#")
}

func validateAnnotationStyle(lines []string) error {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &document); err != nil {
		return fmt.Errorf("parse vendor document: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("vendor document must contain a top-level mapping")
	}
	metadata := mappingValue(document.Content[0], "metadata")
	if metadata == nil || metadata.Kind != yaml.MappingNode {
		return errors.New("top-level metadata mapping is missing")
	}
	annotations := mappingValue(metadata, "annotations")
	if annotations == nil {
		return nil
	}
	if annotations.Kind != yaml.MappingNode || annotations.Style&yaml.FlowStyle != 0 {
		return errors.New("metadata.annotations must use block mapping style")
	}
	return nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	_, value := mappingEntry(mapping, key)
	return value
}

func mappingEntry(mapping *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index], mapping.Content[index+1]
		}
	}
	return nil, nil
}

func mappingScalar(mapping *yaml.Node, key string) string {
	value := mappingValue(mapping, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}

func walkManifestResources(root *yaml.Node, visit func(*yaml.Node) error) error {
	if root.Kind != yaml.MappingNode {
		return errors.New("manifest resource must be a mapping")
	}
	if err := visit(root); err != nil {
		return err
	}
	kind := mappingScalar(root, "kind")
	if kind != "List" && !strings.HasSuffix(kind, "List") {
		return nil
	}
	items := mappingValue(root, "items")
	if items == nil {
		return nil
	}
	if items.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s items must be a sequence", kind)
	}
	for index, item := range items.Content {
		if err := walkManifestResources(item, visit); err != nil {
			return fmt.Errorf("%s item %d: %w", kind, index+1, err)
		}
	}
	return nil
}

func existingCheckovAnnotations(lines []string, start, end int) (map[string]string, int, error) {
	existing := make(map[string]string)
	highest := 0
	for index := start; index < end; index++ {
		line := strings.TrimSpace(lines[index])
		if !strings.HasPrefix(line, "checkov.io/skip") {
			continue
		}
		key, rawValue, ok := strings.Cut(line, ":")
		if !ok {
			return nil, 0, fmt.Errorf("malformed Checkov annotation %q", line)
		}
		numberText := strings.TrimPrefix(key, "checkov.io/skip")
		number, err := strconv.Atoi(numberText)
		if err != nil || number < 1 {
			return nil, 0, fmt.Errorf("malformed Checkov annotation key %q", key)
		}
		if number > highest {
			highest = number
		}

		var value string
		if err := yaml.Unmarshal([]byte(strings.TrimSpace(rawValue)), &value); err != nil {
			return nil, 0, fmt.Errorf("parse %s: %w", key, err)
		}
		check, _, ok := strings.Cut(value, "=")
		if !ok || check == "" {
			return nil, 0, fmt.Errorf("%s does not name a Checkov check", key)
		}
		if _, duplicate := existing[check]; duplicate {
			return nil, 0, fmt.Errorf("duplicate disposition for %s", check)
		}
		existing[check] = value
	}
	return existing, highest, nil
}

func insertLines(lines []string, index int, additions []string) []string {
	result := make([]string, 0, len(lines)+len(additions))
	result = append(result, lines[:index]...)
	result = append(result, additions...)
	result = append(result, lines[index:]...)
	return result
}
