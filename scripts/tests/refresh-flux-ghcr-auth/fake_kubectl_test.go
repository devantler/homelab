package refreshfluxghcrauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type jsonPatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value"`
}

// fakeKubectlImplementation dispatches the kubectl operations exercised by the
// production-auth bridge tests against their filesystem-backed fake cluster.
func fakeKubectlImplementation(args []string) int {
	if flagValue(args, "--context") != "admin@prod" {
		return commandFailure(91, "kubectl must use the production context")
	}
	if calledFile := os.Getenv("KUBECTL_CALLED"); calledFile != "" {
		mustWriteCommandFile(calledFile, "")
	}

	namespace := flagValue(args, "--namespace")
	patchFile := flagValue(args, "--patch-file")
	manifestFile := flagValue(args, "--filename")
	if manifestFile == "" {
		manifestFile = flagValue(args, "-f")
	}

	switch {
	case containsArg(args, "--raw=/readyz"):
		appendEnvFile("OPERATION_LOG", "api-readyz\n")
		if markerExists("transient-node-ready-attempt-prod-worker-1") {
			attemptMarker := "post-reboot-api-ready-attempt"
			attempt := parseInt(markerContent(attemptMarker), 0) + 1
			setMarkerContent(attemptMarker, strconv.Itoa(attempt))
			failures := parseInt(os.Getenv("FAKE_POST_REBOOT_API_READY_FAILURES"), 0)
			if attempt <= failures {
				return commandFailure(
					54,
					"The connection to the server api.example.test:6443 was refused: connect: connection refused",
				)
			}
		}
		fmt.Println("ok")
		return 0
	case containsSequence(args, "get", "kustomizations.kustomize.toolkit.fluxcd.io"):
		return fakeKubectlGetFluxPolicyKustomization(args, namespace)
	case containsSequence(args, "patch", "kustomizations.kustomize.toolkit.fluxcd.io"):
		return fakeKubectlPatchFluxPolicyKustomization(args, namespace, patchFile)
	case containsSequence(args, "get", "deployment.apps"):
		return fakeKubectlGetFluxControllerDeployment(args, namespace)
	case containsSequence(args, "patch", "deployment.apps"):
		return fakeKubectlPatchFluxControllerDeployment(args, namespace, patchFile)
	case containsSequence(args, "rollout", "status"):
		return fakeKubectlRolloutFluxController(args, namespace)
	case containsSequence(args, "get", "pods") &&
		flagValue(args, "--selector") == "app=kustomize-controller":
		return fakeKubectlGetFluxControllerPods(namespace)
	case containsSequence(args, "get", "namespace"):
		return fakeKubectlGetNamespace(args)
	case containsSequence(args, "get", "lease"):
		return fakeKubectlGetSyncLease(args, namespace)
	case containsSequence(args, "patch", "lease"):
		return fakeKubectlPatchSyncLease(args, namespace, patchFile)
	case containsArg(args, "create") && manifestFile != "" && fakeManifestKind(manifestFile) == "Lease":
		return fakeKubectlCreateSyncLease(namespace, manifestFile)
	case containsSequence(args, "delete", "imagevalidatingpolicy.policies.kyverno.io"):
		return fakeKubectlDeleteRetiredImageValidatingPolicy(args)
	case containsSequence(args, "patch", "imagevalidatingpolicy.policies.kyverno.io"):
		return fakeKubectlPatchConsolidatedImageValidatingPolicy(args, patchFile)
	case containsSequence(args, "get", "mutatingwebhookconfigurations.admissionregistration.k8s.io"):
		return fakeKubectlGetImageVerificationWebhooks("mutate")
	case containsSequence(args, "get", "validatingwebhookconfigurations.admissionregistration.k8s.io"):
		return fakeKubectlGetImageVerificationWebhooks("validate")
	case containsSequence(args, "get", "nodes"):
		return fakeKubectlGetNodes()
	case containsSequence(args, "get", "pods"):
		return fakeKubectlGetPods(args)
	case containsSequence(args, "get", "node"):
		return fakeKubectlGetNode(args)
	case containsArg(args, "drain"):
		return fakeKubectlDrain(args)
	case containsArg(args, "uncordon"):
		return fakeKubectlUncordon(args)
	case containsSequence(args, "patch", "node") && containsArg(args, "--type=json"):
		return fakeKubectlPatchNode(args, patchFile)
	case containsArg(args, "cordon"):
		return fakeKubectlCordon(args)
	case containsArg(args, "wait"):
		return fakeKubectlWaitForNode(args)
	case containsArg(args, "create") && manifestFile != "":
		return fakeKubectlCreateRuntimeProbe(namespace, manifestFile)
	case containsSequence(args, "get", "pod"):
		return fakeKubectlGetRuntimeProbe(args)
	case containsSequence(args, "delete", "pod"):
		return fakeKubectlDeleteRuntimeProbe(args)
	}

	if namespace == "" {
		return commandFailure(91, "namespaced kubectl invocation omitted namespace")
	}

	switch {
	case containsSequence(args, "get", "secret", "ksail-registry-credentials") && containsSequence(args, "-o", "json"):
		return fakeKubectlGetRootSecret()
	case containsArg(args, "api-resources"):
		return fakeKubectlAPIResources(args)
	case containsSequence(args, "patch", "secret", "ksail-registry-credentials"):
		return fakeKubectlPatchRootSecret(args, patchFile)
	case containsSequence(args, "get", "secret", "variables-base"):
		return fakeKubectlGetVariablesBase(args)
	case containsSequence(args, "patch", "secret", "variables-base"):
		return fakeKubectlPatchVariablesBase(args, patchFile)
	}

	kind, name := fanoutResource(args)
	if kind != "" {
		return fakeKubectlFanoutResource(args, namespace, kind, name)
	}
	if containsSequence(args, "get", "secret", "ghcr-auth") {
		return fakeKubectlGetConsumerSecret(namespace)
	}

	return commandFailure(91, "unexpected kubectl invocation: %s", strings.Join(args, " "))
}

func fakeKubectlGetNamespace(args []string) int {
	name := argumentAfter(args, "namespace")
	if name == "" {
		return commandFailure(91, "namespace name is required")
	}
	if containsArg(args, "--ignore-not-found") && name == os.Getenv("FAKE_MISSING_NAMESPACE") {
		return 0
	}
	fmt.Printf("namespace/%s\n", name)
	return 0
}

func fakeKubectlGetFluxPolicyKustomization(args []string, namespace string) int {
	name := argumentAfter(args, "kustomizations.kustomize.toolkit.fluxcd.io")
	if name == "flux-system" && containsArg(args, "infrastructure") {
		return fakeKubectlGetFluxPolicyFences(args, namespace)
	}
	if name == "flux-system" {
		return fakeKubectlGetFluxPolicyParent(args, namespace)
	}
	if namespace == "flux-system" &&
		name == os.Getenv("FAKE_FLUX_POLICY_CHILD_DEPENDENCY_NOT_READY") &&
		name != "" {
		if os.Getenv("FAKE_FLUX_POLICY_DEPENDENCY_READ_FAILS") == "true" {
			return commandFailure(1, "Error from server (NotFound): kustomizations.kustomize.toolkit.fluxcd.io %q not found", name)
		}
		fmt.Println(encodeJSON(fakeFluxPolicyDependencyObject(name)))
		return 0
	}
	if namespace != "flux-system" ||
		name != "infrastructure" ||
		(!containsArg(args, "-o") && !containsArg(args, "--output")) {
		return commandFailure(91, "invalid Flux policy Kustomization lookup")
	}
	fmt.Println(encodeJSON(fakeFluxPolicyChildObject()))
	return 0
}

// fakeFluxPolicyDependencyObject models a Kustomization the handoff owner
// depends on, still reconciling with the message that names the real blocker.
func fakeFluxPolicyDependencyObject(name string) map[string]any {
	return map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "flux-system",
			"uid":       name + "-kustomization-uid",
		},
		"spec": map[string]any{"suspend": false},
		"status": map[string]any{
			"conditions": []any{
				map[string]any{
					"type":    "Reconciling",
					"status":  "True",
					"reason":  "ProgressingWithRetry",
					"message": os.Getenv("FAKE_FLUX_POLICY_DEPENDENCY_BLOCKING_MESSAGE"),
				},
				map[string]any{
					"type":    "Ready",
					"status":  "False",
					"reason":  "HealthCheckFailed",
					"message": os.Getenv("FAKE_FLUX_POLICY_DEPENDENCY_BLOCKING_MESSAGE"),
				},
			},
		},
	}
}

func fakeFluxPolicyChildObject() map[string]any {
	owner := markerContent("flux-policy-handoff-owner")
	if owner == "" && os.Getenv("FAKE_FLUX_POLICY_HANDOFF_OWNED") == "true" {
		owner = "other-live-transaction"
	}
	annotations := map[string]any{
		"reconcile.fluxcd.io/requestedAt": "fixture",
	}
	if owner != "" {
		annotations["platform.devantler.tech/ghcr-policy-handoff-owner"] = owner
	}
	if markerExists("flux-policy-handoff-suspended") {
		annotations["kustomize.toolkit.fluxcd.io/reconcile"] = "disabled"
	}
	generation := 13
	suspended := markerExists("flux-policy-handoff-suspended")
	if suspended {
		generation = 14
	}
	metadata := map[string]any{
		"name":            "infrastructure",
		"namespace":       "flux-system",
		"uid":             "infrastructure-kustomization-uid",
		"resourceVersion": defaultString(markerContent("flux-policy-handoff-resource-version"), "20"),
		"generation":      generation,
	}
	if os.Getenv("FAKE_FLUX_POLICY_HANDOFF_NO_ANNOTATIONS") != "true" || owner != "" {
		metadata["annotations"] = annotations
	}
	readyCondition := map[string]any{
		"type":   "Ready",
		"status": "True",
		"reason": "ReconciliationSucceeded",
	}
	spec := map[string]any{"suspend": suspended}
	if unhealthy := os.Getenv("FAKE_FLUX_POLICY_CHILD_UNHEALTHY"); unhealthy != "" {
		readyCondition = map[string]any{
			"type":    "Ready",
			"status":  "False",
			"reason":  "HealthCheckFailed",
			"message": unhealthy,
		}
	}
	if dependency := os.Getenv("FAKE_FLUX_POLICY_CHILD_DEPENDENCY_NOT_READY"); dependency != "" {
		readyCondition = map[string]any{
			"type":    "Ready",
			"status":  "False",
			"reason":  "DependencyNotReady",
			"message": fmt.Sprintf("dependency 'flux-system/%s' is not ready", dependency),
		}
		spec["dependsOn"] = []any{map[string]any{"name": dependency}}
	}
	conditions := []any{readyCondition}
	reconciling := os.Getenv("FAKE_FLUX_POLICY_RECONCILING") == "true"
	if suspended && os.Getenv("FAKE_FLUX_POLICY_RECONCILING_AFTER_PAUSE") == "true" {
		reconciling = true
	}
	if !suspended {
		readCount := parseInt(markerContent("flux-policy-child-read-count"), 0) + 1
		setMarkerContent("flux-policy-child-read-count", strconv.Itoa(readCount))
		reconcilingReads := parseInt(
			os.Getenv("FAKE_FLUX_POLICY_RECONCILING_READS_BEFORE_PAUSE"),
			0,
		)
		if readCount <= reconcilingReads {
			reconciling = true
			appendEnvFile("OPERATION_LOG", "flux-policy-child-reconciling:infrastructure\n")
		} else if reconcilingReads > 0 &&
			!markerExists("flux-policy-child-stable-logged") {
			touchMarker("flux-policy-child-stable-logged")
			appendEnvFile("OPERATION_LOG", "flux-policy-child-stable:infrastructure\n")
		}
	}
	if reconciling {
		reconcilingCondition := map[string]any{
			"type":   "Reconciling",
			"status": "True",
			"reason": defaultString(os.Getenv("FAKE_FLUX_POLICY_RECONCILING_REASON"), "Progressing"),
		}
		if message := os.Getenv("FAKE_FLUX_POLICY_RECONCILING_MESSAGE"); message != "" {
			reconcilingCondition["message"] = message
		}
		conditions = append(conditions, reconcilingCondition)
	}
	return map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata":   metadata,
		"spec":       spec,
		"status": map[string]any{
			"observedGeneration": 13,
			"conditions":         conditions,
		},
	}
}

func fakeKubectlPatchFluxPolicyKustomization(args []string, namespace, patchFile string) int {
	name := argumentAfter(args, "kustomizations.kustomize.toolkit.fluxcd.io")
	if name == "flux-system" {
		return fakeKubectlPatchFluxPolicyParent(args, namespace, patchFile)
	}
	if namespace != "flux-system" ||
		name != "infrastructure" ||
		!containsArg(args, "--type=json") || patchFile == "" {
		return commandFailure(91, "invalid Flux policy Kustomization patch")
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse Flux policy Kustomization patch: %v", err)
	}
	currentResourceVersion := defaultString(
		markerContent("flux-policy-handoff-resource-version"),
		"20",
	)
	if !hasPatchOperation(
		patch,
		"test",
		"/metadata/uid",
		"infrastructure-kustomization-uid",
	) {
		return commandFailure(56, "Flux policy Kustomization CAS failed")
	}

	ownerPath := "/metadata/annotations/platform.devantler.tech~1ghcr-policy-handoff-owner"
	reconcilePath := "/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile"
	if hasPatchOperation(patch, "add", "/spec/suspend", true) {
		owner := patchValueString(patch, "add", ownerPath)
		if !hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) ||
			owner == "" ||
			!hasPatchOperation(patch, "add", reconcilePath, "disabled") ||
			(os.Getenv("FAKE_FLUX_POLICY_HANDOFF_NO_ANNOTATIONS") == "true" &&
				!hasPatchOperation(patch, "add", "/metadata/annotations", map[string]any{})) ||
			markerExists("flux-policy-handoff-owner") {
			return commandFailure(56, "invalid or conflicting Flux policy handoff acquisition")
		}
		setMarkerContent("flux-policy-handoff-owner", owner)
		touchMarker("flux-policy-handoff-suspended")
		setMarkerContent(
			"flux-policy-handoff-resource-version",
			incrementDecimal(currentResourceVersion),
		)
		appendEnvFile("OPERATION_LOG", "flux-policy-pause:infrastructure\n")
		if os.Getenv("FAKE_FLUX_POLICY_HANDOFF_PATCH_RESPONSE_LOST") == "true" &&
			!markerExists("flux-policy-handoff-patch-response-lost") {
			touchMarker("flux-policy-handoff-patch-response-lost")
			return commandFailure(54, "connection reset after policy handoff patch")
		}
		return fakeKubectlGetFluxPolicyKustomization(
			[]string{
				"get",
				"kustomizations.kustomize.toolkit.fluxcd.io",
				"infrastructure",
				"-o",
				"json",
			},
			namespace,
		)
	}

	currentOwner := markerContent("flux-policy-handoff-owner")
	if currentOwner == "" ||
		!markerExists("flux-policy-handoff-suspended") ||
		!hasPatchOperation(patch, "test", ownerPath, currentOwner) ||
		!hasPatchOperation(patch, "test", reconcilePath, "disabled") ||
		!hasPatchOperation(patch, "test", "/spec/suspend", true) ||
		!hasPatchOperation(patch, "add", "/spec/suspend", false) ||
		!hasPatchPath(patch, "remove", ownerPath) ||
		!hasPatchPath(patch, "remove", reconcilePath) {
		return commandFailure(56, "invalid Flux policy handoff release")
	}
	if os.Getenv("FAKE_FLUX_POLICY_HANDOFF_RELEASE_FAIL") == "true" {
		return commandFailure(56, "persistent Flux policy handoff release failure")
	}
	removeMarker("flux-policy-handoff-owner")
	removeMarker("flux-policy-handoff-suspended")
	setMarkerContent(
		"flux-policy-handoff-resource-version",
		incrementDecimal(currentResourceVersion),
	)
	appendEnvFile("OPERATION_LOG", "flux-policy-resume:infrastructure\n")
	if os.Getenv("FAKE_FLUX_POLICY_HANDOFF_RELEASE_RESPONSE_LOST") == "true" &&
		!markerExists("flux-policy-handoff-release-response-lost") {
		touchMarker("flux-policy-handoff-release-response-lost")
		return commandFailure(54, "connection reset after policy handoff release")
	}
	fmt.Println("kustomization.kustomize.toolkit.fluxcd.io/infrastructure patched")
	return 0
}

func fakeKubectlGetFluxPolicyParent(args []string, namespace string) int {
	if namespace != "flux-system" ||
		(!containsArg(args, "-o") && !containsArg(args, "--output")) {
		return commandFailure(91, "invalid parent Flux Kustomization lookup")
	}
	fmt.Println(encodeJSON(fakeFluxPolicyParentObject()))
	return 0
}

func fakeFluxPolicyParentObject() map[string]any {
	owner := markerContent("flux-policy-parent-owner")
	annotations := map[string]any{
		"reconcile.fluxcd.io/requestedAt": "fixture",
	}
	if owner != "" {
		annotations["platform.devantler.tech/ghcr-policy-parent-owner"] = owner
	}
	suspended := markerExists("flux-policy-parent-suspended")
	metadata := map[string]any{
		"name":            "flux-system",
		"namespace":       "flux-system",
		"uid":             "flux-system-kustomization-uid",
		"resourceVersion": defaultString(markerContent("flux-policy-parent-resource-version"), "30"),
		"generation":      1,
	}
	if os.Getenv("FAKE_FLUX_POLICY_PARENT_NO_ANNOTATIONS") != "true" || owner != "" {
		metadata["annotations"] = annotations
	}
	conditions := []any{
		map[string]any{
			"type":   "Ready",
			"status": "True",
			"reason": "ReconciliationSucceeded",
		},
	}
	if suspended {
		readCount := parseInt(markerContent("flux-policy-parent-suspended-read-count"), 0) + 1
		setMarkerContent("flux-policy-parent-suspended-read-count", strconv.Itoa(readCount))
		if os.Getenv("FAKE_FLUX_PARENT_RECONCILING_AFTER_PAUSE") == "true" &&
			readCount <= 2 {
			conditions = append(conditions, map[string]any{
				"type":   "Reconciling",
				"status": "True",
				"reason": "Progressing",
			})
			appendEnvFile("OPERATION_LOG", "flux-policy-parent-reconciling:flux-system\n")
		} else if !markerExists("flux-policy-parent-stable-logged") {
			touchMarker("flux-policy-parent-stable-logged")
			appendEnvFile("OPERATION_LOG", "flux-policy-parent-stable:flux-system\n")
		}
	}
	return map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		"kind":       "Kustomization",
		"metadata":   metadata,
		"spec": map[string]any{
			"suspend": suspended,
		},
		"status": map[string]any{
			"observedGeneration": 1,
			"conditions":         conditions,
		},
	}
}

func fakeKubectlGetFluxPolicyFences(args []string, namespace string) int {
	if namespace != "flux-system" ||
		(!containsArg(args, "-o") && !containsArg(args, "--output")) {
		return commandFailure(91, "invalid Flux policy fence list lookup")
	}
	if markerExists("flux-policy-handoff-suspended") &&
		os.Getenv("FAKE_FLUX_POLICY_RESOURCE_VERSION_CHURN_AFTER_PAUSE") == "true" {
		currentResourceVersion := defaultString(
			markerContent("flux-policy-handoff-resource-version"),
			"20",
		)
		setMarkerContent(
			"flux-policy-handoff-resource-version",
			incrementDecimal(currentResourceVersion),
		)
	}
	fmt.Println(encodeJSON(map[string]any{
		"apiVersion": "v1",
		"kind":       "List",
		"items": []any{
			fakeFluxPolicyParentObject(),
			fakeFluxPolicyChildObject(),
		},
	}))
	return 0
}

func fakeKubectlPatchFluxPolicyParent(args []string, namespace, patchFile string) int {
	if namespace != "flux-system" ||
		!containsArg(args, "--type=json") || patchFile == "" {
		return commandFailure(91, "invalid parent Flux Kustomization patch")
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse parent Flux Kustomization patch: %v", err)
	}
	currentResourceVersion := defaultString(
		markerContent("flux-policy-parent-resource-version"),
		"30",
	)
	if !hasPatchOperation(
		patch,
		"test",
		"/metadata/uid",
		"flux-system-kustomization-uid",
	) {
		return commandFailure(56, "parent Flux Kustomization UID test failed")
	}
	ownerPath := "/metadata/annotations/platform.devantler.tech~1ghcr-policy-parent-owner"
	if hasPatchOperation(patch, "add", "/spec/suspend", true) {
		if rejection := os.Getenv("FAKE_FLUX_POLICY_PARENT_PATCH_REJECTION"); rejection != "" {
			appendEnvFile("OPERATION_LOG", "flux-policy-parent-patch-rejected\n")
			return commandFailure(56, "%s", rejection)
		}
		owner := patchValueString(patch, "add", ownerPath)
		if !hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) ||
			owner == "" ||
			(os.Getenv("FAKE_FLUX_POLICY_PARENT_NO_ANNOTATIONS") == "true" &&
				!hasPatchOperation(patch, "add", "/metadata/annotations", map[string]any{})) ||
			markerExists("flux-policy-parent-owner") {
			return commandFailure(56, "invalid or conflicting parent Flux handoff acquisition")
		}
		setMarkerContent("flux-policy-parent-owner", owner)
		touchMarker("flux-policy-parent-suspended")
		setMarkerContent(
			"flux-policy-parent-resource-version",
			incrementDecimal(currentResourceVersion),
		)
		appendEnvFile("OPERATION_LOG", "flux-policy-parent-pause:flux-system\n")
		if os.Getenv("FAKE_FLUX_POLICY_PARENT_PATCH_RESPONSE_LOST") == "true" &&
			!markerExists("flux-policy-parent-patch-response-lost") {
			touchMarker("flux-policy-parent-patch-response-lost")
			return commandFailure(54, "connection reset after parent Flux handoff patch")
		}
		return fakeKubectlGetFluxPolicyKustomization(
			[]string{
				"get",
				"kustomizations.kustomize.toolkit.fluxcd.io",
				"flux-system",
				"-o",
				"json",
			},
			namespace,
		)
	}

	currentOwner := markerContent("flux-policy-parent-owner")
	if currentOwner == "" ||
		!markerExists("flux-policy-parent-suspended") ||
		!hasPatchOperation(patch, "test", ownerPath, currentOwner) ||
		!hasPatchOperation(patch, "test", "/spec/suspend", true) ||
		!hasPatchOperation(patch, "add", "/spec/suspend", false) ||
		!hasPatchPath(patch, "remove", ownerPath) {
		return commandFailure(56, "invalid parent Flux handoff release")
	}
	removeMarker("flux-policy-parent-owner")
	removeMarker("flux-policy-parent-suspended")
	setMarkerContent(
		"flux-policy-parent-resource-version",
		incrementDecimal(currentResourceVersion),
	)
	appendEnvFile("OPERATION_LOG", "flux-policy-parent-resume:flux-system\n")
	if os.Getenv("FAKE_FLUX_POLICY_PARENT_RELEASE_RESPONSE_LOST") == "true" &&
		!markerExists("flux-policy-parent-release-response-lost") {
		touchMarker("flux-policy-parent-release-response-lost")
		return commandFailure(54, "connection reset after parent Flux handoff release")
	}
	fmt.Println("kustomization.kustomize.toolkit.fluxcd.io/flux-system patched")
	return 0
}

func fakeFluxControllerDeploymentObject() map[string]any {
	restartCount := parseInt(markerContent("flux-controller-restart-count"), 0)
	resourceVersion := strconv.Itoa(40 + restartCount)
	generation := 7 + restartCount
	annotations := map[string]any{
		"prometheus.io/port": "8080",
	}
	if restartCount > 0 {
		annotations["kubectl.kubernetes.io/restartedAt"] = markerContent(
			"flux-controller-restart-token",
		)
	}
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":            "kustomize-controller",
			"namespace":       "flux-system",
			"uid":             "kustomize-controller-deployment-uid",
			"resourceVersion": resourceVersion,
			"generation":      generation,
		},
		"spec": map[string]any{
			"replicas": 1,
			"selector": map[string]any{
				"matchLabels": map[string]any{"app": "kustomize-controller"},
			},
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": annotations,
					"labels":      map[string]any{"app": "kustomize-controller"},
				},
			},
		},
		"status": map[string]any{
			"availableReplicas": 1,
			"updatedReplicas":   1,
		},
	}
}

func fakeKubectlGetFluxControllerDeployment(args []string, namespace string) int {
	if namespace != "flux-system" ||
		argumentAfter(args, "deployment.apps") != "kustomize-controller" ||
		(!containsArg(args, "-o") && !containsArg(args, "--output")) {
		return commandFailure(91, "invalid kustomize-controller Deployment lookup")
	}
	fmt.Println(encodeJSON(fakeFluxControllerDeploymentObject()))
	return 0
}

func fakeKubectlPatchFluxControllerDeployment(args []string, namespace, patchFile string) int {
	if namespace != "flux-system" ||
		argumentAfter(args, "deployment.apps") != "kustomize-controller" ||
		!containsArg(args, "--type=json") || patchFile == "" {
		return commandFailure(91, "invalid kustomize-controller Deployment patch")
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse kustomize-controller restart patch: %v", err)
	}
	restartPath := "/spec/template/metadata/annotations/kubectl.kubernetes.io~1restartedAt"
	restartToken := patchValueString(patch, "add", restartPath)
	restartCount := parseInt(markerContent("flux-controller-restart-count"), 0)
	currentResourceVersion := strconv.Itoa(40 + restartCount)
	if !hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) ||
		!hasPatchOperation(
			patch,
			"test",
			"/metadata/uid",
			"kustomize-controller-deployment-uid",
		) || restartToken == "" {
		return commandFailure(56, "invalid or conflicting kustomize-controller restart")
	}
	setMarkerContent("flux-controller-restart-token", restartToken)
	setMarkerContent("flux-controller-restart-count", strconv.Itoa(restartCount+1))
	if os.Getenv("FAKE_LOG_FLUX_CONTROLLER_RESTART") == "true" {
		appendEnvFile("OPERATION_LOG", "flux-controller-restart:kustomize-controller\n")
	}
	if os.Getenv("FAKE_FLUX_CONTROLLER_RESTART_RESPONSE_LOST") == "true" &&
		!markerExists("flux-controller-restart-response-lost") {
		touchMarker("flux-controller-restart-response-lost")
		return commandFailure(54, "connection reset after kustomize-controller restart patch")
	}
	fmt.Println(encodeJSON(fakeFluxControllerDeploymentObject()))
	return 0
}

func fakeKubectlRolloutFluxController(args []string, namespace string) int {
	restartCount := parseInt(markerContent("flux-controller-restart-count"), 0)
	rolloutCount := parseInt(markerContent("flux-controller-rollout-count"), 0)
	if namespace != "flux-system" ||
		!containsArg(args, "deployment.apps/kustomize-controller") ||
		flagValue(args, "--timeout") != "2m" ||
		restartCount != rolloutCount+1 {
		return commandFailure(91, "invalid kustomize-controller rollout status")
	}
	if os.Getenv("FAKE_FLUX_CONTROLLER_ROLLOUT_FAIL") == "true" {
		return commandFailure(56, "kustomize-controller rollout did not converge")
	}
	setMarkerContent("flux-controller-rollout-count", strconv.Itoa(restartCount))
	if os.Getenv("FAKE_LOG_FLUX_CONTROLLER_RESTART") == "true" {
		if os.Getenv("FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING") == "true" {
			appendEnvFile(
				"OPERATION_LOG",
				"flux-controller-rollout-complete-with-terminating-old-pod:kustomize-controller\n",
			)
		} else {
			appendEnvFile(
				"OPERATION_LOG",
				"flux-controller-old-processes-terminated:kustomize-controller\n",
			)
		}
	}
	fmt.Println("deployment.apps/kustomize-controller successfully rolled out")
	return 0
}

func fakeKubectlGetFluxControllerPods(namespace string) int {
	if namespace != "flux-system" {
		return commandFailure(91, "invalid kustomize-controller Pod lookup")
	}
	rolloutCount := parseInt(markerContent("flux-controller-rollout-count"), 0)
	uid := fmt.Sprintf("kustomize-controller-pod-uid-%d", rolloutCount)
	name := fmt.Sprintf("kustomize-controller-%d", rolloutCount)
	items := []any{map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "flux-system",
			"uid":       uid,
			"labels":    map[string]any{"app": "kustomize-controller"},
		},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":   "Ready",
				"status": "True",
			}},
		},
	}}
	// A pre-handoff Pod that lingers for a bounded number of samples and then disappears models
	// the real termination grace period: the rollout is correct, the old Pod is simply not gone
	// yet at the first sample. Distinct from FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING, where it
	// never goes away and must keep failing.
	terminatingSamples := parseInt(os.Getenv("FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING_SAMPLES"), 0)
	if rolloutCount > 0 && terminatingSamples > 0 {
		observed := parseInt(markerContent("flux-controller-pod-sample-count"), 0) + 1
		setMarkerContent("flux-controller-pod-sample-count", strconv.Itoa(observed))
		if observed > terminatingSamples {
			terminatingSamples = 0
		}
	}
	if rolloutCount > 0 &&
		(terminatingSamples > 0 ||
			os.Getenv("FAKE_FLUX_CONTROLLER_OLD_POD_TERMINATING") == "true") {
		items = append(items, map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":              fmt.Sprintf("kustomize-controller-%d", rolloutCount-1),
				"namespace":         "flux-system",
				"uid":               fmt.Sprintf("kustomize-controller-pod-uid-%d", rolloutCount-1),
				"labels":            map[string]any{"app": "kustomize-controller"},
				"deletionTimestamp": "2026-08-03T09:30:00Z",
			},
			"status": map[string]any{
				"conditions": []any{map[string]any{
					"type":   "Ready",
					"status": "False",
				}},
			},
		})
	}
	fmt.Println(encodeJSON(map[string]any{
		"apiVersion": "v1",
		"kind":       "List",
		"items":      items,
	}))
	return 0
}

func fakeKubectlPatchConsolidatedImageValidatingPolicy(args []string, patchFile string) int {
	if argumentAfter(args, "imagevalidatingpolicy.policies.kyverno.io") != "verify-app-images" ||
		!containsArg(args, "--type=merge") || patchFile == "" {
		return commandFailure(91, "invalid consolidated image-validating policy patch")
	}
	var patch map[string]any
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse consolidated image-validating policy patch: %v", err)
	}
	spec, _ := patch["spec"].(map[string]any)
	webhookConfiguration, _ := spec["webhookConfiguration"].(map[string]any)
	attestors, _ := spec["attestors"].([]any)
	if webhookConfiguration["timeoutSeconds"] != float64(30) || len(attestors) != 4 {
		return commandFailure(91, "consolidated image-validating policy patch omitted its timeout or attestors")
	}
	storageAttestorValid := false
	for _, rawAttestor := range attestors {
		attestor, _ := rawAttestor.(map[string]any)
		if attestor["name"] != "publishkubescapestorage" {
			continue
		}
		cosign, _ := attestor["cosign"].(map[string]any)
		keyless, _ := cosign["keyless"].(map[string]any)
		identities, _ := keyless["identities"].([]any)
		if len(identities) != 1 {
			break
		}
		identity, _ := identities[0].(map[string]any)
		storageAttestorValid = identity["issuer"] == "https://token.actions.githubusercontent.com" &&
			identity["subjectRegExp"] == "^https://github\\.com/devantler-tech/platform/\\.github/workflows/publish-kubescape-storage-hotfix\\.yaml@refs/heads/main$"
	}
	validations, _ := spec["validations"].([]any)
	genericExcludesStorage := false
	dedicatedRoutesStorage := false
	for _, rawValidation := range validations {
		validation, _ := rawValidation.(map[string]any)
		expression, _ := validation["expression"].(string)
		if strings.Contains(expression, "attestors.publishapp") {
			genericExcludesStorage = strings.Contains(expression, "image != 'ghcr.io/devantler-tech/platform-kubescape-storage'") &&
				strings.Contains(expression, "!image.startsWith('ghcr.io/devantler-tech/platform-kubescape-storage:')") &&
				strings.Contains(expression, "!image.startsWith('ghcr.io/devantler-tech/platform-kubescape-storage@')")
		}
		if strings.Contains(expression, "attestors.publishkubescapestorage") {
			dedicatedRoutesStorage = strings.Contains(expression, "image == 'ghcr.io/devantler-tech/platform-kubescape-storage'") &&
				strings.Contains(expression, "image.startsWith('ghcr.io/devantler-tech/platform-kubescape-storage:')") &&
				strings.Contains(expression, "image.startsWith('ghcr.io/devantler-tech/platform-kubescape-storage@')")
		}
	}
	if !storageAttestorValid || !genericExcludesStorage || !dedicatedRoutesStorage {
		return commandFailure(91, "consolidated image-validating policy patch omitted the dedicated storage publisher identity or exact repository routing")
	}
	if containsArg(args, "--dry-run=server") {
		if os.Getenv("FAKE_IMAGE_VERIFICATION_POLICY_DRY_RUN_FAILURE") == "true" {
			return commandFailure(92, "candidate consolidated image-validating policy rejected")
		}
		appendEnvFile("OPERATION_LOG", "ivpol-policy-dry-run:verify-app-images\n")
		fmt.Println("imagevalidatingpolicy.policies.kyverno.io/verify-app-images server-side patch dry-run")
		return 0
	}
	touchMarker("ivpol-policy-verify-app-images")
	appendEnvFile("OPERATION_LOG", "ivpol-policy-apply:verify-app-images\n")
	fmt.Println("imagevalidatingpolicy.policies.kyverno.io/verify-app-images serverside-applied")
	return 0
}

func fakeKubectlDeleteRetiredImageValidatingPolicy(args []string) int {
	if argumentAfter(args, "imagevalidatingpolicy.policies.kyverno.io") != "verify-ksail-images" ||
		!containsArg(args, "--ignore-not-found") {
		return commandFailure(91, "invalid retired image-validating policy delete")
	}
	if os.Getenv("FAKE_IMAGE_VERIFICATION_POLICY_DELETE_FAILURE") == "true" {
		return commandFailure(92, "retired image-validating policy delete failed")
	}
	touchMarker("ivpol-policy-verify-ksail-images-deleted")
	appendEnvFile("OPERATION_LOG", "ivpol-policy-delete:verify-ksail-images\n")
	fmt.Println("imagevalidatingpolicy.policies.kyverno.io/verify-ksail-images deleted")
	return 0
}

func fakeKubectlGetImageVerificationWebhooks(operation string) int {
	stale := os.Getenv("FAKE_IMAGE_VERIFICATION_WEBHOOKS_STALE") == "true"
	consolidated := markerExists("ivpol-policy-verify-app-images")
	if stale && !markerExists("ivpol-consolidated-observed") {
		consolidated = false
		if operation == "validate" {
			touchMarker("ivpol-consolidated-observed")
		}
	}
	failurePolicy := "Fail"
	if os.Getenv("FAKE_IMAGE_VERIFICATION_WEBHOOKS_FAIL_OPEN") == "true" ||
		(operation == "validate" &&
			os.Getenv("FAKE_IMAGE_VERIFICATION_VALIDATING_WEBHOOK_FAIL_OPEN") == "true") {
		failurePolicy = "Ignore"
	}
	if os.Getenv("FAKE_IMAGE_VERIFICATION_WEBHOOKS_NEVER_CONVERGE") == "true" {
		consolidated = false
	}
	var webhooks []any
	if !markerExists("ivpol-policy-verify-ksail-images-deleted") {
		webhooks = append(webhooks, map[string]any{
			"name": operation + ".ivpol.kyverno.svc-fail",
			"clientConfig": map[string]any{
				"service": map[string]any{
					"name":      "kyverno-svc",
					"namespace": "kyverno",
					"path":      "/ivpol/" + operation + "/verify-ksail-images",
				},
			},
			"failurePolicy":  failurePolicy,
			"timeoutSeconds": 10,
		})
	}
	mutationRequired := os.Getenv("FAKE_IMAGE_VERIFICATION_MUTATION_REQUIRED") == "true"
	if consolidated && (operation != "mutate" || mutationRequired) {
		webhooks = append(webhooks, map[string]any{
			"name": operation + ".verify-app-images.ivpol.kyverno.svc-fail",
			"clientConfig": map[string]any{
				"service": map[string]any{
					"name":      "kyverno-svc",
					"namespace": "kyverno",
					"path":      "/ivpol/" + operation + "/verify-app-images",
				},
			},
			"failurePolicy":  failurePolicy,
			"timeoutSeconds": 30,
		})
		if operation == "validate" {
			if markerExists("ivpol-policy-verify-ksail-images-deleted") {
				if !markerExists("ivpol-policy-webhooks-ready-logged") {
					touchMarker("ivpol-policy-webhooks-ready-logged")
					appendEnvFile("OPERATION_LOG", "ivpol-policy-webhooks-ready\n")
				}
			} else {
				if !markerExists("ivpol-policy-consolidated-ready-logged") {
					touchMarker("ivpol-policy-consolidated-ready-logged")
					appendEnvFile("OPERATION_LOG", "ivpol-policy-consolidated-ready\n")
				}
			}
		}
	}
	fmt.Println(encodeJSON(map[string]any{
		"apiVersion": "v1",
		"kind":       "List",
		"items": []any{
			map[string]any{"webhooks": webhooks},
		},
	}))
	return 0
}

func fakeManifestKind(path string) string {
	var manifest map[string]any
	if err := json.Unmarshal([]byte(mustReadCommandFile(path)), &manifest); err != nil {
		return ""
	}
	kind, _ := manifest["kind"].(string)
	return kind
}

func fakeKubectlGetSyncLease(args []string, namespace string) int {
	if namespace != "flux-system" || argumentAfter(args, "lease") != "ghcr-auth-refresh" ||
		(!containsArg(args, "-o") && !containsArg(args, "--output")) {
		return commandFailure(91, "invalid synchronization lease lookup")
	}
	if os.Getenv("FAKE_TRANSIENT_SYNC_LEASE_API_FAIL_AFTER_FIRST_CLAIM") == "true" &&
		markerExists("cordon-owner-prod-worker-1") &&
		!markerExists("sync-lease-api-unreachable-after-first-claim") {
		touchMarker("sync-lease-api-unreachable-after-first-claim")
		return commandFailure(
			54,
			"The connection to the server api.example.test:6443 was refused: connect: connection refused",
		)
	}
	if os.Getenv("FAKE_INTERRUPT_SYNC_LEASE_HEARTBEAT_DURING_DRAIN") == "true" &&
		markerExists("transient-drain-attempt-prod-worker-1") &&
		!markerExists("sync-lease-heartbeat-interrupted") &&
		(os.Getenv("FAKE_DELAY_SYNC_LEASE_HEARTBEAT_FAILURE_ON_RECOVERY") != "true" || !markerExists("sync-lease-heartbeat-interruption-started")) {
		if os.Getenv("FAKE_DELAY_SYNC_LEASE_HEARTBEAT_FAILURE_ON_RECOVERY") == "true" {
			if !markerExists("sync-lease-heartbeat-interruption-started") {
				touchMarker("sync-lease-heartbeat-interruption-started")
				time.Sleep(2 * time.Second)
				touchMarker("sync-lease-heartbeat-interrupted")
				return commandFailure(54, "read: connection reset by peer")
			}
		} else {
			touchMarker("sync-lease-heartbeat-interrupted")
		}
		if os.Getenv("FAKE_REPLACE_SYNC_LEASE_DURING_HEARTBEAT_INTERRUPTION") == "true" {
			setMarkerContent("sync-lease-holder", "newer-transaction")
			setMarkerContent(
				"sync-lease-resource-version",
				incrementDecimal(defaultString(markerContent("sync-lease-resource-version"), "10")),
			)
		}
		return commandFailure(54, "read: connection reset by peer")
	}
	holder := markerContent("sync-lease-holder")
	if !markerExists("sync-lease-holder") {
		if os.Getenv("FAKE_HELD_SYNC_LEASE") != "true" {
			if !containsArg(args, "--ignore-not-found") {
				return commandFailure(44, "lease not found")
			}
			return 0
		}
		holder = "other-live-transaction"
	}
	defaultLeaseTime := "2999-01-01T00:00:00Z"
	if os.Getenv("FAKE_EXPIRED_SYNC_LEASE") == "true" {
		defaultLeaseTime = "2000-01-01T00:00:00Z"
	}
	fmt.Println(encodeJSON(map[string]any{
		"metadata": map[string]any{
			"name":            "ghcr-auth-refresh",
			"namespace":       "flux-system",
			"resourceVersion": defaultString(markerContent("sync-lease-resource-version"), "10"),
		},
		"spec": map[string]any{
			"holderIdentity":       holder,
			"leaseDurationSeconds": parseInt(defaultString(markerContent("sync-lease-duration"), "120"), 120),
			"acquireTime":          defaultString(markerContent("sync-lease-acquire-time"), defaultLeaseTime),
			"renewTime":            defaultString(markerContent("sync-lease-renew-time"), defaultLeaseTime),
			"leaseTransitions":     parseInt(defaultString(markerContent("sync-lease-transitions"), "0"), 0),
		},
	}))
	// The read above has already returned the state the fence report will retain.
	// Advancing the resourceVersion now models the one race --recover-fences must
	// lose: another actor touched the Lease between the report and the patch. The
	// CAS then fails through the ordinary comparison in fakeKubectlPatchSyncLease
	// rather than a recovery-specific short circuit, so the test exercises the
	// real guard instead of a stand-in for it. Once only — the fence report reads
	// the Lease exactly once by design, and a repeat would mask a second read.
	if os.Getenv("FAKE_SYNC_LEASE_TOUCHED_AFTER_FENCE_REPORT") == "true" &&
		!markerExists("sync-lease-touched-after-fence-report") {
		touchMarker("sync-lease-touched-after-fence-report")
		setMarkerContent(
			"sync-lease-resource-version",
			incrementDecimal(defaultString(markerContent("sync-lease-resource-version"), "10")),
		)
	}
	return 0
}

func fakeKubectlCreateSyncLease(namespace, manifestFile string) int {
	if namespace != "flux-system" || markerExists("sync-lease-holder") {
		return commandFailure(45, "synchronization lease already exists")
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(mustReadCommandFile(manifestFile)), &manifest); err != nil {
		return commandFailure(91, "parse synchronization lease manifest: %v", err)
	}
	metadata, _ := manifest["metadata"].(map[string]any)
	spec, _ := manifest["spec"].(map[string]any)
	holder, _ := spec["holderIdentity"].(string)
	if manifest["apiVersion"] != "coordination.k8s.io/v1" || manifest["kind"] != "Lease" ||
		metadata["name"] != "ghcr-auth-refresh" || metadata["namespace"] != "flux-system" ||
		holder == "" || holder != os.Getenv("FLUX_GHCR_SYNC_LEASE_HOLDER") {
		return commandFailure(91, "invalid synchronization lease manifest")
	}
	if err := validateKubernetesMicroTimes(
		fmt.Sprint(spec["acquireTime"]),
		fmt.Sprint(spec["renewTime"]),
	); err != nil {
		return commandFailure(91, `Lease in version "v1" cannot be handled as a Lease: %v`, err)
	}
	if message := os.Getenv("FAKE_SYNC_LEASE_CREATE_ERROR"); message != "" {
		return commandFailure(91, "%s", message)
	}
	setMarkerContent("sync-lease-holder", holder)
	setMarkerContent("sync-lease-resource-version", "10")
	setMarkerContent("sync-lease-duration", fmt.Sprint(spec["leaseDurationSeconds"]))
	setMarkerContent("sync-lease-acquire-time", fmt.Sprint(spec["acquireTime"]))
	setMarkerContent("sync-lease-renew-time", fmt.Sprint(spec["renewTime"]))
	setMarkerContent("sync-lease-transitions", fmt.Sprint(spec["leaseTransitions"]))
	fmt.Println("lease.coordination.k8s.io/ghcr-auth-refresh created")
	return 0
}

func fakeKubectlPatchSyncLease(args []string, namespace, patchFile string) int {
	if namespace != "flux-system" || argumentAfter(args, "lease") != "ghcr-auth-refresh" ||
		!containsArg(args, "--type=json") || patchFile == "" || !markerExists("sync-lease-holder") {
		return commandFailure(91, "invalid synchronization lease patch")
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse synchronization lease patch: %v", err)
	}
	currentResourceVersion := defaultString(markerContent("sync-lease-resource-version"), "10")
	currentHolder := markerContent("sync-lease-holder")

	// release_sync_lease kills the heartbeat shell, but not a kubectl child that
	// shell may be blocked in. That orphaned renewal lands after the release has
	// read the Lease and before its patch is applied. Model the write itself --
	// a same-holder renewal advancing resourceVersion -- and let the ordinary
	// CAS comparison below decide the outcome, exactly as an apiserver would.
	// This fires on the release patch only: it is the one that clears
	// holderIdentity.
	if os.Getenv("FAKE_SYNC_LEASE_ORPHANED_HEARTBEAT_WRITE_BEFORE_RELEASE") == "true" &&
		!markerExists("sync-lease-orphaned-heartbeat-write") &&
		hasPatchPath(patch, "replace", "/spec/holderIdentity") &&
		patchValueString(patch, "replace", "/spec/holderIdentity") == "" {
		touchMarker("sync-lease-orphaned-heartbeat-write")
		currentResourceVersion = incrementDecimal(currentResourceVersion)
		setMarkerContent("sync-lease-resource-version", currentResourceVersion)
	}
	// A real apiserver evaluates the `test` operations a patch actually carries,
	// and nothing more -- so honour resourceVersion exactly when it is present.
	// The holderIdentity test is what makes any write to this Lease safe, so a
	// caller that omits it is rejected outright. Which writers must ALSO pin
	// resourceVersion is a policy question, not an apiserver one, and it is
	// asserted separately below.
	if !hasPatchOperation(patch, "test", "/spec/holderIdentity", currentHolder) {
		return commandFailure(56, "synchronization lease CAS failed")
	}
	if hasPatchPath(patch, "test", "/metadata/resourceVersion") &&
		!hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) {
		return commandFailure(56, "synchronization lease CAS failed")
	}

	// The release is the ONE writer that must not pin resourceVersion: a benign
	// same-holder heartbeat write would otherwise fail it and leave the Lease
	// held. Every other writer still must pin it -- acquire and renew both rely
	// on it to avoid a lost update on leaseTransitions -- so keep requiring it
	// of them rather than dropping the check for everyone.
	releasesTheLease := hasPatchPath(patch, "replace", "/spec/holderIdentity") &&
		patchValueString(patch, "replace", "/spec/holderIdentity") == ""
	if !releasesTheLease && !hasPatchPath(patch, "test", "/metadata/resourceVersion") {
		return commandFailure(56, "synchronization lease CAS failed")
	}
	for _, path := range []string{"/spec/acquireTime", "/spec/renewTime"} {
		if hasPatchPath(patch, "replace", path) {
			if err := validateKubernetesMicroTimes(patchValueString(patch, "replace", path)); err != nil {
				return commandFailure(91, `Lease in version "v1" cannot be handled as a Lease: %v`, err)
			}
		}
	}
	if os.Getenv("FAKE_SYNC_LEASE_RENEW_CONFLICT_ONCE") == "true" &&
		!markerExists("sync-lease-renew-conflict") &&
		!hasPatchPath(patch, "replace", "/spec/holderIdentity") &&
		hasPatchPath(patch, "replace", "/spec/renewTime") {
		setMarkerContent("sync-lease-renew-time", patchValueString(patch, "replace", "/spec/renewTime"))
		setMarkerContent("sync-lease-resource-version", incrementDecimal(currentResourceVersion))
		touchMarker("sync-lease-renew-conflict")
		return commandFailure(56, "simulated same-holder lease renewal race")
	}
	// Every release attempt fails, so the loop's exhaustion path -- its final
	// diagnostics -- becomes reachable. The one-shot fixtures above cannot get
	// there by construction.
	if os.Getenv("FAKE_SYNC_LEASE_RELEASE_ALWAYS_FAILS") == "true" && releasesTheLease {
		touchMarker("sync-lease-release-always-fails")
		return commandFailure(56, "persistent failure releasing the lease")
	}

	// A release whose CAS passed can still fail on a transient API error. The
	// Lease is untouched, so the retry that follows must be able to complete the
	// release rather than leaving it held.
	if os.Getenv("FAKE_SYNC_LEASE_RELEASE_CONFLICT_ONCE") == "true" &&
		!markerExists("sync-lease-release-conflict") &&
		hasPatchPath(patch, "replace", "/spec/holderIdentity") &&
		patchValueString(patch, "replace", "/spec/holderIdentity") == "" {
		touchMarker("sync-lease-release-conflict")
		return commandFailure(56, "simulated transient failure releasing the lease")
	}
	// The apiserver APPLIES the release and the response is then lost (connection
	// reset after the write). kubectl exits non-zero, so the caller retries and
	// finds the Lease already cleared -- which is its goal state, not a failure.
	if os.Getenv("FAKE_SYNC_LEASE_RELEASE_RESPONSE_LOST") == "true" &&
		!markerExists("sync-lease-release-response-lost") &&
		releasesTheLease {
		touchMarker("sync-lease-release-response-lost")
		setMarkerContent("sync-lease-holder", "")
		setMarkerContent("sync-lease-resource-version", incrementDecimal(currentResourceVersion))
		return commandFailure(54, "connection reset after releasing the lease")
	}
	if holder := patchValueString(patch, "replace", "/spec/holderIdentity"); hasPatchPath(patch, "replace", "/spec/holderIdentity") {
		setMarkerContent("sync-lease-holder", holder)
	}
	for path, marker := range map[string]string{
		"/spec/leaseDurationSeconds": "sync-lease-duration",
		"/spec/acquireTime":          "sync-lease-acquire-time",
		"/spec/renewTime":            "sync-lease-renew-time",
		"/spec/leaseTransitions":     "sync-lease-transitions",
	} {
		if hasPatchPath(patch, "replace", path) {
			setMarkerContent(marker, patchValueString(patch, "replace", path))
		}
	}
	setMarkerContent("sync-lease-resource-version", incrementDecimal(currentResourceVersion))
	fmt.Println("lease.coordination.k8s.io/ghcr-auth-refresh patched")
	return 0
}

func validateKubernetesMicroTimes(values ...string) error {
	if os.Getenv("FAKE_REQUIRE_KUBERNETES_MICROTIME") != "true" {
		return nil
	}
	const layout = "2006-01-02T15:04:05.000000Z07:00"
	for _, value := range values {
		if _, err := time.Parse(layout, value); err != nil {
			return fmt.Errorf("parsing time %q as %q: %w", value, layout, err)
		}
	}
	return nil
}

func fakeKubectlGetNodes() int {
	if os.Getenv("FAKE_NODE_DISCOVERY_FAIL") == "true" {
		return commandFailure(46, "node discovery failed")
	}
	// Seed a fence left behind by a transaction that was killed before this run
	// existed -- the #3070 state. Seeded once, guarded by its own marker, so a
	// reclaim that clears it is not silently re-created on the next inventory
	// read and the test can tell "reclaimed" from "never seeded".
	if leaked := os.Getenv("FAKE_LEAKED_FENCE_NODE"); leaked != "" &&
		!markerExists("leaked-fence-seeded-"+leaked) {
		touchMarker("leaked-fence-seeded-" + leaked)
		setMarkerContent("cordon-owner-"+leaked, "dead-transaction-owner")
		setMarkerContent(
			"cordon-phase-"+leaked,
			defaultString(os.Getenv("FAKE_LEAKED_FENCE_PHASE"), "claimed"),
		)
		touchMarker("cordoned-" + leaked)
	}
	if custom := os.Getenv("FAKE_NODE_JSON"); custom != "" {
		fmt.Println(custom)
		return 0
	}

	revision := os.Getenv("EXPECTED_GHCR_REVISION")
	image := os.Getenv("EXPECTED_KSAIL_TARGET_IMAGE")
	verifiedImage := defaultString(os.Getenv("FAKE_TALOS_VERIFIED_IMAGE"), image)
	workerUID := defaultString(os.Getenv("FAKE_WORKER_UID"), "prod-worker-1-uid")
	nodes := []any{
		fakeInventoryNode("prod-worker-1", workerUID, "10.0.0.2", "198.51.100.2", false, revision, "", "", true),
		fakeInventoryNode("prod-control-plane-1", "prod-control-plane-1-uid", "10.0.0.1", "198.51.100.1", true, revision, "", "", true),
		fakeInventoryNode("prod-control-plane-2", "prod-control-plane-2-uid", "10.0.0.3", "198.51.100.3", true, revision, revision, image, false),
		fakeInventoryNode("prod-control-plane-3", "prod-control-plane-3-uid", "10.0.0.4", "198.51.100.4", true, revision, revision, image, false),
	}
	if os.Getenv("FAKE_ALL_TALOS_NODES_STALE") == "true" {
		for _, node := range nodes {
			nodeMap, ok := node.(map[string]any)
			if !ok {
				return commandFailure(91, "invalid fake node object")
			}
			metadata, ok := nodeMap["metadata"].(map[string]any)
			if !ok {
				return commandFailure(91, "invalid fake node metadata")
			}
			annotations, ok := metadata["annotations"].(map[string]any)
			if !ok {
				return commandFailure(91, "invalid fake node annotations")
			}
			delete(annotations, "platform.devantler.tech/ghcr-pull-verified-revision-v2")
			delete(annotations, "platform.devantler.tech/ghcr-pull-verified-image-v2")
		}
	}
	if bootstrapWorker := os.Getenv("FAKE_BOOTSTRAP_WORKER_NAME"); bootstrapWorker != "" {
		verifiedRevision := ""
		verifiedWorkerImage := ""
		if markerExists("talos-revision-10.0.0.5") {
			verifiedRevision = revision
			verifiedWorkerImage = image
		}
		nodes = append(nodes, fakeInventoryNode(
			bootstrapWorker,
			bootstrapWorker+"-uid",
			"10.0.0.5",
			"198.51.100.5",
			false,
			revision,
			verifiedRevision,
			verifiedWorkerImage,
			false,
		))
	}
	if os.Getenv("FAKE_TALOS_NODES_CURRENT") == "true" {
		setInventoryProof(nodes[0], revision, verifiedImage)
		setInventoryProof(nodes[1], revision, verifiedImage)
	}
	if markerExists("talos-revision-10.0.0.2") {
		setInventoryProof(nodes[0], revision, image)
	}
	if markerExists("talos-revision-10.0.0.1") {
		setInventoryProof(nodes[1], revision, image)
	}
	for _, node := range nodes {
		nodeMap := node.(map[string]any)
		status := nodeMap["status"].(map[string]any)
		addresses := status["addresses"].([]any)
		internalIP := addresses[0].(map[string]any)["address"].(string)
		if markerExists("talos-revision-" + internalIP) {
			setInventoryProof(node, revision, image)
		}
		if markerExists("talos-reboot-" + internalIP) {
			status["conditions"] = []any{map[string]any{"type": "Ready", "status": "True"}}
		}
	}

	newNodeName := ""
	if configured := os.Getenv("FAKE_NODE_APPEARS_AFTER_ROLL"); configured != "" &&
		markerExists("talos-revision-10.0.0.2") && markerExists("talos-revision-10.0.0.1") {
		newNodeName = configured
	} else if configured := os.Getenv("FAKE_NODE_APPEARS_DURING_SECOND_FANOUT"); configured != "" &&
		parseInt(markerContent("variables-patch-count"), 0) >= 2 {
		newNodeName = configured
	}
	if newNodeName != "" {
		verifiedRevision := ""
		newNodeImage := ""
		if markerExists("talos-revision-10.0.0.5") {
			verifiedRevision = revision
			newNodeImage = image
		}
		nodes = append(nodes, fakeInventoryNode(
			newNodeName,
			newNodeName+"-uid",
			"10.0.0.5",
			"198.51.100.5",
			false,
			revision,
			verifiedRevision,
			newNodeImage,
			true,
		))
	}

	remaining := nodes[:0]
	for _, node := range nodes {
		name := node.(map[string]any)["metadata"].(map[string]any)["name"].(string)
		if markerExists("removed-before-process-" + name) {
			switch os.Getenv("FAKE_REMOVAL_CONFIRMATION") {
			case "list-fails":
				return commandFailure(46, "node discovery failed")
			case "malformed":
				fmt.Println(`{"items":[{"metadata":{"name":"incomplete"}}]}`)
				return 0
			case "empty":
				fmt.Println(`{"items":[]}`)
				return 0
			case "same-name":
				node = fakeInventoryNode(name, "replacement-uid", "10.0.0.99", "198.51.100.99", false, revision, revision, image, false)
			case "same-address":
				address, _ := fakeNodeAddress(name)
				node = fakeInventoryNode("replacement", "replacement-uid", address, "198.51.100.99", false, revision, revision, image, false)
			case "same-uid":
				node = fakeInventoryNode("replacement", fakeExpectedNodeUID(name), "10.0.0.99", "198.51.100.99", false, revision, revision, image, false)
			case "still-present":
			default:
				continue
			}
		}
		remaining = append(remaining, node)
	}
	fmt.Println(encodeJSON(map[string]any{"items": remaining}))
	return 0
}

func fakeInventoryNode(
	name string,
	uid string,
	internalIP string,
	externalIP string,
	controlPlane bool,
	desiredRevision string,
	verifiedRevision string,
	verifiedImage string,
	omitReady bool,
) map[string]any {
	labels := map[string]any{}
	if controlPlane {
		labels["node-role.kubernetes.io/control-plane"] = ""
	}
	annotations := map[string]any{
		"platform.devantler.tech/ghcr-pull-desired-revision": desiredRevision,
	}
	if verifiedRevision != "" {
		annotations["platform.devantler.tech/ghcr-pull-verified-revision-v2"] = verifiedRevision
	}
	if verifiedImage != "" {
		annotations["platform.devantler.tech/ghcr-pull-verified-image-v2"] = verifiedImage
	}
	if owner := markerContent("cordon-owner-" + name); owner != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-owner"] = owner
	}
	if phase := markerContent("cordon-phase-" + name); phase != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-phase"] = phase
	}
	if recovery := markerContent("cordon-recovery-" + name); recovery != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-recovery"] = recovery
	}
	status := map[string]any{
		"addresses": []any{
			map[string]any{"type": "InternalIP", "address": internalIP},
			map[string]any{"type": "ExternalIP", "address": externalIP},
		},
	}
	if !omitReady {
		status["conditions"] = []any{map[string]any{"type": "Ready", "status": "True"}}
	}
	cordoned := wordListContains(os.Getenv("FAKE_CORDONED_NODES"), name) || markerExists("cordoned-"+name)
	taints := []any{}
	if cordoned {
		taints = append(taints, map[string]any{
			"key":    "node.kubernetes.io/unschedulable",
			"effect": "NoSchedule",
		})
	}
	if markerExists("uncordoned-"+name) &&
		name == os.Getenv("FAKE_TRANSIENT_UNSCHEDULABLE_TAINT_AFTER_RELEASE_NODE") &&
		!markerExists("release-taint-cleared-"+name) {
		taints = append(taints, map[string]any{
			"key":    "node.kubernetes.io/unschedulable",
			"effect": "NoSchedule",
		})
	}
	return map[string]any{
		"metadata": map[string]any{
			"name":        name,
			"uid":         uid,
			"labels":      labels,
			"annotations": annotations,
		},
		"spec": map[string]any{
			"unschedulable": cordoned,
			"taints":        taints,
		},
		"status": status,
	}
}

// fakeKubectlGetPods dispatches Pod inventory requests either to the namespace
// workload probe or to the node-scoped runtime probe used by the bridge tests.
func fakeKubectlGetPods(args []string) int {
	if containsSequence(args, "-o", "name") || containsArg(args, "-o=name") ||
		flagValue(args, "--field-selector") == "status.phase=Running" {
		return fakeKubectlGetNamespaceWorkloads(args, flagValue(args, "--namespace"))
	}
	nodeName := flagValue(args, "--field-selector")
	nodeName = strings.TrimPrefix(nodeName, "spec.nodeName=")
	if nodeName == "" || (!containsSequence(args, "-o", "json") && !containsArg(args, "-o=json")) {
		return commandFailure(91, "pod inventory must select one node as JSON")
	}
	if nodeName == os.Getenv("FAKE_MALFORMED_POD_INVENTORY_NODE") {
		fmt.Println(`{}`)
		return 0
	}
	items := []any{
		map[string]any{
			"metadata": map[string]any{
				"name":            "cilium-" + nodeName,
				"ownerReferences": []any{map[string]any{"kind": "DaemonSet"}},
			},
			"status": map[string]any{"phase": "Running"},
		},
	}
	if !wordListContains(os.Getenv("FAKE_EMPTY_WORKLOAD_NODES"), nodeName) {
		items = append(items, map[string]any{
			"metadata": map[string]any{
				"name":            "workload-" + nodeName,
				"ownerReferences": []any{map[string]any{"kind": "ReplicaSet"}},
			},
			"status": map[string]any{"phase": "Running"},
		})
	}
	fmt.Println(encodeJSON(map[string]any{"items": items}))
	return 0
}

func setInventoryProof(node any, revision, image string) {
	nodeMap := node.(map[string]any)
	metadata := nodeMap["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	annotations["platform.devantler.tech/ghcr-pull-verified-revision-v2"] = revision
	annotations["platform.devantler.tech/ghcr-pull-verified-image-v2"] = image
}

func fakeKubectlGetNode(args []string) int {
	nodeName := argumentAfter(args, "node")
	if nodeName == "" {
		return commandFailure(91, "node target missing")
	}
	removedAfterQuarantine := nodeName == os.Getenv("FAKE_NODE_REMOVED_AFTER_QUARANTINE") &&
		(markerExists("cordon-owner-prod-control-plane-3") || markerExists("removed-before-process-"+nodeName))
	if wordListContains(os.Getenv("FAKE_NODE_REMOVED_BEFORE_PROCESS"), nodeName) || removedAfterQuarantine ||
		(nodeName == os.Getenv("FAKE_NODE_REMOVED_AFTER_UNCORDON") && markerExists("uncordoned-"+nodeName)) {
		if os.Getenv("FAKE_REMOVAL_CONFIRMATION") == "forbidden" {
			return commandFailure(1, "Error from server (Forbidden): nodes is forbidden")
		}
		if os.Getenv("FAKE_REMOVAL_CONFIRMATION") == "not-found-error" {
			return commandFailure(1, "Error from server (NotFound): nodes not found")
		}
		touchMarker("removed-before-process-" + nodeName)
		if containsArg(args, "--ignore-not-found") {
			return 0
		}
		return commandFailure(1, "Error from server (NotFound): nodes not found")
	}
	if !containsSequence(args, "--output", "json") && !containsArg(args, "--output=json") {
		if wordListContains(os.Getenv("FAKE_CORDONED_NODES"), nodeName) {
			fmt.Print("true")
		}
		return 0
	}
	if nodeName == os.Getenv("FAKE_RECOVERY_ADVANCES_BEFORE_RELEASE_NODE") &&
		!markerExists("recovery-advanced-before-release-"+nodeName) {
		var recoveryRecord map[string]any
		if err := json.Unmarshal(
			[]byte(markerContent("cordon-recovery-"+nodeName)),
			&recoveryRecord,
		); err == nil && recoveryRecord["phase"] == "rollback-safe" {
			recoveryRecord["phase"] = "active"
			setMarkerContent("cordon-recovery-"+nodeName, encodeJSON(recoveryRecord))
			currentResourceVersion := defaultString(markerContent("resource-version-"+nodeName), "10")
			setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
			touchMarker("recovery-advanced-before-release-" + nodeName)
			appendEnvFile("OPERATION_LOG", "concurrent-recovery-phase:"+nodeName+":active\n")
		}
	}

	nodeUID := fakeExpectedNodeUID(nodeName)
	nodeIP, controlPlane := fakeNodeAddress(nodeName)
	if nodeName == os.Getenv("FAKE_NODE_REPLACED_BEFORE_PROCESS_NODE") {
		nodeUID = nodeName + "-replacement-uid"
		nodeIP = "10.0.0.99"
	}
	if nodeName == os.Getenv("FAKE_NODE_REPLACED_AFTER_READY_NODE") && markerExists("ready-"+nodeName) {
		nodeUID = nodeName + "-replacement-uid"
		nodeIP = "10.0.0.99"
	}
	if nodeName == os.Getenv("FAKE_NODE_REPLACED_AFTER_UNCORDON_NODE") && markerExists("uncordoned-"+nodeName) {
		nodeUID = nodeName + "-replacement-uid"
		nodeIP = "10.0.0.99"
	}
	if nodeName == os.Getenv("FAKE_NODE_IP_CHANGED_AFTER_DRAIN_NODE") && markerExists("drained-"+nodeName) {
		nodeIP = "10.0.0.99"
	}

	labels := map[string]any{}
	if controlPlane {
		labels["node-role.kubernetes.io/control-plane"] = ""
	}
	annotations := map[string]any{}
	if owner := markerContent("cordon-owner-" + nodeName); owner != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-owner"] = owner
	}
	if phase := markerContent("cordon-phase-" + nodeName); phase != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-phase"] = phase
	}
	if recovery := markerContent("cordon-recovery-" + nodeName); recovery != "" {
		annotations["platform.devantler.tech/ghcr-auth-drain-recovery"] = recovery
	}
	cordoned := wordListContains(os.Getenv("FAKE_CORDONED_NODES"), nodeName) || markerExists("cordoned-"+nodeName)
	if nodeName == os.Getenv("FAKE_EXTERNAL_UNCORDON_AFTER_READY_NODE") && markerExists("ready-"+nodeName) {
		cordoned = false
	}
	taints := make([]any, 0, 2)
	if cordoned {
		taints = append(taints, map[string]any{
			"key":    "node.kubernetes.io/unschedulable",
			"effect": "NoSchedule",
		})
	}
	if markerExists("autoscaler-cordon-" + nodeName) {
		taints = append(taints, map[string]any{
			"key":    "ToBeDeletedByClusterAutoscaler",
			"effect": "NoSchedule",
		})
	}
	// Reproduce the autoscaler's advisory removal-candidate marker being RELEASED
	// while the bridge holds the node: present when the claim captures the node's
	// taints, gone by the time the pre-reboot guard re-reads it. Observed in prod on
	// 2026-08-17, where the autoscaler added the taint at 00:11:26, released it at
	// 00:15:43, and the deploy's guard refused 23s later. The value is a timestamp the
	// autoscaler regenerates on every add, so it churns even key-for-key.
	if nodeName == os.Getenv("FAKE_AUTOSCALER_DELETION_CANDIDATE_RELEASED_NODE") &&
		!markerExists("drained-"+nodeName) {
		taints = append(taints, map[string]any{
			"key":    "DeletionCandidateOfClusterAutoscaler",
			"value":  "1786925486",
			"effect": "PreferNoSchedule",
		})
	}
	if markerExists("uncordoned-"+nodeName) &&
		nodeName == os.Getenv("FAKE_TRANSIENT_UNSCHEDULABLE_TAINT_AFTER_RELEASE_NODE") {
		readMarker := "post-release-node-read-count-" + nodeName
		readCount := parseInt(markerContent(readMarker), 0) + 1
		setMarkerContent(readMarker, strconv.Itoa(readCount))
		if readCount <= 2 {
			taints = append(taints, map[string]any{
				"key":    "node.kubernetes.io/unschedulable",
				"effect": "NoSchedule",
			})
		} else {
			touchMarker("release-taint-cleared-" + nodeName)
		}
	}
	if markerExists("ready-"+nodeName) &&
		(nodeName == os.Getenv("FAKE_TRANSIENT_LIFECYCLE_TAINT_AFTER_READY_NODE") ||
			nodeName == os.Getenv("FAKE_PERSISTENT_LIFECYCLE_TAINT_AFTER_READY_NODE")) {
		readMarker := "post-ready-node-read-count-" + nodeName
		readCount := parseInt(markerContent(readMarker), 0) + 1
		setMarkerContent(readMarker, strconv.Itoa(readCount))
		if readCount == 1 || nodeName == os.Getenv("FAKE_PERSISTENT_LIFECYCLE_TAINT_AFTER_READY_NODE") {
			taints = append(taints,
				map[string]any{
					"key":    "node.kubernetes.io/not-ready",
					"effect": "NoSchedule",
				},
				map[string]any{
					"key":    "node.kubernetes.io/unreachable",
					"effect": "NoExecute",
				},
			)
		}
	}
	if markerExists("ready-"+nodeName) &&
		nodeName == os.Getenv("FAKE_TRANSIENT_CILIUM_STARTUP_TAINT_AFTER_READY_NODE") {
		readMarker := "post-ready-node-read-count-" + nodeName
		readCount := parseInt(markerContent(readMarker), 0) + 1
		setMarkerContent(readMarker, strconv.Itoa(readCount))
		if readCount == 1 {
			taints = append(taints, map[string]any{
				"key":    "node.cilium.io/agent-not-ready",
				"effect": "NoSchedule",
			})
		}
	}
	readyStatus := "True"
	if markerExists("ready-"+nodeName) &&
		nodeName == os.Getenv("FAKE_NOT_READY_WITHOUT_LIFECYCLE_TAINT_NODE") {
		readMarker := "post-ready-node-read-count-" + nodeName
		readCount := parseInt(markerContent(readMarker), 0) + 1
		setMarkerContent(readMarker, strconv.Itoa(readCount))
		readyStatus = "False"
	}
	resourceVersion := defaultString(markerContent("resource-version-"+nodeName), "10")
	nodeSpec := map[string]any{"taints": taints}
	if !markerExists("uncordoned-"+nodeName) ||
		nodeName != os.Getenv("FAKE_OMIT_UNSCHEDULABLE_AFTER_RELEASE_NODE") {
		nodeSpec["unschedulable"] = cordoned
	}
	node := map[string]any{
		"metadata": map[string]any{
			"name":              nodeName,
			"uid":               nodeUID,
			"labels":            labels,
			"resourceVersion":   resourceVersion,
			"deletionTimestamp": nil,
			"annotations":       annotations,
		},
		"spec": nodeSpec,
		"status": map[string]any{
			"addresses":  []any{map[string]any{"type": "InternalIP", "address": nodeIP}},
			"conditions": []any{map[string]any{"type": "Ready", "status": readyStatus}},
		},
	}
	fmt.Println(encodeJSON(node))
	return 0
}

func fakeNodeAddress(nodeName string) (string, bool) {
	switch nodeName {
	case "prod-worker-1":
		return "10.0.0.2", false
	case "prod-control-plane-1":
		return "10.0.0.1", true
	case "prod-control-plane-2":
		return "10.0.0.3", true
	case "prod-control-plane-3":
		return "10.0.0.4", true
	default:
		return "10.0.0.5", false
	}
}

func fakeNodeName(nodeAddress string) string {
	for _, nodeName := range []string{
		"prod-worker-1",
		"prod-worker-2",
		"prod-control-plane-1",
		"prod-control-plane-2",
		"prod-control-plane-3",
	} {
		address, _ := fakeNodeAddress(nodeName)
		if address == nodeAddress {
			return nodeName
		}
	}
	return ""
}

func fakeExpectedNodeUID(nodeName string) string {
	if nodeName == "prod-worker-1" && os.Getenv("FAKE_WORKER_UID") != "" {
		return os.Getenv("FAKE_WORKER_UID")
	}
	return nodeName + "-uid"
}

func fakeKubectlDrain(args []string) int {
	nodeName := argumentAfter(args, "drain")
	if nodeName == "" || !containsArg(args, "--ignore-daemonsets") ||
		!containsArg(args, "--delete-emptydir-data") || !containsArg(args, "--timeout=45m") ||
		containsArg(args, "--disable-eviction") || containsArg(args, "--force") {
		return commandFailure(55, "unsafe or incomplete kubectl drain flags")
	}
	appendEnvFile("OPERATION_LOG", "node-drain:"+nodeName+"\n")
	if !wordListContains(os.Getenv("FAKE_CORDONED_NODES"), nodeName) && !markerExists("cordoned-"+nodeName) {
		return commandFailure(55, "drain target was not cordoned")
	}
	if nodeName == os.Getenv("FAKE_DRAIN_API_FAIL_NODE") {
		return commandFailure(54, "could not list pods before eviction")
	}
	if nodeName == os.Getenv("FAKE_TRANSIENT_DRAIN_API_FAIL_NODE") {
		attemptMarker := "transient-drain-attempt-" + nodeName
		attempt := parseInt(markerContent(attemptMarker), 0) + 1
		setMarkerContent(attemptMarker, strconv.Itoa(attempt))
		if attempt == 1 {
			if os.Getenv("FAKE_INTERRUPT_SYNC_LEASE_HEARTBEAT_DURING_DRAIN") == "true" {
				waitMarker := "sync-lease-heartbeat-interrupted"
				if os.Getenv("FAKE_DELAY_SYNC_LEASE_HEARTBEAT_FAILURE_ON_RECOVERY") == "true" {
					waitMarker = "sync-lease-heartbeat-interruption-started"
				}
				for wait := 0; wait < 40 && !markerExists(waitMarker); wait++ {
					time.Sleep(100 * time.Millisecond)
				}
				if os.Getenv("FAKE_DELAY_SYNC_LEASE_HEARTBEAT_FAILURE_ON_RECOVERY") != "true" {
					// Let the heartbeat process persist its private sticky-loss
					// marker before the foreground drain observes API recovery.
					time.Sleep(500 * time.Millisecond)
				}
			}
			return commandFailure(
				54,
				"error when evicting pod: Cannot evict pod as it would violate the pod's disruption budget.\n"+
					"error: unable to drain node %q due to error: Post https://api.example.test:6443/eviction: read: connection reset by peer",
				nodeName,
			)
		}
	}
	if nodeName == os.Getenv("FAKE_CORDON_OWNER_REPLACED_NODE") {
		setMarkerContent("cordon-owner-"+nodeName, "operator-cordon")
	}
	if nodeName == os.Getenv("FAKE_AUTOSCALER_CORDON_NODE") {
		touchMarker("autoscaler-cordon-" + nodeName)
	}
	if nodeName == os.Getenv("FAKE_DRAIN_FAIL_NODE") {
		return commandFailure(53, "cannot evict pod backstage-db-4: would violate PodDisruptionBudget backstage-db-primary")
	}
	touchMarker("drained-" + nodeName)
	if nodeName == os.Getenv("FAKE_EXTERNAL_UNCORDON_AFTER_DRAIN_NODE") {
		removeMarker("cordoned-" + nodeName)
		appendEnvFile("OPERATION_LOG", "operator-uncordon:"+nodeName+"\n")
	}
	return 0
}

func fakeKubectlUncordon(args []string) int {
	nodeName := argumentAfter(args, "uncordon")
	if nodeName == "" {
		return commandFailure(91, "uncordon target missing")
	}
	if nodeName == os.Getenv("FAKE_CORDON_OWNER_REPLACED_NODE") || nodeName == os.Getenv("FAKE_UNCORDON_FAIL_NODE") {
		return commandFailure(56, "cordon ownership changed; refusing to uncordon")
	}
	appendEnvFile("OPERATION_LOG", "node-uncordon:"+nodeName+"\n")
	return 0
}

func fakeKubectlPatchNode(args []string, patchFile string) int {
	nodeName := argumentAfter(args, "node")
	if nodeName == "" || patchFile == "" {
		return commandFailure(91, "node patch target or patch file missing")
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(patchFile)), &patch); err != nil {
		return commandFailure(91, "parse node patch: %v", err)
	}
	currentResourceVersion := defaultString(markerContent("resource-version-"+nodeName), "10")
	isClaim := hasPatchOperation(patch, "add", "/spec/unschedulable", true)
	isFencePhase := hasPatchPath(
		patch,
		"add",
		"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase",
	) && !hasPatchOperation(patch, "add", "/spec/unschedulable", true)
	if isFencePhase {
		expectedOwner := patchValueString(
			patch,
			"test",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner",
		)
		if nodeName == os.Getenv("FAKE_FENCE_PHASE_FAIL_NODE") ||
			expectedOwner == "" || expectedOwner != markerContent("cordon-owner-"+nodeName) ||
			!hasPatchOperation(patch, "test", "/metadata/uid", fakeExpectedNodeUID(nodeName)) {
			return commandFailure(57, "invalid fence phase update")
		}
		setMarkerContent("cordon-phase-"+nodeName, patchValueString(
			patch,
			"add",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase",
		))
		setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
		appendEnvFile("OPERATION_LOG", "node-fence-phase:"+nodeName+"\n")
		fmt.Printf("node/%s patched\n", nodeName)
		return 0
	}
	isRecoveryPhase := hasPatchPath(
		patch,
		"replace",
		"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
	)
	if isRecoveryPhase {
		expectedOwner := patchValueString(
			patch,
			"test",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner",
		)
		expectedRecovery := patchValueString(
			patch,
			"test",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
		)
		updatedRecovery := patchValueString(
			patch,
			"replace",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
		)
		if nodeName == os.Getenv("FAKE_RECOVERY_PHASE_FAIL_NODE") ||
			expectedOwner == "" || expectedOwner != markerContent("cordon-owner-"+nodeName) ||
			expectedRecovery == "" || expectedRecovery != markerContent("cordon-recovery-"+nodeName) ||
			updatedRecovery == "" ||
			!hasPatchOperation(patch, "test", "/metadata/uid", fakeExpectedNodeUID(nodeName)) ||
			!hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) {
			return commandFailure(56, "invalid bootstrap recovery phase update")
		}
		var recoveryRecord map[string]any
		if err := json.Unmarshal([]byte(updatedRecovery), &recoveryRecord); err != nil {
			return commandFailure(56, "invalid bootstrap recovery JSON")
		}
		phase, _ := recoveryRecord["phase"].(string)
		if phase != "rollback-safe" && phase != "active" && phase != "retain" && phase != "release-ready" {
			return commandFailure(56, "invalid bootstrap recovery phase")
		}
		setMarkerContent("cordon-recovery-"+nodeName, updatedRecovery)
		setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
		appendEnvFile("OPERATION_LOG", "recovery-phase:"+nodeName+":"+phase+"\n")
		return 0
	}
	// Reclaiming a leaked fence is the only patch that REMOVES the phase
	// annotation -- a claim adds it, a release leaves it alone -- so that is the
	// discriminator. Without this branch the reclaim falls through to the
	// release path, whose first test is the owner rather than the uid, and every
	// reclaim would fail exit 56 with no coverage of the mutation at all.
	isReclaim := hasPatchPath(
		patch,
		"remove",
		"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase",
	)
	if isReclaim {
		if nodeName == os.Getenv("FAKE_RECLAIM_FAIL_NODE") {
			return commandFailure(56, "fence changed while being reclaimed")
		}
		expectedOwner := patchValueString(
			patch,
			"test",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner",
		)
		// CAS on identity, the exact owner value, AND the "claimed" phase: a
		// reclaim must never clear a fence that changed hands, sits on a
		// replaced node reusing the name, or already reached Talos mutation.
		if expectedOwner == "" ||
			expectedOwner != markerContent("cordon-owner-"+nodeName) ||
			!hasPatchOperation(patch, "test", "/metadata/uid", fakeExpectedNodeUID(nodeName)) ||
			!hasPatchOperation(
				patch,
				"test",
				"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase",
				"claimed",
			) ||
			!hasPatchPath(
				patch,
				"remove",
				"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner",
			) {
			return commandFailure(56, "invalid orphaned fence reclaim")
		}
		removeMarker("cordon-owner-" + nodeName)
		removeMarker("cordon-phase-" + nodeName)
		setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
		// The cordon marker is deliberately left in place: reclaim releases
		// ownership without uncordoning, because the pre-claim schedulability
		// was never recorded.
		appendEnvFile("OPERATION_LOG", "node-reclaim-fence:"+nodeName+"\n")
		return 0
	}
	if isClaim {
		if nodeName == os.Getenv("FAKE_CORDON_BEFORE_CLAIM_NODE") {
			touchMarker("cordoned-" + nodeName)
			appendEnvFile("OPERATION_LOG", "operator-cordon:"+nodeName+"\n")
			return commandFailure(56, "resourceVersion test failed after concurrent cordon")
		}
		// A conflict that never clears, so the bounded retry budget runs out
		// and the claim must still refuse rather than drain.
		if nodeName == os.Getenv("FAKE_CLAIM_FAIL_NODE") {
			setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
			return commandFailure(56, "resourceVersion test failed")
		}
		// An unrelated writer (a kubelet status heartbeat, the cloud
		// controller manager) bumps resourceVersion between the capturing
		// read and this patch, so the CAS test fails while nothing relevant
		// to drain safety changed. Fires once, so a re-read then succeeds.
		if nodeName == os.Getenv("FAKE_UNRELATED_NODE_WRITE_BEFORE_CLAIM_NODE") &&
			!markerExists("unrelated-write-"+nodeName) {
			touchMarker("unrelated-write-" + nodeName)
			setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
			appendEnvFile("OPERATION_LOG", "unrelated-node-write:"+nodeName+"\n")
			return commandFailure(56, "resourceVersion test failed")
		}
		owner := patchValueString(patch, "add", "/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner")
		if owner == "" || markerExists("cordon-owner-"+nodeName) ||
			len(patch) == 0 || patch[0].Operation != "test" ||
			patch[0].Path != "/metadata/resourceVersion" || fmt.Sprint(patch[0].Value) != currentResourceVersion {
			return commandFailure(56, "invalid atomic cordon claim")
		}
		expectedNodeUID := fakeExpectedNodeUID(nodeName)
		if !hasPatchOperation(patch, "test", "/metadata/uid", expectedNodeUID) {
			return commandFailure(56, "atomic cordon claim omitted node UID")
		}
		setMarkerContent("cordon-owner-"+nodeName, owner)
		if phase := patchValueString(
			patch,
			"add",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase",
		); phase != "" {
			setMarkerContent("cordon-phase-"+nodeName, phase)
		}
		if recovery := patchValueString(
			patch,
			"add",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
		); recovery != "" {
			setMarkerContent("cordon-recovery-"+nodeName, recovery)
		}
		touchMarker("cordoned-" + nodeName)
		setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
		appendEnvFile("OPERATION_LOG", "node-claim-cordon:"+nodeName+"\n")
		if os.Getenv("FAKE_SYNC_LEASE_LOST_AFTER_FIRST_CLAIM") == "true" &&
			!markerExists("sync-lease-lost-after-claim") {
			setMarkerContent("sync-lease-holder", "newer-transaction")
			setMarkerContent(
				"sync-lease-resource-version",
				incrementDecimal(defaultString(markerContent("sync-lease-resource-version"), "10")),
			)
			touchMarker("sync-lease-lost-after-claim")
		}
		return 0
	}

	expectedOwner := ""
	if len(patch) > 0 {
		expectedOwner = fmt.Sprint(patch[0].Value)
	}
	if nodeName == os.Getenv("FAKE_NODE_RESOURCE_VERSION_ADVANCES_BEFORE_RELEASE_NODE") &&
		!markerExists("resource-version-advanced-before-release-"+nodeName) {
		setMarkerContent(
			"resource-version-"+nodeName,
			incrementDecimal(currentResourceVersion),
		)
		touchMarker("resource-version-advanced-before-release-" + nodeName)
		appendEnvFile("OPERATION_LOG", "concurrent-node-resource-version:"+nodeName+"\n")
		return commandFailure(56, "resourceVersion test failed during cordon release")
	}
	if nodeName == os.Getenv("FAKE_UNCORDON_FAIL_NODE") || markerContent("cordon-owner-"+nodeName) != expectedOwner {
		return commandFailure(56, "cordon ownership changed; refusing to uncordon")
	}
	expectedNodeUID := fakeExpectedNodeUID(nodeName)
	if len(patch) == 0 || patch[0].Operation != "test" ||
		patch[0].Path != "/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner" ||
		!hasPatchOperation(patch, "test", "/metadata/uid", expectedNodeUID) ||
		!hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) ||
		!hasPatchPath(patch, "remove", "/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner") {
		return commandFailure(56, "invalid atomic cordon release")
	}
	currentRecovery := markerContent("cordon-recovery-" + nodeName)
	if currentRecovery != "" &&
		(!hasPatchOperation(
			patch,
			"test",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
			currentRecovery,
		) || !hasPatchPath(
			patch,
			"remove",
			"/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery",
		)) {
		return commandFailure(56, "atomic cordon release omitted recovery journal")
	}
	setMarkerContent("resource-version-"+nodeName, incrementDecimal(currentResourceVersion))
	removeMarker("cordon-owner-" + nodeName)
	removeMarker("cordon-recovery-" + nodeName)
	if hasPatchOperation(patch, "add", "/spec/unschedulable", false) {
		appendEnvFile("OPERATION_LOG", "node-uncordon:"+nodeName+"\n")
		removeMarker("cordoned-" + nodeName)
		touchMarker("uncordoned-" + nodeName)
	} else {
		appendEnvFile("OPERATION_LOG", "node-release-cordon-owner:"+nodeName+"\n")
	}
	if nodeName == os.Getenv("FAKE_NODE_RELEASE_RESPONSE_LOST_NODE") &&
		!markerExists("node-release-response-lost-"+nodeName) {
		touchMarker("node-release-response-lost-" + nodeName)
		return commandFailure(54, "connection reset after cordon release")
	}
	return 0
}

func hasPatchOperation(patch []jsonPatchOperation, operation, path string, value any) bool {
	for _, item := range patch {
		if item.Operation == operation && item.Path == path && fmt.Sprint(item.Value) == fmt.Sprint(value) {
			return true
		}
	}
	return false
}

func hasPatchPath(patch []jsonPatchOperation, operation, path string) bool {
	for _, item := range patch {
		if item.Operation == operation && item.Path == path {
			return true
		}
	}
	return false
}

func patchValueString(patch []jsonPatchOperation, operation, path string) string {
	for _, item := range patch {
		if item.Operation == operation && item.Path == path {
			return fmt.Sprint(item.Value)
		}
	}
	return ""
}

func incrementDecimal(value string) string {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return strconv.Itoa(parsed + 1)
}

func fakeKubectlCordon(args []string) int {
	nodeName := argumentAfter(args, "cordon")
	if nodeName == "" {
		return commandFailure(91, "cordon target missing")
	}
	appendEnvFile("OPERATION_LOG", "node-cordon:"+nodeName+"\n")
	return 0
}

func fakeKubectlWaitForNode(args []string) int {
	if !containsArg(args, "--for=condition=Ready") || !containsArg(args, "--timeout=10m") {
		return commandFailure(91, "unsafe node readiness wait")
	}
	nodeName := ""
	for _, argument := range args {
		if strings.HasPrefix(argument, "node/") {
			nodeName = strings.TrimPrefix(argument, "node/")
		}
	}
	if nodeName == "" {
		return commandFailure(91, "readiness target missing")
	}
	appendEnvFile("OPERATION_LOG", "node-ready:"+nodeName+"\n")
	if nodeName == os.Getenv("FAKE_TRANSIENT_NODE_READY_API_FAIL_NODE") {
		attemptMarker := "transient-node-ready-attempt-" + nodeName
		attempt := parseInt(markerContent(attemptMarker), 0) + 1
		setMarkerContent(attemptMarker, strconv.Itoa(attempt))
		if attempt == 1 {
			return commandFailure(
				54,
				"The connection to the server api.example.test:6443 was refused: connect: connection refused",
			)
		}
	}
	if nodeName == os.Getenv("FAKE_NODE_READY_FAIL_NODE") {
		return commandFailure(50, "node did not become ready")
	}
	touchMarker("ready-" + nodeName)
	return 0
}

func fakeKubectlCreateRuntimeProbe(namespace, manifestFile string) int {
	if namespace != "ksail-operator" || manifestFile == "" {
		return commandFailure(91, "invalid runtime probe namespace or manifest")
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(mustReadCommandFile(manifestFile)), &manifest); err != nil {
		return commandFailure(91, "parse runtime probe: %v", err)
	}
	metadata, _ := manifest["metadata"].(map[string]any)
	spec, _ := manifest["spec"].(map[string]any)
	containers, _ := spec["containers"].([]any)
	if manifest["kind"] != "Pod" || metadata["namespace"] != "ksail-operator" ||
		spec["automountServiceAccountToken"] != false || len(containers) != 1 ||
		len(anySlice(spec["imagePullSecrets"])) != 0 {
		return commandFailure(91, "unsafe runtime probe manifest")
	}
	container, _ := containers[0].(map[string]any)
	securityContext, _ := container["securityContext"].(map[string]any)
	image, _ := container["image"].(string)
	if (image != "ghcr.io/devantler-tech/data-product-controller:latest" &&
		image != "ghcr.io/devantler-tech/wedding-app:latest" &&
		image != "ghcr.io/devantler-tech/ascoachingogvaner:latest") ||
		container["imagePullPolicy"] != "Always" || securityContext["allowPrivilegeEscalation"] != false {
		return commandFailure(91, "runtime probe does not prove a private package pull")
	}
	probeName, _ := metadata["name"].(string)
	probeNode, _ := spec["nodeName"].(string)
	if probeName == "" || probeNode == "" {
		return commandFailure(91, "runtime probe name or node missing")
	}
	if wordListContains(
		os.Getenv("FAKE_RUNTIME_PROBE_CREATE_PERSIST_THEN_TIMEOUT_ONCE_NODES"),
		probeNode,
	) {
		attemptMarker := "runtime-probe-create-attempts-" + probeNode
		attempt := parseInt(markerContent(attemptMarker), 0) + 1
		setMarkerContent(attemptMarker, strconv.Itoa(attempt))
		if attempt == 1 {
			setMarkerContent("runtime-probe-"+probeName, probeNode+"\n"+image+"\n")

			return commandFailure(
				75,
				"Error from server (InternalError): failed calling webhook: context deadline exceeded",
			)
		}
	}
	if wordListContains(
		os.Getenv("FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_ONCE_NODES"),
		probeNode,
	) && !markerExists("runtime-probe-create-timeout-once-"+probeNode) {
		touchMarker("runtime-probe-create-timeout-once-" + probeNode)

		return commandFailure(
			75,
			"Error from server (InternalError): failed calling webhook: context deadline exceeded",
		)
	}
	if wordListContains(
		os.Getenv("FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_COUNT_NODES"),
		probeNode,
	) {
		attemptMarker := "runtime-probe-create-timeout-count-" + probeNode
		attempt := parseInt(markerContent(attemptMarker), 0) + 1
		setMarkerContent(attemptMarker, strconv.Itoa(attempt))
		timeoutCount := parseInt(os.Getenv("FAKE_RUNTIME_PROBE_CREATE_TIMEOUT_COUNT"), 3)
		if attempt <= timeoutCount {
			return commandFailure(
				75,
				"Error from server (InternalError): failed calling webhook: context deadline exceeded",
			)
		}
	}
	if wordListContains(os.Getenv("FAKE_RUNTIME_PROBE_CREATE_ALWAYS_FAIL_NODES"), probeNode) {
		return commandFailure(
			75,
			"Error from server (InternalError): failed calling webhook: context deadline exceeded",
		)
	}
	setMarkerContent("runtime-probe-"+probeName, probeNode+"\n"+image+"\n")
	fmt.Printf("pod/%s\n", probeName)
	return 0
}

func fakeKubectlGetRuntimeProbe(args []string) int {
	probeName := argumentAfter(args, "pod")
	contents := markerContent("runtime-probe-" + probeName)
	lines := strings.Split(strings.TrimSuffix(contents, "\n"), "\n")
	if probeName == "" || len(lines) < 2 {
		return commandFailure(91, "runtime probe state missing")
	}
	probeNode, probeImage := lines[0], lines[1]
	pullSecrets := []any{}
	if wordListContains(os.Getenv("FAKE_RUNTIME_PROBE_INJECT_PULL_SECRET_NODES"), probeNode) {
		pullSecrets = append(pullSecrets, map[string]any{"name": "injected-pull-secret"})
	}
	status := map[string]any{}
	probeIP, _ := fakeNodeAddress(probeNode)
	// A probe the kubelet never reported on: the Pod exists but carries no
	// containerStatuses at all. This is what a still-Pending probe, or one the
	// kubelet rejected outright (OutOfmemory/OutOfpods), actually looks like.
	if wordListContains(os.Getenv("FAKE_RUNTIME_PROBE_STALLED_NODES"), probeNode) {
		status["phase"] = defaultString(os.Getenv("FAKE_RUNTIME_PROBE_STALLED_PHASE"), "Pending")
		if reason := os.Getenv("FAKE_RUNTIME_PROBE_STALLED_REASON"); reason != "" {
			status["reason"] = reason
		}
		if message := os.Getenv("FAKE_RUNTIME_PROBE_STALLED_MESSAGE"); message != "" {
			status["message"] = message
		}
		fmt.Println(encodeJSON(map[string]any{
			"spec":   map[string]any{"imagePullSecrets": pullSecrets},
			"status": status,
		}))
		return 0
	}
	if (wordListContains(os.Getenv("FAKE_RUNTIME_PULL_FAIL_NODES"), probeNode) &&
		!markerExists("talos-reboot-"+probeIP)) ||
		wordListContains(os.Getenv("FAKE_RUNTIME_PULL_FAIL_IMAGES"), probeImage) {
		failureMessage := os.Getenv("FAKE_RUNTIME_PULL_FAILURE_MESSAGE")
		if failureMessage == "__EMPTY__" {
			failureMessage = ""
		} else {
			failureMessage = defaultString(
				failureMessage,
				"failed to authorize: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Adevantler-tech%2Fwedding-app%3Apull: 403 Forbidden",
			)
		}
		status["containerStatuses"] = []any{map[string]any{
			"name": "pull-probe",
			"state": map[string]any{"waiting": map[string]any{
				"reason":  "ImagePullBackOff",
				"message": failureMessage,
			}},
		}}
	} else {
		if os.Getenv("FAKE_LOG_RUNTIME_PROBE_SUCCESS") == "true" {
			appendEnvFile(
				"OPERATION_LOG",
				"runtime-probe-success:"+probeNode+":"+probeImage+"\n",
			)
		}
		status["containerStatuses"] = []any{map[string]any{
			"name":    "pull-probe",
			"imageID": "ghcr.io/private@sha256:runtime-probe",
			"state": map[string]any{
				"terminated": map[string]any{"reason": "Completed", "exitCode": 0},
			},
		}}
	}
	fmt.Println(encodeJSON(map[string]any{
		"spec":   map[string]any{"imagePullSecrets": pullSecrets},
		"status": status,
	}))
	return 0
}

func fakeKubectlDeleteRuntimeProbe(args []string) int {
	probeName := argumentAfter(args, "pod")
	if probeName == "" {
		return commandFailure(91, "runtime probe delete target missing")
	}
	removeMarker("runtime-probe-" + probeName)
	fmt.Printf("pod %q deleted\n", probeName)
	return 0
}

func fakeKubectlGetRootSecret() int {
	token := defaultString(os.Getenv("FAKE_CURRENT_ROOT_TOKEN"), "previous-runtime-token")
	config := encodeJSON(map[string]any{
		"auths": map[string]any{
			"ghcr.io": map[string]any{"username": "devantler", "password": token},
		},
	})
	encoded := defaultString(
		markerContent("root-secret-value"),
		base64.StdEncoding.EncodeToString([]byte(config)),
	)
	fmt.Println(encodeJSON(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": defaultString(markerContent("root-secret-resource-version"), "20"),
		},
		"data": map[string]any{".dockerconfigjson": encoded},
	}))
	fakeLoseSyncLeaseAfterSecretRead(
		"FAKE_SYNC_LEASE_LOST_AFTER_ROOT_SECRET_GET",
		"sync-lease-lost-after-root-secret-get",
	)
	return 0
}

func fakeKubectlAPIResources(args []string) int {
	if flagValue(args, "--api-group") != "external-secrets.io" {
		return commandFailure(91, "unexpected api-resources group")
	}
	if os.Getenv("FAKE_FANOUT_CRDS_ABSENT") != "true" {
		fmt.Println("externalsecrets.external-secrets.io")
		fmt.Println("pushsecrets.external-secrets.io")
	}
	return 0
}

func fakeKubectlPatchRootSecret(args []string, patchFile string) int {
	return fakeKubectlPatchSecretWithCAS(fakeSecretCASPatch{
		args:                  args,
		patchFile:             patchFile,
		dataPath:              "/data/.dockerconfigjson",
		dataKey:               ".dockerconfigjson",
		resourceVersionMarker: "root-secret-resource-version",
		valueMarker:           "root-secret-value",
		conflictEnvironment:   "FAKE_ROOT_SECRET_CAS_CONFLICT_ONCE",
		conflictMarker:        "root-secret-cas-conflict",
		conflictLiveValue:     "newer-root-secret-value",
		captureEnvironment:    "PATCH_CAPTURE",
		operation:             "root-patch",
		resourceName:          "ksail-registry-credentials",
	})
}

func fakeKubectlGetVariablesBase(args []string) int {
	if os.Getenv("FAKE_VARIABLES_BASE_ABSENT") == "true" {
		if containsArg(args, "--ignore-not-found") {
			return 0
		}
		return commandFailure(44, "variables-base not found")
	}
	if containsSequence(args, "-o", "json") {
		value := defaultString(markerContent("variables-secret-value"), "previous-variables-value")
		fmt.Println(encodeJSON(map[string]any{
			"metadata": map[string]any{
				"resourceVersion": defaultString(markerContent("variables-secret-resource-version"), "30"),
			},
			"data": map[string]any{"ghcr_dockerconfigjson": value},
		}))
		fakeLoseSyncLeaseAfterSecretRead(
			"FAKE_SYNC_LEASE_LOST_AFTER_VARIABLES_SECRET_GET",
			"sync-lease-lost-after-variables-secret-get",
		)
		return 0
	}
	if !containsArg(args, "--ignore-not-found") || !containsSequence(args, "-o", "name") {
		return commandFailure(91, "variables-base discovery must tolerate a fresh cluster")
	}
	fmt.Println("secret/variables-base")
	return 0
}

func fakeKubectlPatchVariablesBase(args []string, patchFile string) int {
	result := fakeKubectlPatchSecretWithCAS(fakeSecretCASPatch{
		args:                  args,
		patchFile:             patchFile,
		dataPath:              "/data/ghcr_dockerconfigjson",
		dataKey:               "ghcr_dockerconfigjson",
		resourceVersionMarker: "variables-secret-resource-version",
		valueMarker:           "variables-secret-value",
		conflictEnvironment:   "FAKE_VARIABLES_SECRET_CAS_CONFLICT_ONCE",
		conflictMarker:        "variables-secret-cas-conflict",
		conflictLiveValue:     "newer-variables-secret-value",
		captureEnvironment:    "VARIABLES_PATCH_CAPTURE",
		operation:             "variables-patch",
		resourceName:          "variables-base",
	})
	if result == 0 {
		count := parseInt(markerContent("variables-patch-count"), 0) + 1
		setMarkerContent("variables-patch-count", strconv.Itoa(count))
	}
	return result
}

type fakeSecretCASPatch struct {
	args                  []string
	patchFile             string
	dataPath              string
	dataKey               string
	resourceVersionMarker string
	valueMarker           string
	conflictEnvironment   string
	conflictMarker        string
	conflictLiveValue     string
	captureEnvironment    string
	operation             string
	resourceName          string
}

func fakeKubectlPatchSecretWithCAS(request fakeSecretCASPatch) int {
	if !containsArg(request.args, "--type=json") || request.patchFile == "" {
		return commandFailure(91, "invalid %s CAS patch", request.resourceName)
	}
	var patch []jsonPatchOperation
	if err := json.Unmarshal([]byte(mustReadCommandFile(request.patchFile)), &patch); err != nil {
		return commandFailure(91, "parse %s CAS patch: %v", request.resourceName, err)
	}
	currentResourceVersion := defaultString(markerContent(request.resourceVersionMarker), secretResourceVersionDefault(request.resourceName))
	value := patchValueString(patch, "add", request.dataPath)
	if !hasPatchOperation(patch, "test", "/metadata/resourceVersion", currentResourceVersion) || value == "" {
		return commandFailure(56, "%s resourceVersion CAS failed", request.resourceName)
	}
	if os.Getenv(request.conflictEnvironment) == "true" && !markerExists(request.conflictMarker) {
		setMarkerContent(request.resourceVersionMarker, incrementDecimal(currentResourceVersion))
		setMarkerContent(request.valueMarker, request.conflictLiveValue)
		setMarkerContent(request.conflictMarker+"-live-value", request.conflictLiveValue)
		touchMarker(request.conflictMarker)
		return commandFailure(56, "simulated stale %s writer", request.resourceName)
	}
	if request.resourceName == "ksail-registry-credentials" && os.Getenv("FAKE_KUBECTL_FAIL") == "true" {
		mustWriteCommandFile(os.Getenv(request.captureEnvironment), encodeJSON(map[string]any{
			"data": map[string]any{request.dataKey: value},
		}))
		appendEnvFile("OPERATION_LOG", request.operation+"\n")
		return commandFailure(43, "cluster patch failed")
	}
	setMarkerContent(request.resourceVersionMarker, incrementDecimal(currentResourceVersion))
	setMarkerContent(request.valueMarker, value)
	mustWriteCommandFile(os.Getenv(request.captureEnvironment), encodeJSON(map[string]any{
		"data": map[string]any{request.dataKey: value},
	}))
	appendEnvFile("OPERATION_LOG", request.operation+"\n")
	fmt.Printf("secret/%s patched\n", request.resourceName)
	return 0
}

func secretResourceVersionDefault(resourceName string) string {
	if resourceName == "ksail-registry-credentials" {
		return "20"
	}
	return "30"
}

func fakeLoseSyncLeaseAfterSecretRead(environment, marker string) {
	currentHolder := markerContent("sync-lease-holder")
	processHolder := os.Getenv("FLUX_GHCR_SYNC_LEASE_HOLDER")
	if os.Getenv(environment) != "true" || markerExists(marker) ||
		processHolder == "" || currentHolder != processHolder {
		return
	}
	setMarkerContent("sync-lease-holder", "newer-transaction")
	setMarkerContent(
		"sync-lease-resource-version",
		incrementDecimal(defaultString(markerContent("sync-lease-resource-version"), "10")),
	)
	touchMarker(marker)
}

func fanoutResource(args []string) (string, string) {
	if containsSequence(args, "pushsecret", "seed-ghcr") {
		return "pushsecret", "seed-ghcr"
	}
	if containsSequence(args, "externalsecret", "ghcr-auth") {
		return "externalsecret", "ghcr-auth"
	}
	return "", ""
}

func fakeKubectlFanoutResource(args []string, namespace, kind, name string) int {
	resource := kind + "/" + namespace + "/" + name
	missingResource := os.Getenv("FAKE_MISSING_FANOUT_RESOURCE")
	if containsArg(args, "--ignore-not-found") && containsSequence(args, "get", kind, name) {
		if resource != missingResource {
			fmt.Printf("%s/%s\n", kind, name)
		}
		return 0
	}
	if resource == missingResource {
		return commandFailure(44, "%s/%s not found", kind, name)
	}
	if containsSequence(args, "get", kind, name) {
		markerName := kind + "-" + namespace + "-" + name
		refreshTime := "2026-07-13T00:00:00Z"
		resourceVersion := "1"
		if markerExists(markerName + "-annotated") {
			resourceVersion = "2"
		}
		if markerExists(markerName) && os.Getenv("FAKE_SYNC_SAME_REFRESH_TIME") != "true" {
			refreshTime = "2026-07-13T00:00:01Z"
		}
		if markerExists(markerName) {
			resourceVersion = "3"
		}
		fmt.Println(encodeJSON(map[string]any{
			"metadata": map[string]any{"resourceVersion": resourceVersion},
			"status": map[string]any{
				"refreshTime": refreshTime,
				"conditions":  []any{map[string]any{"type": "Ready", "status": "True"}},
			},
		}))
		return 0
	}
	if containsSequence(args, "annotate", kind, name) {
		appendEnvFile("FANOUT_LOG", resource+"\n")
		appendEnvFile("OPERATION_LOG", "fanout:"+resource+"\n")
		markerName := kind + "-" + namespace + "-" + name
		touchMarker(markerName + "-annotated")
		if resource != os.Getenv("FAKE_SYNC_STALL_RESOURCE") {
			touchMarker(markerName)
		}
		fmt.Println(`{"metadata":{"resourceVersion":"2"}}`)
		return 0
	}
	return commandFailure(91, "unexpected fanout resource invocation")
}

func fakeKubectlGetConsumerSecret(namespace string) int {
	variablesPatchCount := parseInt(markerContent("variables-patch-count"), 0)
	revertedMarker := "consumer-reverted-" + namespace
	mismatch := namespace == os.Getenv("FAKE_CONSUMER_MISMATCH_NAMESPACE") ||
		(namespace == os.Getenv("FAKE_CONSUMER_MISMATCH_ON_SECOND_PASS_NAMESPACE") && variablesPatchCount >= 2) ||
		(markerExists(revertedMarker) && variablesPatchCount < 3)
	encoded := ""
	if mismatch {
		encoded = base64.StdEncoding.EncodeToString([]byte(`{"auths":{}}`))
	} else {
		var patch map[string]any
		if err := json.Unmarshal([]byte(mustReadCommandFile(os.Getenv("VARIABLES_PATCH_CAPTURE"))), &patch); err != nil {
			return commandFailure(91, "parse variables-base patch: %v", err)
		}
		data, _ := patch["data"].(map[string]any)
		encoded, _ = data["ghcr_dockerconfigjson"].(string)
		if variablesPatchCount >= 3 {
			removeMarker(revertedMarker)
		}
	}
	fmt.Println(encodeJSON(map[string]any{
		"data": map[string]any{".dockerconfigjson": encoded},
	}))
	return 0
}

func wordListContains(list, target string) bool {
	for _, item := range strings.Fields(list) {
		if item == target {
			return true
		}
	}
	return false
}

// anySlice returns value as a generic slice, or nil when it is absent or not a slice.
func anySlice(value any) []any {
	if value == nil {
		return nil
	}
	items, _ := value.([]any)
	return items
}

// fakeKubectlGetNamespaceWorkloads models the workload probe the fan-out gate
// uses to tell a brand-new consumer apart from an established one. A namespace
// left behind by a failed candidate still runs nothing, so it reports empty
// unless the fixture explicitly declares a running workload.
//
// A failed candidate can also leave a Pod OBJECT behind that never reached Running,
// or a terminating Pod whose last phase is still Running. Neither is an active
// consumer whose pull credential this staging step could break.
func fakeKubectlGetNamespaceWorkloads(args []string, namespace string) int {
	if namespace == "" {
		return 0
	}
	outputJSON := containsSequence(args, "-o", "json") || containsArg(args, "-o=json")
	fieldSelector := flagValue(args, "--field-selector")
	items := []any{}
	if namespace == os.Getenv("FAKE_NAMESPACE_WITH_WORKLOAD") {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": namespace + "-0"},
			"status":   map[string]any{"phase": "Running"},
		})
	}
	if namespace == os.Getenv("FAKE_NAMESPACE_WITH_NONRUNNING_POD") &&
		fieldSelector != "status.phase=Running" {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": namespace + "-0"},
			"status":   map[string]any{"phase": "Pending"},
		})
	}
	if namespace == os.Getenv("FAKE_NAMESPACE_WITH_TERMINATING_RUNNING_POD") {
		items = append(items, map[string]any{
			"metadata": map[string]any{
				"name":              namespace + "-0",
				"deletionTimestamp": "2026-09-01T00:00:00Z",
			},
			"status": map[string]any{"phase": "Running"},
		})
	}
	if outputJSON {
		fmt.Println(encodeJSON(map[string]any{"items": items}))
		return 0
	}
	for _, item := range items {
		pod, _ := item.(map[string]any)
		metadata, _ := pod["metadata"].(map[string]any)
		fmt.Printf("pod/%s\n", metadata["name"])
	}
	return 0
}
