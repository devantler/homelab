// Command validate-eks-ci-role-policy pins the privileges production grants to
// the EKS CI identity.
//
// The permissions that identity ends up with are not written in one place: they
// are the sum of several independently reconciled overlays, so a change in any
// one of them can widen the identity's reach without that being visible in the
// diff under review. This command renders each of those overlays and compares
// the result against approved fingerprints, so an unreviewed privilege grant
// fails CI instead of reaching the cluster.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	roleManifestPath          = "k8s/providers/hetzner/apps/aws/role-eks-ci.yaml"
	boundaryManifestPath      = "k8s/providers/hetzner/apps/aws/policy-eks-ci-smoke-boundary.yaml"
	appsOverlayPath           = "k8s/providers/hetzner/apps"
	infrastructureOverlayPath = "k8s/providers/hetzner/infrastructure"
	controllerOverlayPath     = "k8s/providers/hetzner/infrastructure/controllers"
	bootstrapOverlayPath      = "k8s/clusters/prod/bootstrap"
	rootProductionOverlayPath = "k8s/clusters/prod"
	rendererCommandTimeout    = 2 * time.Minute

	expectedKubectlVersion   = "v1.36.2"
	expectedKustomizeVersion = "v5.8.1"
	expectedRoleManifestSHA  = "96a77d18160c450340e65b0953f44016a01a08429416f7a82142c3f90a61ca07"
	expectedBoundarySHA      = "6e79792b08aa023900734d31c45d6abe1765991ad16b63e84598cc8d7d5b05af"
	expectedTrustPolicySHA   = "85d5d45343f9eac5fdc35717c85c88c5b0f8fde9eddffb169c3a223617fd0a5e"
	expectedInlinePolicySHA  = "60e3086a6d3dac0092ffe8264c04ebae783c0d38f19a3cf073ed8991085a4df8"
	expectedBoundaryJSONSHA  = "2c9bc1ce56efeb6fa30d885d5f9dff8d5d8129a07d9393ccdeb376605cbc5ad8"
)

// expectedRenderedSurfaceSHA is the aggregate fingerprint of the whole selected
// authorization surface.
//
// It sits outside the const block above so this rationale can travel with it
// without re-aligning seven unrelated security constants.
//
// The approved surface includes the encrypted flux-system/variables-cluster
// substitution source and the staged Cilium homogeneous-device activation.
//
// Measured against main d7062144 before approving this value: 550 documents on
// main and 544 on this branch — six REMOVED, zero added, zero renamed, proven by
// set difference in BOTH directions over the complete
// apiVersion|kind|namespace|name identity across all five rendered overlays.
// Neither side carries a duplicate identity, so that pairing is one-to-one. The
// six removals are the decommissioned doggy-countdown tenant and nothing else:
//
//	kustomize.toolkit.fluxcd.io/v1  Kustomization   doggy-countdown/doggy-countdown
//	networking.k8s.io/v1            NetworkPolicy   doggy-countdown/default-deny
//	rbac.authorization.k8s.io/v1    RoleBinding     doggy-countdown/doggy-countdown
//	source.toolkit.fluxcd.io/v1     OCIRepository   doggy-countdown/doggy-countdown
//	v1                              Namespace       doggy-countdown
//	v1                              ServiceAccount  doggy-countdown/doggy-countdown
//
// This is the exact inverse of the approval taken when the tenant was onboarded.
// Grant-bearing documents fall from 80 to 78 (Role / ClusterRole / RoleBinding /
// ClusterRoleBinding / ServiceAccount 11/24/16/12/17 -> 11/24/15/12/16) — exactly
// the one RoleBinding and one ServiceAccount above, and no other grant moves.
// Three surviving documents change content: the restrict-tenant-route-hostnames
// ClusterPolicy, the flux-system/platform-reconciliation Alert and the homepage
// ConfigMap. Each is purely subtractive — across those three sources the diff
// adds no non-comment line, dropping only the doggy-countdown rule, watch entry
// and dashboard entry. All 121 aws-bearing lines are byte-identical across the
// two trees, so nothing granted to the aws/aws service account this validator
// exists to protect is touched.
//
// Measured against main df5bcc39 before approving this value: 534 documents on
// both sides, membership IDENTICAL — zero added, zero removed, zero renamed,
// proven by set difference in BOTH directions over the complete
// apiVersion|kind|namespace|name identity across all five rendered overlays.
// Neither side carries a duplicate identity, so that pairing is one-to-one.
// Exactly ONE entry's content moves:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  crossview/crossview
//
// Its only rendered delta adds a single annotation —
// `configmap.reloader.stakater.com/reload: crossview-config` — to the Deployment
// its postRenderer patch targets. The chart wires every OIDC value in through
// env[].valueFrom.configMapKeyRef, and env resolves once at container creation,
// so a ConfigMap change alone never reaches the running process. The annotation
// tells the already-deployed Reloader controller to roll the Deployment when
// that ConfigMap changes; it names no subject, no role and no resource, and the
// same annotation is already carried by six other rendered documents.
//
// No grant-bearing object moved: the surface carries 72 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents on BOTH sides
// (10/22/15/10/15) and their canonical byte stream is identical. All 116
// `aws`-bearing lines are byte-identical across the two trees, so nothing
// granted to the aws/aws service account this validator exists to protect is
// touched.
//
// Measured against main 025fd5a6 before approving the previous value: 532 documents on
// both sides, membership IDENTICAL — zero added, zero removed, zero renamed,
// proven by set difference in BOTH directions over the complete
// apiVersion|kind|namespace|name identity across all five rendered overlays.
// The surface carries 71 Role / ClusterRole / RoleBinding / ClusterRoleBinding
// / ServiceAccount documents on BOTH sides (10/22/15/10/14). Seventy of them
// are byte-identical after canonicalization. Exactly ONE entry's content moves:
//
//	rbac.authorization.k8s.io/v1  ClusterRole  cluster-reader
//
// Its only rendered delta REMOVES the helm.toolkit.fluxcd.io API group from the
// role's non-core apiGroups list. Nothing is added. A HelmRelease spec persists
// substituted and inline values, so get/list/watch on that group let any bound
// read-only OIDC identity recover secret material that the role's deliberate
// core-group exclusion already withholds as Secrets. Removing the group closes
// that disclosure path and grants no identity or permission; every `aws`-bearing
// line in the surface is byte-identical, so nothing granted to the aws/aws
// service account moved.
//
// Measured by comparing base 4673fe2d with manifest head d0f130a0 before
// approving this value: all five production render trees contain 1,019 documents
// on both sides, with membership IDENTICAL by
// apiVersion|kind|namespace|name set difference. The 64 Role /
// ClusterRole / RoleBinding / ClusterRoleBinding / ServiceAccount documents are
// byte-identical. Exactly ONE rendered entry moves:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  kube-system/cilium
//
// Its only rendered delta changes authentication.enabled and
// authentication.mutual.spire.enabled from true to false. No scoped
// required-authentication policy consumes SPIRE, so disabling the unused
// integration removes continuous delegated-identity errors and grants no
// identity or permission.
//
// Measured against main 94714d94 before approving this value: 511 documents on
// both sides, with membership IDENTICAL -- zero added, removed, or renamed by
// set difference over every apiVersion|kind|namespace|name identity. Exactly
// two rendered entries move:
//
//	autoscaling.k8s.io/v1       VerticalPodAutoscaler  kyverno/kyverno-admission-controller
//	helm.toolkit.fluxcd.io/v2  HelmRelease           kyverno/kyverno
//
// The VPA delta narrows controlledValues from RequestsAndLimits to RequestsOnly
// and its memory ceiling from 6Gi to the authored 1Gi container limit. The
// HelmRelease delta moves that same request/limit block from the ignored
// admissionController.resources key to the chart-consumed
// admissionController.container.resources key. Both are resource-safety
// constraints; neither can grant an identity or permission.
//
// The rendered surface carries 64 Role / ClusterRole / RoleBinding /
// ClusterRoleBinding / ServiceAccount documents on BOTH sides, and their
// canonical byte stream is identical. Every `aws`-bearing line is likewise
// byte-identical, so nothing granted to the aws/aws service account moved.
//
// Measured against main 4cfe7d9f while fixing the Renovate KSail bump: the PR
// changes exactly the ksail-operator chart's pinned SemVer (7.176.4 -> 7.178.2)
// inside the authorization surface. This value migrates the projection so an
// exact Helm chart SemVer is represented by one sentinel; both versions produce
// this fingerprint. Every other HelmRelease field remains byte-exact after
// canonicalization, including chart/source identity, values, post-renderers,
// substitutions, and reconciliation policy. Missing, ranged, wildcarded, or
// substituted versions are not normalized. The required manifest job separately
// Helm-renders and security-scans the selected chart artifact before merge.
//
// Measured against main 9b1990de before approving this value: 510 documents
// on both sides, with membership IDENTICAL — zero added, zero removed, zero
// renamed (proven by set difference in both directions over the complete
// apiVersion|kind|namespace|name identity). Exactly ONE entry's content moved:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  kube-system/cilium
//
// Its rendered delta adds only `nodePort.addresses: [10.0.0.0/16]`, narrowing
// kube-proxy-replacement NodePort listeners from every selected device address
// to the private node CIDR. The surface carries 64 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents on BOTH sides;
// none moved, and no permission or identity grant changed.
//
// Measured against main 6e011890 before approving the previous value: 515 documents on
// both sides, membership IDENTICAL — proven by set difference in BOTH
// directions over apiVersion|kind|namespace|name across all five rendered
// trees, not by count alone, which cannot see a rename. Exactly ONE entry's
// content moved:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  headlamp/headlamp
//
// Its rendered delta is a single line — `hostUsers: false` — activating the
// user-namespace pilot gated since #2650. That field places the pod in its own
// user namespace; it constrains the workload and grants nothing.
//
// No grant-bearing object moved: 64 Role / ClusterRole / RoleBinding /
// ClusterRoleBinding / ServiceAccount documents on BOTH sides, none of them in
// the moved set. All 116 `aws`-bearing lines are byte-identical across the two
// trees, so nothing granted to the aws/aws service account this validator
// exists to protect is touched.
//
// Measured against main 875f5dc3 before approving THIS value: the rendered
// surface moves from 514 -> 519 documents, purely additive. Membership was
// proven by set difference in BOTH directions over apiVersion|kind|namespace|name
// (not by count, which cannot see a rename): zero removed, zero renamed, and the
// five additions are exactly the degraded-CNPG-cluster alert —
//
//	v1                          ServiceAccount      observability/cnpg-degraded-alert
//	v1                          Secret              observability/cnpg-degraded-alert-webhook
//	rbac.authorization.k8s.io/v1 ClusterRole        cnpg-degraded-alert
//	rbac.authorization.k8s.io/v1 ClusterRoleBinding cnpg-degraded-alert
//	batch/v1                    CronJob             observability/cnpg-degraded-alert
//
// Grant-bearing objects DID move here, additively: 64 -> 67 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents, being the three
// above. That is the same shape as the OpenCost usage-scraper approval below —
// one dedicated ServiceAccount, one narrow ClusterRole, one binding between
// exactly those two identities. The ClusterRole is list-only on a single resource
// type (`clusters.postgresql.cnpg.io`); it is cluster-scoped only because the
// check must see databases in every namespace that runs one.
//
// Exactly ONE existing entry's content moved:
//
//	kubescape.io/v1beta1  ClusterSecurityException  gitops-managed-cronjobs
//
// and its rendered delta is one prose sentence in `reason`, naming the new
// CronJob in the enumeration that field already carries. Its `match` scope is
// unchanged, so the exception grants nothing new.
//
// Every `aws`-bearing line in the rendered surface is byte-identical across the
// two trees (116 on both sides), so nothing granted to the aws/aws service
// account this validator exists to protect is touched.
//
// Measured against main fa041449 before approving the previous value: the
// production infrastructure overlay moves from 204 -> 210 documents, with
// exactly six additive OpenCost usage-scraper resources and no existing
// document modified or removed. The authorization delta is one dedicated
// ServiceAccount, one
// ClusterRole limited to get/list/watch on nodes plus get on nodes/metrics, and
// one binding between exactly those identities. The ConfigMap, Deployment, and
// scraper-scoped CiliumNetworkPolicy carry the bounded scrape/remote-write path
// but grant no Kubernetes authorization. The privileged nodes/proxy resource is
// absent. No aws/aws permission or existing grant-bearing object moved.
//
// Measured against main c5e2f307 before approving the previous value: 509
// documents on both sides, with membership IDENTICAL — zero added, zero removed, zero
// renamed (proven by set difference in BOTH directions over
// apiVersion|kind|namespace|name, not by count alone, which cannot see a
// rename). Exactly ONE entry's content moved:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  longhorn-system/longhorn
//
// Its rendered delta is the `postRenderers` block added by this change, which
// pins longhorn-ui's non-root identity (runAsNonRoot/runAsUser/runAsGroup,
// seccomp RuntimeDefault, drop ALL, no privilege escalation). That block
// constrains the workload; it grants nothing.
//
// No grant-bearing object moved: the surface carries 61 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents on BOTH sides, and
// none of them is in the moved set above. Every `aws`-bearing line in the
// rendered surface is byte-identical across the two trees, so nothing granted to
// the aws/aws service account this validator exists to protect is touched.
//
// (The value before this one covered the tenant `ResourceGraphDefinition`,
// measured against 1b204ded: 509 documents on both sides, membership identical,
// exactly one entry moved, and its rendered delta was a single line — the
// cosign `subject:` matcher narrows from
// `(reusable-workflows|actions)/…@.+` to `actions/…@([0-9a-f]{40}|refs/tags/v.+)`.
// That drops the archived `reusable-workflows` repo as an accepted signer and
// stops a floating ref (e.g. `@refs/heads/main`) from satisfying the rule. The
// result is byte-identical to the live `publish-app` OCIRepository trust
// rules (wedding-app, ascoachingogvaner), so the template every
// tenant is generated from now carries the same rule its tenants do. It is
// strictly a tightening: every subject the new matcher accepts, the old one
// already accepted.
//
// moved line was the cosign subject, NOT one of the RGD's grant templates — the
// ServiceAccount and `tenant-edit` RoleBinding it expands to were untouched, no
// grant-bearing object moved, and the RGD being individually pinned meant its
// per-resource fingerprint moved with it and was re-approved from the same
// measurement. The value before that covered onboarding the `doggy-countdown`
// tenant, measured against e77fdb9c: a purely additive 503 -> 509 documents, one
// tenant skeleton, no existing entry modified. The one before that covered the
// cosign matcher tightening on the then-four live trust rules: 503 documents on
// both sides, four changed `subject:` lines, no grant-bearing object moved.)
//
// This value covers narrowing the github-config tenant Role from a resources
// wildcard to the managed-resource kinds its ManagedResourceActivationPolicy
// activates. Measured against main 72fe7919: 515 documents on both sides, with
// membership IDENTICAL — set difference in BOTH directions over
// apiVersion|kind|namespace|name returned zero, so nothing was added, removed
// or renamed. Exactly ONE entry's content moved:
//
//	rbac.authorization.k8s.io/v1  Role  github-config/github-config-managed-resources
//
// Its rendered delta replaces `resources: ['*']` on five
// `*.github.m.upbound.io` groups with the ten activated kinds, and adds
// `providerconfigs` for the ProviderConfig the tenant applies. It is strictly a
// tightening: every resource the new rules admit, the wildcard already admitted.
// The surface carries 133 Role / ClusterRole / RoleBinding / ClusterRoleBinding
// / ServiceAccount documents on BOTH sides, and every `aws`-bearing line is
// byte-identical across the two trees, so nothing granted to the aws/aws
// service account this validator exists to protect is touched.
//
// NOTE for whoever re-approves this next: an opaque ciphertext in the surface
// moves on ANY re-encryption — this value also absorbed a SOPS version bump
// (3.13.2 -> 3.13.3) — so a routine secret rotation reds this gate with no
// authorization change at all. Do NOT treat a moved hash as self-evidently
// benign: re-run the per-entry membership measurement above before re-approving.
// A Go toolchain is only needed to recompute the hash; MEMBERSHIP is a plain
// kubectl render diff — render k8s/providers/hetzner/{apps,infrastructure,
// infrastructure/controllers} plus k8s/clusters/prod/{bootstrap,} for both
// trees and diff them.
//
// Measured while releasing the Cilium homogeneous-device rollout gate, by
// rendering all five roots from both trees and diffing them. Four of the five
// roots — apps, infrastructure, bootstrap, prod — are byte-identical.
// Membership is unchanged: zero documents added, removed, or renamed. Exactly
// FOUR lines move in the whole production render, all of them inside the same
// document:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  kube-system/cilium
//	  spec.upgrade.disableWait: true            (removed)
//	  spec.values.updateStrategy.type: OnDelete (removed)
//	  spec.values.updateStrategy.rollingUpdate  (removed)
//
// Both were temporary overrides carried only while the widened device set was
// being introduced one node at a time. `updateStrategy` selects how the Cilium
// DaemonSet replaces pods and `upgrade.disableWait` selects whether Helm waits
// for them; neither reaches an identity, binding, policy document, or service
// account, and neither is an `aws`-bearing line. Every Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount document is byte-identical
// — trivially so, since the four differing lines are the entire delta across
// the surface and all four belong to one HelmRelease's rollout mechanics.
//
// The fingerprint itself was read from the required job's own output on the
// approved renderer, because the local toolchain is refused as unapproved.
//
// This value covers activating the Crossplane sync-state exporter (#2986) — the
// first change to reference that component, so its three objects enter the
// rendered surface for the first time. Measured by rendering the production
// roots with and without the single `components:` reference: grant-bearing
// documents go 67 -> 70, the set difference in the removal direction is EMPTY,
// and the three additions are the component's own:
//
//	ServiceAccount       observability/crossplane-sync-exporter
//	ClusterRole          crossplane-sync-exporter
//	ClusterRoleBinding   crossplane-sync-exporter
//
// Nothing else is added, removed or renamed, and no existing grant changes.
//
// The ClusterRole is get/list/watch on `repo.github.m.upbound.io/repositories`
// and nothing else — one API group, one resource, read-only. That is narrower
// than the alternative the issue originally specified (binding the aggregated
// `crossplane-view`, which carries 49 rules), which is why the deviation was
// taken; `scripts/tests/test-crossplane-sync-exporter.sh` pins the read-only
// verb set and rejects wildcard access so it cannot widen unobserved.
//
// Nothing granted to the aws/aws service account this validator exists to
// protect is touched: the additions are in `observability`, and the exporter
// cannot read any AWS-bearing resource.
//
// This value additionally covers granting that same exporter the CRD read its
// discovery path requires (#3068). The component shipped unable to read
// anything: kube-state-metrics resolves a CustomResourceStateMetrics
// `groupVersionKind` through the CRD API before it can build a store for it, so
// the repositories rule above is necessary but not sufficient, and without the
// CRD read the reflector retry-loops on a forbidden list while the workload
// reports itself Ready.
//
// Measured by rendering the production infrastructure root on the base commit
// and on this change: the diff is EIGHT added lines and nothing else. No
// document is removed, renamed, or otherwise altered, no resource enters or
// leaves the surface, and the set difference in the removal direction is EMPTY.
// The eight lines are one rule on the existing `crossplane-sync-exporter`
// ClusterRole:
//
//	apiGroups: ["apiextensions.k8s.io"]
//	resources: ["customresourcedefinitions"]
//	verbs:     ["get", "list", "watch"]
//
// The grant reads CRD *definitions*, which carry schemas, not the managed
// resources themselves — so the scoping rationale above is preserved intact:
// managed-resource access, where provider configuration actually lives, stays
// pinned to `repo.github.m.upbound.io/repositories`. It is read-only, and
// `scripts/tests/test-crossplane-sync-exporter.sh` now pins this rule too, so
// the discovery half can no longer go missing unobserved — which is exactly how
// it went missing the first time, since that contract asserted the
// managed-resource half alone.
//
// `resourceNames` cannot narrow it further: RBAC honours that field only for
// get/update/delete/patch, never for list or watch, and the discovery path
// lists.
//
// Nothing granted to the aws/aws service account is touched by this change
// either. The rule is cluster-scoped because CRD definitions are, but it
// confers no access to any AWS-bearing resource, identity, binding, policy
// document or service account.
//
// The fingerprint was produced by two independent renderers that agree
// exactly — the required CI job on the approved toolchain, and a local render —
// which is what rules out a renderer-version artifact in the value.
//
// This value additionally covers conditioning `kms:CreateGrant` on
// `kms:GrantIsForAWSResource=true` in the eks-ci-smoke permissions boundary
// (#2704). Measured by restoring main's copy of the one changed manifest and
// re-rendering all five roots from both trees: 22933 -> 22943 lines, and the
// ENTIRE delta across the production surface is
//
//	GONE   "kms:CreateGrant",   (leaving the unconditioned action list)
//	NEW    "Sid": "KmsGrantsForAwsResourcesOnly",
//	NEW    "Action": "kms:CreateGrant", "Resource": "*",
//	NEW    "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}}
//
// No `kind:` or `name:` line moves, so membership is identical — nothing was
// added, removed or renamed — and every other Role / ClusterRole / RoleBinding
// / ClusterRoleBinding / ServiceAccount document is byte-identical. It is
// strictly a tightening: the action was previously allowed unconditionally and
// is now allowed only for AWS-service-managed resources, so every grant the new
// form permits the old one already permitted. Only ONE per-resource fingerprint
// moves with it — the boundary Policy's own — which corroborates that the edit
// did not leak into any other document.
//
// One trap worth recording, because it looks exactly like a renderer-version
// artifact and is not: a `pull_request` CI job renders the PR's MERGE commit,
// while a local `go test` on the branch renders the branch against whatever
// base it was cut from. When main moves under a branch the two therefore
// disagree on the AGGREGATE surface value while still agreeing on every
// per-resource fingerprint, since the moved documents belong to main's change
// rather than the branch's. Compare like with like before concluding the
// toolchain is at fault.
//
// Measured against main 2f92d8ef before approving this value: the complete
// rendered authorization diff changes exactly one object, ClusterRole
// `cilium-tenant-edit`. Surface membership is unchanged. The only rendered
// change removes its built-in `aggregate-to-edit` label, so ordinary `edit`
// bindings no longer inherit Cilium policy access. The tenant-specific
// aggregation label and all rule verbs remain byte-identical to main: Flux can
// still server-side apply and prune tenant policies through `tenant-edit`.
// This strictly narrows which aggregate role inherits the grant without
// breaking that workflow. Platform#3150 separately tracks admission constraints
// for permissive or platform-owned tenant policy mutations. The committed-tree
// validation reported no per-resource mismatch; only this aggregate fingerprint
// moved.
//
// Measured by comparing base 0a97d6c7 with repair head 966ca01c before
// approving this value: the complete five-layer render diff changes exactly
// four selected entries. The mutateExisting ClusterPolicy is narrowed from
// arbitrary matching Deployments to umami/umami-umami and its fixed
// umami-umami-primary target. The cluster-wide aggregated ClusterRole that
// granted get/list/watch/update/patch on every Deployment is removed. In its
// place, one Role in umami grants only get/update/patch on the single
// umami-umami-primary Deployment, and one RoleBinding grants it only to
// Kyverno's background-controller ServiceAccount. No existing rendered entry
// changes, including the Umami Namespace, whose identical rendered form merely
// moves between two already-scanned ownership layers. The validator reported
// no per-resource mismatch; only this aggregate fingerprint moved.
//
// Measured by comparing the apps layer at branch baseline c7f2842f45b2 with
// the staged Umami provisioning repair using the CI-pinned kubectl v1.36.2
// renderer. Existing authorization documents are byte-identical. Membership
// adds exactly three namespaced entries, all named umami-provision-tenants: a
// ServiceAccount, a RoleBinding to only that ServiceAccount, and a Role whose
// only verbs are get/update on the single coordination.k8s.io Lease with that
// resourceName. The Lease itself is pre-created, so the workload cannot create
// or address any other coordination object.
//
// This value additionally covers the UniFi source containment repair in #2707,
// measured after rebasing the PR onto exact main 57ca1dbe. Three of the five
// authorization roots are byte-identical across main and this change:
// infrastructure/controllers, prod/bootstrap, and prod. The complete apps
// render has identical membership and exactly THREE changed fields across
// three existing documents:
//
//	rbac.authorization.k8s.io/v1    Role           unifi/unifi-managed-resources
//	  verbs: delete                                        (removed)
//	kustomize.toolkit.fluxcd.io/v1  Kustomization  unifi/unifi
//	  prune: true -> false
//	source.toolkit.fluxcd.io/v1      GitRepository  unifi/unifi
//	  ref.branch: main -> one full 40-hex ref.commit pin
//
// The first two changes remove deletion paths. The third replaces a moving
// branch with one full immutable commit from the expected repository, so a
// source-repository compromise cannot alter resources that retain patch/update
// authority without a separately reviewed Platform change. The semantic
// validatePinnedUnifiSource control and its negative tests reject branches,
// tags/mixed selectors, abbreviated hashes, substitutions, and alternate URLs
// before the aggregate hash is considered. The infrastructure render changes
// exactly one existing ClusterPolicy by adding the exact unifi/unifi admission
// exception needed to admit prune:false; validateUnifiPruneExemption pins that
// rule's complete exception set to flux-system/flux-system and unifi/unifi.
// No identity, binding, resource kind, or remaining verb moved.
//
// Measured by comparing exact current main 025fd5a6 with merge head 8654ae7
// for #2742 using the CI-pinned kubectl v1.36.2 / Kustomize v5.8.1 renderer.
// All five production authorization roots retain the same 170 selected
// identities: the set difference is empty in both directions. Exactly ONE
// selected entry changes:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  actual-budget/actual-budget
//
// Its complete projected delta adds ACTUAL_TOKEN_EXPIRATION=openid-provider
// to the existing post-rendered Deployment environment, which changes runtime
// session-expiry behavior. login.openid.tokenExpiration mirrors that value for
// chart-schema alignment; with ingress.enabled=false, chart 1.9.3 does not
// render or consume the OpenID Secret. No IAM, RBAC, Flux source, identity,
// binding, verb, or resource membership changes. The PR's HTTPRoute, ReferenceGrant,
// CiliumNetworkPolicy, and auth-proxy configuration are outside this
// EKS/RBAC/Flux selector, so this fingerprint deliberately makes no claim that
// it validates those independently reviewed surfaces.
//
// Measured against exact current main b32ba493 with merge head 162815ee for
// #2740. The change is a privilege REDUCTION plus one new admission guardrail;
// the complete rendered authorization delta is:
//
//	rbac.authorization.k8s.io/v1  ClusterRole  gateway-tenant-edit
//	  metadata.labels."rbac.authorization.k8s.io/aggregate-to-edit"  (removed)
//
//	kyverno.io/v1  ClusterPolicy  restrict-tenant-route-hostnames  (added)
//
// Removing the built-in aggregation label means ordinary `edit` bindings in
// EVERY namespace no longer inherit Gateway API route verbs. The tenant-specific
// `devantler.tech/aggregate-to-tenant-edit` label and all rule verbs remain
// byte-identical to main, so tenant ServiceAccounts keep exactly the access they
// had through `tenant-edit`. This is the same strict narrowing already approved
// above for `cilium-tenant-edit`, applied to the Gateway API grant.
//
// The added ClusterPolicy grants nothing. It is an Enforce admission rule
// confining each tenant namespace's HTTPRoute hostnames to that tenant's own
// declared set, denying hostname-less routes (which match every hostname on the
// shared wildcard listener), and fail-closed denying any ksail tenant namespace
// with no explicit allow-list. It enters the surface because a policy document
// is authorization-capable, not because it confers a grant.
//
// No identity, binding, ServiceAccount, or verb is added anywhere, and nothing
// granted to the aws/aws service account this validator protects is touched.
// The validator reported no per-resource mismatch; only this aggregate
// fingerprint moved.
//
// The fingerprint was read from the required job's own output on the approved
// renderer, because the local toolchain is refused as unapproved. It was
// re-measured after merging exact main b32ba493: the branch's earlier value
// (5c5d36cc, rendered against a main 10 commits older) no longer described the
// merge result, so it was never approved.
//
// Measured against exact current main 64767a99 after merging it into #2714,
// using the checksum-verified kubectl v1.36.2 / Kustomize v5.8.1 renderer.
// Four of the five complete production roots are byte-identical. The only
// rendered delta is in the infrastructure root and changes exactly ONE entry:
//
//	rbac.authorization.k8s.io/v1  ClusterRole  cluster-reader
//
// Its complete delta removes two API groups from the read-only allow-list:
//
//	coroot.com
//	helm.toolkit.fluxcd.io
//
// Resource membership is identical: no apiVersion, kind, namespace, or name
// line moves in any root. Both removals are privilege reductions. HelmRelease
// specs persist substituted and inline values, while the production Coroot
// Cluster persists the substituted alertmanager_webhook_url. Removing their
// groups prevents an OIDC cluster-reader from recovering those credentials;
// no identity, binding, resource, or verb is added. A parsed-RBAC regression
// independently rejects any future read grant to either secret-bearing group.
//
// Measured against exact current main 388758f5 for #3168 with the
// checksum-verified kubectl v1.36.2 / Kustomize v5.8.1 renderer. The new
// production component is an AnnotationsTransformer whose fieldSpecs select
// only PersistentVolumeClaim, HelmRelease, and Namespace, so it cannot mutate
// a Role, ClusterRole, RoleBinding, ClusterRoleBinding, or ServiceAccount.
// Resource membership across all five production roots is unchanged. The
// rendered changes add only kustomize.toolkit.fluxcd.io/prune=disabled to those
// three selected kinds and kustomize.toolkit.fluxcd.io/force=disabled to PVCs;
// the existing vault-snapshots force override narrows enabled to disabled.
// These metadata-only changes prevent destructive reconciliation and grant no
// identity, binding, resource, or verb.
//
// Measured against exact current main cdababde for #2741 with the
// checksum-verified kubectl v1.36.2 / Kustomize v5.8.1 renderer. The complete
// apps, infrastructure, and controller roots retain 126, 219, and 178
// documents respectively. Apps replaces the retired headlamp/headlamp PVC with
// the authenticated crossview/crossview HTTPRoute; both are outside this
// authorization selector. Infrastructure and controller membership is
// identical. Rendered Role, ClusterRole, RoleBinding, ClusterRoleBinding, and
// ServiceAccount bytes are identical in all three roots, and the two direct AWS
// policy inputs are byte-identical. Exactly THREE selected entries change:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  crossview/crossview
//	helm.toolkit.fluxcd.io/v2  HelmRelease  headlamp/headlamp
//	helm.toolkit.fluxcd.io/v2  HelmRelease  dex/dex
//
// Headlamp disables the runtime plugin manager and its writable plugin state.
// Crossview changes only its CORS origin and OIDC callback from the removed
// localhost port-forward to its native authenticated HTTPS route. Dex replaces
// that localhost callback with the exact HTTPS callback. Chart/source identity,
// reconciliation policy, workload ServiceAccounts, every RBAC object, and every
// verb remain byte-identical. The Cilium policies and HTTPRoute are outside this
// selector and are covered by the focused rendered fresh/upgrade-path test.
//
// Measured by comparing exact reviewed head 253b7aa7 with the maintainer-access
// repair for #2741, using the checksum-verified kubectl v1.36.2 / Kustomize
// v5.8.1 renderer. All five roots retain 532 distinct rendered identities and
// the set difference is empty in both directions. The complete rendered change
// is confined to six existing objects: Crossview's HTTPRoute and
// CiliumNetworkPolicy, oauth2-proxy's ReferenceGrant, auth-proxy's ConfigMap
// and CiliumNetworkPolicy, and Headlamp's HelmRelease.
//
// Of those six, exactly ONE enters this validator's 170-entry selected
// EKS/RBAC/Flux authorization projection:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  headlamp/headlamp
//
// Its complete projected delta removes the post-render patch that appended a
// temporary volume mount to container index 1. The same release already
// disables the dynamic plugin manager, so that sidecar is absent; retaining the
// patch made the Helm render invalid instead of granting or withholding access.
//
// The other five objects restore Crossview's established outer maintainer gate:
// Gateway -> oauth2-proxy allowed_groups -> host-routing auth-proxy -> Crossview,
// with exact ReferenceGrant and Cilium ingress/egress peers. They are outside
// this selector and covered by the focused rendered contract. Across all five
// roots, all 56 distinct RBAC identities have byte-identical canonical content,
// and the direct EKS role and permissions-boundary inputs are byte-identical.
//
// Measured by comparing exact reviewed head 57f70354 with the merge-group
// deployment repair for #2741, using the checksum-verified kubectl v1.36.2 /
// Kustomize v5.8.1 renderer. The five roots retain 126, 219, 178, 5, and 4
// documents respectively. Their combined 532 distinct identities are identical
// in both directions. Exactly ONE existing rendered object changes:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  headlamp/headlamp
//
// The release removes JSON append operations whose volumes and volumeMounts
// parent arrays disappear when pluginsManager and its PVC are disabled, and
// supplies the same two writable directories through Headlamp 0.44.0's native
// chart values instead. This repairs the post-render failure observed in the
// merge group without changing an identity, chart/source pin, ServiceAccount,
// binding, or verb. All 71 distinct rendered Role, ClusterRole, RoleBinding,
// ClusterRoleBinding, and ServiceAccount objects are byte-identical, and the
// direct EKS role and permissions-boundary inputs retain their approved hashes.
//
// Recomputed after rebasing the complete #2741 series onto exact protected
// main cdababde. The persistence annotations introduced by #3168 remain in
// every surviving selected object; #2741 removes only the already-protected
// Headlamp PVC identity and retains the authorization-neutral changes above.
//
// Re-approved for #3181 (2026-08-17), which reclaims orphaned Longhorn replica
// directories. Measured by rendering the hetzner infrastructure/controllers
// root with main's copy of the single changed file and again with the head's
// copy. The complete rendered delta across the whole surface is ONE added line
// inside an existing object:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  longhorn-system/longhorn
//	+      orphanResourceAutoDeletion: replica-data
//
// That is a Helm chart value under spec.values. No identity, ServiceAccount,
// binding, rule, subject, verb, apiGroup, or chart/source pin moved: the root
// retains 177 documents and 21 distinct Role / ClusterRole / RoleBinding /
// ClusterRoleBinding objects on both sides, and the delta contains no rules:,
// subjects:, verbs:, or apiGroups: line. The direct EKS role and
// permissions-boundary inputs are untouched — the PR changes exactly one file.
// The value only authorizes Longhorn's own manager to delete replica data it
// has already marked DataCleanable on disks it owns; it grants nothing to the
// aws/aws service account this selector protects.
// Measured for #2709, which narrows Dex's GitHub connector to the
// devantler-tech/maintainers team, merged with exact main 6ebcb24f. Two
// independent renderers agree on this value: the required CI job on the approved
// toolchain (run 31973901010) and a local render. The branch's own earlier value
// was rendered against an older main and never described this merge result.
//
// The reviewed reasoning for the change itself is unaffected by the merge. Of
// the three manifests the branch touches, only the Dex connector is semantic: it
// adds a `teams: [maintainers]` entry under the existing org-scoped GitHub
// connector, so Dex authenticates the maintainers team instead of every
// devantler-tech org member. That matters for apps authenticating natively
// against Dex rather than through oauth2-proxy's allowed_groups gate. The
// oauth2-proxy and crossview releases change only comment text inside the
// rendered values. This is a privilege REDUCTION on every axis: the
// authenticated population strictly shrinks, and no identity, binding,
// ServiceAccount, resource, or verb is added anywhere. Nothing granted to the
// aws/aws service account this validator protects is touched.
//
// Measured for #2713 merged with exact main 6ebcb24f. Two independent renderers
// agree on this value: the required CI job on the approved toolchain (run
// 31974280947) and a local render. The branch's own earlier value was rendered
// against main 6d926e42 and never described this merge result.
//
// The reviewed reasoning for the change itself is unaffected by the merge. The
// complete authorization delta changes exactly ONE selected entry:
//
//	rbac.authorization.k8s.io/v1  ClusterRole  gateway-tenant-edit
//
// Its resources are narrowed from httproutes, grpcroutes, tcproutes, tlsroutes,
// udproutes and referencegrants to httproutes and referencegrants. The removed
// four route kinds bypass the HTTPRoute-only tenant hostname policy on the
// shared Gateway. Identity, labels, verbs, apiGroups, bindings and membership
// are otherwise byte-identical, so this is a strict privilege reduction. Main
// already carries the canonical restrict-tenant-route-hostnames policy and the
// removal of built-in edit aggregation; neither is duplicated by this change.
// Gateway listener-kind pins are outside this authorization projection and are
// covered by scripts/tests/test-tenant-route-hostname-boundary.sh.
//
// Measured for the #2725 Umami provisioning repair merged with exact main
// 6ebcb24f. Two independent renderers agree on this value: the required CI job
// on the approved toolchain (run 31973534571) and a local render.
//
// Unlike the reductions recorded above, this delta ADDS a grant. The Umami
// scheduled and bootstrap provisioners serialise through one named Lease, so
// the merge introduces:
//
//	rbac.authorization.k8s.io/v1  Role         umami/umami-provision-tenants
//	rbac.authorization.k8s.io/v1  RoleBinding  umami/umami-provision-tenants
//	coordination.k8s.io/v1        Lease        umami/umami-provision-tenants
//	batch/v1                      Job          umami/umami-provision-tenants-bootstrap
//
// The Role's complete rule set is `get` and `update` on `leases`, restricted by
// resourceNames to the single `umami-provision-tenants` Lease; the RoleBinding
// binds it to that namespace's own ServiceAccount and to nothing else. No other
// identity, binding, resource, or verb is added, and nothing granted to the
// aws/aws service account this validator protects is touched.
//
// The CronJob adds Lease coordination to its existing pod template and requests
// the projected token at pod level, which the ServiceAccount's own default still
// withholds from every other consumer. The apps Flux Kustomization timeout moves
// from 20m to 30m in both rendered cluster overlays. The ServiceAccount itself is
// unchanged from main in canonical content.
//
// Re-measured for #3181 after merging exact main d925654e, which had advanced past
// the head the #3181 value above was taken on. Rendered with the approved renderer
// (kubectl v1.36.2, Kustomize v5.8.1); the same renderer validates clean main
// green, which is what establishes it as equivalent to the required job's.
// Re-measured for #2709 after merging exact main d925654e, which had advanced past
// the 6ebcb24f the #2709 value above was taken on. Rendered with the approved
// renderer (kubectl v1.36.2, Kustomize v5.8.1); the same renderer validates clean
// main green, which is what establishes it as equivalent to the required job's.
//
// Conservation across the five authorization roots, measured by rendering both
// trees and comparing:
//
//	k8s/clusters/prod                                 byte-identical
//	k8s/clusters/prod/bootstrap                       byte-identical
//	k8s/providers/hetzner/apps                        byte-identical
//	k8s/providers/hetzner/infrastructure              byte-identical
//	k8s/providers/hetzner/infrastructure/controllers  1 added line, nothing else
//
// The delta is still the single chart value inside an existing object:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  longhorn-system/longhorn
//	+      orphanResourceAutoDeletion: replica-data
//	k8s/providers/hetzner/infrastructure/controllers  2 added lines + comment text
//
// The complete rendered delta is the connector narrowing plus one comment block:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  dex/dex
//	+            teams:
//	+            - maintainers
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  oauth2-proxy/oauth2-proxy
//	  comment text only, inside spec.values
//
// Resource membership in the controllers root is identical — 178 selected
// documents and 21 distinct Role / ClusterRole / RoleBinding / ClusterRoleBinding
// objects on both sides, with no apiVersion, kind, namespace, or name line added,
// removed, or moved — and the delta contains no rules:, subjects:, verbs:, or
// apiGroups: line. The count is 178 rather than the 177 recorded above because
// main itself grew one document in the interval, not because this change adds one.
// The validator reported no per-resource mismatch, no missing resource and no
// duplicate — only this aggregate.
//
// The value still only authorizes Longhorn's own manager to delete replica data it
// has already marked DataCleanable on disks it owns; it grants nothing to the
// aws/aws service account this selector protects.
//
// removed, or moved. The validator reported no per-resource mismatch, no missing
// resource and no duplicate — only this aggregate.
//
// The reviewed reasoning is unchanged and still a privilege REDUCTION on every
// axis: Dex authenticates the maintainers team instead of every devantler-tech org
// member, so the authenticated population strictly shrinks, and no identity,
// binding, ServiceAccount, resource, or verb is added anywhere. Nothing granted to
// the aws/aws service account this validator protects is touched.
// Re-approved after merging main into this branch. Both parents measured against
// the same exact main 6ebcb24f, but each described only its own delta — this
// branch the gateway-tenant-edit route-kind narrowing, main the #2725 Umami
// provisioning grant — so neither value describes the merge result, and the
// conflict could not be resolved by picking a side. Both records above are
// retained because both deltas are present in the merged surface: a strict
// privilege reduction on one selected ClusterRole, and the Lease-scoped Umami
// provisioning grant. They are independent and neither cancels the other, so the
// grant-bearing accounting recorded for each carries over unchanged and only the
// whole-surface digest moves.
//
// Measured against the merge result at c790f999. Two independent renderers agree
// on the value below: the required `🔐 Validate EKS Authorization` job (run
// 32019353067) and a local render on kubectl v1.36.1 / kustomize v5.8.1.
//
// Conservation behind the new digest: the whole-surface fingerprint is the ONLY
// control that moved. Both renderers report zero per-identity mismatches and
// zero missing resources against expectedRenderedHashes, so every individually
// approved entry — including both parents' deltas — is byte-identical to its
// recorded value and only the aggregate over the entry set changed. Both also
// report the same 35 unresolved-substitution notes, which are diagnostic rather
// than a control: a resource carrying `${…}` is forced into the aggregate, so
// its literal text is already covered by this digest.
//
// That symmetry corrects the assumption recorded before the measurement, which
// held that a local render could not approve this because it would be incomplete
// without the CI substitution inputs. The approved toolchain reports the same 35
// notes and the same digest, so the two renders are equivalent here and the
// local one is a genuine second renderer rather than a degraded copy.
//
// Re-approved after merging main d925654e into this branch. Both parents had
// re-approved this constant independently — main for the #2725 Umami
// provisioning grant recorded directly above, and this branch for the crossview
// reload annotation recorded at the top of this block — so neither parent's
// value describes the merge result, and the conflict could not be resolved by
// picking a side. The merged surface is main's #2725 surface with the crossview
// HelmRelease's single annotation delta applied on top; that delta is
// authorization-neutral, so the grant-bearing accounting recorded for #2725
// carries over unchanged and only the whole-surface digest moves.
//
// The value below is the digest the required `🔐 Validate EKS Authorization`
// job measured on the approved toolchain for this merged surface, reported by
// its rejection of the carried-through placeholder. It is recorded here from
// that measurement rather than guessed, per the plan above.
//
// Only ONE renderer stands behind it, and that is stated rather than glossed:
// the approved CI toolchain. A local render cannot corroborate it, because
// without the CI substitution inputs it reports unresolved Flux substitutions
// and is incomplete — the same reason the placeholder was carried through
// unmeasured. So this value does not meet the two-independent-renderer bar the
// reductions recorded above met; it rests on the required job alone.
//
// One independent observation does corroborate that the crossview delta is the
// only thing moving the digest: the required job reported this identical value
// at head 632e2ff3 (before main was merged in) and again at head 422f1890
// (after). Main's intervening commit therefore did not move the authorization
// surface, which is consistent with its content — documentation plus a Kyverno
// policy description annotation, carrying no grant. That is evidence about
// what did NOT change; it is not a second rendering of what did.
//
// Re-approved after merging main b9af3892 into this branch, whose own parent is
// 90cf208e. Both parents had re-approved this constant independently — this
// branch for the gateway-tenant-edit route-kind narrowing recorded above, and
// main for the crossview reload annotation recorded directly above — so neither
// parent's value describes the merge result and the conflict could not be
// resolved by picking a side. The merged surface is main's b9af3892 surface with
// this branch's single authorization delta applied on top: the strict privilege
// reduction on ClusterRole gateway-tenant-edit already described above. Main's
// grant-bearing accounting for the #2725 Umami provisioning repair reached this
// branch through the earlier merge and is unchanged by this one, so only the
// whole-surface digest moves.
//
// Two independent renderers agree on the value below, and each was first proved
// against clean main b9af3892 as a matched control:
//
//   - the approved toolchain (checksum-verified kubectl v1.36.2 / Kustomize
//     v5.8.1) running this validator, which reports the contract passing on
//     clean main and this digest on the merge result;
//   - a local render on kubectl v1.36.1 / Kustomize v5.8.1 through
//     TestValidateAuthorizationAcceptsCommittedPolicy, which passes on clean
//     main and reports this same digest on the merge result.
//
// The matched controls are what make the measurement trustworthy rather than a
// guess: both renderers reproduce every already-approved digest in main, so the
// one value they disagree with main about is the one this merge actually moved.
//
// Conservation behind the new digest: the whole-surface fingerprint is the ONLY
// control that moved. The run reports exactly one problem — this aggregate — and
// zero per-identity mismatches and zero missing resources against
// expectedRenderedHashes, so every individually approved entry is byte-identical
// to its recorded value. It also reports the same 35 unresolved-substitution
// notes that clean main reports; those are diagnostic rather than a control,
// emitted only alongside an aggregate mismatch to explain a hash that moved, and
// a resource carrying `${…}` is forced into the aggregate so its literal text is
// already covered by this digest.
//
// Re-approved after merging main 9a84e92b into this branch. Both parents had
// re-approved this constant independently — this branch for the #3181 Longhorn
// orphan-reclamation chart value recorded above, and main for the #2713
// gateway-tenant-edit route-kind narrowing — so neither parent's value describes
// the merge result and the conflict could not be resolved by picking a side. Both
// records are retained because both deltas are present in the merged surface.
//
// The merged surface is main 9a84e92b's surface with this branch's single Longhorn
// chart-value delta applied on top. Clean main's digest is the value recorded
// below: main's own required `🔐 Validate EKS Authorization` job is green at
// 9a84e92b while that constant is committed there, which is what establishes it as
// clean main's measured digest rather than an assumption.
//
// This branch's delta remains the one added line under spec.values:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  longhorn-system/longhorn
//	+      orphanResourceAutoDeletion: replica-data
//
// Measured against main d925654e when that value was approved: no identity,
// ServiceAccount, binding, rule, subject, verb, apiGroup, or chart/source pin
// moved, and the delta carried no rules:, subjects:, verbs:, or apiGroups: line.
// That accounting is inherited from that measurement and has NOT been re-verified
// against 9a84e92b.
//
// MEASURED — this discharges the placeholder that stood here. The required
// `🔐 Validate EKS Authorization` job rejected clean main's carried-through digest
// exactly as predicted and reported the merge result's actual value, recorded
// below from run 32070742779 at head 74676d5a.
//
// Taken on exact main feaf5059, which is NEWER than the 9a84e92b the placeholder
// named: the branch was levelled to `behind_by` 0 before the measurement, so this
// digest describes the current merge result rather than the older one.
//
// Conservation re-verified at that head, which is what the placeholder required
// before promotion: the aggregate is the ONLY control that moved — zero
// per-identity mismatches, zero missing resources, and zero duplicates against
// expectedRenderedHashes, so every individually approved entry is byte-identical
// and surface MEMBERSHIP is unchanged. The run reports the same 35
// unresolved-substitution notes clean main reports.
//
// The earlier CDN failure that blocked measurement is not repaired by this and is
// not silently dropped: the render still accumulates pinned remote resources over
// the network (tracked as #3196), so a local render remains unavailable here. Only
// ONE renderer therefore stands behind this digest — the approved CI toolchain.
// The local kubectl is v1.36.1 against an approved v1.36.2, so
// validateRendererVersion fails closed and cannot corroborate.
//
// One independent observation does corroborate that only this branch's own delta
// moves the digest: the required job reported this IDENTICAL value at head
// 07ec2b5f, before main was merged in, and again at 74676d5a after four further
// main commits. Those commits therefore did not move the authorization surface.
// That is evidence about what did NOT change; it is not a second rendering of what
// did.
//
// The delta remains authorization-neutral — one chart value under spec.values,
// carrying no rules, subjects, verbs, or apiGroups line, and moving no identity,
// ServiceAccount, binding, or chart/source pin.
//
// ⚠️ The #3181 digest measured above is RETAINED AS A RECORD ONLY and is no longer
// the constant: main has since merged #2709, so it describes a merge result that
// no longer exists. Recorded in full so the measurement is not lost:
//
//	489afc6651045b6643ee40e0098234a873174a8d807690efb0245aaf92f87a4b
//
// It was measured on exact main feaf5059 at head 74676d5a (run 32070742779). See
// the placeholder note at the end of this block for what supersedes it.
//
// Approved for #2709 on exact main feaf5059, which is the value recorded below.
// This SUPERSEDES the two earlier #2709 records above, measured on the 6ebcb24f
// and d925654e merge states; neither was ever committed, because each described a
// merge result that a later main had already moved past. They are kept as the
// branch's measurement history, not as candidate values.
//
// Measured by the required `🔐 Validate EKS Authorization` job (run 32069284792)
// at head 1d357303, taken with the branch level against main — `behind_by` is 0,
// so this digest describes the merge result rather than a stale rendering of it.
//
// Only ONE renderer stands behind it, and that is stated rather than glossed: the
// approved CI toolchain. The local kubectl here is v1.36.1 against an approved
// v1.36.2, so validateRendererVersion fails closed and a local render cannot
// corroborate. It therefore does not meet the two-independent-renderer bar the
// reductions recorded above met; it rests on the required job alone.
//
// Two independent observations do corroborate that the leveling merge moved
// nothing, which is what makes the single rendering safe to approve:
//
//   - the required job reported this IDENTICAL digest at head 629bdd10 (before
//     main was merged in) and again at head 1d357303 (after), so the merge itself
//     did not move the surface;
//   - main feaf5059 already contains that merge's only k8s change — Checkov skip
//     annotations on the umami CronJob — and the required job PASSES on main
//     against the previous digest, so those annotations are not in the surface at
//     all. That is evidence about what did NOT change; it is not a second
//     rendering of what did.
//
// Conservation behind the new digest: the whole-surface fingerprint is the ONLY
// control that moved. The run reports exactly one problem — this aggregate — and
// zero per-identity mismatches, zero missing resources, zero duplicates, and zero
// encrypted-resource findings, so every individually approved entry is
// byte-identical to its recorded value and surface MEMBERSHIP is unchanged. It
// reports the same 35 unresolved-substitution notes that clean main reports.
//
// The reviewed reasoning is unchanged and is a privilege REDUCTION on every axis.
// Of the three files the branch touches, only the Dex connector is semantic: it
// adds a `teams: [maintainers]` entry under the existing org-scoped GitHub
// connector, so Dex authenticates the maintainers team instead of every
// devantler-tech org member — which is what gates apps authenticating natively
// against Dex rather than through oauth2-proxy's allowed_groups. The oauth2-proxy
// release changes only comment text inside its rendered values, and this file is
// not part of the rendered surface. No identity, binding, ServiceAccount,
// resource, or verb is added anywhere, and nothing granted to the aws/aws service
// account this validator protects is touched.
//
// The merge of main 6c5506fe into this branch needed re-approval, because both
// parents had re-approved this constant independently — this branch for the #3181
// Longhorn orphan-reclamation chart value (`489afc66`, recorded above), and main
// for the #2709 Dex maintainers-team narrowing (`8773eaf0`) — so NEITHER parent's
// value described the merge result and the conflict could not be resolved by
// picking a side. Both records are retained because both deltas are present in the
// merged surface: main's Dex connector narrowing AND this branch's Longhorn chart
// value.
//
// The merge result is now MEASURED, and is the value recorded below. The required
// `🔐 Validate EKS Authorization` job rejected the carried-through placeholder at
// head 2ec723d9 (run 32073398792) and reported the merge result's actual digest.
// It was taken with the branch level against main 6c5506fe — `behind_by` is 0 — so
// it describes the merge result rather than a stale rendering of it.
//
// Conservation, measured against this branch's OWN pre-merge rendering at head
// 74676d5a (run 32071082835). That control is what isolates main's contribution:
// both renderings already contain this branch's Longhorn delta, so their
// difference is exactly what the merge brought in. Both report the same 35
// unresolved-substitution notes, all 35 distinct, with ZERO resources added, ZERO
// removed and ZERO duplicated — surface MEMBERSHIP is unchanged. Exactly TWO
// per-identity fingerprints move:
//
//	HelmRelease dex/dex                    c62d1a9f… → 6192cf46…
//	HelmRelease oauth2-proxy/oauth2-proxy  60750d76… → 24f03c83…
//
// Those are precisely the two manifests #2709 changes — it touches
// `controllers/dex/helm-release.yaml`, `controllers/oauth2-proxy/helm-release.yaml`
// and this validator, the last of which is not in the surface. So the prediction
// was falsifiable and held: had the merge carried anything else into the
// authorization surface, a third identity would have moved. Main 6c5506fe contains
// #2709 and PASSES the required job against its own digest `8773eaf0`, so both
// moved documents are already approved on main. Nothing outside them moved, which
// leaves the aggregate as the only control this merge changes. Main's own digest is
// recorded here in full, so replacing the constant does not lose it:
//
//	8773eaf0015f04f14850c5ef025b81657b0ad8d3aab397d99cf969044c04d7e6
//
// Only ONE renderer stands behind this value, as with the records above: the
// approved CI toolchain, via the required job. The local kubectl is v1.36.1
// against an approved v1.36.2, so validateRendererVersion fails closed and cannot
// corroborate.
// Re-measured for #2737 after merging exact main c4fb7f2d, which had advanced
// eleven commits past the base the branch's earlier value was rendered against.
// That stale value never described this merge result, so it is replaced rather
// than re-approved.
//
// The complete delta over main is TWO files, one line each, and nothing else:
//
//	source.toolkit.fluxcd.io/v1  OCIRepository  ascoachingogvaner/ascoachingogvaner
//	  spec.ref.semver: ">=1.0.0"  (removed)
//	  spec.ref.tag:    1.13.4     (added)
//
//	source.toolkit.fluxcd.io/v1  OCIRepository  wedding-app/wedding-app
//	  spec.ref.semver: ">=1.0.0"  (removed)
//	  spec.ref.tag:    1.15.10    (added)
//
// Both are Flux sources and isAuthorizationKind selects OCIRepository, so their
// projected text is covered by the aggregate. Neither carries a pinned entry in
// expectedResourceSHAs, so the aggregate is the ONLY control that can move for
// this change: a per-identity mismatch was never an available signal here, and
// its absence is therefore not evidence on its own.
//
// Conservation reported by the required job on this merge result: ZERO
// per-identity mismatches, ZERO missing resources and ZERO duplicates, so
// surface membership is unchanged. The 35 unresolved-substitution notes are the
// diagnostics emitted alongside any aggregate mismatch and are not findings; no
// note names either tenant OCIRepository, which is the positive signal that the
// pins did not disturb substitution.
//
// The change is a reduction in what may be deployed: a floating ">=1.0.0" range
// lets ANY newer tag published to that registry path be selected and reconciled
// unattended, so whoever can publish a tag chooses the manifests; a fixed tag
// removes that selection. Each tag is the revision production is already
// reconciling, so this pins what is running rather than moving it. No identity,
// binding, ServiceAccount, verb, policy or URL changes, and nothing granted to
// the aws/aws service account this validator protects is touched.
//
// Main's own approved digest is recorded here in full, so replacing the constant
// does not lose it:
//
//	ed2767037a88348b22ec8ecfcc8b2081e86b7979dfe3c86d554034980af01fdf
//
// Only ONE renderer stands behind the new value: the approved CI toolchain via
// the required job. The local kubectl is v1.36.1 against an approved v1.36.2, so
// validateRendererVersion fails closed and cannot corroborate.
//
// This value additionally covers dropping all Linux capabilities and pinning a
// container-level seccompProfile on the four kubescape-operator Deployments
// (#3064). The surface moves only because a HelmRelease is an
// isControllerRBACEmitter, not because any grant changed. Measured by rendering
// all five authorization overlays from both trees, identical but for that one
// manifest:
//
//	765721 -> 766201 bytes. The ENTIRE delta is 16 added lines and ZERO removed
//	lines, all of them the one `postRenderers:` block on
//	helm.toolkit.fluxcd.io/v2 HelmRelease kubescape/kubescape.
//
// Grant-bearing document membership is 74 -> 74 and set-IDENTICAL in both
// directions (Role 11, ClusterRole 22, RoleBinding 16, ClusterRoleBinding 10,
// ServiceAccount 15) — nothing added, removed or renamed. The count is
// corroborated by two independent extractions that agree exactly, because the
// first shapes tried returned a silent 0 and then a nonsense 375058 on the same
// input.
//
// The only `kind: Deployment` line in the delta is the patch TARGET selector,
// not a granted identity; the patch body only ever removes capability
// (`drop: [ALL]`) and pins a seccomp profile. No identity, binding, verb, policy
// document, ServiceAccount or `aws`-bearing line is touched.
//
// The previous approved digest is recorded here in full, so replacing the
// constant does not lose it:
//
//	21195b64582f0cc99b42cc6ee61c77610972c12b1556c3b254f68b15ce95d7fa
//
// The new fingerprint was read from the required job's own output on the
// approved renderer (run 32141093701), because the local toolchain is refused as
// unapproved — the same single-renderer caveat as the value it replaces.
// This value additionally covers adding the posture-staleness-alert check
// (#3024): a CronJob in the observability namespace that reads Kubescape's
// stored configuration-scan objects and alerts when they stop being refreshed.
//
// Grant-bearing objects DID move here, additively: 74 -> 77 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents, being the three
// this check introduces — one dedicated ServiceAccount, one narrow ClusterRole,
// and one binding between exactly those two identities. Same shape as the
// cnpg-degraded-alert addition recorded above. The ClusterRole is list-only on a
// single resource type (workloadconfigurationscans in the
// spdx.softwarecomposition.kubescape.io group) and grants nothing else; it is
// cluster-scoped only because the check must find the newest scan across every
// scanned namespace.
//
// Measured by rendering all five authorization overlays from both trees and
// diffing grant-bearing document IDENTITIES, not merely counts:
//
//	main 353379fd = 74 (Role 11, ClusterRole 22, RoleBinding 16,
//	ClusterRoleBinding 10, ServiceAccount 15) — which independently reproduces
//	the membership already recorded above, corroborating the extraction rather
//	than assuming it.
//	this branch   = 77 (ClusterRole 23, ClusterRoleBinding 11, ServiceAccount 16;
//	Role and RoleBinding UNCHANGED).
//
// The added-set is exactly ServiceAccount observability/posture-staleness-alert,
// ClusterRole posture-staleness-alert and ClusterRoleBinding
// posture-staleness-alert. The removed-set is EMPTY — nothing displaced, renamed
// or re-scoped. No identity, binding, verb, policy document or `aws`-bearing
// line belonging to the aws/aws service account this validator protects is
// touched.
//
// The previous approved digest is recorded here in full, so replacing the
// constant does not lose it:
//
//	f204a2d25d468376946989ab2378c41de86f9f66b0cda21b5f80f54bc99d2306
//
// The new fingerprint was read from the required job's own output on the
// approved renderer (run 32215442664), because the local toolchain is refused as
// unapproved — kubectl v1.36.1 against an approved v1.36.2, so
// validateRendererVersion fails closed and cannot corroborate. The same
// single-renderer caveat as the value it replaces.
// This value additionally covers pinning OpenBao off the autoscaler nodes
// (#2363, PR #3286): a required nodeAffinity on the openbao HelmRelease's
// `server.affinity`, so its single-attach hcloud volumes cannot ride a node the
// autoscaler may delete.
//
// NOTHING grant-bearing moved. Membership is 77 -> 77 and set-IDENTICAL in both
// directions (Role 11, ClusterRole 23, RoleBinding 16, ClusterRoleBinding 11,
// ServiceAccount 16) — added-set EMPTY, removed-set EMPTY. Beyond membership,
// the 77 documents' full canonical CONTENT hashes identically on both trees
// (4932afd49d173ea6), so no rule, subject or verb changed inside an object whose
// name stayed the same.
//
// Across all five authorization overlays — 1093 rendered documents — EXACTLY ONE
// document differs: helm.toolkit.fluxcd.io/v2 HelmRelease openbao/openbao,
// 4812 -> 5334 bytes, the added affinity value. That per-document diff firing on
// openbao and nowhere else is its own positive control for the comparison.
//
// No identity, binding, verb, policy document, ServiceAccount or `aws`-bearing
// line is touched: the 223 aws/eks/sts-bearing lines hash identically on both
// trees (e00b36ee90f0d5e8), and a PLANTED extra `sts:AssumeRole` line was
// confirmed to make that same comparison FIRE, so the identical result is a
// measurement rather than a vacuous pass.
//
// The previous approved digest is recorded here in full, so replacing the
// constant does not lose it:
//
//	3fda03fc7bdccf0a4a9d9057609ea20c0853af6d619523b94d56d21bca77fa71
//
// The new fingerprint was read from the required job's own output on the
// approved renderer (run 32484160592, job 96776995320). UNLIKE the two values
// above, it is NOT single-renderer: the local toolchain is still refused as
// unapproved (kubectl v1.36.1 against the approved v1.36.2, so
// validateRendererVersion fails closed), yet running this same validator locally
// produced the IDENTICAL fingerprint. The two kubectl patch releases therefore
// render this surface byte-identically, which corroborates the value rather than
// resting on one renderer. The conservation figures above were computed with the
// SAME local renderer on both trees, so that comparison is unaffected by the pin.
//
// Measured against current main 026372f9 before approving this value: the
// authorization-surface membership is unchanged. Exactly one selected
// authorization-capable document moves:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  kube-system/cilium
//
// Its complete rendered delta changes only the SPIRE data-permission init
// container's pinned BusyBox index from fd8d9aa6... to dc2d74b2.... The
// command, name, security context, volume mounts, service account, and all
// chart values around it are byte-identical. The same digest moves in both
// containers of userns-longhorn-smoke, a production-only Job deliberately
// omitted from its parent kustomization until a short-lived activation PR;
// their commands, non-root identities, and restrictive security contexts are
// unchanged. No subject, role, binding, verb, AWS identity, permission, or
// grant-bearing source file changes.
//
// The previous approved digest remains recorded here:
//
//	dc6ca143f54e95da342e7da1bdb747f02fa782f1d7dc5ec5cf9488151687a0ed
//
// The new fingerprint was read from the required job's approved renderer (run
// 32537665794, job 96941582102). The local approved renderer independently
// produced the identical value.
//
// Measured against current main 64c4ba23 before approving this value: the five
// authorization overlays move from 546 to 549 rendered documents, with no
// duplicate identities. Set difference in BOTH directions reports exactly
// three additions and no removals or renames:
//
//	v1                               ServiceAccount       observability/crossplane-sync-alerter
//	rbac.authorization.k8s.io/v1    ClusterRole          crossplane-sync-alerter
//	rbac.authorization.k8s.io/v1    ClusterRoleBinding   crossplane-sync-alerter
//
// The grant-bearing surface moves from 77 to 80 objects: Role stays 11,
// ClusterRole 23 -> 24, RoleBinding stays 16, ClusterRoleBinding 11 -> 12,
// and ServiceAccount 16 -> 17. Canonical content comparison of every object
// reports those three additions plus exactly ONE changed existing identity:
// `ClusterRole/crossplane-sync-exporter`. That role replaces its Repository-only
// rule with the exact 16 managed-resource kinds currently installed across
// eight reviewed API groups. Every grant stays get/list/watch, there is no
// wildcard, no core-group access and no Secret access; its existing exact
// get/list/watch on CustomResourceDefinitions is unchanged.
//
// The new alerter ClusterRole is narrower still: its sole rule is `list` on
// `apiextensions.k8s.io/customresourcedefinitions`. Its binding names only the
// new `observability/crossplane-sync-alerter` ServiceAccount. No EKS CI subject,
// AWS service account, AWS role, boundary, policy, or individually pinned core
// authorization identity moved; the validator emitted only this aggregate
// mismatch and no object-specific mismatch.
//
// The previous approved digest remains recorded here:
//
//	072296094a73bafe660540b84da2ee94bbe0683d90c7fc9ed97a6d6f9c292d7a
//
// The new fingerprint was produced by the required hosted renderer (run
// 32587236884, job 97065434213). The local kubectl v1.36.1 render used by the
// tests independently produced the identical value, while the full local CLI
// correctly refused that renderer because the approved pin is v1.36.2.
//
// Re-approved for the Crossview app pod-template annotation that re-runs the
// database schema bootstrap. The rendered delta against main 6e809460 is one
// document, `helm.toolkit.fluxcd.io/v2 HelmRelease crossview/crossview`, which
// gains a single `podAnnotations` key. The annotation names no subject, role,
// verb, resource, policy, service account, or AWS identity, so no grant moves;
// only the aggregate does, because the aggregate covers each document's full
// text while `expectedRenderedHashes` pins the grant-bearing kinds. All 19 of
// those pinned entries stayed byte-identical: zero unapproved, zero missing,
// and zero duplicate rendered resources.
//
// The levelling merge is provably neutral: main 6e809460 renders to the digest
// recorded below as the previous value, so the three commits it brought in
// contribute nothing to this move, and the change is attributable to the PR's
// own diff alone. The diagnostic substitution-note count is 35 on both sides,
// so this adds no unresolved-substitution resource and removes none.
//
// Two independent renderers produced the value below: the required hosted
// kubectl v1.36.2 job (run 32608133113, job 97116555964) at the pre-levelling
// head c1cb9898, and an uncached local kubectl v1.36.1 render at exact levelled
// head 3de36aec. The same local renderer reproduces the previous digest exactly
// at clean main, and rejects a substituted constant there, so it is calibrated
// against the approved tree. The previous approved digest remains recorded here:
//
//	2e5ff04e52117cdbdc88261c35845e51a17ff31b709ed5b7d449b5076c08d8e1
//	bef0f81a74a01efa995543c82c4adf5c18123f3e1b31d0430719f9a3af53daa5
//
// Measured against main 5dfb6f78 for the UniFi Git signature boundary: the
// five production projections move from 539 to 540 documents. Set difference
// in BOTH directions over apiVersion|kind|namespace|name reports exactly one
// addition and no removal or rename:
//
//	v1  Secret  unifi/unifi-git-signing-keys
//
// Exactly one existing rendered identity changes:
//
//	source.toolkit.fluxcd.io/v1  GitRepository  unifi/unifi
//
// Its only delta adds `verify.mode: HEAD` and the exact Secret reference above
// while retaining the already-immutable 40-character commit pin. The Secret
// contains public verification material only; validateUnifiSigningKey pins its
// sole armored key to GitHub's active signer fingerprint
// 968479A1AFF927E37D1A566BB5690EEEBB952194 through the reviewed content hash.
// The pinned commit verifies with that key, while an unsigned empty-commit
// control is rejected. Grant-bearing counts remain byte-for-byte stable:
// Role 11, ClusterRole 24, RoleBinding 15, ClusterRoleBinding 12, and
// ServiceAccount 16. The previous approved aggregate digest was:
//
//	3ef2555fe188f77b84a5927739842929f637688713fa6510bf2c682adce3643b
//
// Measured against main 022dc5c4 for the Tetragon argument-export field filter:
// the five production projections hold 541 documents on BOTH sides. Set
// difference in BOTH directions over apiVersion|kind|namespace|name is empty,
// so this adds, removes and renames nothing. Exactly ONE existing rendered
// identity changes:
//
//	helm.toolkit.fluxcd.io/v2  HelmRelease  kube-system/tetragon
//
// Its only delta adds `tetragon.fieldFilters`, an exporter-side projection that
// drops `process.arguments` and `parent.arguments` from emitted events. The
// value grants nothing: it names neither a subject nor a resource, and it can
// only remove fields from an exported event. Grant-bearing counts remain
// byte-for-byte stable: Role 11, ClusterRole 24, RoleBinding 15,
// ClusterRoleBinding 12, and ServiceAccount 16. All 541 identities were
// compared pairwise, so the single-entry result is not a vacuous join. The
// previous approved aggregate digest was:
//
//	9309a857065fd3d675fd1a26414311d2c7a43717618c904a980c0fe8177839bd
//
// Measured against main 36eadf01 for the Kubescape self-hosted persistence
// repair at 2a2dd717: the five production projections have identical
// grant-bearing resources on both sides. Canonicalizing every Role,
// ClusterRole, RoleBinding, ClusterRoleBinding, and ServiceAccount yields the
// same digest, d328778e3d50a3c43346b6d012ab4c80b32a589e64ecaad74c63a68f078c3a53,
// with stable counts: Role 11, ClusterRole 24, RoleBinding 15,
// ClusterRoleBinding 12, and ServiceAccount 16. The validator reports no
// missing, duplicate, or per-identity mismatches and the same 35 known Flux
// substitution diagnostics. The aggregate changes only because the Kubescape
// HelmRelease scanner image moves from v4.0.10 to v4.0.12; no security context
// or authorization value changes. The previous approved aggregate digest was:
//
//	54e239a1e85e29ed66523bd1d01bfb588678d88e5567d9522a013385ca1285f1
//
// Measured against BOTH parents of this merge for the tag-signed provider
// package. Each parent had already re-approved this constant from the same
// 54e239a1 baseline: this branch 7afb1ed2 carried a015af05 for the provider
// package, and main ad149ddd carried 026c985d after its own Kubescape
// detailed-result storage and scan-window re-approvals. The merged tree
// therefore renders to a third aggregate that neither parent carries:
//
//	a8f0075fcb41fb5b79c608ee9816bfe3c01062bf7c94696f3a044f2f55336a2a
//
// The aggregate is the ONLY thing that moved. Against the merged tree the
// renderer reports ZERO per-identity mismatches, ZERO missing resources, ZERO
// duplicates and ZERO encrypted-SOPS findings, alongside the same 35 known Flux
// substitution diagnostics that accompany any aggregate mismatch and are not
// findings. expectedRenderedHashes is byte-identical to both parents, so no
// per-identity approval changed either.
//
// Grant conservation was proven without reference to any particular renderer.
// That is what makes it independent evidence: approving an aggregate is anchored
// on CI's pinned renderer, whereas a conservation diff only needs the SAME
// renderer on every tree it compares. Rendering all five production overlays of
// the merged tree and of both parents with one and the same local renderer — so
// any renderer difference cancels — and canonicalizing every Role, ClusterRole,
// RoleBinding, ClusterRoleBinding and ServiceAccount yields one identical digest
// on all three trees:
//
//	e07384d8d746ad81a7cb4aec7757eb30a23582fb2e319ad652b6bc7ed13c96d7
//
// at the usual stable counts: Role 11, ClusterRole 24, RoleBinding 15,
// ClusterRoleBinding 12 and ServiceAccount 16, 78 documents in total. The
// three-way match is a measurement and not a vacuous join, and that was checked
// in both directions. Widening one rendered ClusterRole
// (longhorn-stale-node-cleanup) by a single verb moves the digest to
// 4d5c9809598113a20a0797123901b91f9453661d94ed915203a332f70d5f9df2, so it does
// track grant content; and a reformat-only control that rewrites every document
// without changing any grant leaves it at e07384d8, so it does not merely track
// serialization. The merge grants nothing that neither parent already granted.
//
// RENDERER PROVENANCE, stated plainly: the aggregate above was computed on this
// host's kubectl v1.36.1 with kustomize v5.8.1, which is NOT the pinned
// approved renderer. validateAuthorization refuses to run at all on an
// unapproved renderer, so the value was measured with that version gate
// relaxed locally, for measurement only — that relaxation is deliberately NOT
// part of this commit, and expectedKubectlVersion remains v1.36.2. An
// unapproved renderer cannot approve anything on its own: CI's SHA256-verified
// kubectl v1.36.2 is what approves this constant, and if it computes a
// different aggregate the check fails closed and reports the value it computed.
// The conservation digest above is unaffected either way, because it compares
// three trees under one renderer rather than anchoring on a pinned one.
//
// The two superseded approved aggregate digests were:
//
//	a015af05c3b1a620ecd6a7990353e9f1db03b7c50d7ceb2edd63e3563a6591d5
//	026c985d74ec1230e7272488d2a55c028bb78916c4c8362f22c447c862111d78
//
// Measured against main c674d63c for the Kubescape short-transaction storage
// deployment: the five production projections retain the same selected
// identities, every pinned per-identity fingerprint still passes, and the same
// 35 known Flux substitution diagnostics remain. The authored delta advances
// one image override in the Kubescape HelmRelease from the one-worker deferred
// transaction build to the signed build that releases SQLite between derived
// profile writes, preserves failed work for replay, and atomically finalizes
// source rows in one short transaction. The remaining authored changes only
// correct the adjacent explanation of that behavior. It adds no subject, grant,
// security context, authorization resource, or rendered object. The previous
// approved aggregate digest was:
//
//	8758aca997ecdf37b536b18420803f46e67e0af05b851fafefbaa83e02b01fe3
//
// Moved again by the Crossplane provider rename that fixes the dead provider
// fleet (#3454): provider-family-aws becomes upbound-provider-family-aws, the
// name Crossplane derives from its package, so the dependency manager stops
// creating a duplicate Provider for a source the lock already holds.
//
// Measured against main 14351b35 by rendering all five roots from both trees
// with ONE renderer, so renderer differences cancel: 544 documents on main and
// 544 on this branch. Neither side carries a duplicate apiVersion|kind|
// namespace|name identity, so the pairing is one-to-one. Set difference in BOTH
// directions returns exactly one document each way — the rename, and nothing
// else:
//
//	removed  pkg.crossplane.io/v1  Provider  provider-family-aws
//	added    pkg.crossplane.io/v1  Provider  upbound-provider-family-aws
//
// A Crossplane Provider is not a grant-bearing kind, and the grant-bearing
// counts confirm nothing moved: Role / ClusterRole / RoleBinding /
// ClusterRoleBinding / ServiceAccount are 11/24/15/12/16 on BOTH sides.
//
// Exactly two surviving documents change content, both because provider RBAC is
// named after the provider revision, so the rename moves the ClusterRole these
// two match by anchored regex:
//
//	kubescape.io/v1beta1  ClusterSecurityException  secret-reader-rbac
//	v1                    ConfigMap                 kubescape/headlamp-exceptions
//
// Both are byte-identical to main after un-substituting the rename in the
// rendered output, so the regex is their ONLY change; the negative control (the
// same comparison without that substitution) reports a difference, so the check
// is not vacuous. No subject, grant, security context, or authorization
// resource is added, removed or widened. The previous approved aggregate digest
// was:
//
//	ec7889f10c850126e206c93669adbd2c1406c5f189e07b2cbfe5e63e7d24e287
//
// Moved again by the Crossplane provider pod securityContext that fixes the
// same dead provider fleet from the other side (platform#3470), rebased onto
// the rename above. The four provider DeploymentRuntimeConfigs each gain a
// pod-level securityContext so Kyverno's require-seccomp-profile — which
// asserts the POD path and is auto-generated for pod controllers — stops
// denying the Deployment its package manager builds. Crossplane applies its own
// pod defaults only when the config supplies no securityContext at all, so the
// block restates runAsNonRoot/runAsUser/runAsGroup 2000 verbatim rather than
// changing the uid.
//
// Re-measured against main after the rename landed, because the previously
// approved value for this change was computed against the pre-rename tree and
// says nothing about this one. Conservation, by rendering both trees under one
// renderer and diffing: the render differs by exactly 24 lines, all additions,
// all four copies of that same six-line block, zero deletions. Extracting every
// grant-bearing object with its rules, subjects and roleRef, the two trees are
// byte-identical, and a perturbed-row negative control fires. It adds no
// subject, grant, authorization resource, or rendered object; it adds a
// security context, and that is the entire authored delta. The previous
// approved aggregate digest was:
//
//	a3199d02a7c8b32c0c82bd6a619ea020993d0e37f2dc1e4fe1b23e96d3a91f5d
//
// Moved again by the staged tofu-controller retirement. Measured by comparing
// exact current main f19f67e2 with merge head d35c1e96 using the
// checksum-verified kubectl v1.36.2 / Kustomize v5.8.1 renderer. Across all five
// production roots, main renders 548 distinct apiVersion|kind|namespace|name
// identities and this branch renders 547; neither tree has a duplicate. The
// bidirectional set difference is exactly:
//
//	removed  helm.toolkit.fluxcd.io/v2     HelmRelease               flux-system/tofu-controller
//	removed  source.toolkit.fluxcd.io/v1   HelmRepository            flux-system/tofu-controller
//	added    apiextensions.k8s.io/v1       CustomResourceDefinition  terraforms.infra.contrib.fluxcd.io
//
// The added CRD is the byte-verified v0.16.5 chart CRD temporarily inventoried
// by Flux so the follow-up retirement can prune it rather than orphan it. It
// grants no subject or verb. Grant-bearing membership remains 78 objects on
// BOTH sides (Role / ClusterRole / RoleBinding / ClusterRoleBinding /
// ServiceAccount 11/24/15/12/16). Exactly one of those objects changes:
// ClusterRole cluster-reader removes the infra.contrib.fluxcd.io API group.
// That is a strict read-grant reduction; no binding, subject, roleRef, resource
// or verb is added or widened.
//
// Five other surviving documents change: the Coroot autosuppressor drops only
// the retired controller's alert exemption; two Kubescape exceptions remove
// only tofu-specific RBAC matches; one Kubescape exception updates measured
// controller-count prose; and its generated Headlamp ConfigMap mirror follows
// those exception changes. The apps, bootstrap and root production renders are
// byte-identical. The AWS manifests and the recovered provider fleet base are
// untouched by this branch. The previous approved aggregate digest was:
//
//	d07fdcf550827d5b62d48c0ce9e110dea819f8d9168c7ac3abb7f01144939d93
//
// Moved again by the per-controller uid/gid pin on this branch, re-measured
// against main after the tofu-controller retirement landed. The branch's
// tofu-controller postRenderer is gone with the controller itself, so the
// authored delta is now exactly two files: the flux-operator HelmRelease and
// the FluxInstance kustomize patch.
//
// Conservation, rendering all five production roots from both trees with ONE
// renderer so renderer differences cancel: 548 documents on both sides. The
// rendered diff is 29 lines, ALL additions, zero deletions, and every one of
// them belongs to those two patch blocks — `op: test` container-name guards
// and `op: add` writes of runAsUser/runAsGroup under
// /spec/template/spec/containers/0/securityContext.
//
// Grant-bearing membership is unchanged: extracting every Role, ClusterRole,
// RoleBinding, ClusterRoleBinding and ServiceAccount with its rules, subjects
// and roleRef yields 78 objects on BOTH sides, byte-identical. The negative
// control fires for the right reason — injecting one `escalate` verb into
// ClusterRole cert-manager-tenant-edit still extracts 78 objects (so the
// fixture is intact, not broken) and the comparison names exactly that role.
// No subject, grant, roleRef or authorization resource is added or widened;
// the delta is a security context, and it constrains rather than grants.
// The previous approved aggregate digest was:
//
//	2304ac067cc7ec446ddeff107477bb1f34f859b4cd5bca708a3ba0926ef5fc49
//
// Re-measured on the MERGE of this branch with main (a5c6ec2e), not carried over
// from either side. Both parents changed this constant independently -- main via
// the per-controller uid/gid pin (#3459), this branch via the reader-only human
// access surface -- so neither parent's value describes the merged tree and
// taking either side would have produced a validator that is red on the state it
// is meant to approve.
//
// The renderer used for this measurement was verified against a known answer
// first: running this validator on main a5c6ec2e reproduced main's approved
// digest a8383404... exactly and reported the contract as passing, so the local
// toolchain renders identically to CI's for this computation. The merged tree
// then measured as the value below. The previous approved aggregate digest was:
//
//	a8383404dd948c286fc274aed91164b2156c47b0cf66de9deebc7025833a8c20
//
// Re-approved for the cluster-reader provider-group gap (2026-08-30). The
// surface moved because cluster-reader gained the eight API groups that are
// live on the cluster but were absent from its enumerated list: the three AWS
// provider groups and the five UniFi Crossplane groups. Reading the live
// ClusterRole confirmed all eight were missing in production, so Headlamp OIDC
// identities already could not see those managed resources; this PR would have
// extended the same blind spot to Crossview.
//
// Two independent renderers agree on this value: the required CI job on the
// approved toolchain (job 99316243854, kubectl v1.36.2) and a local render
// (kubectl v1.36.1). The local toolchain was verified against a known answer
// first -- running this validator on the parent commit 63795e6e reproduced the
// previously approved digest below and reported the contract as passing -- so
// the patch-version difference does not affect this computation.
//
// The delta is single-variable: the parent was green on this check and the only
// change since is eight added lines in one file, so nothing else moved the
// surface. Secrets remain excluded because the core group stays enumerated, and
// every sensitive field in the added groups' CRDs is a reference
// (presharedKeySecretRef, privateKeySecretRef, contentSecretRef,
// writeConnectionSecretToRef, ProviderConfig spec.credentials.secretRef) rather
// than inline material.
//
// The previous approved aggregate digest was:
//
//	5b298b96eba875cb5c05ba09c82eaf2833676930d1f76a3b7c4a954d104ceebd
//
// Re-approved for #3522: velero's Deployment and its node-agent DaemonSet now
// carry fsGroupChangePolicy and seLinuxOptions.level in their own STORED
// templates, instead of only receiving them from the admission-time mutation.
// Kubescape scores the stored spec, so the scanned verdict never moved while the
// fields existed only on the running pods. The only change since the value above
// is 32 added lines in one file,
// k8s/bases/infrastructure/controllers/velero/helm-release.yaml, so nothing else
// moved the surface.
//
// The aggregate is the ONLY thing that moved, and the validator itself proves it:
// the same run reported no per-identity "unapproved rendered ... fingerprint", no
// "missing rendered authorization resource" and no "duplicate rendered
// authorization resource", so every identity-keyed authorization resource is
// unchanged. No grant-bearing field moved either -- node-agent keeps runAsUser: 0
// (restated explicitly in the values so a later edit cannot silently drop the root
// it needs for host path access) and the server keeps 65532, with fsGroup,
// runAsGroup and runAsNonRoot untouched. Both added fields are non-privilege: one
// governs ownership relabelling on volume mount, the other is an SELinux level
// that is inert on this AppArmor cluster.
//
// The previous approved aggregate digest was:
//
//	005c333f114ad4a2a5706ef9b0d4989623203eadc67657ffd15d2b4d9bb369dc
//
// Re-approved for #2754 (#3560): the stranded-volume-attach alert — a read-only
// CronJob in observability that reads FailedAttachVolume/FailedMount events and
// posts to the shared Slack webhook when a pod has been failing to attach its
// volume for longer than an attach takes (the 2026-07-01 nine-hour delivery
// wedge, #2363).
//
// Measured against main 806e385f before approving THIS value, rendering all
// five roots on BOTH sides with one toolchain (kubectl v1.36.1 / kustomize
// v5.8.1 locally — the pinned renderer refuses to fingerprint on that version,
// which is why the digest below is the value the required job reported at the
// PR head, run 33807229837, and only the membership and content comparison is
// local): the rendered surface moves from 547 -> 552 documents, purely additive.
// Membership was proven by set difference in BOTH directions over
// apiVersion|kind|namespace|name (not by count, which cannot see a rename):
// zero removed, zero renamed, and the five additions are exactly the alert —
//
//	v1                          ServiceAccount      observability/stranded-volume-attach-alert
//	v1                          Secret              observability/stranded-volume-attach-alert-webhook
//	rbac.authorization.k8s.io/v1 ClusterRole        stranded-volume-attach-alert
//	rbac.authorization.k8s.io/v1 ClusterRoleBinding stranded-volume-attach-alert
//	batch/v1                    CronJob             observability/stranded-volume-attach-alert
//
// Grant-bearing objects moved additively: 78 -> 81 Role / ClusterRole /
// RoleBinding / ClusterRoleBinding / ServiceAccount documents, being the three
// above — the same shape as the cnpg-degraded-alert and OpenCost usage-scraper
// approvals: one dedicated ServiceAccount, one narrow ClusterRole, one binding
// between exactly those two identities. The ClusterRole is get/list only, on
// events, pods, persistentvolumes and persistentvolumeclaims in the core group;
// it is cluster-scoped because a strand can happen in any namespace that mounts
// a volume, and it holds no write verb.
//
// No existing entry's content moved: a per-document comparison of every common
// identity across the five roots is byte-identical on both sides. The same run
// reported no per-identity "unapproved rendered ... fingerprint", no "missing
// rendered authorization resource" and no "duplicate rendered authorization
// resource", so every identity-keyed authorization resource is unchanged. The
// gitops-managed-cronjobs ClusterSecurityException gained the new CronJob in its
// enumeration; the reported aggregate is identical with and without that edit,
// so that resource is outside the selected surface.
//
// The previous approved aggregate digest was:
//
//	7a033c38847bf0ea7b052e783cbf1e68f317d8524c701243acb2d8b3c9972116
//
// Re-approved for #3396 (#3566): the tenant identity loses its WRITE verbs on
// standard networking.k8s.io/networkpolicies. Cilium unions a standard
// NetworkPolicy's allow rules with CiliumNetworkPolicy rules, and
// restrict-tenant-network-policies constrains only the latter, so the write
// grant was a bypass of the whole tenant boundary. Read verbs stay.
//
// Measured against main 88c5122e before approving THIS value, rendering all
// five roots on BOTH sides with one toolchain (kubectl v1.36.1 / kustomize
// v5.8.1 locally — the pinned renderer refuses to fingerprint on that version,
// which is why the digest below is the value the required job reported at the
// PR head, run 33823039777, and only the membership and content comparison is
// local): the rendered surface stays at 552 -> 552 documents. Membership was
// proven by set difference in BOTH directions over
// apiVersion|kind|namespace|name: zero removed, zero added, zero renamed.
// Grant-bearing objects stay at 81 -> 81 Role / ClusterRole / RoleBinding /
// ClusterRoleBinding / ServiceAccount documents.
//
// Exactly ONE identity's content moved, and it moved NARROWER: ClusterRole
// tenant-base-edit's single networking.k8s.io rule
//
//	resources: [ingresses, ingresses/status, networkpolicies]
//	verbs: [create, delete, deletecollection, patch, update, get, list, watch]
//
// became two rules — the same eight verbs on [ingresses, ingresses/status]
// only, and [get, list, watch] on [networkpolicies]. No verb, resource or
// group was added anywhere; every other identity across the five roots is
// byte-identical on both sides. The same run reported no "missing rendered
// authorization resource" and no "duplicate rendered authorization resource".
// scripts/tests/test-tenant-edit-networkpolicy-write.sh renders both
// providers' infrastructure layers and refuses the write grant if it returns.
//
// The previous approved aggregate digest was:
//
//	686bf5ade0d7869f3a20d50a05a7ac083744f0e88ede4fc02298ab9f67dfdf19
//
// Re-approved 2026-09-04 for the flux-operator C-0211 template fix (#3239), which
// adds two securityContext ops to that HelmRelease's existing postRenderer patch.
//
// Conservation proven by rendering ALL FIVE overlays from both trees with the same
// renderer and taking the set difference in BOTH directions over the complete
// apiVersion|kind|namespace|name identity: 548 documents on main e37660b2 and 548 on
// this branch — ZERO added, ZERO removed, ZERO renamed. Neither side carries a
// duplicate identity, so that pairing is one-to-one.
//
// The ENTIRE content delta across all five roots is seven added lines inside one
// document — the flux-operator HelmRelease — and nothing is removed anywhere:
//
//   - op: add   /spec/template/spec/containers/0/securityContext/seLinuxOptions  {level: s0}
//   - op: add   /spec/template/spec/securityContext/fsGroupChangePolicy          OnRootMismatch
//
// Neither op is grant-bearing: no rule, verb, resource, group, subject,
// ServiceAccount, role reference or policy moved on either side. The surface digest
// moved only because that HelmRelease is itself a selected authorization-capable
// document, so its text is covered by the aggregate — which is the tripwire working
// as designed, not a privilege change.
//
// The value below is CI's own computed digest at head 5dc2d805, taken from the
// failing run rather than recomputed locally: this validator pins the renderer to
// kubectl v1.36.2 and refuses any other, and the host that prepared this change has
// v1.36.1. The conservation proof above is renderer-robust because both sides were
// rendered with the SAME local renderer; the digest is not, so it comes from the
// pinned one.
//
// Re-approved 2026-09-04 for #3580, which repairs the change the paragraph above
// approved. That change could not apply at all: the pod-level op targets
// /spec/template/spec/securityContext/fsGroupChangePolicy, but the flux-operator
// chart renders no pod-level securityContext, so helm-controller failed the whole
// post-render with `doc is missing path` and neither field reached the cluster.
// #3580 moves that one field to a strategic-merge patch, which creates the missing
// parent; the container ops are unchanged.
//
// Conservation re-proven the same way, with ONE renderer on both sides: all five
// overlays rendered from main d7613b03 and from this branch, compared over the full
// apiVersion|kind|namespace|name identity in BOTH directions. 552 documents each
// side — ZERO added, ZERO removed. Per-root counts (126/226/188/8/4) were
// corroborated against raw document-separator counts, because `yq eval-all`
// evaluates once across a whole stream and silently reports 1. A negative control
// that drops a single document reports removed=1 and names it, so the comparison is
// not vacuous.
//
// Four of the five roots render byte-identical. The ENTIRE delta is confined to the
// flux-operator HelmRelease in the controllers root: 3 lines removed, 13 added, all
// inside its postRenderers block. No rule, verb, resource, group, subject,
// ServiceAccount, role reference or policy moved. The digest moves for the same
// reason as last time — that HelmRelease is itself a selected authorization-capable
// document — not because privilege changed.
//
// The value below is again CI's own computed digest (run 33866934697, head
// 8c9d1d11), for the same reason: this validator pins kubectl v1.36.2 and refuses
// any other, and the preparing host has v1.36.1. That run reported exactly one
// error class — this fingerprint — so nothing else in the authorization surface
// objected.
//
// The previous approved aggregate digest was:
//
//	ab05bc2c95924e372c038f878872aa94e3bd81380daa96a283bd7f74e2132a69
const expectedRenderedSurfaceSHA = "a5dac56d1ee989648670e2bd265b56e574512b37e2e19b8caf0fe4738816d1a4"

// authorizationOverlayPaths lists every independently reconciled production
// layer where an object can grant privileges to the aws/aws service account.
var authorizationOverlayPaths = []string{
	appsOverlayPath,
	infrastructureOverlayPath,
	controllerOverlayPath,
	bootstrapOverlayPath,
	rootProductionOverlayPath,
}

// exactPinnedHelmChartVersion accepts one immutable SemVer selector, including
// the optional v prefix and prerelease/build suffixes used by this portfolio.
// Ranges, wildcards, substitutions, and omitted versions remain fingerprinted
// verbatim because they let a chart move without a reviewed dependency PR.
var exactPinnedHelmChartVersion = regexp.MustCompile(
	`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
		`(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
)

var exactGitCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)
var exactSHA256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const authorizationIsolationAnnotation = "security.devantler.tech/authorization-scope"

// commandExecutor makes the renderer orchestration independently testable
// without weakening the production command and deadline contract.
type commandExecutor func(context.Context, string, ...string) ([]byte, error)

// resourceIdentity is the complete Kubernetes identity used to distinguish
// approved authorization objects from aliases and same-named resources.
type resourceIdentity struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
}

// resourceType identifies every instance of a controller-defined API kind.
type resourceType struct {
	apiVersion string
	kind       string
}

// validatePinnedUnifiSource keeps the external repository from moving without
// a reviewed Platform change. This source retains patch/update authority over
// live UniFi managed resources, so a branch, tag, abbreviated hash, alternate
// repository, or mixed selector is not an acceptable provenance boundary.
func validatePinnedUnifiSource(document map[string]any, identity resourceIdentity) error {
	wantIdentity := resourceIdentity{
		apiVersion: "source.toolkit.fluxcd.io/v1",
		kind:       "GitRepository",
		namespace:  "unifi",
		name:       "unifi",
	}
	if identity != wantIdentity {
		return nil
	}

	spec, ok := document["spec"].(map[string]any)
	if !ok || spec["url"] != "https://github.com/devantler-tech/unifi" {
		return errors.New("unifi GitRepository must use the trusted devantler-tech/unifi source")
	}
	ref, ok := spec["ref"].(map[string]any)
	if !ok || len(ref) != 1 {
		return errors.New("unifi GitRepository must pin exactly one full immutable commit")
	}
	commit, ok := ref["commit"].(string)
	if !ok || !exactGitCommit.MatchString(commit) {
		return errors.New("unifi GitRepository must pin exactly one full immutable commit")
	}
	verify, ok := spec["verify"].(map[string]any)
	if !ok || len(verify) != 2 || verify["mode"] != "HEAD" {
		return errors.New("unifi GitRepository must verify the pinned HEAD commit")
	}
	secretRef, ok := verify["secretRef"].(map[string]any)
	if !ok || len(secretRef) != 1 || secretRef["name"] != "unifi-git-signing-keys" {
		return errors.New("unifi GitRepository must trust only the reviewed unifi Git signing key Secret")
	}
	return nil
}

const expectedUnifiPublicMaterialSHA = "40ce89d21fb075092d256f9fbf62a1c19299d3282cb913d3e61d08235d0c491a"

// validateUnifiSigningKey pins the public trust root used by the UniFi
// GitRepository. A secretRef alone only proves that Flux will look up a name;
// it says nothing about which signer that Secret actually trusts.
func validateUnifiSigningKey(documents []map[string]any) error {
	wantIdentity := resourceIdentity{
		apiVersion: "v1",
		kind:       "Secret",
		namespace:  "unifi",
		name:       "unifi-git-signing-keys",
	}
	count := 0
	for _, document := range documents {
		if identityOf(document) != wantIdentity {
			continue
		}
		count++
		if document["type"] != "Opaque" {
			return errors.New("unifi Git signing key Secret must be type Opaque")
		}
		if _, exists := document["data"]; exists {
			return errors.New("unifi Git signing key Secret must not contain data")
		}
		stringData, ok := document["stringData"].(map[string]any)
		if !ok || len(stringData) != 1 {
			return errors.New("unifi Git signing key Secret must contain only github.asc")
		}
		key, ok := stringData["github.asc"].(string)
		if !ok || key == "" {
			return errors.New("unifi Git signing key Secret must contain github.asc")
		}
		if actual := fingerprint([]byte(key)); actual != expectedUnifiPublicMaterialSHA {
			return fmt.Errorf("unapproved unifi Git signing key fingerprint: %s", actual)
		}
	}
	if count != 1 {
		return fmt.Errorf("unifi Git signing key Secret count is %d, want exactly 1", count)
	}
	return nil
}

// validateUnifiPruneExemption keeps the deliberate non-pruning reconciler
// deployable while requiring the admission-policy exception to remain scoped
// to exactly one namespaced Kustomization.
func validateUnifiPruneExemption(document map[string]any, identity resourceIdentity) error {
	wantIdentity := resourceIdentity{
		apiVersion: "kyverno.io/v1",
		kind:       "ClusterPolicy",
		name:       "enforce-flux-best-practices",
	}
	if identity != wantIdentity {
		return nil
	}

	exactSingleton := func(value any, want string) bool {
		values, ok := value.([]any)
		return ok && len(values) == 1 && values[0] == want
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return errors.New("enforce-flux-best-practices must exempt only unifi/unifi from prune enforcement")
	}
	rules, ok := spec["rules"].([]any)
	if !ok {
		return errors.New("enforce-flux-best-practices must exempt only unifi/unifi from prune enforcement")
	}
	for _, ruleValue := range rules {
		rule, ok := ruleValue.(map[string]any)
		if !ok || rule["name"] != "kustomization-recommended-settings" {
			continue
		}
		exclude, ok := rule["exclude"].(map[string]any)
		if !ok {
			break
		}
		exclusions, ok := exclude["any"].([]any)
		if !ok {
			break
		}
		seenFluxSystem := false
		seenUnifi := false
		for _, exclusionValue := range exclusions {
			exclusion, ok := exclusionValue.(map[string]any)
			if !ok {
				break
			}
			resources, ok := exclusion["resources"].(map[string]any)
			if !ok {
				break
			}
			switch {
			case exactSingleton(resources["namespaces"], "flux-system") &&
				exactSingleton(resources["names"], "flux-system") && !seenFluxSystem:
				seenFluxSystem = true
			case exactSingleton(resources["namespaces"], "unifi") &&
				exactSingleton(resources["names"], "unifi") && !seenUnifi:
				seenUnifi = true
			default:
				return errors.New("enforce-flux-best-practices must exempt only unifi/unifi from prune enforcement")
			}
		}
		if seenFluxSystem && seenUnifi && len(exclusions) == 2 {
			return nil
		}
		break
	}
	return errors.New("enforce-flux-best-practices must exempt only unifi/unifi from prune enforcement")
}

// expectedRenderedHashes preserves object-specific diagnostics for the core
// EKS CI identities while the aggregate surface hash pins every selected
// source, controller, binding, and indirect authorization object.
var expectedRenderedHashes = map[resourceIdentity]string{
	{apiVersion: "iam.aws.m.upbound.io/v1beta1", kind: "Role", namespace: "aws", name: "eks-ci"}:                                        "0967890d16316a8cfcb1cca8a52085c6989c42000fafbbd0ada6323d4e15c97c",
	{apiVersion: "iam.aws.m.upbound.io/v1beta1", kind: "Policy", namespace: "aws", name: "eks-ci-smoke-boundary"}:                       "6f14b5243c945d0d2230821733ea12096d6e92ab155a35482b20a6080c03c037",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", namespace: "aws", name: "aws-managed-resources"}:                         "ff4c3264c519b1b4a7ec9b5145412f39ea2ba7b6163d8dc50fb029b1460edcda",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", namespace: "aws", name: "aws-managed-resources"}:                  "d846c8d9810dd7c0cba33612d2de63183403ccb07c4d5a5c90d0563a444cd714",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", name: "kro-tenant-rgd"}:                                           "4447f41c03e8297fafdabcadf4fdd8ca3260f2c84264c531b2179cb7df2c1556",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", name: "opencost-usage-scraper"}:                                   "3cb22a5a2d178e9cc93ebc3995d936d124800c441785dc23d780281746569937",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", name: "crossview-cluster-reader"}:                          "bc6c370f5bff72c541428274f9ef7ab13e3bb5a2b804ec5f4c81087171311c0d",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", name: "crossview-view"}:                                    "536a4baa1970100ea117d1655f80e06ed874e2248b75f33f161e8b44ca3df50c",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", name: "oidc-cluster-reader"}:                               "7d896404f02d6418c289065d73f9ad79345217d76c8d89eadca2c06e6066b487",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", name: "oidc-view"}:                                         "4d07ba3a995cfc139351b4227739efeba9348777f7fe47ac69b87d08e70bd45f",
	{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", name: "opencost-usage-scraper"}:                            "4b28e1da280a7940a1cb4d538bc31ede1b5d272c17189a81afeae48acbb8b7a0",
	{apiVersion: "kro.run/v1alpha1", kind: "ResourceGraphDefinition", name: "tenant.kro.run"}:                                           "072e4478cdad39c0a7d9f5119cad63d4c56a9fc96ba88d657fef97f6b91bae31",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "ascoachingogvaner", name: "ascoachingogvaner"}:    "89ea0484e37b691594b7a72be2ca2de285697818bf88a5b37b4fa8a9161c54fa",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "aws", name: "aws"}:                                "7bde9c682a81b752bdf9d2b14ce69ca1690008a39f2562d4887f8200447dea71",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "flux-system", name: "apps"}:                       "ee11a54686a68eb49b833b234949f9d21a7b8106c1b3ae677e5c205e5506f6ac",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "flux-system", name: "bootstrap"}:                  "7f674a1762f298330c7c9e4d9d4e8bf46108b10727e02a25ca5096d7913cc0a7",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "flux-system", name: "infrastructure"}:             "d1bc403b6458bd22cf967bd570e24718341cbd584f58e7f0069aaffe1e187945",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "flux-system", name: "infrastructure-controllers"}: "9d9b62d3221442d6355d16a34d31c198619fb3b3728df960fd67222a531ece7b",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "github-config", name: "github-config"}:            "8e9f72b0f4f982d050aff0b97d246c68b538cbc397cdd45d031c95cfae981e7c",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "unifi", name: "unifi"}:                            "33a579299700de2467631854bac4982d3e14caa3bad8cbcd2613ac180b30af32",
	{apiVersion: "kustomize.toolkit.fluxcd.io/v1", kind: "Kustomization", namespace: "wedding-app", name: "wedding-app"}:                "8af27d4845565c57b9ebc618f186669f18ada89e070cf4e6514924717a2532f8",
}

// fingerprint returns the SHA-256 identity used for byte-exact source checks.
func fingerprint(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

// canonicalFingerprint hashes a parsed value after canonical JSON encoding so
// semantically identical YAML formatting cannot bypass structural checks.
func canonicalFingerprint(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical JSON: %w", err)
	}
	return fingerprint(canonical), nil
}

// decodeDocuments parses every non-empty YAML document and rejects malformed
// input instead of silently validating a partial stream.
func decodeDocuments(contents []byte) ([]map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	documents := make([]map[string]any, 0)
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode YAML: %w", err)
		}
		if len(document) != 0 {
			documents = append(documents, document)
		}
	}
	return documents, nil
}

// nestedMap resolves a required object path and fails when any segment is
// missing or has the wrong shape.
func nestedMap(document map[string]any, keys ...string) (map[string]any, error) {
	current := document
	for _, key := range keys {
		value, ok := current[key]
		if !ok {
			return nil, fmt.Errorf("missing %s", strings.Join(keys, "."))
		}
		next, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not an object", strings.Join(keys, "."))
		}
		current = next
	}
	return current, nil
}

// requireExactKeys prevents approved objects from hiding extra policy-bearing
// siblings that a selected-leaf assertion would miss.
func requireExactKeys(object map[string]any, expected ...string) error {
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		return fmt.Errorf("unexpected keys: got %v, want %v", actual, expected)
	}
	return nil
}

// parseJSONPolicy requires Crossplane's embedded IAM policy to remain a valid
// JSON object before its canonical shape is compared.
func parseJSONPolicy(value any, description string) (map[string]any, error) {
	policyText, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON string", description)
	}
	var policy map[string]any
	if err := json.Unmarshal([]byte(policyText), &policy); err != nil {
		return nil, fmt.Errorf("parse %s: %w", description, err)
	}
	if policy == nil {
		return nil, fmt.Errorf("%s is not a JSON object", description)
	}
	return policy, nil
}

// requireCanonicalFingerprint rejects any structural policy drift with a
// diagnostic hash that can be reviewed and deliberately approved.
func requireCanonicalFingerprint(value any, expected string, description string) error {
	actual, err := canonicalFingerprint(value)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("unapproved %s fingerprint: %s", description, actual)
	}
	return nil
}

// validateRole pins the complete EKS CI role source, trust relationship,
// session limit, and sole inline policy rather than a subset of actions.
func validateRole(role []byte) error {
	if actual := fingerprint(role); actual != expectedRoleManifestSHA {
		return fmt.Errorf("unapproved role manifest fingerprint: %s", actual)
	}
	documents, err := decodeDocuments(role)
	if err != nil {
		return fmt.Errorf("decode role manifest: %w", err)
	}
	if len(documents) != 1 {
		return fmt.Errorf("role manifest must contain exactly one document, got %d", len(documents))
	}
	forProvider, err := nestedMap(documents[0], "spec", "forProvider")
	if err != nil {
		return err
	}
	if err := requireExactKeys(forProvider, "description", "maxSessionDuration", "assumeRolePolicy", "inlinePolicy"); err != nil {
		return fmt.Errorf("role forProvider: %w", err)
	}
	if forProvider["maxSessionDuration"] != 7200 {
		return fmt.Errorf("unapproved maxSessionDuration: %v", forProvider["maxSessionDuration"])
	}
	trust, err := parseJSONPolicy(forProvider["assumeRolePolicy"], "trust policy")
	if err != nil {
		return err
	}
	if err := requireCanonicalFingerprint(trust, expectedTrustPolicySHA, "trust policy"); err != nil {
		return err
	}
	inlinePolicies, ok := forProvider["inlinePolicy"].([]any)
	if !ok || len(inlinePolicies) != 1 {
		return errors.New("role must contain exactly one inline policy")
	}
	inlinePolicy, ok := inlinePolicies[0].(map[string]any)
	if !ok || inlinePolicy["name"] != "eks-ci-smoke" {
		return errors.New("role inline policy must be named eks-ci-smoke")
	}
	policy, err := parseJSONPolicy(inlinePolicy["policy"], "inline policy")
	if err != nil {
		return err
	}
	return requireCanonicalFingerprint(policy, expectedInlinePolicySHA, "inline policy")
}

// validateBoundary pins both the permissions-boundary manifest and its embedded
// policy so role grants cannot escape the intended ceiling.
func validateBoundary(boundary []byte) error {
	if actual := fingerprint(boundary); actual != expectedBoundarySHA {
		return fmt.Errorf("unapproved boundary manifest fingerprint: %s", actual)
	}
	documents, err := decodeDocuments(boundary)
	if err != nil {
		return fmt.Errorf("decode boundary manifest: %w", err)
	}
	if len(documents) != 1 {
		return fmt.Errorf("boundary manifest must contain exactly one document, got %d", len(documents))
	}
	forProvider, err := nestedMap(documents[0], "spec", "forProvider")
	if err != nil {
		return err
	}
	if err := requireExactKeys(forProvider, "description", "policy"); err != nil {
		return fmt.Errorf("boundary forProvider: %w", err)
	}
	policy, err := parseJSONPolicy(forProvider["policy"], "permissions boundary")
	if err != nil {
		return err
	}
	return requireCanonicalFingerprint(policy, expectedBoundaryJSONSHA, "permissions boundary")
}

// identityOf derives the canonical identity used by the rendered authorization
// allowlist; cluster-scoped resources use an empty namespace.
func identityOf(document map[string]any) resourceIdentity {
	metadata, _ := document["metadata"].(map[string]any)
	stringValue := func(object map[string]any, key string) string {
		value, ok := object[key]
		if !ok || value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
	return resourceIdentity{
		apiVersion: stringValue(document, "apiVersion"),
		kind:       stringValue(document, "kind"),
		namespace:  stringValue(metadata, "namespace"),
		name:       stringValue(metadata, "name"),
	}
}

// stringListIncludes reports whether a decoded YAML string list contains any
// requested value, including the Kubernetes RBAC wildcard when requested.
func stringListIncludes(value any, expected ...string) bool {
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, rawValue := range values {
		for _, candidate := range expected {
			if fmt.Sprint(rawValue) == candidate {
				return true
			}
		}
	}
	return false
}

// grantsAuthorizationControl identifies Roles and ClusterRoles that can mutate
// RBAC privileges, aggregate them, or assume service-account identities.
func grantsAuthorizationControl(document map[string]any) bool {
	identity := identityOf(document)
	if identity.apiVersion != "rbac.authorization.k8s.io/v1" ||
		(identity.kind != "Role" && identity.kind != "ClusterRole") {
		return false
	}
	if identity.kind == "ClusterRole" {
		if _, aggregates := document["aggregationRule"]; aggregates {
			return true
		}
	}
	rules, ok := document["rules"].([]any)
	if !ok {
		return false
	}
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		if stringListIncludes(
			rule["verbs"],
			"create",
			"update",
			"patch",
			"delete",
			"deletecollection",
			"*",
		) {
			protectedResources := []struct {
				apiGroup  string
				resources []string
			}{
				{apiGroup: "iam.aws.m.upbound.io", resources: []string{"roles", "policies", "*"}},
				{apiGroup: "iam.aws.upbound.io", resources: []string{"roles", "policies", "*"}},
				{apiGroup: "kustomize.toolkit.fluxcd.io", resources: []string{"kustomizations", "*"}},
				{apiGroup: "source.toolkit.fluxcd.io", resources: []string{"*"}},
				{apiGroup: "helm.toolkit.fluxcd.io", resources: []string{"helmreleases", "*"}},
				{apiGroup: "pkg.crossplane.io", resources: []string{"providers", "functions", "configurations", "deploymentruntimeconfigs", "*"}},
				{apiGroup: "kyverno.io", resources: []string{"policies", "clusterpolicies", "*"}},
				{apiGroup: "policies.kyverno.io", resources: []string{"mutatingpolicies", "generatingpolicies", "*"}},
			}
			for _, protected := range protectedResources {
				if stringListIncludes(rule["apiGroups"], protected.apiGroup, "*") &&
					stringListIncludes(rule["resources"], protected.resources...) {
					return true
				}
			}
		}
		if stringListIncludes(rule["apiGroups"], "rbac.authorization.k8s.io", "*") &&
			stringListIncludes(
				rule["resources"],
				"roles",
				"clusterroles",
				"rolebindings",
				"clusterrolebindings",
				"*",
			) &&
			stringListIncludes(
				rule["verbs"],
				"create",
				"update",
				"patch",
				"delete",
				"deletecollection",
				"bind",
				"escalate",
				"*",
			) {
			return true
		}
		if stringListIncludes(rule["apiGroups"], "", "*") &&
			stringListIncludes(rule["resources"], "serviceaccounts/token", "*") &&
			stringListIncludes(rule["verbs"], "create", "*") {
			return true
		}
		if stringListIncludes(rule["apiGroups"], "", "*") &&
			stringListIncludes(rule["resources"], "serviceaccounts", "*") &&
			stringListIncludes(rule["verbs"], "impersonate", "*") {
			return true
		}
	}
	return false
}

// isRBACAuthorizationKind recognizes Kyverno's short and group-qualified role
// and binding kinds, all of which can change effective privileges.
func isRBACAuthorizationKind(kind string) bool {
	return strings.Contains(kind, "${") || kind == "*" || kind == "Role" || kind == "ClusterRole" ||
		kind == "RoleBinding" || kind == "ClusterRoleBinding" ||
		(strings.HasPrefix(kind, "rbac.authorization.k8s.io/") && strings.HasSuffix(kind, "/*")) ||
		strings.HasSuffix(kind, "/Role") || strings.HasSuffix(kind, "/ClusterRole") ||
		strings.HasSuffix(kind, "/RoleBinding") || strings.HasSuffix(kind, "/ClusterRoleBinding")
}

// isAWSIAMAuthorizationKind recognizes the Crossplane IAM kinds that CARRY the
// protected permissions rather than merely pointing at them: the role itself,
// the boundary policy whose document is the permission set, and the attachments
// that decide which policies apply to it.
//
// These are the kinds actually under guard — the role and the boundary policy
// are both in the protected surface — so a Kyverno selector reaching them is an
// authorization selector by definition. Missing them let a legacy ClusterPolicy
// match iam.aws.m.upbound.io/v1beta1/Policy and mutate spec.forProvider.policy,
// widening the permissions boundary on the next admission without moving the
// validator hash.
//
// Bare kind names are accepted even though "Policy" and "Role" are ambiguous
// across API groups. The consequence of over-matching is that a policy joins the
// aggregate surface and the expected hash must be refreshed; the consequence of
// under-matching is a silent boundary widening. This fails closed on purpose.
func isAWSIAMAuthorizationKind(kind string) bool {
	if strings.HasPrefix(kind, "iam.aws.") {
		return true
	}
	targets := []string{
		"Policy",
		"RolePolicyAttachment",
		"UserPolicyAttachment",
		"GroupPolicyAttachment",
		"PolicyAttachment",
	}
	for _, target := range targets {
		if kind == target || strings.HasSuffix(kind, "/"+target) {
			return true
		}
	}
	return false
}

// isFluxSourceResource recognizes artifacts that a Flux Kustomization or
// HelmRelease can consume independently of the handoff object itself.
func isFluxSourceResource(identity resourceIdentity) bool {
	return strings.HasPrefix(identity.apiVersion, "source.toolkit.fluxcd.io/")
}

// isControllerRBACEmitter recognizes declarative packages whose controllers
// can materialize RBAC that does not exist in the Kustomize render.
func isControllerRBACEmitter(identity resourceIdentity) bool {
	if strings.HasPrefix(identity.apiVersion, "helm.toolkit.fluxcd.io/") && identity.kind == "HelmRelease" {
		return true
	}
	return strings.HasPrefix(identity.apiVersion, "pkg.crossplane.io/")
}

// authorizationIsolationRequested identifies the explicit reviewed contract
// used by namespace-local charts whose effective RBAC is validated after Helm
// rendering. Merely adding the annotation never makes it valid.
func authorizationIsolationRequested(document map[string]any) bool {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return false
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	return ok && fmt.Sprint(annotations[authorizationIsolationAnnotation]) == "isolated-chart"
}

// reviewedIsolatedChartIdentities is the explicit allowlist of namespace/name
// pairs whose isolated-chart declaration and exact rendered-child namespace
// gate have both been reviewed. Each entry needs a path-scoped Helm render that
// rejects every namespaced child outside the identity's namespace; the
// data-product-controller gate is test-isolated-chart-namespace-rules.sh.
//
// A namespace denylist is not sufficient. Denying only "", "aws" and
// "flux-system" leaves every other namespace able to exempt itself from the
// production CEL authorization rules by adding the annotation to its own
// manifest -- the resource declaring the scope is the same resource the scope
// is granted to, so nothing outside this list constrains it. Adding an entry
// here is a deliberate, reviewed act.
var reviewedIsolatedChartIdentities = map[string]struct{}{
	"data-product-controller/data-product-controller": {},
}

// validateAuthorizationIsolation fails closed on every precondition behind an
// isolated-chart declaration. It is intentionally limited to a namespace-local
// HelmRelease and its immutable public OCIRepository. A separate path-scoped
// KSail gate Helm-renders that exact artifact, constrains every child namespace,
// and applies the production CEL authorization rules to its effective RBAC.
func validateAuthorizationIsolation(document map[string]any, identity resourceIdentity) error {
	if !authorizationIsolationRequested(document) {
		return nil
	}
	if _, reviewed := reviewedIsolatedChartIdentities[identity.namespace+"/"+identity.name]; !reviewed {
		return fmt.Errorf("isolated-chart authorization scope is not reviewed for identity %q", identity.namespace+"/"+identity.name)
	}

	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return errors.New("isolated-chart resource must have an object spec")
	}
	optionalString := func(object map[string]any, key string) string {
		value, exists := object[key]
		if !exists || value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
	switch {
	case strings.HasPrefix(identity.apiVersion, "helm.toolkit.fluxcd.io/") && identity.kind == "HelmRelease":
		if targetNamespace := optionalString(spec, "targetNamespace"); targetNamespace != "" && targetNamespace != identity.namespace {
			return errors.New("isolated-chart HelmRelease must target only its own namespace")
		}
		if storageNamespace := optionalString(spec, "storageNamespace"); storageNamespace != "" && storageNamespace != identity.namespace {
			return errors.New("isolated-chart HelmRelease must store release metadata only in its own namespace")
		}
		if serviceAccountName := optionalString(spec, "serviceAccountName"); serviceAccountName != "" {
			return errors.New("isolated-chart HelmRelease must not select a reconciliation service account")
		}
		if _, hasKubeConfig := spec["kubeConfig"]; hasKubeConfig {
			return errors.New("isolated-chart HelmRelease must not target another cluster")
		}
		chartRef, ok := spec["chartRef"].(map[string]any)
		if !ok || fmt.Sprint(chartRef["kind"]) != "OCIRepository" || fmt.Sprint(chartRef["name"]) == "" {
			return errors.New("isolated-chart HelmRelease must reference an OCIRepository")
		}
		if chartNamespace := optionalString(chartRef, "namespace"); chartNamespace != "" && chartNamespace != identity.namespace {
			return errors.New("isolated-chart HelmRelease must reference an OCIRepository in its own namespace")
		}
		if containsAuthorizationKind(spec["postRenderers"]) ||
			containsEmbeddedAuthorizationTemplate(spec["postRenderers"], 0) {
			return errors.New("isolated-chart HelmRelease must not post-render authorization resources")
		}
		return nil

	case strings.HasPrefix(identity.apiVersion, "source.toolkit.fluxcd.io/") && identity.kind == "OCIRepository":
		url := fmt.Sprint(spec["url"])
		if !strings.HasPrefix(url, "oci://ghcr.io/devantler-tech/charts/") {
			return errors.New("isolated-chart OCIRepository must use the reviewed public chart registry")
		}
		ref, ok := spec["ref"].(map[string]any)
		if !ok || requireExactKeys(ref, "digest") != nil || !exactSHA256Digest.MatchString(fmt.Sprint(ref["digest"])) {
			return errors.New("isolated-chart OCIRepository must use exactly one immutable sha256 digest")
		}
		for _, key := range []string{"secretRef", "certSecretRef", "proxySecretRef", "serviceAccountName"} {
			if _, exists := spec[key]; exists {
				return fmt.Errorf("isolated-chart OCIRepository must not configure %s", key)
			}
		}
		return nil
	}

	return fmt.Errorf("isolated-chart authorization scope is unsupported for %s/%s", identity.apiVersion, identity.kind)
}

func isAuthorizationIsolated(document map[string]any, identity resourceIdentity) bool {
	return authorizationIsolationRequested(document) && validateAuthorizationIsolation(document, identity) == nil
}

// isCurrentKyvernoMutationPolicy recognizes the non-legacy Kyverno resources
// that can generate or mutate objects using CEL-based policy APIs.
func isCurrentKyvernoMutationPolicy(identity resourceIdentity) bool {
	return strings.HasPrefix(identity.apiVersion, "policies.kyverno.io/") &&
		(identity.kind == "MutatingPolicy" || identity.kind == "GeneratingPolicy")
}

// isLegacyKyvernoPolicy recognizes rule-based mutation and generation APIs.
func isLegacyKyvernoPolicy(identity resourceIdentity) bool {
	return strings.HasPrefix(identity.apiVersion, "kyverno.io/") &&
		(identity.kind == "Policy" || identity.kind == "ClusterPolicy")
}

// isAuthorizationKind recognizes every kind whose contents or controller can
// redirect, emit, or grant the protected authorization surface.
func isAuthorizationKind(kind string) bool {
	if isRBACAuthorizationKind(kind) || isAWSIAMAuthorizationKind(kind) {
		return true
	}
	targets := []string{
		"Kustomization",
		"OCIRepository",
		"GitRepository",
		"Bucket",
		"HelmRepository",
		"ExternalArtifact",
		"HelmRelease",
		"Provider",
		"Function",
		"Configuration",
		"DeploymentRuntimeConfig",
	}
	for _, target := range targets {
		if kind == target || strings.HasSuffix(kind, "/"+target) {
			return true
		}
	}
	return strings.HasPrefix(kind, "source.toolkit.fluxcd.io/") && strings.HasSuffix(kind, "/*") ||
		strings.HasPrefix(kind, "helm.toolkit.fluxcd.io/") && strings.HasSuffix(kind, "/*") ||
		strings.HasPrefix(kind, "pkg.crossplane.io/") && strings.HasSuffix(kind, "/*") ||
		strings.HasPrefix(kind, "kustomize.toolkit.fluxcd.io/") && strings.HasSuffix(kind, "/*")
}

// kindSelectorIncludesAuthorization checks a Kyverno kind/kinds value.
func kindSelectorIncludesAuthorization(value any) bool {
	switch typedValue := value.(type) {
	case string:
		return isAuthorizationKind(typedValue)
	case []any:
		for _, item := range typedValue {
			if kind, ok := item.(string); ok && isAuthorizationKind(kind) {
				return true
			}
		}
	}
	return false
}

// maxEmbeddedTextDepth bounds how many times a string leaf may be decoded into
// a further document. Real manifests nest once — a post-renderer patch string
// holding one YAML document — so the bound only guards against a pathological
// input; beyond it the declaration scan still applies, so deep nesting fails
// closed rather than escaping inspection.
const maxEmbeddedTextDepth = 4

// embeddedAuthorizationKindDeclaration matches a `kind:` line naming an RBAC
// kind. It backs the fail-closed scan for a string that does not parse, where
// there is no decoded `kind` key to test. It deliberately requires the `kind:`
// key rather than the bare word, so prose that merely mentions a role is not
// mistaken for a declaration.
var embeddedAuthorizationKindDeclaration = regexp.MustCompile(
	`(?m)^[\t ]*kind[\t ]*:[\t ]*["']?(ClusterRoleBinding|ClusterRole|RoleBinding|Role)["']?[\t ]*(#.*)?$`,
)

// textDeclaresAuthorizationKind inspects a string leaf. Flux stores a
// post-renderer patch as a string, and Kustomize matches a target-less
// strategic-merge patch on the GVK and name inside that string, so a string
// leaf can introduce an authorization object with no map for a kind selector to
// catch. Decode it and test the real `kind`; when it does not parse — or when
// nesting exceeds the bound — there is nothing left to decode, so fall back to
// the declaration scan and fail closed rather than pass for want of a decode.
func textDeclaresAuthorizationKind(text string, textDepth int) bool {
	if textDepth < maxEmbeddedTextDepth {
		if documents, err := decodeDocuments([]byte(text)); err == nil {
			for _, document := range documents {
				if containsAuthorizationKindAtDepth(document, textDepth) {
					return true
				}
			}
			return false
		}
	}
	return embeddedAuthorizationKindDeclaration.MatchString(text)
}

// containsAuthorizationKind finds protected kinds inside Kyverno match and
// target shapes, including Flux sources and controller package resources, and
// inside string leaves that carry an embedded document.
func containsAuthorizationKind(value any) bool {
	return containsAuthorizationKindAtDepth(value, 0)
}

func containsAuthorizationKindAtDepth(value any, textDepth int) bool {
	switch typedValue := value.(type) {
	case string:
		return textDeclaresAuthorizationKind(typedValue, textDepth+1)
	case []any:
		for _, item := range typedValue {
			if containsAuthorizationKindAtDepth(item, textDepth) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typedValue {
			if (key == "kind" || key == "kinds") && kindSelectorIncludesAuthorization(item) {
				return true
			}
			if containsAuthorizationKindAtDepth(item, textDepth) {
				return true
			}
		}
	}
	return false
}

// containsEmbeddedAuthorizationTemplate finds nested RBAC object templates
// emitted later by controllers such as KRO rather than by Kustomize itself.
func containsEmbeddedAuthorizationTemplate(value any, depth int) bool {
	switch typedValue := value.(type) {
	case []any:
		for _, item := range typedValue {
			if containsEmbeddedAuthorizationTemplate(item, depth+1) {
				return true
			}
		}
	case map[string]any:
		if depth > 0 {
			identity := identityOf(typedValue)
			if strings.Contains(identity.apiVersion, "${") && isAuthorizationKind(identity.kind) ||
				strings.HasPrefix(identity.apiVersion, "iam.aws.") ||
				identity.apiVersion == "rbac.authorization.k8s.io/v1" && isRBACAuthorizationKind(identity.kind) ||
				identity.apiVersion == "kustomize.toolkit.fluxcd.io/v1" && identity.kind == "Kustomization" ||
				isFluxSourceResource(identity) ||
				isControllerRBACEmitter(identity) ||
				isCurrentKyvernoMutationPolicy(identity) ||
				isLegacyKyvernoPolicy(identity) {
				return true
			}
		}
		for _, item := range typedValue {
			if containsEmbeddedAuthorizationTemplate(item, depth+1) {
				return true
			}
		}
	}
	return false
}

// isIndirectAuthorizationPolicy selects Kyverno policies that can generate or
// mutate RBAC privileges without declaring the resulting object in this render.
func isIndirectAuthorizationPolicy(document map[string]any, identity resourceIdentity) bool {
	if !isLegacyKyvernoPolicy(identity) {
		return false
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return false
	}
	rules, ok := spec["rules"].([]any)
	if !ok {
		return false
	}
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		if rawGenerate, generates := rule["generate"]; generates {
			generate, ok := rawGenerate.(map[string]any)
			kind, hasKind := generate["kind"]
			if !ok || !hasKind || kind == nil || isAuthorizationKind(fmt.Sprint(kind)) {
				return true
			}
		}
		if mutate, mutates := rule["mutate"]; mutates {
			match, hasMatch := rule["match"]
			if !hasMatch || containsAuthorizationKind(match) || containsAuthorizationKind(mutate) {
				return true
			}
		}
	}
	return false
}

// containsFluxSubstitution finds unresolved post-build substitution tokens in
// parsed YAML values before they can change an authorization identity at apply.
func containsFluxSubstitution(value any) bool {
	switch typedValue := value.(type) {
	case string:
		return strings.Contains(typedValue, "${")
	case []any:
		for _, item := range typedValue {
			if containsFluxSubstitution(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typedValue {
			if strings.Contains(key, "${") || containsFluxSubstitution(item) {
				return true
			}
		}
	}
	return false
}

// containsSOPSCiphertext finds encrypted scalar values that the static render
// cannot semantically classify before Flux decrypts them in the cluster.
func containsSOPSCiphertext(value any) bool {
	switch typedValue := value.(type) {
	case string:
		return strings.Contains(typedValue, "ENC[AES256_GCM,")
	case []any:
		for _, item := range typedValue {
			if containsSOPSCiphertext(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typedValue {
			if containsSOPSCiphertext(item) {
				return true
			}
		}
	}
	return false
}

// isSOPSEncrypted recognizes both standard root metadata and encrypted values.
func isSOPSEncrypted(document map[string]any) bool {
	_, hasMetadata := document["sops"]
	return hasMetadata || containsSOPSCiphertext(document)
}

// hasDisabledFluxSubstitution distinguishes controller template expressions
// from post-build variables when Flux is explicitly forbidden from expanding
// the document. The document remains subject to its exact authorization hash.
func hasDisabledFluxSubstitution(document map[string]any) bool {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return false
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	return ok && fmt.Sprint(annotations["kustomize.toolkit.fluxcd.io/substitute"]) == "disabled"
}

// isAuthorizationCapableDocument scopes substitution rejection to resources
// that can directly or indirectly change the EKS CI authorization surface.
func isAuthorizationCapableDocument(document map[string]any, identity resourceIdentity) bool {
	if strings.Contains(identity.apiVersion, "${") || strings.Contains(identity.kind, "${") {
		return true
	}
	if strings.HasPrefix(identity.apiVersion, "iam.aws.") ||
		identity.apiVersion == "rbac.authorization.k8s.io/v1" {
		return true
	}
	if identity.apiVersion == "kustomize.toolkit.fluxcd.io/v1" && identity.kind == "Kustomization" ||
		(isFluxSourceResource(identity) || isControllerRBACEmitter(identity)) &&
			!isAuthorizationIsolated(document, identity) ||
		isCurrentKyvernoMutationPolicy(identity) ||
		isLegacyKyvernoPolicy(identity) {
		return true
	}
	return isIndirectAuthorizationPolicy(document, identity) ||
		containsEmbeddedAuthorizationTemplate(document, 0)
}

// isAuthorizationResource selects every rendered object capable of changing
// the EKS CI identity's IAM, RBAC, or Flux authorization surface.
func isAuthorizationResource(
	document map[string]any,
	identity resourceIdentity,
) bool {
	if strings.HasPrefix(identity.apiVersion, "iam.aws.") {
		return true
	}
	if identity.apiVersion == "rbac.authorization.k8s.io/v1" {
		if identity.kind == "RoleBinding" || identity.kind == "ClusterRoleBinding" ||
			grantsAuthorizationControl(document) {
			return true
		}
		if identity.namespace == "aws" &&
			identity.kind == "Role" {
			return true
		}
	}
	if isIndirectAuthorizationPolicy(document, identity) ||
		isCurrentKyvernoMutationPolicy(identity) ||
		(isFluxSourceResource(identity) || isControllerRBACEmitter(identity)) &&
			!isAuthorizationIsolated(document, identity) {
		return true
	}
	if containsEmbeddedAuthorizationTemplate(document, 0) {
		return true
	}
	return identity.apiVersion == "kustomize.toolkit.fluxcd.io/v1" &&
		identity.kind == "Kustomization"
}

// bindingRoleIdentity returns the Role or ClusterRole resolved by one binding.
func bindingRoleIdentity(document map[string]any, identity resourceIdentity) (resourceIdentity, bool) {
	if identity.apiVersion != "rbac.authorization.k8s.io/v1" ||
		(identity.kind != "RoleBinding" && identity.kind != "ClusterRoleBinding") {
		return resourceIdentity{}, false
	}
	roleRef, ok := document["roleRef"].(map[string]any)
	if !ok || fmt.Sprint(roleRef["apiGroup"]) != "rbac.authorization.k8s.io" {
		return resourceIdentity{}, false
	}
	kind := fmt.Sprint(roleRef["kind"])
	name := fmt.Sprint(roleRef["name"])
	if name == "" || kind != "Role" && kind != "ClusterRole" {
		return resourceIdentity{}, false
	}
	namespace := ""
	if kind == "Role" {
		namespace = identity.namespace
	}
	return resourceIdentity{
		apiVersion: "rbac.authorization.k8s.io/v1",
		kind:       kind,
		namespace:  namespace,
		name:       name,
	}, true
}

// labelsMatchSelector implements the aggregation label-selector shapes used by RBAC.
func labelsMatchSelector(labels map[string]any, selector map[string]any) bool {
	if matchLabels, ok := selector["matchLabels"].(map[string]any); ok {
		for key, expected := range matchLabels {
			if fmt.Sprint(labels[key]) != fmt.Sprint(expected) {
				return false
			}
		}
	}
	expressions, ok := selector["matchExpressions"].([]any)
	if !ok {
		return true
	}
	for _, rawExpression := range expressions {
		expression, ok := rawExpression.(map[string]any)
		if !ok {
			return true
		}
		key := fmt.Sprint(expression["key"])
		actual, exists := labels[key]
		switch fmt.Sprint(expression["operator"]) {
		case "In":
			if !exists || !stringListIncludes(expression["values"], fmt.Sprint(actual)) {
				return false
			}
		case "NotIn":
			if exists && stringListIncludes(expression["values"], fmt.Sprint(actual)) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return true
		}
	}
	return true
}

// aggregationSelectors returns every selector that contributes to one role.
func aggregationSelectors(document map[string]any) []map[string]any {
	aggregationRule, ok := document["aggregationRule"].(map[string]any)
	if !ok {
		return nil
	}
	rawSelectors, ok := aggregationRule["clusterRoleSelectors"].([]any)
	if !ok {
		return nil
	}
	selectors := make([]map[string]any, 0, len(rawSelectors))
	for _, rawSelector := range rawSelectors {
		if selector, ok := rawSelector.(map[string]any); ok {
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

// authorizationRoleIdentities finds bound roles and transitive aggregation contributors.
func authorizationRoleIdentities(documents []map[string]any) map[resourceIdentity]bool {
	selected := make(map[resourceIdentity]bool)
	clusterRoles := make(map[resourceIdentity]map[string]any)
	for _, document := range documents {
		identity := identityOf(document)
		if roleIdentity, ok := bindingRoleIdentity(document, identity); ok {
			selected[roleIdentity] = true
		}
		if identity.apiVersion == "rbac.authorization.k8s.io/v1" && identity.kind == "ClusterRole" {
			clusterRoles[identity] = document
		}
	}
	for changed := true; changed; {
		changed = false
		selectors := make([]map[string]any, 0, len(selected))
		for identity := range selected {
			if identity.kind != "ClusterRole" {
				continue
			}
			selectors = append(selectors, map[string]any{"matchLabels": map[string]any{
				"rbac.authorization.k8s.io/aggregate-to-" + identity.name: "true",
			}})
			selectors = append(selectors, aggregationSelectors(clusterRoles[identity])...)
		}
		for identity, document := range clusterRoles {
			if selected[identity] {
				continue
			}
			metadata, _ := document["metadata"].(map[string]any)
			labels, _ := metadata["labels"].(map[string]any)
			for _, selector := range selectors {
				if labelsMatchSelector(labels, selector) {
					selected[identity] = true
					changed = true
					break
				}
			}
		}
	}
	return selected
}

// authorizationSubstitutionSourceIdentities finds every Flux post-build input.
func authorizationSubstitutionSourceIdentities(documents []map[string]any) map[resourceIdentity]bool {
	selected := make(map[resourceIdentity]bool)
	for _, document := range documents {
		identity := identityOf(document)
		if identity.apiVersion != "kustomize.toolkit.fluxcd.io/v1" || identity.kind != "Kustomization" {
			continue
		}
		spec, ok := document["spec"].(map[string]any)
		if !ok {
			continue
		}
		postBuild, ok := spec["postBuild"].(map[string]any)
		if !ok {
			continue
		}
		references, ok := postBuild["substituteFrom"].([]any)
		if !ok {
			continue
		}
		for _, rawReference := range references {
			reference, ok := rawReference.(map[string]any)
			if !ok {
				continue
			}
			kind := fmt.Sprint(reference["kind"])
			name := fmt.Sprint(reference["name"])
			if name == "" || kind != "ConfigMap" && kind != "Secret" {
				continue
			}
			selected[resourceIdentity{
				apiVersion: "v1",
				kind:       kind,
				namespace:  identity.namespace,
				name:       name,
			}] = true
		}
	}
	return selected
}

// authorizationTemplateInstanceTypes finds CRDs whose instances emit authorization.
func authorizationTemplateInstanceTypes(documents []map[string]any) map[resourceType]bool {
	selected := make(map[resourceType]bool)
	for _, document := range documents {
		identity := identityOf(document)
		if !strings.HasPrefix(identity.apiVersion, "kro.run/") ||
			identity.kind != "ResourceGraphDefinition" ||
			!containsEmbeddedAuthorizationTemplate(document, 0) {
			continue
		}
		schema, err := nestedMap(document, "spec", "schema")
		if err != nil {
			continue
		}
		apiVersion := fmt.Sprint(schema["apiVersion"])
		kind := fmt.Sprint(schema["kind"])
		if apiVersion == "" || kind == "" {
			continue
		}
		if !strings.Contains(apiVersion, "/") {
			dot := strings.Index(identity.name, ".")
			if dot < 0 || dot == len(identity.name)-1 {
				continue
			}
			apiVersion = identity.name[dot+1:] + "/" + apiVersion
		}
		selected[resourceType{apiVersion: apiVersion, kind: kind}] = true
	}
	return selected
}

// cloneStringAnyMap returns a shallow copy used to project one nested field
// without changing the decoded document used by the remaining checks.
func cloneStringAnyMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

// authorizationSurfaceDocument normalizes immutable Helm dependency pins and
// strict signer subsets handled by the required approved-revisions guard.
// Identity, source, values, post-renderers, substitutions and policy stay exact.
// The required manifest job separately Helm-renders and security-scans the
// selected chart version, so a routine Renovate pin does not require a manual
// refresh of an otherwise unchanged authorization fingerprint.
func authorizationSurfaceDocument(
	identity resourceIdentity,
	document map[string]any,
) map[string]any {
	if identity.kind == "OCIRepository" {
		return publishMatcherSurfaceDocument(identity, document)
	}
	if !strings.HasPrefix(identity.apiVersion, "helm.toolkit.fluxcd.io/") || identity.kind != "HelmRelease" {
		return document
	}
	spec, ok := document["spec"].(map[string]any)
	if !ok {
		return document
	}
	chart, ok := spec["chart"].(map[string]any)
	if !ok {
		return document
	}
	chartSpec, ok := chart["spec"].(map[string]any)
	if !ok {
		return document
	}
	version, ok := chartSpec["version"].(string)
	if !ok || !exactPinnedHelmChartVersion.MatchString(version) {
		return document
	}

	projected := cloneStringAnyMap(document)
	projectedSpec := cloneStringAnyMap(spec)
	projectedChart := cloneStringAnyMap(chart)
	projectedChartSpec := cloneStringAnyMap(chartSpec)
	projectedChartSpec["version"] = "<exact-semver>"
	projectedChart["spec"] = projectedChartSpec
	projectedSpec["chart"] = projectedChart
	projected["spec"] = projectedSpec
	return projected
}

// authorizationSurfaceEntry serializes one selected object with its complete
// identity so the aggregate hash preserves additions, removals, and duplicates.
func authorizationSurfaceEntry(identity resourceIdentity, document map[string]any) (string, error) {
	canonical, err := json.Marshal(authorizationSurfaceDocument(identity, document))
	if err != nil {
		return "", fmt.Errorf("marshal authorization surface entry: %w", err)
	}
	return strings.Join([]string{
		identity.apiVersion,
		identity.kind,
		identity.namespace,
		identity.name,
		string(canonical),
	}, "\x00"), nil
}

// validateRendered requires the complete selected authorization surface to
// match one canonical hash while preserving precise core-object diagnostics.
func validateRendered(rendered []byte) error {
	documents, err := decodeDocuments(rendered)
	if err != nil {
		return err
	}
	roleIdentities := authorizationRoleIdentities(documents)
	substitutionSourceIdentities := authorizationSubstitutionSourceIdentities(documents)
	templateInstanceTypes := authorizationTemplateInstanceTypes(documents)
	seen := make(map[resourceIdentity]bool, len(expectedRenderedHashes))
	surfaceEntries := make([]string, 0, len(expectedRenderedHashes))
	problems := make([]error, 0)
	if keyErr := validateUnifiSigningKey(documents); keyErr != nil {
		problems = append(problems, keyErr)
	}
	substitutionProblems := make([]error, 0)
	for _, document := range documents {
		identity := identityOf(document)
		if isolationErr := validateAuthorizationIsolation(document, identity); isolationErr != nil {
			problems = append(problems, fmt.Errorf("invalid authorization isolation for %+v: %w", identity, isolationErr))
		}
		if sourceErr := validatePinnedUnifiSource(document, identity); sourceErr != nil {
			problems = append(problems, sourceErr)
		}
		if exemptionErr := validateUnifiPruneExemption(document, identity); exemptionErr != nil {
			problems = append(problems, exemptionErr)
		}
		isAuthorizationCapable := isAuthorizationCapableDocument(document, identity)
		hasAuthorizationSubstitution := isAuthorizationCapable &&
			containsFluxSubstitution(document) &&
			!hasDisabledFluxSubstitution(document)
		hasEncryptedAuthorization := isAuthorizationCapable && isSOPSEncrypted(document)
		instanceType := resourceType{apiVersion: identity.apiVersion, kind: identity.kind}
		if !roleIdentities[identity] && !substitutionSourceIdentities[identity] &&
			!templateInstanceTypes[instanceType] &&
			!hasAuthorizationSubstitution && !hasEncryptedAuthorization &&
			!isAuthorizationResource(document, identity) {
			continue
		}
		entry, entryErr := authorizationSurfaceEntry(identity, document)
		if entryErr != nil {
			problems = append(problems, entryErr)
			continue
		}
		surfaceEntries = append(surfaceEntries, entry)
		actual, hashErr := canonicalFingerprint(document)
		if hashErr != nil {
			problems = append(problems, hashErr)
			continue
		}
		if hasEncryptedAuthorization {
			problems = append(problems, fmt.Errorf(
				"encrypted SOPS authorization resource cannot be validated before reconciliation: %+v fingerprint: %s",
				identity,
				actual,
			))
		}
		if hasAuthorizationSubstitution {
			substitutionProblems = append(substitutionProblems, fmt.Errorf(
				"unresolved Flux substitution in authorization resource: %+v fingerprint: %s",
				identity,
				actual,
			))
		}
		expected, ok := expectedRenderedHashes[identity]
		if !ok {
			continue
		}
		if seen[identity] {
			problems = append(problems, fmt.Errorf("duplicate rendered authorization resource: %+v", identity))
			continue
		}
		seen[identity] = true
		if actual != expected {
			problems = append(problems, fmt.Errorf("unapproved rendered %+v fingerprint: %s", identity, actual))
		}
	}
	for identity := range expectedRenderedHashes {
		if !seen[identity] {
			problems = append(problems, fmt.Errorf("missing rendered authorization resource: %+v", identity))
		}
	}
	// substitutionProblems are DIAGNOSTIC, not a control, and that is deliberate.
	// The control is surface MEMBERSHIP: a resource carrying an unresolved
	// substitution is forced into the aggregate surface above, so its text —
	// including the `${…}` literal — is covered by the fingerprint and cannot
	// change without moving it. Emitting the notes only alongside a mismatch is
	// what keeps them useful: they explain a hash that moved.
	//
	// Measured 2026-07-21: promoting them to unconditional errors fails the
	// committed, approved tree on THIRTY-plus HelmReleases, because post-build
	// substitution is the platform's normal configuration mechanism and
	// containsFluxSubstitution matches a document anywhere. A validator that is
	// red on the approved state is not a stricter gate, it is a disabled one.
	sort.Strings(surfaceEntries)
	canonicalSurface, marshalErr := json.Marshal(surfaceEntries)
	if marshalErr != nil {
		problems = append(problems, fmt.Errorf("marshal authorization surface: %w", marshalErr))
		problems = append(problems, substitutionProblems...)
	} else if actualSurfaceSHA := fingerprint(canonicalSurface); actualSurfaceSHA != expectedRenderedSurfaceSHA {
		problems = append(problems, fmt.Errorf(
			"unapproved rendered authorization surface fingerprint: %s",
			actualSurfaceSHA,
		))
		problems = append(problems, substitutionProblems...)
	}
	return errors.Join(problems...)
}

// validateAuthorization combines source and final-render checks so neither
// Kustomize transformations nor source edits can bypass the contract.
func validateAuthorization(role []byte, boundary []byte, rendered []byte) error {
	if err := validateRole(role); err != nil {
		return err
	}
	if err := validateBoundary(boundary); err != nil {
		return err
	}
	return validateRendered(rendered)
}

// validateRendererVersion pins kubectl and its embedded Kustomize version,
// keeping canonical render hashes reproducible across CI and local validation.
func validateRendererVersion(versionJSON []byte) error {
	var version struct {
		ClientVersion struct {
			GitVersion string `json:"gitVersion"`
		} `json:"clientVersion"`
		KustomizeVersion string `json:"kustomizeVersion"`
	}
	if err := json.Unmarshal(versionJSON, &version); err != nil {
		return fmt.Errorf("parse kubectl version: %w", err)
	}
	if version.ClientVersion.GitVersion != expectedKubectlVersion ||
		version.KustomizeVersion != expectedKustomizeVersion {
		return fmt.Errorf(
			"unapproved renderer: kubectl=%s kustomize=%s",
			version.ClientVersion.GitVersion,
			version.KustomizeVersion,
		)
	}
	return nil
}

// commandOutput runs a repository-controlled command under the caller's
// deadline and includes its output in failures instead of returning a false red.
func commandOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...) //nolint:gosec // Fixed binary and repository-controlled arguments.
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, output)
	}
	return output, nil
}

// renderAuthorizationLayers renders every independently reconciled production
// layer and joins them into one YAML stream for fail-closed authorization checks.
func renderAuthorizationLayers(ctx context.Context, repoRoot string, execute commandExecutor) ([]byte, error) {
	var rendered bytes.Buffer
	for _, overlayPath := range authorizationOverlayPaths {
		layer, err := execute(ctx, "kubectl", "kustomize", filepath.Join(repoRoot, overlayPath))
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", overlayPath, err)
		}
		if rendered.Len() > 0 {
			if previous := rendered.Bytes(); previous[len(previous)-1] != '\n' {
				_ = rendered.WriteByte('\n')
			}
			_, _ = rendered.WriteString("---\n")
		}
		_, _ = rendered.Write(layer)
	}
	return rendered.Bytes(), nil
}

// run executes the complete repository-root authorization validation and
// returns a process-compatible status without mutating cluster state.
func run(repoRoot string, stdout io.Writer, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), rendererCommandTimeout)
	defer cancel()

	version, err := commandOutput(ctx, "kubectl", "version", "--client", "-o", "json")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: %v\n", err)
		return 1
	}
	if err := validateRendererVersion(version); err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: %v\n", err)
		return 1
	}
	rendered, err := renderAuthorizationLayers(ctx, repoRoot, commandOutput)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: %v\n", err)
		return 1
	}
	role, err := os.ReadFile(filepath.Join(repoRoot, roleManifestPath)) //nolint:gosec // Explicit repository path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: read role: %v\n", err)
		return 1
	}
	boundary, err := os.ReadFile(filepath.Join(repoRoot, boundaryManifestPath)) //nolint:gosec // Explicit repository path.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: read boundary: %v\n", err)
		return 1
	}
	if err := validateAuthorization(role, boundary, rendered); err != nil {
		_, _ = fmt.Fprintf(stderr, "EKS CI role policy: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "EKS CI role authorization contract passed.")
	return 0
}

// runCLI enforces the single explicit repository-root argument before invoking
// validation, preventing ambient working-directory assumptions.
func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: validate-eks-ci-role-policy <repository-root>")
		return 2
	}
	return run(args[0], stdout, stderr)
}

// main executes the validator process and returns its contract result to CI.
func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}
