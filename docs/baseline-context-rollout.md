# Baseline security context rollout

The stored controller templates are the C-0211 measurement surface. Pod admission
defaults do not backfill them. Source-owned template changes travel through the
normal GitOps merge queue, which can deploy them while an engineer's interactive
production credentials remain read-only.

## Longhorn UI canary

The Longhorn HelmRelease supplies `fsGroupChangePolicy: OnRootMismatch` and an
empty container `seLinuxOptions` object through its existing `longhorn-ui`
post-renderer. The empty object leaves SELinux/MCS label selection to the runtime.
The UI has no `fsGroup` and uses only `emptyDir` volumes, so the ownership policy
has no effect on mounted data. Its existing numeric identity, dropped capabilities,
seccomp profile, replica count and volumes remain unchanged.

The real pinned chart test exercises the defaults present and absent, proves
that every other rendered resource is identical, and renders the source rollback.
It fails if a renamed chart target causes the post-renderer to miss the UI.

The shared production deploy action and disaster-recovery rebuild workflow
handle the evidence in deployment order:

1. Before publication, the read-only canary guard checks whether the desired
   source declares the defaults and the stored UI template has both fields plus
   a successful proof for its own UID. Fields alone never disarm verification:
   a failed first proof or a crash before recording must retry. A source rollback
   disarms before reading the workload; a successfully proven deployment does
   not freeze the UI's initial replica count or identity on later chart changes.
2. An existing canary must be Helm-owned, fully ready, non-root, have no init
   containers, and use only ephemeral volumes without an `fsGroup`. API failure is an error, never an
   empty population. A reachable API reporting an uninstalled UI allows the
   initial installation but still requires the next step.
3. After Flux reports the released revision Ready, the guard reads the stored
   defaults and complete rollout status, then watches the template for 30 seconds.
   Missing fields, unhealthy replicas, changed privilege settings or a rewriting
   owner fail the deployment. The output records the observed generation without
   emitting workload environment values or credentials.
4. Only after that proof succeeds, a separate workflow step records the
   `pod-security.devantler.tech/longhorn-ui-baseline-proof` metadata annotation.
   Its JSON Patch atomically tests the UID and resourceVersion from the final
   observed object before recording that UID. A concurrent change or replacement
   rejects the write; no earlier observation can certify a different object.
   The chart does not declare this annotation. Losing the receipt safely requires
   revalidation, and a replacement cannot inherit the prior Deployment's proof.
5. A failed merge-group deployment remains failed and the existing heal job
   restores the current `main` revision. Removing only the two source defaults
   restores the prior rendered resources; it preserves the existing UI hardening.
   A manual CD or rebuild failure requires the normal Git revert and recovery
   path; those workflows do not have the merge-group heal job.

An engineer can reproduce the read-only phases with
`bash scripts/guard-longhorn-ui-baseline-context.sh before-publish --context <read-only-context>`
and `after-reconcile` after deployment. An after-apply result is recorded after
the deploy; the activation commit does not claim evidence from a future rollout.

## Remaining controller population

The namespace-wide `baseline-context-controllers` admission switch remains off.
Enabling it changes every subsequently written eligible template in that
namespace. A blanket restart would roll storage managers and CSI workloads and
can introduce an admission/reconciliation loop for operator-owned resources.
The UI canary does not establish safety for those workloads.

Helm and Git templates have a source-owned route through values or exact
post-renderers. Operator-generated templates instead depend on supported owner
configuration and convergence: admission of a field absent from the owner's
desired state can cause repeated writes. Storage managers, CSI components and
operator-generated workloads are outside the UI canary's ephemeral-volume scope.
Permission to deploy does not prove those compatibility conditions.

The remaining rollout and its acceptance measurements are tracked in
[issue #3239](https://github.com/devantler-tech/platform/issues/3239). C-0211 sizing
depends on a complete measurement of stored controllers and every regular/init
container, with runtime health evidence. The original 33-workload denominator is
historical; neither this canary nor a stale scanner verdict completes that target.

The existing namespace inventory test pins the default-off controller rollout.
Its historical demand for post-rollout evidence inside the activation commit is
not a usable ordering for GitOps. A future namespace activation must replace
that assumption with the enforceable preflight and after-apply sequence above,
scoped to the owners it actually changes; changing the inventory pin alone does
not satisfy the rollout contract.
