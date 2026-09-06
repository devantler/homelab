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

The shared production deploy action handles the evidence in deployment order:

1. Before publication, the read-only canary guard checks whether the desired
   source declares the defaults and the stored UI template still lacks them.
   Only that transition arms the canary. A source rollback disarms it before
   reading the workload; a later deployment with the defaults already present
   does not freeze the UI's initial replica count or identity.
2. An existing canary must be Helm-owned, fully ready, non-root, and use only
   ephemeral volumes without an `fsGroup`. API failure is an error, never an
   empty population. A reachable API reporting an uninstalled UI allows the
   initial installation but still requires the next step.
3. After Flux reports the released revision Ready, the guard reads the stored
   defaults and complete rollout status, then watches the template for 30 seconds.
   Missing fields, unhealthy replicas, changed privilege settings or a rewriting
   owner fail the deployment. The output records the observed generation without
   emitting workload environment values or credentials.
4. A failed merge-group deployment remains failed and the existing heal job
   restores the current `main` revision. Removing only the two source defaults
   restores the prior rendered resources; it preserves the existing UI hardening.
   A manual CD failure requires the same normal Git revert and CD recovery path;
   it does not have the merge-group heal job.

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

The next increments follow the same source-first route:

1. Re-enumerate stored Deployments, DaemonSets, StatefulSets and CronJobs in the
   excluded namespaces. Record each owner's source, existing security context,
   persistent storage, rollout strategy and current readiness. Include regular
   and init containers; distinguish a missing SELinux object from a deliberate
   partial or empty object. Exclude stale scanner verdicts from the evidence.
2. For a Helm- or Git-owned workload, add only the missing defaults to its
   declared pod template, using chart values where supported and a tested exact
   post-renderer otherwise. Review one workload's rendered delta and rollback
   before deploying it. Chart-owned Longhorn components are separate increments
   from the UI; no manager or CSI restart is implied by this canary.
3. For an operator-owned workload, first establish how its reconciler builds
   the desired template. Prefer an operator-supported source field. An admission
   fallback needs exact owner/object scoping, a tested convergence contract and
   its own staged preflight/after-apply gate. Keep that owner's mutation off
   until those conditions are implemented; user permission cannot substitute
   for them.
4. Re-measure stored templates and runtime health after each applied increment.
   Update C-0211 exception sizing only from the new complete measurement. The
   original 33-workload denominator is historical, and completing the UI canary
   does not complete platform issue #3239.

The existing namespace inventory test pins the default-off controller rollout.
Its historical demand for post-rollout evidence inside the activation commit is
not a usable ordering for GitOps. A future namespace activation must replace
that assumption with the enforceable preflight and after-apply sequence above,
scoped to the owners it actually changes; changing the inventory pin alone does
not satisfy the rollout contract.
