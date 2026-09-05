# Actual Budget user-namespace pilot

This production-only component is **disabled by default**. It sets
`hostUsers: false` on the Actual Budget Deployment and labels its namespace for
the existing Kyverno user-namespace admission policy. The sync server and
`enablebanking-seed` sidecar keep their existing user/group IDs, mounts, and
shared database volume. The deployment retains its single-replica `Recreate`
strategy.

The pod setting is applied through an appended Helm post-renderer. The chart's
Deployment has no `metadata.namespace`, so the inner target uses its exact
name and API kind; the outer patch targets only the Actual Budget HelmRelease
in its namespace. Existing post-renderers remain in order, including the
authentication, startup-probe, and deployment-strategy patches.

Kubernetes user namespaces remap container IDs to different host IDs. Stateful
pods also require idmapped mounts on the underlying filesystem. A successful
render proves the configuration, while the live pilot must establish that this
application can still read and write its existing data. See the
[Kubernetes user-namespace documentation](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).

## Validate without deploying

From the repository root, run:

```bash
bash scripts/tests/test-actual-budget-user-namespaces.sh
ksail workload validate
ksail --config ksail.prod.yaml workload validate
```

The regression script requires `kubectl`, Helm, `jq`, and `yq` v4. It downloads
the chart version pinned by the HelmRelease, renders all its post-renderers,
and compares both pilot states. Only `hostUsers` may change in the chart's
workload; the complete PVC and container definitions must remain identical.
It also checks the full production overlay, local isolation, and exact rollback.
It uses a temporary copy of the manifests and needs no cluster or secrets.

## Activate through a separate PR

Activation is tracked by [#3604](https://github.com/devantler-tech/platform/issues/3604).
Before enabling it, confirm the app, nodes, storage and backups are healthy.
Record the current Deployment revision and pod UID privately as pre-rollout
baselines; both are expected to change during the rollout. Also record the PVC
UID, PV name and storage volume identity so post-rollout verification confirms
that the same storage objects remain bound. A different healthy volume is not
evidence that the original data was preserved.

Uncomment only this component entry in
[`apps/kustomization.yaml`](../../../kustomization.yaml):

```yaml
components:
  # Other existing components stay in place.
  - actual-budget/components/user-namespaces
```

Run the validations above, adapting the staging-only default-off assertion in
the activation PR to test the new committed state and a temporary disabled
state. Submit through the normal review and deployment path. Enabling the
component replaces the one pod; the `Recreate` strategy entails a brief outage.

The runtime verdict requires all the following:

- The new deployed revision is the reviewed one. The Deployment is Available
  1/1, its replacement pod is Ready 2/2, and the pod spec contains
  `hostUsers: false`.
- Both actual containers show non-zero subordinate host IDs in
  `/proc/self/uid_map` and `/proc/self/gid_map`. A disposable smoke pod proves
  its own mapping only; it does not replace this check.
- Existing budgets open and sync through the authenticated route. The main
  container and bank-sync sidecar retain access to their existing database,
  and the sidecar completes a reconciliation. Keep budget data, credentials,
  and raw application logs out of public issue comments.
- The same PVC/PV/storage volume remains bound and healthy. No new mount,
  permission, or warning events appear.
- The app stays healthy for at least 30 minutes, including a sidecar interval.
  Record the observation window and an aggregate verdict on the activation
  issue, with detailed evidence kept private.

Only after this verdict should the short-lived component be retired and the
proven setting made permanent through a separate reviewed change, tracked by
[#3605](https://github.com/devantler-tech/platform/issues/3605).

## Roll back without touching storage

Remove the component reference from `apps/kustomization.yaml` in a rollback PR.
This removes the namespace enforcement label and the appended pod patch
together. After deployment, verify that both are absent, the replacement pod
is Ready, the same storage identities remain bound, and budget access and
sidecar reconciliation work again.

Do not delete or recreate PVCs, reinstall the chart, change ownership
recursively, or disable namespace policy independently as part of rollback.
Those actions are not the inverse of this pilot. The regression test proves
that removing the single reference restores the original rendered resources.
