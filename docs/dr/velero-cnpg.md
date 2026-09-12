# Application & volume backups — Velero + CloudNativePG → R2

The application/PV backup tier. With Omni retired, etcd is a cattle
resource recreated by `ksail cluster create` on demand (see
[runbook.md](./runbook.md) scenario 4). This layer covers everything that
needs to survive a full cluster rebuild — Kubernetes objects, PVC
contents, and Postgres data.

## Architecture

```
                ┌─────────────────────────────────────┐
                │  Cloudflare R2                      │
                │  bucket: <your-bucket>              │
                │    velero/<env>/   (this layer)     │
                │    cnpg/<env>/     (this layer)     │
                └─────────────────────────────────────┘
                              ▲           ▲
                              │           │
                       ┌──────┴───┐  ┌────┴───────────────┐
                       │ Velero   │  │ CloudNativePG      │
                       │ Kopia    │  │ Cluster + Barman   │
                       │ uploader │  │ (per-Cluster)      │
                       └──────────┘  └────────────────────┘
```

Credentials are SOPS-encrypted per environment in the cluster secret
(`k8s/clusters/<env>/bootstrap/secret.enc.yaml`), seeded
into OpenBao at `infrastructure/backup/r2` by the `seed-r2-credentials`
PushSecret, and materialised into the Velero and CNPG namespaces by
ExternalSecrets.

## Velero

- Chart: `vmware-tanzu/velero` (HelmRepository at
  `https://vmware-tanzu.github.io/helm-charts`), Velero 1.18.
- Namespace: `velero`.
- BackupStorageLocation: `default` → R2, prefix `velero/<env>`.
- Daily schedule `daily-full` at 02:17, 14-day TTL, all namespaces except
  `kube-system` and `velero`. Long-term retention is enforced by R2 object
  lock + lifecycle rules (configured on the bucket) so even a misconfigured
  Velero cannot delete history beyond the 30-day governance window.
- HA: `velero_replicas` (prod = 1, leader-elected), hostname topologySpread,
  `Recreate` strategy — **no PDB** (a single leader-elected pod with a PDB
  would deadlock rolling upgrades). The node-agent runs as a DaemonSet on
  every node (required for both Kopia FSB and the CSI data mover).

### Backup method: per-StorageClass (prod) vs uniform FSB (local)

Backups always land in R2 as a Kopia repository, so they are portable for
cross-provider/cross-distribution restore regardless of how the volume was
captured. *How* each volume is captured depends on its storage backend:

| Storage backend                    | Method                               | Why                                                                                  |
| ---------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------ |
| Longhorn (`longhorn` SC)           | CSI snapshot → Kopia data mover → R2  | Crash-consistent; also backs up PVCs of scaled-to-zero apps (no running pod needed).  |
| hcloud (`hcloud` SC, e.g. openbao) | File-system backup (Kopia) → R2       | **Hetzner block storage has no CSI snapshot support** (the driver advertises no `CREATE_DELETE_SNAPSHOT`; Hetzner has no volume-snapshot product). |
| anything else / new PVCs           | File-system backup (Kopia) → R2       | Fail-safe default.                                                                    |

The routing is declarative (by StorageClass), not per-pod annotations:

- `defaultVolumesToFsBackup: true` everywhere is the **fail-safe default** — any
  volume not otherwise routed is Kopia-FSB'd, so nothing is ever silently
  skipped.
- **prod only:** a Velero **Volume Policy** ConfigMap (`velero-volume-policies`,
  referenced by the schedule's `spec.resourcePolicy`) routes `storageClass:
  [longhorn]` → the `snapshot` action. Volume policies take precedence over the
  FSB default, so Longhorn PVCs take the CSI path and everything else falls back
  to FSB. `snapshotMoveData: true` makes the data mover upload the CSI snapshots
  to R2 (so they are not tied to Longhorn at restore time).
- **local/CI:** no Volume Policy and no CSI (the docker `local-path` provider
  cannot snapshot) → every volume uses FSB. That is the same Kopia FSB code path
  prod uses for its hcloud/fallback volumes, so the CI restore drill still
  regression-tests it.

### CSI snapshot prerequisites (prod/hetzner)

CSI snapshots need cluster-wide plumbing that the hetzner overlay adds:

- **snapshot-controller + the `snapshot.storage.k8s.io` CRDs** — the piraeus
  `snapshot-controller` chart (appVersion = kubernetes-csi external-snapshotter
  v8.5.0, the version Longhorn 1.11 targets), in `kube-system`. The conversion
  webhook is disabled (only the v1 API is used).
- **Longhorn CSI snapshotter sidecar** — enabled via
  `longhorn_csi_snapshotter_replicas: "1"`. Longhorn `dependsOn`
  snapshot-controller so the CRDs exist before the sidecar starts.
- **`VolumeSnapshotClass` `longhorn-snapshot-vsc`** (`type: snap`, labelled
  `velero.io/csi-volumesnapshot-class`) — a plain in-cluster Longhorn snapshot
  (NOT a billed cloud snapshot, and NOT Longhorn's own `bak` backup target)
  which the data mover reads and then deletes. It lives in the `infrastructure`
  Flux layer so the CRDs (installed in `infrastructure-controllers`) are
  established first.
- Velero `features: EnableCSI` (the CSI plugin is built into Velero 1.18 core,
  so no extra plugin beyond `velero-plugin-for-aws` for the R2 BSL).

> **Transient disk during the backup window.** For each Longhorn PVC the data
> mover provisions a short-lived PVC from the snapshot (on `longhorn`, so
> ×`longhorn_replica_count`) and a node-agent pod copies it to R2, then deletes
> both. On the space-constrained cx23 workers this transiently consumes up to
> the source volume's size × replica count per PVC during the 02:17 run — fine
> for the current set (umami 5Gi, actual-budget 10Gi, headlamp 256Mi) but worth
> watching if larger Longhorn volumes are added.

## CloudNativePG

- CNPG backup credentials are projected **per-namespace** from OpenBao: each
  CNPG `Cluster` gets an ExternalSecret next to it that reads the shared
  `infrastructure/backup/r2` OpenBao path (the same key/secret Velero uses)
  into a Secret in the Cluster's own namespace — CNPG's
  `barmanObjectStore.s3Credentials` can only reference a Secret there. The
  earlier reusable `cnpg-r2-credentials` Secret in `cnpg-system` was removed:
  no `Cluster` could reference it across namespaces.
- Live example: `umami-db` — `k8s/bases/apps/umami/external-secret-db-backup.yaml`
  projects `umami-db-backup-r2`, which the `Cluster` in
  `k8s/bases/apps/umami/cluster.yaml` references (with a
  `ScheduledBackup` in `scheduled-backup.yaml`).
- When the next CNPG-backed app lands, copy the umami ExternalSecret next to
  its `Cluster` and point `barmanObjectStore.destinationPath` at a distinct
  `s3://${r2_bucket}/cnpg/<app>` prefix.
- Give each CNPG Barman plugin an explicit `parameters.serverName` that
  identifies the current logical Cluster incarnation. The plugin admission
  webhook forbids this field on the `ObjectStore`; it belongs on the Cluster's
  `spec.plugins` entry. Barman requires an empty archive for a new PostgreSQL
  system ID, so reusing an implicit Cluster-name server after a restore or
  replacement makes continuous WAL archiving fail with `Expected empty
  archive`, even when base backups still report success. Keep the ObjectStore
  destination path stable so retained recovery data remains available, and
  advance the server name in the same reviewed recovery change that creates the
  new Cluster. Do not change it for an ordinary rollout of a healthy Cluster.

## Local clusters: MinIO replaces R2

Same Velero install, different backend. Local uses an in-cluster
**Bitnami MinIO** chart (single replica, ephemeral storage) so the entire
S3 code path runs end-to-end in CI. The redirection happens via Flux
variable overrides in `k8s/clusters/local/bootstrap/`:

| Variable               | Local value                                       |
| ---------------------- | ------------------------------------------------- |
| `r2_endpoint`          | `http://minio.minio.svc.cluster.local:9000`       |
| `r2_region`            | `us-east-1` (MinIO ignores; Velero requires)      |
| `r2_bucket`            | `platform-backups`                                |
| `r2_access_key_id`     | `minio` (SOPS-encrypted)                          |
| `r2_secret_access_key` | `minio-local-development-only` (SOPS-encrypted)   |

No code changes between local and prod — only the variable values differ.
This is the whole point of the substitution layer: the CI restore drill
(see [restore-drill.md](./restore-drill.md))
exercises the *exact* same `velero backup` / `velero restore` calls
that an operator would run against R2 in prod.

The MinIO credentials are hard-coded local-only secrets. They are
SOPS-encrypted at rest per the platform-wide rule, but they are not
sensitive — the bucket is in-cluster and ephemeral, accessible only from
inside the local Docker cluster, and is wiped on every
`ksail cluster delete`.

## Operator commands (post-install)

```bash
# List backup storage locations
kubectl -n velero get backupstoragelocations.velero.io

# Trigger an ad-hoc backup. NOTE: unlike the daily-full schedule, a manual
# Backup does NOT inherit the volume policy. Add resourcePolicy (prod) if you
# want Longhorn PVCs captured via CSI snapshot; without it every volume is
# FSB'd (safe, just not crash-consistent for Longhorn). Omit it on local.
kubectl -n velero create -f - <<EOF
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: manual-$(date +%s)
  namespace: velero
spec:
  ttl: 720h
  defaultVolumesToFsBackup: true
  resourcePolicy:
    kind: configmap
    name: velero-volume-policies
EOF

# Restore (e.g. into a fresh cluster after etcd restore)
kubectl -n velero create -f - <<EOF
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: full-restore-$(date +%s)
  namespace: velero
spec:
  backupName: <backup-name>
EOF
```

For the full DR procedure (which order to restore in, expected RTO breakdown,
etc.) see [`runbook.md`](./runbook.md).

## Credential rotation

Stored per environment in
`k8s/clusters/<env>/bootstrap/secret.enc.yaml`. Rotation
flow (see also runbook.md Scenario 7):

```bash
# 1. Mint a new R2 token in Cloudflare; revoke the old one only after step 4.
# 2. Update both keys in-place with sops:
sops --set '["stringData"]["r2_access_key_id"] "<new-id>"' \
  k8s/clusters/prod/bootstrap/secret.enc.yaml
sops --set '["stringData"]["r2_secret_access_key"] "<new-secret>"' \
  k8s/clusters/prod/bootstrap/secret.enc.yaml
# 3. PR + merge -> Flux reconciles the new Secret -> the hourly
#    seed-r2-credentials PushSecret refreshes OpenBao -> the Velero/CNPG
#    ExternalSecrets re-sync within their refresh interval.
# 4. Revoke the old token in Cloudflare.
```

## Related

- [DR runbook](./runbook.md) — restore-from-zero procedure
- [Alerting](./alerting.md) — alarms on missed backups / failures
- [CI restore drill](./restore-drill.md) — automated proof
