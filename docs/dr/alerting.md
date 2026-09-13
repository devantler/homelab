# Observability & Alerting

**Coroot** (Community Edition, fully self-hosted) is the single observability
tool — metrics, logs, traces, continuous profiling, a service map, predefined
dashboards/inspections and SLO-based alerting, all out of the box — plus
**OpenCost** (cost), running per cluster. No SaaS tier, no remote-write.

It replaces the previous `kube-prometheus-stack` + Loki + Alloy assembly: one
operator and one custom resource collapse Prometheus, Grafana, Alertmanager,
node-exporter, kube-state-metrics, the log store and the log shipper into a
single eBPF-based stack.

## Architecture

The `coroot-operator` HelmRelease installs the operator + the `Coroot` CRD; the
`Coroot` custom resource (`coroot.yaml`) is reconciled into the workloads:

| Component         | Role                                                          | Persistence (prod)   |
| ----------------- | ------------------------------------------------------------- | -------------------- |
| Coroot (UI/app)   | Web UI, dashboards, inspections, alerting engine              | `hcloud` PVC, 2 Gi   |
| Prometheus        | Bundled metrics TSDB (14 d retention), queryable by OpenCost  | `hcloud` PVC, 20 Gi  |
| ClickHouse        | Logs, traces and continuous profiles (+ 1 keeper)             | `hcloud` PVC, 15 Gi  |
| node-agent        | eBPF DaemonSet: per-node + per-pod metrics, logs, traces      | n/a                  |
| cluster-agent     | kube-state-metrics-equivalent cluster inventory               | n/a                  |
| OpenCost          | Cost allocation, querying Coroot's bundled Prometheus         | n/a                  |

The node-agent uses eBPF, so it observes every pod's traffic, latency, errors,
logs and traces **without** per-app scrape config or ServiceMonitors — there is
no prometheus-operator and no `ServiceMonitor`/`PodMonitor`/`PrometheusRule`
CRD any more. It runs `platform-critical` so per-node telemetry survives memory
pressure (the operator only exposes `priorityClassName` on the node-agent).

Local/CI (docker provider) runs the same CR on the cluster's default storage
class (ephemeral — losing telemetry on a restart is fine there). The `hcloud`
PVC overrides and longer retention live in the hetzner overlay
(`k8s/providers/hetzner/infrastructure/coroot/patches/`), the same
way OpenBao gets block storage.

## SSO

Coroot CE has no native OIDC (SSO is an Enterprise feature), so the UI is
fronted by **oauth2-proxy** (Dex) — the same forward-auth pattern the Prometheus
and Alertmanager UIs used. The `coroot.${domain}` HTTPRoute backends to
oauth2-proxy; after authentication, auth-proxy routes by Host to the Coroot
Service (`coroot-coroot.coroot.svc:8080`). The CR sets `authAnonymousRole:
Admin`, so whoever clears the GitHub SSO gate (oauth2-proxy, `devantler` only)
is the operator — mirroring the old "everyone → Grafana Admin" posture.

## Alerting → Slack

Coroot ships **built-in alerting** with no rules to author: SLO-based alerts
(per-application latency/error budgets) plus automatic inspections — node down,
OOM kills, container restarts/crashloops, disk filling up, deployment issues,
CPU/memory saturation. These deliver to Slack (and PagerDuty / Teams / Opsgenie
/ webhook).

Slack is wired **fully declaratively** in the hetzner overlay — no UI step, no
token to paste. Coroot CE has no pre-fillable bot-token integration, so its
generic **webhook** integration is used instead: it POSTs a Slack-mrkdwn payload
(rendered from `incidentTemplate` / `alertTemplate`, JSON-escaped via the `json`
template func) to the **exact Slack incoming-webhook the prometheus stack used** —
`${alertmanager_webhook_url}`, injected by Flux from the per-cluster
`variables-cluster` Secret. Nothing new to set; the value is inherited.

The project's agent API key (`coroot-api-key`) is **created automatically by the
operator** (generated in-cluster, no seed), so describing the project doesn't
break agent telemetry. This lives only in the hetzner overlay — the base Coroot
CR has no `projects`/webhook integration — so local/CI has nothing to send and
stays quiet by design, exactly as the old Alertmanager did.

### Changed from the old stack

- **Custom PromQL platform alerts: partially re-instated.** The old
  `alerts/platform-critical.yaml` (Velero/CNPG backup, cert expiry,
  `FluxKustomizationNotReady`, autoscaler) had no 1:1 in Coroot's SLO/inspection
  model and was dropped. Node/pod/OOM/disk/crashloop health is covered by
  Coroot's auto-inspections. The **`FluxKustomizationNotReady`** check is now
  back — re-expressed the Flux-native way rather than as a Coroot rule: a
  notification-controller `Provider` + `Alert`
  (`providers/hetzner/infrastructure/flux-notifications/`) posts every
  Kustomization reconciliation error to the same Slack webhook, event-driven and
  with no polling pod for the kubescape scan to flag. The four top-level
  Kustomizations (`bootstrap → infrastructure-controllers → infrastructure →
  apps`) wait on their children, so a failed controller / app / HelmRelease
  surfaces here as its parent going NotReady. Sustained CNPG continuous-WAL
  archival failure is covered by the degraded-cluster check below. The
  remaining **scheduled base-backup success/staleness** and **cert-expiry**
  checks are not Flux resources, so they need a scan-safe synthetic check (e.g.
  per-CronJob dead-man pings like the heartbeat below, tied to the silent vault
  snapshot in #1970) and are still TODO.
- **Degraded CNPG clusters alert on their own, not via the merge-queue gate.**
  A database losing a replica used to reach Slack only through the gate
  described above — as a *Flux* error naming a Kustomization, 20 minutes late,
  after `apps` had already timed out and evicted every PR from the merge queue.
  That happened twice in three weeks (coroot-db 2026-07-14, umami-db
  2026-08-05, the latter degraded for over five hours with no alert). Coroot's
  inspections cover crashloops, but the 07-14 case was a pod that stayed
  Running, never Ready, with zero restarts.
  `bases/infrastructure/controllers/coroot/cron-job-cnpg-degraded-alert.yaml` now
  checks every CNPG `Cluster` every 30 minutes and posts to the same Slack
  webhook when its replicas or configured continuous WAL archiver have been
  degraded past a 15-minute grace. The archive branch also treats a missing
  `ContinuousArchiving` condition as `Unknown` after the Cluster creation grace;
  this catches a sidecar that never reports state. It is deliberately
  independent of any Flux health gate, so relaxing that gate cannot silently
  remove this coverage. The archive branch was added after wedding-db remained
  3/3 Ready while Barman rejected WAL from a replacement system ID for roughly
  three days.
- **Velero maintenance OOMKills remain visible after a successful retry.**
  `bases/components/coroot-velero-maintenance-oom-alert/cron-job-velero-maintenance-oom-alert.yaml`
  checks retained repository-maintenance pod status every 30 minutes. It alerts
  on an `OOMKilled` termination from the previous two hours even when a later
  Job for the same repository succeeds and restores `BackupRepository` readiness.
  Its cross-namespace Role is limited to `list` on pods in `velero`.
- **A stranded volume attach alerts within about fifteen minutes.** On
  2026-07-01 one hcloud volume that stayed attached to a departed node took all
  prod delivery down for nine hours: the rescheduled `openbao-0` logged
  `FailedAttachVolume … volume is attached` 26,632 times, OpenBao stayed down,
  the `vault-config` Job timed out, `infrastructure` and `apps` went NotReady and
  every merge-group deploy was evicted — and nothing reported the strand itself
  (#2363). `bases/infrastructure/controllers/coroot/cron-job-stranded-volume-attach-alert.yaml`
  now reads the `FailedAttachVolume` / `FailedMount` events every 5 minutes and
  posts to the same Slack webhook when a pod has been failing to attach for more
  than 10 minutes, is still failing, and is still not Ready — naming the pod,
  node, PVC, PV and the CSI message. It reads the symptom rather than the
  `VolumeAttachment`, because the strand lives in the cloud provider while the
  Kubernetes objects can look consistent; it is read-only, and force-detach
  stays a manual step (#2754).
- **kube-apiserver audit logs are searchable in Coroot again.** Coroot's
  node-agent ingests container logs/traces, not host audit-log files, so the
  previous alloy-audit → Loki pipeline was removed with the migration. The
  `audit-log-forwarder` (`bases/infrastructure/audit-log-forwarder/`,
  a control-plane-only OpenTelemetry Collector DaemonSet) re-introduces that
  capability against Coroot: it tails `/var/log/audit/kube/audit.log` and ships
  it to the Coroot OTLP logs endpoint as the `kube-apiserver-audit` application.
  Retention in Coroot follows the Coroot CR's `logsTTL` (3d in the base, 7d in
  prod); the on-node file backend (`talos/cluster/enable-audit-logging.yaml`,
  30-day rotation) remains the resilient primary for forensics beyond that
  window.

## Kubescape runtime-detection alerts

The Kubescape node-agent's **runtime-detection** alerts (rule violations,
malware) are the one signal that does **not** fit the Coroot model, because their
only first-class dashboard — the **Headlamp Kubescape plugin's "Runtime
Detection → Alerts" tab** — reads exclusively from a Prometheus **Alertmanager**
(`GET /api/v2/alerts`, filtered on `alertname="KubescapeRuleViolated"`). It
cannot read Kubescape's storage CRs and cannot query Coroot's Prometheus (a
metrics store, not an Alertmanager). So a **single, minimal Alertmanager** is
reintroduced *scoped to Kubescape* — not a re-adoption of the Prometheus stack.
It lives in the `kubescape` namespace, prod-only
(`providers/hetzner/infrastructure/controllers/alertmanager/`), ~10m CPU / 32Mi
RAM, ephemeral (no PVC).

The node-agent fans each alert out to **all three destinations** (wired in
`providers/hetzner/infrastructure/controllers/kubescape/patches/`):

| Destination | Path |
| --- | --- |
| **Headlamp plugin** | `nodeAgent.config.alertManagerExporterUrls` → the Alertmanager, which the plugin queries. |
| **Slack** | the Alertmanager's `slack_configs` receiver → the shared `${alertmanager_webhook_url}` incoming-webhook (same channel as Coroot/Flux). |
| **Coroot** | `nodeAgent.config.stdoutExporter` (on by default) → Coroot's eBPF log capture surfaces the alert in the **Logs** view (Coroot CE has no inbound alert receiver). |

**One manual step (Headlamp).** The plugin's Alertmanager address is a
**per-user, per-browser** setting (stored in `localStorage`; there is no
declarative/Helm way to seed it — [headlamp#3979](https://github.com/kubernetes-sigs/headlamp/issues/3979)).
Each operator sets it **once** in Headlamp → *Settings → Plugins → Kubescape*,
in the `namespace/service:port` form the plugin validates:

```text
kubescape/alertmanager:9093
```

The plugin reaches it through the Kubernetes API server's Service proxy, so the
logged-in user needs `get`/`create` on `services/proxy` in the `kubescape`
namespace (satisfied by the admin binding). Until it is set, the tab shows
"Alertmanager URL is not configured" — the data source now exists, only the
per-user pointer is manual.

## Dead-man's-switch (off-cluster heartbeat)

In-cluster alerting cannot tell you the cluster is down — it's down too. A tiny
`cluster-heartbeat` CronJob (`observability` namespace, every 5 minutes) covers
that: it pings an **external** monitor unconditionally. A successful ping
proves the cluster as a whole is alive — a node, the scheduler, kubelet, the
CNI, DNS and egress all worked. If the cluster dies, the pings stop and the
monitor notifies Slack out-of-band.

The ping is deliberately not gated on any component: component health (Coroot,
Prometheus, …) is alerted on in-cluster by Coroot's notification integrations
and checked by connecting to the cluster. This switch signals exactly one
thing — "the cluster as a whole stopped".

Recommended monitor: [healthchecks.io](https://healthchecks.io) (free,
open-source, native Slack integration). Create a check with a ~5 min period and
~10 min grace, connect it to Slack, and put its ping URL in
`alertmanager_heartbeat_url` (below — the variable name is retained from the old
stack for compatibility). Flux substitutes the URL into the
`cluster-heartbeat-url` Secret, which the Job mounts read-only, so it is not
readable from the CronJob spec. Unset, it defaults to an invalid URL, so
local/CI simply never heartbeat — harmless (`|| true` keeps the Job from
flapping).

## Off-cluster backup

There is no remote-write or SaaS mirror. The persistent Coroot, Prometheus and
ClickHouse volumes live in the `coroot` namespace, which Velero's `daily-full`
schedule backs up to R2 every day (`includedNamespaces: ["*"]`, Kopia
fs-backup). Restore is the standard Velero flow in [runbook.md](./runbook.md);
backups are filesystem-level and crash-consistent, fine for a 24 h RPO.

## Per-environment setup

**No new setup** — both values are inherited from the previous stack, already
present in the per-cluster `secret.enc.yaml` (under
`bootstrap/`) and injected by Flux `substituteFrom`:

- `alertmanager_webhook_url` — Slack incoming-webhook, reused by Coroot's
  webhook integration (prod-only).
- `alertmanager_heartbeat_url` — external heartbeat monitor, reused by the
  `cluster-heartbeat` CronJob via the `cluster-heartbeat-url` Secret it mounts.

| Env   | `alertmanager_webhook_url`        | `alertmanager_heartbeat_url`     |
| ----- | --------------------------------- | -------------------------------- |
| local | placeholder (Slack stays quiet)   | unset → invalid (no heartbeat)   |
| prod  | Slack `#platform-alerts` webhook  | healthchecks.io ping URL         |

To change either, `sops --set` it in the prod secret, e.g.:

```bash
sops --set '["stringData"]["alertmanager_heartbeat_url"] "https://hc-ping.com/<uuid>"' \
  k8s/clusters/prod/bootstrap/secret.enc.yaml
```

Recommended heartbeat monitor: [healthchecks.io](https://healthchecks.io) — a
~5 min period / ~10 min grace check with its Slack integration connected.

## On-call: inspect

- **Everything** — Coroot UI at `https://coroot.${domain}`: the service map,
  per-app SLOs, metrics, logs (full-text over ClickHouse), traces, continuous
  profiling, and the active inspections/incidents.
- **Cost** — OpenCost at `https://opencost.${domain}`.

Both are behind GitHub SSO (oauth2-proxy, `devantler` only).

## Resource footprint (prod, approximate)

| Component   | Notes                                                        |
| ----------- | ------------------------------------------------------------ |
| Coroot app  | small web app; 2 Gi state PVC                                |
| Prometheus  | bundled TSDB, 14 d retention, 20 Gi PVC                      |
| ClickHouse  | logs/traces/profiles store, 15 Gi PVC (+ 2 Gi keeper)        |
| node-agent  | eBPF DaemonSet (×node), `platform-critical`                  |
| cluster-agent / operator | lightweight controllers                         |

ClickHouse is a new stateful component versus the old stack; on the
memory-constrained Hetzner cluster keep retention modest (`logsTTL` /
`tracesTTL` / `profilesTTL` = 7 d in prod, 3 d in base) and watch node memory
after rollout. VPA right-sizes requests at runtime.

## Related

- [DR runbook](./runbook.md) — what to do when an alert fires, and restore
- [Velero + CNPG](./velero-cnpg.md) — the systems whose health is checked
- [restore-drill.md](./restore-drill.md) — CI validation of backups
- [HA primitives](../../README.md) — cluster environments and topology
