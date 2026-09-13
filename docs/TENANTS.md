# Onboarding a GitOps tenant

A **tenant** is an application that runs on the platform but lives in its **own
repository**. The tenant repo builds a container image and publishes its
Kubernetes manifests (`deploy/`) as a **signed OCI artifact** to GHCR; the
platform pulls that artifact with a Flux `OCIRepository` + `Kustomization` and
runs it in a dedicated, locked-down namespace.

> **KRO `Tenant` CR fast path.** The platform-registration half below (step 2)
> is the original hand-copied skeleton. A local-first pilot now generates that
> same skeleton from a small typed `Tenant` custom resource via
> [kro](https://kro.run) — see [`tenant-abstraction.md`](./tenant-abstraction.md)
> (the ADR, including the opt-in `resourceQuota`/`limitRange` guardrails) and
> the live examples under
> [`k8s/providers/docker/apps/`](../k8s/providers/docker/apps). This file still
> documents the pre-KRO flow in full; reconciling the two is an open follow-up.

There are two halves to onboarding, in two repos:

1. **The tenant repo** — created from the
   [`platform-tenant-template`](https://github.com/devantler-tech/platform-tenant-template),
   which ships the shared, framework-agnostic CI/CD plumbing and keeps it current
   via [template-sync](https://github.com/AndreasAugustin/actions-template-sync).
2. **The platform registration** — a small directory in *this* repo under
   `k8s/bases/apps/<tenant>/` that grants the tenant a namespace, identity, RBAC,
   and the Flux resources that pull its artifact. The tenant's own
   `CiliumNetworkPolicy` allow-lists and its namespaced `SecretStore` live in the
   **tenant repo's `deploy/`** — the platform provides only the default-deny
   network floor and the Vault role those resources authenticate against, and
   grants the tenant `edit` aggregates (`cilium-tenant-edit`,
   `external-secrets-tenant-edit`) so its ServiceAccount may manage them.

Use an existing tenant —
[`k8s/bases/apps/ascoachingogvaner/`](../k8s/bases/apps/ascoachingogvaner) — as
the reference while following the steps below.

## 1. Create the tenant repository

Create the repo from the template with **"Use this template"** (GitHub UI), or:

```sh
gh repo create devantler-tech/<tenant> \
  --template devantler-tech/platform-tenant-template --private
```

The template gives you the shared plumbing it keeps in sync (`cd.yaml`,
`release.yaml`, `template-sync.yaml`, `CLAUDE.md`, `zizmor.yml`) plus scaffolding
you then customise and own (`AGENTS.md`, the `maintain` skill, `ci.yaml`,
`Dockerfile`, `deploy/`, `.releaserc`, `.gitignore`, `.github/dependabot.yml`).
See the template's `README.md` for the exact owned-vs-synced split.

## 2. Fill in your stack

- **Application code + `Dockerfile`** — your app, building to a container that
  listens on the port your `deploy/` manifests expose.
- **`deploy/`** — your Kubernetes manifests (`kustomization.yaml`,
  `deployment.yaml`, `service.yaml`, `httproute.yaml`, an optional
  CloudNativePG `cluster.yaml`, and — when the app needs secrets — a namespaced
  `SecretStore` + `ExternalSecret` sourcing them from OpenBao; see §3).
  - The `HTTPRoute` attaches to the shared platform Gateway:
    `parentRefs: [{ name: platform, namespace: kube-system, sectionName: https }]`.
  - **The Deployment's container `name` MUST equal the repository name.** `cd.yaml`
    publishes via the platform's signed-publish path and pins the freshly-built
    image digest into the container named after the repo (see §4).
- **`ci.yaml`** — replace the example job with your stack's lint/test/build, kept
  behind the `aggregate-job-checks` required-checks gate.
- **`.templatesyncignore`** — list every file in the repo that *you* own so
  template-sync never overwrites it (your `AGENTS.md`,
  `.claude/skills/maintain/SKILL.md`, `ci.yaml`, `Dockerfile`, `deploy/`,
  `.releaserc`, `.gitignore`, `.github/dependabot.yml`, `README.md`, `LICENSE`,
  and the `.templatesyncignore` itself). Everything the template ships that is
  not ignored is kept in sync.

## 3. Secrets

Tenant secrets come from **OpenBao** via **External Secrets** — never SOPS. No
tenant ships a SOPS-encrypted Secret.

### App secrets (DB creds, API keys, … — only for tenants that need them)

A tenant gets a store + Vault role **only if it needs app secrets** — a purely
static site with no integrations gets none. The **tenant owns its app secrets
end-to-end**; the platform only provisions the store + isolation and never seeds
a tenant's app values. How a value gets *into* the tenant's path is the tenant's
business: **paste it straight into OpenBao** (the usual flow for
externally-issued credentials — e.g. ascoachingogvaner's simply.com DNS
credentials at `apps/ascoachingogvaner/simply`), or seed it from a committed
generator/`PushSecret`. The platform's contract is just two rules: nothing
sensitive sits in git in plaintext (whatever is committed is secure at rest),
and workloads consume the values **from OpenBao via `ExternalSecret`s**.

- **Tenant (`deploy/`)** — own your secret end-to-end. Your `edit` RoleBinding
  aggregates `external-secrets-tenant-edit`, so you may create `Password`
  generators, `PushSecret`s and `ExternalSecret`s in your namespace. They all
  reference the platform-provided **namespaced** store (`secretStoreRef:
  { name: openbao, kind: SecretStore }`) — never the shared `ClusterSecretStore`
  (the `restrict-tenant-secret-stores` Kyverno policy blocks that). The store
  authenticates via your tenant Vault role, scoped to `apps/<tenant>/*` (read **+
  write**), so you both seed and read your own path. The standard pattern for a
  generated value (an admin code, a token): a `Password` generator → a `PushSecret`
  (`selector.generatorRef`, `refreshInterval: "0"`) that writes it once to
  `apps/<tenant>/*` → an `ExternalSecret` that reads it back into the Secret your
  app consumes. See `wedding-app`'s `deploy/admin-code-*.yaml`.
- **Platform (one-time per such tenant)** — in
  [`vault-config/job.yaml`](../k8s/bases/infrastructure/vault-config/job.yaml) add
  an `app-<tenant>` policy scoped to `secret/{data,metadata}/apps/<tenant>/*` (read
  **+ write**, so the tenant can seed) and a dedicated `auth/kubernetes/role/<tenant>`
  bound to the tenant SA (mirror `app-wedding-app` + the `wedding-app` role). The
  tenant ships its own namespaced `secretstore.yaml` (`kind: SecretStore`, named
  `openbao`) in its `deploy/` — its `edit` RoleBinding aggregates
  `external-secrets-tenant-edit`, so it owns the store too. The store can never
  reach infra or another tenant's path, and the platform does **not** seed tenant
  app values.

### The GHCR image-pull secret (`ghcr-auth`)

A **platform-managed** credential, not a tenant secret. Every registration dir
ships a `external-secret-ghcr-auth.yaml` that sources the shared org pull
credential from OpenBao (`infrastructure/ghcr/auth`) via the cluster-scoped `openbao`
**ClusterSecretStore** and materialises the `ghcr-auth` dockerconfigjson the
`OCIRepository` and ServiceAccount consume. It is reconciled by flux-system (not
your tenant SA) — which is why it may use the ClusterSecretStore where your own
resources may not (the Kyverno policy carves out flux-system-applied resources).
The value lives SOPS-encrypted as `ghcr_dockerconfigjson` in the shared
`secret.enc.yaml` (the same org token both clusters use); the
`seed-ghcr` PushSecret pushes it to `infrastructure/ghcr/auth` via the `openbao`
ClusterSecretStore.

- The release and template-sync workflows mint a **GitHub App token** from the
  org-level `APP_CLIENT_ID` variable and `APP_PRIVATE_KEY` secret — already available to
  every repo in the org, so no per-repo setup is needed.

## 4. How publishing & trust fit together

On every `v*` tag, the tenant's `cd.yaml` calls the
[`publish-app.yaml`](https://github.com/devantler-tech/actions/blob/main/.github/workflows/publish-app.yaml)
reusable workflow, which builds and pushes the image, pins its digest into
`deploy/deployment.yaml`, pushes the manifests as an OCI artifact, and
**cosign-signs** both (keyless, via GitHub OIDC). The platform's `OCIRepository`
(§5) **verifies** that signature against the `publish-app.yaml` identity.

That verification establishes the GitHub OIDC issuer and that the signer ran the
`publish-app.yaml` workflow path at a 40-hex commit — the **commit shape**, not a reviewed
revision. The verifiers in use (Flux, the `verify-app-images` admission policy, and the Talos
pull rule) match only the certificate's issuer and subject, so a commit reference under that
path does not prove the commit belongs to the actions repository's reviewed history.
Application tenants may advance that workflow at any 40-hex commit without a platform-side
revision update. Package write access, namespace, RBAC, network policy, and admission policy
bound what a release can do; the remaining risk is accepted in
[#3746](https://github.com/devantler-tech/platform/issues/3746). A tenant that needs authority
outside those bounds requires a reviewed platform change; an ordinary release inside them does
not.

> Tags come from `release.yaml` → semantic-release: merge Conventional-Commit
> PRs to `main` and a `vX.Y.Z` tag (and thus a publish) follows automatically.

## 5. Register the tenant on the platform

> **Piloting: the `Tenant` archetype (#1932).** The manual multi-file copy below
> is being replaced by one typed declaration — a KRO `Tenant` CR expanded by the
> [tenant ResourceGraphDefinition](../k8s/bases/infrastructure/resource-graph-definitions/tenant/resource-graph-definition.yaml)
> into this whole skeleton (namespace, SA + RoleBinding, ghcr-auth
> ExternalSecret, default-deny NetworkPolicy, cosign-verified OCIRepository,
> impersonating Kustomization, optional external-dns RBAC / SOPS decryption).
> It is piloting **local-first** as an opt-in on the Docker provider
> (`k8s/providers/docker/apps/tenant-ascoachingogvaner.yaml`); prod tenants keep
> the manual skeleton until the pilot proves out. Until then, follow the steps
> below for a new tenant.

Add `k8s/bases/apps/<tenant>/` — copy `wedding-app/` (a tenant with app secrets)
or `ascoachingogvaner/` (a static tenant that also runs a **tenant-owned
external-dns** for its custom domain, with the extra external-dns RBAC
grants below) and rename — with:

| File | Purpose |
| --- | --- |
| `kustomization.yaml` | Kustomize entrypoint listing the resources in this directory |
| `namespace.yaml` | Namespace, `pod-security.kubernetes.io/enforce: restricted` |
| `service-account.yaml` | SA with `automountServiceAccountToken: false` + `imagePullSecrets: [ghcr-auth]` |
| `role-binding.yaml` | Binds the SA to the `edit` ClusterRole in the namespace |
| `external-secret-ghcr-auth.yaml` | OpenBao-backed `ExternalSecret` (shared `openbao` ClusterSecretStore, key `infrastructure/ghcr/auth`) producing the `ghcr-auth` pull secret (just `external-secret.yaml` when it is the tenant's only one) |
| `role-binding-external-dns*.yaml` + `cluster-role-binding.yaml` | *Only if the tenant runs its own external-dns for a tenant-owned domain* — bind the tenant's `external-dns` SA to the `tenant-external-dns(-global)` ClusterRoles (HTTPRoutes in its namespace, the shared Gateway in kube-system, namespaces) — mirror `ascoachingogvaner/` |
| `oci-repository.yaml` + `flux-kustomization.yaml` | `OCIRepository` (semver `>=1.0.0`, cosign `verify`) + Flux `Kustomization` (prune, `serviceAccountName: <tenant>`) |

> **Tenant-owned (in the tenant repo's `deploy/`, not here):** the
> `CiliumNetworkPolicy` allow-lists (`networkpolicy.yaml`, and
> `external-dns-networkpolicy.yaml` for an external-dns tenant) and — for a tenant
> with app secrets — the namespaced `secretstore.yaml`. The tenant's `edit`
> RoleBinding aggregates `cilium-tenant-edit` and `external-secrets-tenant-edit`,
> so its ServiceAccount applies them from its own artifact; the platform keeps
> only the default-deny floor, the external-dns cross-namespace
> grants, and the Vault role/policy.

Tenant `CiliumNetworkPolicy` Service references must explicitly set the Service
namespace to the policy's own namespace. This applies to both `k8sService` and
`k8sServiceSelector`: Cilium treats an omitted or empty namespace as a match across
namespaces, so admission refuses those forms as well as foreign namespaces. For
example, a policy in `my-tenant` can allow its own database Service with:

```yaml
egress:
  - toServices:
      - k8sService:
          serviceName: db
          namespace: my-tenant
```

Service selectors likewise need `namespace: my-tenant` beside `selector`, plus a
specific label or an `In` expression. Platform-generated DNS and other policies
applied by the platform controllers retain their existing identity exemptions.

In `oci-repository.yaml` / `flux-kustomization.yaml`, update the `name`/`namespace`/`url`
(`oci://ghcr.io/devantler-tech/<tenant>/manifests`) and keep the `verify` block
pointing at `publish-app.yaml`. No Flux `spec.decryption` is needed — tenant
secrets are delivered by External Secrets from OpenBao (§3), not SOPS-encrypted
inside the artifact.

Tenant network rules must omit `fromNodes`, `toNodes`, `fromGroups`, and `toGroups`,
including empty or null fields. Node selectors reach the host network, while
provider groups resolve infrastructure addresses outside the namespace. Use
ordinary pod selectors or the supported explicit destinations instead. A tenant
use case for node or provider selection needs a deliberate platform boundary
change with validation before enabling it; turning on a Cilium integration alone
does not grant that capability. The platform controllers retain their existing
identity exemptions.

Finally, add the directory to
[`k8s/bases/apps/kustomization.yaml`](../k8s/bases/apps/kustomization.yaml):

```yaml
resources:
  - <tenant>/
```

Open the change as a PR; once merged, Flux reconciles the new tenant.

## 6. Provider overlays — what may be patched platform-side

A tenant's manifests ship from its own OCI artifact, but the **prod (hetzner) overlay** can
layer a `Kustomization` `spec.patches` onto the tenant's platform-side Flux `Kustomization`
at `k8s/providers/hetzner/apps/<tenant>/patches/flux-kustomization-<purpose>.yaml`, which Flux then
applies to the tenant's resources *after* pulling the artifact. This is a **narrow escape
hatch**, not a place for tenant config.

A platform-side patch is legitimate **only for what the environment-agnostic artifact cannot
carry itself**:

- **Environment adaptations** — values that must differ per provider/cluster and so cannot be
  hardcoded in the single artifact that deploys to both local/docker and prod/hetzner. The
  only example in the repo: `wedding-app`'s CNPG `Cluster` `storage.storageClass: longhorn`
  (local/docker has no longhorn, so the artifact stays class-agnostic and the overlay supplies
  the class).
- **Operational-safety annotations** — platform-enforced guards such as
  `kustomize.toolkit.fluxcd.io/{force,prune}: disabled` on a stateful resource to prevent a
  Flux delete+recreate data-loss event.

**Everything a tenant can express in its own `deploy/` is tenant-owned and must NOT be patched
here** — **hostnames**, **`gethomepage.dev/*` dashboard annotations**, routes, and app config:

- List all of a tenant's hostnames (local + prod + any custom domains) directly in its
  `deploy/httproute.yaml`, and add every approved hostname to the platform-side
  Kyverno allow-list in
  [`restrict-tenant-route-hostnames.yaml`](../k8s/bases/infrastructure/cluster-policies/best-practices/restrict-tenant-route-hostnames.yaml).
  The shared platform Gateway intentionally accepts routes from all namespaces, so the
  admission policy is the boundary that prevents a tenant artifact from claiming another
  platform hostname.
- **A tenant with no rule of its own is denied by default.** Adding the allow-list entry is
  therefore part of onboarding, not an optional hardening step: until a tenant namespace has
  a rule naming its approved hostnames, its HTTPRoutes are refused at admission with a
  message saying exactly that. The alternative — enumerating only some tenants — is
  fail-open, and a tenant once ran that way, able to claim any hostname because no rule
  matched its namespace.
- **`HTTPRoute` is the only route kind a tenant can use.** The hostname allow-list above
  matches `HTTPRoute`, so every other Gateway API route kind is closed off rather than left
  to reach the shared listener unchecked: the tenant role grants only `httproutes` and
  `referencegrants`, and each Gateway listener pins `allowedRoutes.kinds` to `HTTPRoute`
  (an HTTPS listener would otherwise accept `GRPCRoute` too). A tenant needing another kind
  is a platform change, not a tenant one — extend the hostname policy to cover that kind
  and relax both layers together. CI runs the rendered two-layer route-kind boundary test
  alongside the canonical Kyverno policy fixtures, so neither half can widen silently.
- The platform's `homepage` app discovers `gethomepage.dev/*` annotations on the tenant's
  HTTPRoute cluster-wide, so the tenant authors them in its own artifact — they are tenant
  self-presentation, not platform config.

Use an existing tenant's `deploy/httproute.yaml` (e.g. `ascoachingogvaner`, which owns its
hostnames *and* its dashboard annotations) as the reference.

> **Validation gotcha:** these patch files are schema-validated **standalone** by
> `ksail workload validate`. If removing a patch leaves the file empty, **delete the file and
> its `- path:` entry** in
> [`k8s/providers/hetzner/apps/kustomization.yaml`](../k8s/providers/hetzner/apps/kustomization.yaml)
> — a partial `Kustomization` (no `spec.interval`) fails validation on its own (the same reason
> the disabled `fleetdm` patch was deleted, not just unreferenced).

## 7. Staying current

template-sync opens a PR in the tenant whenever the template's shared plumbing
changes (a bumped action pin, a workflow fix, an updated convention). Review and
merge it like any dependency update — your owned files are untouched.
