# Actual Budget

[Actual Budget](https://actualbudget.org/) is a local-first personal finance
app with an optional self-hosted sync server.

- [Documentation](https://actualbudget.org/docs/)
- [Helm Chart](https://github.com/community-charts/helm-charts/tree/main/charts/actualbudget)

## User namespaces

Production has a default-off [stateful user-namespace pilot](../../../providers/hetzner/apps/actual-budget/components/user-namespaces/README.md).
Its component pairs the pod setting with the existing admission policy and
preserves the database volume, both containers' identities and mounts, and the
single-writer deployment strategy. The guide covers offline validation,
activation evidence, and rollback. Local app opt-in keeps the shared defaults.

## Bank sync (Enable Banking)

Bank-sync credentials (Application ID + PEM secret key) live only in the
sync-server's internal `secrets` SQLite table — Actual exposes no env/config
hook for them. They are stored in OpenBao at `apps/actual-budget/enablebanking`
and reconciled into the table by the `enablebanking-seed` sidecar (see
[`config-map.yaml`](config-map.yaml)). The sync-server reaches the Enable
Banking API (`api.enablebanking.com`) egress-allowed by
[`cilium-network-policy.yaml`](cilium-network-policy.yaml).

## End-to-end encryption (manual, by design)

Actual's end-to-end encryption **cannot be enabled declaratively**, and by
design it should not be: it is a **client-side, password-derived** feature. When
you turn it on, the client derives an encryption key from a password *locally*,
re-encrypts the budget, and uploads only ciphertext plus non-secret key metadata
(`keyId`, `keySalt`, an encrypted `testContent`). The **server never sees the
password or key** — that is precisely what makes it end-to-end. There is no
`ACTUAL_*` env var and no server endpoint to turn it on; the sync-server's
`/user-create-key` only *stores* metadata the client computed.

So enabling it is a **one-time manual step**, and what we manage declaratively is
the **password of record** (in OpenBao) so it survives DR:

1. Store the password in OpenBao at `apps/actual-budget/encryption`
   (property `password`). The path is seeded create-only with a placeholder by
   [`push-secret-seed-actual-budget-encryption.yaml`](../../infrastructure/vault-seed/push-secret-seed-actual-budget-encryption.yaml);
   type the real password in via the OpenBao UI/CLI. Nothing in-cluster reads it
   back — it exists only as the durable record of the password.
2. In the Actual web UI: open the budget → **Settings → Show advanced settings →
   Enable encryption**, and enter that same password.
3. Every device that opens the file will now prompt for the password once.

> [!CAUTION]
> A lost E2EE password means the budget data is **permanently unrecoverable** —
> the server cannot help, because it never had the key. Treat the OpenBao
> `apps/actual-budget/encryption` entry as a root of trust; custody guidance is
> in [`docs/dr/crypto-custody.md`](../../../../docs/dr/crypto-custody.md).
