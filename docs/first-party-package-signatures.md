# First-party package signature checks

The registry-reading CI job checks proposed first-party Crossplane packages on
same-repository pull requests and merge-group revisions. It renders the five
production Flux layers and reads `spec.package` from Crossplane `Provider`,
`Function`, and `Configuration` resources. OCI source artifacts and third-party
packages are outside this inventory.

Run the same check locally with Go, kubectl, yq v4, jq, cosign, and Kyverno 1.18.2:

```sh
bash scripts/check-first-party-package-signatures.sh
```

The script only renders files and reads the registry. It does not contact the
cluster. For private packages, authenticate to GHCR through a Docker config that
the credential can read; CI uses its package-read token and removes its temporary
Docker config after the check. Kyverno 1.18.2's CLI has no Kubernetes Secret
lister, so an ephemeral policy copy replaces its cluster pull-secret references
with the default Docker credential provider. Image selection, signing identities,
and validation expressions are preserved. This does not prove the live cluster's
pull Secret has equivalent registry access.

Each reference must pass both checks:

- The existing signature inventory applies the first matching Talos pull rule.
- Kyverno evaluates `verify-app-images` against a synthetic Pod carrying the
  package image, as a provider controller would. This exercises the policy's
  actual image-to-attestor routing and identity, rather than a copied regex.

Both verifiers must then reject a deliberately impossible identity, and both
positive checks must still pass afterward. Empty inventories, unmatched packages,
skipped policy evaluations, malformed reports, and unreadable registries fail the
gate. An unreadable registry is `UNKNOWN`, not evidence that an image is unsigned.

For a focused reproduction, pass a rendered manifest stream and optional verifier
files:

```sh
bash scripts/check-first-party-package-signatures.sh \
  --rendered /tmp/proposed-packages.yaml \
  --rules /tmp/proposed-talos-rules.yaml \
  --policy /tmp/proposed-image-policy.yaml
```

This is the package slice of #3425. It does not enumerate Helm-rendered containers,
operator-generated child images, or tenant images arriving through remote OCI
artifacts. Those still require the broader repository/fleet inventory. Checking a
tag proves the registry's answer at check time; it does not make a mutable tag
immutable or prove that the live cluster enforces the configured rules.
