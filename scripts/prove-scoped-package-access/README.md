# Repository-scoped GHCR access experiment

`Prove Scoped Package Access` is the manual CI experiment for #3274. It uses the
existing App credentials to mint a token with `packages: read` for `wedding-app`
only. The existing encrypted Flux pull credential supplies the independent
baseline. No cluster access, package publication or authentication cutover occurs.

The probe verifies the candidate's complete repository scope and both packages'
private visibility and exact repository association through GitHub's API. It
resolves the two current `latest` manifests to immutable digests, establishes
anonymous denial, and fully downloads both images with the baseline credential.
The candidate must fully download its own image and be denied the other image's
manifest. Positive controls run again afterward.

Full downloads use a fresh credential directory and destination for every
[`crane pull`](https://github.com/google/go-containerregistry/blob/v0.21.9/cmd/crane/doc/crane_pull.md),
without a daemon or shared layer cache. Images are never executed. Credentials,
raw network responses, image manifests and image contents are excluded from the
result; temporary credentials and downloads are deleted after each pull.

Run the existing workflow against `main`:

```sh
gh workflow run prove-scoped-package-access.yaml --repo devantler-tech/platform --ref main
```

The process and workflow preserve three outcomes:

| Exit | Result | Meaning |
| --- | --- | --- |
| 0 | PASS | Own full pull and cross-package denial passed with every control. |
| 1 | FAIL | A valid scoped token could not read its own package, or could read the other package. |
| 2 | UNKNOWN | Metadata, privacy, token scope, full download or availability could not be established. |

A missing image, throttling, server error, redirect or malformed response never
counts as a successful restriction. A failed or unknown run does not authorize
registry-authentication changes. The spike's result must be recorded before its
dependent implementation advances.

The hermetic regression suite uses local HTTP fixtures and synthetic credentials:

```sh
go test ./scripts/prove-scoped-package-access
```
