# Welcome to Devantler's Homelab 🚀

This Homelab is a Flux2-based GitOps repository to manage my personal Kubernetes clusters. It focuses on providing a secure and reliable infrastructure for my projects, with a focus on ease of use and automation of common tasks, such as safe and secure CI/CD pipelines.

## Overview

### Clusters

- Local - A local cluster for development purposes.

### Apps

- [GitOps Dashboard](https://github.com/weaveworks/weave-gitops/tree/main/charts/gitops-server): GitOps Dashboard: The Weave GitOps Dashboard is a web-based UI for managing your Weave GitOps deployments.
  
### Infrastructure

- [Cert-Manager](https://cert-manager.io/docs/): Cert-Manager is a Kubernetes add-on to automate the management and issuance of TLS certificates from various issuing sources.
- [Traefik](https://doc.traefik.io/traefik/): Traefik is an open-source Edge Router that makes publishing your services a fun and easy experience.

## Getting Started

### Prerequisites

- [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [Flux2 CLI](https://fluxcd.io/docs/installation/#install-the-flux-cli)
- [k3d](https://k3d.io/#installation) for dev/CI
- Any cluster provider for **sandbox**, **staging**, and **production**

### Local Setup

To get started, you need to create a separate branch to work on your increments. Doing so allows you to bootstrap the local cluster, such that Flux2 can sync any changes you push to the branch.

Run the `scripts/bootstrap-local.sh` script to:

1. Create a local cluster with k3d.
2. Bootstrap Flux2 to sync the local cluster with the branch you are working on.

To access the services in the cluster you need to update your `/etc/hosts` file with the following entries:

```bash
# Please keep this list updated with new services you introduce to the cluster.
127.0.0.1 traefik.local
127.0.0.1 gitops.local
```

> [!IMPORTANT]
> You might need to clear your DNS cache for the changes to take effect.
>
> - macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
> - Windows: `ipconfig /flushdns`
> - Linux: `sudo systemd-resolve --flush-caches`

That is it! You should now be able to work on the cluster, and Flux2 will sync any changes you push to the branch, so you can test your changes locally.

## Valuable Resources

- [fluxcd](https://fluxcd.io/flux/): a tool for keeping Kubernetes clusters in sync with sources of configuration (like Git repositories), and automating updates to the configuration when there is new code to deploy.
  - [flagger](https://fluxcd.io/flagger/): a progressive delivery tool that automates the release process for applications running on Kubernetes.
  - [post-build-variable-substitution](https://fluxcd.io/flux/components/kustomize/kustomization/#post-build-variable-substitution): It is not possible to read variables from the environment with FluxCD, but this is an excellent alternative to feed in dynamic values.
  - [sops](https://fluxcd.io/flux/guides/mozilla-sops/): sops is similar to sealed-secrets, but is a more general tool for encrypting and decrypting values in YAML files. It can be used with a Flux plugin to decrypt secrets in-flight while enabling a more flexible workflow for editing the secrets.
[terraform](https://developer.hashicorp.com/terraform?product_intent=terraform): infrastructure as code tool that lets you build, change, and version infrastructure safely and efficiently.
