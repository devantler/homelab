# Welcome to Devantler's Homelab 🚀

This Homelab is a Flux2-based GitOps repository to manage my personal Kubernetes clusters. It focuses on providing a secure and reliable infrastructure for my projects, with a focus on ease of use and automation of common tasks, such as safe and secure CI/CD pipelines.

- [Overview](#overview)
  - [Clusters](#clusters)
  - [Infrastructure](#infrastructure)
  - [CRDs](#crds)
  - [Apps](#apps)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
- [Managing secrets](#managing-secrets)
  - [Setting up SOPS](#setting-up-sops)
  - [SOPS VSCode Integration](#sops-vscode-integration)
- [Cluster Setups](#cluster-setups)
  - [Local Setup](#local-setup)
  - [Production Setup](#production-setup)
- [Resources](#resources)

## Overview

```txt
.
├─ ...
├─ k8s
│  ├─ apps
│  │  ├─ base
│  │  └─ overlays
│  ├─ clusters
│  │  └─ ...
│  ├── crds
│  │  ├─ base
│  │  └─ overlays
│  └─ infrastructure
│  │  ├─ base
│  │  └─ overlays
└─ ...
```

### Clusters

A collection of clusters, each with their own flux manifests, and cluster configuration.

### Infrastructure

- [Cert-Manager](https://cert-manager.io/docs/): Cert-Manager is a Kubernetes add-on to automate the management and issuance of TLS certificates from various issuing sources.
- [Traefik](https://doc.traefik.io/traefik/): Traefik is an open-source Edge Router that makes publishing your services a fun and easy experience.

### CRDs

- Certificates
- Cluster Issuers
- Middlewares
- Ingress Routes

### Apps

- none

## Getting Started

These instructions will guide you through the process of installing the necessary tools, and setting up your local environment to work on the clusters.

### Prerequisites

For running CI locally:

- [yq](https://github.com/mikefarah/yq) for validating YAML files.
- [kubeconform](https://github.com/yannh/kubeconform) for validating Kubernetes manifests.

For administrating clusters:

- [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [Helm 3](https://helm.sh/docs/intro/install/)

For bootstrapping clusters:

- [Flux CLI](https://fluxcd.io/docs/installation/#install-the-flux-cli)
- [k3d](https://k3d.io/#installation) for creating local clusters.

For encrypting/decrypting secrets:

- [gnupg](https://gnupg.org/download/index.html): GnuPG is a complete and free implementation of the OpenPGP standard as defined by RFC4880 (also known as PGP).
- [sops](https://github.com/getsops/sops): SOPS is an editor of encrypted files that supports YAML, JSON, ENV, INI, and BINARY formats and encrypts with AWS KMS, GCP KMS, Azure Key Vault, and PGP.
- Access to the private/public PGP key for the environment you are working on.

## Managing secrets

> [!WARNING]
> Never commit unencrypted secrets to the repo. This will compromise the security of the clusters, and require a complicated process to both rotate the public and private keys, as well as removing the leaked secrets from the Git history.

This section describes how to manage secrets in the repo, and how to encrypt/decrypt secrets locally.

### Setting up SOPS

> [!NOTE]
> If no GPG key has been added to a cluster, follow [this guide](https://fluxcd.io/flux/guides/mozilla-sops/) to create a new GPG key and add it to the cluster.

1. Import the full key: `gpg --import <path-to-key>`

After doing so you will be able to encrypt and decrypt secrets locally.

```bash
# Encrypting secrets
sops --encrypt --in-place <path-to-secret>

# Decrypting secrets
sops --decrypt --in-place <path-to-secret>
```

As a best practice, secrets should be named `<secret-name>.sops.yaml`, to make it clear that the file is encrypted, and to avoid accidentally encrypting secrets that should not be encrypted.

### SOPS VSCode Integration

If you use VSCode, there is an extension called [SOPS easy edit]([ShipitSmarter.sops-edit](https://marketplace.visualstudio.com/items?itemName=ShipitSmarter.sops-edit)), which enables a seamless way to edit secrets encrypted by SOPS. It does so by decrypting the secret when you open it, and encrypting it when you save it. This means you can edit the secret as if it were a normal YAML file, and the extension will handle the encryption/decryption for you. This of course requires you to have access to the private and public keys for the environment you are working on.

> [!NOTE]
> If secrets must be encrypted/decrypted by SOPS easy edit it is important that the follow the naming practice: `<secret-name>.sops.yaml`. This rule is defined in the `.sops.yaml` config file, and is necessary for the extension to work.

## Cluster Setups

- **Local** - A local cluster for development purposes.
  - `<service>.local`
- **Production** - A production environment for hosting services.
  - `<service>.devantler.com`

### Local Setup

> [!NOTE]
> The repo includes a few scripts for bootstrapping, destroying and validating the manifest files. All scripts have been made runnable from VSCode tasks or run configurations. So if you are using VSCode, you can find and run all scripts from the Run and Debug tab, or by searching for `Tasks: Run Task` in the command palette.

To get started, you need to create a separate branch to work on your increments. Doing so allows you to bootstrap the local cluster, such that Flux can sync any changes you push to the branch:

```bash
./scripts/bootstrap-local.sh
```

The script will do the following:

1. Create a local cluster with k3d.
2. Bootstrap Flux2 to sync the local cluster with the branch you are working on.

To access the services in the cluster you need to update your `/etc/hosts` file with the following entries:

```bash
# Please keep this list updated with new services you introduce to the cluster.
127.0.0.1 traefik.local
```

> [!IMPORTANT]
> You might need to clear your DNS cache for the changes to take effect.
>
> - macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
> - Windows: `ipconfig /flushdns`
> - Linux: `sudo systemd-resolve --flush-caches`

That is it! You should now be able to work on the cluster, and Flux2 will sync any changes you push to the branch, so you can test your changes locally.

### Production Setup

The production cluster is fully managed by Flux2, and should not be modified directly through `kubectl`, `helm`, or similar tools.

- The **production** cluster is updated whenever changes are merged to the main branch.

In case the cluster needs to be recreated or upgraded, you can run the `scripts/bootstrap-production.sh` script.

## Resources

- [flux](https://fluxcd.io/flux/): a tool for keeping Kubernetes clusters in sync with sources of configuration (like Git repositories), and automating updates to the configuration when there is new code to deploy.
  - [flux-kustomize-helm-example](https://github.com/fluxcd/flux2-kustomize-helm-example): an example repository to demonstrate how to use Flux v2 with Kustomize and Helm. Should be used as a reference for how to structure the repo.
  - [flagger](https://fluxcd.io/flagger/): a progressive delivery tool that automates the release process for applications running on Kubernetes.
  - [post-build-variable-substitution](https://fluxcd.io/flux/components/kustomize/kustomization/#post-build-variable-substitution): a way to template manifests before applying them to the cluster. (Should be used over patches, when possible.)
  - [patches](https://fluxcd.io/flux/components/kustomize/kustomizations/#patches): a way to extend manifests before applying them to the cluster.
  - [sops](https://fluxcd.io/flux/guides/mozilla-sops/): Mozilla SOPS is a tool to manage secrets using a GitOps workflow, where secrets are encrypted/decrypted using GPG keys, and stored in Git. Flux uses a plugin to decrypt the secrets before applying them to the cluster.
  - [recommendations](https://fluxcd.io/flux/components/kustomize/kustomizations/#working-with-kustomizations): a list of recommendations for working with Flux Kustomizations.
