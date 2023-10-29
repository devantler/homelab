# Welcome to Devantler's Homelab 🚀

This Homelab is a Flux2-based GitOps repository to manage my personal Kubernetes clusters. It focuses on providing a secure and reliable infrastructure for my projects, with a focus on ease of use and automation of common tasks, such as safe and secure CI/CD pipelines.

- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
- [Managing secrets](#managing-secrets)
  - [Setting up SOPS](#setting-up-sops)
  - [SOPS VSCode Integration](#sops-vscode-integration)
- [Cluster Setups](#cluster-setups)
  - [Local Setup](#local-setup)
  - [Production Setup](#production-setup)

## Overview

<!-- readme-tree start -->
```
.
├── .github
│   ├── scripts
│   └── workflows
├── .vscode
├── k8s
│   ├── apps
│   ├── clusters
│   │   ├── production
│   │   │   ├── .bootstrap
│   │   │   │   └── flux-system
│   │   │   ├── apps
│   │   │   ├── infrastructure
│   │   │   │   └── configs
│   │   │   └── variables
│   │   └── local
│   │       ├── .bootstrap
│   │       │   └── flux-system
│   │       ├── apps
│   │       ├── infrastructure
│   │       │   └── configs
│   │       └── variables
│   └── infrastructure
│       ├── configs
│       │   ├── certificates
│       │   ├── cluster-issuers
│       │   ├── ingress-routes
│       │   └── middlewares
│       └── services
│           ├── cert-manager
│           │   └── secrets
│           ├── cloudflared
│           ├── flux-github-status-updater
│           ├── flux-webhook-receiver
│           │   └── secrets
│           ├── kube-prometheus-stack
│           ├── openebs
│           ├── reloader
│           └── traefik
│               └── secrets
└── scripts
    └── talos-config-patches
        ├── homelab-production
        │   ├── cluster
        │   ├── controlplane
        │   └── worker
        └── homelab-local
            ├── cluster
            ├── controlplane
            └── worker

49 directories
```
<!-- readme-tree end -->

## Getting Started

These instructions will guide you through the process of installing the necessary tools, and setting up your local environment to work on the clusters.

### Prerequisites

- [Flux CLI](https://fluxcd.io/docs/installation/#install-the-flux-cli)
- [gnupg](https://gnupg.org/download/index.html): GnuPG is a complete and free implementation of the OpenPGP standard as defined by RFC4880 (also known as PGP).
- [sops](https://github.com/getsops/sops): SOPS is an editor of encrypted files that supports YAML, JSON, ENV, INI, and BINARY formats and encrypts with AWS KMS, GCP KMS, Azure Key Vault, and PGP.
- Local Setup
  - [Docker](https://docs.docker.com/get-docker/) for running talos clusters locally.
  - [yq](https://github.com/mikefarah/yq) for validating YAML.
  - [kubeconform](https://github.com/yannh/kubeconform) for validating Kubernetes manifests.
- Debugging
  - [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) for administrating clusters.
  - [k9s](https://k9scli.io): K9s provides a curses based terminal UI to interact with your Kubernetes clusters.

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

- **Local** - A local environment for testing new services.
  - `<service>.local.<domain>`
- **Production** - A production environment for hosting services.
  - `<service>.<domain>`

### Local Setup

> [!NOTE]
> Currently the local cluster is setup to run in Docker, and is not intended to be used for anything other than testing new services locally. This will change as the maintainer gets more hardware, and it makes sense to scale out into multiple environments.

The local cluster is fully managed by Flux2 and GitHub Actions, and it should not be modified directly through `kubectl`, `helm`, or similar tools.

- The **local** cluster is updated whenever changes are merged to the main branch.

In case the cluster needs to be recreated or upgraded, you can run the `scripts/bootstrap-local.sh` script. This script will configure a set of Talos Linux nodes in Docker and bootstrap Flux2 to sync the cluster.

### Production Setup

The production cluster is fully managed by Flux2 and GitHub Actions, and it should not be modified directly through `kubectl`, `helm`, or similar tools.

- The **production** cluster is updated whenever changes are merged to the main branch.

In case the cluster needs to be recreated or upgraded, you can run the `scripts/bootstrap-production.sh` script. This script will configure a set of Talos Linux nodes and bootstrap Flux2 to sync the cluster.
