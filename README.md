# Welcome to Devantler's Homelab 🚀

<details>
  <summary>Show/Hide Folder Structure</summary>

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
│   │   └── docker
│   │       ├── .flux
│   │       ├── infrastructure
│   │       │   ├── configs
│   │       │   └── services
│   │       └── variables
│   └── infrastructure
│       ├── cert-manager
│       │   ├── certificates
│       │   └── cluster-issuers
│       ├── cloudflared
│       ├── flux-github-status-updater
│       ├── flux-webhook-receiver
│       │   ├── ingress-routes
│       │   └── secrets
│       ├── gha-runner-scale-set
│       ├── gha-runner-scale-set-controller
│       ├── harbor
│       ├── kube-prometheus-stack
│       ├── kubelet-serving-cert-approver
│       ├── local-storage
│       ├── metrics-server
│       ├── openebs
│       ├── pulumi-operator
│       │   └── programs
│       ├── redis
│       ├── reloader
│       ├── strapi
│       ├── testkube
│       ├── traefik
│       └── vertical-pod-autoscaler
├── pulumi
├── scripts
└── talos
    ├── cluster
    ├── controlplane
    └── worker

44 directories
```
<!-- readme-tree end -->

</details>

This Homelab is a [flux-based GitOps repository](https://github.com/fluxcd/flux2-kustomize-helm-example) to manage my personal Kubernetes clusters. It focuses on providing a secure and reliable infrastructure for my projects, with a focus on ease of use and automation of common tasks, such as safe and secure CI/CD pipelines.

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
- [Managing secrets](#managing-secrets)
  - [Setting up SOPS](#setting-up-sops)
  - [SOPS VSCode Integration](#sops-vscode-integration)
- [Cluster Setups](#cluster-setups)
  - [Local Setup](#local-setup)
  - [Production Setup](#production-setup)

## Getting Started

This section will guide through the process of running the homelab locally in Docker, or how to setup the Homelab as a flux OCI source.

### Prerequisites

- MacOS or Linux: This setup is not tested on Windows, but it should work with WSL2. It uses shell scripts to provision the docker setup, and these scripts are written to work on MacOS and Linux.

> [!NOTE]
> All dependencies needed to run and debug the clusters are installed with Homebrew in the different scripts. As such, you do not need to install any dependencies manually. However, it is recommended that you install the following tools to make it easier to work with the clusters:
>
> - [k9s](https://k9scli.io)

## Managing secrets

> [!WARNING]
> Never commit unencrypted secrets to the repo. This will compromise the security of the clusters, and require a complicated process to both rotate the public and private keys, as well as removing the leaked secrets from the Git history.

This section describes how to manage secrets in the repo, and how to encrypt/decrypt secrets locally.

### Setting up SOPS

> [!NOTE]
> If no GPG key has been created for the cluster, follow [this guide](https://fluxcd.io/flux/guides/mozilla-sops/) to create a new GPG key.

1. Create or import a new GPG key:
   - `gpg --full-generate-key`
   - `gpg --import <path-to-key>`

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

In case the cluster needs to be recreated or upgraded, you can run the `scripts/provision-local.sh` script. This script will configure a set of Talos Linux nodes in Docker and bootstrap Flux2 to sync the cluster.

### Production Setup

The production cluster is fully managed by Flux2 and GitHub Actions, and it should not be modified directly through `kubectl`, `helm`, or similar tools.

- The **production** cluster is updated whenever changes are merged to the main branch.

In case the cluster needs to be recreated or upgraded, you can run the `scripts/provision-production.sh` script. This script will configure a set of Talos Linux nodes and bootstrap Flux2 to sync the cluster.
