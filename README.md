# Welcome to Devantler's Homelab 🚀

<details>
  <summary>Show/Hide Folder Structure</summary>

<!-- readme-tree start -->
```
.
├── .github
│   └── workflows
├── .vscode
├── k8s
│   ├── clusters
│   │   ├── homelab-ksail
│   │   │   ├── flux-system
│   │   │   └── variables
│   │   └── homelab-prod
│   │       ├── flux-system
│   │       └── variables
│   ├── environments
│   │   └── talos
│   │       └── infrastructure
│   │           └── patches
│   └── manifests
│       ├── apps
│       │   ├── ingresses
│       │   └── patches
│       ├── infrastructure
│       │   └── releases
│       ├── infrastructure-config
│       │   ├── ingresses
│       │   ├── middlewares
│       │   ├── pipelines
│       │   └── tasks
│       └── repositories
└── talos
    └── patches
        ├── cluster
        └── nodes

31 directories
```
<!-- readme-tree end -->

</details>

<img width="1657" alt="image" src="https://github.com/devantler/homelab/assets/26203420/f2c4cf51-67b1-4fc9-ab08-16f8ea140457">

This repo contains the deployment artifacts for Devantler's Homelab. The Homelab is a Kubernetes cluster that is highly automated with the use of Flux GitOps, CI/CD with Automated Testing, and much more. Feel free to look around. You might find some inspiration 🙌🏻

## Cluster Nodes

- 1x Mac Mini M2 Pro (Split into 2x UTM (QEMU) VMs)
- 1x Zima Board

## Supporting Hardware

- Unifi Cloud Gateway
- External Disks

## Supporting Software

- Unifi
- Talos Omni
- Cloudflare (R3, Tunneling, Domains)
- Flux GitOps
- SOPS
- KSail
