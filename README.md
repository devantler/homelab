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
│       │   └── patches
│       ├── infrastructure
│       │   ├── configmaps
│       │   ├── ingresses
│       │   └── patches
│       └── infrastructure-crds
│           └── middlewares
└── talos
    └── patches

26 directories
```
<!-- readme-tree end -->

</details>

<img width="1720" alt="image" src="https://github.com/devantler/homelab/assets/26203420/de0268be-cadb-4128-90d1-11da5925450a">

This repo contains the deployment artifacts for Devantler's Homelab. The Homelab is a Kubernetes cluster that is highly automated with the use of Flux GitOps, CI/CD with Automated Testing, and much more. Feel free to look around. You might find some inspiration 🙌🏻

## Cluster Nodes

- 1x Mac Mini M2 Pro (Split into 2x UTM VMs)
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
