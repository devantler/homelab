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
│   │       ├── infrastructure
│   │       │   ├── cilium
│   │       │   ├── gha-runner-scale-sets
│   │       │   └── longhorn
│   │       └── variables
│   ├── environments
│   │   ├── k3s
│   │   │   └── variables
│   │   └── talos
│   │       ├── infrastructure
│   │       │   └── kubelet-serving-cert-approver
│   │       └── variables
│   └── manifests
│       ├── apps
│       │   ├── homepage
│       │   └── plantuml
│       ├── infrastructure
│       │   ├── cert-manager
│       │   ├── cloudflared
│       │   ├── gha-runner-scale-set-controller
│       │   ├── goldilocks
│       │   ├── harbor
│       │   ├── metrics-server
│       │   ├── oauth2-proxy
│       │   └── traefik
│       ├── repositories
│       └── variables
└── talos
    ├── hetzner
    └── patches
        ├── cluster
        └── nodes

42 directories
```
<!-- readme-tree end -->

</details>

<img width="1837" alt="image" src="https://github.com/user-attachments/assets/f1010229-e704-403c-a779-55651d7a23f5">

This repo contains the deployment artifacts for Devantler's Homelab. The Homelab is a Kubernetes cluster that is highly automated with the use of Flux GitOps, CI/CD with Automated Testing, and much more. Feel free to look around. You might find some inspiration 🙌🏻

## Nodes

- 3x Hetzner CAX21 nodes (QEMU ARM64)
- 1x UTM QEMU ARM64 VM (Running on Mac Mini M2 Pro)

## Hardware

- Unifi Cloud Gateway
- External Disks

## Software

- Unifi
- Talos Omni
- Cloudflare (R3, Tunneling, Domains)
- Flux GitOps
- SOPS
- KSail
