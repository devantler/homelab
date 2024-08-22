# Welcome to Devantler's Homelab 🚀

<details>
  <summary>Show/hide folder structure</summary>

<!-- readme-tree start -->
```
.
├── .github
│   └── workflows
├── .vscode
├── k8s
│   ├── apps
│   │   ├── fleetdm
│   │   ├── homepage
│   │   ├── open-webui
│   │   └── plantuml
│   ├── clusters
│   │   ├── homelab-local
│   │   │   ├── flux-system
│   │   │   └── variables
│   │   └── homelab-prod
│   │       ├── flux-system
│   │       ├── infrastructure
│   │       │   ├── cilium
│   │       │   └── gha-runner-scale-sets
│   │       └── variables
│   ├── custom-resources
│   │   ├── middlewares
│   │   │   ├── basic-auth
│   │   │   └── forward-auth
│   │   └── selfsigned-cluster-issuer
│   ├── distributions
│   │   ├── k3s
│   │   │   └── variables
│   │   └── talos
│   │       ├── infrastructure
│   │       │   ├── kubelet-serving-cert-approver
│   │       │   └── longhorn
│   │       └── variables
│   ├── infrastructure
│   │   ├── capi-operator
│   │   ├── cert-manager
│   │   ├── cloudflared
│   │   ├── gha-runner-scale-set-controller
│   │   ├── goldilocks
│   │   ├── harbor
│   │   ├── helm-charts-oci-proxy
│   │   ├── k8sgpt-operator
│   │   ├── kyverno
│   │   ├── metrics-server
│   │   ├── oauth2-proxy
│   │   ├── ollama
│   │   ├── reloader
│   │   ├── traefik
│   │   └── trivy-operator
│   ├── tenants
│   └── variables
└── talos
    ├── hetzner
    └── patches
        ├── cluster
        └── nodes

55 directories
```
<!-- readme-tree end -->

</details>

![image](https://github.com/user-attachments/assets/cc96e95c-4362-4432-9509-7f52c6c21636)

This repo contains the deployment artifacts for Devantler's Homelab. The Homelab is a Kubernetes cluster that is highly automated with the use of Flux GitOps, CI/CD with Automated Testing, and much more. Feel free to look around. You might find some inspiration 🙌🏻

## Prerequisites

For development:

- [Docker](https://docs.docker.com/get-docker/)
- [KSail](https://github.com/devantler/ksail)

For production:

- A Talos Cluster

> [!NOTE]
> You can use other distributions as well, but the configuration is optimized for Talos, and thus it is not guaranteed to work with other distributions.

## Usage

To run this cluster locally, simply run the following command:

```bash
ksail up homelab-local
```

> [!NOTE]
> To run this cluster on your metal, would require that you have access to my SOPS keys. This is ofcourse not possible, so you would need to create your own keys and replace the existing ones, if you want to run my cluster configuration on your own metal.
>
> - The keys that `KSail` uses are stored in `~/.ksail/age` where one Age key is store for each cluster, and named according to the cluster name. For example `~/.ksail/age/homelab-local`.
> - To update SOPS to work with `Ksail`, you need to update the `.sops.yaml` file in the root of the repository, and replace the `age` keys with your own keys.
> - To update the manifests to work with `KSail`, you need to replace all `.sops.yaml` files with new ones, that are encrypted with your own keys.
>
> For the production cluster, you would need to do the same, but in addition to storing the keys in `~/.ksail/age`, you would also need to store the keys in GitHub Secrets, such that the CI/CD pipeline can provision the keys to the cluster.

## Stack

The cluster uses Flux GitOps to reconcile the state of the cluster with single source of truth stored in this repository and published as an OCI image. For development, the cluster is spun up by `KSail` and for production, the cluster is provisioned by `Talos Omni`.

The cluster configuration is stored in the `k8s/*` directories where the structure is as follows:

- `apps/*`: Contains the application specific manifests.
  - [FleetDM](k8s/apps/fleetdm/README.md) - To provide a device management for my devices. (currently not in use, as it does not support ARM64)
  - [Homepage](k8s/apps/homepage/README.md) - To provide a dashborad for the cluster.
  - [Open WebUI](k8s/apps/open-webui/README.md) - To provide a web interface and a REST API for interacting with LLM's.
  - [PlantUML](k8s/infrastructure/plantuml/README.md) - To provide a web interface and a REST API for generating PlantUML diagrams.
  - [Traefik](k8s/infrastructure/traefik/README.md) - To provide an ingress controller for the cluster.
- `clusters/*`: Contains the the cluster specific configuration for each environment.
- `distributions/*`: Contains the distribution specific configuration.
- `infrastructure/*`: Contains the infrastructure specific manifests.
  - [Cert Manager](k8s/infrastructure/cert-manager/README.md) - For managing certificates in the cluster.
  - [Cloudflared](k8s/infrastructure/cloudflared/README.md) - For tunneling traffic to the cluster.
  - [Cluster API Operator](k8s/infrastructure/capi-operator/README.md) - For managing the lifecycle of Kubernetes clusters.
  - [GitHub Actions Runner Scale Set Controller](k8s/infrastructure/gha-runner-scale-set-controller/README.md) - To manage GitHub Actions Runner Scale Sets in the cluster.
  - [GitHub Actions Runner Scale Sets](k8s/clusters/homelab-prod/infrastructure/gha-runner-scale-sets/README.md) - To run GitHub Actions in the cluster.
  - [Goldilocks](k8s/infrastructure/goldilocks/README.md) - To provide and apply resource recommendations for pods.
  - [Harbor](k8s/infrastructure/harbor/README.md) - To store and distribute container images.
  - [K8sGPT Operator](k8s/infrastructure/k8sgpt-operator/README.md) - To analyze the cluster for improvements, vulnerabilities or bugs.
  - [Kyverno](k8s/infrastructure/kyverno/README.md) - To enforce policies in the cluster.
  - [Longhorn](k8s/distributions/talos/infrastructure/longhorn/README.md) - To provide distributed storage for the cluster.
  - [Metrics Server](k8s/infrastructure/metrics-server/README.md) - To provide metrics for the cluster.
  - [OAuth2 Proxy](k8s/infrastructure/oauth2-proxy/README.md) - To provide authentication for the cluster.
  - [Ollama](k8s/infrastructure/ollama/README.md) - To run LLM's on the cluster.
  - [Reloader](k8s/infrastructure/reloader/README.md) - To reload deployments when secrets or configmaps change.
  - [Trivy Operator](k8s/infrastructure/trivy-operator/README.md) - To analyze the cluster for vulnerabilities.
- `tenants`: Contains Flux kustomizations to bootstrap and onboard tenants. (currently not in use)
- `variables/*`: Contains global variables, that are the same for all clusters.

## Production Environment

### Nodes

- 3x [Hetzner CAX41 node](https://www.hetzner.com/cloud/) (QEMU ARM64 16CPU 32Gb RAM 320Gb SSD) for the control plane and worker node
- 1x [UTM](https://mac.getutm.app) Apple Hypervisor ARM64 VM (Running on Mac Mini M2 Pro with access to 32GB RAM and 20 cores (overprovisioned 2/1) as a worker node

### Hardware

- [Unifi Cloud Gateway](https://eu.store.ui.com/eu/en/pro/products/ucg-ultra) - For networking and firewall.
- [External Samsung T5/T7 SSD Disks](https://www.samsung.com/dk/memory-storage/portable-ssd/portable-ssd-t7-1tb-gray-mu-pc1t0t-ww/) - For distributed storage across the cluster.

### Software

- [Unifi](https://ui.com/) - For configuring a DMZ zone for my own nodes to run in, along with other security features.
- [Talos Omni](https://www.siderolabs.com/platform/saas-for-kubernetes/) - For provisioning the production cluster, and managing nodes, updates, and the Talos configuration.
- [Cloudflare](https://www.cloudflare.com) - For etcd backups, DNS, and tunneling all traffic so my network stays private.
- [Flux GitOps](https://fluxcd.io) - For managing the kubernetes applications and infrastructure declaratively.
- [SOPS](https://getsops.io) and [Age](https://github.com/FiloSottile/age) - For encrypting secrets at rest, allowing me to store them in this repository with confidence.
- [KSail](https://github.com/devantler/ksail) - For developing the cluster locally, and for running the cluster in CI to ensure all changes are properly tested before being applied to the production cluster.
- [K8sGPT](https://k8sgpt.ai) - To analyze the cluster for improvements, vulnerabilities or bugs. It integrates with Trivy and Kuverno to also provide security and policy suggestions.

### Cost

| Budget |	Total USD (Monthly) |
|-------|------------|
| Hetzner CAX21 |	7,49 € |
| Hetzner CAX41	| 29,99 € |
| Talos Omni |	10,00 US$ |
| Cloudflare Domains |	0,87 US$$ |
| TOTAL	| 52,51 US$ |


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=devantler/homelab&type=Date)](https://star-history.com/#devantler/homelab&Date)
