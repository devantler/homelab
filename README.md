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
│   │       │   ├── gha-runner-scale-sets
│   │       │   └── longhorn
│   │       └── variables
│   ├── distributions
│   │   ├── k3s
│   │   │   └── variables
│   │   └── talos
│   │       ├── infrastructure
│   │       │   └── kubelet-serving-cert-approver
│   │       └── variables
│   ├── infrastructure
│   │   ├── cert-manager
│   │   ├── cloudflared
│   │   ├── gha-runner-scale-set-controller
│   │   ├── goldilocks
│   │   ├── harbor
│   │   ├── k8sgpt-operator
│   │   ├── metrics-server
│   │   ├── oauth2-proxy
│   │   ├── ollama
│   │   └── traefik
│   ├── repositories
│   ├── tenants
│   └── variables
└── talos
    ├── hetzner
    └── patches
        ├── cluster
        └── nodes

45 directories
```
<!-- readme-tree end -->

</details>

<img width="1800" alt="image" src="https://github.com/user-attachments/assets/a990a5ce-6cf7-4abb-ab6d-6361461e45b6">

This repo contains the deployment artifacts for Devantler's Homelab. The Homelab is a Kubernetes cluster that is highly automated with the use of Flux GitOps, CI/CD with Automated Testing, and much more. Feel free to look around. You might find some inspiration 🙌🏻

## Prerequisites

For development, you need the following tools:

- [Docker](https://docs.docker.com/get-docker/)
- [KSail](https://github.com/devantler/ksail)

For production, you need the following tools:

- Talos Cluster

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

- [Cert Manager](https://cert-manager.io/docs/) - For managing certificates in the cluster.
- [Cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) - To tunnel all traffic through Cloudflare, and to keep my network private.
- [GitHub Actions Runner Scale Sets](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners-with-actions-runner-controller/about-actions-runner-controller) - To run GitHub Actions in the cluster.
- [Goldilocks](https://goldilocks.docs.fairwinds.com) - To recommend and update Vertical Pod Autoscaler requests and limits.
- [Harbor](https://goharbor.io) - To store and manage container images.
- [K8sGPT Operator](https://k8sgpt.ai) - To analyze and optimize the cluster for errors and improvements.
- [Metrics Server](https://kubernetes-sigs.github.io/metrics-server/) - To collect and expose metrics from the cluster.
- [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/) - To proxy authentication requests to upstream OAuth2 providers.
- [Ollama](https://ollama.com) - To run LLM's in the cluster, and to provide a REST API to access them remotely.
- [Open WebUI](https://openwebui.com) - A web interface to interact with Ollama and OpenAI's AI models.
- [Traefik](https://doc.traefik.io/traefik/) - To route traffic to the correct services in the cluster.
- [Homepage](https://gethomepage.dev/) - To provide a dashboard for the cluster.
- [PlantUML](https://plantuml.com) - To generate UML diagrams from text.

## Cluster Configuration

The cluster uses Flux GitOps to reconcile the state of the cluster with single source of truth stored in this repository and published as an OCI image. For development, the cluster is spun up by `KSail` and for production, the cluster is provisioned by `Talos Omni`.

The cluster configuration is storen in the `k8s/*` directories where the structure is as follows:

- `clusters/*`: Contains the the cluster specific configuration for each environment. For example entry-level Flux kustomizations, and the environment specific variables.
- `distributions/*`: Contains the distribution specific configuration. For example distribution specific variables, and infrastructure components needed to support the distribution. Talos for example does not have a built-in kubelet-serving-cert-approver, so it is required to make metrics server access kubelet with a certificate.
- `apps/*`: Contains the application specific manifests. For example the homepage, local-ai, ollama, and plantuml.
- `infrastructure/*`: Contains the infrastructure specific manifests. For example cert-manager, cloudflared, gha-runner-scale-set-controller, goldilocks, harbor, k8sgpt-operator, metrics-server, oauth2-proxy, and traefik.
- `repositories/*`: Contains the repositories that are used by the cluster. For example the `flux-system` repository.
- `tenants`: Contains Flux kustomizations to bootstrap and onboard tenants. (currently not used)
- `variables/*`: Contains global variables, that are the same for all clusters.

## Production Environment

### Nodes

- 3x Hetzner CAX21 nodes (QEMU ARM64) for the control plane
- 1x UTM Apple Hypervisor ARM64 VM (Running on Mac Mini M2 Pro with access to 32GB RAM and 10 cores) as a worker node
  - The Apple Hypervisor performs better than QEMU, and is thus preferred for the worker nodes.
- 1x UTM QEMU ARM64 VM (Running on Mac Mini M2 Pro with access to 2GB RAM and 2 cores) as a worker node
  - The QEMU VM is used to attach external disks to the cluster. This is not well supported by the Apple Hypervisor.

### Hardware

- Unifi Cloud Gateway - For networking and firewall.
- External Disks - For distributed storage across the cluster.

### Software

- Unifi - For configuring a DMZ zone for my own nodes to run in, along with other security features.
- Talos Omni - For provisioning the production cluster, and managing nodes, updates, and the Talos configuration.
- Cloudflare - For etcd backups, DNS, and tunneling all traffic so my network stays private.
- Flux GitOps - For managing the kubernetes applications and infrastructure declaratively.
- SOPS and Age - For encrypting secrets at rest, allowing me to store them in this repository with confidence.
- KSail - For developing the cluster locally, and for running the cluster in CI to ensure all changes are properly tested before being applied to the production cluster.
