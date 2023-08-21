# Welcome to Devantler's Homelab 🚀

This Homelab is a Flux2-based GitOps repository to manage my personal Kubernetes clusters. It focuses on providing a secure and reliable infrastructure for my personal projects, with a focus on ease-of-use and automation of common tasks, such as safe an secure CI/CD pipelines.

## Overview

### Apps

- [GitOps Dashboard](https://github.com/weaveworks/weave-gitops/tree/main/charts/gitops-server): GitOps Dashboard: The Weave GitOps Dashboard is a web-based UI for managing your Weave GitOps deployments.
- [Kubernetes Dashboard](https://github.com/kubernetes/dashboard/tree/master): General-purpose web UI for Kubernetes clusters.
  
### Infrastructure

- [Cert-Manager](https://cert-manager.io/docs/): Cert-Manager is a Kubernetes add-on to automate the management and issuance of TLS certificates from various issuing sources.
- [Traefik](https://doc.traefik.io/traefik/): Traefik is an open-source Edge Router that makes publishing your services a fun and easy experience.

## Getting Started

To run the Homelab you must:

1. Create and configure a domain on Cloudflare.
2. Set up Cloudflare to tunnel service access.
3. Run the `scripts/provision.sh` script to set up a development and production cluster.
    - The development cluster is accessible on `x.test` (requires `/etc/hosts` configuration).
    - The production cluster is accessible on `x.devantler.com`. If you want to use a different domain, you must update the domains in the `patches` folders.
