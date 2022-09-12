# My HomeLab!

This repo contains Ansible playbooks and FluxCD Kustomization manifests.

Ansible is used to deploy a High-Availability Kubernetes cluster. It is configured to work with Raspberry Pi's running Ubuntu, and MacOs nodes. 

FluxCD is to deploy infrarstructure and apps with a GitOps workflow, meaning any changes to the main branch will be synced to the cluster. To ensure that no bugs are introduced an end-2-end testing suite has been set up to ensure the infrastructure and apps can be deployed without errors. The infrastructure is centered around Cloudflare as a hosting platform, and is able to provision DNS names automatically.
