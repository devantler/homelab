# My HomeLab!

**NEEDS CLEANUP**

## Getting started

1. Connect to a server node (SSH, remote desktop, etc.)
   - I recommend using VSCode Remote Explorer (SSH)
2. Install dependencies on each node (git, Nomad, Consul, and Vault)
   - You might be able to use the Ansible playbook to initialize nodes (configured for RaspberryPi 4B 64bit).
3. Initialize Nomad with all your nodes.
<!-- TODO: Add steps to setup Nomad nodes -->
4. Deploy Portainer, Traefik, Wireguard, and Keepalived manually.
5. You can now open Portainer by going to <https://{keepalived-virtual-ip}:9443>
6. Go nuts! You now have a functional cluster that you can manage from Portainer.

## Services in the cluster

### Portainer

Portainer is a centralized service delivery platform for containerized apps that allows self-hosting docker applications in fully managed environments with Docker Swarm, HashiCorp Nomad, or Kubernetes.

This service manages all other stacks in the cluster and is capable of:

- Auto deploying stacks from GitHub when they change.
- Running multiple environments, e.g., development web apps or production web apps.
- Manage all stuff Docker related

<https://www.portainer.io>

### Traefik

Traefik is an open-source reverse proxy that is fast and easy to configure. It makes publishing your services a fun and quick experience, where you will have HTTPS working with automatically generated self-managed certificates in no time.

<https://doc.traefik.io/traefik/>

### WireGuard

Wireguard is a highly secure and performant VPN.

<https://www.wireguard.com>

### AdGuard Home

AdGuard is a network-wide ad-blocking service that blocks an impressive amount of ads. The stack is set to direct all traffic through AdGuard from local clients or clients connected through a VPN.

<https://adguard.com/da/adguard-home/overview.html>

### Keepalived

Keepalived is used to set a virtual IP for each manager node, such that connecting to the virtual IP will ensure a manager is reached in case of system failure.

<https://keepalived.readthedocs.io/en/latest/introduction.html>