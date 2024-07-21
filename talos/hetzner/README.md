# Talos Hetzner Cloud Bootstrapping Scripts

This directory contains scripts to bootstrap a Talos Omni nodis on Hetzner Cloud.

## Usage

1. Create an account on Hetzner Cloud
2. Create a new project on Hetzner Cloud (manually)
3. Create a new network on Hetzner Cloud with a subnet, and call it `homelab` (manually)
4. Create a new API token on Hetzner Cloud with read/write access to the project (manually)
5. Creat an SSH Key on Hetzner Cloud (manually)
6. Download the Talos installation media for Hetzner Cloud from the Talos Omni UI (manually)
7. Move the Talos installation media to the `talos/hcloud/media` folder, and ensure it is named according to the `hcloud.pkr.hcl` file
8. Run the `create-snapshot.sh` script to create a snapshot of the Talos image.
9. Run the `create-server.sh` script to create a new server with the Talos image.
10. Run the `delete-server.sh` script to delete the server.
