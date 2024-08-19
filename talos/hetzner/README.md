# Talos Hetzner Cloud Bootstrapping Scripts

This directory contains scripts to bootstrap a Talos Omni nodis on Hetzner Cloud.

## Usage

Before you can create and delete servers, you need a Hetzner Cloud Account with a Hetzner Cloud API token and SSH key configured.

1. Create an account on Hetzner Cloud
2. Create a new project on Hetzner Cloud (manually)
3. Create a new network on Hetzner Cloud with a subnet, and call it `homelab` (manually)
4. Create a new API token on Hetzner Cloud with read/write access to the project (manually)
5. Create an SSH Key on Hetzner Cloud (manually)

Now that Hetzner Cloud is configured, and is ready to spin up servers for you, you need to get the Talos installation media, so we can create a snapshot of it, and use it to create servers in the future.

1. Download the Talos installation media for Hetzner Cloud from the Talos Omni UI (manually)
2. Move the Talos installation media to the `talos/hcloud/media` folder, and ensure it is named according to the `hcloud.pkr.hcl` file
3. Run the `create-snapshot.sh` script to create a snapshot of the Talos image.

That's it! Now you can create and delete servers!

### Creating a Server

To create a server, you need to run the `create-server.sh` script. This script will create a new server with the Talos image, and will configure the server to use the `homelab` network.

### Deleting a Server

> [!WARNING]
> Before deleting a server, ensure you have drained it, and destroyed it from your cluster. You can do this manually in the Talos Omni UI.

To delete a server, you need to run the `delete-server.sh` script. This script will delete the server, and all of its resources.
