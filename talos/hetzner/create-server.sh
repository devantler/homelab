#!/bin/bash
token="$1"
server_name="$2"
server_type="$3"
location="$4"
placement_group="$5"
image_id="$6"
ssh_key_name="$7"

if [ -z "$token" ] || [ -z "$server_name" ] || [ -z "$server_type" ] || [ -z "$location" ] || [ -z "$placement_group" ] || [ -z "$image_id" ] || [ -z "$ssh_key_name" ]; then
  echo "Usage: $0 <token> <server_name> <server_type> <location> <placement_group> <image_id> <ssh_key_name>"
  echo ""
  echo "Where:"
  echo "  <token> is the Hetzner Cloud API token for a Hetzner Cloud project"
  echo "  <server_name> is the name of the server to create"
  echo "  <server_type> is the type of server to create e.g. cx11"
  echo "  <location> is the location to create the server in e.g. fsn1"
  echo "  <placement_group> is the placement group to create the server. Can be the either a name or ID"
  echo "  <image_id> is the ID of the snapshot image to use for the server"
  echo "  <ssh_key_name> is the name of the SSH key to use for the server"
  exit 1
fi

export HCLOUD_TOKEN=$1

hcloud context create talos

hcloud network create --name talos-network --ip-range 10.0.0.0/16

if [ "$(hcloud network describe talos-network | yq -e '.Subnets[]')" == "null" ]; then
  hcloud network add-subnet talos-network --type server --network-zone eu-central
fi

hcloud firewall create --name talos-firewall --rules-file - <<<'[
    {
        "description": "Allow KubeSpan Traffic",
        "direction": "in",
        "port": "51820",
        "protocol": "udp",
        "source_ips": [
            "0.0.0.0/0",
            "::/0"
        ]
    }
]'

hcloud server create --name "$2" \
  --type "$3" \
  --location "$4" \
  --placement-group "$5" \
  --image "$6" \
  --network talos-network \
  --firewall talos-firewall \
  --ssh-key "$7"
