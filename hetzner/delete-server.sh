#!/bin/bash
token="$1"
server_name="$2"

if [ -z "$token" ] || [ -z "$server_name" ]; then
  echo "Usage: $0 <token> <server_name>"
  echo ""
  echo "Where:"
  echo "  <token> is the Hetzner Cloud API token for a Hetzner Cloud project"
  echo "  <server_name> is the name of the server to delete"
  exit 1
fi

export HCLOUD_TOKEN=$1

hcloud context create talos

hcloud server delete "$2"
