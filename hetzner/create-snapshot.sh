#!/bin/bash
token="$1"

if [ -z "$token" ]; then
  echo "Usage: $0 <token>"
  echo ""
  echo "Where:"
  echo "  <token> is the Hetzner Cloud API token for a Hetzner Cloud project"
  exit 1
fi

export HCLOUD_TOKEN=$1
packer init .
packer build .
