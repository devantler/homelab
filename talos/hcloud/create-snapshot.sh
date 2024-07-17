#!/bin/bash
token="$1"

if [ -z "$token" ]; then
  echo "Usage: $0 <token>"
  exit 1
fi

export HCLOUD_TOKEN=$1
packer init .
packer build .
