#!/bin/bash
token="$1"
server_name="$2"

if [ -z "$token" ]; then
  echo "Usage: $0 <token> <server_name>"
  exit 1
elif [ -z "$server_name" ]; then
  echo "Usage: $0 <token> <server_name>"
  exit 1
fi

export HCLOUD_TOKEN=$1

hcloud context create talos

hcloud server delete "$2"
