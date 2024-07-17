#!/bin/bash
token="$1"
server_name="$2"
image_id="$3"
server_type="$4"
location="$5"

if [ -z "$token" ]; then
  echo "Usage: $0 <token> <server_name> <image_id> <location>"
  exit 1
elif [ -z "$server_name" ]; then
  echo "Usage: $0 <token> <server_name> <image_id> <location>"
  exit 1
elif [ -z "$image_id" ]; then
  echo "Usage: $0 <token> <server_name> <image_id> <location>"
  exit 1
elif [ -z "$server_type" ]; then
  echo "Usage: $0 <token> <server_name> <image_id> <location>"
  exit 1
elif [ -z "$location" ]; then
  echo "Usage: $0 <token> <server_name> <image_id> <location>"
  exit 1
fi

export HCLOUD_TOKEN=$1

hcloud context create talos

hcloud server create --name "$2" \
  --without-ipv6 \
  --image "$3" \
  --type "$4" --location "$5"
