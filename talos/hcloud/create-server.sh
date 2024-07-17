#!/bin/bash
token="$1"
server_name="$2"
server_type="$3"
location="$4"
placement_group="$5"
image_id="$6"

if [ -z "$token" ] || [ -z "$server_name" ] || [ -z "$server_type" ] || [ -z "$location" ] || [ -z "$placement_group" ] || [ -z "$image_id" ]; then
  echo "Usage: $0 <token> <server_name> <server_type> <location> <placement_group> <image_id>"
  exit 1
fi

export HCLOUD_TOKEN=$1

hcloud context create talos

hcloud server create --name "$2" \
  --type "$3" \
  --location "$4" \
  --placement-group "$5" \
  --image "$6" \
  --without-ipv6
