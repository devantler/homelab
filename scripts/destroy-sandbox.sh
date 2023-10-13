#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🔥 Destroy Sandbox"
talosctl cluster destroy --name homelab-sandbox --force
talosctl config context default
talosctl config remove homelab-sandbox -y
kubectl config delete-context admin@homelab-sandbox
kubectl config delete-cluster homelab-sandbox
