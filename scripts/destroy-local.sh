#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🔥 Destroy Local"
talosctl cluster destroy --name homelab-local --force
talosctl config context default
talosctl config remove homelab-local -y
kubectl config delete-context admin@homelab-local
kubectl config delete-cluster homelab-local
kubectl config delete-user admin@homelab-local
kubectl config unset current-context
