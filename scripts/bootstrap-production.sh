#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo " Set current cluster to homelab"
kubectl config use-context homelab

echo "🔧 Patch machine-config on all control-plane nodes"
talosctl patch mc \
    -n 10.0.0.201 \
    -n 10.0.0.202 \
    -n 10.0.0.203 \
    --patch @machine-config.control-plane.yaml

echo "🔧 Patch machine-config on all worker nodes"
echo "No worker nodes to patch yet"

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/production --personal --branch=main

echo "🔐 Adding SOPS GPG key"
gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
    kubectl create secret generic sops-gpg \
        --namespace=flux-system \
        --from-file=sops.asc=/dev/stdin
