#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🪵 Get current branch"
branch=$(git branch --show-current)

echo "🔥 Destroy existing Talos Linux cluster in Docker"
talosctl cluster destroy --config talos-configs/talos-config.local.yaml

echo "🐳 Provision Talos Linux cluster in Docker"
talosctl cluster create --config talos-configs/talos-config.local.yaml

echo "🏡 Set current cluster to 'homelab-sandbox'"
kubectl config use-context 'homelab-sandbox'

echo "🔐 Adding SOPS GPG key"
kubectl create namespace flux-system
gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
  kubectl create secret generic sops-gpg \
    --namespace=flux-system \
    --from-file=sops.asc=/dev/stdin

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github \
  --owner=$GITHUB_USER \
  --repository=homelab \
  --path=./k8s/clusters/sandbox/.bootstrap \
  --personal \
  --branch=$branch
