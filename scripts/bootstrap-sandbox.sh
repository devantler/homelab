#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🪵 Get current branch"
branch=$(git branch --show-current)

echo "🐳 Provision Talos Linux cluster in Docker"
talosctl cluster create --name homelab-sandbox --cidr "10.6.0.0/24" --with-kubespan --wait

echo "🩹 Apply cluster wide patches"
talosctl patch mc -n 127.0.0.1 --patch @./talos-config-patches/homelab-sandbox/cluster/extra-mounts.yaml
talosctl patch mc -n 127.0.0.1 --patch @./talos-config-patches/homelab-sandbox/cluster/metrics-server.yaml

echo "🩹 Apply controlplane patches"
talosctl patch mc -n 127.0.0.1 --patch @./talos-config-patches/homelab-sandbox/controlplane/scheduling.yaml

echo "🏡 Set current cluster to 'homelab-sandbox'"
kubectl config use-context 'admin@homelab-sandbox' || exit 1

echo "🔐 Adding SOPS GPG key"
kubectl create namespace flux-system
gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
  kubectl create secret generic sops-gpg \
    --namespace=flux-system \
    --from-file=sops.asc=/dev/stdin

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github \
  --components-extra="image-reflector-controller,image-automation-controller" \
  --owner=$GITHUB_USER \
  --repository=homelab \
  --path=./k8s/clusters/sandbox/.bootstrap \
  --personal \
  --branch=$branch
