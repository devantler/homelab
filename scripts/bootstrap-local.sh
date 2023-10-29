#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🪵 Get current branch"
branch=$(git branch --show-current)

echo "🐳 Provision Talos Linux cluster in Docker"
talosctl cluster create \
  --name homelab-local \
  --cidr "10.6.0.0/24" \
  --with-kubespan \
  --controlplanes 1 \
  --workers 3 \
  --config-patch @./../talos/patches/cluster/extra-mounts.yaml \
  --config-patch @./../talos/patches/cluster/kubespan.yaml \
  --config-patch @./../talos/patches/cluster/metrics-server.yaml \
  --config-patch-control-plane @./../talos/patches/controlplane/scheduling.yaml \
  --config-patch-worker @./../talos/patches/worker/mayastor.yaml \
  --wait

echo "🏡 Set current cluster to 'homelab-local'"
kubectl config use-context 'admin@homelab-local' || exit 1

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
  --path=./k8s/clusters/local/.bootstrap \
  --personal \
  --branch=$branch
