#!/bin/bash

function get_current_branch() {
  echo "🪵 Get current branch"
  branch=$(git branch --show-current)
}

function destroy_local() {
  echo "🔥 Destroy Local"
  ./destroy-local.sh
}

function add_pull_through_registries() {
  echo "🧮 Add pull-through registries"
  docker run -d -p 5001:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io \
    --restart always \
    --name registry-docker.io \
    --volume registry-docker.io:/var/lib/registry \
    registry:2

  docker run -d -p 5002:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://registry.k8s.io \
    --restart always \
    --name registry-registry.k8s.io \
    --volume registry-k8s.io:/var/lib/registry \
    registry:2

  docker run -d -p 5003:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://gcr.io \
    --restart always \
    --name registry-gcr.io \
    --volume registry-gcr.io:/var/lib/registry \
    registry:2

  docker run -d -p 5004:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://ghcr.io \
    --restart always \
    --name registry-ghcr.io \
    --volume registry-ghcr.io:/var/lib/registry \
    registry:2
}

function provision_talos_linux_cluster() {
  echo "🐳 Provision Talos Linux cluster in Docker"
  talosctl cluster create \
    --name homelab-local \
    --cidr "10.6.0.0/24" \
    --with-kubespan \
    --controlplanes 1 \
    --workers 3 \
    --registry-mirror docker.io=http://172.17.0.1:5001 \
    --registry-mirror registry.k8s.io=http://172.17.0.1:5002 \
    --registry-mirror gcr.io=http://172.17.0.1:5003 \
    --registry-mirror ghcr.io=http://172.17.0.1:5004 \
    --config-patch @./../talos/patches/cluster/extra-mounts.yaml \
    --config-patch @./../talos/patches/cluster/kubespan.yaml \
    --config-patch @./../talos/patches/cluster/metrics-server.yaml \
    --config-patch-control-plane @./../talos/patches/controlplane/scheduling.yaml \
    --config-patch-worker @./../talos/patches/worker/mayastor.yaml \
    --wait
}

function set_current_cluster() {
  echo "🏡 Set current cluster to 'homelab-local'"
  kubectl config use-context 'admin@homelab-local' || exit 1
}

function add_sops_gpg_key() {
  echo "🔐 Adding SOPS GPG key"
  kubectl create namespace flux-system
  gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
    kubectl create secret generic sops-gpg \
      --namespace=flux-system \
      --from-file=sops.asc=/dev/stdin
}

function install_flux() {
  echo "🚀 Installing Flux"
  flux check --pre
  flux bootstrap github \
    --components-extra="image-reflector-controller,image-automation-controller" \
    --owner=$GITHUB_USER \
    --repository=homelab \
    --path=./k8s/clusters/local/.bootstrap \
    --personal \
    --branch=$branch
}

function main() {
  pushd $(dirname "$0") >/dev/null

  get_current_branch
  destroy_local
  add_pull_through_registries
  provision_talos_linux_cluster
  set_current_cluster
  add_sops_gpg_key
  install_flux
}

main
