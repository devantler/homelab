#!/bin/bash

function create_oci_registries() {
  echo "🧮 Add pull-through registries"
  docker run -d -p 5001:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io \
    --restart always \
    --name proxy-docker.io \
    --volume proxy-docker.io:/var/lib/registry \
    registry:2

  docker run -d -p 5002:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://hub.docker.com \
    --restart always \
    --name proxy-docker-hub.com \
    --volume proxy-docker-hub.com:/var/lib/registry \
    registry:2

  docker run -d -p 5003:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://registry.k8s.io \
    --restart always \
    --name proxy-registry.k8s.io \
    --volume proxy-registry.k8s.io:/var/lib/registry \
    registry:2

  docker run -d -p 5004:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://gcr.io \
    --restart always \
    --name proxy-gcr.io \
    --volume proxy-gcr.io:/var/lib/registry \
    registry:2

  docker run -d -p 5005:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://ghcr.io \
    --restart always \
    --name proxy-ghcr.io \
    --volume proxy-ghcr.io:/var/lib/registry \
    registry:2

  docker run -d -p 5006:5000 \
    -e REGISTRY_PROXY_REMOTEURL=https://quay.io \
    --restart always \
    --name proxy-quay.io \
    --volume proxy-quay.io:/var/lib/registry \
    registry:2

  docker run -d -p 5050:5000 \
    --restart always \
    --name manifests \
    --volume manifests:/var/lib/registry \
    registry:2
}

function provision_cluster() {
  local cluster_name=${1}
  echo "🐳 Provision ${cluster_name} in Docker"
  talosctl cluster create \
    --name ${cluster_name} \
    --with-kubespan \
    --wait
  # echo "🩹 Apply cluster wide patches"
  # talosctl patch mc -n 127.0.0.1 --patch @./../talos-config-patches/${cluster_name}/cluster/metrics-server.yaml

  # echo "🩹 Apply controlplane patches"
  # talosctl patch mc -n 127.0.0.1 --patch @./../talos-config-patches/${cluster_name}/controlplane/scheduling.yaml

  # echo "🩹 Apply worker patches"
  # talosctl patch mc -n 127.0.0.1 --patch @./../talos-config-patches/${cluster_name}/worker/mayastor.yaml
  #add_sops_gpg_key
  install_flux $cluster_name
}

function add_sops_gpg_key() {
  echo "🔐 Adding SOPS GPG key"
  kubectl create namespace flux-system
  if [[ -z ${SOPS_GPG_KEY} ]]; then
    gpg --export-secret-keys --armor "" |
      kubectl create secret generic sops-gpg \
        --namespace=flux-system \
        --from-file=sops.asc=/dev/stdin
  else
    kubectl create secret generic sops-gpg \
      --namespace=flux-system \
      --from-literal=sops.asc="${SOPS_GPG_KEY}"
  fi
}

function install_flux() {
  local cluster_name=${1}
  echo "🚀 Installing Flux"
  flux check --pre || {
    echo "🚨 Flux prerequisites check failed. Exiting..."
    exit 1
  }
  flux install || {
    echo "🚨 Flux installation failed. Exiting..."
    exit 1
  }

  local source_url="oci://host.docker.internal:5050/${cluster_name}"
  flux create source oci flux-system \
    --url=$source_url \
    --insecure=true \
    --tag=latest || {
    echo "🚨 Flux OCI source creation failed. Exiting..."
    exit 1
  }

  flux create kustomization flux-system \
    --source=OCIRepository/flux-system \
    --path=./clusters/$cluster_name/.flux || {
    echo "🚨 Flux kustomization creation failed. Exiting..."
    exit 1
  }
}

function main() {
  pushd $(dirname "$0") >/dev/null
  local cluster_name=${1}
  create_oci_registries
  ./update-clusters.sh $cluster_name
  provision_cluster $cluster_name
}

main "homelab-docker"
