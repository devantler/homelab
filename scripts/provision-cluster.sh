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
  echo "⛴️ Provision ${cluster_name} cluster"
  talosctl cluster create \
    --name ${cluster_name} \
    --registry-mirror docker.io=http://192.168.65.254:5001 \
    --registry-mirror hub.docker.com=http://192.168.65.254:5002 \
    --registry-mirror registry.k8s.io=http://192.168.65.254:5003 \
    --registry-mirror gcr.io=http://192.168.65.254:5004 \
    --registry-mirror ghcr.io=http://192.168.65.254:5005 \
    --registry-mirror quay.io=http://192.168.65.254:5006 \
    --registry-mirror manifests=http://192.168.65.254:5050 \
    --wait || {
    echo "🚨 Cluster creation failed. Exiting..."
    exit 1
  }
  add_sops_gpg_key || {
    echo "🚨 SOPS GPG key creation failed. Exiting..."
    exit 1
  }
  install_flux $cluster_name || {
    echo "🚨 Flux installation failed. Exiting..."
    exit 1
  }

}

function add_sops_gpg_key() {
  echo "🔐 Adding SOPS GPG key"
  kubectl create namespace flux-system
  if [[ -z ${SOPS_GPG_KEY} ]]; then
    gpg --export-secret-keys --armor "F78D523ADB73F206EA60976DED58208970F326C8" |
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
  local source_url="oci://192.168.65.254:5050/${cluster_name}"
  flux create source oci flux-system \
    --url=$source_url \
    --insecure=true \
    --tag=latest || {
    echo "🚨 Flux OCI source creation failed. Exiting..."
    exit 1
  }

  flux create kustomization flux-system \
    --source=OCIRepository/flux-system \
    --path=./clusters/docker/.flux || {
    echo "🚨 Flux kustomization creation failed. Exiting..."
    exit 1
  }
}

function main() {
  pushd $(dirname "$0") >/dev/null
  local cluster_name=${1}
  create_oci_registries
  ./update-cluster.sh $cluster_name || {
    echo "🚨 Cluster update failed. Exiting..."
    exit 1
  }
  ./destroy-cluster.sh $cluster_name
  provision_cluster $cluster_name || {
    echo "🚨 Cluster provisioning failed. Exiting..."
    exit 1
  }
}

main "homelab-docker"
