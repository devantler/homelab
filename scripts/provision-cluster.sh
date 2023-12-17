#!/bin/bash

function install_dependencies() {
  echo "📦 Installing dependencies"
  if [[ "$OSTYPE" == "darwin"* || "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v brew &>/dev/null; then
      echo "📦✅ Homebrew already installed. Updating..."
      brew upgrade
    else
      echo "📦🔨 Installing Homebrew"
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      (
        echo
        echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"'
      ) >>/home/runner/.bashrc
      eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
      sudo apt-get install build-essential
      brew install gcc
      echo "📦✅ Homebrew installed"
    fi

    if command -v yq &>/dev/null; then
      echo "📦✅ YQ already installed. Skipping..."
    else
      echo "📦🔨 Installing YQ"
      brew install yq
      echo "📦✅ YQ installed"
    fi

    if command -v kubeconform &>/dev/null; then
      echo "📦✅ Kubeconform already installed. Skipping..."
    else
      echo "📦🔨 Installing Kubeconform"
      brew install kubeconform
      echo "📦✅ Kubeconform installed"
    fi

    if command -v kustomize &>/dev/null; then
      echo "📦✅ Kustomize already installed. Skipping..."
    else
      echo "📦🔨 Installing Kustomize"
      brew install kustomize
      echo "📦✅ Kustomize installed"
    fi

    if command -v docker &>/dev/null; then
      echo "📦✅ Docker already installed. Skipping..."
    else
      echo "📦🔨 Installing Docker"
      brew install --cask docker
      echo "📦✅ Docker installed"
    fi

    if command -v talosctl &>/dev/null; then
      echo "📦✅ Talosctl already installed. Skipping..."
    else
      echo "📦🔨 Installing Talosctl"
      brew install siderolabs/talos/talosctl
      echo "📦✅ Talosctl installed"
    fi

    if command -v flux &>/dev/null; then
      echo "📦✅ Flux already installed. Skipping..."
    else
      echo "📦🔨 Installing Flux"
      brew install fluxcd/tap/flux
      echo "📦✅ Flux installed"
    fi

    if command -v gpg &>/dev/null; then
      echo "📦✅ GPG already installed. Skipping..."
    else
      echo "📦🔨 Installing GPG"
      brew install gpg
      echo "📦✅ GPG installed"
    fi

    if command -v kubectl &>/dev/null; then
      echo "📦✅ Kubectl already installed. Skipping..."
    else
      echo "📦🔨 Installing Kubectl"
      brew install kubectl
      echo "📦✅ Kubectl installed"
    fi
  else
    echo "🚨 Unsupported OS. Exiting..."
    exit 1
  fi
  echo ""
}

function create_oci_registries() {
  echo "🧮 Add pull-through registries"
  # Check if registries already exist
  if (docker volume ls | grep -q proxy-docker.io) && (docker container ls -a | grep -q proxy-docker.io); then
    echo "🧮✅ Registry 'proxy-docker.io' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-docker.io'"
    docker run -d -p 5001:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io \
      --restart always \
      --name proxy-docker.io \
      --volume proxy-docker.io:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q proxy-docker-hub.com) && (docker container ls -a | grep -q proxy-docker-hub.com); then
    echo "🧮✅ Registry 'proxy-docker-hub.com' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-docker-hub.com'"
    docker run -d -p 5002:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://hub.docker.com \
      --restart always \
      --name proxy-docker-hub.com \
      --volume proxy-docker-hub.com:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q proxy-registry.k8s.io) && (docker container ls -a | grep -q proxy-registry.k8s.io); then
    echo "🧮✅ Registry 'proxy-registry.k8s.io' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-registry.k8s.io'"
    docker run -d -p 5003:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://registry.k8s.io \
      --restart always \
      --name proxy-registry.k8s.io \
      --volume proxy-registry.k8s.io:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q proxy-gcr.io) && (docker container ls -a | grep -q proxy-gcr.io); then
    echo "🧮✅ Registry 'proxy-gcr.io' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-gcr.io'"
    docker run -d -p 5004:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://gcr.io \
      --restart always \
      --name proxy-gcr.io \
      --volume proxy-gcr.io:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q proxy-ghcr.io) && (docker container ls -a | grep -q proxy-ghcr.io); then
    echo "🧮✅ Registry 'proxy-ghcr.io' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-ghcr.io'"
    docker run -d -p 5005:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://ghcr.io \
      --restart always \
      --name proxy-ghcr.io \
      --volume proxy-ghcr.io:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q proxy-quay.io) && (docker container ls -a | grep -q proxy-quay.io); then
    echo "🧮✅ Registry 'proxy-quay.io' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'proxy-quay.io'"
    docker run -d -p 5006:5000 \
      -e REGISTRY_PROXY_REMOTEURL=https://quay.io \
      --restart always \
      --name proxy-quay.io \
      --volume proxy-quay.io:/var/lib/registry \
      registry:2
  fi

  if (docker volume ls | grep -q manifests) && (docker container ls -a | grep -q manifests); then
    echo "🧮✅ Registry 'manifests' already exists. Skipping..."
  else
    echo "🧮🔨 Creating registry 'manifests'"
    docker run -d -p 5050:5000 \
      --restart always \
      --name manifests \
      --volume manifests:/var/lib/registry \
      registry:2
  fi
  echo ""
}

function provision_cluster() {
  local cluster_name=${1}
  local docker_gateway_ip=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')
  if [[ "$OSTYPE" == "darwin"* ]]; then
    docker_gateway_ip="192.168.65.254"
  fi
  echo "⛴️ Provision ${cluster_name} cluster"
  talosctl cluster create \
    --name ${cluster_name} \
    --registry-mirror docker.io=http://$docker_gateway_ip:5001 \
    --registry-mirror hub.docker.com=http://$docker_gateway_ip:5002 \
    --registry-mirror registry.k8s.io=http://$docker_gateway_ip:5003 \
    --registry-mirror gcr.io=http://$docker_gateway_ip:5004 \
    --registry-mirror ghcr.io=http://$docker_gateway_ip:5005 \
    --registry-mirror quay.io=http://$docker_gateway_ip:5006 \
    --registry-mirror manifests=http://$docker_gateway_ip:5050 \
    --wait || {
    echo "🚨 Cluster creation failed. Exiting..."
    exit 1
  }
  talosctl config nodes 10.5.0.2 10.5.0.3 || {
    echo "🚨 Cluster configuration failed. Exiting..."
    exit 1
  }

  echo "🩹 Patch ${cluster_name} cluster"
  talosctl patch mc --patch @./../talos/cluster/rotate-server-certificates.yaml || {
    echo "🚨 Cluster patching failed. Exiting..."
    exit 1
  }

  add_sops_gpg_key || {
    echo "🚨 SOPS GPG key creation failed. Exiting..."
    exit 1
  }
  install_flux $cluster_name $docker_gateway_ip || {
    echo "🚨 Flux installation failed. Exiting..."
    exit 1
  }
  echo ""
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
  local docker_gateway_ip=${2}
  echo "🚀 Installing Flux"
  flux check --pre || {
    echo "🚨 Flux prerequisites check failed. Exiting..."
    exit 1
  }
  flux install || {
    echo "🚨 Flux installation failed. Exiting..."
    exit 1
  }
  local source_url="oci://$docker_gateway_ip:5050/${cluster_name}"
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
  install_dependencies || {
    echo "🚨 Dependencies installation failed. Exiting..."
    exit 1
  }
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
  ./verify-cluster.sh $cluster_name || {
    echo "🚨 Cluster verification failed. Exiting..."
    exit 1
  }
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐎 Print free CPU"
    top -bn2 | grep '%Cpu' | tail -1 | grep -P '(....|...) id,' | awk -v cores=$(nproc --all) '{print "CPU Usage: " 100-($8/cores) "%"}'
  fi

  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🧠 Print free memory in this format"
    free -m | awk 'NR==2{printf "Memory Usage: %s/%sMB (%.2f%%)\n", $3,$2,$3*100/$2 }'
  fi
}

main "homelab-docker"
