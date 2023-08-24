branch=$(git rev-parse --abbrev-ref HEAD)

echo "🚀 Provisioning local Kubernetes cluster"
k3d cluster create cluster-local --config k3d-config.yaml

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/local --personal --branch=$branch
