branch=$(git rev-parse --abbrev-ref HEAD)

echo "🚀 Provisioning local Kubernetes cluster"
k3d cluster create cluster-local --config k3d-config.yaml

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap git --url=ssh://git@github.com/energinet-digitalisering/infrastructure.git --private-key-file=$HOME/.ssh/energinet_admin --password=$ENERGINET_DIGITAL_ADMIN_SSH_KEY_PASSWORD --path=k8s/clusters/local --branch=$branch
