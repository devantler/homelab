#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo " Set current cluster to 'admin@homelab-production'"
kubectl config use-context 'admin@homelab-production'

echo "🔧 Patch machine-config on all nodes"
sops -d talos-configs/production/machine-config.talos-rpi-1.sops.yaml | talosctl -n 10.0.0.201 apply-config -f /dev/stdin
sops -d talos-configs/production/machine-config.talos-rpi-2.sops.yaml | talosctl -n 10.0.0.202 apply-config -f /dev/stdin
sops -d talos-configs/production/machine-config.talos-rpi-3.sops.yaml | talosctl -n 10.0.0.203 apply-config -f /dev/stdin

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
    --path=./k8s/clusters/production/.bootstrap \
    --personal \
    --branch=main
