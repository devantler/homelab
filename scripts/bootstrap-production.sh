#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo " Set current cluster to 'homelab-production'"
kubectl config use-context 'homelab-production'

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
