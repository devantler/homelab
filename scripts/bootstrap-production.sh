#!/bin/bash

echo "☸️  Provisioning Kubernetes cluster"
microk8s install -y

echo "🔐 Adding SOPS GPG key"
gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
kubectl create secret generic sops-gpg \
--namespace=flux-system \
--from-file=sops.asc=/dev/stdin

echo "🔼☸️  Upgrading Kubernetes cluster"
kubectl drain microk8s-vm --ignore-daemonsets
multipass exec microk8s-vm -- sudo snap refresh microk8s --channel latest/stable
kubectl uncordon microk8s-vm

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/production --personal --branch=main
