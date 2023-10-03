#!/bin/bash

pushd $(dirname "$0") >/dev/null

branch=$(git rev-parse --abbrev-ref HEAD)

echo "🔥 Destroying existing local Kubernetes cluster"
k3d cluster delete cluster-local

echo "🚀 Provisioning local Kubernetes cluster"
k3d cluster create cluster-local --config k3d-config.yaml

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/local --personal --branch=$branch
