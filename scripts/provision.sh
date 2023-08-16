#!/bin/bash

echo "🚀 Provisioning K3s development cluster"
k3d cluster create -c cluster-configs/cluster-development.yaml
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --branch=main --path=./k8s/clusters/development --personal

echo -e "\n"

echo "🚀 Provisioning K3s production cluster"
k3d cluster create -c cluster-configs/cluster-production.yaml
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --branch=main --path=./k8s/clusters/production --personal
