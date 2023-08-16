#!/bin/bash

echo "🚀 Provisioning K3s development cluster"
k3d cluster create -c cluster-configs/cluster-development.yaml

echo -e "\n"

echo "🚀 Provisioning K3s production cluster"
k3d cluster create -c cluster-configs/cluster-production.yaml
