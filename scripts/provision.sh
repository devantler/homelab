#!/bin/bash

echo "🚀 Provision K3s development cluster"
k3d cluster create -c cluster-configs/cluster-development.yaml

echo "🚀 Provision K3s production cluster"
k3d cluster create -c cluster-configs/cluster-production.yaml
