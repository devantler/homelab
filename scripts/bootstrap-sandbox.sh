#!/bin/bash

pushd $(dirname "$0") >/dev/null

branch=$(git rev-parse --abbrev-ref HEAD)

echo "🔥 Destroying existing sandbox Kubernetes cluster"
talosctl cluster destroy

echo "🚀 Provisioning sandbox Kubernetes cluster"
talosctl cluster create

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/sandbox --personal --branch=$branch
