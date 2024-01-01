#!/bin/bash

pushd $(dirname "$0") >/dev/null
./validate-cluster.sh || {
  echo "🚨 Cluster validation failed. Exiting..."
  exit 1
}
pushd $(dirname "$0") >/dev/null

TIME=$(date +%s)
CLUSTER_NAME=${1}
echo "🗳️ Push OCI artifact to Docker"
flux push artifact oci://localhost:5050/${CLUSTER_NAME}:$TIME \
  --path=./../k8s \
  --source="$(git config --get remote.origin.url)" \
  --revision="$(git branch --show-current)@sha1:$(git rev-parse HEAD)"
flux tag artifact oci://localhost:5050/${CLUSTER_NAME}:$TIME \
  --tag latest
echo
