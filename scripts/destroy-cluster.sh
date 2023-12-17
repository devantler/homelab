#!/bin/bash

function destroy_cluster() {
  local cluster_name=${1}
  echo "🔥 Delete ${cluster_name} cluster"
  talosctl cluster destroy --name ${cluster_name} --force
  talosctl config context default
  talosctl config remove ${cluster_name} -y
  kubectl config unset current-context
  if [[ $(kubectl config get-contexts -o name | grep admin@${cluster_name}) ]]; then
    kubectl config delete-context admin@${cluster_name}
  fi
  if [[ $(kubectl config get-clusters | grep ${cluster_name}) ]]; then
    kubectl config delete-cluster ${cluster_name}
  fi
  if [[ $(kubectl config get-users | grep admin@${cluster_name}) ]]; then
    kubectl config delete-user admin@${cluster_name}
  fi
}

function main() {
  pushd $(dirname "$0") >/dev/null
  local cluster_name=${1}
  destroy_cluster $cluster_name
  echo ""
}

main "homelab-docker"
