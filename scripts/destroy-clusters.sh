#!/bin/bash

function destroy_cluster() {
  local cluster_name=${1}
  echo "🔥 Delete ${cluster_name} cluster"
  talosctl cluster destroy --name ${cluster_name} --force
  talosctl config context default
  talosctl config remove ${cluster_name} -y
  kubectl config delete-context admin@${cluster_name}
  kubectl config delete-cluster ${cluster_name}
  kubectl config delete-user admin@${cluster_name}
  kubectl config unset current-context
}

function main() {
  pushd $(dirname "$0") >/dev/null
  local cluster_name=${1}
  destroy_cluster $cluster_name
}

main "homelab-docker"
