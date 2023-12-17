echo "✅ Verifying cluster..."
global_start_time=$(date +%s)
echo "Starting reconciliation of kustomization/flux-system..."
if [[ $(kubectl -n flux-system get kustomization/variables -o jsonpath='{.metadata.name}' 2>/dev/null) == "" ]]; then
  echo "kustomization/variables does not exist. Skipping..."
else
  start_time=$(date +%s)
  echo "Starting reconciliation of kustomization/variables..."
  kubectl -n flux-system wait kustomization/variables --for=condition=ready --timeout=1m || exit 1
  echo "Time taken for kustomization/variables: $(($(date +%s) - $start_time)) seconds"
fi

if [[ $(kubectl -n flux-system get kustomization/infrastructure-services -o jsonpath='{.metadata.name}' 2>/dev/null) == "" ]]; then
  echo "kustomization/infrastructure-services does not exist. Skipping..."
else
  start_time=$(date +%s)
  echo "Starting reconciliation of kustomization/infrastructure-services..."
  kubectl -n flux-system wait kustomization/infrastructure-services --for=condition=ready --timeout=5m || exit 1
  echo "Time taken for kustomization/infrastructure-services: $(($(date +%s) - $start_time)) seconds"
fi

if [[ $(kubectl -n flux-system get kustomization/infrastructure-configs -o jsonpath='{.metadata.name}' 2>/dev/null) == "" ]]; then
  echo "kustomization/infrastructure-configs does not exist. Skipping..."
else
  start_time=$(date +%s)
  echo "Starting reconciliation of kustomization/infrastructure-configs..."
  kubectl -n flux-system wait kustomization/infrastructure-configs --for=condition=ready --timeout=1m || exit 1
  echo "Time taken for kustomization/infrastructure-configs: $(($(date +%s) - $start_time)) seconds"
fi

if [[ $(kubectl -n flux-system get kustomization/apps -o jsonpath='{.metadata.name}' 2>/dev/null) == "" ]]; then
  echo "kustomization/apps does not exist. Skipping..."
else
  start_time=$(date +%s)
  echo "Starting reconciliation of kustomization/apps..."
  kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m || exit 1
  echo "Time taken for kustomization/apps: $(($(date +%s) - $start_time)) seconds"
fi

kubectl -n flux-system wait kustomization/flux-system --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/flux-system: $(($(date +%s) - $global_start_time)) seconds"
echo "✅ Cluster verified successfully"
