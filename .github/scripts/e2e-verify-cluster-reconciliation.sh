global_start_time=$(date +%s)
echo "Starting reconciliation of kustomization/flux-system..."
start_time=$(date +%s)
echo "Starting reconciliation of kustomization/variables..."
kubectl -n flux-system wait kustomization/variables --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/variables: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
echo "Starting reconciliation of kustomization/infrastructure..."
kubectl -n flux-system wait kustomization/infrastructure --for=condition=ready --timeout=5m || exit 1
echo "Time taken for kustomization/infrastructure: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
echo "Starting reconciliation of kustomization/infrastructure-configs..."
kubectl -n flux-system wait kustomization/infrastructure-configs --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/infrastructure-configs: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
echo "Starting reconciliation of kustomization/apps..."
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m || exit 1
echo "Time taken for kustomization/apps: $(($(date +%s) - $start_time)) seconds"

kubectl -n flux-system wait kustomization/flux-system --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/flux-system: $(($(date +%s) - $global_start_time)) seconds"
