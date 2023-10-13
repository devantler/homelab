start_time=$(date +%s)
kubectl -n flux-system wait kustomization/variables --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/variables: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/infrastructure --for=condition=ready --timeout=10m || exit 1
echo "Time taken for kustomization/infrastructure: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/infrastructure-configs --for=condition=ready --timeout=1m || exit 1
echo "Time taken for kustomization/infrastructure-configs: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m || exit 1
echo "Time taken for kustomization/apps: $(($(date +%s) - $start_time)) seconds"
