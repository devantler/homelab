start_time=$(date +%s)
kubectl -n flux-system wait kustomization/post-build --for=condition=ready --timeout=5m
echo "Time taken for post-build kustomization: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/infrastructure --for=condition=ready --timeout=5m
echo "Time taken for infrastructure kustomization: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/infrastructure-configs --for=condition=ready --timeout=5m
echo "Time taken for infrastructure-configs kustomization: $(($(date +%s) - $start_time)) seconds"

start_time=$(date +%s)
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m
echo "Time taken for apps kustomization: $(($(date +%s) - $start_time)) seconds"
