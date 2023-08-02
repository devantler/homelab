kubectl -n flux-system wait kustomization/infrastructure --for=condition=ready --timeout=2m
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=2m
