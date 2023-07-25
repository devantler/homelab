kubectl -n flux-system wait kustomization/infra-controllers --for=condition=ready --timeout=5m
kubectl -n flux-system wait kustomization/apps --for=condition=ready --timeout=5m
