helm_releases=$(find k8s -type f -name "release.yaml" | grep -E "k8s\/(.+\/)?(base)\/" | sort -u)
if [[ -z "$helm_releases" ]]; then
    echo "No Helm releases found in k8s/**/base"
else
    for helm_release in $helm_releases; do
        namespace=$(yq eval '.metadata.namespace' "$helm_release")
        release_name=helmrelease/$(yq eval '.metadata.name' "$helm_release")
        kubectl -n "$namespace" wait "$release_name" --for=condition=ready --timeout=5m
    done
fi
