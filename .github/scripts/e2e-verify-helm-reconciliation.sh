helmreleases=$(find k8s -type f -name "release.yaml" | grep -E "k8s\/(.+\/)?(development|base)\/" | sort -u)
if [[ -z "$helmreleases" ]]; then
    echo "No helmreleases found in k8s/**/development or k8s/**/base"
else
    for helmrelease in $helmreleases; do
        namespace=$(yq eval '.metadata.namespace' "$helmrelease")
        release_name=$(yq eval '.metadata.name' "$helmrelease")
        kubectl -n "$namespace" wait "$release_name" --for=condition=ready --timeout=5m
    done
fi
