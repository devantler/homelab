## METHODS
function test_helm_releases() {
    local releases=()
    local release_file=$(yq eval '.resources[] | select(. == "*release.yaml" )' "$1"/kustomization.yaml)
    if [[ -n $release_file ]]; then
        releases+=$(yq eval '.metadata.name' "$1"/$release_file)
        namespace=$(yq eval '.metadata.namespace' "$1"/$release_file)
        name=helmrelease/$(yq eval '.metadata.name' "$1"/$release_file)
        kubectl -n "$namespace" wait "$name" --for=condition=ready --timeout=5m
    fi

    local subdirectories=$(yq eval '.resources[] | select(. != "*.yaml" )' "$1"/kustomization.yaml)
    if [[ -n $subdirectories ]]; then
        for subdirectory in $subdirectories; do
            test_helm_releases "$1/$subdirectory"
        done
    fi
}

## MAIN
if [ -z "$1" ]; then
    echo "Error: 'environment' argument not set"
    exit 1
fi

environment=$1

infrastructure_path=$(yq eval -N '.spec.path' k8s/clusters/$environment/infrastructure.yaml | head -n 1)
infrastructure_configs_path=$(yq eval -N '.spec.path' k8s/clusters/$environment/infrastructure.yaml | tail -n 1)
apps_path=$(yq eval '.spec.path' k8s/clusters/$environment/apps.yaml)

for path in $apps_path $infrastructure_path $infrastructure_configs_path; do
    test_helm_releases $path
done
