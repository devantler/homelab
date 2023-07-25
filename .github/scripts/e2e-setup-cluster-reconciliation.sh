if [ -z "$1" ]
    then
        echo "Error: 'repository_url' argument not set"
        exit 1
fi

if [ -z "$2" ]
    then
        echo "Error: 'branch_name' argument not set"
        exit 1
fi

repository_url=$1
branch_name=$2

flux create source git flux-system \
        --url=$repository_url \
        --branch=$branch_name \
        --ignore-paths="k8s/clusters/**/flux-system/" \
        flux create kustomization flux-system \
        --source=flux-system \
        --path=./k8s/clusters/development
