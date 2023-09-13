if [ -z "$1" ]; then
    echo "Error: 'repository_url' argument not set"
    exit 1
fi

if [ -z "$2" ]; then
    echo "Error: 'branch_name' argument not set"
    exit 1
fi

if [ -z "$3" ]; then
    echo "Error: 'environment' argument not set"
    exit 1
fi

if [ -z "$4" ]; then
    echo "Error: 'github_actor' argument not set"
    exit 1
fi

if [ -z "$5" ]; then
    echo "Error: 'github_token' argument not set"
    exit 1
fi

repository_url=$1
branch_name=$2
environment=$3
github_actor=$4
github_token=$5

flux create source git flux-system \
    --url=$repository_url \
    --branch=$branch_name \
    --username=$github_actor \
    --password=$github_token \
    --ignore-paths="k8s/clusters/**/flux-system/"

flux create kustomization flux-system \
    --source=flux-system \
    --path=./k8s/clusters/$environment
