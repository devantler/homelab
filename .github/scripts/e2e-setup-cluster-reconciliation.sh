repository_url=$1
branch_name=$2

flux create source git flux-system \
    --url=$repository_url \
    --branch=$branch_name \
    --ignore-paths="k8s/clusters/**/flux-system/" \
    flux create kustomization flux-system \
    --source=flux-system \
    --path=./k8s/clusters/development
