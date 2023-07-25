flux create source git flux-system \
--url=${{ github.event.repository.html_url }} \
--branch=${{ steps.extract_branch.outputs.branch }} \
--ignore-paths="./k8s/clusters/development/flux-system/" \
--ignore-paths="./k8s/clusters/production/flux-system/"
flux create kustomization flux-system \
--source=flux-system \
--path=./k8s/clusters/development