#!/usr/bin/env bash

set -o errexit
set -o pipefail

pushd "$(dirname "$0")/.." >/dev/null

# mirror kustomize-controller build options
kustomize_flags=("--load-restrictor=LoadRestrictionsNone")
kustomize_config="kustomization.yaml"

# skip Kubernetes Secrets due to SOPS fields failing validation
kubeconform_flags=("-skip=Secret")
kubeconform_config=("-strict" "-ignore-missing-schemas" "-schema-location" "default" "-schema-location" "/tmp/flux-crd-schemas" "-verbose")

echo "🔍 INFO - Downloading Flux OpenAPI schemas"
mkdir -p /tmp/flux-crd-schemas/master-standalone-strict
curl -sL https://github.com/fluxcd/flux2/releases/latest/download/crd-schemas.tar.gz | tar zxf - -C /tmp/flux-crd-schemas/master-standalone-strict

echo "🔍 INFO - Validating files"
find . -type f -name '*.yaml' -print0 | while IFS= read -r -d $'\0' file; do
  echo "Validating $file"
  yq e 'true' "$file" >/dev/null
done

echo "🔍 INFO - Validating clusters"
find ./k8s/clusters -maxdepth 2 -type f -name '*.yaml' -print0 | while IFS= read -r -d $'\0' file; do
  kubeconform "${kubeconform_flags[@]}" "${kubeconform_config[@]}" "${file}"
  if [[ ${PIPESTATUS[0]} != 0 ]]; then
    exit 1
  fi
done

echo "🔍 INFO - Validating kustomize overlays"
find . -type f -name $kustomize_config -print0 | while IFS= read -r -d $'\0' file; do
  echo "🔍 INFO - Validating kustomization ${file/%$kustomize_config/}"
  kustomize build "${file/%$kustomize_config/}" "${kustomize_flags[@]}" |
    kubeconform "${kubeconform_flags[@]}" "${kubeconform_config[@]}"
  if [[ ${PIPESTATUS[0]} != 0 ]]; then
    exit 1
  fi
done
echo ""
