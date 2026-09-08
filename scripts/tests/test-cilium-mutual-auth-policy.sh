#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly production_overlay_dirs=(
  "${root_dir}/k8s/providers/hetzner/infrastructure/controllers"
  "${root_dir}/k8s/providers/hetzner/infrastructure"
  "${root_dir}/k8s/providers/hetzner/apps"
)

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v kubectl >/dev/null 2>&1 || fail 'kubectl is required to render the production workload overlays'
command -v yq >/dev/null 2>&1 || fail 'yq v4 is required to inspect the rendered Cilium policies'

rendered="$({
  for overlay_dir in "${production_overlay_dirs[@]}"; do
    kubectl kustomize "${overlay_dir}" || exit 1
    printf '%s\n' '---'
  done
})" || fail 'every production workload overlay must render successfully'

broad_authenticated_policies="$({
  printf '%s\n' "${rendered}" |
    yq e -r '
      select(
        (.kind == "CiliumNetworkPolicy") or
        (.kind == "CiliumClusterwideNetworkPolicy")
      ) |
      {
        "name": .metadata.name,
        "rules": (
          (.spec.ingress // []) +
          [(.specs // [])[] | (.ingress // [])[]]
        )
      } |
      {
        "name": .name,
        "broadRules": [
          .rules[] |
          select(.authentication.mode == "required") |
          select(
            (
              [
                (.fromEndpoints // [])[] |
                select(
                  ((((.matchLabels // {}) | length) == 0) and
                  (((.matchExpressions // []) | length) == 0))
                )
              ] |
              length > 0
            ) or
            (
              (((.fromEndpoints // []) | length) == 0) and
              (((.fromEntities // []) | length) == 0) and
              (((.fromCIDR // []) | length) == 0) and
              (((.fromCIDRSet // []) | length) == 0) and
              (((.fromNodes // []) | length) == 0) and
              (((.fromServices // []) | length) == 0) and
              (((.fromRequires // []) | length) == 0)
            )
          )
        ]
      } |
      select((.broadRules | length) > 0) |
      .name
    ' -
})" || fail 'the rendered Cilium policy inspection must succeed'

if [[ -n "${broad_authenticated_policies}" ]]; then
  fail "mutual-auth rules must not allow ingress from every endpoint: ${broad_authenticated_policies}"
fi

required_authentication_policies="$({
  printf '%s\n' "${rendered}" |
    yq e -r '
      select(
        (.kind == "CiliumNetworkPolicy") or
        (.kind == "CiliumClusterwideNetworkPolicy")
      ) |
      {
        "name": .metadata.name,
        "rules": (
          (.spec.ingress // []) +
          [(.specs // [])[] | (.ingress // [])[]]
        )
      } |
      select([.rules[] | select(.authentication.mode == "required")] | length > 0) |
      .name
    ' -
})" || fail 'the rendered Cilium authentication consumer inspection must succeed'

orphaned_authentication_releases="$({
  printf '%s\n' "${rendered}" |
    yq e -r '
      select(
        (.kind == "HelmRelease") and
        (.metadata.name == "cilium") and
        (.metadata.namespace == "kube-system")
      ) |
      select(
        (.spec.values.authentication.enabled == true) or
        (.spec.values.authentication.mutual.spire.enabled == true)
      ) |
      .metadata.name
    ' -
})" || fail 'the rendered Cilium authentication configuration inspection must succeed'

if [[ -z "${required_authentication_policies}" && -n "${orphaned_authentication_releases}" ]]; then
  fail 'Cilium authentication and SPIRE must be disabled when no required-authentication policy is rendered'
fi

enabled_authentication_releases="$({
  printf '%s\n' "${rendered}" |
    yq e -r '
      select(
        (.kind == "HelmRelease") and
        (.metadata.name == "cilium") and
        (.metadata.namespace == "kube-system")
      ) |
      select(
        (.spec.values.authentication.enabled == true) and
        (.spec.values.authentication.mutual.spire.enabled == true)
      ) |
      .metadata.name
    ' -
})" || fail 'the rendered Cilium authentication activation inspection must succeed'

if [[ -n "${required_authentication_policies}" && -z "${enabled_authentication_releases}" ]]; then
  fail 'Cilium authentication and SPIRE must be enabled when a required-authentication policy is rendered'
fi

spire_vpas="$(printf '%s\n' "${rendered}" | yq e -r '
  select(.kind == "VerticalPodAutoscaler" and .metadata.namespace == "kube-system") |
  select(.spec.targetRef.name == "spire-agent" or .spec.targetRef.name == "spire-server") |
  .metadata.name
' -)" || fail 'the rendered SPIRE autoscaler inspection must succeed'

if [[ -z "${enabled_authentication_releases}" && -n "${spire_vpas}" ]]; then
  fail "disabled SPIRE must not retain autoscalers for absent workloads: ${spire_vpas}"
fi

printf 'PASS: rendered production Cilium authentication preserves allow-lists and is disabled or consumed\n'
