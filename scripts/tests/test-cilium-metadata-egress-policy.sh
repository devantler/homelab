#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly policy_name="deny-workload-instance-metadata-egress"
readonly coredns_policy_name="allow-coredns-control-plane-egress"
readonly deleted_policy="${root_dir}/k8s/providers/hetzner/infrastructure/controllers/cilium/cilium-clusterwide-network-policy.yaml"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
readonly tmp_dir
trap 'rm -rf "${tmp_dir}"' EXIT
readonly prod_render="${tmp_dir}/prod.yaml"
readonly rendered_policy="${tmp_dir}/policy.yaml"
readonly policy_json="${tmp_dir}/policy.json"
readonly rendered_coredns_policy="${tmp_dir}/coredns-policy.yaml"
readonly controllers_layer_render="${tmp_dir}/controllers-layer.yaml"
readonly controllers_render="${tmp_dir}/controllers.yaml"
readonly crossplane_policy="${tmp_dir}/crossplane-policy.yaml"
readonly local_render="${tmp_dir}/local.yaml"

kubectl kustomize "${root_dir}/k8s/providers/hetzner/infrastructure" >"${prod_render}" ||
  fail 'the production Hetzner infrastructure build did not render'
policy_count="$(
  yq ea \
    "[select(.kind == \"CiliumClusterwideNetworkPolicy\" and .metadata.name == \"${policy_name}\")] | length" \
    "${prod_render}"
)" || fail 'the production policy count could not be read'
[[ "${policy_count}" == 1 ]] ||
  fail "the production build rendered ${policy_count} metadata-egress policies instead of one"
yq ea \
  "select(.kind == \"CiliumClusterwideNetworkPolicy\" and .metadata.name == \"${policy_name}\")" \
  "${prod_render}" >"${rendered_policy}" ||
  fail 'the production metadata-egress policy could not be extracted'
kubectl kustomize "${root_dir}/k8s/providers/hetzner/infrastructure/controllers" >"${controllers_layer_render}" ||
  fail 'the production Hetzner controllers build did not render'
coredns_policy_count="$(
  yq ea \
    "[select(.kind == \"CiliumNetworkPolicy\" and .metadata.namespace == \"kube-system\" and .metadata.name == \"${coredns_policy_name}\")] | length" \
    "${controllers_layer_render}"
)" || fail 'the production CoreDNS egress policy count could not be read'
[[ "${coredns_policy_count}" == 1 ]] ||
  fail "the production build rendered ${coredns_policy_count} CoreDNS egress policies instead of one"
yq ea \
  "select(.kind == \"CiliumNetworkPolicy\" and .metadata.namespace == \"kube-system\" and .metadata.name == \"${coredns_policy_name}\")" \
  "${controllers_layer_render}" >"${rendered_coredns_policy}" ||
  fail 'the production CoreDNS egress policy could not be extracted'

kubectl kustomize "${root_dir}/k8s/providers/hetzner/infrastructure/controllers/crossplane" >"${controllers_render}" ||
  fail 'the production Crossplane controller build did not render'
yq ea \
  'select(.kind == "CiliumNetworkPolicy" and .metadata.namespace == "crossplane-system" and .metadata.name == "allow-crossplane")' \
  "${controllers_render}" >"${crossplane_policy}" ||
  fail 'the Crossplane egress policy could not be extracted'

kubectl kustomize "${root_dir}/k8s/providers/docker/infrastructure" >"${local_render}" ||
  fail 'the local Docker infrastructure build did not render'
if grep -Fq -- "name: ${policy_name}" "${local_render}"; then
  fail 'the Hetzner metadata policy leaked into the local Docker build'
fi

[[ ! -e "${deleted_policy}" ]] ||
  fail 'the deliberately deleted Cilium mutual-auth policy file was restored'

yq -e '.apiVersion == "cilium.io/v2" and .kind == "CiliumClusterwideNetworkPolicy"' \
  "${rendered_policy}" >/dev/null ||
  fail 'the rendered control is not a CiliumClusterwideNetworkPolicy'
yq -o=json '.' "${rendered_policy}" >"${policy_json}"
# Exercise selector semantics on the rendered policy, including every missing
# and mismatched identity label. NotIn matches a missing key; Exists does not.
# The expected boundary is independent of how many deny rules implement it.
jq -er '
  def rules: if has("specs") then .specs else [.spec] end;
  def matches($selector; $labels):
    all(($selector.matchLabels // {} | to_entries)[];
      $labels[.key] == .value) and
    all(($selector.matchExpressions // [])[];
      . as $e |
      if .operator == "Exists" then $labels | has($e.key)
      elif .operator == "NotIn" then
        ($e.values | index($labels[$e.key])) == null
      elif .operator == "In" then
        ($e.values | index($labels[$e.key])) != null
      else error("unsupported selector operator") end);
  . as $policy |
  [ ["kube-system", "tenant-example", "crossplane-system", null][] as $ns |
    ["hcloud-csi", "other-app", null][] as $name |
    ["hcloud-csi", "other-instance", null][] as $instance |
    ["node", "controller", null][] as $component |
    {
      labels: ({
        "k8s:io.kubernetes.pod.namespace": $ns,
        "k8s:app.kubernetes.io/name": $name,
        "k8s:app.kubernetes.io/instance": $instance,
        "k8s:app.kubernetes.io/component": $component
      } | with_entries(select(.value != null))),
      denied: ($ns != null and $ns != "crossplane-system" and
        ([$ns, $name, $instance, $component] !=
          ["kube-system", "hcloud-csi", "hcloud-csi", "node"]))
    }
  ] as $cases |
  [$cases[] | . as $case |
    ($policy | rules | any(.[]; matches(.endpointSelector; $case.labels))) as $selected |
    select($selected != .denied) | {labels, expectedDenied: .denied, selected: $selected}
  ] as $failures |
  if ($cases | length) != 108 then error("incomplete selector matrix")
  elif ($failures | length) > 0 then error($failures | tojson)
  else "PASS: all 108 metadata selector cases preserve the exact CSI node exception" end
' "${policy_json}" || fail 'the metadata selector boundary does not match the infrastructure exception'

jq -e '
  (has("spec") != has("specs")) and
  (
  (if has("specs") then .specs else [.spec] end) as $rules |
  ($rules | length) > 0 and all($rules[];
    (keys == ["egressDeny", "enableDefaultDeny", "endpointSelector"]) and
    .egressDeny == [{"toCIDR": ["169.254.169.254/32"]}] and
    .enableDefaultDeny == {"egress": false})
  )
' "${policy_json}" >/dev/null ||
  fail 'every metadata rule must deny only the metadata address without enabling default-deny or selecting hosts'

# A policy carrying only egressDeny rules puts every selected endpoint into
# default-deny egress: the CRD defaults enableDefaultDeny to true for each
# direction that has rules. This policy carries no egress allow rules, so leaving the field
# unset silently revokes egress from every workload that has no allow policy
# of its own. Pin it off so the deny stays a deny.
# The per-rule assertion above keeps it off in every selector branch.

yq -e '(.spec.endpointSelector | keys | length) == 1 and
  (.spec.endpointSelector.matchLabels | keys | length) == 1 and
  .spec.endpointSelector.matchLabels."k8s-app" == "kube-dns" and
  (.spec.egress | length) == 2 and
  ([.spec.egress[] |
    select((keys | length) == 2 and
      (.toEntities | length) == 1 and
      .toEntities[0] == "host" and
      (.toPorts | length) == 1 and
      (.toPorts[0].ports | length) == 2 and
      ([.toPorts[0].ports[] |
        select(.port == "53" and (.protocol == "UDP" or .protocol == "TCP"))] | length) == 2)] | length) == 1 and
  ([.spec.egress[] |
    select((keys | length) == 2 and
      (.toEntities | length) == 1 and
      .toEntities[0] == "kube-apiserver" and
      (.toPorts | length) == 1 and
      (.toPorts[0].ports | length) == 1 and
      .toPorts[0].ports[0].port == "6443" and
      .toPorts[0].ports[0].protocol == "TCP")] | length) == 1 and
  (.spec | has("egressDeny") == false)' \
  "${rendered_coredns_policy}" >/dev/null ||
  fail 'CoreDNS must retain only host DNS and Kubernetes API egress while the metadata deny selects it'

yq -e '(.spec.egressDeny | length) == 1 and
  (.spec.egressDeny[0] | keys | length) == 1 and
  (.spec.egressDeny[0].toCIDR | length) == 1 and
  .spec.egressDeny[0].toCIDR[0] == "169.254.169.254/32"' \
  "${crossplane_policy}" >/dev/null ||
  fail 'the existing Crossplane policy must carry the same exact metadata deny'

printf 'PASS: production preserves workload metadata isolation and the CSI node exception\n'
