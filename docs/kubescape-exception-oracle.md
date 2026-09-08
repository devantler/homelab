# Kubescape posture exception oracle

The Kubescape storage API holds raw posture findings. It does not apply the
platform's `ClusterSecurityException` resources, so a stored `failed` status is
not evidence that an exception is ineffective. Use the client-side oracle to
combine those raw findings with the generated exception artifact and explain
the decision for each workload/control pair.

The oracle is read-only. It changes neither the cluster nor the committed
exception resources.

The generated artifact maps the CR's `ignore` action to Kubescape's native
`disable` action. `alertOnly` acknowledges a finding while leaving it actionable.
Regenerate artifacts produced by older converters before using the oracle;
the reader rejects legacy `alertOnly`, mixed, missing, and unknown actions.

## Collect hydrated posture summaries

Kubescape strips `spec.controls` from LIST responses and ignores server-side
label selectors. Use LIST only to enumerate object identities, then GET every
object individually. Run this from the repository root with Bash:

```bash
set -euo pipefail

oracle_dir="$(mktemp -d)"
mkdir -p "${oracle_dir}/posture"

kubectl --context=admin@prod \
  get workloadconfigurationscansummaries -A -o json \
  | jq -r '.items[] | [.metadata.namespace, .metadata.name] | @tsv' \
  | while IFS=$'\t' read -r namespace name; do
      kubectl --context=admin@prod \
        get workloadconfigurationscansummaries "${name}" \
        --namespace "${namespace}" -o json \
        >"${oracle_dir}/posture/${namespace}__${name}.json"
    done

go run ./scripts/generate-kubescape-exceptions \
  -o "${oracle_dir}/exceptions.json"
```

The command fails closed if any supplied summary is still a stripped LIST
skeleton, has an incomplete workload identity, or carries malformed control
data.

## Explain every failed pair

Build the repeated posture arguments from the collected directory so the
command receives every hydrated object:

```bash
oracle_args=()
for file in "${oracle_dir}"/posture/*.json; do
  oracle_args+=( -posture "${file}" )
done

go run ./scripts/kubescape-backlog-bridge \
  -mode oracle \
  -exceptions "${oracle_dir}/exceptions.json" \
  "${oracle_args[@]}"
```

Each raw failed pair produces one deterministic, tab-separated row. The
`[TAB]` markers below make those delimiters visible:

```text
excepted[TAB]control=C-0016[TAB]component=app/Job/nightly[TAB]policies=batch-workloads
unexcepted[TAB]control=C-0016[TAB]component=app/Deployment/api[TAB]policies=-
```

`excepted` means at least one named policy matches both the control and the
component. `unexcepted` means the raw finding remains actionable. The component
identity comes from the `kubescape.io/workload-namespace`,
`kubescape.io/workload-kind`, and `kubescape.io/workload-name` labels. The
oracle does not parse identity from `wlid`.

The answer covers only the objects supplied to the command. A cluster-wide
statement requires the complete collection loop above to finish successfully.

## Prove the oracle discriminates

A policy-specific verification removes that policy from a local copy of the
artifact and evaluates the same raw inputs again. This does not alter the
deployed exception:

```bash
policy=controller-rbac
jq -e --arg policy "${policy}" \
  'any(.[]; .name == $policy)' \
  "${oracle_dir}/exceptions.json" >/dev/null

jq --arg policy "${policy}" \
  '[.[] | select(.name != $policy)]' \
  "${oracle_dir}/exceptions.json" \
  >"${oracle_dir}/exceptions-without-${policy}.json"

go run ./scripts/kubescape-backlog-bridge \
  -mode oracle \
  -exceptions "${oracle_dir}/exceptions-without-${policy}.json" \
  "${oracle_args[@]}"
```

For a pair covered only by that policy, the row changes from `excepted` with
the policy name to `unexcepted` with `policies=-`. If no row changes, the
supplied findings do not demonstrate that policy's effect; do not infer that
the exception works from an unchanged aggregate count.
