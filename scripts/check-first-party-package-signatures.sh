#!/usr/bin/env bash
# Check proposed Crossplane package images before merge (#3425). These are
# rendered from this revision, not obtained from already-running Pods. The
# broader Helm/container inventory remains a separate part of that issue.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rendered=""
rules=talos/cluster/verify-first-party-images.yaml
policy=k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || {
    echo 'expected --rendered PATH, --rules PATH or --policy PATH' >&2
    exit 2
  }
  case "$1" in
    --rendered) rendered="$2" ;;
    --rules) rules="$2" ;;
    --policy) policy="$2" ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift 2
done

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
if [[ -z "$rendered" ]]; then
  rendered="$scratch/rendered.yaml"
  # Flux reconciles these layers separately; building clusters/prod alone
  # produces Flux Kustomizations rather than the Provider objects they apply.
  for layer in k8s/clusters/prod k8s/clusters/prod/bootstrap \
    k8s/providers/hetzner/infrastructure/controllers \
    k8s/providers/hetzner/infrastructure k8s/providers/hetzner/apps; do
    if ! kubectl kustomize "$layer" >>"$rendered"; then
      echo "UNKNOWN: could not render $layer" >&2
      exit 1
    fi
    printf '\n---\n' >>"$rendered"
  done
fi
go run ./scripts/collect-first-party-packages <"$rendered" >"$scratch/packages.json"
jq -er '.images[]' "$scratch/packages.json" >"$scratch/images.txt"
# Kyverno's CLI needs separate resources; a Kubernetes List panics in its
# fake-client setup. JSON objects are valid YAML documents, with no re-encoding
# of image references or regexes needed.
jq -r '.pods[] | "---\n" + tojson' "$scratch/packages.json" >"$scratch/pods.yaml"
count="$(jq -er '.images | length' "$scratch/packages.json")"
policy_name="$(yq -er '.metadata.name' "$policy")"
# The pinned Kyverno CLI has no Kubernetes Secret lister. Replace only its
# registry-credential transport with the default Docker provider; leave image
# selection, identities and validation expressions exactly as deployed.
yq 'del(.spec.credentials.secrets) | .spec.credentials.providers = ["default"]' \
  "$policy" >"$scratch/offline-policy.yaml"
policy="$scratch/offline-policy.yaml"

# Check every proposed package against the supplied Talos rules and expected
# PASS/FAIL verdict. Return nonzero for missing verdicts or inconsistent status.
inventory() {
  local rule_file="$1" verdict="$2" status=0
  bash scripts/inventory-first-party-image-signatures.sh --rules "$rule_file" \
    --images "$scratch/images.txt" >"$scratch/inventory.tsv" || status=$?
  cat "$scratch/inventory.tsv"
  # The inventory skips unmatched references. Its success alone is therefore
  # insufficient: every proposed package must have an explicit verdict.
  if ! awk -F '\t' -v expected="$count" -v verdict="$verdict" \
    '$1 == verdict { n++ } END { exit n != expected }' "$scratch/inventory.tsv"; then
    echo "UNKNOWN: expected $count Talos $verdict verdicts; missing or unproven verification" >&2
    return 1
  fi
  if [[ "$verdict" == PASS ]]; then
    [[ "$status" -eq 0 ]]
  else
    [[ "$status" -eq 1 ]]
  fi
}

# Check every synthetic Pod against the supplied Kyverno policy and expected
# pass/fail verdict. Return nonzero for incomplete reports or inconsistent status.
admission() {
  local policy_file="$1" verdict="$2" status=0
  kyverno apply "$policy_file" --resource "$scratch/pods.yaml" --registry \
    --warn-no-pass --warn-exit-code 1 --policy-report --output-format json \
    >"$scratch/report.json" 2>"$scratch/kyverno.log" || status=$?
  # A skipped policy or empty report can exit successfully. Require precisely
  # one verdict for each synthetic Pod, from this ImageValidatingPolicy. JSON
  # parsing/registry/engine errors remain UNKNOWN, never an apparent refusal.
  if ! jq -e --arg verdict "$verdict" --arg policy "$policy_name" \
    --slurpfile packages "$scratch/packages.json" '
      (.results | length) == ($packages[0].pods | length) and
      all(.results[]; .source == "KyvernoImageValidatingPolicy" and
        .policy == $policy and .result == $verdict and
        (.resources | length) == 1 and
        .resources[0].kind == "Pod" and .resources[0].apiVersion == "v1") and
      ([.results[].resources[] | .namespace + "/" + .name] | sort) ==
      ([$packages[0].pods[].metadata | .namespace + "/" + .name] | sort)
    ' "$scratch/report.json" >/dev/null; then
    echo "UNKNOWN: Kyverno did not produce $count explicit $verdict verdicts (exit $status)" >&2
    # Preserve the engine's reason on failure; otherwise a registry/CLI error
    # is indistinguishable from a report format change on another runner.
    jq '{summary, results: [.results[] | {source, policy, result, message}]}' \
      "$scratch/report.json" >&2 || true
    head -n 40 "$scratch/kyverno.log" >&2
    return 1
  fi
  if [[ "$verdict" == pass ]]; then
    [[ "$status" -eq 0 ]]
  else
    [[ "$status" -ne 0 ]]
  fi
}

inventory "$rules" PASS
admission "$policy" pass

# Both engines must refuse a well-formed but impossible signing identity.
# Read rules from the proposed manifests; never copy production regexes here.
export PACKAGE_WRONG_SUBJECT='^https://github\.com/devantler-tech/NOT-A-REAL-REPO/.*$'
yq '.rules[].keyless.subjectRegex = strenv(PACKAGE_WRONG_SUBJECT)' "$rules" >"$scratch/wrong-rules.yaml"
yq '.spec.attestors[].cosign.keyless.identities[].subjectRegExp = strenv(PACKAGE_WRONG_SUBJECT)' \
  "$policy" >"$scratch/wrong-policy.yaml"
if ! inventory "$scratch/wrong-rules.yaml" FAIL; then
  echo 'UNKNOWN: Talos negative control did not prove a mismatch' >&2
  exit 1
fi
if ! admission "$scratch/wrong-policy.yaml" fail; then
  echo 'UNKNOWN: Kyverno negative control did not prove a mismatch' >&2
  exit 1
fi

# Refusal during an outage proves nothing. Recheck both positive paths after
# the negative controls, using the same references and registry credentials.
inventory "$rules" PASS
admission "$policy" pass
echo "$count package signatures and both negative controls passed"
