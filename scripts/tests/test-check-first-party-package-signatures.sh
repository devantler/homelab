#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/bin"
cat >"$scratch/packages.yaml" <<'YAML'
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: unifi
spec:
  package: ghcr.io/devantler-tech/provider-upjet-unifi:v1.0.0
YAML
cat >"$scratch/verify" <<'SH'
#!/usr/bin/env bash
[[ "$1" == ghcr.io/devantler-tech/provider-upjet-unifi:v1.0.0 || "$1" == ghcr.io/devantler-tech/provider-upjet-extra:v1.0.0 ]] || exit 1
[[ "$2" == https://token.actions.githubusercontent.com ]] || exit 1
[[ ${SIGNATURE_UNREADABLE:-false} != true ]] || exit 1
identity='https://github.com/devantler-tech/provider-upjet-unifi/.github/workflows/publish-provider-package.yml@refs/tags/v1.0.0'
[[ "$identity" =~ $3 ]]
SH
cat >"$scratch/probe" <<'SH'
#!/usr/bin/env bash
if [[ ${SIGNATURE_UNREADABLE:-false} == true ]]; then echo 401; else echo 200; fi
SH
# Only the external engine is substituted in this hermetic suite. The real
# Kyverno engine and cosign are exercised by the required registry job.
cat >"$scratch/bin/kyverno" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
# The real CLI requires individual documents, and panics on a Kubernetes List.
yq -o=json -I=0 '.' "$4" | jq -se 'all(.[]; .kind == "Pod")' > /dev/null
# Kyverno 1.18.2 cannot resolve Kubernetes pull Secrets in its CLI; the
# standalone check must use the Docker credential provider for registry reads.
yq -o=json '.' "$2" | jq -e '(.spec.credentials.secrets // [] | length) == 0 and .spec.credentials.providers == ["default"]' > /dev/null
verdict=pass
status=0
if [[ ${KYVERNO_MODE:-normal} != inert ]] &&
  yq -e '.spec.attestors[].cosign.keyless.identities[].subjectRegExp | contains("NOT-A-REAL-REPO")' "$2" >/dev/null; then
  verdict=fail
  status=1
fi
if [[ ${KYVERNO_MODE:-normal} == empty ]]; then
  echo '{"results":[],"summary":{"pass":0,"skip":1}}'
else
  yq -o=json -I=0 '.' "$4" | jq -s --arg verdict "$verdict" '{results:map({source:"KyvernoImageValidatingPolicy",policy:"verify-app-images",result:$verdict,resources:[{apiVersion:.apiVersion,kind:.kind,namespace:.metadata.namespace,name:.metadata.name}]})}'
fi
exit "$status"
SH
chmod +x "$scratch/verify" "$scratch/probe" "$scratch/bin/kyverno"
export INVENTORY_VERIFY_CMD="$scratch/verify" INVENTORY_PROBE_CMD="$scratch/probe"
export PATH="$scratch/bin:$PATH"
rules=talos/cluster/verify-first-party-images.yaml
policy=k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml
# Run the real checker with the supplied Talos rules and this suite's fixture
# inventory and admission policy; preserve its output and exit status.
check() {
  bash scripts/check-first-party-package-signatures.sh --rendered "$scratch/packages.yaml" --rules "$1" --policy "$policy"
}
# Require the fixture to pass both real checker paths and their negative controls,
# printing the captured diagnostic and stopping the suite on failure.
accept() {
  if ! check "$rules" >"$scratch/output" 2>&1; then
    cat "$scratch/output" >&2
    exit 1
  fi
}
# Require the named command to fail with the expected literal diagnostic. Reject
# accidental success and unrelated failures so each negative control proves its cause.
reject() {
  local name="$1" expected="$2"
  shift 2
  if "$@" >"$scratch/output" 2>&1; then
    echo "FAIL: $name passed" >&2
    exit 1
  fi
  if ! grep -qF "$expected" "$scratch/output"; then
    echo "FAIL: $name failed for the wrong reason" >&2
    cat "$scratch/output" >&2
    exit 1
  fi
}
# #3422's bump alone: tag-signed package plus the old main-only verifier.
yq '.rules[] |= (.keyless.subjectRegex = "^https://github\\.com/devantler-tech/provider-upjet-unifi/\\.github/workflows/publish-provider-package\\.yml@refs/heads/main$")' "$rules" >"$scratch/main-only.yaml"
reject 'tag bump with old verifier' 'FAIL' check "$scratch/main-only.yaml"
accept
grep -qF 'package signatures and both negative controls passed' "$scratch/output"
SIGNATURE_UNREADABLE=true reject 'unauthenticated registry' 'UNKNOWN' check "$rules"
KYVERNO_MODE=empty reject 'skipped admission check' 'UNKNOWN' check "$rules"
KYVERNO_MODE=inert reject 'inert admission verifier' 'negative control' check "$rules"
cat >>"$scratch/packages.yaml" <<'YAML'
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
spec:
  package: ghcr.io/devantler-tech/provider-upjet-extra:v1.0.0
YAML
accept
grep -qF '2 package signatures and both negative controls passed' "$scratch/output"
yq '.rules = [.rules[1]] | .rules[0].image = "ghcr.io/devantler-tech/provider-upjet-unifi"' "$rules" >"$scratch/unmatched.yaml"
reject 'one package silently unmatched by Talos' 'UNKNOWN' check "$scratch/unmatched.yaml"
printf 'first-party package signature guard tests passed\n'
