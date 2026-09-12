#!/usr/bin/env bash

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly helm_release="${root_dir}/k8s/bases/infrastructure/controllers/kubescape/helm-release.yaml"
readonly network_policy="${root_dir}/k8s/bases/infrastructure/controllers/kubescape/cilium-network-policy.yaml"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

command -v yq >/dev/null 2>&1 || fail 'yq v4 is required to inspect the Kubescape HelmRelease'
command -v helm >/dev/null 2>&1 || fail 'helm is required to render the pinned Kubescape chart'
command -v kubectl >/dev/null 2>&1 || fail 'kubectl is required to exercise the Flux Helm post-renderer'

scanner_tag="$(yq -er '.spec.values.kubescape.image.tag | select(tag == "!!str")' "${helm_release}")" ||
  fail 'the Kubescape scanner image tag is missing or is not a string'
readonly scanner_tag

[[ "${scanner_tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  fail "Kubescape scanner tag ${scanner_tag} is not an exact vMAJOR.MINOR.PATCH release"
readonly major="${BASH_REMATCH[1]}"
readonly minor="${BASH_REMATCH[2]}"
readonly patch="${BASH_REMATCH[3]}"

# The tag regex admits components of any length, but Bash arithmetic wraps past
# 2^63-1, so a tag like v4.0.9223372036854775808 would evaluate to a negative
# patch and be rejected as older than every minimum below. Compare components as
# decimal strings instead: the regex forbids leading zeros, so a longer component
# is always the larger one, and equal-length components order lexically.
component_lt() {
  local left="$1" right="$2"
  if [[ ${#left} -ne ${#right} ]]; then
    [[ ${#left} -lt ${#right} ]]
    return
  fi
  [[ "${left}" < "${right}" ]]
}

scanner_predates() {
  local want_major="$1" want_minor="$2" want_patch="$3"
  if [[ "${major}" != "${want_major}" ]]; then
    component_lt "${major}" "${want_major}"
    return
  fi
  if [[ "${minor}" != "${want_minor}" ]]; then
    component_lt "${minor}" "${want_minor}"
    return
  fi
  component_lt "${patch}" "${want_patch}"
}

# Kubescape <=4.0.11 can override an explicit local-only request, enter SaaS
# submission with no backend configured, and abort on account-ID chmod before
# its in-cluster report receiver persists WorkloadConfigurationScan objects.
# Upstream kubescape#2556 fixes all three links and first ships in v4.0.12.
if scanner_predates 4 0 12; then
  fail "Kubescape scanner ${scanner_tag} predates v4.0.12 and can silently drop self-hosted posture results"
fi

# Kubescape v4.0.12 ships CEL admission support with the v0.13 policy bundle,
# which does not contain the ValidatingAdmissionPolicy for control C-0262. A
# full scheduled scan therefore aborts after discovery with "no
# ValidatingAdmissionPolicy for control C-0262" and persists no posture data.
# v4.0.13 bumps the embedded library to v0.14 and includes that policy.
if scanner_predates 4 0 13; then
  fail "Kubescape scanner ${scanner_tag} predates v4.0.13 and can abort on the incomplete embedded CEL policy bundle"
fi

# v4.0.13 still races on concurrent CEL parameter lookups during a scan; v4.0.14
# is the first scanner carrying that fix. No cluster-level test exercises the
# race, so this guard is what stops a downgrade from reintroducing it.
if scanner_predates 4 0 14; then
  fail "Kubescape scanner ${scanner_tag} predates v4.0.14 and can race on concurrent CEL parameter lookups"
fi

# kubevuln v0.3.159 swallows an exhausted conflict retry while updating a
# VulnerabilityManifestSummary: it logs the original AlreadyExists result and
# returns success. kubescape/kubevuln#745 fixed both error reporting and
# propagation, first released in v0.3.404. Chart 1.40.4 selects v0.3.430;
# verify the rendered image below so a later chart cannot regress silently.
readonly kubevuln_tag='v0.3.430'

keep_local="$(yq -er '
  .spec.values.kubescapeScheduler.requestBody.commands[] |
  select(.CommandName == "kubescapeScan") |
  .args.scanV1.keepLocal |
  select(tag == "!!bool")
' "${helm_release}")" || fail 'the scheduled Kubescape scan has no explicit keepLocal setting'
readonly keep_local
[[ "${keep_local}" == "true" ]] ||
  fail 'the scheduled Kubescape scan must remain local-only in this self-hosted deployment'

offline="$(yq -er '.spec.values.capabilities.kubescapeOffline' "${helm_release}")" ||
  fail 'capabilities.kubescapeOffline is missing'
readonly offline
[[ "${offline}" == "disable" ]] ||
  fail 'Kubescape offline mode must stay disabled so the scanner can fetch policy artifacts'

# The scanner's API-server persistence handler stores detailed
# WorkloadConfigurationScan objects only when clusterData.continuousPostureScan
# is true. Chart 1.40.4 derives that flag from this capability.
continuous_scan="$(yq -er '.spec.values.capabilities.continuousScan' "${helm_release}")" ||
  fail 'capabilities.continuousScan is missing'
readonly continuous_scan
[[ "${continuous_scan}" == "enable" ]] ||
  fail 'continuousScan must be enabled so scheduled scans persist detailed posture results'

# Enabling the capability also starts the operator's event-driven scanner. Keep
# its resource set empty: the pinned operator turns an empty match list into an
# empty watch pool, preserving scheduled persistence without scan-on-change
# traffic that omits keepLocal.
continuous_match_count="$(yq -er '
  .spec.values.continuousScanning.matchingRules.match |
  select(tag == "!!seq") |
  length
' "${helm_release}")" || fail 'continuous-scanning matchingRules.match must be an explicit list'
readonly continuous_match_count
[[ "${continuous_match_count}" == "0" ]] ||
  fail 'continuous-scanning matchingRules.match must stay empty in this self-hosted deployment'

continuous_namespace_count="$(yq -er '
  .spec.values.continuousScanning.matchingRules.namespaces |
  select(tag == "!!seq") |
  length
' "${helm_release}")" || fail 'continuous-scanning matchingRules.namespaces must be an explicit list'
readonly continuous_namespace_count
[[ "${continuous_namespace_count}" == "0" ]] ||
  fail 'continuous-scanning matchingRules.namespaces must stay empty in this self-hosted deployment'

# The chart hashes one shared cluster seed for both default schedules, so its
# nominally different posture/vulnerability defaults render to the same cron
# instant. Both scans are high-volume writers to one SQLite-backed storage API;
# keep their authored windows separated so detailed posture writes do not lose
# the single-writer lock to vulnerability results. These value paths and their
# CronJob mapping were verified against immutable chart 1.40.4; fail on a chart
# bump so the new chart must be rendered and this contract deliberately renewed.
chart_version="$(yq -er '
  .spec.chart.spec.version |
  select(tag == "!!str" and length > 0)
' "${helm_release}")" || fail 'the Kubescape chart version must be an exact string'
readonly chart_version
[[ "${chart_version}" == "1.40.4" ]] ||
  fail 'the Kubescape chart changed; revalidate both rendered scheduler CronJobs before updating this guard'

posture_schedule="$(yq -er '
  .spec.values.kubescapeScheduler.scanSchedule |
  select(tag == "!!str" and length > 0)
' "${helm_release}")" || fail 'the Kubescape posture schedule must be explicit'
readonly posture_schedule
[[ "${posture_schedule}" == "12 9 * * *" ]] ||
  fail 'the Kubescape posture scan must stay in its authored daily window'

vulnerability_schedule="$(yq -er '
  .spec.values.kubevulnScheduler.scanSchedule |
  select(tag == "!!str" and length > 0)
' "${helm_release}")" || fail 'the Kubescape vulnerability schedule must be explicit'
readonly vulnerability_schedule
[[ "${vulnerability_schedule}" == "12 1 * * *" ]] ||
  fail 'the Kubescape vulnerability scan must stay separated from posture persistence'

[[ "${posture_schedule}" != "${vulnerability_schedule}" ]] ||
  fail 'posture and vulnerability scans must not contend for storage in the same window'

# Exercise the immutable chart contract rather than trusting value-path names.
# The K8s validation job already fetches Helm sources through KSail; this direct
# render additionally proves that the reviewed chart maps each authored value to
# the intended CronJob. Pin the archive bytes so a republished tag fails closed.
readonly chart_repository='https://kubescape.github.io/helm-charts/'
readonly chart_archive_sha256='9c9dad697b13d085ed1c6cbb166d9ade239305aa2e8b5999840d455fc91a10ea'
chart_dir="$(mktemp -d "${TMPDIR:-/tmp}/kubescape-chart.XXXXXX")" ||
  fail 'could not create a temporary directory for the Kubescape chart'
readonly chart_dir
cleanup() {
  rm -rf -- "${chart_dir}"
}
trap cleanup EXIT

helm pull kubescape-operator \
  --repo "${chart_repository}" \
  --version "${chart_version}" \
  --destination "${chart_dir}" >/dev/null || fail 'could not fetch the pinned Kubescape chart'
readonly chart_archive="${chart_dir}/kubescape-operator-${chart_version}.tgz"

if command -v sha256sum >/dev/null 2>&1; then
  chart_archive_actual_sha256="$(sha256sum "${chart_archive}" | cut -d ' ' -f 1)"
else
  chart_archive_actual_sha256="$(shasum -a 256 "${chart_archive}" | cut -d ' ' -f 1)"
fi
readonly chart_archive_actual_sha256
[[ "${chart_archive_actual_sha256}" == "${chart_archive_sha256}" ]] ||
  fail 'the pinned Kubescape chart archive checksum changed'

readonly chart_values="${chart_dir}/values.yaml"
readonly rendered_chart="${chart_dir}/rendered.yaml"
yq '.spec.values' "${helm_release}" >"${chart_values}"
helm template kubescape "${chart_archive}" \
  --namespace kubescape \
  --values "${chart_values}" >"${rendered_chart}" || fail 'the pinned Kubescape chart did not render'

# Chart 1.40.4 removed the node-agent's existing read-only profile rule while
# node-agent still lists ApplicationProfiles during its storage readiness gate.
# Exercise the platform post-renderer against a synthetic copy with that rule
# removed so a future chart refactor cannot silently reintroduce the startup
# failure observed during the 1.40.4 production rollout.
readonly regressed_chart="${chart_dir}/rendered-without-node-agent-profile-read.yaml"
yq ea '
  (select(.kind == "ClusterRole" and .metadata.name == "node-agent").rules) |=
    map(select(
      (.apiGroups[0] // "") != "spdx.softwarecomposition.kubescape.io" or
      ((.resources // []) | sort | join(",")) != "applicationprofiles,networkneighborhoods"
    ))
' "${rendered_chart}" >"${regressed_chart}" || fail 'could not construct the chart RBAC regression fixture'

readonly postrenderer_kustomization="${chart_dir}/kustomization.yaml"
HELM_RELEASE="${helm_release}" yq -n '
  .apiVersion = "kustomize.config.k8s.io/v1beta1" |
  .kind = "Kustomization" |
  .resources = ["rendered-without-node-agent-profile-read.yaml"] |
  .patches = (load(strenv(HELM_RELEASE)).spec.postRenderers[0].kustomize.patches // [])
' >"${postrenderer_kustomization}" || fail 'could not construct the Flux post-renderer fixture'

readonly postrendered_chart="${chart_dir}/postrendered.yaml"
kubectl kustomize "${chart_dir}" >"${postrendered_chart}" || fail 'the Flux Helm post-renderer did not apply'

node_agent_profile_reader_count="$(yq ea -er '
  select(.kind == "ClusterRole" and .metadata.name == "node-agent") |
  [.rules[] | select(
    .apiGroups[0] == "spdx.softwarecomposition.kubescape.io" and
    (.apiGroups | length) == 1 and
    (.resources | sort | join(",")) == "applicationprofiles,networkneighborhoods" and
    (.verbs | sort | join(",")) == "get,list,watch"
  )] | length
' "${postrendered_chart}")" || fail 'the post-rendered node-agent ClusterRole is missing'
readonly node_agent_profile_reader_count
[[ "${node_agent_profile_reader_count}" == "1" ]] ||
  fail 'the Helm post-renderer must restore exactly the node-agent profile read rule removed by chart 1.40.4'

rendered_posture_schedule="$(yq ea -er '
  select(.kind == "CronJob" and .metadata.name == "kubescape-scheduler") |
  .spec.schedule |
  select(tag == "!!str")
' "${rendered_chart}")" || fail 'the rendered posture CronJob schedule is missing'
readonly rendered_posture_schedule
[[ "${rendered_posture_schedule}" == "${posture_schedule}" ]] ||
  fail 'the rendered posture CronJob does not use the authored schedule'

rendered_vulnerability_schedule="$(yq ea -er '
  select(.kind == "CronJob" and .metadata.name == "kubevuln-scheduler") |
  .spec.schedule |
  select(tag == "!!str")
' "${rendered_chart}")" || fail 'the rendered vulnerability CronJob schedule is missing'
readonly rendered_vulnerability_schedule
[[ "${rendered_vulnerability_schedule}" == "${vulnerability_schedule}" ]] ||
  fail 'the rendered vulnerability CronJob does not use the authored schedule'

[[ "${rendered_posture_schedule}" != "${rendered_vulnerability_schedule}" ]] ||
  fail 'the rendered posture and vulnerability CronJobs must use separate windows'

storage_repository="$(yq -er '
  .spec.values.storage.image.repository |
  select(tag == "!!str" and length > 0)
' "${helm_release}")" || fail 'the authored Kubescape storage image repository is missing'
readonly storage_repository
storage_tag="$(yq -er '
  .spec.values.storage.image.tag |
  select(tag == "!!str" and length > 0)
' "${helm_release}")" || fail 'the authored Kubescape storage image tag is missing'
readonly storage_tag
rendered_storage_image="$(yq ea -er '
  select(.kind == "Deployment" and .metadata.name == "storage") |
  .spec.template.spec.containers[] |
  select(.name == "apiserver") |
  .image |
  select(tag == "!!str")
' "${rendered_chart}")" || fail 'the rendered Kubescape storage image is missing'
readonly rendered_storage_image
[[ "${rendered_storage_image}" == "${storage_repository}:${storage_tag}" ]] ||
  fail 'the rendered Kubescape storage Deployment does not use the signed compatibility digest'

rendered_kubevuln_image="$(yq ea -er '
  select(.kind == "Deployment" and .metadata.name == "kubevuln") |
  .spec.template.spec.containers[] |
  select(.name == "kubevuln") |
  .image |
  select(tag == "!!str")
' "${rendered_chart}")" || fail 'the rendered kubevuln image is missing'
readonly rendered_kubevuln_image
[[ "${rendered_kubevuln_image}" == "quay.io/kubescape/kubevuln:${kubevuln_tag}" ]] ||
  fail 'the rendered kubevuln Deployment does not use the conflict-safe image'

# Registry blob pulls can redirect from their API hosts to separate CDN hosts.
# If a redirect host is blocked, kubevuln retries timeouts for hours and keeps
# the SQLite storage backend contended while posture results try to persist.
assert_https_fqdn() {
  local fqdn="$1"
  local description="$2"
  local matches
  local https_rules

  matches="$(REQUIRED_FQDN="${fqdn}" yq -er '
    [.spec.egress[].toFQDNs[]? |
      select(.matchName == strenv(REQUIRED_FQDN))] |
    length
  ' "${network_policy}")" || fail "could not inspect ${description} in the Kubescape egress policy"
  [[ "${matches}" == "1" ]] ||
    fail "Kubescape egress must allow ${description} exactly once"

  https_rules="$(REQUIRED_FQDN="${fqdn}" yq -er '
    [.spec.egress[] |
      select(
        (.toFQDNs // []) |
        map(.matchName) |
        contains([strenv(REQUIRED_FQDN)])
      ) |
      select(
        (.toPorts | length) == 1 and
        (.toPorts[0].ports | length) == 1 and
        .toPorts[0].ports[0].port == "443" and
        .toPorts[0].ports[0].protocol == "TCP"
      )] |
    length
  ' "${network_policy}")" || fail "could not inspect ${description} port restriction"
  [[ "${https_rules}" == "1" ]] ||
    fail "Kubescape ${description} egress must be restricted to TCP port 443"
}

assert_https_fqdn 'production.cloudfront.docker.com' 'Docker Hub CloudFront blob redirect host'
assert_https_fqdn 'cdn.registry.k8s.io' 'Kubernetes registry CDN redirect host'

printf 'Kubescape self-hosted scan persistence contract is valid (%s).\n' "${scanner_tag}"
