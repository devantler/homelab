#!/usr/bin/env bash
# Refresh the KSail-managed root Flux pull Secret from the Git/SOPS source.
#
# Flux cannot fetch the artifact containing a rotated credential while its
# bootstrap Secret is stale. Keep this bridge outside Flux so a deployment can
# repair that bootstrap edge before asking Flux to reconcile.

set -euo pipefail
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source=scripts/ghcr-auth-lib.sh
source "${SCRIPT_DIR}/ghcr-auth-lib.sh"
# shellcheck source=scripts/refresh-flux-ghcr-auth-safety.sh
source "${SCRIPT_DIR}/refresh-flux-ghcr-auth-safety.sh"
require_flux_ghcr_yaml_tool

check_only=false
allow_incomplete_fanout=false
report_fences=false
recover_fences=false
record_runtime_proof_path=""
reuse_runtime_proof_path=""
usage() {
  echo "Usage: $0 [--check-only|--allow-incomplete-fanout|--fences|--recover-fences|--record-runtime-proof PATH|--reuse-runtime-proof PATH]" >&2
}
while (($# > 0)); do
  case "$1" in
    --check-only)
      check_only=true
      shift
      ;;
    --allow-incomplete-fanout)
      allow_incomplete_fanout=true
      shift
      ;;
    --fences)
      report_fences=true
      shift
      ;;
    --recover-fences)
      recover_fences=true
      shift
      ;;
    --record-runtime-proof | --reuse-runtime-proof)
      if (($# < 2)) || [[ -z "$2" ]]; then
        usage
        exit 64
      fi
      if [[ "$1" == "--record-runtime-proof" ]]; then
        record_runtime_proof_path="$2"
      else
        reuse_runtime_proof_path="$2"
      fi
      shift 2
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done
if [[ "${check_only}" == "true" ||
  "${allow_incomplete_fanout}" == "true" ]] &&
  [[ -n "${record_runtime_proof_path}${reuse_runtime_proof_path}" ]]; then
  usage
  exit 64
fi
# --fences is an ALTERNATIVE mode, as the usage string says. It reports and
# exits before any credential or proof work runs, so accepting it alongside an
# operational mode makes that step exit 0 having silently skipped the operation
# it was configured to perform — an automation failure that looks like a pass.
#
# --recover-fences is the same kind of alternative mode and carries the same
# hazard, so it is rejected alongside an operational mode for the same reason.
# It is also rejected alongside --fences: --recover-fences already emits the
# full report as the evidence it acts on, so accepting both would leave the
# caller's intent ambiguous between "report" and "report and then mutate".
if { [[ "${report_fences}" == "true" ]] || [[ "${recover_fences}" == "true" ]]; } &&
  { [[ "${check_only}" == "true" ]] ||
    [[ "${allow_incomplete_fanout}" == "true" ]] ||
    [[ -n "${record_runtime_proof_path}${reuse_runtime_proof_path}" ]]; }; then
  usage
  exit 64
fi
if [[ "${report_fences}" == "true" && "${recover_fences}" == "true" ]]; then
  usage
  exit 64
fi
if [[ -n "${record_runtime_proof_path}" &&
  -n "${reuse_runtime_proof_path}" ]]; then
  usage
  exit 64
fi
for runtime_proof_path in \
  "${record_runtime_proof_path}" "${reuse_runtime_proof_path}"; do
  [[ -n "${runtime_proof_path}" ]] || continue
  if [[ "${runtime_proof_path}" != /* ]]; then
    echo "::error::Runtime proof paths must be absolute runner-local paths."
    exit 64
  fi
done

readonly SECRET_FILE="${FLUX_GHCR_SECRET_FILE:-k8s/bases/bootstrap/secret.enc.yaml}"
readonly KUBE_CONTEXT="${KUBE_CONTEXT:-admin@prod}"
readonly SYNC_ATTEMPTS="${FLUX_GHCR_SYNC_ATTEMPTS:-60}"
readonly SYNC_INTERVAL="${FLUX_GHCR_SYNC_INTERVAL:-2}"
readonly TALOS_CONVERGENCE_ATTEMPTS="${FLUX_GHCR_TALOS_CONVERGENCE_ATTEMPTS:-${SYNC_ATTEMPTS}}"
readonly DRAIN_TIMEOUT="${FLUX_GHCR_DRAIN_TIMEOUT:-45m}"
# Kyverno image verification is fail-closed and can consume its full webhook
# timeout during a cold signature lookup. Keep retrying the same immutable Pod
# name so an ambiguous admission response is reused instead of duplicated.
readonly RUNTIME_PROBE_CREATE_ATTEMPTS=6
readonly NODE_READY_TRANSPORT_RETRY_ATTEMPTS=3
readonly CORDON_RELEASE_ATTEMPTS=3
readonly IMAGE_VERIFICATION_WEBHOOK_TIMEOUT_SECONDS=30
readonly IMAGE_VERIFICATION_POLICY="verify-app-images"
readonly RETIRED_IMAGE_VERIFICATION_POLICY="verify-ksail-images"
readonly IMAGE_VERIFICATION_POLICY_FILE="k8s/bases/infrastructure/cluster-policies/best-practices/verify-app-images.yaml"
readonly IMAGE_VERIFICATION_FLUX_KUSTOMIZATION="infrastructure"
readonly IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION="flux-system"
readonly FLUX_KUSTOMIZATION_RESOURCE="kustomizations.kustomize.toolkit.fluxcd.io"
readonly FLUX_POLICY_HANDOFF_OWNER_ANNOTATION="platform.devantler.tech/ghcr-policy-handoff-owner"
readonly FLUX_POLICY_HANDOFF_OWNER_JSON_PATH="/metadata/annotations/platform.devantler.tech~1ghcr-policy-handoff-owner"
readonly FLUX_POLICY_PARENT_OWNER_ANNOTATION="platform.devantler.tech/ghcr-policy-parent-owner"
readonly FLUX_POLICY_PARENT_OWNER_JSON_PATH="/metadata/annotations/platform.devantler.tech~1ghcr-policy-parent-owner"
readonly FLUX_RECONCILE_ANNOTATION="kustomize.toolkit.fluxcd.io/reconcile"
readonly FLUX_RECONCILE_JSON_PATH="/metadata/annotations/kustomize.toolkit.fluxcd.io~1reconcile"
readonly FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT="kustomize-controller"
readonly FLUX_KUSTOMIZE_CONTROLLER_SELECTOR="app=kustomize-controller"
readonly FLUX_CONTROLLER_RESTART_JSON_PATH="/spec/template/metadata/annotations/kubectl.kubernetes.io~1restartedAt"
readonly FLUX_CONTROLLER_ROLLOUT_TIMEOUT="2m"
readonly SYNC_LEASE_NAME="ghcr-auth-refresh"
readonly SYNC_LEASE_DURATION_SECONDS=120
readonly SYNC_LEASE_HEARTBEAT_SECONDS="${FLUX_GHCR_SYNC_LEASE_HEARTBEAT_SECONDS:-30}"
readonly SYNC_LEASE_RELEASE_ATTEMPTS=3
readonly CORDON_OWNER_ANNOTATION="platform.devantler.tech/ghcr-auth-drain-owner"
readonly CORDON_OWNER_JSON_PATH="/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-owner"
readonly CORDON_RECOVERY_ANNOTATION="platform.devantler.tech/ghcr-auth-drain-recovery"
readonly CORDON_RECOVERY_JSON_PATH="/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-recovery"
# Records how far a fence got, so a LEAKED fence is self-describing (#3070).
# Written "claimed" in the claim patch itself, then advanced to "mutating"
# BEFORE the first Talos mutation. That ordering is what makes the marker
# trustworthy in both kill directions: killed before the advance lands, the
# fence still reads "claimed" and nothing was mutated; killed after it lands but
# before the mutation runs, it reads "mutating" and we refuse — conservative,
# never the reverse. There is no window in which Talos is mutated under a fence
# still reading "claimed".
readonly CORDON_PHASE_ANNOTATION="platform.devantler.tech/ghcr-auth-drain-phase"
readonly CORDON_PHASE_JSON_PATH="/metadata/annotations/platform.devantler.tech~1ghcr-auth-drain-phase"
KSAIL_OPERATOR_VERSION="$(yq -er '.spec.chart.spec.version' \
  k8s/bases/infrastructure/controllers/ksail-operator/helm-release.yaml)"
readonly KSAIL_OPERATOR_VERSION
readonly KSAIL_OPERATOR_IMAGE="ghcr.io/devantler-tech/ksail:v${KSAIL_OPERATOR_VERSION}"
# Private first-party release workflows create/update latest alongside every
# semver image or artifact tag. Flux still selects immutable releases; latest is
# the stable read-permission/existence probe for the same private packages.
readonly -a REQUIRED_PULL_TARGETS=(
  "devantler-tech/platform/manifests:latest"
  "devantler-tech/wedding-app/manifests:latest"
  "devantler-tech/ascoachingogvaner/manifests:latest"
  "devantler-tech/data-product-controller:latest"
  "devantler-tech/wedding-app:latest"
  "devantler-tech/ascoachingogvaner:latest"
  "devantler-tech/ksail:v${KSAIL_OPERATOR_VERSION}"
  "devantler-tech/provider-upjet-unifi:v1.0.0"
)
# These packages are intentionally private and have independent ACLs. A public
# image (including KSail itself) can prove registry reachability but cannot
# prove that containerd loaded a working credential.
readonly -a RUNTIME_CREDENTIAL_PROBE_IMAGES=(
  "ghcr.io/devantler-tech/data-product-controller:latest"
  "ghcr.io/devantler-tech/wedding-app:latest"
  "ghcr.io/devantler-tech/ascoachingogvaner:latest"
)
readonly -a FANOUT_NAMESPACES=(
  # data-product-controller is staged off in k8s/bases/apps/kustomization.yaml,
  # so production never reconciles data-product-controller/ghcr-auth and this
  # entry must stay commented out while that gate is closed. Listing it anyway
  # fails EVERY prod deploy: the pre-publish invocation defers a missing new
  # consumer, but the post-reconcile reassertion runs with --reuse-runtime-proof
  # and has no such exemption, so it marks the fan-out incomplete and exits 1.
  # Uncomment this in the SAME change that enables the component in the apps
  # base — scripts/guard-ghcr-fanout-component-gate.sh fails if the two disagree.
  # "data-product-controller"
  "wedding-app"
  "ascoachingogvaner"
  "kyverno"
)

if ! [[ "${SYNC_ATTEMPTS}" =~ ^[1-9][0-9]*$ ]] ||
  ((SYNC_ATTEMPTS < 2)) ||
  ! [[ "${TALOS_CONVERGENCE_ATTEMPTS}" =~ ^[3-9]$|^[1-9][0-9]+$ ]] ||
  ! [[ "${SYNC_INTERVAL}" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
  ! [[ "${DRAIN_TIMEOUT}" =~ ^[1-9][0-9]*(s|m|h)$ ]] ||
  ! [[ "${SYNC_LEASE_HEARTBEAT_SECONDS}" =~ ^[1-9][0-9]*$ ]] ||
  ((SYNC_LEASE_HEARTBEAT_SECONDS >= SYNC_LEASE_DURATION_SECONDS)); then
  echo "::error::FLUX_GHCR_SYNC_ATTEMPTS must be at least 2, FLUX_GHCR_TALOS_CONVERGENCE_ATTEMPTS must be at least 3, FLUX_GHCR_SYNC_INTERVAL must be non-negative, FLUX_GHCR_DRAIN_TIMEOUT must be a positive whole number of seconds, minutes, or hours, and FLUX_GHCR_SYNC_LEASE_HEARTBEAT_SECONDS must be a positive integer below the Lease duration."
  exit 64
fi

work_dir="$(mktemp -d)"
chmod 700 "${work_dir}"
umask 077
active_runtime_probe=""
bootstrap_cordon_dir="${work_dir}/bootstrap-cordons"
bootstrap_retain_dir="${work_dir}/bootstrap-retain"
bootstrap_ordered_targets="${work_dir}/bootstrap-ordered-targets.tsv"
bootstrap_overlap_result="${work_dir}/bootstrap-overlap-result.txt"
bootstrap_seed_uid=""
mkdir -p "${bootstrap_cordon_dir}" "${bootstrap_retain_dir}"

cleanup_refresh_work() {
  local original_status=$?
  local cleanup_status=0

  trap - EXIT

  if [[ -n "${active_runtime_probe}" ]]; then
    kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace ksail-operator \
      delete pod "${active_runtime_probe}" \
      --ignore-not-found \
      --wait=false \
      >/dev/null 2>&1 || true
  fi
  if declare -F resume_flux_policy_handoff >/dev/null &&
    [[ "${flux_policy_handoff_acquired:-false}" == "true" ]] &&
    ! resume_flux_policy_handoff; then
    cleanup_status=1
    echo "::error::Could not safely resume Flux policy reconciliation; the ownership annotation was retained for explicit recovery."
  fi
  if declare -F resume_flux_policy_parent >/dev/null &&
    [[ "${flux_policy_parent_acquired:-false}" == "true" ]]; then
    if [[ "${flux_policy_handoff_acquired:-false}" == "true" ]]; then
      cleanup_status=1
      echo "::error::The child Flux policy handoff remains fenced; retaining the parent fence for explicit recovery."
    elif ! resume_flux_policy_parent; then
      cleanup_status=1
      echo "::error::Could not safely resume the parent Flux reconciliation; its ownership annotation was retained for explicit recovery."
    fi
  fi
  if declare -F cleanup_bootstrap_quarantine >/dev/null &&
    ! cleanup_bootstrap_quarantine; then
    cleanup_status=1
    echo "::error::Bootstrap quarantine cleanup was incomplete; durable recovery annotations remain on the affected nodes."
  fi
  if declare -F release_sync_lease >/dev/null &&
    [[ "${sync_lease_acquired:-false}" == "true" ]] &&
    ! release_sync_lease; then
    cleanup_status=1
    echo "::error::Could not safely release the GHCR synchronization lease."
  fi
  rm -rf "${work_dir}"
  if ((original_status == 0 && cleanup_status != 0)); then
    exit 1
  fi
  exit "${original_status}"
}
trap cleanup_refresh_work EXIT

docker_config="${work_dir}/config.json"
credentials_file="${work_dir}/credentials.json"
basic_curl_config="${work_dir}/curl-basic.config"
bearer_curl_config="${work_dir}/curl-bearer.config"
token_response="${work_dir}/token.json"
current_root_secret_file="${work_dir}/current-root-secret.json"
current_root_docker_config="${work_dir}/current-root-config.json"
current_root_credentials_file="${work_dir}/current-root-credentials.json"
current_root_basic_curl_config="${work_dir}/current-root-curl-basic.config"
current_root_token_response="${work_dir}/current-root-token.json"
current_root_bearer_curl_config="${work_dir}/current-root-curl-bearer.config"
patch_file="${work_dir}/patch.json"
variables_patch_file="${work_dir}/variables-patch.json"
expected_normalized="${work_dir}/expected-normalized.json"
fanout_api_resources="${work_dir}/fanout-api-resources.txt"
talos_auth_patch_file="${work_dir}/talos-registry-auth.json"
talos_revision_patch_file="${work_dir}/talos-registry-revision.json"
talos_result_file="${work_dir}/talos-result.txt"
drain_result_file="${work_dir}/drain-result.txt"
reboot_result_file="${work_dir}/reboot-result.txt"
cordon_state_file="${work_dir}/cordon-state.json"
cordon_claim_patch_file="${work_dir}/cordon-claim-patch.json"
cordon_release_patch_file="${work_dir}/cordon-release-patch.json"
cordon_recovery_patch_file="${work_dir}/cordon-recovery-patch.json"
talos_nodes_file="${work_dir}/talos-nodes.json"
talos_node_targets="${work_dir}/talos-node-targets.tsv"
talos_pending_targets="${work_dir}/talos-pending-targets.tsv"
talos_preflight_targets="${work_dir}/talos-preflight-targets.tsv"
talos_processed_targets="${work_dir}/talos-processed-targets.tsv"
talos_stage_result_file="${work_dir}/talos-stage-result.txt"
runtime_probe_nodes_file="${work_dir}/runtime-probe-nodes.json"
runtime_probe_targets_file="${work_dir}/runtime-probe-targets.tsv"
runtime_proved_targets_file="${work_dir}/runtime-proved-targets.txt"
runtime_probe_manifest_file="${work_dir}/runtime-probe-pod.json"
runtime_probe_state_file="${work_dir}/runtime-probe-state.json"
runtime_probe_result_file="${work_dir}/runtime-probe-result.txt"
normalized_runtime_proof_file="${work_dir}/reusable-runtime-proof.json"
runtime_proof_nodes_file="${work_dir}/runtime-proof-nodes.json"
image_verification_policy_patch_file="${work_dir}/image-verification-policy-patch.json"
image_verification_policy_result_file="${work_dir}/image-verification-policy-result.txt"
image_verification_mutating_webhooks_file="${work_dir}/image-verification-mutating-webhooks.json"
image_verification_validating_webhooks_file="${work_dir}/image-verification-validating-webhooks.json"
flux_policy_handoff_state_file="${work_dir}/flux-policy-handoff-state.json"
flux_policy_handoff_patch_file="${work_dir}/flux-policy-handoff-patch.json"
flux_policy_handoff_result_file="${work_dir}/flux-policy-handoff-result.txt"
flux_policy_parent_state_file="${work_dir}/flux-policy-parent-state.json"
flux_policy_parent_patch_file="${work_dir}/flux-policy-parent-patch.json"
flux_policy_parent_result_file="${work_dir}/flux-policy-parent-result.txt"
flux_policy_fences_state_file="${work_dir}/flux-policy-fences-state.json"
flux_policy_blocker_names_file="${work_dir}/flux-policy-blocker-names.txt"
flux_policy_blocker_state_file="${work_dir}/flux-policy-blocker-state.json"
flux_controller_deployment_state_file="${work_dir}/flux-controller-deployment-state.json"
flux_controller_restart_patch_file="${work_dir}/flux-controller-restart-patch.json"
flux_controller_result_file="${work_dir}/flux-controller-result.txt"
flux_controller_pods_before_file="${work_dir}/flux-controller-pods-before.json"
flux_controller_pods_after_file="${work_dir}/flux-controller-pods-after.json"
recovery_nodes_file="${work_dir}/recovery-nodes.json"
recovery_node_file="${work_dir}/recovery-node.json"
recovery_targets_file="${work_dir}/recovery-targets.jsonl"
recovery_record_file="${work_dir}/recovery-record.json"
recovery_blocked_owners_file="${work_dir}/recovery-blocked-owners.txt"
sync_lease_file="${work_dir}/sync-lease.json"
sync_lease_manifest_file="${work_dir}/sync-lease-manifest.json"
sync_lease_patch_file="${work_dir}/sync-lease-patch.json"
sync_lease_result_file="${work_dir}/sync-lease-result.txt"
sync_lease_lost_file="${work_dir}/sync-lease-lost"
root_secret_state_file="${work_dir}/root-secret-state.json"
root_secret_cas_patch_file="${work_dir}/root-secret-cas-patch.json"
variables_secret_state_file="${work_dir}/variables-secret-state.json"
variables_secret_cas_patch_file="${work_dir}/variables-secret-cas-patch.json"
sync_lease_holder=""
sync_lease_acquired=false
sync_lease_heartbeat_pid=""
sync_lease_renewal_failure=""
flux_policy_handoff_acquired=false
flux_policy_handoff_owner=""
flux_policy_handoff_uid=""
flux_policy_parent_acquired=false
flux_policy_parent_owner=""
flux_policy_parent_uid=""
runtime_probe_sequence=0
runtime_probe_bootstrap_needed=0

# Every fence below is released by cleanup_refresh_work in one ordered pass. A
# hard kill leaves an arbitrary prefix released and the remainder held, and a
# held fence is never auto-reclaimed: Talos machine-config writes expose no
# fencing token, so a surviving process could still write after any timeout
# takeover. Recovery is therefore deliberately human. This read-only report is
# what makes it a procedure rather than an improvisation — it names each fence
# still held, states whether the holder is provably dead, and prints the exact
# CAS-guarded release. It performs no mutation by design: an operator running
# the printed command is the explicit step the fencing model requires.
# State the fence report hands to --recover-fences. Declared here, beside the
# report that populates them, so the two cannot drift apart.
fence_non_lease_held=0
fence_lease_holder=""
fence_lease_heartbeat_live=false
fence_lease_state_file=""

fence_run_segment() {
  if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
    printf 'gh%s.%s' "${GITHUB_RUN_ID}" "${GITHUB_RUN_ATTEMPT:-1}"
    return 0
  fi
  printf 'local'
}

fence_holder_run_reference() {
  local holder="$1"
  [[ "${holder}" =~ -gh([0-9]+)\.([0-9]+)- ]] || return 1
  printf '%s %s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

fence_report_liveness() {
  local holder="$1"
  local run_reference run_id run_attempt

  if run_reference="$(fence_holder_run_reference "${holder}")"; then
    run_id="${run_reference%% *}"
    run_attempt="${run_reference##* }"
    printf '    holder ran as GitHub run %s attempt %s. Confirm it is terminal:\n' \
      "${run_id}" "${run_attempt}"
    # --attempt, because a rerun REUSES the run id: without it `gh` reports the
    # latest attempt, so an orphan from a finished attempt 1 reads as live while
    # attempt 2 runs — blocking recovery on a holder that is already dead.
    printf '      gh run view %s --repo devantler-tech/platform --attempt %s --json status,conclusion\n' \
      "${run_id}" "${run_attempt}"
    printf '    A status other than "completed" means the holder is LIVE — do not recover.\n'
    return 0
  fi
  printf '    holder carries no run reference (written before that was recorded, or a\n'
  printf '    local run). Prove the process is dead before recovering.\n'
}

# Reported LAST on purpose. The Lease is the global exclusion fence: releasing
# it while a policy or node fence is still held lets a queued or newly
# dispatched deploy start against a half-recovered cluster and collide with the
# state the operator is still restoring. This mirrors cleanup_refresh_work,
# which releases the Lease after everything it guards.
fence_report_lease() {
  local state="$1"
  local holder now_epoch renew_epoch duration

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get lease "${SYNC_LEASE_NAME}" \
    --ignore-not-found \
    -o json >"${state}"; then
    echo "::error::Could not read the GHCR synchronization lease."
    return 1
  fi
  [[ -s "${state}" ]] || return 0
  holder="$(jq -r '.spec.holderIdentity // ""' "${state}")"
  [[ -n "${holder}" ]] || return 0
  held=$((held + 1))
  # Retain what --recover-fences needs to decide, so recovery reasons over the
  # SAME observation the report just printed rather than re-reading the Lease.
  # A second read could land either side of a fresh acquisition, which would let
  # recovery act on a holder the operator never saw evidence for.
  fence_lease_holder="${holder}"
  # Only recovery consumes the retained copy, and only the mode dispatch sets the
  # path. Guarded so a caller that reports without recovering cannot turn an
  # unset path into a failed `cp` and lose the report itself — which is read
  # precisely when a deploy is already refusing to start.
  if [[ -n "${fence_lease_state_file}" ]] &&
    ! cp -- "${state}" "${fence_lease_state_file}"; then
    echo "::error::Could not retain the GHCR synchronization lease state."
    return 1
  fi
  duration="$(jq -r '.spec.leaseDurationSeconds // 0' "${state}")"
  now_epoch="$(date -u +%s)"
  renew_epoch="$(fence_report_epoch "$(jq -r '.spec.renewTime // ""' "${state}")")"
  printf 'HELD  Lease flux-system/%s\n' "${SYNC_LEASE_NAME}"
  printf '    holder: %s\n' "${holder}"
  if [[ -n "${renew_epoch}" ]] &&
    ((now_epoch - renew_epoch < duration)); then
    fence_lease_heartbeat_live=true
    printf '    renewed %ss ago, inside its %ss duration — the holder is LIVE. Do not recover.\n' \
      "$((now_epoch - renew_epoch))" "${duration}"
  else
    printf '    last renewed %s (duration %ss) — heartbeat has stopped.\n' \
      "$(jq -r '.spec.renewTime // "never"' "${state}")" "${duration}"
    fence_report_liveness "${holder}"
    printf '    release LAST, after every fence above is released:\n      %s\n' \
      "$(fence_lease_release_command "${state}" "${holder}")"
  fi
  printf '\n'
}

report_fences_now() {
  local state="${work_dir}/fence-report.json"
  local blocked_owners="${work_dir}/fence-report-blocked-owners.txt"
  local fence_report_nodes="${work_dir}/fence-report-nodes.rs"
  local held=0
  local holder name uid suspend phase resource_version uncordon deleting
  local drain_phase scheduling_intent

  printf '== GHCR deploy fences on context %s ==\n\n' "${KUBE_CONTEXT}"

  for name in "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
    "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}"; do
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" "${name}" \
      --ignore-not-found \
      -o json >"${state}"; then
      echo "::error::Could not read Kustomization flux-system/${name}."
      return 1
    fi
    [[ -s "${state}" ]] || continue
    if [[ "${name}" == "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" ]]; then
      holder="$(jq -r \
        --arg a "${FLUX_POLICY_HANDOFF_OWNER_ANNOTATION}" \
        '(.metadata.annotations // {})[$a] // ""' "${state}")"
    else
      holder="$(jq -r \
        --arg a "${FLUX_POLICY_PARENT_OWNER_ANNOTATION}" \
        '(.metadata.annotations // {})[$a] // ""' "${state}")"
    fi
    [[ -n "${holder}" ]] || continue
    held=$((held + 1))
    uid="$(jq -r '.metadata.uid' "${state}")"
    suspend="$(jq -r '.spec.suspend // false' "${state}")"
    printf 'HELD  Kustomization flux-system/%s\n' "${name}"
    printf '    holder: %s\n' "${holder}"
    printf '    suspend=%s — Flux reconciliation of this layer is STOPPED while held.\n' \
      "${suspend}"
    fence_report_liveness "${holder}"
    printf '    release:\n      %s\n' \
      "$(fence_kustomization_release_command "${name}" "${uid}" "${holder}")"
    printf '\n'
  done

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get nodes -o json >"${state}"; then
    echo "::error::Could not read nodes."
    return 1
  fi
  # reconcile_bootstrap_recovery_journals quarantines an interrupted bootstrap
  # by OWNER, not by node: it groups every journal by owner and blocks the whole
  # batch when the phases are mixed or any member is active/retain. A per-node
  # check therefore prints a release for the release-ready member of a batch
  # whose sibling is still retain, and an operator following the runbook steps
  # around the all-or-nothing guard one node at a time. Compute the same set
  # here so the report refuses every node belonging to a blocked owner.
  # A journal this cannot PARSE must not be dropped from the grouping. The
  # reconciler validates every journal up front and refuses EVERY recovery
  # mutation when any one of them is malformed, so silently excluding an
  # unparseable record would leave a valid sibling under the same owner looking
  # releasable — the same all-or-nothing guard walked around from the other
  # side. Whenever any journal fails that validation, emit the `*` sentinel and
  # block every journal-carrying node, mirroring the global refusal rather than
  # guessing an owner the record does not supply.
  #
  # The sentinel test applies the reconciler's FULL schema, not merely "parses
  # as an object carrying string owner and phase". A journal can clear that
  # weaker bar and still fail the reconciler — an empty owner, a non-hex
  # desiredRevision, an extra key, a wasCordoned outside {0,1}, an unsupported
  # phase, or a UID / owner-annotation that does not match its node. The
  # reconciler refuses every recovery mutation for all of those, so anything
  # short of its own predicate leaves such a record outside the sentinel while
  # its well-formed rollback-safe sibling under the same owner keeps a printed
  # release the bridge would refuse. The per-node validation further down
  # refuses the malformed node itself and says nothing about its siblings,
  # which is why the batch-level predicate is the strict one.
  #
  # `try fromjson catch null` is required over `fromjson?`: the `?` form yields
  # EMPTY, which drops the whole entry instead of its record, so the sentinel
  # test would pass vacuously across the records that survive.
  if ! jq -r \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" '
    [
      .items[]
      | select((.metadata.annotations[$recovery_annotation] // "") != "")
      | . as $node
      | ($node.metadata.annotations[$recovery_annotation]
         | try fromjson catch null) as $record
      | {node: $node, record: $record}
    ] as $entries
    | (
        if any($entries[];
             (
               .record != null
               and (.record | keys | sort) == ([
                 "desiredRevision", "initialTaints", "owner", "phase",
                 "uid", "v", "wasCordoned"
               ] | sort)
               and .record.v == 1
               and (.record.owner | type == "string" and length > 0)
               and (.record.uid | type == "string" and length > 0)
               and (.record.desiredRevision
                 | type == "string" and test("^[0-9a-f]{64}$"))
               and (.record.wasCordoned == 0 or .record.wasCordoned == 1)
               and (.record.initialTaints | type == "array")
               and (.record.phase == "rollback-safe"
                 or .record.phase == "active"
                 or .record.phase == "retain"
                 or .record.phase == "release-ready")
               and .node.metadata.uid == .record.uid
               and .node.metadata.deletionTimestamp == null
               and .node.metadata.annotations[$owner_annotation] == .record.owner
             ) | not)
        then "*"
        else empty
        end
      ),
      (
        $entries
        | map(.record)
        | map(select((type == "object")
            and ((.owner | type) == "string")
            and ((.phase | type) == "string")))
        | sort_by(.owner)
        | group_by(.owner)[]
        | select(
            (map(.phase) | unique | length) > 1
            or .[0].phase == "active"
            or .[0].phase == "retain"
          )
        | .[0].owner
      )
  ' "${state}" >"${blocked_owners}"; then
    echo "::error::Could not group durable GHCR bootstrap recovery journals by owner."
    return 1
  fi
  # The OWNER annotation is the fence; the recovery journal is optional context.
  # The ordinary per-node path claims cordon ownership with an empty recovery
  # record, so a node killed there carries an owner and no journal — keying this
  # on the journal alone would report "no fence held" while that node stays
  # cordoned and the next run refuses its existing owner.
  # UNIT SEPARATOR, not a tab. Tab is IFS *whitespace*, so bash collapses runs of
  # them and drops empty fields — and BOTH `owner` and `recovery` are legitimately
  # empty (a node claimed with no journal is the ordinary per-node claim; an
  # ownerless journal is the case the validation above refuses). With a tab, such
  # a row shifted every later field left: `uid` received the resourceVersion and
  # `resource_version` the deletionTimestamp, so the CAS patch tested values that
  # were never read from that node. \u001f is not IFS whitespace, so empty fields
  # are preserved.
  # Materialized rather than piped through `< <(...)`: a process substitution's
  # exit status is invisible to the `while`, so a jq abort mid-stream (a corrupted
  # journal whose initialTaints holds a non-object aborts `scheduling_taints` on
  # `.key`) would truncate the feed, silently omit that node and every node after
  # it, and let this function go on to print "No fence is held" — the worst
  # possible answer from a tool whose whole job is finding held fences.
  if ! jq -r \
    --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    --arg phase_annotation "${CORDON_PHASE_ANNOTATION}" '
    # The SAME normalization node_scheduling_state_is_safe_to_reboot applies,
    # and the same one that captured initialTaints. A different one would
    # disagree with the reference predicate on exactly the taint it exists to
    # ignore, so the report would refuse releases the bridge would perform.
    def scheduling_taints:
      map(select((
        (.key == "node.kubernetes.io/unschedulable"
          and .effect == "NoSchedule"
          and (.value // "") == "")
        or (.key == "DeletionCandidateOfClusterAutoscaler"
          and .effect == "PreferNoSchedule")
      ) | not))
      | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")]);
    .items[]
    | . as $node
    | (.metadata.annotations // {}) as $a
    | ($a[$owner_annotation] // "") as $owner
    | ($a[$recovery_annotation] // "") as $recovery
    | select($owner != "" or $recovery != "")
    # `try/catch null`, never `fromjson?`: the latter yields EMPTY on a malformed
    # journal, and `empty as $record` drops the whole node from this feed — so a
    # node carrying an unparseable journal would disappear from the report and
    # read as no fence held at all, the worst possible failure for this tool.
    | ($recovery | try fromjson catch null) as $record
    | [
        .metadata.name,
        $owner,
        $recovery,
        ((.spec.unschedulable // false) | tostring),
        .metadata.uid,
        .metadata.resourceVersion,
        (.metadata.deletionTimestamp // ""),
        ($a[$phase_annotation] // ""),
        # Precomputed here because the loop receives fields, not the node. The
        # resourceVersion CAS only rejects a change made AFTER this read; drift
        # that already happened is invisible to it, so compare the captured
        # scheduling intent against what is on the node right now.
        (if $record == null or ($record.initialTaints | type) != "array"
         then "unknown"
         elif ((($node.spec.unschedulable // false) == true)
           and ((($node.spec.taints // []) | scheduling_taints)
             == ($record.initialTaints | scheduling_taints)))
         then "true"
         else "false"
         end)
      ]
    | map(tostring | gsub("[\u001f\n\r]"; " "))
    | join("\u001f")
  ' "${state}" >"${fence_report_nodes}"; then
    echo "::error::Could not enumerate node fences for the report; refusing to report fence state from a truncated feed. A corrupted recovery journal is the likely cause. Run './scripts/refresh-flux-ghcr-auth.sh --fences' after repairing it, and see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
    return 1
  fi
  while IFS=$'\037' read -r name owner recovery unschedulable uid resource_version deleting drain_phase scheduling_intent; do
    [[ -n "${name}" ]] || continue
    held=$((held + 1))
    printf 'HELD  Node %s (drain quarantine)\n' "${name}"
    printf '    cordon owner: %s\n' "${owner:-<none>}"
    printf '    recovery record: %s\n' "${recovery:-<none — claimed without a journal>}"
    printf '    drain phase: %s\n' "${drain_phase:-<none>}"
    printf '    unschedulable: %s\n' "${unschedulable}"
    [[ -n "${owner}" ]] && fence_report_liveness "${owner}"
    # The no-journal case is the ordinary per-node claim, and reclaim_orphaned_
    # node_fences clears it ONLY at phase "claimed": "mutating" means a Talos
    # write was already in flight, and a MISSING phase is a pre-#3070 fence of
    # unknown depth. select_orphaned_node_fences fails closed on both, so the
    # report has to as well — otherwise releasing here strips the owner, the
    # next report reads clean, and the following bridge claims a node whose
    # Talos write never completed.
    if [[ -z "${recovery}" && "${drain_phase}" != "claimed" ]]; then
      printf '    NOT releasable: the drain phase is %s, not claimed. Only a fence\n' \
        "${drain_phase:-absent}"
      printf '    that never reached a Talos mutation is provably safe to clear, and\n'
      printf '    an absent phase is never read as innocence. Run the bridge so\n'
      printf '    reclaim adjudicates it.\n\n'
      continue
    fi
    # A journal in `active` or `retain` is NOT releasable by annotation removal:
    # `active` may hold an interrupted pre-reboot mutation and `retain` has
    # crossed the reboot edge without a release-ready runtime proof, which is
    # why reconcile_bootstrap_recovery refuses both. Printing the removals for
    # them would discard the only durable recovery state and invite restoring an
    # unverified node, so those phases get directed to bootstrap recovery
    # instead of a command.
    phase="$(printf '%s' "${recovery}" |
      jq -r 'if type == "object" and (.phase | type) == "string"
             then .phase else "" end' 2>/dev/null || printf '')"
    case "${phase}" in
      active | retain)
        printf '    NOT releasable by annotation removal: journal phase is %s.\n' "${phase}"
        printf '    %s\n' "$(
          [[ "${phase}" == active ]] &&
            printf 'A pre-reboot mutation may have been interrupted.' ||
            printf 'The node crossed the reboot edge without a release-ready proof.'
        )"
        printf '    Run the bridge so bootstrap recovery reconciles this node; do not\n'
        printf '    hand-clear the journal, it is the only durable record of that state.\n\n'
        continue
        ;;
      release-ready)
        # reconcile_bootstrap_recovery_journals admits this phase ONLY when the
        # journal's recorded desiredRevision equals the current one: the runtime
        # proof and Talos marker cover the revision they were taken against, and
        # a newer credential needs the full proof the bridge performs. This mode
        # deliberately never loads the credential — that is what lets it answer
        # while a deploy is refusing to start — so it cannot compute that
        # equality at all. A well-formed hash is not a current hash, so route it
        # to the bridge rather than emit a release it has no evidence for.
        printf '    NOT releasable by annotation removal: this report cannot prove the\n'
        printf '    journal covers the CURRENT credential revision. It never loads the\n'
        printf '    credential, and a release-ready journal from an older revision needs\n'
        printf '    a full proof. Run the bridge so bootstrap recovery adjudicates it.\n\n'
        continue
        ;;
    esac
    # An interrupted bootstrap is quarantined per OWNER, all-or-nothing. Refuse
    # every node in a blocked batch, or the runbook walks around that guard one
    # node at a time.
    # The `*` sentinel covers only journal-carrying nodes: the reconciler's
    # global refusal is about recovery journals, while a node with no journal is
    # the ordinary per-node claim that reclaim_orphaned_node_fences owns and the
    # drain-phase guard above has already adjudicated.
    if [[ -n "${recovery}" ]] && grep -Fqx -- '*' "${blocked_owners}"; then
      printf '    NOT releasable: at least one recovery journal in the cluster is\n'
      printf '    malformed, and bootstrap recovery refuses every recovery mutation\n'
      printf '    while that is true. Run the bridge so it adjudicates them together.\n\n'
      continue
    fi
    if [[ -n "${owner}" ]] && grep -Fqx -- "${owner}" "${blocked_owners}"; then
      printf '    NOT releasable: another node under bootstrap owner %s is still\n' "${owner}"
      printf '    active, retained, or in a different phase, and that quarantine is\n'
      printf '    all-or-nothing. Run the bridge so bootstrap recovery releases the\n'
      printf '    whole batch together.\n\n'
      continue
    fi
    # restore_node_schedulability_if_needed gates every uncordon on
    # node_scheduling_state_is_safe_to_reboot, which requires the node's CURRENT
    # normalized taints and cordon state to still match the journal's captured
    # intent. The resourceVersion CAS below only rejects a change made after
    # this read; drift that already happened is invisible to it, so a patch
    # could otherwise uncordon a node into a taint set nobody captured.
    if [[ -n "${recovery}" && "${scheduling_intent}" != "true" ]]; then
      printf '    NOT releasable: the node scheduling state no longer matches the\n'
      printf '    intent its journal captured (%s), so the release the bridge would\n' \
        "${scheduling_intent}"
      printf '    perform is not the one printed here. Run the bridge so bootstrap\n'
      printf '    recovery re-adjudicates it.\n\n'
      continue
    fi
    # CAS protects against a CONCURRENT change; it says nothing about whether
    # the state recorded here is safe to restore. reconcile_bootstrap_recovery_journals
    # and restore_node_schedulability_if_needed both refuse a journal whose
    # schema, owner, UID or phase is wrong, and the report has to refuse on the
    # same terms — otherwise a malformed record like {"wasCordoned":0}, or one
    # belonging to another owner or node, reaches the phase check as a non-active
    # non-retain journal and earns a patch that drops it and uncordons the node.
    # A node with NO journal is unaffected: that is the ordinary per-node claim,
    # and the real release path likewise validates only when one is present.
    if [[ -n "${recovery}" ]] &&
      ! printf '%s' "${recovery}" | jq -e \
        --arg owner "${owner}" \
        --arg uid "${uid}" '
        (keys | sort) == ([
          "desiredRevision", "initialTaints", "owner", "phase",
          "uid", "v", "wasCordoned"
        ] | sort)
        and .v == 1
        and (.owner | type == "string" and length > 0)
        and .owner == $owner
        and .uid == $uid
        and (.desiredRevision | type == "string" and test("^[0-9a-f]{64}$"))
        and (.wasCordoned == 0 or .wasCordoned == 1)
        and (.initialTaints | type == "array")
        and .phase == "rollback-safe"
      ' >/dev/null 2>&1; then
      printf '    NOT releasable: the recovery journal is malformed, records no\n'
      printf '    releasable phase, or belongs to another owner or node.\n'
      printf '    Run the bridge so bootstrap recovery adjudicates it; releasing on a\n'
      printf '    journal this script cannot validate is how a node gets uncordoned\n'
      printf '    against a state nobody verified.\n\n'
      continue
    fi
    # The cordon owner annotation IS the fence, so releasing without one proves
    # nothing about who holds it. fence_node_release_command omits the owner
    # test and remove when the annotation is absent, and the patch would still
    # drop the journal and — on wasCordoned 0 — uncordon the node. This loop
    # selects a node carrying an owner OR a journal, so the ownerless-journal
    # case is reachable and has to be refused here rather than emitted unguarded.
    # The canonical journal rule requires .metadata.deletionTimestamp == null.
    # A node being deleted is not a node to make schedulable again, and its
    # annotations are about to go with it, so releasing here races the deletion
    # for no benefit.
    if [[ -n "${deleting}" ]]; then
      printf '    NOT releasable: the node is being deleted (deletionTimestamp %s).\n' \
        "${deleting}"
      printf '    Let the deletion finish; there is nothing to restore.\n\n'
      continue
    fi
    if [[ -z "${owner}" ]]; then
      printf '    NOT releasable: the node carries no cordon owner annotation, so no\n'
      printf '    release can prove this transaction holds the fence. Run the bridge so\n'
      printf '    bootstrap recovery adjudicates the journal.\n\n'
      continue
    fi
    printf '    release (ONE CAS-guarded patch — fails safely if anything changed):\n'
    # Only uncordon a node this transaction is RECORDED to have cordoned. The
    # journal keeps the pre-claim state precisely because a node can already be
    # cordoned for maintenance or ill health, and an unconditional uncordon
    # would make it schedulable again — reversing an intent this script never
    # owned. Without a journal that state is unknown, so say so and let the
    # operator decide rather than emitting a command that might be wrong.
    uncordon=false
    if [[ "${unschedulable}" == "true" ]]; then
      # The journal serializes wasCordoned as NUMERIC 0/1 — it is validated as
      # `== 0 or == 1` — so match those, not the booleans this once compared
      # against and never matched. `has` rather than `//`, because jq's
      # alternative operator treats a falsy value as empty and would report the
      # recorded 0 case as unrecorded: the one case that may safely uncordon.
      case "$(printf '%s' "${recovery}" |
        jq -r 'if type == "object" and has("wasCordoned")
               then (.wasCordoned | tostring) else "unknown" end' 2>/dev/null ||
        printf 'unknown')" in
        0)
          uncordon=true
          ;;
        1)
          printf '      # node was ALREADY cordoned before this transaction — the patch below\n'
          printf '      # drops the fence and LEAVES it cordoned.\n'
          ;;
        *)
          printf '      # pre-claim schedulability is UNRECORDED — the patch below does NOT\n'
          printf '      # uncordon. Confirm the node should be schedulable before doing so\n'
          printf '      # yourself; this fence cannot tell you.\n'
          ;;
      esac
    fi
    printf '      %s\n' \
      "$(fence_node_release_command \
        "${name}" "${uid}" "${resource_version}" \
        "${owner}" "${recovery}" "${uncordon}")"
    printf '\n'
  done <"${fence_report_nodes}"

  # Captured BEFORE the Lease is reported, so it counts only the fences the
  # Lease's own ordering rule says must be released first. --recover-fences
  # refuses while this is non-zero rather than duplicating the node-journal
  # grouping above, which is the part that is genuinely hard to get right.
  fence_non_lease_held="${held}"

  fence_report_lease "${state}" || return 1

  if ((held == 0)); then
    printf 'No fence is held. A deploy can acquire cleanly.\n'
  else
    printf 'ATTENTION: %s fence(s) held. Recover ONLY after proving the holder is dead.\n' \
      "${held}"
    printf 'Release in the order printed above — policy fences, then nodes, then the\n'
    printf 'Lease. The Lease is the global exclusion fence: clearing it first lets a\n'
    printf 'deploy start against a half-recovered cluster.\n'
  fi
}

# Answers "is this holder provably dead?" — never "has its lease expired?".
#
# Expiry cannot answer it: the script's own acquisition comment explains that an
# expired shell process can resume after a timeout takeover and write stale
# credentials even under CAS, which is why automatic expiry takeover is disabled.
# A run reported `completed` by the API is different in kind: Actions does not
# resume a completed attempt, so this is a positive death proof rather than an
# inference from a clock.
#
# Every failure path returns non-zero. An unreadable API, an absent gh, a missing
# token, an empty body, or any status this does not recognise means NOT PROVEN,
# never "assume dead" — the whole safety property is that the proof and the
# release cannot be separated.
fence_run_is_terminal() {
  local run_id="$1"
  local run_attempt="$2"
  local repository="${GITHUB_REPOSITORY:-devantler-tech/platform}"
  local status

  if ! command -v gh >/dev/null 2>&1; then
    echo "::error::Cannot prove the fence holder is dead: gh is not available. Recover manually after confirming the run is terminal — see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
    return 1
  fi
  # The ATTEMPT is pinned. A rerun reuses the run id, so an unpinned query
  # reports the newest attempt: an orphan left by a finished attempt 1 would
  # read as live while attempt 2 runs, and — worse for an automatic path — a
  # finished attempt 2 would vouch for an attempt 1 that is still going.
  if ! status="$(gh api \
    "repos/${repository}/actions/runs/${run_id}/attempts/${run_attempt}" \
    --jq '.status' 2>/dev/null)"; then
    echo "::error::Cannot prove the fence holder is dead: querying run ${run_id} attempt ${run_attempt} failed. Not recovering."
    return 1
  fi
  if [[ -z "${status}" ]]; then
    echo "::error::Cannot prove the fence holder is dead: run ${run_id} attempt ${run_attempt} reported no status. Not recovering."
    return 1
  fi
  if [[ "${status}" != "completed" ]]; then
    echo "::error::Fence holder run ${run_id} attempt ${run_attempt} is ${status}, not completed — the holder is LIVE. Not recovering."
    return 1
  fi
  printf '  run %s attempt %s is completed — holder proven dead.\n' \
    "${run_id}" "${run_attempt}"
}

recover_fences_now() {
  local run_reference run_id run_attempt patch_file

  report_fences_now || return 1

  printf '\n== Automatic recovery ==\n'

  if [[ -z "${fence_lease_holder}" ]]; then
    printf 'No Lease fence is held; nothing to recover.\n'
    return 0
  fi
  # The Lease is released LAST for the reason the report states: it is the global
  # exclusion fence, so clearing it while a policy or node fence is still held
  # lets a deploy start against a half-recovered cluster. Automation therefore
  # refuses rather than reordering — the remaining fences need the operator.
  if ((fence_non_lease_held > 0)); then
    echo "::error::Refusing to recover the Lease while ${fence_non_lease_held} other fence(s) are held. Release those first, in the order the report prints."
    return 1
  fi
  # Belt and braces against a stale or cached API read: if the heartbeat is still
  # inside its duration the holder is writing right now, whatever any run status
  # says.
  if [[ "${fence_lease_heartbeat_live}" == "true" ]]; then
    echo "::error::Refusing to recover: the Lease heartbeat is still inside its duration, so the holder is live."
    return 1
  fi
  if ! run_reference="$(fence_holder_run_reference "${fence_lease_holder}")"; then
    echo "::error::Refusing to recover: holder '${fence_lease_holder}' carries no run reference, so its liveness cannot be proven from the API. This is the expected shape for a local run; recover manually."
    return 1
  fi
  run_id="${run_reference%% *}"
  run_attempt="${run_reference##* }"
  fence_run_is_terminal "${run_id}" "${run_attempt}" || return 1

  # Literally the same patch the report prints for an operator — one builder, so
  # the two cannot diverge. It is built from the state the report RETAINED, never
  # a fresh read, so the CAS tests the observation this decision was made on.
  patch_file="${work_dir}/fence-recovery-patch.json"
  fence_lease_release_patch \
    "${fence_lease_state_file}" "${fence_lease_holder}" >"${patch_file}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch lease "${SYNC_LEASE_NAME}" \
    --type=json \
    --patch-file "${patch_file}"; then
    echo "::error::Recovery patch was refused; the Lease was not released. Its holder or resourceVersion changed after the report — re-run to re-evaluate."
    return 1
  fi
  printf 'Released Lease flux-system/%s held by %s.\n' \
    "${SYNC_LEASE_NAME}" "${fence_lease_holder}"
}

fence_report_epoch() {
  local stamp="${1%%.*}"
  [[ -n "${stamp}" ]] || return 0
  stamp="${stamp%Z}"
  date -u -j -f '%Y-%m-%dT%H:%M:%S' "${stamp}" +%s 2>/dev/null ||
    date -u -d "${stamp}Z" +%s 2>/dev/null ||
    true
}

# The printed release commands are meant to be pasted into a shell, and every
# patch they carry is built from values READ OFF THE CLUSTER — the Lease holder,
# the node cordon-owner annotation, the recovery journal. Interpolating that JSON
# straight into `-p '…'` breaks on the first single quote in any of them: the
# command either fails to run, or — because a holder/annotation is attacker- or
# accident-writable — closes the quote and appends shell syntax the operator then
# executes. Same shape as the CAS gap above: the REPORT was not held to the
# safety rules the release path enforces. POSIX single-quoting is what makes an
# arbitrary byte string safe as one shell word: end the quote, emit an escaped
# quote, reopen. Resource NAMES are not routed through this because Kubernetes
# constrains them to RFC 1123 (lowercase alphanumeric, `-`, `.`), which cannot
# contain a quote; the patch is the only free-form value here.
fence_shell_quote() {
  # `'\''` — close the quote, emit an escaped quote, reopen — is the only way to
  # carry a single quote inside a single-quoted shell word. Pattern and
  # replacement are locals, and are deliberately left UNQUOTED in the expansion:
  # bash does not re-split or glob them there, but double-quoting them inside
  # `${var//…/…}` emits the quote characters literally, which silently corrupts
  # every escaped value. Both spellings were checked against a round-trip.
  local literal="$1"
  local quote="'"
  local escaped="'\\''"

  # shellcheck disable=SC2295 # quoting the pattern here would embed literal quotes
  printf "'%s'" "${literal//$quote/$escaped}"
}

# The ONE release patch. Both consumers build it here — the command the report
# prints for an operator, and the patch --recover-fences applies itself — so the
# automated path cannot end up on a weaker CAS than the runbook it mirrors.
# Kept as a single builder deliberately: two copies of a guard that must stay
# identical will eventually diverge silently, and nothing would fail when they do.
#
# Both `test` ops must still hold at apply time, so a Lease that moved after the
# observation aborts the whole patch instead of clearing a live acquisition.
fence_lease_release_patch() {
  local state="$1"
  local holder="$2"

  jq -nc \
    --arg rv "$(jq -r '.metadata.resourceVersion' "${state}")" \
    --arg holder "${holder}" '[
    {op: "test", path: "/metadata/resourceVersion", value: $rv},
    {op: "test", path: "/spec/holderIdentity", value: $holder},
    {op: "replace", path: "/spec/holderIdentity", value: ""},
    {op: "replace", path: "/spec/leaseDurationSeconds", value: 1}
  ]'
}

fence_lease_release_command() {
  local state="$1"
  local holder="$2"
  local patch

  patch="$(fence_lease_release_patch "${state}" "${holder}")"
  printf "kubectl --context %s -n flux-system patch lease %s --type=json -p %s" \
    "$(fence_shell_quote "${KUBE_CONTEXT}")" "${SYNC_LEASE_NAME}" "$(fence_shell_quote "${patch}")"
}

# One CAS-guarded patch, mirroring restore_node_schedulability_if_needed's own
# release patch. The node path previously printed a bare `uncordon` plus one
# `annotate … -` per annotation: three unguarded commands, each racing whatever
# the report observed. Between reading the report and pasting them an operator
# can lose the race — a new transaction claims the node, and the stale commands
# then strip ITS fence and uncordon a node it is actively draining. Test ops
# make that impossible: the API rejects the whole patch if the UID,
# resourceVersion, owner, or journal moved, so a lost race fails loudly instead
# of silently releasing someone else's fence. Emitting it as a single patch is
# what makes it atomic — three commands cannot be, however each is guarded.
fence_node_release_command() {
  local name="$1"
  local uid="$2"
  local resource_version="$3"
  local owner="$4"
  local recovery="$5"
  local uncordon="$6"
  local patch

  # `test` on the annotation paths only when the annotation is actually present:
  # a test against a missing path fails, which would make the patch unusable for
  # a node fenced without a journal — the ordinary per-node claim.
  patch="$(jq -nc \
    --arg uid "${uid}" \
    --arg resource_version "${resource_version}" \
    --arg owner_path "${CORDON_OWNER_JSON_PATH}" \
    --arg owner "${owner}" \
    --arg recovery_path "${CORDON_RECOVERY_JSON_PATH}" \
    --arg recovery "${recovery}" \
    --argjson uncordon "${uncordon}" '
    [
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: "/metadata/resourceVersion", value: $resource_version}
    ]
    + (if $owner == "" then [] else
        [{op: "test", path: $owner_path, value: $owner}] end)
    + (if $recovery == "" then [] else
        [{op: "test", path: $recovery_path, value: $recovery}] end)
    + (if $uncordon then
        [{op: "add", path: "/spec/unschedulable", value: false}] else [] end)
    + (if $recovery == "" then [] else
        [{op: "remove", path: $recovery_path}] end)
    + (if $owner == "" then [] else
        [{op: "remove", path: $owner_path}] end)
  ')"
  printf "kubectl --context %s patch node %s --type=json -p %s" \
    "$(fence_shell_quote "${KUBE_CONTEXT}")" "${name}" "$(fence_shell_quote "${patch}")"
}

fence_kustomization_release_command() {
  local name="$1"
  local uid="$2"
  local holder="$3"
  local owner_path patch

  # Only the CHILD handoff carries `reconcile: disabled` — pause_flux_policy_parent
  # writes the owner annotation and spec.suspend and nothing else. Emitting the
  # reconcile test for the parent would make the whole patch fail its test op,
  # so the printed command could never release the root Kustomization. Mirror
  # each resume_* function exactly.
  if [[ "${name}" == "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" ]]; then
    owner_path="${FLUX_POLICY_HANDOFF_OWNER_JSON_PATH}"
    patch="$(jq -nc \
      --arg uid "${uid}" \
      --arg owner_path "${owner_path}" \
      --arg reconcile_path "${FLUX_RECONCILE_JSON_PATH}" \
      --arg holder "${holder}" '[
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: $owner_path, value: $holder},
      {op: "test", path: $reconcile_path, value: "disabled"},
      {op: "test", path: "/spec/suspend", value: true},
      {op: "add", path: "/spec/suspend", value: false},
      {op: "remove", path: $owner_path},
      {op: "remove", path: $reconcile_path}
    ]')"
  else
    owner_path="${FLUX_POLICY_PARENT_OWNER_JSON_PATH}"
    patch="$(jq -nc \
      --arg uid "${uid}" \
      --arg owner_path "${owner_path}" \
      --arg holder "${holder}" '[
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: $owner_path, value: $holder},
      {op: "test", path: "/spec/suspend", value: true},
      {op: "add", path: "/spec/suspend", value: false},
      {op: "remove", path: $owner_path}
    ]')"
  fi
  printf "kubectl --context %s -n flux-system patch %s %s --type=json -p %s" \
    "$(fence_shell_quote "${KUBE_CONTEXT}")" "${FLUX_KUSTOMIZATION_RESOURCE}" "${name}" "$(fence_shell_quote "${patch}")"
}

# Read-only, and deliberately before any credential work: an operator reaches
# for this exactly when a deploy is refusing to start, so it must not need a
# GHCR credential, a SOPS key, or a healthy fence to answer.
if [[ "${report_fences}" == "true" || "${recover_fences}" == "true" ]]; then
  fence_lease_state_file="${work_dir}/fence-lease-state.json"
  # This mode acquires nothing, so the release pass has nothing to do — and it
  # runs before the rest of the file is parsed into functions, so letting the
  # EXIT trap fire would call a cleanup helper that does not exist yet and turn
  # the report into a confusing secondary failure. Run it as an `if` condition:
  # errexit is suspended there, so a FAILED cluster read still reaches the
  # trap-disable below. A bare call would exit through the very handler this
  # has to avoid — and a failing read is exactly when an operator is reading.
  #
  # --recover-fences shares that shape: it acquires nothing either, and its own
  # release is a single CAS patch that either lands or is refused, so there is
  # still nothing for the release pass to unwind.
  if [[ "${recover_fences}" == "true" ]]; then
    if recover_fences_now; then
      fence_report_status=0
    else
      fence_report_status=$?
    fi
  elif report_fences_now; then
    fence_report_status=0
  else
    fence_report_status=$?
  fi
  trap - EXIT
  rm -rf "${work_dir}"
  exit "${fence_report_status}"
fi

# Force an ESO resource to reconcile and observe a post-annotation Ready edge.
force_sync_resource() {
  local kind="$1"
  local namespace="$2"
  local name="$3"
  local before_file="${work_dir}/${kind}-${namespace}-${name}-before.json"
  local annotated_file="${work_dir}/${kind}-${namespace}-${name}-annotated.json"
  local current_file="${work_dir}/${kind}-${namespace}-${name}-current.json"
  local before_refresh
  local annotated_resource_version
  local attempt
  local stamp

  kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace "${namespace}" \
    get "${kind}" "${name}" \
    -o json \
    >"${before_file}"
  before_refresh="$(jq -r '.status.refreshTime // ""' "${before_file}")"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}"

  kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace "${namespace}" \
    annotate "${kind}" "${name}" \
    "force-sync=${stamp}" \
    --overwrite \
    -o json \
    >"${annotated_file}"
  annotated_resource_version="$(jq -er '.metadata.resourceVersion' \
    "${annotated_file}")"

  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace "${namespace}" \
      get "${kind}" "${name}" \
      -o json \
      >"${current_file}"
    if jq -e \
      --arg before "${before_refresh}" \
      --arg annotated_resource_version "${annotated_resource_version}" '
      (.status.refreshTime // "") as $refresh
      | (($refresh != "" and $refresh != $before)
          or ((.metadata.resourceVersion // "") != ""
            and .metadata.resourceVersion != $annotated_resource_version))
        and any(.status.conditions[]?;
          .type == "Ready" and .status == "True")
    ' "${current_file}" >/dev/null; then
      return 0
    fi
    sleep "${SYNC_INTERVAL}"
  done

  echo "::error::Timed out waiting for ${kind}/${namespace}/${name} to complete the forced GHCR credential sync."
  return 1
}

# Verify that a namespace's materialized GHCR Secret matches the SOPS source.
verify_consumer_secret() {
  local namespace="$1"
  local secret_file="${work_dir}/consumer-${namespace}.json"
  local decoded_file="${work_dir}/consumer-${namespace}-decoded.json"
  local normalized_file="${work_dir}/consumer-${namespace}-normalized.json"

  kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace "${namespace}" \
    get secret ghcr-auth \
    -o json \
    >"${secret_file}"
  if ! jq -er '.data[".dockerconfigjson"] | @base64d' \
    "${secret_file}" \
    >"${decoded_file}" 2>/dev/null ||
    ! jq -S -c . "${decoded_file}" >"${normalized_file}" 2>/dev/null ||
    ! cmp -s "${expected_normalized}" "${normalized_file}"; then
    echo "::error::ExternalSecret ${namespace}/ghcr-auth did not materialise the Git/SOPS GHCR credential."
    return 1
  fi
}

# Emit bounded, printable output only from operations that cannot contain the
# registry credential. Prefix each line so it cannot become a workflow command.
emit_safe_operation_output() {
  local label="$1" result_file="$2"
  [[ -s "${result_file}" ]] || return 0

  LC_ALL=C tr -cd '\11\12\40-\176' <"${result_file}" |
    tail -n 50 |
    sed -e "s/^/${label}: /" >&2 ||
    true
}

# Prove a Docker credential with real manifest reads for every package this
# deployment can pull. Callers provide mode-0600 curl config/temp paths so the
# credential never appears in argv or output. This serves both the incoming
# SOPS credential and the still-live root credential whose overlap keeps peers
# safe while the first stale node drains.
verify_ghcr_pull_credential() {
  local basic_config="$1"
  local token_file="$2"
  local bearer_config="$3"
  local credential_label="$4"
  local target repository reference http_status

  for target in "${REQUIRED_PULL_TARGETS[@]}"; do
    repository="${target%:*}"
    reference="${target##*:}"
    if ! http_status="$(curl --disable \
      --config "${basic_config}" \
      --connect-timeout 10 \
      --max-time 60 \
      --silent \
      --show-error \
      --output "${token_file}" \
      --write-out '%{http_code}' \
      --get \
      --data-urlencode 'service=ghcr.io' \
      --data-urlencode "scope=repository:${repository}:pull" \
      'https://ghcr.io/token')"; then
      echo "::error::Could not request a GHCR pull token for ${repository} with the ${credential_label}; root Flux auth was not changed."
      return 1
    fi
    if [[ "${http_status}" != "200" ]] || ! jq -e '
      (.token // .access_token // "")
      | type == "string" and length > 0
    ' "${token_file}" >/dev/null; then
      echo "::error::The ${credential_label} could not obtain a pull token for ${repository} (GHCR HTTP ${http_status}); root Flux auth was not changed."
      return 1
    fi

    jq -r '
      (.token // .access_token) as $token
      | "header = " + (("Authorization: Bearer " + $token) | @json)
    ' "${token_file}" >"${bearer_config}"
    chmod 600 "${bearer_config}"

    if ! http_status="$(curl --disable \
      --config "${bearer_config}" \
      --connect-timeout 10 \
      --max-time 60 \
      --silent \
      --show-error \
      --output /dev/null \
      --write-out '%{http_code}' \
      --header 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json' \
      "https://ghcr.io/v2/${repository}/manifests/${reference}")"; then
      echo "::error::Could not read the GHCR manifest for ${target} with the ${credential_label}; root Flux auth was not changed."
      return 1
    fi
    if [[ "${http_status}" != "200" ]]; then
      echo "::error::The ${credential_label} cannot read ${target} (GHCR HTTP ${http_status}); root Flux auth was not changed."
      return 1
    fi
  done
}

# Before the first credential-stale node is drained, prove that the credential
# still stored in the live root Secret remains accepted by every GHCR package.
# Peers have not rebooted onto the incoming credential yet, so a revoked old
# credential would make them unsafe eviction destinations. Root auth stays old
# until the complete Talos convergence succeeds.
verify_current_root_credential_overlap() {
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get secret ksail-registry-credentials \
    -o json \
    >"${current_root_secret_file}"; then
    echo "::error::Could not read the current root GHCR credential; refusing to drain onto peers whose runtime credential cannot be proved."
    return 1
  fi
  if ! jq -er '.data[".dockerconfigjson"] | @base64d' \
    "${current_root_secret_file}" \
    >"${current_root_docker_config}" 2>/dev/null ||
    ! jq -e . "${current_root_docker_config}" >/dev/null 2>&1; then
    echo "::error::The current root GHCR credential is malformed; refusing to drain onto unproved peers."
    return 1
  fi
  if ! write_flux_ghcr_credentials \
    "${current_root_docker_config}" \
    "${current_root_credentials_file}"; then
    echo "::error::The current root GHCR credential cannot be parsed; refusing to drain onto unproved peers."
    return 1
  fi
  jq -r '
    "user = " + ((.username + ":" + .password) | @json)
  ' "${current_root_credentials_file}" \
    >"${current_root_basic_curl_config}"
  chmod 600 \
    "${current_root_docker_config}" \
    "${current_root_credentials_file}" \
    "${current_root_basic_curl_config}"

  verify_ghcr_pull_credential \
    "${current_root_basic_curl_config}" \
    "${current_root_token_response}" \
    "${current_root_bearer_curl_config}" \
    "current root GHCR credential"
}

delete_runtime_pull_probe() {
  local probe_name="$1"

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace ksail-operator \
    delete pod "${probe_name}" \
    --ignore-not-found \
    --wait=false \
    >"${runtime_probe_result_file}" 2>&1; then
    echo "::error::Could not remove runtime pull probe ${probe_name}; root Flux auth remains unchanged."
    emit_safe_operation_output "runtime-probe-delete" \
      "${runtime_probe_result_file}"
    return 1
  fi
  if [[ "${active_runtime_probe}" == "${probe_name}" ]]; then
    active_runtime_probe=""
  fi
}

# Exercise each possible eviction destination through kubelet/containerd with
# no imagePullSecret. A valid live root Secret is not sufficient evidence: in
# the legacy outage state, machine config already held the new token while the
# running runtime still presented a revoked predecessor. imagePullPolicy Always
# forces a registry resolution even when the exact private image is cached.
# Describe an observed probe Pod in bounded, non-sensitive terms. Kubelet and
# registry messages can carry node detail and scoped token URLs, so this reports
# only the enumerated state fields that make a failure diagnosable, never a raw
# message. An unreadable document degrades to "unavailable" rather than failing
# the caller: this is evidence for an error path that has already been decided.
summarize_runtime_probe_state() {
  jq -r '
    (first(.status.containerStatuses[]? | select(.name == "pull-probe")) // null) as $cs
    | [
        "phase=" + (.status.phase // "unknown"),
        "podReason=" + (.status.reason // "none"),
        (if $cs == null then
           "containerStatus=absent"
         else
           "containerStatus=present",
           "waitingReason=" + ($cs.state.waiting.reason // "none"),
           "terminatedReason=" + ($cs.state.terminated.reason // "none")
         end)
      ]
    | join(" ")
  ' "$1" 2>/dev/null || printf 'unavailable'
}

probe_node_runtime_pull() {
  local node_name="$1"
  local probe_image="$2"
  local probe_name
  local attempt create_attempt image_id waiting_reason auth_rejected
  local probe_created=0
  local probe_phase probe_state_summary="unavailable"

  assert_sync_lease_held || return 1
  runtime_probe_sequence=$((runtime_probe_sequence + 1))
  probe_name="ghcr-runtime-probe-$$-${RANDOM}-${runtime_probe_sequence}"
  jq -n \
    --arg name "${probe_name}" \
    --arg node "${node_name}" \
    --arg image "${probe_image}" '
    {
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "ksail-operator",
        labels: {
          "app.kubernetes.io/name": "ghcr-runtime-probe",
          "app.kubernetes.io/component": "credential-verification",
          "app.kubernetes.io/managed-by": "refresh-flux-ghcr-auth"
        }
      },
      spec: {
        nodeName: $node,
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        restartPolicy: "Never",
        terminationGracePeriodSeconds: 0,
        securityContext: {
          runAsNonRoot: true,
          runAsUser: 65532,
          runAsGroup: 65532,
          seccompProfile: {type: "RuntimeDefault"}
        },
        containers: [{
          name: "pull-probe",
          image: $image,
          imagePullPolicy: "Always",
          args: ["--version"],
          resources: {
            requests: {cpu: "10m", memory: "16Mi"},
            limits: {cpu: "100m", memory: "64Mi"}
          },
          securityContext: {
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: {drop: ["ALL"]}
          }
        }]
      }
    }
  ' >"${runtime_probe_manifest_file}"

  active_runtime_probe="${probe_name}"
  for ((create_attempt = 1; create_attempt <= RUNTIME_PROBE_CREATE_ATTEMPTS; create_attempt++)); do
    # The published infrastructure artifact still declares the legacy
    # two-policy topology until this transaction publishes its candidate. Flux
    # can reconcile that artifact during a long multi-node roll, so reassert
    # and verify the candidate policy immediately before every admission
    # attempt, including retries after an ambiguous timeout.
    stage_image_verification_webhook_budget || return 1
    assert_sync_lease_held || return 1
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace ksail-operator \
      create --filename "${runtime_probe_manifest_file}" \
      -o name \
      >"${runtime_probe_result_file}" 2>&1; then
      probe_created=1
      break
    fi

    # A timed-out admission response is ambiguous: the API server may have
    # persisted the Pod after the client stopped waiting. Reuse that exact
    # named probe when it exists; otherwise retry the same immutable manifest.
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace ksail-operator \
      get pod "${probe_name}" \
      -o name \
      >/dev/null 2>&1; then
      probe_created=1
      break
    fi

    if ((create_attempt < RUNTIME_PROBE_CREATE_ATTEMPTS)); then
      echo "::warning::Runtime pull probe admission failed on ${node_name} (attempt ${create_attempt}/${RUNTIME_PROBE_CREATE_ATTEMPTS}); retrying the same target."
      sleep "${SYNC_INTERVAL}"
    fi
  done

  if ((probe_created == 0)); then
    echo "::error::Could not create a kubelet/containerd GHCR pull probe on ${node_name}; refusing to drain onto an unproved runtime."
    emit_safe_operation_output "runtime-probe-create" \
      "${runtime_probe_result_file}"
    return 1
  fi

  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace ksail-operator \
      get pod "${probe_name}" \
      -o json \
      >"${runtime_probe_state_file}" 2>"${runtime_probe_result_file}"; then
      echo "::error::Could not read the kubelet/containerd GHCR pull probe on ${node_name}; refusing to drain onto an unproved runtime."
      emit_safe_operation_output "runtime-probe-read" \
        "${runtime_probe_result_file}"
      delete_runtime_pull_probe "${probe_name}" || true
      return 1
    fi
    if ! jq -e \
      '(.spec.imagePullSecrets // [] | length) == 0' \
      "${runtime_probe_state_file}" >/dev/null; then
      delete_runtime_pull_probe "${probe_name}" || true
      echo "::error::Runtime probe on ${node_name} received an imagePullSecret, so it did not prove the running containerd credential; refusing the drain."
      return 1
    fi
    probe_state_summary="$(summarize_runtime_probe_state \
      "${runtime_probe_state_file}")"
    image_id="$(jq -r '
      first(.status.containerStatuses[]?
        | select(.name == "pull-probe")
        | .imageID) // ""
    ' \
      "${runtime_probe_state_file}")"
    if [[ -n "${image_id}" ]]; then
      delete_runtime_pull_probe "${probe_name}" || return 1
      return 0
    fi
    # A terminal phase with no container status means the kubelet disposed of
    # the Pod without ever starting the probe container (for example
    # OutOfmemory/OutOfpods admission on the pinned node). The running
    # containerd credential was never exercised, so this is a mechanism
    # failure, not credential evidence. Polling it to the end of the budget
    # would spend the whole window and then misreport it as an unproved
    # runtime, which is exactly what made this undiagnosable in production.
    probe_phase="$(jq -r '.status.phase // ""' \
      "${runtime_probe_state_file}")"
    if [[ "${probe_phase}" == "Failed" || "${probe_phase}" == "Succeeded" ]] &&
      ! jq -e \
        'any(.status.containerStatuses[]?; .name == "pull-probe")' \
        "${runtime_probe_state_file}" >/dev/null; then
      delete_runtime_pull_probe "${probe_name}" || true
      echo "::error::The runtime pull probe on ${node_name} did not run (${probe_state_summary}); the running containerd credential was never exercised, so this is not credential evidence. Refusing the drain."
      return 1
    fi
    waiting_reason="$(jq -r '
      first(.status.containerStatuses[]?
        | select(.name == "pull-probe")
        | .state.waiting.reason) // ""
    ' \
      "${runtime_probe_state_file}")"
    case "${waiting_reason}" in
      ErrImagePull | ImagePullBackOff)
        auth_rejected="$(jq -r '
          first(.status.containerStatuses[]?
            | select(.name == "pull-probe")
            | .state.waiting.message) // ""
          | test(
              "(^|.*: )(unexpected status from GET request to https://ghcr\\.io/token(?:\\?[^[:space:]]*)?: (401 Unauthorized|403 Forbidden)|unauthorized: authentication required|insufficient_scope: authorization failed)$";
              "i"
            )
        ' "${runtime_probe_state_file}")"
        if [[ "${auth_rejected}" == "true" ]]; then
          runtime_probe_bootstrap_needed=1
        fi
        delete_runtime_pull_probe "${probe_name}" || true
        echo "::error::The running containerd on ${node_name} could not pull ${probe_image} (${waiting_reason}); refusing to drain workloads onto peers with unproved runtime auth."
        return 1
        ;;
      InvalidImageName)
        delete_runtime_pull_probe "${probe_name}" || true
        echo "::error::The runtime probe image ${probe_image} was invalid on ${node_name}; refusing to treat that as stale credential evidence."
        return 1
        ;;
    esac
    sleep "${SYNC_INTERVAL}"
  done

  delete_runtime_pull_probe "${probe_name}" || true
  echo "::error::Timed out proving the running containerd GHCR credential on ${node_name} after $((SYNC_ATTEMPTS))x${SYNC_INTERVAL}s (last observed probe state: ${probe_state_summary}); refusing to drain workloads onto an unproved runtime."
  return 1
}

# The credential bridge runs before the candidate artifact is published, so a
# policy fix carried by that artifact cannot repair admission for the runtime
# probes that protect the publish. Bootstrap the exact declarative consolidated
# IVPOL under the same synchronization lease, then retire the superseded KSail
# IVPOL and wait for its one effective fail-closed mutating/validating path.
# Applying the covering policy before deleting the old one preserves signature
# enforcement throughout; the transient overlap can deny but cannot admit an
# unverified image.
read_image_verification_webhooks() {
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get mutatingwebhookconfigurations.admissionregistration.k8s.io \
    -o json \
    >"${image_verification_mutating_webhooks_file}" \
    2>"${image_verification_policy_result_file}"; then
    echo "::error::Could not inspect effective Kyverno mutating admission webhooks; refusing runtime pull probes."
    emit_safe_operation_output \
      "image-verification-mutating-webhook-read" \
      "${image_verification_policy_result_file}"
    return 1
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get validatingwebhookconfigurations.admissionregistration.k8s.io \
    -o json \
    >"${image_verification_validating_webhooks_file}" \
    2>"${image_verification_policy_result_file}"; then
    echo "::error::Could not inspect effective Kyverno validating admission webhooks; refusing runtime pull probes."
    emit_safe_operation_output \
      "image-verification-validating-webhook-read" \
      "${image_verification_policy_result_file}"
    return 1
  fi
}

image_verification_webhook_set_matches() {
  local webhook_file="$1"
  local operation="$2"
  local exclusive="$3"
  local required="$4"

  jq -e \
    --argjson timeout "${IMAGE_VERIFICATION_WEBHOOK_TIMEOUT_SECONDS}" \
    --arg expected_path "/ivpol/${operation}/${IMAGE_VERIFICATION_POLICY}" \
    --arg retired "${RETIRED_IMAGE_VERIFICATION_POLICY}" \
    --argjson exclusive "${exclusive}" \
    --argjson required "${required}" '
    [
      .items[]?.webhooks[]?
      | select(
          (.clientConfig.service.name // "") == "kyverno-svc"
          and (.clientConfig.service.namespace // "") == "kyverno"
        )
    ] as $webhooks
    | (
      if $required then
        any(
          $webhooks[];
          (.clientConfig.service.path // "") == $expected_path
          and .failurePolicy == "Fail"
          and .timeoutSeconds == $timeout
        )
      else
        all(
          $webhooks[];
          ((.clientConfig.service.path // "") | contains($expected_path)) | not
        )
      end
    )
    and (
      if $exclusive then
        all(
          $webhooks[];
          (.clientConfig.service.path // "") as $path
          | if ($path | contains($retired)) then
              false
            elif ($path | contains($expected_path)) then
              $required
              and $path == $expected_path
              and .failurePolicy == "Fail"
              and .timeoutSeconds == $timeout
            else
              true
            end
        )
      else
        true
      end
    )
  ' "${webhook_file}" >/dev/null
}

image_verification_policy_needs_mutating_webhook() {
  # Kyverno v1.19 moved signature and attestation verification entirely into
  # validation. Its IVPOL mutating webhook now only pins digests, and the API
  # defaults mutateDigest to true when the field is absent.
  yq -e \
    '.spec.validationConfigurations.mutateDigest != false' \
    "${IMAGE_VERIFICATION_POLICY_FILE}" >/dev/null
}

wait_for_image_verification_webhooks() {
  local exclusive="$1"
  local attempt mutation_required=false

  if image_verification_policy_needs_mutating_webhook; then
    mutation_required=true
  fi

  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    assert_sync_lease_held || return 1
    read_image_verification_webhooks || return 1
    if image_verification_webhook_set_matches \
      "${image_verification_mutating_webhooks_file}" "mutate" "${exclusive}" \
      "${mutation_required}" &&
      image_verification_webhook_set_matches \
        "${image_verification_validating_webhooks_file}" "validate" "${exclusive}" true; then
      return 0
    fi
    if ((attempt < SYNC_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done
  return 1
}

stage_image_verification_webhook_budget() {
  if ! yq -e \
    '.apiVersion == "policies.kyverno.io/v1"
      and .kind == "ImageValidatingPolicy"
      and .metadata.name == "verify-app-images"
      and .spec.failurePolicy == "Fail"
      and .spec.webhookConfiguration.timeoutSeconds == 30
      and (
        .spec.validationConfigurations.mutateDigest == null
        or .spec.validationConfigurations.mutateDigest == true
        or .spec.validationConfigurations.mutateDigest == false
      )' \
    "${IMAGE_VERIFICATION_POLICY_FILE}" >/dev/null; then
    echo "::error::The candidate consolidated image-verification policy is malformed or not fail-closed; refusing runtime pull probes."
    return 1
  fi

  if ! yq -o=json '{"spec": .spec}' \
    "${IMAGE_VERIFICATION_POLICY_FILE}" \
    >"${image_verification_policy_patch_file}"; then
    echo "::error::Could not build the consolidated image-verification policy patch; refusing runtime pull probes."
    return 1
  fi

  assert_sync_lease_held || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    patch imagevalidatingpolicy.policies.kyverno.io \
    "${IMAGE_VERIFICATION_POLICY}" \
    --type=merge --dry-run=server \
    --patch-file="${image_verification_policy_patch_file}" \
    >"${image_verification_policy_result_file}" 2>&1; then
    echo "::error::The API server rejected the candidate consolidated image-verification policy; refusing runtime pull probes."
    emit_safe_operation_output \
      "image-verification-policy-dry-run" \
      "${image_verification_policy_result_file}"
    return 1
  fi

  assert_sync_lease_held || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    patch imagevalidatingpolicy.policies.kyverno.io \
    "${IMAGE_VERIFICATION_POLICY}" \
    --type=merge \
    --patch-file="${image_verification_policy_patch_file}" \
    >"${image_verification_policy_result_file}" 2>&1; then
    echo "::error::Could not stage the consolidated fail-closed image-verification policy; refusing runtime pull probes."
    emit_safe_operation_output \
      "image-verification-policy-apply" \
      "${image_verification_policy_result_file}"
    return 1
  fi

  # The existing app-only policy can already own a webhook path with the same
  # policy name. Require Kyverno to expose the candidate's exact independent
  # fail-closed shape while the retired KSail verifier is still present:
  # validation always, plus mutation only when digest pinning is enabled. This
  # closes the policy-cache handoff gap: deletion is not evidence that the
  # replacement has become effective.
  if ! wait_for_image_verification_webhooks false; then
    echo "::error::The consolidated fail-closed image-verification admission webhooks did not become effective before retirement of the existing KSail verifier."
    return 1
  fi

  assert_sync_lease_held || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    delete imagevalidatingpolicy.policies.kyverno.io \
    "${RETIRED_IMAGE_VERIFICATION_POLICY}" \
    --ignore-not-found \
    >"${image_verification_policy_result_file}" 2>&1; then
    echo "::error::Could not retire the superseded image-verification policy; refusing runtime pull probes."
    emit_safe_operation_output \
      "image-verification-policy-delete" \
      "${image_verification_policy_result_file}"
    return 1
  fi

  if ! wait_for_image_verification_webhooks true; then
    echo "::error::The consolidated fail-closed image-verification admission webhooks did not converge to one ${IMAGE_VERIFICATION_WEBHOOK_TIMEOUT_SECONDS}s policy path; refusing runtime pull probes."
    return 1
  fi

  echo "✅ Consolidated fail-closed image-verification admission is effective at ${IMAGE_VERIFICATION_WEBHOOK_TIMEOUT_SECONDS}s."
}

verify_peer_runtime_pull_overlap() {
  local draining_node="$1"
  local peer_name peer_uid
  local probe_image

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get nodes \
    -o json \
    >"${runtime_probe_nodes_file}"; then
    echo "::error::Could not list eviction destinations for runtime GHCR proof; refusing to drain ${draining_node}."
    return 1
  fi
  if ! validate_talos_node_inventory "${runtime_probe_nodes_file}"; then
    echo "::error::Eviction-destination inventory was ambiguous during runtime GHCR proof; refusing to drain ${draining_node}."
    return 1
  fi
  if ! jq -r \
    --arg draining "${draining_node}" '
    .items[]
    | select(.metadata.name != $draining)
    | select(.metadata.deletionTimestamp == null)
    | select((.spec.unschedulable // false) == false)
    | select(any(.spec.taints[]?;
        .effect == "NoSchedule" or .effect == "NoExecute") | not)
    | select(any(.status.conditions[]?;
        .type == "Ready" and .status == "True"))
    | [.metadata.name, .metadata.uid]
    | @tsv
  ' "${runtime_probe_nodes_file}" >"${runtime_probe_targets_file}"; then
    echo "::error::Could not select eviction destinations for runtime GHCR proof; refusing to drain ${draining_node}."
    return 1
  fi
  if [[ ! -s "${runtime_probe_targets_file}" ]]; then
    runtime_probe_bootstrap_needed=1
    echo "::error::No Ready schedulable peer can receive workloads while ${draining_node} reboots; refusing the drain."
    return 1
  fi

  while IFS=$'\t' read -r peer_name peer_uid; do
    [[ -n "${peer_name}" && -n "${peer_uid}" ]] || {
      echo "::error::Eviction-destination identity was empty during runtime GHCR proof; refusing to drain ${draining_node}."
      return 1
    }
    if grep -Fqx -- "${peer_uid}" "${runtime_proved_targets_file}"; then
      continue
    fi
    for probe_image in "${RUNTIME_CREDENTIAL_PROBE_IMAGES[@]}"; do
      probe_node_runtime_pull "${peer_name}" "${probe_image}" || return 1
    done
    printf '%s\n' "${peer_uid}" >>"${runtime_proved_targets_file}"
  done <"${runtime_probe_targets_file}"
}

verify_bootstrap_quarantine_covers_unproved_destinations() {
  local pending_targets_file="$1"
  local peer_name peer_uid

  if ! jq -r '
    .items[]
    | select(.metadata.deletionTimestamp == null)
    | select((.spec.unschedulable // false) == false)
    | select(any(.spec.taints[]?;
        .effect == "NoSchedule" or .effect == "NoExecute") | not)
    | select(any(.status.conditions[]?;
        .type == "Ready" and .status == "True"))
    | [.metadata.name, .metadata.uid]
    | @tsv
  ' "${runtime_probe_nodes_file}" >"${runtime_probe_targets_file}"; then
    echo "::error::Could not enumerate workload destinations for bootstrap quarantine; refusing the roll."
    return 1
  fi

  while IFS=$'\t' read -r peer_name peer_uid; do
    [[ -n "${peer_name}" && -n "${peer_uid}" ]] || {
      echo "::error::Workload-destination identity was empty during bootstrap quarantine; refusing the roll."
      return 1
    }
    if grep -Fqx -- "${peer_uid}" "${runtime_proved_targets_file}"; then
      continue
    fi
    if ! awk -F '\t' -v uid="${peer_uid}" '
      $4 == "reboot" && $5 == uid { found = 1 }
      END { exit !found }
    ' "${pending_targets_file}"; then
      echo "::error::Runtime-unproved workload destination ${peer_name} is not a pending credential-reboot target; refusing bootstrap quarantine."
      return 1
    fi
  done <"${runtime_probe_targets_file}"
}

# Atomically claim the right to reverse the cordon and make the node
# unschedulable. Combining both mutations closes the gap where another actor
# could cordon after our ownership annotation but before kubectl drain. A bare
# cordon after this patch is an idempotent no-op; an actor taking over an
# already-cordoned node must replace the annotation to express new ownership.
claim_node_cordon_ownership() {
  local node_name="$1" owner_token="$2" state_file="$3" result_file="$4"
  local recovery_record="${5:-}"
  local was_cordoned="${6:-}" initial_taints="${7:-}"
  local resource_version node_uid initial_node_uid
  local attempt=1
  local max_attempts="${CORDON_CLAIM_MAX_ATTEMPTS:-5}"
  # The re-read below needs its own stderr sink. Pointed at result_file it would
  # succeed, write nothing, and truncate the conflict output that explains why
  # the claim was refused — leaving the operator a bare refusal with no cause in
  # exactly the case that matters most, a concurrent actor changing the node.
  local reread_error_file="${result_file}.reread"

  initial_node_uid="$(jq -er '.metadata.uid' "${state_file}")"

  while :; do
    build_and_apply_cordon_claim \
      "${node_name}" "${owner_token}" "${state_file}" "${result_file}" \
      "${recovery_record}" && return 0

    # Only a conflict against a still-conforming node is retryable, and only
    # when the caller supplied the scheduling facts needed to re-verify that.
    if [[ -z "${was_cordoned}" || -z "${initial_taints}" ]] ||
      ((attempt >= max_attempts)); then
      break
    fi

    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json \
      >"${state_file}" 2>"${reread_error_file}"; then
      # A failed re-read is now the actionable cause, so it replaces the claim
      # conflict in the emitted output. The redirection truncates result_file
      # before cat runs, so a failed copy would leave it EMPTY -- and
      # emit_safe_operation_output skips an empty file entirely, which is the
      # very silence this block exists to prevent. Fall back to a deterministic
      # non-empty line instead of discarding the failure.
      if ! cat "${reread_error_file}" >"${result_file}" 2>/dev/null; then
        echo "node re-read failed; its diagnostic could not be read" \
          >"${result_file}"
      fi
      break
    fi

    if ! node_claim_preconditions_still_hold \
      "${state_file}" "${initial_node_uid}" \
      "${was_cordoned}" "${initial_taints}"; then
      break
    fi

    attempt=$((attempt + 1))
  done

  rm -f "${reread_error_file}"
  echo "::error::Could not atomically claim and cordon Talos node ${node_name}; refusing to drain it."
  emit_safe_operation_output "cordon-claim" "${result_file}"
  return 1
}

# Render the claim patch from the current captured state and apply it. Split out
# so a rejected claim can be rebuilt against a re-read resourceVersion without
# duplicating the patch shape.
build_and_apply_cordon_claim() {
  local node_name="$1" owner_token="$2" state_file="$3" result_file="$4"
  local recovery_record="${5:-}"
  local resource_version node_uid
  resource_version="$(jq -er '.metadata.resourceVersion' "${state_file}")"
  node_uid="$(jq -er '.metadata.uid' "${state_file}")"

  if jq -e '.metadata.annotations | type == "object"' \
    "${state_file}" >/dev/null; then
    jq -n \
      --arg owner_path "${CORDON_OWNER_JSON_PATH}" \
      --arg owner "${owner_token}" \
      --arg recovery_path "${CORDON_RECOVERY_JSON_PATH}" \
      --arg recovery "${recovery_record}" \
      --arg phase_path "${CORDON_PHASE_JSON_PATH}" \
      --arg uid "${node_uid}" \
      --arg resource_version "${resource_version}" '
      [
        {
          op: "test",
          path: "/metadata/resourceVersion",
          value: $resource_version
        },
        {op: "test", path: "/metadata/uid", value: $uid},
        {op: "add", path: $owner_path, value: $owner},
        {op: "add", path: $phase_path, value: "claimed"}
      ]
      + (if $recovery == "" then [] else
          [{op: "add", path: $recovery_path, value: $recovery}]
        end)
      + [
        {op: "add", path: "/spec/unschedulable", value: true}
      ]
    ' >"${cordon_claim_patch_file}"
  else
    jq -n \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
      --arg owner "${owner_token}" \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      --arg recovery "${recovery_record}" \
      --arg phase_annotation "${CORDON_PHASE_ANNOTATION}" \
      --arg uid "${node_uid}" \
      --arg resource_version "${resource_version}" '
      [
        {
          op: "test",
          path: "/metadata/resourceVersion",
          value: $resource_version
        },
        {op: "test", path: "/metadata/uid", value: $uid},
        {
          op: "add",
          path: "/metadata/annotations",
          value: ({($owner_annotation): $owner,
                   ($phase_annotation): "claimed"}
            + (if $recovery == "" then {} else
                {($recovery_annotation): $recovery}
              end))
        },
        {op: "add", path: "/spec/unschedulable", value: true}
      ]
    ' >"${cordon_claim_patch_file}"
  fi

  kubectl \
    --context "${KUBE_CONTEXT}" \
    patch node "${node_name}" \
    --type=json \
    --patch-file="${cordon_claim_patch_file}" \
    >"${result_file}" 2>&1
}

# The atomic claim cordons the node before kubectl drain. Restore schedulability
# only when this bridge owns that cordon; a pre-existing operator cordon must
# remain untouched.
node_schedulability_release_is_complete() {
  local state_file="$1" node_uid="$2" was_cordoned="$3"

  jq -e \
    --arg uid "${node_uid}" \
    --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    --argjson was_cordoned "${was_cordoned}" '
    .metadata.uid == $uid
    and (((.metadata.annotations // {})[$owner_annotation] // "") == "")
    and (((.metadata.annotations // {})[$recovery_annotation] // "") == "")
    and ((.spec.unschedulable // false) == ($was_cordoned == 1))
  ' "${state_file}" >/dev/null
}

restore_node_schedulability_if_needed() {
  local node_name="$1" was_cordoned="$2" owner_token="$3"
  local initial_node_uid="$4" initial_node_taints="$5" result_file="$6"
  local expected_recovery="${7:-}"
  local release_attempt="${8:-1}"
  local current_resource_version current_recovery

  if [[ -z "${owner_token}" ]]; then
    echo "::error::Refusing to release Talos node ${node_name} without a bridge ownership token."
    return 1
  fi

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get node "${node_name}" \
    --output json \
    >"${cordon_state_file}" 2>"${result_file}"; then
    echo "::error::Could not re-read Talos node ${node_name}; refusing to uncordon it."
    emit_safe_operation_output "uncordon-read" "${result_file}"
    return 1
  fi
  if node_schedulability_release_is_complete \
    "${cordon_state_file}" "${initial_node_uid}" "${was_cordoned}"; then
    if [[ "${was_cordoned}" == "0" ]]; then
      echo "Restored schedulability on ${node_name}."
    else
      echo "Released bridge ownership while preserving the pre-existing cordon on ${node_name}."
    fi
    return 0
  fi
  if ! node_scheduling_state_is_safe_to_reboot \
    "${cordon_state_file}" \
    "${was_cordoned}" \
    "${owner_token}" \
    "${initial_node_uid}" \
    "${initial_node_taints}"; then
    echo "::error::Cordon ownership changed or scheduling safety state changed for Talos node ${node_name}; refusing to uncordon it."
    return 1
  fi
  current_resource_version="$(jq -er \
    '.metadata.resourceVersion' "${cordon_state_file}")"
  current_recovery="$(jq -r \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    '.metadata.annotations[$recovery_annotation] // ""' \
    "${cordon_state_file}")"
  if [[ "${current_recovery}" != "${expected_recovery}" ]]; then
    echo "::error::Recovery journal changed for Talos node ${node_name}; refusing to release its cordon ownership."
    return 1
  fi
  if [[ -n "${current_recovery}" ]] &&
    ! jq -ne \
      --arg recovery "${current_recovery}" \
      --arg owner "${owner_token}" \
      --arg uid "${initial_node_uid}" '
      ($recovery | fromjson?) as $record
      | $record != null
      and $record.v == 1
      and $record.owner == $owner
      and $record.uid == $uid
      and ($record.phase == "rollback-safe"
        or $record.phase == "active"
        or $record.phase == "retain"
        or $record.phase == "release-ready")
    ' >/dev/null; then
    echo "::error::Recovery journal changed or was malformed for Talos node ${node_name}; refusing to release its cordon ownership."
    return 1
  fi

  jq -n \
    --arg path "${CORDON_OWNER_JSON_PATH}" \
    --arg owner "${owner_token}" \
    --arg recovery_path "${CORDON_RECOVERY_JSON_PATH}" \
    --arg recovery "${current_recovery}" \
    --arg uid "${initial_node_uid}" \
    --arg resource_version "${current_resource_version}" \
    --argjson was_cordoned "${was_cordoned}" '
    [
      {op: "test", path: $path, value: $owner},
      {op: "test", path: "/metadata/uid", value: $uid},
      {
        op: "test",
        path: "/metadata/resourceVersion",
        value: $resource_version
      }
    ]
    + (if $was_cordoned == 0 then
        [{op: "add", path: "/spec/unschedulable", value: false}]
      else [] end)
    + (if $recovery == "" then [] else
        [
          {op: "test", path: $recovery_path, value: $recovery},
          {op: "remove", path: $recovery_path}
        ]
      end)
    + [{op: "remove", path: $path}]
  ' >"${cordon_release_patch_file}"

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    patch node "${node_name}" \
    --type=json \
    --patch-file="${cordon_release_patch_file}" \
    >"${result_file}" 2>&1; then
    if ((release_attempt < CORDON_RELEASE_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
      if restore_node_schedulability_if_needed \
        "${node_name}" "${was_cordoned}" "${owner_token}" \
        "${initial_node_uid}" "${initial_node_taints}" \
        "${result_file}" "${expected_recovery}" \
        "$((release_attempt + 1))"; then
        return 0
      fi
      return 1
    fi
    echo "::error::Cordon ownership changed or could not be released for Talos node ${node_name}; refusing to uncordon it."
    emit_safe_operation_output "uncordon" "${result_file}"
    return 1
  fi
  if [[ "${was_cordoned}" == "0" ]]; then
    echo "Restored schedulability on ${node_name}."
  else
    echo "Released bridge ownership while preserving the pre-existing cordon on ${node_name}."
  fi
}

update_bootstrap_recovery_phase() {
  local node_name="$1" owner_token="$2" initial_node_uid="$3"
  local desired_revision="$4" expected_phase="$5" next_phase="$6"
  local result_file="$7"
  local current_recovery updated_recovery current_resource_version
  local was_cordoned initial_taints

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get node "${node_name}" \
    --output json \
    >"${cordon_state_file}" 2>"${result_file}"; then
    echo "::error::Could not re-read bootstrap recovery journal for ${node_name}; refusing to cross the reboot/release edge."
    emit_safe_operation_output "recovery-read" "${result_file}"
    return 1
  fi
  current_recovery="$(jq -r \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    '.metadata.annotations[$recovery_annotation] // ""' \
    "${cordon_state_file}")"
  if ! jq -ne \
    --arg recovery "${current_recovery}" \
    --arg owner "${owner_token}" \
    --arg uid "${initial_node_uid}" \
    --arg revision "${desired_revision}" \
    --arg phase "${expected_phase}" '
    ($recovery | fromjson?) as $record
    | $record != null
    and ($record | keys | sort) == ([
      "desiredRevision", "initialTaints", "owner", "phase",
      "uid", "v", "wasCordoned"
    ] | sort)
    and $record.v == 1
    and $record.owner == $owner
    and $record.uid == $uid
    and $record.desiredRevision == $revision
    and ($record.wasCordoned == 0 or $record.wasCordoned == 1)
    and ($record.initialTaints | type == "array")
    and $record.phase == $phase
  '; then
    echo "::error::Bootstrap recovery journal for ${node_name} was missing, malformed, or changed; refusing to cross the reboot/release edge."
    return 1
  fi
  was_cordoned="$(jq -nr \
    --arg recovery "${current_recovery}" \
    '$recovery | fromjson | .wasCordoned')"
  initial_taints="$(jq -nc \
    --arg recovery "${current_recovery}" \
    '$recovery | fromjson | .initialTaints')"
  if ! node_scheduling_state_is_safe_to_reboot \
    "${cordon_state_file}" "${was_cordoned}" "${owner_token}" \
    "${initial_node_uid}" "${initial_taints}"; then
    echo "::error::Bootstrap scheduling state changed on ${node_name}; refusing to cross the reboot/release edge."
    return 1
  fi
  current_resource_version="$(jq -er \
    '.metadata.resourceVersion' "${cordon_state_file}")"
  updated_recovery="$(jq -cn \
    --arg recovery "${current_recovery}" \
    --arg phase "${next_phase}" '
    ($recovery | fromjson) + {phase: $phase}
  ')"
  jq -n \
    --arg owner_path "${CORDON_OWNER_JSON_PATH}" \
    --arg recovery_path "${CORDON_RECOVERY_JSON_PATH}" \
    --arg owner "${owner_token}" \
    --arg recovery "${current_recovery}" \
    --arg updated_recovery "${updated_recovery}" \
    --arg uid "${initial_node_uid}" \
    --arg resource_version "${current_resource_version}" '
    [
      {op: "test", path: $owner_path, value: $owner},
      {op: "test", path: $recovery_path, value: $recovery},
      {op: "test", path: "/metadata/uid", value: $uid},
      {
        op: "test",
        path: "/metadata/resourceVersion",
        value: $resource_version
      },
      {op: "replace", path: $recovery_path, value: $updated_recovery}
    ]
  ' >"${cordon_recovery_patch_file}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    patch node "${node_name}" \
    --type=json \
    --patch-file="${cordon_recovery_patch_file}" \
    >"${result_file}" 2>&1; then
    echo "::error::Bootstrap recovery phase changed or could not be updated for ${node_name}; refusing to cross the reboot/release edge."
    emit_safe_operation_output "recovery-phase" "${result_file}"
    return 1
  fi
}

# Rollback only bootstrap cordons still owned by this invocation. A node that
# reached the reboot edge stays cordoned on uncertainty, matching the normal
# fail-closed path. Missing ownership means the node was already restored or a
# newer actor took over; neither case is ours to reverse.
cleanup_bootstrap_quarantine() {
  local state_file node_name was_cordoned owner_token initial_uid
  local initial_taints current_owner current_recovery expected_recovery
  local expected_phase desired_revision
  local cleanup_failed=0

  [[ -d "${bootstrap_cordon_dir:-}" ]] || return 0
  for state_file in "${bootstrap_cordon_dir}"/*.json; do
    [[ -e "${state_file}" ]] || continue
    if ! node_name="$(jq -er '.nodeName' "${state_file}")" ||
      ! was_cordoned="$(jq -er '.wasCordoned' "${state_file}")"; then
      echo "::error::Could not read bootstrap recovery state from ${state_file}; the durable node journal was left intact."
      cleanup_failed=1
      continue
    fi
    if [[ -e "${bootstrap_retain_dir}/${node_name}" ]]; then
      continue
    fi
    if ! owner_token="$(jq -er '.ownerToken' "${state_file}")" ||
      ! initial_uid="$(jq -er '.initialUID' "${state_file}")" ||
      ! initial_taints="$(jq -c '.initialTaints' "${state_file}")" ||
      ! expected_recovery="$(jq -er '.recoveryRecord' "${state_file}")"; then
      echo "::error::Bootstrap recovery state for ${node_name} was malformed; the durable node journal was left intact."
      cleanup_failed=1
      continue
    fi
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json \
      >"${cordon_state_file}" 2>/dev/null; then
      echo "::error::Could not re-read bootstrap-owned node ${node_name} during rollback; its durable recovery journal was left intact."
      cleanup_failed=1
      continue
    fi
    current_owner="$(jq -r \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
      '.metadata.annotations[$owner_annotation] // ""' \
      "${cordon_state_file}")"
    current_recovery="$(jq -r \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      '.metadata.annotations[$recovery_annotation] // ""' \
      "${cordon_state_file}")"
    if [[ "${current_owner}" != "${owner_token}" ]]; then
      if [[ -z "${current_owner}" && -z "${current_recovery}" ]]; then
        rm -f "${state_file}"
      elif [[ -z "${current_owner}" ]]; then
        echo "::error::Bootstrap recovery journal on ${node_name} remained after its owner disappeared; refusing to discard the local recovery state."
        cleanup_failed=1
      else
        echo "::error::Bootstrap owner changed on ${node_name} during rollback; refusing to release the cordon."
        cleanup_failed=1
      fi
      continue
    fi
    expected_phase="$(jq -nr \
      --arg recovery "${expected_recovery}" \
      '$recovery | fromjson? | .phase // ""')"
    if [[ "${current_recovery}" == "${expected_recovery}" &&
      "${expected_phase}" == "active" ]]; then
      desired_revision="$(jq -nr \
        --arg recovery "${expected_recovery}" \
        '$recovery | fromjson? | .desiredRevision // ""')"
      if [[ ! "${desired_revision}" =~ ^[0-9a-f]{64}$ ]] ||
        ! update_bootstrap_recovery_phase \
          "${node_name}" "${owner_token}" "${initial_uid}" \
          "${desired_revision}" "active" "rollback-safe" \
          "${drain_result_file}"; then
        echo "::error::Could not mark bootstrap recovery on ${node_name} rollback-safe during cleanup; leaving it cordoned."
        cleanup_failed=1
        continue
      fi
      expected_recovery="$(jq -cn \
        --arg recovery "${expected_recovery}" '
        ($recovery | fromjson) + {phase: "rollback-safe"}
      ')"
    fi
    if restore_node_schedulability_if_needed \
      "${node_name}" "${was_cordoned}" "${owner_token}" \
      "${initial_uid}" "${initial_taints}" \
      "${drain_result_file}" "${expected_recovery}"; then
      rm -f "${state_file}"
    else
      cleanup_failed=1
    fi
  done
  return "${cleanup_failed}"
}

reconcile_bootstrap_recovery_journals() {
  local desired_revision="$1"
  local node_json node_name owner_token initial_uid initial_taints
  local was_cordoned phase recorded_revision recovery_record
  local reconcile_failed=0

  assert_sync_lease_held || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get nodes \
    -o json >"${recovery_nodes_file}"; then
    echo "::error::Could not inspect durable GHCR bootstrap recovery journals; refusing a new rollout."
    return 1
  fi
  if ! validate_talos_node_inventory "${recovery_nodes_file}"; then
    echo "::error::Node inventory was malformed while reconciling durable GHCR bootstrap recovery journals."
    return 1
  fi
  if ! jq -c \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" '
    .items[]
    | select((.metadata.annotations[$recovery_annotation] // "") != "")
  ' "${recovery_nodes_file}" >"${recovery_targets_file}"; then
    echo "::error::Could not select durable GHCR bootstrap recovery journals."
    return 1
  fi
  if ! jq -e \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
    --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" '
    [
      .items[]
      | select((.metadata.annotations[$recovery_annotation] // "") != "")
      | . as $node
      | ($node.metadata.annotations[$recovery_annotation] | fromjson?) as $record
      | {node: $node, record: $record}
    ] as $journals
    | all($journals[];
        .record != null
        and (.record | keys | sort) == ([
          "desiredRevision", "initialTaints", "owner", "phase",
          "uid", "v", "wasCordoned"
        ] | sort)
        and .record.v == 1
        and (.record.owner | type == "string" and length > 0)
        and (.record.uid | type == "string" and length > 0)
        and (.record.desiredRevision
          | type == "string" and test("^[0-9a-f]{64}$"))
        and (.record.wasCordoned == 0 or .record.wasCordoned == 1)
        and (.record.initialTaints | type == "array")
        and (.record.phase == "rollback-safe"
          or .record.phase == "active"
          or .record.phase == "retain"
          or .record.phase == "release-ready")
        and .node.metadata.uid == .record.uid
        and .node.metadata.deletionTimestamp == null
        and .node.metadata.annotations[$owner_annotation] == .record.owner)
  ' "${recovery_nodes_file}" >/dev/null; then
    echo "::error::At least one durable GHCR bootstrap recovery journal is malformed or does not match its owner/UID; refusing every recovery mutation."
    return 1
  fi
  if ! jq -r \
    --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" '
    [
      .items[]
      | select((.metadata.annotations[$recovery_annotation] // "") != "")
      | (.metadata.annotations[$recovery_annotation] | fromjson)
    ]
    | sort_by(.owner)
    | group_by(.owner)[]
    | select(
        (map(.phase) | unique | length) > 1
        or .[0].phase == "active"
        or .[0].phase == "retain"
      )
    | .[0].owner
  ' "${recovery_nodes_file}" >"${recovery_blocked_owners_file}"; then
    echo "::error::Could not group durable GHCR bootstrap recovery journals by owner."
    return 1
  fi

  while IFS= read -r node_json; do
    [[ -n "${node_json}" ]] || continue
    printf '%s\n' "${node_json}" >"${recovery_node_file}"
    node_name="$(jq -r '.metadata.name // ""' "${recovery_node_file}")"
    recovery_record="$(jq -r \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      '.metadata.annotations[$recovery_annotation] // ""' \
      "${recovery_node_file}")"
    if ! jq -e \
      --arg recovery "${recovery_record}" \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
      --arg node_name "${node_name}" '
      ($recovery | fromjson?) as $record
      | $record != null
      and ($record | keys | sort) == ([
        "desiredRevision", "initialTaints", "owner", "phase",
        "uid", "v", "wasCordoned"
      ] | sort)
      and $record.v == 1
      and ($record.owner | type == "string" and length > 0)
      and ($record.uid | type == "string" and length > 0)
      and ($record.desiredRevision
        | type == "string" and test("^[0-9a-f]{64}$"))
      and ($record.wasCordoned == 0 or $record.wasCordoned == 1)
      and ($record.initialTaints | type == "array")
      and ($record.phase == "rollback-safe"
        or $record.phase == "active"
        or $record.phase == "retain"
        or $record.phase == "release-ready")
      and .metadata.name == $node_name
      and .metadata.uid == $record.uid
      and .metadata.deletionTimestamp == null
      and .metadata.annotations[$owner_annotation] == $record.owner
    ' "${recovery_node_file}" >/dev/null; then
      echo "::error::Durable GHCR bootstrap recovery journal on ${node_name:-unknown node} is malformed or does not match its owner/UID; refusing to execute it."
      reconcile_failed=1
      continue
    fi
    printf '%s\n' "${recovery_record}" >"${recovery_record_file}"
    owner_token="$(jq -er '.owner' "${recovery_record_file}")"
    initial_uid="$(jq -er '.uid' "${recovery_record_file}")"
    initial_taints="$(jq -c '.initialTaints' "${recovery_record_file}")"
    was_cordoned="$(jq -er '.wasCordoned' "${recovery_record_file}")"
    phase="$(jq -er '.phase' "${recovery_record_file}")"
    recorded_revision="$(jq -er '.desiredRevision' "${recovery_record_file}")"

    if grep -Fqx -- "${owner_token}" "${recovery_blocked_owners_file}"; then
      echo "::error::Bootstrap recovery owner ${owner_token} still has an active, retained, or mixed-phase quarantine; refusing to release any node in that batch."
      reconcile_failed=1
      continue
    fi

    case "${phase}" in
      rollback-safe)
        ;;
      release-ready)
        if [[ "${recorded_revision}" != "${desired_revision}" ]]; then
          echo "::error::Release-ready bootstrap journal on ${node_name} belongs to a different credential revision; leaving it cordoned."
          reconcile_failed=1
          continue
        fi
        ;;
      active)
        echo "::error::Bootstrap node ${node_name} has an active or interrupted pre-reboot mutation; leaving it cordoned for explicit recovery."
        reconcile_failed=1
        continue
        ;;
      retain)
        echo "::error::Bootstrap node ${node_name} crossed the reboot edge without a release-ready proof; leaving it cordoned for explicit recovery."
        reconcile_failed=1
        continue
        ;;
    esac

    if ! assert_sync_lease_held; then
      reconcile_failed=1
      continue
    fi
    if ! restore_node_schedulability_if_needed \
      "${node_name}" "${was_cordoned}" "${owner_token}" \
      "${initial_uid}" "${initial_taints}" "${drain_result_file}" \
      "${recovery_record}"; then
      echo "::error::Could not reconcile durable GHCR bootstrap recovery journal on ${node_name}; leaving it cordoned."
      reconcile_failed=1
    fi
  done <"${recovery_targets_file}"

  return "${reconcile_failed}"
}

node_has_no_evictable_workloads() {
  local node_name="$1"
  local pods_file="${work_dir}/bootstrap-pods-${node_name}.json"

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get pods \
    --all-namespaces \
    --field-selector "spec.nodeName=${node_name}" \
    -o json >"${pods_file}"; then
    echo "::error::Could not inspect workloads on bootstrap candidate ${node_name}; refusing to infer that it is empty."
    return 2
  fi
  jq -e '
    (.items | type == "array")
    and all(.items[];
      (.status.phase == "Succeeded" or .status.phase == "Failed")
      or ((.metadata.annotations["kubernetes.io/config.mirror"] // "") != "")
      or any(.metadata.ownerReferences[]?; .kind == "DaemonSet"))
  ' "${pods_file}" >/dev/null
}

node_is_ready_workload_destination() {
  local state_file="$1"
  local expected_uid="$2"

  jq -e \
    --arg uid "${expected_uid}" '
    .metadata.uid == $uid
    and .metadata.deletionTimestamp == null
    and ((.spec.unschedulable // false) == false)
    and any(.status.conditions[]?;
      .type == "Ready" and .status == "True")
    and all(.spec.taints[]?;
      .effect != "NoSchedule" and .effect != "NoExecute")
  ' "${state_file}" >/dev/null
}

wait_for_bootstrap_seed_release() {
  local node_name="$1" node_uid="$2" node_ip="$3" node_role="$4"
  local attempt

  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json >"${cordon_state_file}"; then
      echo "::error::Could not re-read proven bootstrap seed ${node_name} while waiting for scheduling release."
      return 1
    fi
    if ! selected_node_identity_is_current \
      "${cordon_state_file}" "${node_name}" "${node_uid}" \
      "${node_ip}" "${node_role}"; then
      echo "::error::Proven bootstrap seed ${node_name} changed identity before it could become an eviction destination."
      return 1
    fi
    # The release patch is already committed at this point. Wait only for
    # Kubernetes' controller-owned Ready/taint projection; an owner, renewed
    # spec cordon, or unrelated hard taint is newer scheduling intent.
    if ! jq -e \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" '
      ((.metadata.annotations[$owner_annotation] // "") == "")
      and ((.spec.unschedulable // false) == false)
      and all(.spec.taints[]?;
        (.effect != "NoSchedule" and .effect != "NoExecute")
        or .key == "node.kubernetes.io/unschedulable"
        or .key == "node.kubernetes.io/not-ready"
        or .key == "node.kubernetes.io/unreachable")
    ' "${cordon_state_file}" >/dev/null; then
      echo "::error::Scheduling intent changed on proven bootstrap seed ${node_name} after its owned cordon was released."
      return 1
    fi
    if node_is_ready_workload_destination \
      "${cordon_state_file}" "${node_uid}"; then
      return 0
    fi
    if ((attempt < SYNC_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done

  echo "::error::Timed out waiting for proven bootstrap seed ${node_name} to become a workload-schedulable eviction destination; root Flux auth remains unchanged."
  return 1
}

# When the previous host credential is already revoked, no stale runtime can
# receive an eviction. Use the platform's empty warm worker as a seed: atomically
# cordon every stale target first, reboot the empty workload-schedulable seed,
# then release nodes one by one only after their runtime pull proof succeeds.
# If the warm-spare contract is not currently satisfied, make no destructive
# progress and leave the pre-existing scheduling state intact.
prepare_runtime_bootstrap_roll() {
  local desired_revision="$1"
  local pending_targets_file="$2"
  local node_role node_name node_ip node_mode node_uid
  local seed_line="" state_file was_cordoned owner_token existing_owner
  local initial_taints bootstrap_owner existing_recovery recovery_record
  local workload_rc

  bootstrap_seed_uid=""
  : >"${bootstrap_ordered_targets}"
  assert_sync_lease_held || return 1

  while IFS=$'\t' read -r \
    node_role node_name node_ip node_mode node_uid; do
    [[ "${node_mode}" == "reboot" ]] || continue
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json >"${cordon_state_file}"; then
      echo "::error::Could not inspect bootstrap candidate ${node_name}; refusing the all-stale rollout."
      return 1
    fi
    if ! selected_node_identity_is_current \
      "${cordon_state_file}" "${node_name}" "${node_uid}" \
      "${node_ip}" "${node_role}"; then
      echo "::error::Bootstrap candidate ${node_name} changed identity; refusing the all-stale rollout."
      return 1
    fi
    if ! node_is_ready_workload_destination \
      "${cordon_state_file}" "${node_uid}"; then
      continue
    fi
    if node_has_no_evictable_workloads "${node_name}"; then
      bootstrap_seed_uid="${node_uid}"
      seed_line="${node_role}"$'\t'"${node_name}"$'\t'"${node_ip}"$'\t'"${node_mode}"$'\t'"${node_uid}"
      break
    else
      workload_rc=$?
      ((workload_rc == 1)) || return "${workload_rc}"
    fi
  done <"${pending_targets_file}"

  if [[ -z "${bootstrap_seed_uid}" ]]; then
    echo "::error::All eligible runtimes use the stale GHCR credential and no empty workload-schedulable node is available to seed the refresh; refusing to drain any workload."
    return 1
  fi

  # Carries the run reference for the same reason the lease holder does: a node
  # fence outlives the runner that took it, and a PID cannot be checked.
  bootstrap_owner="bootstrap-${desired_revision:0:12}-$(fence_run_segment)-$$-${RANDOM}"
  while IFS=$'\t' read -r \
    node_role node_name node_ip node_mode node_uid; do
    [[ "${node_mode}" == "reboot" ]] || continue
    state_file="${bootstrap_cordon_dir}/${node_name}.json"
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json >"${cordon_state_file}"; then
      echo "::error::Could not capture scheduling state for stale node ${node_name}; refusing the bootstrap roll."
      return 1
    fi
    if ! selected_node_identity_is_current \
      "${cordon_state_file}" "${node_name}" "${node_uid}" \
      "${node_ip}" "${node_role}"; then
      echo "::error::Stale node ${node_name} changed identity before bootstrap quarantine."
      return 1
    fi
    if ! jq -e \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" '
      (.metadata.resourceVersion | type == "string" and length > 0)
      and ((.spec.unschedulable // false) | type == "boolean")
      and ((.metadata.annotations[$owner_annotation] // "")
        | type == "string")
      and ((.spec.taints // []) | type == "array")
    ' "${cordon_state_file}" >/dev/null; then
      echo "::error::Scheduling state for stale node ${node_name} was malformed; refusing bootstrap quarantine."
      return 1
    fi
    if ! existing_owner="$(jq -er \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
      '.metadata.annotations[$owner_annotation] // ""' \
      "${cordon_state_file}")"; then
      echo "::error::Could not read GHCR bridge ownership for stale node ${node_name}."
      return 1
    fi
    if [[ -n "${existing_owner}" ]]; then
      echo "::error::Stale node ${node_name} already has a GHCR bridge owner; refusing concurrent bootstrap quarantine."
      return 1
    fi
    existing_recovery="$(jq -r \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      '.metadata.annotations[$recovery_annotation] // ""' \
      "${cordon_state_file}")"
    if [[ -n "${existing_recovery}" ]]; then
      echo "::error::Stale node ${node_name} has a GHCR bridge recovery journal without an owner; refusing bootstrap quarantine."
      return 1
    fi
    if ! initial_taints="$(jq -ecS '
      (.spec.taints // [])
      | map(select((
          (.key == "node.kubernetes.io/unschedulable"
            and .effect == "NoSchedule"
            and (.value // "") == "")
          or (.key == "DeletionCandidateOfClusterAutoscaler"
            and .effect == "PreferNoSchedule")
        ) | not))
      | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")])
    ' "${cordon_state_file}")"; then
      echo "::error::Could not normalize scheduling taints for stale node ${node_name}."
      return 1
    fi
    if jq -e '.spec.unschedulable == true' \
      "${cordon_state_file}" >/dev/null; then
      was_cordoned=1
    else
      was_cordoned=0
    fi
    owner_token="${bootstrap_owner}"
    recovery_record="$(jq -cn \
      --arg owner "${owner_token}" \
      --arg uid "${node_uid}" \
      --arg desired_revision "${desired_revision}" \
      --argjson was_cordoned "${was_cordoned}" \
      --argjson initial_taints "${initial_taints}" '
      {
        v: 1,
        owner: $owner,
        uid: $uid,
        desiredRevision: $desired_revision,
        wasCordoned: $was_cordoned,
        initialTaints: $initial_taints,
        phase: "active"
      }
    ')"
    if ! jq -n \
      --arg node_name "${node_name}" \
      --arg owner_token "${owner_token}" \
      --arg recovery_record "${recovery_record}" \
      --arg initial_uid "${node_uid}" \
      --argjson was_cordoned "${was_cordoned}" \
      --argjson initial_taints "${initial_taints}" '
      {
        nodeName: $node_name,
        ownerToken: $owner_token,
        recoveryRecord: $recovery_record,
        initialUID: $initial_uid,
        wasCordoned: $was_cordoned,
        initialTaints: $initial_taints
      }
    ' >"${state_file}"; then
      echo "::error::Could not persist bootstrap ownership state for stale node ${node_name}."
      return 1
    fi
    assert_sync_lease_held || return 1
    if ! claim_node_cordon_ownership \
      "${node_name}" "${owner_token}" \
      "${cordon_state_file}" "${drain_result_file}" \
      "${recovery_record}" "${was_cordoned}" "${initial_taints}"; then
      return 1
    fi
    assert_sync_lease_held || return 1
  done <"${pending_targets_file}"

  printf '%s\n' "${seed_line}" >"${bootstrap_ordered_targets}"
  awk -F '\t' -v seed_uid="${bootstrap_seed_uid}" \
    '$5 != seed_uid' "${pending_targets_file}" \
    >>"${bootstrap_ordered_targets}"
}

# Close every post-cordon scheduling race. A drain, reboot, readiness wait, or
# image proof can outlive an operator/autoscaler change, so re-read before each
# destructive Talos edge and fail closed when the captured guard no longer holds.
revalidate_node_scheduling_guard() {
  local node_name="$1" was_cordoned="$2" owner_token="$3"
  local initial_node_uid="$4" initial_node_taints="$5" result_file="$6"
  local selected_node_ip="$7" selected_node_role="$8"
  local operation="$9"

  assert_sync_lease_held || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get node "${node_name}" \
    --output json \
    >"${cordon_state_file}" 2>"${result_file}"; then
    echo "::error::Could not re-read Talos node ${node_name} immediately before ${operation}; refusing the mutation."
    emit_safe_operation_output "scheduling-guard" "${result_file}"
    return 1
  fi
  if ! selected_node_identity_is_current \
    "${cordon_state_file}" \
    "${node_name}" \
    "${initial_node_uid}" \
    "${selected_node_ip}" \
    "${selected_node_role}" ||
    ! node_scheduling_state_is_safe_to_reboot \
      "${cordon_state_file}" \
      "${was_cordoned}" \
      "${owner_token}" \
      "${initial_node_uid}" \
      "${initial_node_taints}"; then
    echo "::error::Talos node ${node_name} identity changed, cordon ownership changed, or scheduling safety state changed before ${operation}; refusing the mutation."
    return 1
  fi
}

wait_for_node_lifecycle_taints_to_clear() {
  local node_name="$1" was_cordoned="$2" owner_token="$3"
  local initial_node_uid="$4" initial_node_taints="$5" result_file="$6"
  local selected_node_ip="$7" selected_node_role="$8"
  local attempt

  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get node "${node_name}" \
      --output json \
      >"${cordon_state_file}" 2>"${result_file}"; then
      echo "::error::Could not re-read Talos node ${node_name} while waiting for its post-reboot lifecycle taints to clear; refusing image verification."
      emit_safe_operation_output "lifecycle-taint-read" "${result_file}"
      return 1
    fi
    if ! selected_node_identity_is_current \
      "${cordon_state_file}" \
      "${node_name}" \
      "${initial_node_uid}" \
      "${selected_node_ip}" \
      "${selected_node_role}" ||
      ! node_scheduling_state_is_safe_while_lifecycle_taints_clear \
        "${cordon_state_file}" \
        "${was_cordoned}" \
        "${owner_token}" \
        "${initial_node_uid}" \
        "${initial_node_taints}"; then
      echo "::error::Talos node ${node_name} identity changed, cordon ownership changed, or non-lifecycle scheduling safety state changed while waiting for its post-reboot lifecycle taints to clear; refusing image verification."
      return 1
    fi
    if ! node_has_lifecycle_taints "${cordon_state_file}" &&
      jq -e '
        any(.status.conditions[]?;
          .type == "Ready" and .status == "True")
      ' "${cordon_state_file}" >/dev/null; then
      return 0
    fi
    if ((attempt < SYNC_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done

  echo "::error::Timed out waiting for Talos node ${node_name} to remain Ready and for post-reboot lifecycle taints to clear; it remains cordoned and image verification was not attempted."
  return 1
}

# Talos returns gRPC NotFound with the exact image reference when that image is
# already absent from the selected runtime namespace. Match both so transport,
# authorization, and unrelated removal failures remain fatal.
talos_image_remove_reports_absent() {
  local result_file="$1"
  local operator_image="$2"

  LC_ALL=C grep -Fq -- \
    "rpc error: code = NotFound desc = image ${operator_image} not found" \
    "${result_file}"
}

drain_failed_for_transient_api_transport() {
  local result_file="$1"

  # kubectl may log resolved PDB retries before an unrelated API outage.
  # Classify only its terminal drain error so a real PDB timeout is never
  # converted into another eviction attempt.
  LC_ALL=C grep -Eq \
    '^error: unable to drain node .*(''connection reset by peer|connect: connection refused|''i/o timeout|TLS handshake timeout|http2: client connection lost|''no route to host|network is unreachable|unexpected EOF)' \
    "${result_file}"
}

kubernetes_api_transport_interrupted() {
  local result_file="$1"

  LC_ALL=C grep -Eq \
    'connection reset by peer|connect: connection refused|i/o timeout|TLS handshake timeout|http2: client connection lost|no route to host|network is unreachable|unexpected EOF' \
    "${result_file}"
}

revalidate_selected_node_identity_before_mutation() {
  local node_name="$1" node_uid="$2" node_ip="$3" node_role="$4"
  local allow_removed="${5:-0}"

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get node "${node_name}" \
    --ignore-not-found \
    --output json \
    >"${cordon_state_file}" 2>"${talos_result_file}"; then
    echo "::error::Could not re-read Talos node ${node_name} before mutation; refusing to target a stale address."
    emit_safe_operation_output "node-identity" "${talos_result_file}"
    return 1
  fi
  if [[ ! -s "${cordon_state_file}" && "${allow_removed}" == 1 ]]; then
    # Empty output from a successful --ignore-not-found GET is authoritative
    # absence, unlike stderr text or a failed request. Rebind the whole live
    # inventory too: a replacement reusing this identity/address is not removal.
    if ! kubectl --context "${KUBE_CONTEXT}" get nodes -o json \
      >"${cordon_state_file}" 2>"${talos_result_file}" ||
      ! validate_talos_node_inventory "${cordon_state_file}" ||
      ! jq -e --arg name "${node_name}" --arg uid "${node_uid}" \
        --arg address "${node_ip}" '
          all(.items[];
            .metadata.name != $name and .metadata.uid != $uid
            and all(.status.addresses[]?;
              .type != "InternalIP" or .address != $address))
        ' "${cordon_state_file}" >/dev/null; then
      echo "::error::Could not prove selected Talos node ${node_name} was removed without replacement; refusing to continue."
      return 1
    fi
    assert_sync_lease_held || return 1
    echo "::notice::Talos node ${node_name} was removed before mutation; deselected without recording verification."
    return 2
  fi
  if ! selected_node_identity_is_current \
    "${cordon_state_file}" \
    "${node_name}" \
    "${node_uid}" \
    "${node_ip}" \
    "${node_role}"; then
    echo "::error::Talos node ${node_name} identity changed after inventory selection; refusing to patch, drain, or reboot it."
    return 1
  fi
}

# Apply Git/SOPS auth to stale Talos nodes, reboot them so containerd actually
# adopts the credential, prove an uncached pull of the declared incoming image,
# and only then record its non-secret revision+image proof markers so either
# credential or target changes trigger verification.
process_talos_node_target() {
  local desired_revision="$1"
  local operator_image="$2"
  local node_role="$3"
  local node_name="$4"
  local node_ip="$5"
  local node_mode="$6"
  local node_uid="$7"
  local was_cordoned=0 existing_cordon_owner="" existing_cordon_recovery=""
  local cordon_owner_token=""
  local initial_node_uid="" initial_node_taints="[]"
  local bootstrap_state_file="${bootstrap_cordon_dir}/${node_name}.json"
  # Bash 5 keeps an unassigned `local` nounset; Bash 3 expands it as empty.
  # Initialise the optional recovery payload so CI and operators get the same
  # fail-closed cleanup path when no bootstrap recovery record was required.
  local probe_image recovery_record=""
  local drain_attempt=1 api_attempt api_ready
  local ready_attempt
  local reusable_proof_uid=""
  local identity_result=0 allow_removed=1

  assert_sync_lease_held || return 1

  if [[ "${node_mode}" != "reboot" &&
    "${node_mode}" != "image-only" &&
    "${node_mode}" != "proof-only" ]]; then
    echo "::error::Unknown Talos GHCR synchronization mode '${node_mode}' for ${node_name}."
    return 1
  fi
  # Bootstrap preparation can already own a durable fence on this target.
  # Its recovery remains fail-closed; only an untouched target may be skipped.
  if [[ -f "${bootstrap_state_file}" ]]; then
    allow_removed=0
  fi
  revalidate_selected_node_identity_before_mutation \
    "${node_name}" "${node_uid}" "${node_ip}" "${node_role}" \
    "${allow_removed}" || identity_result=$?
  if ((identity_result != 0)); then
    return "${identity_result}"
  fi

  if [[ "${node_mode}" == "reboot" ]]; then
    # Writing the credential is NOT enough to make a RUNNING node use it, and
    # this is the step whose absence caused the 2026-07-14 outage.
    #
    # containerd reads registry auth from its STATIC config
    # (plugins.'io.containerd.cri.v1.images'.registry.configs.'ghcr.io'.auth),
    # which it loads ONCE at process start. Talos re-renders that file
    # (/etc/cri/conf.d/01-registries.part) immediately on a config change, but
    # it does not restart containerd — and it refuses to let us either:
    #
    #   $ talosctl service cri restart
    #   error: service "cri" doesn't support restart operation via API
    #
    # So after a --mode=no-reboot patch the new credential sits on disk,
    # correct and INERT, while the running containerd keeps presenting the old
    # one. A REBOOT is the only supported way to make it adopt the new auth.
    #
    # Do not be tempted to drop this and trust the `image pull` check below:
    # that check goes through the TALOS image API, which builds its auth from
    # the machine config we just wrote, NOT from containerd's CRI plugin. It
    # therefore passes on a node whose kubelet pulls are still failing 403 —
    # which is exactly what happened: every node had the legacy unversioned
    # ghcr-pull-verified-revision marker while every ksail-operator pod sat in
    # ImagePullBackOff, and prod stayed four releases behind for over a day.
    # The pull check proves the CREDENTIAL is good; only the reboot proves
    # CONTAINERD is using it.
    #
    # Credential-revision drift always takes this reboot path; a desired-machine
    # marker is not evidence that the running containerd loaded the credential.
    # A node whose v2 credential proof is already current but whose declared
    # image changed takes the image-only path below and is never rebooted.
    #
    # etcd tolerates exactly one control plane down in a 3-member cluster. This
    # loop is serial and control planes sort last, but a peer can be
    # Kubernetes-Ready while its etcd member is unhealthy. Re-read the peer
    # inventory, then prove every other peer is Ready, answers `etcd status`,
    # and has no etcd alarm immediately before each control-plane reboot.
    if [[ "${node_role}" == "1" ]] &&
      ! other_control_planes_safe_to_reboot \
        "${node_name}" "${KUBE_CONTEXT}" "${work_dir}"; then
      echo "::error::Refusing to reboot control plane ${node_name} for the GHCR auth refresh: another control plane is not Ready with healthy, alarm-free etcd, so rebooting this one risks quorum."
      return 1
    fi
  fi

  # Remember scheduling intent before any cordon. Both reboot and image-only
  # verification exclude new placements while the exact target is removed;
  # only the reboot path drains existing workloads.
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get node "${node_name}" \
    --output json \
    >"${cordon_state_file}"; then
    echo "::error::Refusing to synchronize ${node_name}: its scheduling state could not be read."
    return 1
  fi
  if ! selected_node_identity_is_current \
    "${cordon_state_file}" \
    "${node_name}" \
    "${node_uid}" \
    "${node_ip}" \
    "${node_role}" ||
    ! jq -e \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" '
      (.metadata.uid | type == "string" and length > 0)
      and (.metadata.resourceVersion | type == "string" and length > 0)
      and ((.spec.unschedulable // false) | type == "boolean")
      and ((.metadata.annotations[$owner_annotation] // "")
        | type == "string")
    ' "${cordon_state_file}" >/dev/null; then
    echo "::error::Refusing to synchronize ${node_name}: its identity changed or scheduling state was malformed."
    return 1
  fi
  if [[ -f "${bootstrap_state_file}" ]]; then
    if ! jq -e \
      --arg node_name "${node_name}" \
      --arg node_uid "${node_uid}" '
        .nodeName == $node_name
        and .initialUID == $node_uid
        and (.ownerToken | type == "string")
        and (.recoveryRecord | type == "string" and length > 0)
        and (.wasCordoned == 0 or .wasCordoned == 1)
        and (.initialTaints | type == "array")
      ' "${bootstrap_state_file}" >/dev/null; then
      echo "::error::Bootstrap ownership state for ${node_name} was malformed; refusing the mutation."
      return 1
    fi
    initial_node_uid="$(jq -er '.initialUID' "${bootstrap_state_file}")"
    initial_node_taints="$(jq -c '.initialTaints' "${bootstrap_state_file}")"
    was_cordoned="$(jq -er '.wasCordoned' "${bootstrap_state_file}")"
    cordon_owner_token="$(jq -er '.ownerToken' "${bootstrap_state_file}")"
    recovery_record="$(jq -er '.recoveryRecord' "${bootstrap_state_file}")"
    if ! jq -e \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      --arg recovery "${recovery_record}" \
      '.metadata.annotations[$recovery_annotation] == $recovery' \
      "${cordon_state_file}" >/dev/null; then
      echo "::error::Bootstrap recovery journal changed for ${node_name}; refusing the mutation."
      return 1
    fi
    if ! node_scheduling_state_is_safe_to_reboot \
      "${cordon_state_file}" \
      "${was_cordoned}" \
      "${cordon_owner_token}" \
      "${initial_node_uid}" \
      "${initial_node_taints}"; then
      echo "::error::Bootstrap quarantine ownership or scheduling state changed for ${node_name}; refusing the mutation."
      return 1
    fi
  else
    initial_node_uid="$(jq -r '.metadata.uid' "${cordon_state_file}")"
    initial_node_taints="$(jq -cS '
        (.spec.taints // [])
        | map(select((
            (.key == "node.kubernetes.io/unschedulable"
              and .effect == "NoSchedule"
              and (.value // "") == "")
            or (.key == "DeletionCandidateOfClusterAutoscaler"
              and .effect == "PreferNoSchedule")
          ) | not))
        | sort_by([.key, .effect, (.value // ""), (.timeAdded // "")])
      ' "${cordon_state_file}")"
    existing_cordon_owner="$(jq -r \
      --arg owner_annotation "${CORDON_OWNER_ANNOTATION}" \
      '.metadata.annotations[$owner_annotation] // ""' \
      "${cordon_state_file}")"
    if [[ -n "${existing_cordon_owner}" ]]; then
      echo "::error::Refusing to synchronize ${node_name}: it already has a GHCR bridge cordon owner, so a previous or concurrent roll must be resolved first."
      return 1
    fi
    existing_cordon_recovery="$(jq -r \
      --arg recovery_annotation "${CORDON_RECOVERY_ANNOTATION}" \
      '.metadata.annotations[$recovery_annotation] // ""' \
      "${cordon_state_file}")"
    if [[ -n "${existing_cordon_recovery}" ]]; then
      echo "::error::Refusing to synchronize ${node_name}: it has a GHCR bridge recovery journal without an owner."
      return 1
    fi
    if jq -e '.spec.unschedulable == true' \
      "${cordon_state_file}" >/dev/null; then
      was_cordoned=1
    else
      was_cordoned=0
    fi
    cordon_owner_token="${desired_revision:0:16}-$(fence_run_segment)-$$-${RANDOM}"
    assert_sync_lease_held || return 1
    claim_node_cordon_ownership \
      "${node_name}" "${cordon_owner_token}" \
      "${cordon_state_file}" "${drain_result_file}" \
      "" "${was_cordoned}" "${initial_node_taints}" || return 1
  fi

  # A node resourceVersion fences only the claim itself. Renew after the claim
  # and re-read the owned scheduling guard so a process that lost its cluster
  # transaction cannot carry stale credentials into Talos.
  if ! revalidate_node_scheduling_guard \
    "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
    "${initial_node_uid}" "${initial_node_taints}" \
    "${talos_result_file}" "${node_ip}" "${node_role}" \
    "credential patch"; then
    restore_node_schedulability_if_needed \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${drain_result_file}" "${recovery_record}" || true
    return 1
  fi

  # Past this point Talos is mutated, so a fence leaked from here on must NOT be
  # reclaimed automatically: the Lease proves no owner is alive, never that the
  # node reached a known state. Advance the marker first and fail closed if it
  # cannot be advanced -- an un-advanced marker would make a mutated node look
  # reclaimable, which is the one direction that is never safe.
  if ! mark_node_fence_mutating \
    "${node_name}" "${cordon_owner_token}" "${initial_node_uid}"; then
    restore_node_schedulability_if_needed \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${drain_result_file}" "${recovery_record}" || true
    return 1
  fi

  if [[ "${node_mode}" == "reboot" ]]; then
    if ! talosctl \
      --nodes "${node_ip}" \
      patch machineconfig \
      --mode=no-reboot \
      --patch-file="${talos_auth_patch_file}" \
      >"${talos_result_file}" 2>&1; then
      echo "::error::Talos node ${node_name} did not accept the Git/SOPS GHCR registry auth."
      restore_node_schedulability_if_needed \
        "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
        "${initial_node_uid}" "${initial_node_taints}" \
        "${drain_result_file}" "${recovery_record}" || return 1
      return 1
    fi

    # The Talos API call above is a concurrency window. Rebind both the selected
    # machine identity and the owned scheduling state before asking Kubernetes
    # to evict anything from that node.
    revalidate_node_scheduling_guard \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${drain_result_file}" "${node_ip}" "${node_role}" "drain" || return 1

    # Drain through the Kubernetes context already proven by this deployment.
    # Talos v1.13's integrated --drain path fetches a separate admin kubeconfig;
    # this cluster's generated config targets an unreachable API endpoint.
    # kubectl also retries PDB-protected evictions, giving CloudNativePG time to
    # switch primaries and Longhorn time to enforce its data-safety policy.
    while ! kubectl \
      --context "${KUBE_CONTEXT}" \
      drain "${node_name}" \
      --ignore-daemonsets \
      --delete-emptydir-data \
      --timeout="${DRAIN_TIMEOUT}" \
      >"${drain_result_file}" 2>&1; do
      if ((drain_attempt >= 2)) ||
        ! drain_failed_for_transient_api_transport \
          "${drain_result_file}"; then
        echo "::error::Talos node ${node_name} could not be safely drained before its GHCR auth reboot."
        emit_safe_operation_output "drain" "${drain_result_file}"
        restore_node_schedulability_if_needed \
          "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
          "${initial_node_uid}" "${initial_node_taints}" \
          "${drain_result_file}" "${recovery_record}" || return 1
        return 1
      fi

      echo "::warning::Kubernetes API transport interrupted the drain of ${node_name}; waiting for API readiness before one guarded retry."
      api_ready=false
      for ((api_attempt = 1; api_attempt <= SYNC_ATTEMPTS; api_attempt++)); do
        if kubectl \
          --context "${KUBE_CONTEXT}" \
          get --raw=/readyz \
          --request-timeout=30s \
          >"${talos_result_file}" 2>&1; then
          api_ready=true
          break
        fi
        if ((api_attempt < SYNC_ATTEMPTS)); then
          sleep "${SYNC_INTERVAL}"
        fi
      done
      if [[ "${api_ready}" != "true" ]]; then
        echo "::error::Kubernetes API did not recover after the interrupted drain of ${node_name}; refusing to retry."
        emit_safe_operation_output "drain-api-readiness" \
          "${talos_result_file}"
        restore_node_schedulability_if_needed \
          "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
          "${initial_node_uid}" "${initial_node_taints}" \
          "${drain_result_file}" "${recovery_record}" || return 1
        return 1
      fi
      if ! recover_sync_lease_heartbeat_after_transport_interruption; then
        restore_node_schedulability_if_needed \
          "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
          "${initial_node_uid}" "${initial_node_taints}" \
          "${drain_result_file}" "${recovery_record}" || return 1
        return 1
      fi
      revalidate_node_scheduling_guard \
        "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
        "${initial_node_uid}" "${initial_node_taints}" \
        "${drain_result_file}" "${node_ip}" "${node_role}" \
        "drain retry" || return 1
      drain_attempt=$((drain_attempt + 1))
    done

    # A PDB-respecting drain can legitimately take most of DRAIN_TIMEOUT. An
    # etcd peer that was healthy before it began may fail while workloads move,
    # so refresh the quorum proof at the last safe point before the reboot.
    if [[ "${node_role}" == "1" ]] &&
      ! other_control_planes_safe_to_reboot \
        "${node_name}" "${KUBE_CONTEXT}" "${work_dir}"; then
      echo "::error::Refusing to reboot control plane ${node_name} after its drain: another control plane is no longer Ready with healthy, alarm-free etcd, so rebooting this one risks quorum."
      restore_node_schedulability_if_needed \
        "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
        "${initial_node_uid}" "${initial_node_taints}" \
        "${drain_result_file}" "${recovery_record}" || return 1
      return 1
    fi

    if ! revalidate_node_scheduling_guard \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${drain_result_file}" "${node_ip}" "${node_role}" "reboot"; then
      # Scheduling intent changed after the PDB-respecting drain. Never reboot
      # or undo the newer actor's decision; leave the node in its observed state
      # for an operator or the next run to reconcile explicitly.
      return 1
    fi

    # The node is now cordoned and fully drained under PDB control, so a plain
    # Talos reboot cannot terminate a workload behind Kubernetes' back. Keep
    # --wait explicit so Kubernetes readiness is checked only after a new boot.
    if [[ -f "${bootstrap_state_file}" ]]; then
      update_bootstrap_recovery_phase \
        "${node_name}" "${cordon_owner_token}" \
        "${initial_node_uid}" "${desired_revision}" \
        "active" "retain" "${drain_result_file}" || return 1
      : >"${bootstrap_retain_dir}/${node_name}"
    fi
    assert_sync_lease_held || return 1
    if ! talosctl \
      --nodes "${node_ip}" \
      reboot \
      --wait \
      >"${reboot_result_file}" 2>&1; then
      echo "::error::Talos node ${node_name} did not reboot to load the refreshed GHCR registry auth; it remains cordoned because its reboot state is uncertain."
      emit_safe_operation_output "reboot" "${reboot_result_file}"
      return 1
    fi
    for ((ready_attempt = 1; ready_attempt <= NODE_READY_TRANSPORT_RETRY_ATTEMPTS; ready_attempt++)); do
      if kubectl \
        --context "${KUBE_CONTEXT}" \
        wait \
        --for=condition=Ready \
        "node/${node_name}" \
        --timeout=10m \
        >"${reboot_result_file}" 2>&1; then
        break
      fi
      if ((ready_attempt >= NODE_READY_TRANSPORT_RETRY_ATTEMPTS)) ||
        ! kubernetes_api_transport_interrupted \
          "${reboot_result_file}"; then
        echo "::error::Talos node ${node_name} did not return Ready after its GHCR auth reboot; it remains cordoned and the next node will not be rolled."
        emit_safe_operation_output "ready" "${reboot_result_file}"
        return 1
      fi

      echo "::warning::Kubernetes API transport interrupted the post-reboot Ready wait for ${node_name}; waiting for API recovery before retrying under the same cordon claim."
      api_ready=false
      for ((api_attempt = 1; api_attempt <= SYNC_ATTEMPTS; api_attempt++)); do
        if kubectl \
          --context "${KUBE_CONTEXT}" \
          get --raw=/readyz \
          --request-timeout=30s \
          >"${reboot_result_file}" 2>&1; then
          api_ready=true
          break
        fi
        if ((api_attempt < SYNC_ATTEMPTS)); then
          sleep "${SYNC_INTERVAL}"
        fi
      done
      if [[ "${api_ready}" != "true" ]]; then
        echo "::error::Kubernetes API did not recover after rebooting ${node_name}; it remains cordoned and the next node will not be rolled."
        emit_safe_operation_output "ready-api-recovery" \
          "${reboot_result_file}"
        return 1
      fi
      if ! recover_sync_lease_heartbeat_after_transport_interruption; then
        return 1
      fi
    done
    wait_for_node_lifecycle_taints_to_clear \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${reboot_result_file}" "${node_ip}" "${node_role}" || return 1
  fi

  if [[ "${node_mode}" != "proof-only" ]]; then
    # A reboot/readiness wait or even a short image-only cordon can outlive a
    # replacement, uncordon, taint, or owner change. Rebind identity and the
    # scheduling guard at the final Talos edge before touching the image cache.
    revalidate_node_scheduling_guard \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${talos_result_file}" "${node_ip}" "${node_role}" \
      "image verification" || return 1

    # A cached image can make a pull look healthy without proving that the
    # node's runtime can authenticate to GHCR. Remove the incoming exact target
    # first so the following pull must complete a registry round-trip.
    if ! talosctl \
      --nodes "${node_ip}" \
      image remove "${operator_image}" \
      --namespace cri \
      >"${talos_result_file}" 2>&1; then
      if ! talos_image_remove_reports_absent \
        "${talos_result_file}" "${operator_image}"; then
        echo "::error::Talos node ${node_name} could not remove the cached incoming KSail image before GHCR verification; it remains cordoned because registry access is unproved."
        return 1
      fi
    fi

    revalidate_node_scheduling_guard \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${talos_result_file}" "${node_ip}" "${node_role}" \
      "image pull" || return 1

    # Credential validity against GHCR (see the caveat above: this is not, on
    # its own, proof that containerd is using it — the reboot is).
    if ! talosctl \
      --nodes "${node_ip}" \
      image pull "${operator_image}" \
      --namespace cri \
      >"${talos_result_file}" 2>&1; then
      echo "::error::Talos node ${node_name} could not pull the exact incoming KSail image after its auth refresh; it remains cordoned because registry access is unproved."
      return 1
    fi

    revalidate_node_scheduling_guard \
      "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${initial_node_taints}" \
      "${talos_result_file}" "${node_ip}" "${node_role}" \
      "runtime pull proof" || return 1

    # Talos' image API authenticates from machine config, not through the
    # kubelet's running CRI client. Before this freshly rebooted node can
    # receive workloads, prove all three private images through kubelet/containerd
    # while the bridge-owned cordon is still in place.
    if [[ "${node_mode}" == "reboot" ]]; then
      for probe_image in "${RUNTIME_CREDENTIAL_PROBE_IMAGES[@]}"; do
        probe_node_runtime_pull "${node_name}" "${probe_image}" || return 1
      done
      if ! grep -Fqx -- "${node_uid}" "${runtime_proved_targets_file}"; then
        printf '%s\n' "${node_uid}" >>"${runtime_proved_targets_file}"
      fi
    fi
  fi

  revalidate_node_scheduling_guard \
    "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
    "${initial_node_uid}" "${initial_node_taints}" \
    "${talos_result_file}" "${node_ip}" "${node_role}" \
    "revision marker" || return 1

  # Record the proof only after the real runtime checks, while the selected
  # machine remains protected by the owned cordon. Releasing ownership first
  # would let a concurrent credential revision race this marker write.
  if [[ "${node_mode}" == "proof-only" ]]; then
    reusable_proof_uid="${node_uid}"
  fi
  # Test hook consumed by fake talosctl to verify Node binding; Talos ignores it.
  if ! FLUX_GHCR_REUSABLE_PROOF_UID="${reusable_proof_uid}" \
    talosctl \
    --nodes "${node_ip}" \
    patch machineconfig \
    --mode=no-reboot \
    --patch-file="${talos_revision_patch_file}" \
    >"${talos_result_file}" 2>&1; then
    echo "::error::Talos node ${node_name} proved GHCR access but could not record the synchronized credential revision."
    return 1
  fi

  if [[ -f "${bootstrap_state_file}" ]]; then
    update_bootstrap_recovery_phase \
      "${node_name}" "${cordon_owner_token}" \
      "${initial_node_uid}" "${desired_revision}" \
      "retain" "release-ready" "${drain_result_file}" || return 1
    recovery_record="$(jq -cn \
      --arg recovery "${recovery_record}" '
        ($recovery | fromjson) + {phase: "release-ready"}
      ')"
  fi

  # Restore original scheduling intent only after the proof marker is durable.
  # Residual ownership makes the next selector fail closed rather than letting
  # a release failure masquerade as a clean node.
  rm -f "${bootstrap_retain_dir}/${node_name}"
  assert_sync_lease_held || return 1
  restore_node_schedulability_if_needed \
    "${node_name}" "${was_cordoned}" "${cordon_owner_token}" \
    "${initial_node_uid}" "${initial_node_taints}" \
    "${drain_result_file}" "${recovery_record}" || return 1

  # The release is the final replacement boundary before this UID is marked
  # processed in the convergence loop. Rebind it once more so a replacement
  # cannot inherit the old machine's proof within this pass.
  revalidate_selected_node_identity_before_mutation \
    "${node_name}" "${node_uid}" "${node_ip}" "${node_role}" || return 1
}

validate_talos_node_inventory() {
  local nodes_file="$1"

  # talosctl proxies node targets through the public control-plane endpoints,
  # so use the stable, unique InternalIP. UID is part of convergence identity:
  # an autoscaler replacement may reuse a name or address and still needs proof.
  jq -e '
    (.items | length) > 0
    and all(.items[];
      (.metadata.name | type == "string" and test("^[^\\t\\r\\n]+$"))
      and (.metadata.uid | type == "string" and test("^[^\\t\\r\\n]+$"))
      and ([.status.addresses[]?
        | select(.type == "InternalIP") | .address] | length) == 1
      and (([.status.addresses[]?
        | select(.type == "InternalIP") | .address][0])
        | type == "string" and test("^[^\\t\\r\\n]+$")))
    and (([.items[].metadata.uid] | unique | length) == (.items | length))
    and (([.items[]
      | [.status.addresses[]?
        | select(.type == "InternalIP") | .address][0]]
      | unique | length) == (.items | length))
  ' "${nodes_file}" >/dev/null
}

# Converge the live node set, rather than trusting one inventory captured before
# a potentially long roll. Completed node UIDs are not rolled twice while their
# Kubernetes annotations propagate; newly autoscaled/replaced nodes are picked
# up in the next pass. Two consecutive clean inventories close the common
# cutover race, and the bounded loop fails before root auth changes if the set
# never stabilizes.
sync_talos_registry_auth() {
  local desired_revision="$1"
  local operator_image="$2"
  local sync_result_file="$3"
  local convergence_attempt=0
  local consecutive_clean_inventories=0
  local processed_any_node=0
  local deselected_any_node=0 target_result=0
  local node_role node_name node_ip node_mode node_uid
  local batch_targets_file first_reboot_name bootstrap_mode

  : >"${talos_result_file}"
  : >"${drain_result_file}"
  : >"${reboot_result_file}"
  : >"${talos_processed_targets}"
  : >"${sync_result_file}"
  : >"${runtime_proved_targets_file}"
  chmod 600 \
    "${talos_result_file}" \
    "${drain_result_file}" \
    "${reboot_result_file}" \
    "${talos_processed_targets}" \
    "${sync_result_file}" \
    "${runtime_proved_targets_file}"

  reconcile_bootstrap_recovery_journals "${desired_revision}" || return 1

  while ((convergence_attempt < TALOS_CONVERGENCE_ATTEMPTS)); do
    convergence_attempt=$((convergence_attempt + 1))
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      get nodes \
      -o json \
      >"${talos_nodes_file}"; then
      echo "::error::Could not list Talos nodes; refusing to mutate any Kubernetes credential consumers."
      return 1
    fi
    if ! validate_talos_node_inventory "${talos_nodes_file}"; then
      echo "::error::Every Talos node must expose a non-empty unique UID and exactly one non-empty unique InternalIP before GHCR auth can be synchronized."
      return 1
    fi
    # Reclaim leaked fences from the FIRST inventory this loop reads, rather
    # than reading nodes of its own straight after acquiring the Lease. The
    # liveness proof is a property of the ACQUISITION — the Lease was free, so
    # no transaction was alive — and nothing has run between that acquisition
    # and this first read, so acting on that proof here is equally sound.
    # Reading nodes earlier would move a node-discovery failure ahead of the
    # credential fan-out, which is deliberately staged first so a discovery
    # failure cannot leave the fan-out half-applied.
    #
    # Later attempts are deliberately EXCLUDED. This loop re-reads the node
    # inventory every iteration, so a later read reflects fences this very
    # transaction has since claimed — and a fence sitting at "claimed" is
    # exactly what the selector matches. Reclaiming from a later inventory
    # would therefore let the transaction clear its OWN live fence, report it
    # as leaked, and leave the node cordoned. Today no such fence survives an
    # iteration (a per-node failure returns immediately, and every success
    # releases), but that is an unstated invariant of another function rather
    # than a property of this proof, so it is not what safety should rest on.
    if ((convergence_attempt == 1)); then
      reclaimed_fence_count=0
      if ! reclaim_orphaned_node_fences "${talos_nodes_file}"; then
        return 1
      fi
      # A reclaim mutates the very nodes this snapshot describes, so the file
      # still carries the owner annotations that were just removed -- and
      # selection fails closed on exactly those. Re-read before selecting, or
      # the reclaim "succeeds" and the deploy then refuses on its own cleanup.
      if ((reclaimed_fence_count > 0)); then
        if ! kubectl \
          --context "${KUBE_CONTEXT}" \
          get nodes \
          -o json \
          >"${talos_nodes_file}"; then
          echo "::error::Could not re-list Talos nodes after reclaiming leaked drain fences."
          return 1
        fi
        if ! validate_talos_node_inventory "${talos_nodes_file}"; then
          echo "::error::Every Talos node must expose a non-empty unique UID and exactly one non-empty unique InternalIP before GHCR auth can be synchronized."
          return 1
        fi
      fi
    fi
    if ! select_talos_node_targets \
      "${talos_nodes_file}" \
      "${desired_revision}" \
      "${operator_image}" \
      "${talos_node_targets}" \
      "${normalized_runtime_proof_file}"; then
      echo "::error::Could not select Talos nodes requiring GHCR synchronization."
      return 1
    fi

    : >"${talos_pending_targets}"
    while IFS=$'\t' read -r \
      node_role node_name node_ip node_mode node_uid; do
      [[ -n "${node_name}" ]] || continue
      if grep -Fqx -- "${node_uid}" "${talos_processed_targets}"; then
        continue
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "${node_role}" "${node_name}" "${node_ip}" \
        "${node_mode}" "${node_uid}" \
        >>"${talos_pending_targets}"
    done <"${talos_node_targets}"

    # A reboot target can disappear after selection but before overlap chooses
    # a peer or prepares a bootstrap seed. Deselect only an untouched target
    # whose absence is confirmed against a fresh, unambiguous inventory;
    # process_talos_node_target revalidates again at the mutation boundary.
    : >"${talos_preflight_targets}"
    while IFS=$'\t' read -r \
      node_role node_name node_ip node_mode node_uid; do
      [[ -n "${node_name}" ]] || continue
      if [[ "${node_mode}" == "reboot" ]]; then
        target_result=0
        revalidate_selected_node_identity_before_mutation \
          "${node_name}" "${node_uid}" "${node_ip}" "${node_role}" \
          1 || target_result=$?
        if ((target_result == 2)); then
          deselected_any_node=1
          consecutive_clean_inventories=0
          continue
        elif ((target_result != 0)); then
          return 1
        fi
      fi
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "${node_role}" "${node_name}" "${node_ip}" \
        "${node_mode}" "${node_uid}" \
        >>"${talos_preflight_targets}"
    done <"${talos_pending_targets}"
    if ! mv "${talos_preflight_targets}" "${talos_pending_targets}"; then
      echo "::error::Could not persist the revalidated Talos target batch."
      return 1
    fi

    if [[ ! -s "${talos_pending_targets}" ]]; then
      if [[ ! -s "${talos_node_targets}" ]]; then
        consecutive_clean_inventories=$((consecutive_clean_inventories + 1))
        if ((consecutive_clean_inventories >= 2)); then
          if ((deselected_any_node == 1 && processed_any_node == 0)); then
            echo "::error::Every selected Talos target was removed before verification; refusing an empty successful rollout."
            return 1
          fi
          if ((processed_any_node == 1)); then
            printf '%s\n' processed >"${sync_result_file}"
          else
            printf '%s\n' clean >"${sync_result_file}"
          fi
          return 0
        fi
      else
        # A completed node can remain in the selector briefly while Talos node
        # annotations propagate back to Kubernetes. Wait; never re-roll it.
        consecutive_clean_inventories=0
      fi
    else
      consecutive_clean_inventories=0
      batch_targets_file="${talos_pending_targets}"
      bootstrap_mode=0
      # Prefer direct peer-runtime overlap: it avoids batch-wide quarantine
      # while every possible destination can still pull. A revoked root Secret
      # does not outweigh that stronger live proof. Only a stale/no-peer result
      # enters the owned warm-spare bootstrap; admission and probe-integrity
      # errors remain immediate fail-closed outcomes.
      if awk -F '\t' '$4 == "reboot" { found = 1 } END { exit !found }' \
        "${talos_pending_targets}"; then
        first_reboot_name="$(awk -F '\t' '$4 == "reboot" { print $2; exit }' \
          "${talos_pending_targets}")"
        : >"${bootstrap_overlap_result}"
        runtime_probe_bootstrap_needed=0
        verify_current_root_credential_overlap \
          >>"${bootstrap_overlap_result}" 2>&1 || true
        if ! verify_peer_runtime_pull_overlap "${first_reboot_name}" \
          >>"${bootstrap_overlap_result}" 2>&1; then
          if ((runtime_probe_bootstrap_needed == 0)); then
            emit_safe_operation_output \
              "runtime-overlap" "${bootstrap_overlap_result}"
            return 1
          fi
          if ! verify_bootstrap_quarantine_covers_unproved_destinations \
            "${talos_pending_targets}"; then
            emit_safe_operation_output \
              "runtime-overlap" "${bootstrap_overlap_result}"
            return 1
          fi
          if ! prepare_runtime_bootstrap_roll \
            "${desired_revision}" "${talos_pending_targets}"; then
            emit_safe_operation_output \
              "runtime-overlap" "${bootstrap_overlap_result}"
            return 1
          fi
          bootstrap_mode=1
          batch_targets_file="${bootstrap_ordered_targets}"
        fi
      fi

      # Targets are sorted workers-first and processed strictly sequentially,
      # so only one node is down and control planes go last.
      while IFS=$'\t' read -r \
        node_role node_name node_ip node_mode node_uid; do
        if [[ "${node_mode}" == "reboot" ]]; then
          if ((bootstrap_mode == 1)) &&
            [[ "${node_uid}" == "${bootstrap_seed_uid}" ]]; then
            if ! node_has_no_evictable_workloads "${node_name}"; then
              echo "::error::Bootstrap seed ${node_name} gained an evictable workload before its reboot; refusing the roll."
              return 1
            fi
          else
            verify_peer_runtime_pull_overlap \
              "${node_name}" || return 1
          fi
        fi
        target_result=0
        process_talos_node_target \
          "${desired_revision}" \
          "${operator_image}" \
          "${node_role}" \
          "${node_name}" \
          "${node_ip}" \
          "${node_mode}" \
          "${node_uid}" || target_result=$?
        if ((target_result == 2)); then
          deselected_any_node=1
          consecutive_clean_inventories=0
          continue
        elif ((target_result != 0)); then
          return 1
        fi
        if ((bootstrap_mode == 1)) &&
          [[ "${node_uid}" == "${bootstrap_seed_uid}" ]]; then
          wait_for_bootstrap_seed_release \
            "${node_name}" "${node_uid}" \
            "${node_ip}" "${node_role}" || return 1
        fi
        rm -f \
          "${bootstrap_cordon_dir}/${node_name}.json" \
          "${bootstrap_retain_dir}/${node_name}"
        processed_any_node=1
        printf '%s\n' "${node_uid}" >>"${talos_processed_targets}"
      done <"${batch_targets_file}"
    fi

    if ((convergence_attempt < TALOS_CONVERGENCE_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done

  echo "::error::Talos node inventory did not converge after ${TALOS_CONVERGENCE_ATTEMPTS} checks; root Flux auth remains unchanged."
  return 1
}

# Normalize a runner-local proof from the successful pre-update stage. The
# document contains no credential: it binds only the encrypted-source digest,
# declared image, and immutable Kubernetes Node identities. A missing, stale,
# malformed, or symlinked document is ignored, which safely falls back to the
# existing uncached-pull/reboot path.
prepare_reusable_runtime_proof() {
  local desired_revision="$1"
  local operator_image="$2"

  jq -n \
    --arg revision "${desired_revision}" \
    --arg image "${operator_image}" '
      {version: 1, credentialRevision: $revision, image: $image, nodes: []}
    ' >"${normalized_runtime_proof_file}"

  [[ -n "${reuse_runtime_proof_path}" ]] || return 0
  if [[ ! -f "${reuse_runtime_proof_path}" ||
    -L "${reuse_runtime_proof_path}" ]] ||
    ! jq -e \
      --arg revision "${desired_revision}" \
      --arg image "${operator_image}" '
        .version == 1
        and .credentialRevision == $revision
        and .image == $image
        and (.nodes | type == "array" and length > 0)
        and all(.nodes[];
          (.name | type == "string" and length > 0)
          and (.uid | type == "string" and length > 0))
        and ((.nodes | map(.name) | unique | length) == (.nodes | length))
        and ((.nodes | map(.uid) | unique | length) == (.nodes | length))
      ' "${reuse_runtime_proof_path}" >/dev/null 2>&1; then
    echo "::warning::The pre-update GHCR runtime proof is absent, stale, or malformed; using full per-node verification."
    return 0
  fi

  jq -cS . "${reuse_runtime_proof_path}" \
    >"${normalized_runtime_proof_file}"
}

# Export an exact-node proof only after the normal transaction has converged.
# The subsequent reassert can restore a machine annotation erased by KSail,
# but only for the same credential, image, name, and Kubernetes Node UID.
record_runtime_proof() {
  local desired_revision="$1"
  local operator_image="$2"
  local proof_parent

  [[ -n "${record_runtime_proof_path}" ]] || return 0
  proof_parent="$(dirname -- "${record_runtime_proof_path}")"
  if [[ ! -d "${proof_parent}" ||
    -e "${record_runtime_proof_path}" ||
    -L "${record_runtime_proof_path}" ]]; then
    echo "::error::Refusing to overwrite or create the runtime proof outside an existing runner-local directory."
    return 1
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    get nodes \
    -o json >"${runtime_proof_nodes_file}"; then
    echo "::error::Could not capture the converged Node identities for the post-update GHCR reassert."
    return 1
  fi
  if ! validate_talos_node_inventory "${runtime_proof_nodes_file}"; then
    echo "::error::Could not record runtime proof from an invalid Talos node inventory."
    return 1
  fi
  if ! jq -e \
    --arg revision "${desired_revision}" \
    --arg image "${operator_image}" \
    --arg revision_annotation "${GHCR_PULL_VERIFIED_REVISION_ANNOTATION}" \
    --arg image_annotation "${GHCR_PULL_VERIFIED_IMAGE_ANNOTATION}" '
      all(.items[];
        .metadata.annotations[$revision_annotation] == $revision
        and .metadata.annotations[$image_annotation] == $image)
    ' "${runtime_proof_nodes_file}" >/dev/null; then
    echo "::error::Refusing to record a post-update handoff before every exact Node has current runtime proof."
    return 1
  fi
  if ! jq -cS \
    --arg revision "${desired_revision}" \
    --arg image "${operator_image}" '
      {
        version: 1,
        credentialRevision: $revision,
        image: $image,
        nodes: [.items[] | {name: .metadata.name, uid: .metadata.uid}]
          | sort_by(.name)
      }
    ' "${runtime_proof_nodes_file}" >"${record_runtime_proof_path}"; then
    rm -f "${record_runtime_proof_path}"
    return 1
  fi
  chmod 600 "${record_runtime_proof_path}"
}

# KSail embeds SOPS, so the deploy uses the same pinned toolchain as workload
# reconciliation. Decrypt only the Docker config scalar and never emit it to
# stdout or place its plaintext/base64 representation in an argument.
decrypt_flux_ghcr_docker_config "${docker_config}" "${SECRET_FILE}"
write_flux_ghcr_credentials "${docker_config}" "${credentials_file}"
jq -S -c . "${docker_config}" >"${expected_normalized}"

# Build curl's Basic-auth config without putting the credential in argv or
# stdout. Support both Docker config representations used in this repository:
# explicit username/password and base64(username:password) in auth.
jq -r '
  "user = " + ((.username + ":" + .password) | @json)
' "${credentials_file}" >"${basic_curl_config}"
chmod 600 "${basic_curl_config}"

# GHCR permissions are package-granular, so a token response alone is not proof
# of access. Exchange and read every required manifest with the incoming SOPS
# credential before touching any cluster consumer.
verify_ghcr_pull_credential \
  "${basic_curl_config}" \
  "${token_response}" \
  "${bearer_curl_config}" \
  "SOPS GHCR credential" || exit 1

if [[ "${check_only}" == "true" ]]; then
  echo "✅ Validated every required GHCR package pull from Git/SOPS."
  exit 0
fi

# Talos image verification resolves cosign artifacts with host registry auth;
# pod imagePullSecrets cannot satisfy that request. Prepare the supported v1.13
# RegistryAuthConfig and post-reboot proof patch without placing credentials in
# argv. Existing-cluster nodes are synchronized only after the complete tenant
# fan-out has been staged and verified below.
jq '
  {
    apiVersion: "v1alpha1",
    kind: "RegistryAuthConfig",
    name: "ghcr.io",
    username: .username,
    password: .password
  }
' "${credentials_file}" >"${talos_auth_patch_file}"
pull_revision="$(flux_ghcr_revision "${SECRET_FILE}")"
readonly pull_revision
jq -n \
  --arg revision "${pull_revision}" \
  --arg image "${KSAIL_OPERATOR_IMAGE}" \
  --arg revision_annotation "${GHCR_PULL_VERIFIED_REVISION_ANNOTATION}" \
  --arg image_annotation "${GHCR_PULL_VERIFIED_IMAGE_ANNOTATION}" '
  {
    machine: {
      nodeAnnotations: {
        ($revision_annotation): $revision,
        ($image_annotation): $image
      }
    }
  }
' >"${talos_revision_patch_file}"
chmod 600 "${talos_auth_patch_file}" "${talos_revision_patch_file}"
prepare_reusable_runtime_proof "${pull_revision}" "${KSAIL_OPERATOR_IMAGE}"

# Merge only Secret data fields so ownership metadata survives. The sensitive
# payload stays in pipes/temp files and never appears in argv or logs.
base64 <"${docker_config}" |
  tr -d '\r\n' |
  jq -Rs '{data: {".dockerconfigjson": .}}' \
    >"${patch_file}"

sync_lease_is_available() {
  # Talos machine-config writes do not expose a downstream fencing token. An
  # expired shell process could resume after an automatic timeout takeover and
  # write stale credentials even if every Kubernetes write uses CAS. Therefore
  # expiry is diagnostic only: a non-empty holder always requires explicit
  # recovery after the old process has been proven dead.
  jq -e '(.spec.holderIdentity // "") == ""' \
    "${sync_lease_file}" >/dev/null
}

kubernetes_microtime_now() {
  date -u +%Y-%m-%dT%H:%M:%S.000000Z
}

acquire_sync_lease() {
  local desired_revision="$1"
  local attempt now resource_version current_holder transitions failure_detail

  # The identity is what a later operator has to judge for liveness, and a PID
  # belongs to a runner that no longer exists. Record the GitHub run and
  # attempt so a held fence can be resolved against the API instead of by
  # correlating timestamps across workflow runs. The policy fences below reuse
  # this same identity, so every fence becomes decidable together.
  sync_lease_holder="${desired_revision:0:16}-$(fence_run_segment)-$$-${RANDOM}"
  export FLUX_GHCR_SYNC_LEASE_HOLDER="${sync_lease_holder}"
  for attempt in 1 2 3; do
    : >"${sync_lease_file}"
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get lease "${SYNC_LEASE_NAME}" \
      --ignore-not-found \
      -o json >"${sync_lease_file}"; then
      echo "::error::Could not inspect the GHCR synchronization lease."
      return 1
    fi
    now="$(kubernetes_microtime_now)"
    if [[ ! -s "${sync_lease_file}" ]]; then
      jq -n \
        --arg name "${SYNC_LEASE_NAME}" \
        --arg holder "${sync_lease_holder}" \
        --arg now "${now}" \
        --argjson duration "${SYNC_LEASE_DURATION_SECONDS}" '
        {
          apiVersion: "coordination.k8s.io/v1",
          kind: "Lease",
          metadata: {name: $name, namespace: "flux-system"},
          spec: {
            holderIdentity: $holder,
            leaseDurationSeconds: $duration,
            acquireTime: $now,
            renewTime: $now,
            leaseTransitions: 0
          }
        }
      ' >"${sync_lease_manifest_file}"
      if kubectl \
        --context "${KUBE_CONTEXT}" \
        --namespace flux-system \
        create --filename "${sync_lease_manifest_file}" \
        >"${sync_lease_result_file}" 2>&1; then
        sync_lease_acquired=true
        sync_lease_heartbeat_loop &
        sync_lease_heartbeat_pid=$!
        return 0
      fi
      continue
    fi
    if ! jq -e '
      (.metadata.resourceVersion | type == "string" and length > 0)
      and ((.spec.holderIdentity // "") | type == "string")
      and (.spec.leaseDurationSeconds | type == "number" and . > 0)
      and ((.spec.renewTime // .spec.acquireTime // "")
        | type == "string" and length > 0)
      and ((.spec.leaseTransitions // 0) | type == "number")
    ' "${sync_lease_file}" >/dev/null; then
      echo "::error::The GHCR synchronization lease is malformed; refusing cluster mutation."
      return 1
    fi
    if ! sync_lease_is_available; then
      echo "::error::Another GHCR synchronization transaction holds the synchronization lease; automatic expiry takeover is disabled because Talos writes cannot be fenced. Prove the prior process is dead before explicitly recovering the Lease. Run './scripts/refresh-flux-ghcr-auth.sh --fences' to list every held fence with its liveness evidence and exact release command, and see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
      return 1
    fi
    resource_version="$(jq -er '.metadata.resourceVersion' "${sync_lease_file}")"
    current_holder="$(jq -r '.spec.holderIdentity // ""' "${sync_lease_file}")"
    transitions="$(jq -er '(.spec.leaseTransitions // 0) + 1' "${sync_lease_file}")"
    jq -n \
      --arg resource_version "${resource_version}" \
      --arg current_holder "${current_holder}" \
      --arg holder "${sync_lease_holder}" \
      --arg now "${now}" \
      --argjson duration "${SYNC_LEASE_DURATION_SECONDS}" \
      --argjson transitions "${transitions}" '
      [
        {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
        {op: "test", path: "/spec/holderIdentity", value: $current_holder},
        {op: "replace", path: "/spec/holderIdentity", value: $holder},
        {op: "replace", path: "/spec/leaseDurationSeconds", value: $duration},
        {op: "replace", path: "/spec/acquireTime", value: $now},
        {op: "replace", path: "/spec/renewTime", value: $now},
        {op: "replace", path: "/spec/leaseTransitions", value: $transitions}
      ]
    ' >"${sync_lease_patch_file}"
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      patch lease "${SYNC_LEASE_NAME}" \
      --type=json \
      --patch-file="${sync_lease_patch_file}" \
      >"${sync_lease_result_file}" 2>&1; then
      sync_lease_acquired=true
      sync_lease_heartbeat_loop &
      sync_lease_heartbeat_pid=$!
      return 0
    fi
  done

  failure_detail="$(head -c 1000 "${sync_lease_result_file}" | tr '\r\n' '  ')"
  failure_detail="${failure_detail//%/%25}"
  if [[ -n "${failure_detail}" ]]; then
    echo "::error::Could not atomically acquire the GHCR synchronization lease. Last API error: ${failure_detail}"
  else
    echo "::error::Could not atomically acquire the GHCR synchronization lease after concurrent updates."
  fi
  return 1
}

renew_sync_lease() {
  local invocation_id="$$-${RANDOM}"
  local lease_file="${work_dir}/sync-lease-renew-${invocation_id}.json"
  local patch_file_local="${work_dir}/sync-lease-renew-patch-${invocation_id}.json"
  local result_file="${work_dir}/sync-lease-renew-result-${invocation_id}.txt"
  local resource_version now observed_holder

  sync_lease_renewal_failure=""
  [[ "${sync_lease_acquired}" == "true" && -n "${sync_lease_holder}" ]] || return 1
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get lease "${SYNC_LEASE_NAME}" \
    -o json >"${lease_file}" 2>"${result_file}"; then
    sync_lease_renewal_failure="api-unreachable"
    return 1
  fi
  observed_holder="$(jq -er '.spec.holderIdentity // ""' "${lease_file}")" || {
    sync_lease_renewal_failure="invalid-lease-state"
    return 1
  }
  if [[ "${observed_holder}" != "${sync_lease_holder}" ]]; then
    sync_lease_renewal_failure="held-by-another"
    return 1
  fi
  resource_version="$(jq -er '.metadata.resourceVersion' "${lease_file}")" || {
    sync_lease_renewal_failure="invalid-lease-state"
    return 1
  }
  now="$(kubernetes_microtime_now)"
  jq -n \
    --arg resource_version "${resource_version}" \
    --arg holder "${sync_lease_holder}" \
    --arg now "${now}" \
    --argjson duration "${SYNC_LEASE_DURATION_SECONDS}" '
    [
      {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
      {op: "test", path: "/spec/holderIdentity", value: $holder},
      {op: "replace", path: "/spec/renewTime", value: $now},
      {op: "replace", path: "/spec/leaseDurationSeconds", value: $duration}
    ]
  ' >"${patch_file_local}"
  if kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch lease "${SYNC_LEASE_NAME}" \
    --type=json \
    --patch-file="${patch_file_local}" \
    >"${result_file}" 2>&1; then
    return 0
  fi

  # Foreground guards and the heartbeat can legitimately race each other. A
  # resourceVersion conflict is harmless when the winning renewal still belongs
  # to this transaction and remains live; re-read before declaring lease loss.
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get lease "${SYNC_LEASE_NAME}" \
    -o json >"${lease_file}" 2>"${result_file}"; then
    sync_lease_renewal_failure="api-unreachable"
    return 1
  fi
  observed_holder="$(jq -er '.spec.holderIdentity // ""' "${lease_file}")" || {
    sync_lease_renewal_failure="invalid-lease-state"
    return 1
  }
  if [[ "${observed_holder}" != "${sync_lease_holder}" ]]; then
    sync_lease_renewal_failure="held-by-another"
    return 1
  fi
  if jq -e \
    --arg holder "${sync_lease_holder}" \
    --argjson now_epoch "$(date -u +%s)" '
    .spec.holderIdentity == $holder
    and (((.spec.renewTime // .spec.acquireTime)
      | sub("\\.[0-9]+Z$"; "Z")
      | fromdateiso8601) + .spec.leaseDurationSeconds > $now_epoch)
  ' "${lease_file}" >/dev/null; then
    return 0
  fi

  sync_lease_renewal_failure="not-live"
  return 1
}

# Advance this transaction's own fence from "claimed" to "mutating", immediately
# before the first Talos mutation on that node.
#
# The CAS tests pin both the node uid and our own owner value, so this can never
# advance a fence that changed hands and never resurrects one on a replaced node
# reusing the same name. Failing to advance is fatal for that node: an
# un-advanced marker would leave a mutated node looking reclaimable, which is
# the one direction that is never safe.
mark_node_fence_mutating() {
  local node_name="$1" owner_token="$2" node_uid="$3"
  local patch_file_local="${work_dir}/fence-phase-patch.json"
  local result_file="${work_dir}/fence-phase-result.txt"

  # CAS on uid + our own owner value so this can never advance a fence that
  # changed hands, and never resurrect one on a replaced node of the same name.
  jq -n \
    --arg uid "${node_uid}" \
    --arg owner_path "${CORDON_OWNER_JSON_PATH}" \
    --arg owner "${owner_token}" \
    --arg phase_path "${CORDON_PHASE_JSON_PATH}" '
    [
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: $owner_path, value: $owner},
      {op: "add", path: $phase_path, value: "mutating"}
    ]
  ' >"${patch_file_local}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    patch node "${node_name}" \
    --type=json \
    --patch-file="${patch_file_local}" \
    >"${result_file}" 2>&1; then
    echo "::error::Could not mark node ${node_name} as entering Talos mutation; refusing to mutate it."
    emit_safe_operation_output "fence-phase" "${result_file}"
    return 1
  fi
}

# Reclaim drain fences that were ALREADY leaked when this transaction acquired
# the synchronization Lease.
#
# The liveness proof is the Lease itself. sync_lease_is_available refuses any
# non-empty holderIdentity, so acquiring it proves that at that instant no
# bridge transaction was running — and a node fence is only ever held by a
# running transaction, which asserts the Lease at every mutation point. A fence
# already present at acquisition therefore has no owner alive to protect, and
# reclaiming it cannot race a live drain. That needs no run id and no timestamp,
# so it also recovers fences leaked by earlier versions of this script (#3070).
#
# It does NOT weaken the refusal against a live holder: a live holder holds the
# Lease, so this transaction would never have acquired it and would never reach
# here. A fence that appears AFTER acquisition is not reclaimed either — the
# caller runs this against the FIRST convergence inventory only, so a fence this
# transaction itself creates later is never in the snapshot being reclaimed.
#
# Deliberately narrow, in two ways:
#   * A fence carrying a recovery journal is left alone. The journal records an
#     interrupted bootstrap whose phase decides what is safe to do, bootstrap
#     recovery owns that state, and clearing it would destroy the only durable
#     record of an in-flight Talos mutation.
#   * The node is left CORDONED, loudly. Without a journal the pre-claim
#     schedulability was never recorded, so uncordoning could re-admit a node an
#     operator had deliberately drained. Losing capacity is recoverable by hand;
#     silently re-admitting a drained node is not.
reclaim_orphaned_node_fences() {
  local nodes_file="$1"
  local patch_file_local="${work_dir}/reclaim-fence-patch.json"
  local result_file="${work_dir}/reclaim-fence-result.txt"
  local name uid owner cordoned reclaimed=0

  while IFS=$'\t' read -r name uid owner cordoned; do
    [[ -n "${name}" ]] || continue
    # CAS on identity AND the exact owner value: a node replaced under the same
    # name, or a fence that changed hands since the read, must not be cleared.
    jq -n \
      --arg uid "${uid}" \
      --arg owner_path "${CORDON_OWNER_JSON_PATH}" \
      --arg owner "${owner}" \
      --arg phase_path "${CORDON_PHASE_JSON_PATH}" '
      [
        {op: "test", path: "/metadata/uid", value: $uid},
        {op: "test", path: $owner_path, value: $owner},
        {op: "test", path: $phase_path, value: "claimed"},
        {op: "remove", path: $owner_path},
        {op: "remove", path: $phase_path}
      ]
    ' >"${patch_file_local}"
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      patch node "${name}" \
      --type=json \
      --patch-file="${patch_file_local}" \
      >"${result_file}" 2>&1; then
      echo "::error::Could not reclaim the leaked GHCR drain fence on node ${name}; it changed while being reclaimed."
      return 1
    fi
    reclaimed=$((reclaimed + 1))
    printf '::warning::Reclaimed a leaked GHCR drain fence on node %s (owner %s). The synchronization Lease was free when this transaction acquired it, so no owner was alive to protect it.\n' \
      "${name}" "${owner}"
    if [[ "${cordoned}" == "true" ]]; then
      printf '::warning::Node %s is left CORDONED on purpose: the killed transaction recorded no pre-claim schedulability, so this cannot tell whether it was already drained. Confirm it should be schedulable, then: kubectl --context %s uncordon %s\n' \
        "${name}" "${KUBE_CONTEXT}" "${name}"
    fi
    # The selection lives in the safety library so the decision — what counts as
    # provably orphaned — is unit-testable against real leaked-fence JSON,
    # separately from the mutation it authorises.
  done < <(select_orphaned_node_fences "${nodes_file}" /dev/stdout)

  # Published so the caller knows the inventory it holds is now stale: the
  # reclaim removed annotations that are still present in its snapshot.
  reclaimed_fence_count="${reclaimed}"
  ((reclaimed == 0)) || assert_sync_lease_held || return 1
}

# Report what the Lease looked like at the moment a renewal was refused.
#
# "The GHCR synchronization lease was lost" is currently indistinguishable
# between two very different causes: another transaction genuinely took the
# Lease, or this one simply failed to renew it (a throttled or dropped read, a
# resourceVersion race whose re-read also failed). They call for opposite
# responses, and the current message supports neither — a prod investigation on
# 2026-08-10 could not separate them from the logs at all (platform#3071).
#
# Purely diagnostic: every read is best-effort and the caller's control flow is
# unchanged whether this succeeds, fails, or finds nothing. The Lease holds no
# credential material, so printing it verbatim is safe.
report_sync_lease_state() {
  local context="$1"
  local probe="${work_dir}/sync-lease-diagnostic-$$-${RANDOM}.json"

  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --request-timeout=30s \
    --namespace flux-system \
    get lease "${SYNC_LEASE_NAME}" \
    -o json >"${probe}" 2>/dev/null; then
    # The redirect creates the file before kubectl fails, so this path has a
    # partial probe to remove too. work_dir outlives every heartbeat renewal, so
    # skipping it here would accumulate one file per failed renewal for the whole
    # run — exactly the path that fires repeatedly when the API is unhealthy.
    rm -f "${probe}"
    printf '::warning::sync-lease diagnostic (%s): the Lease could not be read, so ownership is UNKNOWN — this is the transient-failure shape, not proof of loss. ours=%s\n' \
      "${context}" "${sync_lease_holder:-<unset>}"
    return 0
  fi
  jq -r \
    --arg context "${context}" \
    --arg ours "${sync_lease_holder:-}" '
    "::warning::sync-lease diagnostic (" + $context + "): "
    + "ours=" + (if $ours == "" then "<unset>" else $ours end)
    + " holder=" + ((.spec.holderIdentity // "") | if . == "" then "<released>" else . end)
    + " same_holder=" + (((.spec.holderIdentity // "") == $ours) | tostring)
    + " transitions=" + ((.spec.leaseTransitions // 0) | tostring)
    + " renewTime=" + ((.spec.renewTime // .spec.acquireTime // "<none>") | tostring)
    + " durationSeconds=" + ((.spec.leaseDurationSeconds // 0) | tostring)
    + " resourceVersion=" + (.metadata.resourceVersion // "<none>")
  ' "${probe}" 2>/dev/null ||
    printf '::warning::sync-lease diagnostic (%s): the Lease was read but could not be parsed.\n' \
      "${context}"
  rm -f "${probe}"
  return 0
}

sync_lease_heartbeat_loop() {
  local elapsed
  while true; do
    for ((elapsed = 0; elapsed < SYNC_LEASE_HEARTBEAT_SECONDS; elapsed++)); do
      sleep 1
    done
    if ! renew_sync_lease; then
      printf '%s\n' "${sync_lease_renewal_failure:-unknown}" >"${sync_lease_lost_file}"
      report_sync_lease_state 'heartbeat renewal failed'
      return 1
    fi
  done
}

wait_for_sync_lease_api_recovery() {
  local attempt
  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      get --raw=/readyz \
      --request-timeout=30s \
      >"${sync_lease_result_file}" 2>&1; then
      return 0
    fi
    if ((attempt < SYNC_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done

  echo "::error::The Kubernetes API remained unreachable while verifying the GHCR synchronization Lease; no further cluster mutation is safe."
  emit_safe_operation_output "api-ready" "${sync_lease_result_file}"
  return 1
}

assert_sync_lease_held() {
  # Distinguish the two refusal paths: a latched heartbeat failure happened
  # earlier and elsewhere, so its state has already been reported, while a
  # foreground failure is happening right now.
  local failure_reason=""
  if [[ -e "${sync_lease_lost_file}" ]]; then
    failure_reason="$(head -n 1 "${sync_lease_lost_file}")"
  elif renew_sync_lease; then
    return 0
  else
    failure_reason="${sync_lease_renewal_failure:-unknown}"
    report_sync_lease_state 'foreground guard renewal failed'
  fi

  case "${failure_reason}" in
    api-unreachable)
      echo "::warning::The Kubernetes API was unreachable while verifying the GHCR synchronization Lease; waiting for API recovery before re-proving the same holder."
      wait_for_sync_lease_api_recovery || return 1
      recover_sync_lease_heartbeat_after_transport_interruption
      ;;
    held-by-another)
      echo "::error::The GHCR synchronization Lease is now held by another transaction; refusing further cluster mutation."
      return 1
      ;;
    not-live)
      echo "::error::The GHCR synchronization Lease is no longer live for this transaction; refusing further cluster mutation."
      return 1
      ;;
    *)
      echo "::error::The GHCR synchronization Lease state could not be proved (${failure_reason}); refusing further cluster mutation."
      return 1
      ;;
  esac
}

recover_sync_lease_heartbeat_after_transport_interruption() {
  # API readiness can return while the heartbeat's failed renewal is still in
  # flight and before it writes the sticky marker. Stop and reap the old child
  # unconditionally so it cannot report a stale failure after the foreground
  # path has re-proved the same holder.
  if [[ -n "${sync_lease_heartbeat_pid}" ]]; then
    kill "${sync_lease_heartbeat_pid}" 2>/dev/null || true
    wait "${sync_lease_heartbeat_pid}" 2>/dev/null || true
    sync_lease_heartbeat_pid=""
  fi
  if ! renew_sync_lease; then
    if [[ "${sync_lease_renewal_failure}" == "held-by-another" ]]; then
      echo "::error::The Kubernetes API recovered, but this transaction could not re-prove and renew its synchronization Lease holder because the Lease is now held by another transaction."
    else
      echo "::error::The Kubernetes API recovered, but this transaction could not re-prove and renew its synchronization Lease holder (${sync_lease_renewal_failure:-unknown})."
    fi
    return 1
  fi

  rm -f "${sync_lease_lost_file}"
  sync_lease_heartbeat_loop &
  sync_lease_heartbeat_pid=$!
  echo "::warning::Re-proved the same GHCR synchronization Lease holder after API recovery and restarted its heartbeat."
}

release_sync_lease() {
  local lease_file="${work_dir}/sync-lease-release.json"
  local patch_file_local="${work_dir}/sync-lease-release-patch.json"
  local result_file="${work_dir}/sync-lease-release-result.txt"
  local now attempt backoff observed_holder release_failure="" failure_detail=""

  if [[ -n "${sync_lease_heartbeat_pid}" ]]; then
    kill "${sync_lease_heartbeat_pid}" 2>/dev/null || true
    wait "${sync_lease_heartbeat_pid}" 2>/dev/null || true
    sync_lease_heartbeat_pid=""
  fi
  [[ "${sync_lease_acquired}" == "true" && -n "${sync_lease_holder}" ]] || return 0

  # Killing the heartbeat shell does not reap the kubectl child it may be
  # blocked in, so that renewal can still land between the read and the patch
  # below. The CAS therefore tests holderIdentity ONLY. That alone carries the
  # safety property of a release -- the lease is still ours -- while a
  # resourceVersion conjunct would additionally fail on exactly the benign
  # same-holder write renew_sync_lease is already documented to expect. A
  # release that refuses leaves the lease held, so that conjunct converts a
  # harmless race into a wedge that blocks every later transaction until a
  # human clears it. A lease held by anyone ELSE still refuses, below.
  #
  # (fence_lease_release_patch keeps its resourceVersion conjunct deliberately:
  # there the holder is terminal and nothing races the write, so pinning the
  # version is what proves the Lease has not moved between the report a human
  # read and the command they paste.)
  for ((attempt = 1; attempt <= SYNC_LEASE_RELEASE_ATTEMPTS; attempt++)); do
    # Retrying an API failure in the same millisecond re-asks a server that has
    # not had time to recover, so every attempt lands inside one blip and the
    # retry adds nothing. A linear backoff makes the later attempts sample a
    # genuinely different moment, scaling SYNC_INTERVAL so this stays the same
    # tunable knob every other retry loop here uses -- which also keeps the suite
    # fast, since the tests set it to 0.
    #
    # Repeated sleeps rather than arithmetic: SYNC_INTERVAL is validated as
    # ^[0-9]+([.][0-9]+)?$, so a DECIMAL is a documented-valid setting, and bash
    # $(( )) is integer-only -- multiplying it would abort the release with an
    # arithmetic syntax error on a value the script explicitly accepts.
    for ((backoff = 1; backoff < attempt; backoff++)); do
      sleep "${SYNC_INTERVAL}"
    done
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      --request-timeout=30s \
      get lease "${SYNC_LEASE_NAME}" \
      --ignore-not-found \
      -o json >"${lease_file}" 2>"${result_file}"; then
      release_failure="api-unreachable"
      continue
    fi

    # --ignore-not-found prints nothing when the Lease is gone. That is NOT a
    # quiet success: acquire_sync_lease CREATES the Lease when it is absent, so
    # a concurrent transaction that found it deleted has already acquired it
    # without ever conflicting with us. That is the same thing the foreign-holder
    # branch below exists to surface -- this run can no longer prove it held the
    # lease while it was mutating -- so it is reported on the same terms. Nothing
    # is left held, so failing here wedges nothing.
    if [[ ! -s "${lease_file}" ]]; then
      echo "::error::The GHCR synchronization lease no longer exists; this run cannot prove it held the lease while it was mutating."
      return 1
    fi
    observed_holder="$(jq -er '.spec.holderIdentity // ""' "${lease_file}" 2>"${result_file}")" || {
      release_failure="invalid-lease-state"
      continue
    }

    # An empty holder IS this function's goal state, so reaching it is success
    # however it happened. The reachable case is a patch that the apiserver
    # APPLIED and whose response was then lost: kubectl exits non-zero, and the
    # retry finds the Lease already cleared. Treating that as a failure would
    # fail a wholly successful deploy over a released lease -- the same wedge
    # this retry exists to remove, in the likeliest instance of the very
    # transient it targets.
    if [[ -z "${observed_holder}" ]]; then
      sync_lease_holder=""
      sync_lease_acquired=false
      return 0
    fi

    # Losing the lease to another holder stays fatal: this transaction can no
    # longer prove it held the lease while it was mutating, which is exactly
    # the condition the exclusion guarantee exists to surface. Retrying cannot
    # change a holder that already moved away, so refuse immediately -- and say
    # so, because this is a concurrency breach and not a transient.
    if [[ "${observed_holder}" != "${sync_lease_holder}" ]]; then
      echo "::error::The GHCR synchronization lease is held by another transaction; refusing to release a lease this run does not own."
      report_sync_lease_state 'release found a foreign lease holder'
      return 1
    fi

    now="$(kubernetes_microtime_now)"
    jq -n \
      --arg holder "${sync_lease_holder}" \
      --arg now "${now}" '
      [
        {op: "test", path: "/spec/holderIdentity", value: $holder},
        {op: "replace", path: "/spec/holderIdentity", value: ""},
        {op: "replace", path: "/spec/leaseDurationSeconds", value: 1},
        {op: "replace", path: "/spec/renewTime", value: $now}
      ]
    ' >"${patch_file_local}"
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      --request-timeout=30s \
      patch lease "${SYNC_LEASE_NAME}" \
      --type=json \
      --patch-file="${patch_file_local}" \
      >"${result_file}" 2>&1; then
      sync_lease_holder=""
      sync_lease_acquired=false
      return 0
    fi
    release_failure="patch-rejected"
  done

  # Every attempt read a lease still held by this transaction and still failed
  # to clear it. That is a genuine refusal: report it rather than pretending the
  # lease was released. Two halves are needed, and neither substitutes for the
  # other -- which STAGE gave up, and what the API actually said. The caller's
  # own message carries neither, so an operator clearing the lease by hand would
  # otherwise have nothing to go on.
  # Sanitise exactly as acquire_sync_lease already does for this same class of
  # content: bound it, flatten CR *and* LF, and escape '%'. GitHub Actions
  # decodes %25/%0A/%0D inside a workflow command, so unescaped captured output
  # can inject an annotation of its own -- which is why that escaping exists
  # there. Emitting it raw here would have dropped all three protections.
  if [[ -s "${result_file}" ]]; then
    failure_detail="$(head -c 1000 "${result_file}" | tr '\r\n' '  ')"
    failure_detail="${failure_detail//%/%25}"
  fi
  if [[ -n "${failure_detail}" ]]; then
    echo "::error::Could not clear the GHCR synchronization lease after ${SYNC_LEASE_RELEASE_ATTEMPTS} attempts (${release_failure}). Last error: ${failure_detail}"
  else
    echo "::error::Could not clear the GHCR synchronization lease after ${SYNC_LEASE_RELEASE_ATTEMPTS} attempts (${release_failure})."
  fi
  report_sync_lease_state 'lease release failed'
  return 1
}

# The live image-verification policies are owned by the infrastructure Flux
# Kustomization, which is itself owned by the root flux-system Kustomization.
# Fence both levels for the complete runtime-proof window: suspend the child
# and add Flux's documented per-resource reconciliation exclusion so the parent
# cannot restore the Git version between a policy check and Pod admission.
flux_policy_parent_is_owned() {
  jq -e \
    --arg uid "${flux_policy_parent_uid}" \
    --arg owner_annotation "${FLUX_POLICY_PARENT_OWNER_ANNOTATION}" \
    --arg owner "${flux_policy_parent_owner}" '
    .metadata.uid == $uid
    and ((.metadata.annotations // {})[$owner_annotation] == $owner)
    and .spec.suspend == true
  ' "${flux_policy_parent_state_file}" >/dev/null
}

flux_policy_parent_is_stable() {
  flux_policy_parent_is_owned &&
    jq -e '
      any(.status.conditions[]?;
        .type == "Reconciling" and .status == "True") | not
    ' "${flux_policy_parent_state_file}" >/dev/null
}

flux_policy_parent_is_released() {
  jq -e \
    --arg uid "${flux_policy_parent_uid}" \
    --arg owner_annotation "${FLUX_POLICY_PARENT_OWNER_ANNOTATION}" '
    .metadata.uid == $uid
    and (((.metadata.annotations // {})[$owner_annotation] // "") == "")
    and ((.spec.suspend // false) == false)
  ' "${flux_policy_parent_state_file}" >/dev/null
}

pause_flux_policy_parent() {
  local resource_version attempt annotations_present

  # The parent/child ownership annotations are a separate fail-closed fence:
  # even if this process loses the synchronization Lease during acquisition, a
  # new holder sees the durable owner and stops. The first credential/policy
  # mutation below still renews the Lease normally before it can proceed.
  if [[ "${sync_lease_acquired}" != "true" ||
    -z "${sync_lease_holder}" ||
    -e "${sync_lease_lost_file}" ]]; then
    echo "::error::The GHCR synchronization transaction is not locally active; refusing to fence Flux reconciliation."
    return 1
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
    -o json >"${flux_policy_parent_state_file}"; then
    echo "::error::Could not inspect the parent Flux reconciliation before the image-verification policy handoff."
    return 1
  fi
  if jq -e \
    --arg annotation "${FLUX_POLICY_PARENT_OWNER_ANNOTATION}" '
    ((.metadata.annotations // {})[$annotation] // "") != ""
  ' "${flux_policy_parent_state_file}" >/dev/null; then
    # A killed transaction leaves this annotation behind, so this branch — not the
    # malformed/suspended one below — is what an orphaned parent fence actually hits.
    # It needs the same pointer the child-handoff refusal already carries.
    echo "::error::Another transaction already owns the parent Flux policy handoff; refusing cluster mutation. Run './scripts/refresh-flux-ghcr-auth.sh --fences' to list every held fence with its liveness evidence and exact release command, and see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
    return 1
  fi
  if ! jq -e '
    .kind == "Kustomization"
    and (.metadata.uid | type == "string" and length > 0)
    and (.metadata.resourceVersion | type == "string" and length > 0)
    and ((.metadata.annotations // {}) | type == "object")
    and ((.spec.suspend // false) == false)
  ' "${flux_policy_parent_state_file}" >/dev/null; then
    # A run that stops here never reaches the child-handoff refusal, so it needs
    # its own pointer: an orphaned parent fence is exactly the staged-fence case
    # the report exists to make discoverable.
    echo "::error::The parent Flux reconciliation is malformed or already suspended. If a previous transaction was killed, run './scripts/refresh-flux-ghcr-auth.sh --fences' to list every held fence with its liveness evidence and exact release command, and see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
    return 1
  fi

  resource_version="$(jq -er '.metadata.resourceVersion' \
    "${flux_policy_parent_state_file}")"
  flux_policy_parent_uid="$(jq -er '.metadata.uid' \
    "${flux_policy_parent_state_file}")"
  flux_policy_parent_owner="${sync_lease_holder}"
  annotations_present="$(jq -r \
    '(.metadata.annotations? | type) == "object"' \
    "${flux_policy_parent_state_file}")"
  jq -n \
    --arg resource_version "${resource_version}" \
    --arg uid "${flux_policy_parent_uid}" \
    --arg owner_path "${FLUX_POLICY_PARENT_OWNER_JSON_PATH}" \
    --arg owner "${flux_policy_parent_owner}" \
    --argjson annotations_present "${annotations_present}" '
    [
      {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
      {op: "test", path: "/metadata/uid", value: $uid}
    ]
    + (if $annotations_present then [] else
      [{op: "add", path: "/metadata/annotations", value: {}}]
    end)
    + [
      {op: "add", path: $owner_path, value: $owner},
      {op: "add", path: "/spec/suspend", value: true}
    ]
  ' >"${flux_policy_parent_patch_file}"
  if kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
    --type=json \
    --patch-file="${flux_policy_parent_patch_file}" \
    -o json \
    >"${flux_policy_parent_state_file}" \
    2>"${flux_policy_parent_result_file}"; then
    flux_policy_parent_acquired=true
  else
    # A lost patch response is ambiguous. Re-read and adopt only the exact
    # UID/owner/suspend tuple written by this transaction so EXIT cleanup owns
    # the durable fence even when kubectl reported failure.
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
      -o json >"${flux_policy_parent_state_file}" ||
      ! flux_policy_parent_is_owned; then
      emit_safe_operation_output "flux-policy-parent-patch" \
        "${flux_policy_parent_result_file}"
      echo "::error::Could not atomically pause or adopt the parent Flux policy handoff."
      return 1
    fi
    flux_policy_parent_acquired=true
  fi

  # New parent reconciliations now stop at spec.suspend. After a mandatory
  # quiet interval, require a fresh observation without an in-flight
  # Reconciling condition before touching the child that this parent owns.
  for ((attempt = 1; attempt <= SYNC_ATTEMPTS + 2; attempt++)); do
    sleep "${SYNC_INTERVAL}"
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
      -o json >"${flux_policy_parent_state_file}" &&
      flux_policy_parent_is_stable; then
      return 0
    fi
  done

  echo "::error::The parent Flux reconciliation did not quiesce before the image-verification policy handoff."
  return 1
}

resume_flux_policy_parent() {
  [[ "${flux_policy_parent_acquired}" == "true" ]] || return 0
  jq -n \
    --arg uid "${flux_policy_parent_uid}" \
    --arg owner_path "${FLUX_POLICY_PARENT_OWNER_JSON_PATH}" \
    --arg owner "${flux_policy_parent_owner}" '
    [
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: $owner_path, value: $owner},
      {op: "test", path: "/spec/suspend", value: true},
      {op: "add", path: "/spec/suspend", value: false},
      {op: "remove", path: $owner_path}
    ]
  ' >"${flux_policy_parent_patch_file}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
    --type=json \
    --patch-file="${flux_policy_parent_patch_file}" \
    >"${flux_policy_parent_result_file}" 2>&1; then
    # A successful release can lose its API response just like acquisition.
    # Adopt only the exact desired post-release UID/owner/suspend state; any
    # other outcome retains local ownership and fails closed for recovery.
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
      -o json >"${flux_policy_parent_state_file}" ||
      ! flux_policy_parent_is_released; then
      return 1
    fi
  fi
  flux_policy_parent_acquired=false
  flux_policy_parent_owner=""
  flux_policy_parent_uid=""
}

flux_policy_handoff_is_owned() {
  jq -e \
    --arg uid "${flux_policy_handoff_uid}" \
    --arg owner_annotation "${FLUX_POLICY_HANDOFF_OWNER_ANNOTATION}" \
    --arg reconcile_annotation "${FLUX_RECONCILE_ANNOTATION}" \
    --arg owner "${flux_policy_handoff_owner}" '
    .metadata.uid == $uid
    and ((.metadata.annotations // {})[$owner_annotation] == $owner)
    and ((.metadata.annotations // {})[$reconcile_annotation] == "disabled")
    and .spec.suspend == true
  ' "${flux_policy_handoff_state_file}" >/dev/null
}

flux_policy_handoff_is_quiescent() {
  jq -e '
    any(.status.conditions[]?;
      .type == "Reconciling" and .status == "True") | not
  ' "${flux_policy_handoff_state_file}" >/dev/null
}

# Print the conditions that explain a Kustomization's reconciliation state.
# Diagnostic output only: an unreadable or unparseable state file prints
# nothing and still succeeds.
flux_policy_report_conditions() {
  local state_file="$1" label="$2"

  [[ -s "${state_file}" ]] || return 0
  jq -r --arg label "${label}" '
    [.status.conditions[]?
      | select(.type == "Reconciling" or .type == "Ready" or .type == "Healthy")
      | "\($label): \(.type)=\(.status) \(.reason // "-"): "
        + ((.message // "-") | gsub("\\s+"; " "))]
    | if length == 0 then ["\($label): reported no status conditions"] else . end
    | .[]
  ' "${state_file}" 2>/dev/null || true
}

# Explain a failed quiesce wait. The blocking condition is already in the state
# file that wait just read, and when the owner is held up by a dependency the
# cause is one read further out. Without this the failure names image
# verification while the real blocker is an unrelated workload, which is what
# makes the merge-queue eviction it causes read as "some PR failed CI".
#
# Strictly best-effort: this runs on the production credential path, so a
# diagnostic must never change the outcome it is describing.
report_flux_policy_handoff_blockers() {
  local dependency dependency_name dependency_namespace

  flux_policy_report_conditions \
    "${flux_policy_handoff_state_file}" \
    "kustomization/${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}"

  # Read the dependencies the owner itself declares rather than parsing them
  # out of a controller-authored message.
  jq -r '
    if any(.status.conditions[]?;
      .type == "Ready" and .reason == "DependencyNotReady")
    then
      .metadata.namespace as $namespace
      | .spec.dependsOn[]?
      | "\(.namespace // $namespace)/\(.name)"
    else empty end
  ' "${flux_policy_handoff_state_file}" \
    2>/dev/null >"${flux_policy_blocker_names_file}" || return 0

  while IFS= read -r dependency; do
    dependency_namespace="${dependency%%/*}"
    dependency_name="${dependency##*/}"
    [[ -n "${dependency_namespace}" && -n "${dependency_name}" &&
      "${dependency}" == "${dependency_namespace}/${dependency_name}" ]] ||
      continue
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace "${dependency_namespace}" \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${dependency_name}" \
      -o json </dev/null >"${flux_policy_blocker_state_file}" 2>/dev/null; then
      flux_policy_report_conditions \
        "${flux_policy_blocker_state_file}" \
        "kustomization/${dependency_name} (dependency)"
    else
      echo "Could not read dependency ${dependency} while explaining the image-verification policy handoff quiesce timeout."
    fi
  done <"${flux_policy_blocker_names_file}"
  return 0
}

read_flux_policy_fences() {
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
    "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
    -o json >"${flux_policy_fences_state_file}" ||
    ! jq -e \
      --arg parent "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" \
      --arg child "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" '
      .kind == "List"
      and ([.items[] | select(.metadata.name == $parent)] | length) == 1
      and ([.items[] | select(.metadata.name == $child)] | length) == 1
    ' "${flux_policy_fences_state_file}" >/dev/null; then
    return 1
  fi
  jq -e \
    --arg child "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" '
    .items[] | select(.metadata.name == $child)
  ' "${flux_policy_fences_state_file}" >"${flux_policy_handoff_state_file}"
  jq -e \
    --arg parent "${IMAGE_VERIFICATION_FLUX_PARENT_KUSTOMIZATION}" '
    .items[] | select(.metadata.name == $parent)
  ' "${flux_policy_fences_state_file}" >"${flux_policy_parent_state_file}"
}

restart_flux_kustomize_controller_for_handoff() {
  local resource_version deployment_uid replicas annotations_present
  local restart_token
  local pre_handoff_pods_replaced attempt

  assert_sync_lease_held || return 1
  if ! read_flux_policy_fences ||
    ! flux_policy_handoff_is_owned ||
    ! flux_policy_parent_is_stable; then
    echo "::error::The Flux policy fences changed before the kustomize-controller handoff restart."
    return 1
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get deployment.apps \
    "${FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT}" \
    -o json >"${flux_controller_deployment_state_file}"; then
    echo "::error::Could not inspect kustomize-controller before the policy handoff restart."
    return 1
  fi
  if ! jq -e \
    --arg name "${FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT}" '
    .kind == "Deployment"
    and .metadata.name == $name
    and (.metadata.uid | type == "string" and length > 0)
    and (.metadata.resourceVersion | type == "string" and length > 0)
    and (.spec.replicas | type == "number" and . >= 1 and floor == .)
    and .spec.selector.matchLabels.app == $name
    and ((.status.availableReplicas // 0) >= .spec.replicas)
    and (((.spec.template.metadata.annotations // {}) | type) == "object")
  ' "${flux_controller_deployment_state_file}" >/dev/null; then
    echo "::error::kustomize-controller is malformed or not fully available; refusing the policy handoff restart."
    return 1
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get pods \
    --selector "${FLUX_KUSTOMIZE_CONTROLLER_SELECTOR}" \
    -o json >"${flux_controller_pods_before_file}" ||
    ! jq -e '
      .kind == "List"
      and (.items | length) >= 1
      and all(.items[];
        (.metadata.uid | type == "string" and length > 0)
        and ((.metadata.deletionTimestamp // "") == "")
        and any(.status.conditions[]?;
          .type == "Ready" and .status == "True")
      )
    ' "${flux_controller_pods_before_file}" >/dev/null; then
    echo "::error::Could not prove the current kustomize-controller Pods are Ready before restarting them."
    return 1
  fi

  resource_version="$(jq -er '.metadata.resourceVersion' \
    "${flux_controller_deployment_state_file}")"
  deployment_uid="$(jq -er '.metadata.uid' \
    "${flux_controller_deployment_state_file}")"
  replicas="$(jq -er '.spec.replicas' \
    "${flux_controller_deployment_state_file}")"
  annotations_present="$(jq -r \
    '(.spec.template.metadata.annotations? | type) == "object"' \
    "${flux_controller_deployment_state_file}")"
  restart_token="$(kubernetes_microtime_now)"
  jq -n \
    --arg resource_version "${resource_version}" \
    --arg uid "${deployment_uid}" \
    --arg restart_path "${FLUX_CONTROLLER_RESTART_JSON_PATH}" \
    --arg restart_token "${restart_token}" \
    --argjson annotations_present "${annotations_present}" '
    [
      {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
      {op: "test", path: "/metadata/uid", value: $uid}
    ]
    + (if $annotations_present then [] else
      [{op: "add", path: "/spec/template/metadata/annotations", value: {}}]
    end)
    + [{op: "add", path: $restart_path, value: $restart_token}]
  ' >"${flux_controller_restart_patch_file}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch deployment.apps \
    "${FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT}" \
    --type=json \
    --patch-file="${flux_controller_restart_patch_file}" \
    -o json >"${flux_controller_deployment_state_file}" \
    2>"${flux_controller_result_file}"; then
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get deployment.apps \
      "${FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT}" \
      -o json >"${flux_controller_deployment_state_file}" ||
      ! jq -e \
        --arg uid "${deployment_uid}" \
        --arg restart "${restart_token}" '
        .metadata.uid == $uid
        and ((.spec.template.metadata.annotations // {})["kubectl.kubernetes.io/restartedAt"] == $restart)
      ' "${flux_controller_deployment_state_file}" >/dev/null; then
      echo "::error::Could not atomically restart or adopt the kustomize-controller policy handoff rollout."
      return 1
    fi
  fi
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    rollout status \
    "deployment.apps/${FLUX_KUSTOMIZE_CONTROLLER_DEPLOYMENT}" \
    --timeout="${FLUX_CONTROLLER_ROLLOUT_TIMEOUT}" \
    >"${flux_controller_result_file}" 2>&1; then
    echo "::error::kustomize-controller did not complete the policy handoff restart."
    return 1
  fi
  # `kubectl rollout status` returns as soon as the new ReplicaSet is available; it does not wait
  # for the superseded Pods to finish terminating. Sampling the proof once therefore fails a
  # correct rollout whenever a pre-handoff Pod is still inside its termination grace period. Poll
  # instead, on the same budget as the rest of this script. The success condition is unchanged: a
  # pre-handoff Pod object that never goes away still exhausts the budget and fails, because its
  # process can still hold the superseded GHCR credential.
  pre_handoff_pods_replaced=false
  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get pods \
      --selector "${FLUX_KUSTOMIZE_CONTROLLER_SELECTOR}" \
      -o json >"${flux_controller_pods_after_file}" &&
      jq -e \
        --argjson replicas "${replicas}" \
        --slurpfile before "${flux_controller_pods_before_file}" '
        [.items[] | select((.metadata.deletionTimestamp // "") == "")] as $current
        | [.items[].metadata.uid] as $post_uids
        | [$before[0].items[].metadata.uid] as $old_uids
        | ($current | length) >= $replicas
        and all($current[];
          (.metadata.uid | type == "string" and length > 0)
          and any(.status.conditions[]?;
            .type == "Ready" and .status == "True")
        )
        and all($old_uids[];
          . as $old_uid | ($post_uids | index($old_uid)) == null)
      ' "${flux_controller_pods_after_file}" >/dev/null; then
      pre_handoff_pods_replaced=true
      break
    fi
    if ((attempt < SYNC_ATTEMPTS)); then
      sleep "${SYNC_INTERVAL}"
    fi
  done
  if [[ "${pre_handoff_pods_replaced}" != "true" ]]; then
    echo "::error::Could not prove every pre-handoff kustomize-controller process was replaced by a Ready Pod."
    return 1
  fi
  assert_sync_lease_held || return 1
  if ! read_flux_policy_fences ||
    ! flux_policy_handoff_is_owned ||
    ! flux_policy_parent_is_stable; then
    echo "::error::The Flux policy fences changed during the kustomize-controller handoff restart."
    return 1
  fi
}

flux_policy_handoff_is_released() {
  jq -e \
    --arg uid "${flux_policy_handoff_uid}" \
    --arg owner_annotation "${FLUX_POLICY_HANDOFF_OWNER_ANNOTATION}" \
    --arg reconcile_annotation "${FLUX_RECONCILE_ANNOTATION}" '
    .metadata.uid == $uid
    and (((.metadata.annotations // {})[$owner_annotation] // "") == "")
    and (((.metadata.annotations // {})[$reconcile_annotation] // "") == "")
    and ((.spec.suspend // false) == false)
  ' "${flux_policy_handoff_state_file}" >/dev/null
}

pause_flux_policy_handoff() {
  local resource_version attempt annotations_present
  local stable_resource_version="" current_resource_version

  # Quiesce the child before changing spec.suspend. Suspending a Kustomization
  # while it is already reconciling can strand Reconciling=True in status: the
  # suspended controller intentionally does not advance observedGeneration, so
  # the post-patch status can never prove the old reconcile finished. The
  # parent is already fenced; wait for the child to finish, then use its latest
  # resourceVersion as the acquisition CAS so any intervening Kustomization
  # write rejects the pause patch.
  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    if read_flux_policy_fences; then
      if jq -e \
        --arg annotation "${FLUX_POLICY_HANDOFF_OWNER_ANNOTATION}" '
        ((.metadata.annotations // {})[$annotation] // "") != ""
      ' "${flux_policy_handoff_state_file}" >/dev/null; then
        echo "::error::Another transaction already owns the image-verification policy handoff; refusing cluster mutation. Run './scripts/refresh-flux-ghcr-auth.sh --fences' to list every held fence with its liveness evidence and exact release command, and see docs/dr/runbook.md → 'Recover an orphaned GHCR deploy fence'."
        return 1
      fi
      if ! jq -e \
        --arg reconcile_annotation "${FLUX_RECONCILE_ANNOTATION}" '
        .kind == "Kustomization"
        and (.metadata.uid | type == "string" and length > 0)
        and (.metadata.resourceVersion | type == "string" and length > 0)
        and (.metadata.generation | type == "number" and . > 0)
        and ((.metadata.annotations // {}) | type == "object")
        and (((.metadata.annotations // {})[$reconcile_annotation] // "") == "")
        and ((.spec.suspend // false) == false)
      ' "${flux_policy_handoff_state_file}" >/dev/null; then
        echo "::error::The Flux image-verification policy owner is malformed, already suspended, or already excluded from reconciliation."
        return 1
      fi
      if flux_policy_parent_is_stable &&
        flux_policy_handoff_is_quiescent; then
        break
      fi
    fi
    if ((attempt == SYNC_ATTEMPTS)); then
      echo "::error::The Flux image-verification policy owner did not quiesce before the image-verification policy handoff."
      report_flux_policy_handoff_blockers || true
      return 1
    fi
    sleep "${SYNC_INTERVAL}"
  done

  resource_version="$(jq -er '.metadata.resourceVersion' \
    "${flux_policy_handoff_state_file}")"
  flux_policy_handoff_uid="$(jq -er '.metadata.uid' \
    "${flux_policy_handoff_state_file}")"
  flux_policy_handoff_owner="${sync_lease_holder}"
  annotations_present="$(jq -r \
    '(.metadata.annotations? | type) == "object"' \
    "${flux_policy_handoff_state_file}")"
  jq -n \
    --arg resource_version "${resource_version}" \
    --arg uid "${flux_policy_handoff_uid}" \
    --arg owner_path "${FLUX_POLICY_HANDOFF_OWNER_JSON_PATH}" \
    --arg reconcile_path "${FLUX_RECONCILE_JSON_PATH}" \
    --arg owner "${flux_policy_handoff_owner}" \
    --argjson annotations_present "${annotations_present}" '
    [
      {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
      {op: "test", path: "/metadata/uid", value: $uid}
    ]
    + (if $annotations_present then [] else
      [{op: "add", path: "/metadata/annotations", value: {}}]
    end)
    + [
      {op: "add", path: $owner_path, value: $owner},
      {op: "add", path: $reconcile_path, value: "disabled"},
      {op: "add", path: "/spec/suspend", value: true}
    ]
  ' >"${flux_policy_handoff_patch_file}"
  if kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
    --type=json \
    --patch-file="${flux_policy_handoff_patch_file}" \
    -o json \
    >"${flux_policy_handoff_state_file}" \
    2>"${flux_policy_handoff_result_file}"; then
    flux_policy_handoff_acquired=true
  else
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
      -o json >"${flux_policy_handoff_state_file}" ||
      ! flux_policy_handoff_is_owned; then
      echo "::error::Could not atomically pause or adopt the Flux image-verification policy owner."
      return 1
    fi
    flux_policy_handoff_acquired=true
  fi

  # Flux explicitly documents that suspension does not stop an execution that
  # already started. Replace every pre-pause kustomize-controller process while
  # both policy-owner fences and the synchronization Lease are held. The new
  # controller observes spec.suspend=true, so no old execution can write a
  # managed ImageValidatingPolicy after this point.
  restart_flux_kustomize_controller_for_handoff || return 1

  # A suspended reconciliation intentionally does not advance
  # status.observedGeneration and can leave its pre-suspension Reconciling=True
  # condition behind. That status is therefore not a valid post-pause clock.
  # Require the exact owned fence and its resourceVersion to remain unchanged
  # across two fresh observations instead, while re-proving the parent in each
  # polling pass. Any controller or competing API write resets the quiet proof.
  for ((attempt = 1; attempt <= SYNC_ATTEMPTS; attempt++)); do
    sleep "${SYNC_INTERVAL}"
    if ! read_flux_policy_fences; then
      stable_resource_version=""
      continue
    fi
    if flux_policy_handoff_is_owned &&
      flux_policy_parent_is_stable; then
      current_resource_version="$(jq -er '.metadata.resourceVersion' \
        "${flux_policy_handoff_state_file}")"
      if [[ -n "${stable_resource_version}" &&
        "${current_resource_version}" == "${stable_resource_version}" ]]; then
        return 0
      fi
      stable_resource_version="${current_resource_version}"
    else
      stable_resource_version=""
    fi
  done

  echo "::error::Flux did not acknowledge a stable pause of the image-verification policy owner."
  return 1
}

resume_flux_policy_handoff() {
  [[ "${flux_policy_handoff_acquired}" == "true" ]] || return 0
  jq -n \
    --arg uid "${flux_policy_handoff_uid}" \
    --arg owner_path "${FLUX_POLICY_HANDOFF_OWNER_JSON_PATH}" \
    --arg reconcile_path "${FLUX_RECONCILE_JSON_PATH}" \
    --arg owner "${flux_policy_handoff_owner}" '
    [
      {op: "test", path: "/metadata/uid", value: $uid},
      {op: "test", path: $owner_path, value: $owner},
      {op: "test", path: $reconcile_path, value: "disabled"},
      {op: "test", path: "/spec/suspend", value: true},
      {op: "add", path: "/spec/suspend", value: false},
      {op: "remove", path: $owner_path},
      {op: "remove", path: $reconcile_path}
    ]
  ' >"${flux_policy_handoff_patch_file}"
  if ! kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    patch "${FLUX_KUSTOMIZATION_RESOURCE}" \
    "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
    --type=json \
    --patch-file="${flux_policy_handoff_patch_file}" \
    >"${flux_policy_handoff_result_file}" 2>&1; then
    # Accept a lost release response only after re-reading the exact safe child
    # state; otherwise retain local ownership and fail closed for recovery.
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace flux-system \
      get "${FLUX_KUSTOMIZATION_RESOURCE}" \
      "${IMAGE_VERIFICATION_FLUX_KUSTOMIZATION}" \
      -o json >"${flux_policy_handoff_state_file}" ||
      ! flux_policy_handoff_is_released; then
      return 1
    fi
  fi
  flux_policy_handoff_acquired=false
  flux_policy_handoff_owner=""
  flux_policy_handoff_uid=""
}

# Every Secret write is fenced by the resourceVersion observed after a
# foreground lease renewal. A delayed request from an expired lease holder can
# therefore never overwrite a newer transaction that has already updated the
# same Secret. Keep the credential payload in files so it never enters argv.
patch_secret_data_with_cas() {
  local namespace="$1"
  local name="$2"
  local data_key="$3"
  local payload_file="$4"
  local state_file="$5"
  local cas_patch_file="$6"
  local resource_version attempt patch_status=1

  for attempt in 1 2 3; do
    assert_sync_lease_held || return 1
    if ! kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace "${namespace}" \
      get secret "${name}" \
      -o json >"${state_file}"; then
      echo "::error::Could not inspect Secret ${namespace}/${name} for an atomic credential update."
      return 1
    fi
    resource_version="$(jq -er '
      .metadata.resourceVersion
      | select(type == "string" and length > 0)
    ' "${state_file}")" || {
      echo "::error::Secret ${namespace}/${name} has no valid resourceVersion; refusing a non-atomic credential update."
      return 1
    }
    jq -n \
      --arg resource_version "${resource_version}" \
      --arg data_path "/data/${data_key}" \
      --arg data_key "${data_key}" \
      --slurpfile payload "${payload_file}" '
      ($payload[0].data[$data_key] // null) as $value
      | if ($value | type) != "string" or ($value | length) == 0 then
          error("credential payload is missing its data key")
        else
          [
            {op: "test", path: "/metadata/resourceVersion", value: $resource_version},
            {op: "add", path: $data_path, value: $value}
          ]
        end
    ' >"${cas_patch_file}"

    # Renew again after the read/build window. If a stale request lands after
    # this point, the captured Secret resourceVersion rejects it; if it lands
    # first, the current holder retries and deterministically wins.
    assert_sync_lease_held || return 1
    if kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace "${namespace}" \
      patch secret "${name}" \
      --type=json \
      --patch-file="${cas_patch_file}"; then
      return 0
    else
      patch_status=$?
    fi
    assert_sync_lease_held || return 1
  done

  echo "::error::Could not atomically update Secret ${namespace}/${name} after concurrent writes."
  return "${patch_status}"
}

# Patch only the root Flux Secret payload, preserving KSail ownership metadata.
patch_root_secret() {
  patch_secret_data_with_cas \
    flux-system \
    ksail-registry-credentials \
    .dockerconfigjson \
    "${patch_file}" \
    "${root_secret_state_file}" \
    "${root_secret_cas_patch_file}"
}

patch_variables_base() {
  patch_secret_data_with_cas \
    flux-system \
    variables-base \
    ghcr_dockerconfigjson \
    "${variables_patch_file}" \
    "${variables_secret_state_file}" \
    "${variables_secret_cas_patch_file}"
}

acquire_sync_lease "${pull_revision}"

# A fresh DR cluster does not have variables-base or the ESO fan-out resources
# until its first Flux reconcile. In that case the current artifact creates the
# chain from the same SOPS value, so only the root bootstrap patch is needed.
if ! variables_base_name="$(kubectl \
  --context "${KUBE_CONTEXT}" \
  --namespace flux-system \
  get secret variables-base \
  --ignore-not-found \
  -o name)"; then
  echo "::error::Could not determine whether the GHCR fan-out exists; refusing to reconcile with an unverified tenant credential path."
  exit 1
fi
if [[ -z "${variables_base_name}" ]]; then
  if [[ "${allow_incomplete_fanout}" != "true" ]]; then
    echo "::error::The GHCR fan-out is not initialized; root Flux auth was not changed. Use --allow-incomplete-fanout only during the DR bootstrap, then run the full verifier after reconciliation."
    exit 1
  fi
  patch_root_secret
  echo "✅ Refreshed root Flux GHCR auth; the first reconcile will create the downstream fan-out."
  exit 0
fi

# Prepare the variables-base payload locally, but do not mutate its live Secret
# until normal mode has proved the complete fan-out exists. Otherwise a failed
# normal deploy could leave PushSecret free to propagate an unmerged credential
# even though root Flux auth stayed unchanged.
jq '{data: {ghcr_dockerconfigjson: .data[".dockerconfigjson"]}}' \
  "${patch_file}" \
  >"${variables_patch_file}"

# A partially-bootstrapped DR cluster can already have variables-base while ESO
# CRDs or individual fan-out objects do not exist yet. That state still needs
# root auth so Flux can fetch the artifact that completes the chain. Distinguish
# an absent API/resource from a failed lookup, and never force-sync a partial set.
if ! kubectl \
  --context "${KUBE_CONTEXT}" \
  --namespace flux-system \
  api-resources \
  --api-group=external-secrets.io \
  -o name \
  >"${fanout_api_resources}"; then
  echo "::error::Could not inspect the External Secrets API; refusing to change root Flux auth."
  exit 1
fi

fanout_complete=true
prepublish_fanout_namespaces=()
if ! grep -qx 'pushsecrets.external-secrets.io' "${fanout_api_resources}" ||
  ! grep -qx 'externalsecrets.external-secrets.io' "${fanout_api_resources}"; then
  fanout_complete=false
else
  if ! pushsecret_name="$(kubectl \
    --context "${KUBE_CONTEXT}" \
    --namespace flux-system \
    get pushsecret seed-ghcr \
    --ignore-not-found \
    -o name)"; then
    echo "::error::Could not determine whether PushSecret flux-system/seed-ghcr exists; refusing to change root Flux auth."
    exit 1
  fi
  if [[ -z "${pushsecret_name}" ]]; then
    fanout_complete=false
  fi

  for namespace in "${FANOUT_NAMESPACES[@]}"; do
    if ! externalsecret_name="$(kubectl \
      --context "${KUBE_CONTEXT}" \
      --namespace "${namespace}" \
      get externalsecret ghcr-auth \
      --ignore-not-found \
      -o name)"; then
      echo "::error::Could not determine whether ExternalSecret ${namespace}/ghcr-auth exists; refusing to change root Flux auth."
      exit 1
    fi
    if [[ -z "${externalsecret_name}" ]]; then
      # A new consumer cannot have its ExternalSecret until Flux is allowed to
      # publish and reconcile the candidate that introduces it. Only the
      # pre-publish staging invocation may omit such a target. The
      # post-reconcile reassertion runs without this exemption and therefore
      # proves the newly-created fan-out before the deployment can succeed.
      #
      # Namespace absence alone cannot decide this. A candidate that fails
      # after its namespace is applied leaves that namespace behind, because
      # app namespaces carry prune: disabled and the rollback cannot remove
      # them. Keying the exemption on absence would then refuse every later
      # attempt, deadlocking the very change that introduces the consumer.
      # Defer while the namespace is absent or still runs no active workload:
      # neither state has a consumer whose pull credential this staging step
      # could break. A missing object in a namespace that already runs an
      # active workload is always an incomplete fan-out.
      #
      # The probe asks for Running Pods and then excludes terminating objects.
      # A candidate that failed before its ExternalSecret existed can leave a
      # Pod that never pulled its image, while a rolled-back candidate can
      # leave a terminating Pod whose last phase is still Running. Counting
      # either as active would deny the exemption on every retry, recreating
      # the deadlock this exemption exists to prevent.
      if [[ -n "${record_runtime_proof_path}" ]]; then
        if ! namespace_name="$(kubectl \
          --context "${KUBE_CONTEXT}" \
          get namespace "${namespace}" \
          --ignore-not-found \
          -o name)"; then
          echo "::error::Could not determine whether namespace ${namespace} exists; refusing to change root Flux auth."
          exit 1
        fi
        namespace_has_active_workload=false
        if [[ -n "${namespace_name}" ]]; then
          if ! namespace_has_active_workload="$(
            kubectl \
              --context "${KUBE_CONTEXT}" \
              --namespace "${namespace}" \
              get pods \
              --field-selector=status.phase=Running \
              -o json |
              jq -er '
                if (.items | type) != "array" or any(.items[];
                  type != "object"
                  or (.metadata | type) != "object"
                  or (.status | type) != "object"
                  or (.status.phase | type) != "string"
                  or ((.metadata.deletionTimestamp | type) != "null"
                    and (.metadata.deletionTimestamp | type) != "string")
                ) then
                  error("malformed Pod inventory")
                elif any(.items[];
                  .status.phase == "Running"
                  and .metadata.deletionTimestamp == null
                ) then
                  "true"
                else
                  "false"
                end
              '
          )"; then
            echo "::error::Could not determine whether namespace ${namespace} runs an active workload; refusing to change root Flux auth."
            exit 1
          fi
        fi
        if [[ -z "${namespace_name}" || "${namespace_has_active_workload}" != "true" ]]; then
          echo "::notice::Deferring new GHCR fan-out target ${namespace}/ghcr-auth until the candidate reconciles it; the post-reconcile reassertion remains mandatory."
          continue
        fi
      fi
      fanout_complete=false
      continue
    fi
    prepublish_fanout_namespaces+=("${namespace}")
  done
fi

if [[ "${fanout_complete}" != "true" ]]; then
  if [[ "${allow_incomplete_fanout}" != "true" ]]; then
    echo "::error::The GHCR fan-out is incomplete; root Flux auth was not changed. Use --allow-incomplete-fanout only during the DR bootstrap, then run the full verifier after reconciliation."
    exit 1
  fi
  patch_root_secret
  patch_variables_base
  patch_root_secret
  echo "✅ Staged the Git/SOPS credential and refreshed root Flux auth; the first reconcile will complete the missing downstream fan-out."
  exit 0
fi

# Existing clusters update and verify the whole SOPS -> variables-base ->
# PushSecret -> OpenBao -> ExternalSecret chain before the first Talos drain.
# Root Flux auth remains last so any failed node proof leaves it unchanged.
pause_flux_policy_parent
pause_flux_policy_handoff
# Apply every reviewed policy-only change even when all node credentials are
# already current and the convergence loop therefore needs no runtime probe.
# The per-probe reassertion remains necessary because a long node roll can
# overlap reconciliation of the still-published predecessor artifact.
stage_image_verification_webhook_budget
stage_fanout_before_talos \
  "${pull_revision}" \
  "${KSAIL_OPERATOR_IMAGE}" \
  "${talos_stage_result_file}" \
  "${prepublish_fanout_namespaces[@]}"
resume_flux_policy_handoff
resume_flux_policy_parent

echo "✅ Synchronised every existing consumer and refreshed root Flux GHCR auth from Git/SOPS."
