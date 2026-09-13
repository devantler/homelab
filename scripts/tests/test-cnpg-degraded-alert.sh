#!/usr/bin/env bash

# Contract for the cnpg-degraded-alert CronJob (#2787).
#
# This CronJob is the ONLY signal for a CloudNativePG cluster that is degraded
# without crashlooping — either a pod that stays Running but never Ready, or a
# Ready database whose continuous WAL archive is failing. It had no test at
# all, so every behaviour its own manifest comment calls load-bearing was
# pinned by nothing.
#
# Two classes are asserted here, and they fail in opposite directions:
#
#   SILENT-ZERO. A broken check and a healthy fleet both print "none degraded".
#   The script guards that with an HTTP-code check, a response-shape check and a
#   deliberate absence of `|| true` on the delivery. Each of those is a line
#   someone could remove while every schema validation stayed green, so each is
#   pinned by a scenario that removes it and expects the run to FAIL.
#
#   CREDENTIAL EXPOSURE. checkov CKV_K8S_35 flags the webhook arriving as an
#   environment variable. The remediation is only real if the value reaches the
#   script from a mounted file AND does not reappear in curl's argv, so both are
#   asserted — a fix that moves the secret from `/proc/self/environ` to
#   `/proc/<pid>/cmdline` has relocated the exposure, not removed it.
#
# The script is extracted from the rendered manifest rather than copied here, so
# this cannot drift into testing a stale transcription of it.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly root_dir
readonly manifest="${root_dir}/k8s/bases/infrastructure/controllers/coroot/cron-job-cnpg-degraded-alert.yaml"
readonly ci_workflow="${root_dir}/.github/workflows/ci.yaml"

# Deliberately NOT a hooks.slack.com-shaped literal. GitHub push protection
# matches that shape and blocks the push on a synthetic value just as it would
# on a live one — correctly, since it cannot tell them apart. The script only
# special-cases the example.invalid placeholder, so any other host exercises the
# delivery path exactly the same way. `.invalid` is RFC 2606 reserved, so this
# can never resolve even if a stub were missed.
readonly REAL_WEBHOOK='https://hooks.test.invalid/delivery-target'
readonly PLACEHOLDER_WEBHOOK='https://example.invalid/no-slack-configured'

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'ok — %s\n' "$1"
}

for tool in yq jq; do
  command -v "${tool}" >/dev/null 2>&1 || {
    printf '::error::%s is required to run this contract test.\n' "${tool}" >&2
    exit 64
  }
done
[ -f "${manifest}" ] || fail "manifest not found: ${manifest} (run from the repository root)"

# ---------------------------------------------------------------------------
# Structural assertions on the rendered container.
# ---------------------------------------------------------------------------

container_path='.spec.jobTemplate.spec.template.spec.containers[0]'
pod_path='.spec.jobTemplate.spec.template.spec'

env_block="$(yq eval "${container_path}.env" "${manifest}")"
script_body="$(yq eval "${container_path}.command[2]" "${manifest}")"
volumes="$(yq eval "${pod_path}.volumes" "${manifest}")"

[ -n "${script_body}" ] && [ "${script_body}" != "null" ] ||
  fail "could not extract the container script from ${manifest}"

# CKV_K8S_35. `secretKeyRef` anywhere in this container's env is the finding.
if grep -q 'secretKeyRef' <<<"${env_block}"; then
  fail "CKV_K8S_35: container env still carries a secretKeyRef; the webhook must arrive as a mounted file"
fi
pass "no secretKeyRef in the container environment"

# The secret has to actually reach the pod, or the check above is satisfied by
# simply deleting the credential. Assert the volume and its mount exist and name
# the same Secret the manifest's own secret-cnpg-degraded-alert.yaml creates.
grep -q 'cnpg-degraded-alert-webhook' <<<"${volumes}" ||
  fail "no volume sourced from the cnpg-degraded-alert-webhook Secret"
pass "webhook Secret is mounted as a volume"

webhook_mount_path="$(yq eval \
  "${container_path}.volumeMounts[] | select(.name == \"webhook\") | .mountPath" "${manifest}")"
[ -n "${webhook_mount_path}" ] && [ "${webhook_mount_path}" != "null" ] ||
  fail "the webhook volume is not mounted into the container"
grep -q 'readOnly: true' <<<"$(yq eval \
  "${container_path}.volumeMounts[] | select(.name == \"webhook\")" "${manifest}")" ||
  fail "the webhook mount must be readOnly"
pass "webhook mount is present and readOnly at ${webhook_mount_path}"

# A mounted credential that every process in the pod can read is only half the
# control. defaultMode narrows it to root and the pod's fsGroup.
#
# These two assertions are ONE invariant and must stay together: kubelet owns
# secret-volume files root:fsGroup, never uid:fsGroup, so the mode has to carry
# the GROUP bit and fsGroup has to name the container's group. Pinning the mode
# alone is what let an owner-only 0400 ship against a non-root container with no
# fsGroup -- a combination that reads as maximally strict and actually denies the
# container its own credential, failing the CronJob before its first API call.
default_mode="$(yq eval \
  "${pod_path}.volumes[] | select(.name == \"webhook\") | .secret.defaultMode" "${manifest}")"
[ "${default_mode}" = "288" ] ||
  fail "expected the webhook volume defaultMode 0440 (288 decimal), got: ${default_mode}"

fs_group="$(yq eval "${pod_path}.securityContext.fsGroup" "${manifest}")"
run_as_user="$(yq eval "${pod_path}.securityContext.runAsUser" "${manifest}")"
[ "${fs_group}" = "${run_as_user}" ] ||
  fail "fsGroup (${fs_group}) must match runAsUser (${run_as_user}), or the mounted webhook is unreadable"
pass "webhook volume is mounted 0440 and readable by fsGroup ${fs_group}"

# The relocation trap: the URL must not be handed to curl as an argument, or it
# is simply exposed through /proc/<pid>/cmdline instead of /proc/self/environ.
#
# Checked as two LINE-anchored patterns rather than one expression spanning the
# whole invocation. grep is line-oriented, and this curl call is written across
# five continuation lines, so a `curl.*"$WEBHOOK_URL"` pattern matches nothing
# whatever the script says — it passes identically on a fixed and a reverted
# manifest. That vacuous form was caught by ablating this very assertion.
if grep -Eq '^[[:space:]]*"\$\{?WEBHOOK_URL\}?"[[:space:]]*$' <<<"${script_body}"; then
  fail "the webhook URL is a bare curl continuation argument; it would appear in /proc/<pid>/cmdline"
fi
if grep -Eq 'curl.*"\$\{?WEBHOOK_URL\}?"' <<<"${script_body}"; then
  fail "the webhook URL is passed to curl as an argument; it would appear in /proc/<pid>/cmdline"
fi
grep -Fq -- '--config -' <<<"${script_body}" ||
  fail "the delivery does not read its URL from a stdin config; the URL must not travel in argv"
pass "webhook URL is never passed to curl in argv"

# ---------------------------------------------------------------------------
# Behavioural scenarios. The extracted script runs against a stubbed kube API
# and a stubbed curl, so what is asserted is what the container would really do.
# ---------------------------------------------------------------------------

# Anchored under /tmp deliberately, rather than a bare `mktemp -d`.
#
# The patched script below rewrites `/tmp/` to point inside this sandbox, so the
# sandbox's OWN path has to be able to collide with that rule — otherwise the
# collision, and the guard that detects it, are both inert. A bare `mktemp -d`
# returns /var/folders/… on macOS and /tmp/… on Linux, so the ordering bug this
# guards against passed every local run and failed only in CI. Anchoring here
# makes the local run reproduce the CI condition.
work_root="$(mktemp -d /tmp/tmp.XXXXXXXXXX)"
trap 'rm -rf "${work_root}"' EXIT

# Build one scenario sandbox: a fake serviceaccount dir, a webhook file, a
# stubbed curl that serves a canned kube API response and records deliveries.
#
# The stub distinguishes the two curl calls the script makes the same way curl
# itself does — the API read asks for an output file with -o, the delivery does
# not — so neither has to be matched on its URL.
setup_scenario() {
  local name="$1" api_code="$2" api_body="$3" webhook="$4"
  local dir="${work_root}/${name}"

  mkdir -p "${dir}/bin" "${dir}/sa" "${dir}/webhook" "${dir}/tmp"
  printf 'fake-ca' >"${dir}/sa/ca.crt"
  printf 'fake-token' >"${dir}/sa/token"
  printf '%s' "${webhook}" >"${dir}/webhook/url"
  printf '%s' "${api_body}" >"${dir}/api-body.json"
  printf '%s' "${api_code}" >"${dir}/api-code"

  cat >"${dir}/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Stub curl. Distinguishes the kube API read (-o <file>) from the Slack
# delivery, records every invocation, and never touches the network.
set -uo pipefail
dir="${SCENARIO_DIR}"
printf '%s\n' "$*" >>"${dir}/curl-argv.log"

out_file=""
prev=""
for arg in "$@"; do
  [ "${prev}" = "-o" ] && out_file="${arg}"
  prev="${arg}"
done

if [ -n "${out_file}" ]; then
  cat "${dir}/api-body.json" >"${out_file}"
  printf '%s' "$(cat "${dir}/api-code")"
  code="$(cat "${dir}/api-code")"
  # -f is not in play for the API read; the script inspects the printed code.
  exit 0
fi

# Delivery. Record the config curl was handed on stdin plus the payload, so the
# test can assert the URL travelled out-of-band and the body is well-formed.
cat >>"${dir}/curl-stdin.log"
for arg in "$@"; do
  case "${arg}" in
    @*) cp "${arg#@}" "${dir}/delivered-payload.json" 2>/dev/null || true ;;
  esac
done
printf 'delivered\n' >>"${dir}/deliveries.log"
exit "${STUB_DELIVERY_EXIT:-0}"
STUB
  chmod +x "${dir}/bin/curl"
  printf '%s' "${dir}"
}

# Run the extracted script inside a scenario sandbox.
#
# The script hard-codes the in-cluster serviceaccount path and the kube API
# host, so both are redirected here rather than edited into a copy: a test that
# rewrites the script is no longer testing the script.
run_scenario() {
  local dir="$1" grace="${2:-900}"
  local patched="${dir}/script.sh"

  {
    printf '%s\n' 'set -eu'
    printf 'GRACE_SECONDS=%s\n' "${grace}"
    printf 'export SCENARIO_DIR=%q\n' "${dir}"
    # Redirect the two in-cluster absolute paths at the top, so the body below
    # is byte-identical to what the container runs.
    printf 'SA_OVERRIDE=%q\n' "${dir}/sa"
    printf 'WEBHOOK_OVERRIDE=%q\n' "${dir}/webhook/url"
    # ORDER IS LOAD-BEARING: the `/tmp/` rewrite must run FIRST.
    #
    # `${dir}` is itself under `/tmp/` (mktemp -d), so running it last would
    # re-match the sandbox path the webhook rule had just introduced and double
    # it: `/etc/cnpg-degraded-alert/url` -> `${dir}/webhook/url` -> then the
    # leading `/tmp/` of THAT becomes `${dir}/tmp/`, yielding
    # `${dir}/tmp/${dir#/}/webhook/url`. Reversing the order leaves the webhook
    # rule's output untouched because `/tmp/` has already been rewritten.
    #
    # This reproduces only where mktemp returns a path under /tmp — Linux CI,
    # not macOS, where it returns /var/folders/… — so it passes locally and
    # fails in CI.
    # shellcheck disable=SC2016  # `$SA_OVERRIDE` is emitted INTO the patched script; the shell here must not expand it.
    printf '%s\n' "${script_body}" |
      sed -e 's#^\( *\)SA=/var/run/secrets/kubernetes.io/serviceaccount$#\1SA="$SA_OVERRIDE"#' \
        -e 's#/tmp/#'"${dir}"'/tmp/#g' \
        -e 's#/etc/cnpg-degraded-alert/url#'"${dir}"'/webhook/url#g'
  } >"${patched}"

  # Prove the redirection actually applied. Without this the sed could silently
  # match nothing and every scenario would exercise real in-cluster paths,
  # failing identically for the wrong reason.
  # shellcheck disable=SC2016  # matching the LITERAL `$SA_OVERRIDE` the sed above wrote into the file.
  grep -q 'SA="\$SA_OVERRIDE"' "${patched}" ||
    fail "serviceaccount path redirection did not apply; the script's SA line changed shape"
  grep -q "${dir}/webhook/url" "${patched}" ||
    fail "webhook path redirection did not apply; the script no longer reads /etc/cnpg-degraded-alert/url"
  # The check above is a SUBSTRING match, so the doubled path `${dir}/tmp/${dir#/}/webhook/url`
  # satisfies it — that is exactly how the ordering bug reached CI. Assert the
  # sandbox root appears at most once per line to catch any future rule that
  # rewrites another rule's output.
  ! grep -q -- "${dir}.*${dir}" "${patched}" ||
    fail "a redirection rewrote another rule's output; the sandbox path is doubled in the patched script"

  (
    cd "${dir}"
    PATH="${dir}/bin:${PATH}" SCENARIO_DIR="${dir}" bash "${patched}" >"${dir}/stdout.log" 2>"${dir}/stderr.log"
  )
}

deliveries() {
  local dir="$1"
  [ -f "${dir}/deliveries.log" ] && wc -l <"${dir}/deliveries.log" | tr -d ' ' || printf '0'
}

# A cluster degraded well past any grace period.
old_stamp="$(date -u -r 0 +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @0 +%Y-%m-%dT%H:%M:%SZ)"
degraded_body="$(
  jq -n --arg ts "${old_stamp}" '{
    items: [{
      metadata: { namespace: "umami", name: "umami-db" },
      spec: { instances: 3 },
      status: {
        readyInstances: 2,
        conditions: [{ type: "Ready", status: "True", lastTransitionTime: $ts }]
      }
    }]
  }'
)"
readonly degraded_body
healthy_body="$(
  jq -n --arg ts "${old_stamp}" '{
    items: [{
      metadata: { namespace: "umami", name: "umami-db" },
      spec: { instances: 3 },
      status: {
        readyInstances: 3,
        conditions: [{ type: "Ready", status: "True", lastTransitionTime: $ts }]
      }
    }]
  }'
)"
readonly healthy_body
archive_failed_body="$(
  jq -n --arg ts "${old_stamp}" '{
    items: [{
      metadata: { namespace: "wedding-app", name: "wedding-db", creationTimestamp: $ts },
      spec: {
        instances: 3,
        plugins: [{
          name: "barman-cloud.cloudnative-pg.io",
          isWALArchiver: true
        }]
      },
      status: {
        readyInstances: 3,
        conditions: [
          { type: "Ready", status: "True", lastTransitionTime: $ts },
          { type: "ContinuousArchiving", status: "False", lastTransitionTime: $ts }
        ]
      }
    }]
  }'
)"
readonly archive_failed_body
archive_missing_body="$(
  jq '.items[0].status.conditions |= map(select(.type != "ContinuousArchiving"))' \
    <<<"${archive_failed_body}"
)"
readonly archive_missing_body
archive_disabled_body="$(
  jq '.items[0].spec.plugins[0].enabled = false' <<<"${archive_failed_body}"
)"
readonly archive_disabled_body

# Scenario 1 — degraded cluster, real webhook: exactly one delivery, and the URL
# reaches curl through its stdin config rather than its argv.
dir="$(setup_scenario delivers 200 "${degraded_body}" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'delivers': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "1" ] ||
  fail "scenario 'delivers': expected exactly 1 delivery, got $(deliveries "${dir}")"
grep -Fq "${REAL_WEBHOOK}" "${dir}/curl-stdin.log" ||
  fail "scenario 'delivers': the webhook URL never reached curl's stdin config"
if grep -Fq "${REAL_WEBHOOK}" "${dir}/curl-argv.log"; then
  fail "scenario 'delivers': the webhook URL appeared in curl's argv"
fi
jq -e '.text | test("umami/umami-db")' "${dir}/delivered-payload.json" >/dev/null ||
  fail "scenario 'delivers': payload does not name the degraded cluster"
jq -e '.text | test("2/3 instances ready")' "${dir}/delivered-payload.json" >/dev/null ||
  fail "scenario 'delivers': payload does not carry the ready/desired counts"
pass "a degraded cluster delivers exactly one alert, with the URL out of argv"

# Scenario 1b — INCIDENT REGRESSION. A database can be fully Ready while every
# WAL upload is rejected. That happened to wedding-db after its 2026-09-09
# replacement reused the predecessor's Barman server name: all three instances
# were healthy, so the replica-only check stayed silent for roughly three days.
dir="$(setup_scenario archive_failed 200 "${archive_failed_body}" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'archive_failed': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "1" ] ||
  fail "scenario 'archive_failed': expected exactly 1 delivery, got $(deliveries "${dir}")"
jq -e '.text | test("wedding-app/wedding-db")' "${dir}/delivered-payload.json" >/dev/null ||
  fail "scenario 'archive_failed': payload does not name the affected cluster"
jq -e '.text | test("WAL archiving") and test("ContinuousArchiving=False")' \
  "${dir}/delivered-payload.json" >/dev/null ||
  fail "scenario 'archive_failed': payload does not identify the failed archival condition"
pass "a Ready cluster with sustained WAL archival failure delivers an alert"

# Scenario 1c — a configured archiver that never publishes its condition must
# not disappear from monitoring. Use Cluster creation as the fallback grace
# clock, then report the missing condition as Unknown.
dir="$(setup_scenario archive_missing 200 "${archive_missing_body}" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'archive_missing': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "1" ] ||
  fail "scenario 'archive_missing': expected exactly 1 delivery, got $(deliveries "${dir}")"
jq -e '.text | test("ContinuousArchiving=Unknown")' "${dir}/delivered-payload.json" >/dev/null ||
  fail "scenario 'archive_missing': payload does not identify the missing archival condition"
pass "a configured archiver with no condition alerts after the grace period"

# Scenario 1d — an explicitly disabled plugin is retained configuration, not an
# active archiver. Its stale condition must not page until it is enabled again.
dir="$(setup_scenario archive_disabled 200 "${archive_disabled_body}" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'archive_disabled': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'archive_disabled': an explicitly disabled archiver must not alert"
pass "an explicitly disabled WAL archiver stays quiet"

# Scenario 2 — the reserved placeholder host stays inert, so local and CI runs
# are quiet by design without swallowing a real delivery failure.
dir="$(setup_scenario placeholder 200 "${degraded_body}" "${PLACEHOLDER_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'placeholder': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'placeholder': expected no delivery against example.invalid"
grep -q 'No Slack webhook configured' "${dir}/stdout.log" ||
  fail "scenario 'placeholder': the skip was not reported"
pass "the example.invalid placeholder stays inert"

# Scenario 3 — a healthy fleet is quiet, and says how many it checked.
dir="$(setup_scenario healthy 200 "${healthy_body}" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'healthy': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'healthy': a healthy fleet must not alert"
grep -q 'Checked 1 CNPG cluster' "${dir}/stdout.log" ||
  fail "scenario 'healthy': the checked count was not reported"
pass "a healthy fleet is quiet and reports what it checked"

# Scenario 4 — SILENT-ZERO. A 500 from the kube API must fail the Job, never
# read as "nothing degraded".
dir="$(setup_scenario api_error 500 '{}' "${REAL_WEBHOOK}")"
if run_scenario "${dir}"; then
  fail "scenario 'api_error': a 500 from the kube API was reported as success"
fi
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'api_error': delivered an alert despite a failed API read"
grep -q 'kube API returned HTTP 500' "${dir}/stderr.log" ||
  fail "scenario 'api_error': the failure was not reported to stderr"
pass "a failing kube API read fails the Job instead of reading as healthy"

# Scenario 5 — SILENT-ZERO, second shape. A 200 whose body is not the expected
# list shape must also fail rather than count zero items.
dir="$(setup_scenario bad_shape 200 '{"unexpected":true}' "${REAL_WEBHOOK}")"
if run_scenario "${dir}"; then
  fail "scenario 'bad_shape': an unparseable API response was reported as success"
fi
grep -q 'unexpected response shape' "${dir}/stderr.log" ||
  fail "scenario 'bad_shape': the shape guard did not report"
pass "an unexpected API response shape fails the Job"

# Scenario 5b — SILENT-ZERO, third shape. `has("items")` is satisfied by a
# non-array `items`, which then counts zero clusters and reports a malformed
# response as a healthy one. The guard must require the ARRAY, not the key.
dir="$(setup_scenario items_not_array 200 '{"items":{}}' "${REAL_WEBHOOK}")"
if run_scenario "${dir}"; then
  fail "scenario 'items_not_array': a non-array items was reported as success"
fi
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'items_not_array': delivered an alert on a malformed response"
grep -q 'unexpected response shape' "${dir}/stderr.log" ||
  fail "scenario 'items_not_array': the shape guard did not report"
pass "an items value that is not an array fails the Job"

# Scenario 5c — CURL CONFIG INJECTION. The URL is handed to curl as a config
# directive, where a newline begins a SECOND directive. A Secret carrying an LF
# could therefore append arbitrary curl configuration (`output = ...` and the
# rest) to a request this script believes it fully controls. The value must be
# rejected before the config is built, and nothing may be delivered.
injected="${REAL_WEBHOOK}
output = ${work_root}/injected-output"
dir="$(setup_scenario url_control_chars 200 '{"items":[]}' "${injected}")"
if run_scenario "${dir}"; then
  fail "scenario 'url_control_chars': an LF in the webhook URL was accepted"
fi
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'url_control_chars': delivered despite a malformed webhook URL"
[ ! -e "${work_root}/injected-output" ] ||
  fail "scenario 'url_control_chars': the injected curl directive took effect"
grep -q 'control characters' "${dir}/stderr.log" ||
  fail "scenario 'url_control_chars': the control-character guard did not report"
pass "a webhook URL carrying a control character fails before any delivery"

# Scenario 5d — PLAINTEXT DELIVERY. The webhook token travels in the URL path,
# and the allow-coroot network policy permits hooks.slack.com by PORT, not by
# scheme — so an `http://…:443` value would be delivered in the clear. The
# scheme is checked beside the control-character guard, before any delivery,
# and the refusal names the requirement. Same guard as the stranded-volume
# alert (#3560).
dir="$(setup_scenario plain_http 200 "${degraded_body}" 'http://hooks.test.invalid:443/delivery-target')"
if run_scenario "${dir}"; then
  fail "scenario 'plain_http': an http:// webhook URL was accepted"
fi
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'plain_http': delivered over plaintext"
grep -q 'must use https://' "${dir}/stderr.log" ||
  fail "scenario 'plain_http': the refusal does not name the https requirement"
pass "a non-https webhook URL fails before any delivery"

# Scenario 6 — a CRD-less cluster is a supported state, not a failure.
dir="$(setup_scenario no_crd 404 '{}' "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'no_crd': a 404 should exit 0"
[ "$(deliveries "${dir}")" = "0" ] || fail "scenario 'no_crd': alerted with no CNPG CRD installed"
pass "a cluster without the CNPG CRD exits cleanly"

# Scenario 7 — SILENT-ZERO, delivery end. A webhook POST that fails must fail
# the Job; recording a successful run having sent nothing is the whole failure
# this check exists to avoid.
dir="$(setup_scenario delivery_fails 200 "${degraded_body}" "${REAL_WEBHOOK}")"
if STUB_DELIVERY_EXIT=22 run_scenario "${dir}"; then
  fail "scenario 'delivery_fails': a failed webhook POST was reported as a successful run"
fi
pass "a failed webhook delivery fails the Job"

# Scenario 8 — a cluster degraded only INSIDE the grace period stays quiet, so
# a rolling restart or a scale-up does not page.
dir="$(setup_scenario within_grace 200 "$(
  jq -n --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
    items: [{
      metadata: { namespace: "umami", name: "umami-db" },
      spec: { instances: 3 },
      status: {
        readyInstances: 2,
        conditions: [{ type: "Ready", status: "True", lastTransitionTime: $ts }]
      }
    }]
  }'
)" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'within_grace': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'within_grace': alerted on a cluster still inside its grace period"
pass "a cluster still inside the grace period does not page"

# Scenario 8b — the archive condition gets its own grace clock. A new Cluster
# may report ContinuousArchiving=False while its sidecar starts; that ordinary
# transition must stay quiet even though every database instance is Ready.
dir="$(setup_scenario archive_within_grace 200 "$(
  jq --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '.items[0].metadata.creationTimestamp = $ts
     | (.items[0].status.conditions[] | select(.type == "ContinuousArchiving").lastTransitionTime) = $ts' \
    <<<"${archive_failed_body}"
)" "${REAL_WEBHOOK}")"
run_scenario "${dir}" || fail "scenario 'archive_within_grace': script exited non-zero: $(cat "${dir}/stderr.log")"
[ "$(deliveries "${dir}")" = "0" ] ||
  fail "scenario 'archive_within_grace': alerted on an archiver still inside its grace period"
pass "a WAL archiver still inside the grace period does not page"

# ---------------------------------------------------------------------------
# Wiring. A contract nothing runs protects nothing.
# ---------------------------------------------------------------------------

grep -Fq "scripts/tests/test-cnpg-degraded-alert.sh" "${ci_workflow}" ||
  fail "this test is not referenced from ${ci_workflow}"
grep -Fq "bash scripts/tests/test-cnpg-degraded-alert.sh" "${ci_workflow}" ||
  fail "this test is listed in the paths filter but never executed by a CI step"
pass "the contract is wired into CI and executed"

printf '\nAll cnpg-degraded-alert contract assertions passed.\n'
