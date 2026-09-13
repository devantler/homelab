#!/usr/bin/env bash
set -euo pipefail

# The real script pins one version and one digest, so its constants cannot match
# a fixture. Each case runs the SHIPPED logic with those two constants
# substituted, and asserts the substitution actually fired — a silently failed
# rewrite would otherwise leave every case exercising the production pin against
# a fixture and "passing" for the wrong reason.

repo_root=$(git rev-parse --show-toplevel)
script_under_test="${repo_root}/.github/scripts/setup-talosctl.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/test-setup-talosctl.XXXXXX")
trap 'rm -rf "${test_root}"' EXIT

fixture_dir="${test_root}/fixtures"
fake_bin="${test_root}/bin"
runner_temp="${test_root}/runner"
mkdir -p "${fixture_dir}" "${fake_bin}" "${runner_temp}"

test_version='9.9.9'

printf '#!/usr/bin/env bash\nexit 0\n' >"${fixture_dir}/talosctl"
served_digest=$(sha256sum "${fixture_dir}/talosctl" | cut -d' ' -f1)

# A digest that is syntactically valid and belongs to nothing.
absent_digest=$(printf '%064d' 0)

cat >"${fake_bin}/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
case "${url}" in
  */talosctl-linux-amd64)
    cp "${TEST_FIXTURE_DIR}/talosctl" "${output}"
    ;;
  */sha256sum.txt)
    if [ "${TEST_MANIFEST_REACHABLE}" != '1' ]; then
      exit 22
    fi
    if [ -n "${output}" ]; then
      cp "${TEST_FIXTURE_DIR}/sha256sum.txt" "${output}"
    else
      cat "${TEST_FIXTURE_DIR}/sha256sum.txt"
    fi
    ;;
  *)
    printf 'unexpected URL: %s\n' "${url}" >&2
    exit 2
    ;;
esac
FAKE_CURL

cat >"${fake_bin}/sudo" <<'FAKE_SUDO'
#!/usr/bin/env bash
set -euo pipefail
touch "${TEST_INSTALL_MARKER}"
FAKE_SUDO

cat >"${fake_bin}/talosctl" <<'FAKE_TALOSCTL'
#!/usr/bin/env bash
exit 0
FAKE_TALOSCTL

chmod +x "${fake_bin}/curl" "${fake_bin}/sudo" "${fake_bin}/talosctl"

# Build a copy of the shipped script with the two pinned constants replaced.
make_variant() {
  pinned_digest=$1
  variant="${test_root}/setup-talosctl-variant.sh"
  sed \
    -e "s|^TALOS_VERSION=.*|TALOS_VERSION=\"${test_version}\"|" \
    -e "s|^TALOSCTL_SHA256=.*|TALOSCTL_SHA256=\"${pinned_digest}\"|" \
    "${script_under_test}" >"${variant}"
  chmod +x "${variant}"
  # Assert the substitution fired in BOTH places, or every case below is vacuous.
  grep -qx "TALOS_VERSION=\"${test_version}\"" "${variant}" ||
    {
      printf 'version substitution did not fire\n' >&2
      exit 1
    }
  grep -qx "TALOSCTL_SHA256=\"${pinned_digest}\"" "${variant}" ||
    {
      printf 'digest substitution did not fire\n' >&2
      exit 1
    }
}

run_installer() {
  rm -f "${test_root}/installed"
  if output=$(
    cd "${repo_root}" &&
      PATH="${fake_bin}:${PATH}" \
        RUNNER_TEMP="${runner_temp}" \
        TEST_FIXTURE_DIR="${fixture_dir}" \
        TEST_INSTALL_MARKER="${test_root}/installed" \
        TEST_MANIFEST_REACHABLE="${manifest_reachable:-1}" \
        "${test_root}/setup-talosctl-variant.sh" 2>&1
  ); then
    status=0
  else
    status=$?
  fi
}

assert_installed() {
  if [ "${status}" -ne 0 ]; then
    printf 'expected install to succeed, got status %s:\n%s\n' "${status}" "${output}" >&2
    exit 1
  fi
  if [ ! -e "${test_root}/installed" ]; then
    printf 'expected the binary to be installed, but sudo install never ran\n' >&2
    exit 1
  fi
}

assert_rejected_before_install() {
  expected_output=$1
  if [ "${status}" -eq 0 ]; then
    printf 'expected setup-talosctl.sh to reject the download\n%s\n' "${output}" >&2
    exit 1
  fi
  # The exit status alone does not prove the guard held — assert the side effect.
  if [ -e "${test_root}/installed" ]; then
    printf 'setup-talosctl.sh installed the binary despite failing verification\n' >&2
    exit 1
  fi
  case "${output}" in
    *"${expected_output}"*) ;;
    *)
      printf 'unexpected failure output: %s\n' "${output}" >&2
      exit 1
      ;;
  esac
}

# --- Case 1: the served bytes match the pin -> installs.
printf '%s  talosctl-linux-amd64\n' "${served_digest}" >"${fixture_dir}/sha256sum.txt"
make_variant "${served_digest}"
run_installer
assert_installed

# --- Case 2: pin stale (the Renovate failure) -> names the digest to write.
# The served bytes match the release's published manifest; only the pin is behind.
printf '%s  talosctl-linux-amd64\n' "${served_digest}" >"${fixture_dir}/sha256sum.txt"
make_variant "${absent_digest}"
run_installer
assert_rejected_before_install "the pinned talosctl digest is stale for v${test_version}"
case "${output}" in
  *"${served_digest}"*) ;;
  *)
    printf 'stale-pin error did not name the digest to write: %s\n' "${output}" >&2
    exit 1
    ;;
esac

# --- Case 3: the bytes match neither the pin nor the manifest -> substitution.
printf '%s  talosctl-linux-amd64\n' "$(printf '%064d' 1)" >"${fixture_dir}/sha256sum.txt"
make_variant "${absent_digest}"
run_installer
assert_rejected_before_install 'match neither the pin nor'

# --- Case 4: manifest unreachable and pin mismatched -> still fails closed.
manifest_reachable=0
make_variant "${absent_digest}"
run_installer
assert_rejected_before_install 'could not be read, so whether the pin is stale or the bytes are wrong is undetermined'
manifest_reachable=1

# --- Case 5: every call site routes through the script, and none installs raw.
#
# Scoped to the "⚙️ Setup talosctl" STEP, not the whole file. A whole-file grep
# is vacuous in ci.yaml, which also names the installer in its path filter and
# in the step that runs this very suite — so reverting the real step to a raw
# download still matched, and the check passed over exactly the regression it
# exists to catch.
extract_setup_step() {
  awk '
    /^[[:space:]]*-[[:space:]]*name:[[:space:]]*⚙️ Setup talosctl[[:space:]]*$/ { in_step = 1; next }
    in_step && /^[[:space:]]*-[[:space:]]*name:/ { in_step = 0 }
    in_step { print }
  ' "$1"
}

# The two assertions answer DIFFERENT questions and both are needed.
#
#   1. Step-scoped: "the ⚙️ Setup talosctl step invokes the installer, and does
#      not download talosctl itself". Scoping is what makes this one real --
#      ci.yaml names the installer a second time in the step that lints it, so a
#      whole-file grep passed even with the real setup step deleted.
#   2. Whole-file: "no call site downloads talosctl directly, ANYWHERE". Scoping
#      this one narrows it: a raw install added as its OWN step, alongside an
#      untouched setup step, satisfies every step-scoped check -- and that is
#      precisely the shape this assertion exists to stop.
#
# Only `talosctl-linux-amd64` is checked whole-file. `curl` cannot be -- these
# workflows use it legitimately elsewhere -- so it stays inside the step, where
# any curl at all is wrong.
#
# Returns non-zero rather than exiting, so the fixtures below can assert that it
# actually fails when it should.
assert_callsite() {
  callsite_path="$1"
  callsite_label="$2"
  step=$(extract_setup_step "${callsite_path}")
  # Assert the extraction fired: an empty block would make the checks below
  # pass without reading anything.
  if [ -z "${step}" ]; then
    printf 'no "Setup talosctl" step found in %s\n' "${callsite_label}" >&2
    return 1
  fi
  case "${step}" in
    *".github/scripts/setup-talosctl.sh"*) ;;
    *)
      printf 'Setup talosctl step does not invoke the installer: %s\n' "${callsite_label}" >&2
      return 1
      ;;
  esac
  case "${step}" in
    *"curl"* | *"talosctl-linux-amd64"*)
      printf 'Setup talosctl step still downloads talosctl directly: %s\n' "${callsite_label}" >&2
      return 1
      ;;
  esac
  if grep -q 'talosctl-linux-amd64' "${callsite_path}"; then
    printf 'call site downloads talosctl directly outside its setup step: %s\n' "${callsite_label}" >&2
    return 1
  fi
}

for callsite in \
  .github/actions/deploy-prod/action.yml \
  .github/workflows/ci.yaml \
  .github/workflows/dr-rebuild.yaml \
  .github/workflows/probe-image-signature-enforcement.yaml \
  .github/workflows/validate-image-verifier-liveness.yaml; do
  assert_callsite "${repo_root}/${callsite}" "${callsite}" || exit 1
done

# --- Case 7: the whole-file assertion, exercised against fixtures so it is
# pinned by something that can actually fail. A raw install as its OWN step
# leaves every step-scoped check satisfied.
callsite_fixture="${test_root}/callsite.yaml"

cat >"${callsite_fixture}" <<'FIXTURE'
name: fixture
jobs:
  build:
    steps:
      - name: ⚙️ Setup talosctl
        run: |
          .github/scripts/setup-talosctl.sh
      - name: 🚀 Do the thing
        run: |
          talosctl version --client
FIXTURE
if ! assert_callsite "${callsite_fixture}" 'fixture(clean)'; then
  printf 'a clean call-site fixture must pass\n' >&2
  exit 1
fi

cat >"${callsite_fixture}" <<'FIXTURE'
name: fixture
jobs:
  build:
    steps:
      - name: ⚙️ Setup talosctl
        run: |
          .github/scripts/setup-talosctl.sh
      - name: 😈 Smuggled raw install
        run: |
          curl -fsSL https://example.invalid/talosctl-linux-amd64 -o /tmp/talosctl
          sudo install /tmp/talosctl /usr/local/bin/talosctl
FIXTURE
if assert_callsite "${callsite_fixture}" 'fixture(smuggled)' 2>/dev/null; then
  printf 'a raw talosctl install in a NON-setup step must be rejected\n' >&2
  exit 1
fi

printf 'setup-talosctl verification tests passed\n'
