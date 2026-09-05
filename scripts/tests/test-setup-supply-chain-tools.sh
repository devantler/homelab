#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
installer="${repo_root}/.github/scripts/setup-supply-chain-tools.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[[ -f "${installer}" ]] || fail 'the digest-verified supply-chain installer is missing'

test_root=$(mktemp -d "${TMPDIR:-/tmp}/test-supply-chain-tools.XXXXXX")
trap 'rm -rf "${test_root}"' EXIT
mkdir -p "${test_root}/bin" "${test_root}/fixtures" "${test_root}/runner" "${test_root}/installed"
export TEST_ROOT="${test_root}"

# Execute the installed fixture programs, so success proves which bytes ran.
for tool in cosign syft; do
  cat >"${test_root}/fixtures/${tool}" <<FIXTURE_TOOL
#!/usr/bin/env bash
printf '${tool} %s\\n' "\$*" >>"\${TEST_ROOT}/executed"
FIXTURE_TOOL
done
tar -czf "${test_root}/fixtures/syft.tar.gz" -C "${test_root}/fixtures" syft
cosign_sha=$(sha256sum "${test_root}/fixtures/cosign" | cut -d' ' -f1)
syft_sha=$(sha256sum "${test_root}/fixtures/syft.tar.gz" | cut -d' ' -f1)

cat >"${test_root}/bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
url='' output=''
while (( $# )); do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --proto|--proto-redir) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "${url}" >>"${TEST_ROOT}/downloads"
case "${url}" in
  https://github.com/sigstore/cosign/releases/download/v9.9.9/cosign-linux-amd64)
    [[ ${FAIL_DOWNLOAD:-} != cosign ]] || exit 22
    cp "${TEST_ROOT}/fixtures/cosign" "${output}" ;;
  https://github.com/anchore/syft/releases/download/v9.9.9/syft_9.9.9_linux_amd64.tar.gz)
    [[ ${FAIL_DOWNLOAD:-} != syft ]] || exit 22
    cp "${TEST_ROOT}/fixtures/syft.tar.gz" "${output}" ;;
  *) printf 'unexpected download: %s\n' "${url}" >&2; exit 2 ;;
esac
FAKE_CURL
cat >"${test_root}/bin/sudo" <<'FAKE_SUDO'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == install ]] || exit 2
shift
[[ $1 == -m && $2 == 0755 ]] || exit 2
shift 2
source_path=$1 destination=$2
printf '%s\n' "${destination}" >>"${TEST_ROOT}/installs"
case "${destination}" in
  /usr/local/bin/cosign|/usr/local/bin/syft)
    install -m 0755 "${source_path}" "${TEST_ROOT}/installed/${destination##*/}" ;;
  *) exit 2 ;;
esac
FAKE_SUDO
cat >"${test_root}/bin/uname" <<'FAKE_UNAME'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' "${TEST_OS:-Linux}" ;;
  -m) printf '%s\n' "${TEST_ARCH:-x86_64}" ;;
  *) exit 2 ;;
esac
FAKE_UNAME
chmod +x "${test_root}/bin/"*

make_variant() {
  sed -e 's/^COSIGN_VERSION=.*/COSIGN_VERSION="9.9.9"/' \
    -e 's/^SYFT_VERSION=.*/SYFT_VERSION="9.9.9"/' \
    -e "s/^COSIGN_SHA256=.*/COSIGN_SHA256=\"$1\"/" \
    -e "s/^SYFT_SHA256=.*/SYFT_SHA256=\"$2\"/" \
    -e "s|/usr/local/bin/cosign version|${test_root}/installed/cosign version|" \
    -e "s|/usr/local/bin/syft version|${test_root}/installed/syft version|" \
    "${installer}" >"${test_root}/installer.sh"
  for assignment in 'COSIGN_VERSION="9.9.9"' 'SYFT_VERSION="9.9.9"' \
    "COSIGN_SHA256=\"$1\"" "SYFT_SHA256=\"$2\""; do
    grep -Fxq "${assignment}" "${test_root}/installer.sh" || fail "fixture did not substitute ${assignment}"
  done
}

run_installer() {
  rm -f "${test_root}/installs" "${test_root}/executed" "${test_root}/downloads" "${test_root}/github-path" "${test_root}/installed/"*
  status=0
  output=$(PATH="${test_root}/bin:${test_root}/installed:${PATH}" \
    RUNNER_TEMP="${test_root}/runner" GITHUB_PATH="${test_root}/github-path" \
    bash "${test_root}/installer.sh" 2>&1) || status=$?
  [[ -z $(find "${test_root}/runner" -mindepth 1 -print -quit) ]] || fail 'installer left temporary downloads behind'
}

assert_refused() {
  [[ ${status} != 0 ]] || fail "$1 was accepted"
  [[ ! -e ${test_root}/installs ]] || fail "$1 reached installation"
  [[ ! -e ${test_root}/executed ]] || fail "$1 executed a downloaded tool"
  [[ ${output} == *"$2"* ]] || fail "$1 failed for the wrong reason: ${output}"
}

make_variant "${cosign_sha}" "${syft_sha}"
run_installer
[[ ${status} == 0 ]] || fail "verified downloads failed: ${output}"
cmp "${test_root}/fixtures/cosign" "${test_root}/installed/cosign" || fail 'wrong cosign bytes installed'
cmp "${test_root}/fixtures/syft" "${test_root}/installed/syft" || fail 'wrong syft bytes installed'
grep -Fxq 'cosign version' "${test_root}/executed" || fail 'verified cosign never ran'
grep -Fxq 'syft version' "${test_root}/executed" || fail 'verified syft never ran'
if [[ ! -f ${test_root}/github-path ]] || ! grep -Fxq /usr/local/bin "${test_root}/github-path"; then
  fail 'subsequent workflow steps can select an unverified tool earlier on PATH'
fi

bad_sha=$(printf '%064d' 0)
make_variant "${bad_sha}" "${syft_sha}"
run_installer
assert_refused 'substituted cosign binary' 'cosign digest mismatch'
make_variant "${cosign_sha}" "${bad_sha}"
run_installer
assert_refused 'substituted syft archive' 'syft digest mismatch'

# No remote checksum may replace the reviewed pin, including after a version-only bump.
[[ $(wc -l <"${test_root}/downloads") -eq 2 ]] || fail 'installer fetched an unreviewed fallback digest'
make_variant "${cosign_sha}" "${syft_sha}"
for tool in cosign syft; do
  export FAIL_DOWNLOAD="${tool}"
  run_installer
  assert_refused "failed ${tool} download" ''
done
unset FAIL_DOWNLOAD

export TEST_ARCH=aarch64
run_installer
assert_refused 'unsupported architecture' 'Linux x86_64'
[[ ! -e ${test_root}/downloads ]] || fail 'unsupported architecture downloaded a binary'
unset TEST_ARCH

# An archive that passes its digest check must still contain an extractable
# syft binary. Neither a truncated archive nor a missing member may install cosign.
printf 'not an archive\n' >"${test_root}/fixtures/syft.tar.gz"
make_variant "${cosign_sha}" "$(sha256sum "${test_root}/fixtures/syft.tar.gz" | cut -d' ' -f1)"
run_installer
assert_refused 'invalid syft archive' ''
tar -czf "${test_root}/fixtures/syft.tar.gz" -C "${test_root}/fixtures" cosign
make_variant "${cosign_sha}" "$(sha256sum "${test_root}/fixtures/syft.tar.gz" | cut -d' ' -f1)"
run_installer
assert_refused 'archive without syft' ''

printf 'supply-chain tool installer tests passed\n'
