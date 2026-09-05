#!/usr/bin/env bash
set -euo pipefail

# These pins authorize the bytes used to sign production artifacts and generate
# their SBOMs. Update each version AND its SHA-256 together in the same PR,
# using the named release's published checksums. A version-only Renovate bump
# fails closed; a downloaded checksum never replaces a reviewed local pin.
# renovate: datasource=github-releases depName=sigstore/cosign extractVersion=^v(?<version>.+)$
COSIGN_VERSION="3.1.3"
# cosign_checksums.txt: cosign-linux-amd64
COSIGN_SHA256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
# renovate: datasource=github-releases depName=anchore/syft extractVersion=^v(?<version>.+)$
SYFT_VERSION="1.51.1"
# syft_1.51.1_checksums.txt: syft_1.51.1_linux_amd64.tar.gz
SYFT_SHA256="8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo '::error::Supply-chain tool pins support Linux x86_64 runners. Add reviewed release digests before using another platform.' >&2
  exit 1
fi
: "${GITHUB_PATH:?GITHUB_PATH must name the runner path file}"

download_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/supply-chain-tools.XXXXXX")
trap 'rm -rf "${download_dir}"' EXIT

verify_digest() {
  local tool=$1 expected=$2 file=$3
  if ! printf '%s  %s\n' "${expected}" "${file}" | sha256sum -c - >/dev/null; then
    echo "::error::${tool} digest mismatch. Refusing to install or execute downloaded tools. Review the release checksums and update its version and SHA-256 together in .github/scripts/setup-supply-chain-tools.sh." >&2
    exit 1
  fi
}

curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
  --output "${download_dir}/cosign"
verify_digest cosign "${COSIGN_SHA256}" "${download_dir}/cosign"

curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
  --output "${download_dir}/syft.tar.gz"
verify_digest syft "${SYFT_SHA256}" "${download_dir}/syft.tar.gz"

# Verify both downloads before extracting or installing either tool. Extract
# only the executable into the private directory, never the whole archive.
tar -xzf "${download_dir}/syft.tar.gz" -C "${download_dir}" syft
sudo install -m 0755 "${download_dir}/cosign" /usr/local/bin/cosign
sudo install -m 0755 "${download_dir}/syft" /usr/local/bin/syft
printf '%s\n' /usr/local/bin >>"${GITHUB_PATH}"
/usr/local/bin/cosign version
/usr/local/bin/syft version
