#!/usr/bin/env bash
set -euo pipefail

# Install talosctl and verify the downloaded bytes before running it with
# production credentials.
#
# Every caller installs this binary with sudo and then points it at a live
# cluster, so the download is a privileged one. The version pins the URL, not
# what that URL serves.
#
# The version and the digest are pinned HERE, on adjacent lines, because they
# have to move together. Renovate can bump the version from its datasource but
# cannot know the new digest, so a bump that touches only the line below leaves
# the pair inconsistent. That failure is caught at install time and reported
# with the digest to write, rather than installing unverified bytes.
#
# Keep the version in step with spec.cluster.talos.version in ksail.prod.yaml —
# the Talos version the prod cluster runs (ksail's node image pin, see ksail
# DefaultTalosImage). A client older than the cluster can start failing before it
# inspects a single node, which reads as a fleet-wide fault rather than a stale
# pin.
# renovate: datasource=github-releases depName=siderolabs/talos extractVersion=^v(?<version>.+)$
TALOS_VERSION="1.14.0"
# SHA-256 of talosctl-linux-amd64 for the TALOS_VERSION above, from that
# release's sha256sum.txt. UPDATE BOTH TOGETHER.
TALOSCTL_SHA256="2c147c4a99d124c95bd5c190fe054e0b3c93495f2243fd652ebd423adb8377c7"

asset_name="talosctl-linux-amd64"
release_base="https://github.com/siderolabs/talos/releases/download/v${TALOS_VERSION}"
# mktemp, not a fixed name: the fallback below is a world-writable directory, so
# a predictable path lets another user pre-create the target as a symlink and
# have curl write through it — and it is this file that sudo install then reads.
target=$(mktemp "${RUNNER_TEMP:-/tmp}/talosctl.XXXXXX")
trap 'rm -f "${target}"' EXIT

curl -fsSL "${release_base}/${asset_name}" -o "${target}"

actual_digest=$(sha256sum "${target}" | cut -d' ' -f1)

if [ "${actual_digest}" != "${TALOSCTL_SHA256}" ]; then
  # Two very different faults land here, and the operator response differs, so
  # name which one it is rather than printing a bare mismatch. The published
  # manifest is consulted ONLY to explain the failure — the pin above is what
  # authorises the install, so an unreachable manifest still fails closed.
  published_digest=$(
    curl -fsSL "${release_base}/sha256sum.txt" 2>/dev/null |
      awk -v asset="${asset_name}" '$2 == asset {print $1}'
  ) || published_digest=''

  if [ -z "${published_digest}" ]; then
    # Say so rather than implying the manifest disagreed — it was never read, so
    # which of the two faults this is remains unknown.
    echo "::error::talosctl digest mismatch for v${TALOS_VERSION}: expected ${TALOSCTL_SHA256}, got ${actual_digest}. This release's published sha256sum.txt could not be read, so whether the pin is stale or the bytes are wrong is undetermined. Refusing to install unverified bytes."
  elif [ "${published_digest}" = "${actual_digest}" ]; then
    echo "::error::the pinned talosctl digest is stale for v${TALOS_VERSION} — the served bytes match this release's published sha256sum.txt, so the version was bumped without its digest. Set TALOSCTL_SHA256 to ${actual_digest} in .github/scripts/setup-talosctl.sh"
  else
    echo "::error::talosctl digest mismatch for v${TALOS_VERSION}: expected ${TALOSCTL_SHA256}, got ${actual_digest} — the served bytes match neither the pin nor this release's published sha256sum.txt (${published_digest}). Refusing to install unverified bytes."
  fi
  exit 1
fi

sudo install "${target}" /usr/local/bin/talosctl
talosctl version --client
