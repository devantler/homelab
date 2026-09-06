#!/usr/bin/env bash
# Emit the shared policy-engine pin without changing another step's environment.
set -euo pipefail

# renovate: datasource=github-releases depName=kyverno/kyverno extractVersion=^v(?<version>.+)$
KYVERNO_VERSION="1.19.0"

: "${GITHUB_OUTPUT:?GitHub Actions output file required}"
printf 'release=v%s\n' "$KYVERNO_VERSION" >> "$GITHUB_OUTPUT"
