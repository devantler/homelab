#!/bin/bash

pushd $(dirname "$0") >/dev/null

echo "🔥 Destroy Sandbox"
talosctl cluster destroy --name homelab-sandbox
