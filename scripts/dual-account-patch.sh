#!/usr/bin/env bash
# Write xodus-dual-account.patch (source changes of dual-account against
# nexus-base, crates/ only) and print the Nexus backend lock entry for it.
# Usage: scripts/dual-account-patch.sh [output, default xodus-dual-account.patch]
set -euo pipefail
out=${1:-xodus-dual-account.patch}
git diff --no-color --full-index nexus-base..dual-account -- crates > "$out"
sha=$(sha256sum "$out" | cut -d' ' -f1)
printf '{ "file": "xodus-dual-account.patch", "sha256": "%s" }\n' "$sha"
