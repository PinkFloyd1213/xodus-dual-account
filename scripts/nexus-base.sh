#!/usr/bin/env bash
# Rebuild a branch equal to the backend Xodus Nexus builds: the commit pinned in
# assets/backend-source.lock.json plus every listed patch, in order, applied the
# way Nexus applies them (git apply --check, then git apply). One commit per
# patch. Never touches the Nexus checkout.
# Usage: scripts/nexus-base.sh <xodus-nexus checkout> [branch, default nexus-base]
set -euo pipefail
nexus=$(cd "$1" && pwd)
branch=${2:-nexus-base}
lock="$nexus/assets/backend-source.lock.json"
[ -z "$(git status --porcelain)" ] || { echo "Working tree is not clean" >&2; exit 1; }
read -r commit cargo_sha < <(python3 -I -c 'import json,sys; l=json.load(open(sys.argv[1])); print(l["commit"], l["cargoLockSha256"])' "$lock")
git fetch -q upstream
git switch -q -c "$branch" "$commit"
[ "$(sha256sum Cargo.lock | cut -d' ' -f1)" = "$cargo_sha" ] || { echo "Cargo.lock does not match the lock" >&2; exit 1; }
python3 -I -c 'import json,sys
for p in json.load(open(sys.argv[1]))["patches"]: print(p["file"], p["sha256"])' "$lock" |
while read -r file sha; do
    [ "$(sha256sum "$nexus/assets/$file" | cut -d' ' -f1)" = "$sha" ] || { echo "Checksum mismatch: $file" >&2; exit 1; }
    git apply --check "$nexus/assets/$file" || { echo "Does not apply: $file" >&2; exit 1; }
    git apply "$nexus/assets/$file"
    git add -A
    git commit -q -m "${file%.patch}"
    echo "applied $file"
done
echo "Rust toolchain required by the lock: $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["rust"])' "$lock")"
