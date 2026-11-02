#!/usr/bin/env bash
# Move nexus-base to the backend recipe pinned by a Nexus checkout, as ONE new
# commit on top of nexus-base (no history rewrite): the commit's tree is the
# pinned Xodus commit with every listed patch applied, the dual-account patch
# excluded. dual-account then follows by merging nexus-base.
# Usage: scripts/nexus-base-update.sh <xodus-nexus checkout>
# Prints "unchanged" or "updated <patchId>".
set -euo pipefail
nexus=$(cd "$1" && pwd)
lock="$nexus/assets/backend-source.lock.json"
read -r commit cargo_sha patch_id version < <(python3 -I -c 'import json,sys; l=json.load(open(sys.argv[1])); print(l["commit"], l["cargoLockSha256"], l["patchId"], l["version"])' "$lock")
patch_id=${patch_id%-dual-account-*}
git cat-file -e "$commit^{commit}" 2>/dev/null || git fetch -q upstream "$commit" 2>/dev/null || git fetch -q origin main
work=$(mktemp -d)
trap 'git worktree remove --force "$work" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
git worktree add -q --detach "$work" "$commit"
[ "$(sha256sum "$work/Cargo.lock" | cut -d' ' -f1)" = "$cargo_sha" ] || { echo "Cargo.lock does not match the lock" >&2; exit 1; }
python3 -I -c 'import json,sys
for p in json.load(open(sys.argv[1]))["patches"]:
    if p["file"] != "xodus-dual-account.patch": print(p["file"], p["sha256"])' "$lock" |
while read -r file sha; do
    [ "$(sha256sum "$nexus/assets/$file" | cut -d' ' -f1)" = "$sha" ] || { echo "Checksum mismatch: $file" >&2; exit 1; }
    git -C "$work" apply --check "$nexus/assets/$file" || { echo "Does not apply: $file" >&2; exit 1; }
    git -C "$work" apply "$nexus/assets/$file"
done
git -C "$work" add -A
tree=$(git -C "$work" write-tree)
if [ "$tree" = "$(git rev-parse 'nexus-base^{tree}')" ]; then echo unchanged; exit 0; fi
new=$(git commit-tree "$tree" -p nexus-base -m "nexus-base: $patch_id (backend $version)

Xodus $commit with the patches pinned by Xodus Nexus ($patch_id),
without the dual-account patch.")
git update-ref refs/heads/nexus-base "$new"
echo "updated $patch_id"
