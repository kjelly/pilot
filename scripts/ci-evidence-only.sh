#!/usr/bin/env bash
# Unknown base, non-PR events and empty diffs run the full suite.
set -euo pipefail
base=${1:-}
head=${2:-}
if [[ -z "$base" || -z "$head" ]]; then
    echo evidence_only=false
    exit 0
fi
changes=$(mktemp)
trap 'rm -f "$changes"' EXIT
git diff --name-only --no-renames -z "$base...$head" > "$changes"
only=false
while IFS= read -r -d '' path; do
    case "$path" in
        docs/evidence/*) only=true ;;
        *) echo evidence_only=false; exit 0 ;;
    esac
done < "$changes"
echo "evidence_only=$only"
