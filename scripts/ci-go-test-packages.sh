#!/usr/bin/env bash
# Partition go list's package set without dropping newly added packages.
set -euo pipefail
case "${1:-}" in spec|cmd|rest) shard=$1 ;; *) echo 'expected spec, cmd or rest' >&2; exit 2 ;; esac
# CI executes -race; include packages whose source is gated by the race tag.
packages=$(go list -race ./...)
while IFS= read -r package; do
    case "$package" in
        github.com/kjelly/pilot/internal/spec) group=spec ;;
        github.com/kjelly/pilot/cmd/pilot/cmd) group=cmd ;;
        *) group=rest ;;
    esac
    if [[ "$group" = "$shard" ]]; then printf '%s\n' "$package"; fi
done <<< "$packages"
