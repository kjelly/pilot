#!/usr/bin/env bash
# Build the pre-baked pilot target image.
#
# Idempotent: re-running rebuilds the image (docker build is
# content-addressed so unchanged layers are reused from cache).
#
# Tag: pilot-target:ubuntu-24.04
#
# Usage:
#   ./images/build.sh                  # default tag
#   ./images/build.sh --tag myorg/v0.1 # custom tag
#
# After build:
#   pilot docker-target up --image pilot-target:ubuntu-24.04 --name x
#   # or:
#   pilot docker-target up --image-pilot ubuntu-24.04 --name x

set -euo pipefail
cd "$(dirname "$0")/.."

TAG="pilot-target:ubuntu-24.04"
DOCKERFILE="images/Dockerfile.pilot-target-ubuntu"

while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --dockerfile) DOCKERFILE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

echo "▶ building $TAG from $DOCKERFILE"
docker build -t "$TAG" -f "$DOCKERFILE" .
echo "✓ built $TAG"
docker images --format "  {{.Repository}}:{{.Tag}}\t{{.Size}}" "$TAG"
