#!/usr/bin/env bash
# scripts/verify-hello-localhost.sh — verification script for hello-localhost playbook
set -euo pipefail

# 1. Output helper
emit() {
  local id=$1 status=$2 detail=$3
  local esc
  if command -v python3 >/dev/null 2>&1; then
    esc=$(printf '%s' "$detail" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')
  else
    esc=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n')
    esc="\"$esc\""
  fi
  printf '{"id":"%s","status":"%s","detail":%s}\n' "$id" "$status" "$esc"
}

# C1: Check if /etc/os-release is present
if [ -f /etc/os-release ]; then
  emit C1 pass "/etc/os-release is present and readable"
else
  emit C1 fail "/etc/os-release is missing"
fi

# C2: Check load average is less than 20.0
load=$(cat /proc/loadavg | cut -d' ' -f1)
if (( $(echo "$load < 20.0" | bc -l) )); then
  emit C2 pass "Load average OK: $load (threshold 20.0)"
else
  emit C2 fail "Load average too high: $load"
fi

# C3: Check kernel version
kernel=$(uname -r)
if [ -n "$kernel" ]; then
  emit C3 pass "Kernel version probed: $kernel"
else
  emit C3 fail "Failed to probe kernel version"
fi

exit 0
