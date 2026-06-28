#!/bin/bash
# verify.sh — generic NDJSON verification template
#
# Usage:
#   1. Copy to scripts/verify-<host>.sh
#   2. Replace the example checks (C1..C4) with real ones from your spec
#   3. Run:
#        bash scripts/verify-<host>.sh > /tmp/verify.ndjson
#        python3 scripts/render-report.py < /tmp/verify.ndjson
#
# Output format: NDJSON, one JSON object per line:
#   {"id":"C1","status":"pass","detail":"exists"}
#
# Status values: pass | fail | skip
#
# Requirements: bash, coreutils, optionally python3 (for JSON escape)

set -u

# ---------- helpers ----------

# emit <id> <status> <detail>
emit() {
  local id=$1 status=$2 detail=$3
  local esc
  if command -v python3 >/dev/null 2>&1; then
    esc=$(printf '%s' "$detail" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')
  else
    # fallback: rough escape (good enough for simple ASCII)
    esc=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n')
    esc="\"$esc\""
  fi
  printf '{"id":"%s","status":"%s","detail":%s}\n' "$id" "$status" "$esc"
}

# pass <id> <detail>
pass() { emit "$1" pass "$2"; }

# fail <id> <detail>
fail() { emit "$1" fail "$2"; }

# skip <id> <reason>
skip() { emit "$1" skip "$2"; }

# ---------- checks (REPLACE THESE) ----------
#
# 規則：
#   - 每個 check 對應 spec 裡一個 ID（C1、C2...）
#   - 用 pass / fail / skip 其中之一
#   - detail 盡量放實際值，方便人讀也方便 LLM 判讀

# C1: 檔案存在
if [ -f /etc/ssh/sshd_config ]; then
  pass C1 "/etc/ssh/sshd_config exists"
else
  fail C1 "/etc/ssh/sshd_config missing"
fi

# C2: sshd_config 含 PermitRootLogin no
if [ -f /etc/ssh/sshd_config ] && grep -qE '^PermitRootLogin\s+no$' /etc/ssh/sshd_config; then
  pass C2 "PermitRootLogin no"
else
  actual=$(grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo not-set)
  fail C2 "actual=$actual want=PermitRootLogin no"
fi

# C3: sysctl 值（注意 sysctl -n 永遠回字串）
actual=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$actual" = "0" ]; then
  pass C3 "ip_forward=0"
else
  fail C3 "ip_forward=$actual want=0"
fi

# C4: service 狀態
state=$(systemctl is-active sshd 2>/dev/null || echo unknown)
if [ "$state" = "active" ]; then
  pass C4 "sshd active"
else
  fail C4 "sshd state=$state want=active"
fi

# ---------- end of checks ----------

# 範例：怎麼加 skip
# skip C99 "不適用此環境"

exit 0
