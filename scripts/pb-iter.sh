#!/usr/bin/env bash
# scripts/pb-iter.sh — Ansible playbook 開發迭代工具
#
# 對應 docs/ansible-playbook-development.md 描述的 L1..L8 流程。
# 由 Makefile target 呼叫，也可單獨使用。
#
# 用法：
#   ./scripts/pb-iter.sh iter        PB_SPEC=docs/verification/bastion.md
#   ./scripts/pb-iter.sh verify      PB_SPEC=...
#   ./scripts/pb-iter.sh idempotent  PB_SPEC=... PB_RUNS=3
#   ./scripts/pb-iter.sh baseline    PB_SPEC=...
#   ./scripts/pb-iter.sh report      PB_SPEC=...
#   ./scripts/pb-iter.sh lint        PB_SPEC=...
#   ./scripts/pb-iter.sh clean       PB_SPEC=...
#
# 必要環境變數：
#   PB_SPEC — spec 檔案路徑（必填）
#
# 選用環境變數（有預設值）：
#   PB_PLAYBOOK   — playbook 路徑（預設從 spec 推導）
#   PB_VERIFY     — verify 腳本路徑（預設從 spec 推導）
#   PB_INVENTORY  — inventory 路徑（預設 inventory/hosts）
#   PB_RUNS       — idempotent 連跑次數（預設 3）
#   PB_VERIF_ROOT — 報告輸出目錄（預設 .verification/）

set -euo pipefail

# ---------- args ------------------------------------------------------------
CMD="${1:-iter}"
shift || true

PB_SPEC="${PB_SPEC:-}"
PB_PLAYBOOK="${PB_PLAYBOOK:-}"
PB_VERIFY="${PB_VERIFY:-}"
PB_INVENTORY="${PB_INVENTORY:-inventory/hosts}"
PB_RUNS="${PB_RUNS:-3}"
PB_VERIF_ROOT="${PB_VERIF_ROOT:-.verification}"

# ---------- logging ---------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ts() { date +%H:%M:%S; }
log()  { printf "${GREEN}[%s]${NC} %s\n" "$(ts)" "$*"; }
warn() { printf "${YELLOW}[%s]${NC} %s\n" "$(ts)" "$*" >&2; }
err()  { printf "${RED}[%s]${NC} %s\n" "$(ts)" "$*" >&2; }
banner() { printf "${CYAN}========== %s ==========${NC}\n" "$*"; }

# ---------- helpers ---------------------------------------------------------
require_spec() {
  if [ -z "$PB_SPEC" ]; then
    err "PB_SPEC 未設定"
    echo "  用法：PB_SPEC=docs/verification/<host>.md $0 <cmd>" >&2
    echo "  範本：docs/verification-spec-template.md" >&2
    exit 2
  fi
  if [ ! -f "$PB_SPEC" ]; then
    err "Spec 檔案不存在：$PB_SPEC"
    echo "  從範本複製：" >&2
    echo "    cp docs/verification-spec-template.md $PB_SPEC" >&2
    exit 2
  fi
}

# 從 spec 檔名推導 host tag
host_tag_from_spec() {
  basename "$PB_SPEC" .md
}

# 推導預設 playbook 路徑
default_playbook() {
  local host
  host=$(host_tag_from_spec)
  echo "playbooks/${host}.yml"
}

# 推導預設 verify 腳本
default_verify() {
  local host
  host=$(host_tag_from_spec)
  echo "scripts/verify-${host}.sh"
}

resolve_paths() {
  require_spec
  PB_PLAYBOOK="${PB_PLAYBOOK:-$(default_playbook)}"
  PB_VERIFY="${PB_VERIFY:-$(default_verify)}"
  HOST_TAG="$(host_tag_from_spec)"
  TS="$(date +%Y%m%d-%H%M%S)"
  REPORT_MD="${PB_VERIF_ROOT}/${HOST_TAG}-${TS}.md"
  REPORT_NDJSON="${PB_VERIF_ROOT}/${HOST_TAG}-${TS}.ndjson"

  log "Spec:        $PB_SPEC"
  log "Playbook:    $PB_PLAYBOOK"
  log "Verify:      $PB_VERIFY"
  log "Inventory:   $PB_INVENTORY"
  log "Report dir:  $PB_VERIF_ROOT/"
  log "Host tag:    $HOST_TAG"
  echo
}

check_paths() {
  local missing=0
  if [ ! -f "$PB_PLAYBOOK" ]; then
    warn "playbook 不存在：$PB_PLAYBOOK（之後的 apply 會 fail）"
    missing=1
  fi
  if [ ! -f "$PB_VERIFY" ]; then
    warn "verify script 不存在：$PB_VERIFY（之後的 verify 會 fail）"
    missing=1
  fi
  return $missing
}

ensure_verif_root() {
  mkdir -p "$PB_VERIF_ROOT"
}

# ---------- L1..L8 steps ----------------------------------------------------

l1_syntax() {
  banner "L1 syntax check"
  ansible-playbook --syntax-check "$PB_PLAYBOOK"
}

l2_lint() {
  banner "L2 lint"
  if command -v ansible-lint >/dev/null 2>&1; then
    ansible-lint "$PB_PLAYBOOK"
  else
    warn "ansible-lint 未安裝，跳過（pip install ansible-lint）"
  fi
}

l3_dryrun() {
  banner "L3 dry-run (--check --diff)"
  ansible-playbook -i "$PB_INVENTORY" "$PB_PLAYBOOK" --check --diff
}

l4_apply() {
  banner "L4 apply"
  ansible-playbook -i "$PB_INVENTORY" "$PB_PLAYBOOK"
}

l5_verify() {
  banner "L5 verify"
  ensure_verif_root
  bash "$PB_VERIFY" > "$REPORT_NDJSON"
  python3 scripts/render-report.py < "$REPORT_NDJSON" > "$REPORT_MD"
  cat "$REPORT_MD"
  if grep -q 'verdict: \*\*FAIL\*\*' "$REPORT_MD"; then
    err "Verify report verdict=FAIL"
    return 1
  fi
}

l6_idempotent() {
  banner "L6 idempotent x${PB_RUNS}"
  local i last_changed out
  for i in $(seq 1 "$PB_RUNS"); do
    log "run $i/$PB_RUNS"
    out=$(ansible-playbook -i "$PB_INVENTORY" "$PB_PLAYBOOK" 2>&1) || { echo "$out"; return 1; }
    last_changed=$(echo "$out" | grep -oE 'changed=[0-9]+' | tail -1 | cut -d= -f2 || echo "?")
    log "  changed=$last_changed"
    if [ "$i" -gt 1 ] && [ "${last_changed:-0}" != "0" ]; then
      err "run $i changed=$last_changed（idempotency 失敗）"
      return 1
    fi
  done
}

l7_baseline_diff() {
  banner "L7 baseline diff"
  local latest prev
  # 注意：避免用 bash 函式 head()，改用 ls 排序 + 全路徑
  latest=$(ls -1t "${PB_VERIF_ROOT}/${HOST_TAG}-"*.md 2>/dev/null | /usr/bin/head -n 1 || true)
  prev=$(ls -1t "${PB_VERIF_ROOT}/${HOST_TAG}-"*.md 2>/dev/null | /usr/bin/head -n 2 | /usr/bin/tail -n 1 || true)
  if [ -z "$latest" ]; then
    warn "沒有 baseline report"
    return 0
  fi
  if [ -z "$prev" ]; then
    warn "只有一份 report，無從 diff：$latest"
    return 0
  fi
  log "prev:   $prev"
  log "latest: $latest"
  diff -u "$prev" "$latest" || true
}

# ---------- commands -------------------------------------------------------

cmd_iter() {
  resolve_paths
  check_paths || true
  l1_syntax
  l2_lint
  l3_dryrun
  l4_apply
  l5_verify
  l6_idempotent
  l7_baseline_diff
  log "全部完成。最新報告：$REPORT_MD"
}

cmd_verify() {
  resolve_paths
  l5_verify
}

cmd_idempotent() {
  resolve_paths
  l6_idempotent
}

cmd_baseline() {
  resolve_paths
  l7_baseline_diff
}

cmd_report() {
  resolve_paths
  ensure_verif_root
  printf "=== %s 的 baseline 報告（最新 10 份）===\n" "$HOST_TAG"
  # 用 /usr/bin/head 避免和自定 head() 函式衝突
  matches=$(ls -1t "${PB_VERIF_ROOT}/${HOST_TAG}-"*.md 2>/dev/null || true)
  if [ -z "$matches" ]; then
    echo "（無）"
  else
    printf "%s\n" "$matches" | /usr/bin/head -n 10
  fi
}

cmd_lint() {
  resolve_paths
  l1_syntax
  l2_lint
}

cmd_clean() {
  resolve_paths
  echo "即將刪除 ${PB_VERIF_ROOT}/${HOST_TAG}-*"
  matches=$(ls -1t "${PB_VERIF_ROOT}/${HOST_TAG}-"*.md 2>/dev/null || true)
  if [ -z "$matches" ]; then
    echo "（無）"
    return 0
  fi
  printf "%s\n" "$matches" | /usr/bin/head -n 5
  read -rp "確認刪除？[y/N] " ans
  case "$ans" in
    y|Y) rm -f "${PB_VERIF_ROOT}/${HOST_TAG}-"*.md "${PB_VERIF_ROOT}/${HOST_TAG}-"*.ndjson
         log "已刪除" ;;
    *)   log "取消" ;;
  esac
}

cmd_help() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------- main ------------------------------------------------------------
case "$CMD" in
  iter)        cmd_iter ;;
  verify)      cmd_verify ;;
  idempotent)  cmd_idempotent ;;
  baseline)    cmd_baseline ;;
  report)      cmd_report ;;
  lint)        cmd_lint ;;
  clean)       cmd_clean ;;
  -h|--help|help|"") cmd_help ;;
  *) err "未知指令：$CMD"; cmd_help; exit 2 ;;
esac
