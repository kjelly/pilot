#!/usr/bin/env bash
# scripts/pilot-access-gateway-lockout-test.sh — repeatable extension of
# spec.md §55.1's lockout regression test (docs/verification/pilot-access-
# gateway.md §4, AG20/AG21/AG25). That original 3-step test only proved
# "no PTY -> requested command doesn't run" and "root still gets a normal
# shell" — it never exercised the other standard restricted-shell escape
# vectors an OpenSSH ForceCommand session offers a client. This script
# formalizes the additional live probes run manually against ag-gw01 on
# 2026-09-15 (found nothing exploitable; see the conversation this was
# extracted from) so they can be rerun after any future change to
# playbooks/apply/pilot-access-gateway-apply.yml's Step 19 ForceCommand
# drop-in or /usr/local/libexec/pilot-session.
#
# Scope: assumes pilot_access_gateway_install_forcecommand is already
# active on the target gateway (the default since 2026-09-14) — this
# script is read-only, it never flips that flag or re-applies the
# playbook itself (unlike the original 3-step test, which did).
#
# Probes covered (all expected to be BLOCKED — a "fail" here is a real
# lockout regression, i.e. a jailbreak):
#   1. `ssh -tt user@gw "<cmd>"`      — forced-PTY command injection via
#                                       SSH_ORIGINAL_COMMAND, verified by
#                                       inspecting the live process tree
#                                       on the gateway, not just exit code.
#   2. `ssh -o RemoteCommand=...`     — client-side command override.
#   3. `ssh -N -L <port>:...`         — local port forwarding; verified via
#                                       the server's actual channel-open
#                                       refusal, not just client behavior.
#   4. `sftp user@gw`                 — SFTP subsystem request.
#   5. `sshd -T -C user=...`          — effective (Match-block-evaluated)
#                                       sshd directives for the portal
#                                       group: ForceCommand, DisableForwarding,
#                                       PermitUserRC, X11Forwarding,
#                                       AllowTcpForwarding, AllowAgentForwarding,
#                                       PermitTunnel.
#   6. pilot-connect grammar rejection — (spec.md §16/§17/§38, added Phase 5
#                                       / 2026-09-18) malformed/malicious
#                                       `pilot-connect <session-id> <fqdn>`
#                                       shapes (shell metacharacter,
#                                       user@host, IP literal, leading `-`,
#                                       embedded newline, non-UUID session
#                                       id, missing target) — verified both
#                                       by pilot-session's own rejection
#                                       message on the client and by the
#                                       live process tree never showing an
#                                       ssh child toward any target host.
#
# §55.1 / §0 G4 still applies in full: only ever run this against a
# disposable vm-target, never a real/shared host — this script logs in as
# a REAL portal user and actively attempts to escape the captive shell.
#
# Usage:
#   GATEWAY_HOST=192.168.122.3 \
#   GATEWAY_ADMIN_KEY=/var/lib/libvirt/images/pilot/ag-gw01/id_ed25519 \
#   PORTAL_USER=alice PORTAL_PASSWORD='...' \
#   CONFIRM_DISPOSABLE=yes \
#   ./scripts/pilot-access-gateway-lockout-test.sh
#
# Required env:
#   GATEWAY_HOST       — IP/FQDN of the gateway under test.
#   GATEWAY_ADMIN_KEY  — private key for an admin/root account on the
#                        gateway (used only to read process list + `sshd
#                        -T`, never to mutate anything).
#   PORTAL_USER        — a real FreeIPA user who IS a member of
#                        gateway_portal_user_group (default role-pilot-
#                        portal-user) on this gateway.
#   PORTAL_PASSWORD    — that user's current live password. Never pass this
#                        as an argv flag or under `set -x`; this script
#                        only ever exports it as SSHPASS for `sshpass -e`
#                        (same discipline as scripts/minimal-poc-section4-
#                        spotcheck.sh).
#   CONFIRM_DISPOSABLE — must be exactly "yes". A deliberate speed bump so
#                        this can't be copy-pasted against a real gateway
#                        by accident.
#
# Optional env:
#   GATEWAY_ADMIN_USER — admin account name (default root).
#   FWD_TEST_PORT      — local port used for the forwarding probe (default 18022).
#
# Output: one JSON line per probe on stdout (id/status/detail); a one-line
# summary on stderr. Exit 0 only if every probe's expected (blocked) outcome
# held.

set -uo pipefail

GATEWAY_HOST="${GATEWAY_HOST:-}"
GATEWAY_ADMIN_KEY="${GATEWAY_ADMIN_KEY:-}"
GATEWAY_ADMIN_USER="${GATEWAY_ADMIN_USER:-root}"
PORTAL_USER="${PORTAL_USER:-}"
FWD_TEST_PORT="${FWD_TEST_PORT:-18022}"

if [ "${CONFIRM_DISPOSABLE:-}" != "yes" ]; then
  echo "ERROR: set CONFIRM_DISPOSABLE=yes to confirm GATEWAY_HOST is a disposable test gateway (spec.md §0 G4/§55.1 — never run this against a real/shared host)." >&2
  exit 2
fi
if [ -z "$GATEWAY_HOST" ] || [ -z "$GATEWAY_ADMIN_KEY" ] || [ -z "$PORTAL_USER" ] || [ -z "${PORTAL_PASSWORD:-}" ]; then
  echo "ERROR: GATEWAY_HOST, GATEWAY_ADMIN_KEY, PORTAL_USER and PORTAL_PASSWORD are all required." >&2
  exit 2
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo "ERROR: sshpass is required (used the same way as scripts/minimal-poc-section4-spotcheck.sh)." >&2
  exit 2
fi

PASS_COUNT=0
FAIL_COUNT=0

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
  if [ "$status" = pass ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

PORTAL_SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=no
                 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=8)
ADMIN_SSH=(ssh -i "$GATEWAY_ADMIN_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o ConnectTimeout=8 "${GATEWAY_ADMIN_USER}@${GATEWAY_HOST}")

MARKER="LOCKOUT_TEST_MARKER_$$"
CLEANUP_PIDS=()
cleanup() {
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  # Best-effort: this script only ever targets a disposable test gateway
  # (enforced by CONFIRM_DISPOSABLE above), so killing every remaining
  # session for PORTAL_USER on it is an acceptable, deliberate cleanup —
  # never do this against a real/shared host.
  "${ADMIN_SSH[@]}" "pkill -9 -u '$PORTAL_USER' -f pilot-session; pkill -9 -u '$PORTAL_USER' -f 'pilot portal'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. forced-PTY command injection, verified via the live process tree ---

log1=$(mktemp)
SSHPASS="$PORTAL_PASSWORD" sshpass -e ssh -tt "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" \
  "echo $MARKER; whoami; id" </dev/null >"$log1" 2>&1 &
CLEANUP_PIDS+=("$!")
sleep 3
tree1=$("${ADMIN_SSH[@]}" "ps -ef | grep -F '$PORTAL_USER'" 2>/dev/null)
kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
sleep 1

if grep -q "$MARKER" "$log1"; then
  emit lockout-forced-pty-command-ignored fail "injected command's own marker appeared in client output: $(cat "$log1")"
elif ! grep -q 'pilot-session' <<<"$tree1" || ! grep -q '/usr/bin/pilot portal' <<<"$tree1"; then
  emit lockout-forced-pty-command-ignored fail "expected pilot-session -> pilot portal in the process tree, got: $tree1"
else
  emit lockout-forced-pty-command-ignored pass "process tree shows only pilot-session -> pilot portal; injected command never ran: $tree1"
fi
rm -f "$log1"

# --- 2. client-side RemoteCommand override ---

log2=$(mktemp)
SSHPASS="$PORTAL_PASSWORD" sshpass -e ssh -tt "${PORTAL_SSH_OPTS[@]}" -o RemoteCommand="echo $MARKER; /bin/sh -i" \
  "${PORTAL_USER}@${GATEWAY_HOST}" </dev/null >"$log2" 2>&1 &
CLEANUP_PIDS+=("$!")
sleep 3
kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
sleep 1

if grep -q "$MARKER" "$log2"; then
  emit lockout-remotecommand-ignored fail "RemoteCommand marker appeared in client output: $(cat "$log2")"
else
  emit lockout-remotecommand-ignored pass "RemoteCommand override had no effect (ForceCommand won)"
fi
rm -f "$log2"

# --- 3. local port forwarding must be refused server-side ---

log3=$(mktemp)
SSHPASS="$PORTAL_PASSWORD" sshpass -e ssh -v "${PORTAL_SSH_OPTS[@]}" -o ExitOnForwardFailure=no \
  -N -L "${FWD_TEST_PORT}:127.0.0.1:22" "${PORTAL_USER}@${GATEWAY_HOST}" >"$log3" 2>&1 &
CLEANUP_PIDS+=("$!")
sleep 2
(exec 3<>"/dev/tcp/127.0.0.1/${FWD_TEST_PORT}") >/dev/null 2>&1
sleep 1
kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
sleep 1

if grep -qi "administratively prohibited" "$log3"; then
  emit lockout-port-forward-refused pass "server refused the forwarded channel: $(grep -i 'administratively prohibited' "$log3")"
else
  emit lockout-port-forward-refused fail "expected an 'administratively prohibited' channel refusal; ssh -v log: $(cat "$log3")"
fi
rm -f "$log3"

# --- 4. SFTP subsystem must be refused (no PTY -> pilot-session exits 1) ---

sftp_out=$(SSHPASS="$PORTAL_PASSWORD" sshpass -e sftp "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" <<<"pwd" 2>&1)
sftp_rc=$?
# NOTE: piping into sshpass (`printf ... | sshpass -e sftp -b -`) breaks
# sshpass's own pty-based password injection and fails auth outright
# ("Permission denied") before ForceCommand is ever reached — found while
# writing this script. A here-string avoids that; if "Permission denied"
# still shows up below, the probe proved nothing about ForceCommand and
# must be treated as a setup failure, not a pass.
if grep -qi "Permission denied" <<<"$sftp_out"; then
  emit lockout-sftp-refused fail "authentication itself failed (not a ForceCommand result) — check PORTAL_PASSWORD: $sftp_out"
elif [ "$sftp_rc" -ne 0 ]; then
  emit lockout-sftp-refused pass "sftp authenticated then session was closed (session refused): $sftp_out"
else
  emit lockout-sftp-refused fail "sftp unexpectedly succeeded: $sftp_out"
fi

# --- 5. effective (Match-evaluated) sshd directives for the portal group ---

effective=$("${ADMIN_SSH[@]}" "sshd -T -C user=${PORTAL_USER},host=localhost,addr=127.0.0.1,lport=22" 2>&1)
check_directive() {
  local id=$1 directive=$2 want=$3
  local got
  got=$(grep -i "^${directive} " <<<"$effective" | awk '{$1=""; sub(/^ /,""); print}')
  if [ "$want" = "*pilot-session*" ]; then
    if [[ "$got" == *pilot-session* ]]; then
      emit "$id" pass "$directive = $got"
    else
      emit "$id" fail "$directive = '$got', want it to reference pilot-session"
    fi
  elif [ "$got" = "$want" ]; then
    emit "$id" pass "$directive = $got"
  else
    emit "$id" fail "$directive = '$got', want '$want'"
  fi
}
check_directive lockout-directive-forcecommand forcecommand '*pilot-session*'
check_directive lockout-directive-disableforwarding disableforwarding yes
check_directive lockout-directive-permituserrc permituserrc no
check_directive lockout-directive-x11forwarding x11forwarding no
check_directive lockout-directive-allowtcpforwarding allowtcpforwarding no
check_directive lockout-directive-allowagentforwarding allowagentforwarding no
check_directive lockout-directive-permittunnel permittunnel no

# --- 6. Phase 5 handoff grammar rejection (docs/tmp/now/spec.md §16/§17/§38,
#     AG35/AG36): every malformed/malicious pilot-connect-shaped
#     SSH_ORIGINAL_COMMAND must be denied by the Go parser in
#     cmd/pilot/cmd/portal_session.go — never executed, never silently
#     falling back to the interactive TUI. Each case is sent as the
#     client's requested command over a forced-PTY session (same
#     technique as probe 1) and verified two ways: the client-side output
#     must show pilot-session's own rejection message (a stable
#     "pilot-session:" prefix), and the gateway's live process tree must
#     show no ssh child ever spawned toward any target host.
UUID="0d33c638-83fa-4d77-9811-a97a7a7af1d5"
declare -a GRAMMAR_CASES=(
  "pilot-connect $UUID host;id"
  "pilot-connect $UUID host\$(id)"
  "pilot-connect $UUID user@host.example.com"
  "pilot-connect $UUID 1.2.3.4"
  "pilot-connect $UUID -oProxyCommand=x"
  "pilot-connect $UUID host.example.com."$'\n'"id"
  "pilot-connect not-a-uuid host.example.com"
  "pilot-connect $UUID"
)
for i in "${!GRAMMAR_CASES[@]}"; do
  case_cmd="${GRAMMAR_CASES[$i]}"
  logN=$(mktemp)
  SSHPASS="$PORTAL_PASSWORD" sshpass -e ssh -tt "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" \
    "$case_cmd" </dev/null >"$logN" 2>&1 &
  CLEANUP_PIDS+=("$!")
  sleep 2
  treeN=$("${ADMIN_SSH[@]}" "ps -ef | grep -F '$PORTAL_USER'" 2>/dev/null)
  kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
  sleep 1

  if grep -qE 'ssh .*(gpu-|dmz-|target)' <<<"$treeN"; then
    emit "lockout-handoff-grammar-$i" fail "an ssh child toward a target host appeared for case [$case_cmd]: $treeN"
  elif ! grep -q "pilot-session:" "$logN"; then
    emit "lockout-handoff-grammar-$i" fail "expected pilot-session's own rejection message for case [$case_cmd], got: $(cat "$logN")"
  else
    emit "lockout-handoff-grammar-$i" pass "rejected: $(cat "$logN")"
  fi
  rm -f "$logN"
done

echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >&2
[ "$FAIL_COUNT" -eq 0 ]
