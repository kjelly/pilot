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
#   7. (captive-transport spec §15.4, 2026-09-23) no-PTY arbitrary command
#      denied; `ssh -tt ... pilot-transport-v1|pilot-known-hosts-v1` denied
#      (those states forbid a TTY); scp to the gateway denied; -R and -D
#      forwarding refused server-side; effective AllowStreamLocalForwarding
#      no and global PermitUserEnvironment no; and — only when
#      TRANSPORT_TARGET names a transport-ready target — a live
#      pilot-transport-v1 session's `pilot portal-session` process has no
#      child at all (no shell, no /usr/bin/ssh).
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
#   PORTAL_KEY         — alternative to PORTAL_PASSWORD: a private key file
#                        whose public half is the portal user's FreeIPA
#                        ipaSshPubKey (e.g. the captive-transport E2E
#                        fixture's disposable key). Exactly one of
#                        PORTAL_PASSWORD / PORTAL_KEY is required.
#   CONFIRM_DISPOSABLE — must be exactly "yes". A deliberate speed bump so
#                        this can't be copy-pasted against a real gateway
#                        by accident.
#
# Optional env:
#   GATEWAY_ADMIN_USER — admin account name (default root).
#   FWD_TEST_PORT      — local port used for the forwarding probe (default 18022).
#   TRANSPORT_TARGET   — a target FQDN the portal user may open a
#                        pilot-transport-v1 transport to (gateway transport
#                        enabled + target in pilot-transport-ready). When
#                        unset, the live-transport process-tree probe is
#                        reported as skipped.
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
PORTAL_KEY="${PORTAL_KEY:-}"
TRANSPORT_TARGET="${TRANSPORT_TARGET:-}"

if [ "${CONFIRM_DISPOSABLE:-}" != "yes" ]; then
  echo "ERROR: set CONFIRM_DISPOSABLE=yes to confirm GATEWAY_HOST is a disposable test gateway (spec.md §0 G4/§55.1 — never run this against a real/shared host)." >&2
  exit 2
fi
if [ -z "$GATEWAY_HOST" ] || [ -z "$GATEWAY_ADMIN_KEY" ] || [ -z "$PORTAL_USER" ]; then
  echo "ERROR: GATEWAY_HOST, GATEWAY_ADMIN_KEY and PORTAL_USER are all required." >&2
  exit 2
fi
if [ -n "${PORTAL_PASSWORD:-}" ] && [ -n "$PORTAL_KEY" ]; then
  echo "ERROR: set exactly one of PORTAL_PASSWORD or PORTAL_KEY, not both." >&2
  exit 2
fi
if [ -z "${PORTAL_PASSWORD:-}" ] && [ -z "$PORTAL_KEY" ]; then
  echo "ERROR: one of PORTAL_PASSWORD or PORTAL_KEY is required." >&2
  exit 2
fi
if [ -n "${PORTAL_PASSWORD:-}" ] && ! command -v sshpass >/dev/null 2>&1; then
  echo "ERROR: sshpass is required for PORTAL_PASSWORD (used the same way as scripts/minimal-poc-section4-spotcheck.sh)." >&2
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

PORTAL_SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=no -o ConnectTimeout=8)
# PORTAL_AUTH is prefixed to every portal-user ssh/sftp/scp invocation:
# `sshpass -e` (with SSHPASS exported once) for password auth, nothing for
# key auth (the key goes into PORTAL_SSH_OPTS instead).
if [ -n "$PORTAL_KEY" ]; then
  PORTAL_AUTH=()
  PORTAL_SSH_OPTS+=(-i "$PORTAL_KEY" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no)
else
  export SSHPASS="$PORTAL_PASSWORD"
  PORTAL_AUTH=(sshpass -e)
  PORTAL_SSH_OPTS+=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
fi
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
"${PORTAL_AUTH[@]}" ssh -tt "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" \
  "echo $MARKER; whoami; id" </dev/null >"$log1" 2>&1 &
CLEANUP_PIDS+=("$!")
sleep 3
tree1=$("${ADMIN_SSH[@]}" "ps -ef | grep -F '$PORTAL_USER'" 2>/dev/null)
kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
sleep 1

# Since the Phase 5 dispatcher (2026-09-18) an unrecognized command is
# denied outright ("pilot-session: unrecognized command") instead of
# falling through to the interactive TUI, so either outcome — an explicit
# rejection, or (older builds) pilot-session -> pilot portal in the tree —
# proves the injected command never ran; the marker is what must be absent.
if grep -q "$MARKER" "$log1"; then
  emit lockout-forced-pty-command-ignored fail "injected command's own marker appeared in client output: $(cat "$log1")"
elif grep -q 'pilot-session:' "$log1"; then
  emit lockout-forced-pty-command-ignored pass "dispatcher rejected the injected command: $(cat "$log1")"
elif grep -q 'pilot-session' <<<"$tree1" && grep -q '/usr/bin/pilot portal' <<<"$tree1"; then
  emit lockout-forced-pty-command-ignored pass "process tree shows only pilot-session -> pilot portal; injected command never ran: $tree1"
else
  emit lockout-forced-pty-command-ignored fail "neither a pilot-session rejection nor pilot-session -> pilot portal was observed; output: $(cat "$log1"); tree: $tree1"
fi
rm -f "$log1"

# --- 2. client-side RemoteCommand override ---

log2=$(mktemp)
"${PORTAL_AUTH[@]}" ssh -tt "${PORTAL_SSH_OPTS[@]}" -o RemoteCommand="echo $MARKER; /bin/sh -i" \
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
"${PORTAL_AUTH[@]}" ssh -v "${PORTAL_SSH_OPTS[@]}" -o ExitOnForwardFailure=no \
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

# --- 4. SFTP subsystem must be refused (the subsystem's SSH_ORIGINAL_COMMAND is not a recognized grammar -> denied) ---

sftp_out=$("${PORTAL_AUTH[@]}" sftp "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" <<<"pwd" 2>&1)
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
check_directive lockout-directive-allowstreamlocalforwarding allowstreamlocalforwarding no

# PermitUserEnvironment is not allowed inside a Match block, so the drop-in
# cannot set it; the GLOBAL effective value is what must be "no".
global_env=$("${ADMIN_SSH[@]}" "sshd -T" 2>&1 | grep -i '^permituserenvironment ' | awk '{print $2}')
if [ "$global_env" = no ]; then
  emit lockout-directive-permituserenvironment pass "global permituserenvironment = no"
else
  emit lockout-directive-permituserenvironment fail "global permituserenvironment = '$global_env', want 'no'"
fi

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
  "${PORTAL_AUTH[@]}" ssh -tt "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" \
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

# --- 7. captive-transport spec §15.4 probes (2026-09-23) ---

# 7a. no-PTY arbitrary command: denied by the dispatcher, never executed.
log7a=$(mktemp)
"${PORTAL_AUTH[@]}" ssh -T "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" "echo $MARKER; id" </dev/null >"$log7a" 2>&1
rc7a=$?
if grep -q "$MARKER" "$log7a"; then
  emit lockout-notty-command-denied fail "injected no-PTY command ran: $(cat "$log7a")"
elif [ "$rc7a" -ne 0 ] && grep -q 'pilot-session:' "$log7a"; then
  emit lockout-notty-command-denied pass "rc=$rc7a: $(cat "$log7a")"
else
  emit lockout-notty-command-denied fail "rc=$rc7a, expected a pilot-session rejection: $(cat "$log7a")"
fi
rm -f "$log7a"

# 7b. transport / known-hosts states forbid a TTY.
tty_target="${TRANSPORT_TARGET:-transport-probe.example.internal}"
for verb in pilot-transport-v1 pilot-known-hosts-v1; do
  log7b=$(mktemp)
  timeout 20 "${PORTAL_AUTH[@]}" ssh -tt "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" -- "$verb" "$tty_target" </dev/null >"$log7b" 2>&1
  rc7b=$?
  if [ "$rc7b" -ne 0 ] && grep -q 'a TTY is not allowed' "$log7b"; then
    emit "lockout-tty-$verb-denied" pass "rc=$rc7b: $(tr -d '\r' <"$log7b")"
  else
    emit "lockout-tty-$verb-denied" fail "rc=$rc7b, expected 'a TTY is not allowed': $(cat "$log7b")"
  fi
  rm -f "$log7b"
done

# 7c. scp to the gateway (both the default SFTP-based protocol and legacy -O)
#     is refused, and nothing lands on the gateway.
scp_src=$(mktemp)
echo "$MARKER" >"$scp_src"
for mode in sftp legacy; do
  extra=()
  [ "$mode" = legacy ] && extra=(-O)
  scp_out=$("${PORTAL_AUTH[@]}" scp "${extra[@]}" "${PORTAL_SSH_OPTS[@]}" "$scp_src" "${PORTAL_USER}@${GATEWAY_HOST}:/tmp/lockout-scp-$mode-$$" 2>&1 </dev/null)
  scp_rc=$?
  landed=$("${ADMIN_SSH[@]}" "test -e /tmp/lockout-scp-$mode-$$ && echo LANDED" 2>/dev/null)
  if [ "$scp_rc" -ne 0 ] && [ -z "$landed" ]; then
    emit "lockout-scp-$mode-refused" pass "rc=$scp_rc, nothing written on the gateway: $scp_out"
  else
    emit "lockout-scp-$mode-refused" fail "rc=$scp_rc landed=[$landed]: $scp_out"
  fi
done
rm -f "$scp_src"

# 7d. remote (-R) forwarding is refused by the server.
log7d=$(mktemp)
timeout 15 "${PORTAL_AUTH[@]}" ssh -v "${PORTAL_SSH_OPTS[@]}" -o ExitOnForwardFailure=yes \
  -N -R "$((FWD_TEST_PORT + 1)):127.0.0.1:22" "${PORTAL_USER}@${GATEWAY_HOST}" >"$log7d" 2>&1
if grep -qiE "remote port forwarding failed|forwarding request denied|administratively prohibited" "$log7d"; then
  emit lockout-remote-forward-refused pass "$(grep -iE 'remote port forwarding failed|forwarding request denied|administratively prohibited' "$log7d" | head -1)"
else
  emit lockout-remote-forward-refused fail "expected the server to refuse -R; ssh -v log: $(tail -20 "$log7d")"
fi
rm -f "$log7d"

# 7e. dynamic (-D) forwarding: the SOCKS listener is local, but every
#     channel it opens must be refused server-side.
log7e=$(mktemp)
DYN_PORT=$((FWD_TEST_PORT + 2))
"${PORTAL_AUTH[@]}" ssh -v "${PORTAL_SSH_OPTS[@]}" -N -D "127.0.0.1:${DYN_PORT}" "${PORTAL_USER}@${GATEWAY_HOST}" >"$log7e" 2>&1 &
CLEANUP_PIDS+=("$!")
sleep 3
curl -s --max-time 5 --socks5-hostname "127.0.0.1:${DYN_PORT}" "http://127.0.0.1:22/" >/dev/null 2>&1
sleep 1
kill "${CLEANUP_PIDS[-1]}" >/dev/null 2>&1 || true
sleep 1
if grep -qi "administratively prohibited" "$log7e"; then
  emit lockout-dynamic-forward-refused pass "$(grep -i 'administratively prohibited' "$log7e" | head -1)"
else
  emit lockout-dynamic-forward-refused fail "expected an 'administratively prohibited' refusal for the -D channel; ssh -v log: $(tail -20 "$log7e")"
fi
rm -f "$log7e"

# 7f. a live transport session's pilot portal-session has no child at all.
if [ -z "$TRANSPORT_TARGET" ]; then
  printf '{"id":"lockout-transport-no-child","status":"skip","detail":"TRANSPORT_TARGET unset"}\n'
else
  # Keep stdin open so the bridge stays up while the tree is inspected.
  (sleep 8 | "${PORTAL_AUTH[@]}" ssh -T "${PORTAL_SSH_OPTS[@]}" "${PORTAL_USER}@${GATEWAY_HOST}" -- pilot-transport-v1 "$TRANSPORT_TARGET" >/dev/null 2>&1) &
  CLEANUP_PIDS+=("$!")
  sleep 4
  tree7f=$("${ADMIN_SSH[@]}" "pid=\$(pgrep -u '$PORTAL_USER' -f 'pilot portal-session' | head -1); [ -n \"\$pid\" ] && { echo PID=\$pid; ps -o pid=,cmd= --ppid \$pid; }" 2>/dev/null)
  if ! grep -q '^PID=' <<<"$tree7f"; then
    emit lockout-transport-no-child fail "no live pilot portal-session process found for the transport session"
  elif [ "$(grep -vc '^PID=' <<<"$tree7f")" -ne 0 ]; then
    emit lockout-transport-no-child fail "pilot portal-session has child process(es): $tree7f"
  else
    emit lockout-transport-no-child pass "live transport: pilot portal-session ($(grep '^PID=' <<<"$tree7f")) has no child process"
  fi
fi

echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >&2
[ "$FAIL_COUNT" -eq 0 ]
