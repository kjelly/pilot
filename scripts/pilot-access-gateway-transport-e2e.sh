#!/usr/bin/env bash
# scripts/pilot-access-gateway-transport-e2e.sh — end-to-end probes for the
# Pilot Access Gateway captive SSH transport
# (docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md
# §14.3/§14.5/§15.4) on docs/topologies/pilot-access-transport-topology.yaml.
#
# It never changes playbook state itself: the operator (or the evidence run)
# puts the topology into the state a phase expects with
# playbooks/test/pilot-access-transport-e2e.yml / the component playbooks,
# then runs the matching phase here:
#
#   --phase strict      gateway transport enabled, target policy present
#                       (strict), recording metadata: AG63-AG67, AG70-AG72,
#                       TP06 (member), TP07 (-L/-D/-R/-A/-X/-w), TP09
#   --phase remote-dev  same, target profile remote-dev: AG63 (ssh), TP08
#   --phase recording   gateway recording terminal_output: AG69 (transport
#                       and known-hosts refused; pilot-connect's local
#                       FileSink file holds the session output while it runs)
#   --phase not-ready   target policy absent: AG68, TP06 (not a member), TP10
#   --phase disabled    gateway transport disabled/unset: AG62/AG73 (+AG72)
#
# The workstation side runs on WS_HOST as WS_USER — a host that is NOT a
# FreeIPA client and has no route/DNS to the target, only to the gateway.
# Every transport session goes through an OpenSSH config written to
# ~WS_USER/.pilot-e2e/ssh_config that follows spec §6.1 exactly
# (ProxyCommand pilot-transport-v1, KnownHostsCommand pilot-known-hosts-v1,
# /dev/null known_hosts, StrictHostKeyChecking yes, ControlMaster).
#
# Only ever run this against disposable VMs (CONFIRM_DISPOSABLE=yes): it logs
# in as a real portal user, opens forwarding channels on purpose, and starts
# a throwaway loopback HTTP listener on the target.
#
# Required env:
#   CONFIRM_DISPOSABLE=yes
#   WS_HOST, WS_ADMIN_KEY            root on the workstation VM
#   GATEWAY_HOST, GATEWAY_ADMIN_KEY  root on the gateway VM (process tree,
#                                    journald, service-principal lookups)
#   GATEWAY_FQDN                     the gateway name the workstation uses
#   TARGET_HOST, TARGET_ADMIN_KEY    root on the target VM (listener, logs)
#   TARGET_FQDN                      the target's FreeIPA FQDN
# Optional env:
#   WS_USER            workstation user holding the portal key (default wsuser)
#   PORTAL_USER        FreeIPA portal user (default transportuser)
#   PORTAL_KEY         controller-side copy of that user's private key; needed
#                      for the pilot-connect / portal probes (AG69, AG72, AG73)
#   PORTAL_PASSWORD    the user's FreeIPA password for pilot-connect's
#                      session-scoped kinit; read from the environment only
#   OUT_OF_SCOPE_FQDN  an enrolled host outside the gateway scope
#                      (default ipa1.ipa.pilot.internal)
#
# Output: one JSON line per probe on stdout (id/status/detail); a summary on
# stderr. Exit 0 only if no probe failed (skips do not fail the run).

set -uo pipefail

PHASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --phase) PHASE="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$PHASE" in
  strict|remote-dev|recording|not-ready|disabled) ;;
  *) echo "usage: $0 --phase strict|remote-dev|recording|not-ready|disabled" >&2; exit 2 ;;
esac
if [ "${CONFIRM_DISPOSABLE:-}" != "yes" ]; then
  echo "ERROR: set CONFIRM_DISPOSABLE=yes — only ever run this against disposable test VMs." >&2
  exit 2
fi
for v in WS_HOST WS_ADMIN_KEY GATEWAY_HOST GATEWAY_ADMIN_KEY GATEWAY_FQDN TARGET_HOST TARGET_ADMIN_KEY TARGET_FQDN; do
  if [ -z "${!v:-}" ]; then echo "ERROR: $v is required." >&2; exit 2; fi
done
WS_USER="${WS_USER:-wsuser}"
PORTAL_USER="${PORTAL_USER:-transportuser}"
PORTAL_KEY="${PORTAL_KEY:-}"
OUT_OF_SCOPE_FQDN="${OUT_OF_SCOPE_FQDN:-ipa1.ipa.pilot.internal}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
emit() {
  local id=$1 status=$2 detail=$3
  printf '{"id":"%s","status":"%s","detail":%s}\n' "$id" "$status" \
    "$(printf '%s' "$detail" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"
  case "$status" in
    pass) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    skip) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    *) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
  esac
}

ADMIN_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes)
on_ws()  { ssh -i "$WS_ADMIN_KEY" "${ADMIN_OPTS[@]}" "root@$WS_HOST" "$@"; }
on_gw()  { ssh -i "$GATEWAY_ADMIN_KEY" "${ADMIN_OPTS[@]}" "root@$GATEWAY_HOST" "$@"; }
on_tgt() { ssh -i "$TARGET_ADMIN_KEY" "${ADMIN_OPTS[@]}" "root@$TARGET_HOST" "$@"; }
# Run one shell command line as WS_USER on the workstation.
as_ws() { on_ws "runuser -u $WS_USER -- bash -c $(printf %q "$1")"; }

# Absolute: rsync -e and KnownHostsCommand never expand "~".
CFG="/home/$WS_USER/.pilot-e2e/ssh_config"
TSSH="ssh -F $CFG"
MARK="e2e-$$-$RANDOM"
LPORT=18081   # throwaway loopback HTTP listener on the target
BG_PIDS=()
cleanup() {
  for p in "${BG_PIDS[@]:-}"; do kill "$p" >/dev/null 2>&1 || true; done
  as_ws "pkill -u $WS_USER -f '[s]sh -F .*pilot-e2e' ; rm -f /tmp/$MARK*; rm -rf /tmp/$MARK.tree" >/dev/null 2>&1 || true
  on_ws "ip tuntap del dev tun97 mode tun" >/dev/null 2>&1 || true
  on_tgt "pkill -f '^python3 -m http.server $LPORT' ; rm -rf /tmp/$MARK*" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---- workstation OpenSSH config (spec §6.1) ---------------------------------
as_ws "mkdir -p ~/.pilot-e2e && chmod 700 ~/.pilot-e2e && cat > ~/.pilot-e2e/ssh_config <<'EOF'
Host pilot-gw
    HostName $GATEWAY_FQDN
    User $PORTAL_USER
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.pilot-e2e/gateway_known_hosts
    ForwardAgent no
    ClearAllForwardings yes
    ControlMaster auto
    ControlPath ~/.pilot-e2e/cm-%C
    ControlPersist 60

Host * !pilot-gw
    User $PORTAL_USER
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    ProxyCommand /usr/bin/ssh -F /home/$WS_USER/.pilot-e2e/ssh_config -T pilot-gw -- pilot-transport-v1 %h
    KnownHostsCommand /usr/bin/ssh -F /home/$WS_USER/.pilot-e2e/ssh_config -T pilot-gw -- pilot-known-hosts-v1 %h
    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    CheckHostIP no
    ForwardAgent no
    ForwardX11 no
EOF
chmod 600 ~/.pilot-e2e/ssh_config"

# ---- shared probes ------------------------------------------------------------
probe_direct_blocked() { # AG63a
  local r
  r=$(as_ws "timeout 5 bash -c '</dev/tcp/$TARGET_HOST/22' >/dev/null 2>&1 && echo OPEN || echo BLOCKED")
  if [ "$r" = BLOCKED ]; then
    emit AG63-direct-target-blocked pass "workstation -> $TARGET_HOST:22 by IP: blocked"
  else
    emit AG63-direct-target-blocked fail "workstation reached $TARGET_HOST:22 directly: $r"
  fi
}

probe_ssh_via_transport() { # AG63b
  local out
  out=$(as_ws "$TSSH $TARGET_FQDN 'whoami; hostname -f; echo transport-ok' 2>&1")
  if grep -qx "$PORTAL_USER" <<<"$out" && grep -qx "$TARGET_FQDN" <<<"$out" && grep -qx transport-ok <<<"$out"; then
    emit AG63-ssh-via-transport pass "$(tr '\n' ' ' <<<"$out")"
  else
    emit AG63-ssh-via-transport fail "$out"
  fi
}

probe_no_child() { # AG63c
  as_ws "$TSSH $TARGET_FQDN sleep 10 >/dev/null 2>&1" &
  BG_PIDS+=("$!")
  sleep 5
  local tree
  tree=$(on_gw "for p in \$(pgrep -u $PORTAL_USER -f 'pilot portal-session'); do echo PID=\$p; ps -o pid=,cmd= --ppid \$p; done")
  wait "${BG_PIDS[-1]}" 2>/dev/null
  if ! grep -q '^PID=' <<<"$tree"; then
    emit AG63-gateway-no-child fail "no live pilot portal-session found during a transport"
  elif [ "$(grep -vc '^PID=' <<<"$tree")" -ne 0 ]; then
    emit AG63-gateway-no-child fail "pilot portal-session has child process(es): $tree"
  else
    emit AG63-gateway-no-child pass "pilot portal-session process(es) without any child: $(grep '^PID=' <<<"$tree" | tr '\n' ' ')"
  fi
}

probe_sftp() { # AG64
  local out
  out=$(as_ws "set -e; head -c 1048576 /dev/urandom > /tmp/$MARK.sftp.src
printf 'put /tmp/$MARK.sftp.src /tmp/$MARK.sftp\nrename /tmp/$MARK.sftp /tmp/$MARK.sftp.moved\nls -l /tmp/$MARK.sftp.moved\nget /tmp/$MARK.sftp.moved /tmp/$MARK.sftp.back\nrm /tmp/$MARK.sftp.moved\n' > /tmp/$MARK.batch
sftp -F $CFG -b /tmp/$MARK.batch $TARGET_FQDN >/dev/null
a=\$(sha256sum < /tmp/$MARK.sftp.src); b=\$(sha256sum < /tmp/$MARK.sftp.back); [ \"\$a\" = \"\$b\" ] && echo SAME || echo DIFF
$TSSH $TARGET_FQDN 'test -e /tmp/$MARK.sftp.moved && echo STILL-THERE || echo REMOVED'" 2>&1)
  local on_gateway
  on_gateway=$(on_gw "find / -xdev -name '$MARK*' 2>/dev/null | head -3")
  if grep -qx SAME <<<"$out" && grep -qx REMOVED <<<"$out" && [ -z "$on_gateway" ]; then
    emit AG64-sftp pass "put/rename/stat/get/rm ok, checksum same, removed on target, nothing on gateway"
  else
    emit AG64-sftp fail "out=[$out] on-gateway=[$on_gateway]"
  fi
}

probe_scp() { # AG65
  local out
  out=$(as_ws "set -e; head -c 8388608 /dev/urandom > /tmp/$MARK.scp.src
scp -q -F $CFG /tmp/$MARK.scp.src $TARGET_FQDN:/tmp/$MARK.scp
scp -q -F $CFG $TARGET_FQDN:/tmp/$MARK.scp /tmp/$MARK.scp.back
a=\$(sha256sum < /tmp/$MARK.scp.src); b=\$(sha256sum < /tmp/$MARK.scp.back); [ \"\$a\" = \"\$b\" ] && echo SAME || echo DIFF" 2>&1)
  if grep -qx SAME <<<"$out"; then emit AG65-scp pass "8 MiB up + down, checksum same"; else emit AG65-scp fail "$out"; fi
}

probe_rsync() { # AG66
  local out
  out=$(as_ws "set -e; mkdir -p /tmp/$MARK.tree/a/b; echo one > /tmp/$MARK.tree/a/one; echo two > /tmp/$MARK.tree/a/b/two
head -c 67108864 /dev/urandom > /tmp/$MARK.tree/big.bin
rsync -a -e 'ssh -F $CFG' /tmp/$MARK.tree/ $TARGET_FQDN:/tmp/$MARK.tree/
l=\$(cd /tmp/$MARK.tree && find . -type f -exec sha256sum {} + | sort)
r=\$($TSSH $TARGET_FQDN 'cd /tmp/$MARK.tree && find . -type f -exec sha256sum {} + | sort')
[ \"\$l\" = \"\$r\" ] && echo SAME || echo DIFF" 2>&1)
  if grep -qx SAME <<<"$out"; then emit AG66-rsync pass "tree + 64 MiB file, per-file sha256 identical"; else emit AG66-rsync fail "$out"; fi
}

probe_known_hosts() { # AG67
  local before after out bad
  before=$(as_ws "find ~/.ssh ~/.pilot-e2e -name 'known_hosts*' ! -name gateway_known_hosts -exec sha256sum {} + 2>/dev/null | sort")
  out=$(as_ws "$TSSH $TARGET_FQDN 'echo kh-ok' 2>&1")
  after=$(as_ws "find ~/.ssh ~/.pilot-e2e -name 'known_hosts*' ! -name gateway_known_hosts -exec sha256sum {} + 2>/dev/null | sort")
  if grep -qx kh-ok <<<"$out" && [ "$before" = "$after" ]; then
    emit AG67-freeipa-host-key pass "StrictHostKeyChecking yes + /dev/null known_hosts + KnownHostsCommand: connected, no known_hosts file written"
  else
    emit AG67-freeipa-host-key fail "out=[$out] known_hosts before/after differ: [$before] vs [$after]"
  fi
  bad=$(as_ws "k=\$(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub); $TSSH -o \"KnownHostsCommand=/bin/echo %h \$k\" $TARGET_FQDN true 2>&1")
  if grep -q 'Host key verification failed' <<<"$bad"; then
    emit AG67-wrong-host-key-refused pass "$(grep -m1 'Host key' <<<"$bad")"
  else
    emit AG67-wrong-host-key-refused fail "$bad"
  fi
}

probe_grammar_real_sshd() { # AG70
  local start fails=0 details="" out
  start=$(on_tgt "date +%s")
  for t in "10.0.0.1" "$TARGET_FQDN:22" "$PORTAL_USER@$TARGET_FQDN" "x;id.example.internal" "-oProxyCommand=x"; do
    out=$(as_ws "ssh -F $CFG -T pilot-gw -- pilot-transport-v1 $(printf %q "$t") </dev/null 2>&1; echo rc=\$?")
    if grep -q 'rc=0' <<<"$out" || ! grep -q 'pilot-transport: usage:' <<<"$out"; then
      fails=$((fails + 1)); details+="[$t => $out] "
    fi
  done
  out=$(as_ws "ssh -F $CFG -T pilot-gw -- pilot-transport-v1 $OUT_OF_SCOPE_FQDN </dev/null 2>&1; echo rc=\$?")
  if grep -q 'rc=0' <<<"$out" || ! grep -q 'pilot-transport: access denied' <<<"$out"; then
    fails=$((fails + 1)); details+="[wrong-scope $OUT_OF_SCOPE_FQDN => $out] "
  fi
  local seen
  seen=$(on_tgt "journalctl -u ssh --since @$start --no-pager 2>/dev/null | grep -c 'from $GATEWAY_HOST' || true")
  if [ "$fails" -eq 0 ] && [ "${seen:-0}" -eq 0 ]; then
    emit AG70-grammar-and-scope-real-sshd pass "IP, host:22, user@host, shell metachar, option injection -> usage; out-of-scope -> access denied; target sshd saw 0 connections from the gateway"
  else
    emit AG70-grammar-and-scope-real-sshd fail "failures=$fails target-connections-from-gateway=$seen $details"
  fi
}

probe_audit() { # AG71 (run after at least one successful and one denied transport)
  local since=$1 lines
  lines=$(on_gw "journalctl -t pilot-access-gateway --since @$since --no-pager -o cat 2>/dev/null")
  python3 - "$lines" "$MARK" <<'PY'
import json, sys
raw, mark = sys.argv[1], sys.argv[2]
evs = []
for l in raw.splitlines():
    l = l.strip()
    if l.startswith('{'):
        try: evs.append(json.loads(l))
        except ValueError: pass
by = {}
for e in evs:
    by.setdefault(e.get('session_id'), []).append(e)
ok_session = None
for sid, es in by.items():
    kinds = [e['kind'] for e in es]
    closed = [e for e in es if e['kind'] == 'gateway_transport_closed']
    if kinds[:1] == ['gateway_transport_requested'] and 'gateway_transport_connected' in kinds and closed:
        c = closed[-1]
        if c.get('target_ip') and c.get('bytes_client_to_target', 0) > 0 and c.get('bytes_target_to_client', 0) > 0 and 'duration_ms' in c:
            ok_session = (sid, c)
            break
denied = [e for e in evs if e['kind'] == 'gateway_transport_denied']
leak = mark in raw
if ok_session and denied and not leak:
    sid, c = ok_session
    print("PASS session=%s target=%s ip=%s c2t=%s t2c=%s ms=%s; denied=%d (%s)" % (
        sid, c.get('target_fqdn'), c.get('target_ip'), c.get('bytes_client_to_target'),
        c.get('bytes_target_to_client'), c.get('duration_ms'), len(denied), denied[-1].get('result')))
else:
    print("FAIL ok_session=%s denied=%d leak=%s events=%d" % (bool(ok_session), len(denied), leak, len(evs)))
PY
}

# pilot-connect through the gateway with the session-scoped Kerberos
# password, landing in the target shell (legacy path, AG72/AG69).
# pilot-connect's session id is a caller-chosen UUID; a fixed one lets the
# AG69 watcher find that session's FileSink file on the gateway.
CONNECT_SID=0d33c638-83fa-4d77-9811-a97a7a7af1d5
run_pilot_connect() {
  local marker=$1 hold=${2:-0} leave="exit"
  # hold > 0 keeps the target shell open for that many seconds after the
  # marker, so a gateway-side check can see files that only exist while the
  # portal user is logged in (/run/user/<uid> is removed at logout).
  [ "$hold" -gt 0 ] && leave="sleep $hold; exit"
  PORTAL_PASSWORD="$PORTAL_PASSWORD" expect -f - <<EOF 2>&1
set timeout 45
log_user 1
spawn ssh -tt -i $PORTAL_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $PORTAL_USER@$GATEWAY_HOST -- pilot-connect $CONNECT_SID $TARGET_FQDN
expect {
  "Kerberos password" { send "\$env(PORTAL_PASSWORD)\r" }
  timeout { puts "NO-PASSWORD-PROMPT"; exit 1 }
}
expect {
  -re {[\$#] $} {}
  timeout { puts "NO-TARGET-PROMPT"; exit 1 }
}
send {echo $marker-\$(whoami)-\$(hostname -f)}
send "\r"
expect {
  "$marker-$PORTAL_USER-$TARGET_FQDN" {}
  timeout { puts "NO-MARKER"; exit 1 }
}
send "$leave\r"
expect eof
EOF
}

# AG69: poll the gateway for pilot-connect's local FileSink file
# (<runtime dir>/pilot-session-recordings/<session>.ndjson) until its decoded
# terminal output contains the marker. Prints "FILE <path> <owner> <mode>
# <events>" or "NO-FILE".
watch_recording_file() {
  local marker=$1
  on_gw "bash -s -- $CONNECT_SID $(printf %q "$marker")" <<'EOS'
sid=$1 marker=$2
for _ in $(seq 1 90); do
  for f in /run/user/*/pilot-session-recordings/$sid.ndjson /tmp/pilot-session-recordings/$sid.ndjson; do
    [ -f "$f" ] || continue
    n=$(python3 - "$f" "$marker" <<'PY'
import base64, json, sys
data, events = b"", 0
for line in open(sys.argv[1]):
    events += 1
    data += base64.b64decode(json.loads(line).get("data_base64", ""))
print(events if sys.argv[2].encode() in data else "")
PY
)
    if [ -n "$n" ]; then echo "FILE $(stat -c '%n %U %a' "$f") $n"; exit 0; fi
  done
  sleep 0.5
done
echo NO-FILE
EOS
}

probe_pilot_connect() { # AG72 (legacy one-shot connect still works)
  local id=$1
  if [ -z "$PORTAL_KEY" ] || [ -z "${PORTAL_PASSWORD:-}" ] || ! command -v expect >/dev/null 2>&1; then
    emit "$id" skip "PORTAL_KEY/PORTAL_PASSWORD/expect not available"
    return
  fi
  local out
  out=$(run_pilot_connect "PC-$MARK")
  if grep -q "PC-$MARK-$PORTAL_USER-$TARGET_FQDN" <<<"$out"; then
    emit "$id" pass "pilot-connect -> Kerberos password -> target shell as $PORTAL_USER on $TARGET_FQDN"
  else
    emit "$id" fail "$(tail -c 600 <<<"$out")"
  fi
}

probe_portal_tty() { # AG72/AG73 (interactive Portal still renders with a TTY)
  local id=$1
  if [ -z "$PORTAL_KEY" ]; then emit "$id" skip "PORTAL_KEY unset"; return; fi
  local tmp out
  tmp=$(mktemp)
  timeout 20 script -qfc "stty cols 120 rows 40; ssh -tt -i $PORTAL_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes $PORTAL_USER@$GATEWAY_HOST" "$tmp" </dev/null >/dev/null 2>&1
  out=$(python3 -c 'import re,sys;t=open(sys.argv[1],"rb").read().decode("utf-8","replace");t=re.sub(r"\x1b\[[0-9;?>=<]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b.","",t);print(" ".join(l.strip() for l in re.split(r"[\r\n]+",t) if l.strip()))' "$tmp")
  rm -f "$tmp"
  if grep -q 'Pilot Portal' <<<"$out" && grep -q "User $PORTAL_USER" <<<"$out" && grep -q 'My Hosts' <<<"$out"; then
    emit "$id" pass "Portal TUI rendered for $PORTAL_USER"
  else
    emit "$id" fail "$(tail -c 400 <<<"$out")"
  fi
}

probe_transport_denied() { # AG62/AG68/AG69a/AG73
  local id=$1 want=$2 out
  out=$(as_ws "ssh -F $CFG -T pilot-gw -- pilot-transport-v1 $TARGET_FQDN </dev/null 2>&1; echo rc=\$?")
  if ! grep -q 'rc=0' <<<"$out" && grep -q "$want" <<<"$out"; then
    emit "$id" pass "$(tr '\n' ' ' <<<"$out")"
  else
    emit "$id" fail "want [$want]: $out"
  fi
}

ready_member() { # prints MEMBER or NOT-MEMBER, via the gateway's own service principal
  on_gw "export KRB5CCNAME=FILE:/tmp/e2e-svc-cc; kinit -kt /etc/pilot/pilot-access-gateway.keytab pilot-access-gateway/$GATEWAY_FQDN >/dev/null 2>&1; ipa hostgroup-show pilot-transport-ready 2>&1 | grep -qw '$TARGET_FQDN' && echo MEMBER || echo NOT-MEMBER; kdestroy >/dev/null 2>&1"
}

start_listener() {
  local up
  up=$(on_tgt "pkill -f '^python3 -m http.server $LPORT' ; cd /tmp && (setsid python3 -m http.server $LPORT --bind 127.0.0.1 >/dev/null 2>&1 < /dev/null &) ; sleep 1; ss -ltn | grep -c '127.0.0.1:$LPORT '")
  [ "${up:-0}" -ge 1 ] || emit loopback-listener fail "could not start the target loopback listener on 127.0.0.1:$LPORT"
}

# fwd_probe <id> <want: works|refused> <ssh forwarding flags...> -- <curl args...>
fwd_probe() {
  local id=$1 want=$2; shift 2
  local sflags=() cargs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do sflags+=("$1"); shift; done
  shift
  cargs=("$@")
  local out
  out=$(as_ws "log=/tmp/$MARK.fwd.log; $TSSH -v -o ExitOnForwardFailure=no -N ${sflags[*]} $TARGET_FQDN >\$log 2>&1 & sp=\$!; sleep 4
code=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 ${cargs[*]} || true); sleep 2
if [ \"\$code\" != 200 ] && ! grep -qi 'administratively prohibited' \$log; then code=\$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 ${cargs[*]} || true); sleep 2; fi
kill \$sp 2>/dev/null; sleep 1
echo HTTP=\$code; grep -m1 -iE 'administratively prohibited|open failed' \$log || true")
  local code
  code=$(sed -n 's/^HTTP=//p' <<<"$out")
  if [ "$want" = works ] && [ "$code" = 200 ]; then
    emit "$id" pass "HTTP 200 through the forward"
  elif [ "$want" = refused ] && [ "$code" != 200 ] && grep -qi 'administratively prohibited' <<<"$out"; then
    emit "$id" pass "server refused the channel: $(grep -m1 -i 'administratively prohibited' <<<"$out")"
  else
    emit "$id" fail "want $want: $(tr '\n' ' ' <<<"$out")"
  fi
}

probe_remote_forward_refused() {
  local id=$1 out
  out=$(as_ws "timeout 20 $TSSH -o ExitOnForwardFailure=yes -N -R 19183:127.0.0.1:22 $TARGET_FQDN 2>&1; echo rc=\$?")
  if grep -q 'remote port forwarding failed' <<<"$out"; then
    emit "$id" pass "$(grep -m1 'remote port forwarding failed' <<<"$out")"
  else
    emit "$id" fail "$out"
  fi
}

probe_tunnel_refused() { # TP07 -w
  # An unprivileged ssh cannot create a tun device ("Tunnel device open
  # failed", a client-side failure that proves nothing about the target), so
  # root pre-creates one owned by WS_USER; the only remaining refusal is the
  # target sshd's own.
  local id=$1 out
  on_ws "ip tuntap add dev tun97 mode tun user $WS_USER" >/dev/null 2>&1
  out=$(as_ws "$TSSH -v -o ExitOnForwardFailure=yes -w 97:any $TARGET_FQDN echo TUNNEL-SESSION-RAN 2>&1; echo rc=\$?")
  on_ws "ip tuntap del dev tun97 mode tun" >/dev/null 2>&1
  if grep -q 'Server has rejected tunnel device forwarding' <<<"$out" && ! grep -q '^TUNNEL-SESSION-RAN' <<<"$out" && ! grep -q '^rc=0' <<<"$out"; then
    emit "$id" pass "$(grep -E 'Server has rejected|Tunnel forwarding failed|^rc=' <<<"$out" | tr -d '\r' | tr '\n' ' ')"
  else
    emit "$id" fail "$(grep -i -E 'tun|rejected|^rc=' <<<"$out" | tail -6 | tr -d '\r' | tr '\n' ' ')"
  fi
}

# ---- phases -------------------------------------------------------------------
PHASE_START=$(on_gw "date +%s")
case "$PHASE" in
  strict)
    probe_direct_blocked
    probe_ssh_via_transport
    probe_no_child
    probe_sftp
    probe_scp
    probe_rsync
    probe_known_hosts
    probe_grammar_real_sshd
    r=$(ready_member); [ "$r" = MEMBER ] && emit TP06-ready-member pass "$TARGET_FQDN is in pilot-transport-ready" || emit TP06-ready-member fail "$r"
    start_listener
    fwd_probe TP07-local-forward-loopback-refused refused -L 127.0.0.1:19181:localhost:$LPORT -- http://127.0.0.1:19181/
    fwd_probe TP07-dynamic-forward-refused refused -D 127.0.0.1:19182 -- --socks5-hostname 127.0.0.1:19182 http://127.0.0.1:$LPORT/
    probe_remote_forward_refused TP07-remote-forward-refused
    out=$(as_ws "eval \$(ssh-agent -s) >/dev/null; ssh-add -q ~/.ssh/id_ed25519 2>/dev/null; $TSSH -A $TARGET_FQDN 'echo AUTH_SOCK=\${SSH_AUTH_SOCK:-none}' 2>&1; ssh-agent -k >/dev/null")
    grep -qx 'AUTH_SOCK=none' <<<"$out" && emit TP07-agent-forward-refused pass "SSH_AUTH_SOCK absent on the target despite -A" || emit TP07-agent-forward-refused fail "$out"
    out=$(as_ws "DISPLAY=:99 $TSSH -X $TARGET_FQDN 'echo DISPLAY=\${DISPLAY:-none}' 2>&1")
    grep -qx 'DISPLAY=none' <<<"$out" && emit TP07-x11-forward-refused pass "DISPLAY unset on the target despite -X: $(grep -m1 -i x11 <<<"$out" || true)" || emit TP07-x11-forward-refused fail "$out"
    probe_tunnel_refused TP07-tunnel-forward-refused
    # TP09: a non-gateway session (controller as root, direct) keeps the baseline.
    out=$(on_tgt true >/dev/null; ssh -i "$TARGET_ADMIN_KEY" "${ADMIN_OPTS[@]}" -o ExitOnForwardFailure=yes -N -L 127.0.0.1:19184:localhost:$LPORT "root@$TARGET_HOST" & sp=$!; sleep 3; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:19184/ || true); kill $sp 2>/dev/null; echo "$code")
    [ "$out" = 200 ] && emit TP09-non-gateway-unaffected pass "direct (non-gateway) -L to target loopback still works: HTTP 200" || emit TP09-non-gateway-unaffected fail "HTTP=$out"
    # one deliberately denied transport so the audit window has a denied event
    as_ws "ssh -F $CFG -T pilot-gw -- pilot-transport-v1 $OUT_OF_SCOPE_FQDN </dev/null >/dev/null 2>&1" || true
    res=$(probe_audit "$PHASE_START")
    case "$res" in PASS*) emit AG71-audit-journald pass "${res#PASS }" ;; *) emit AG71-audit-journald fail "$res" ;; esac
    probe_portal_tty AG72-portal-tty
    probe_pilot_connect AG72-pilot-connect
    ;;
  remote-dev)
    probe_ssh_via_transport
    start_listener
    fwd_probe TP08-local-forward-loopback-works works -L 127.0.0.1:19181:localhost:$LPORT -- http://127.0.0.1:19181/
    fwd_probe TP08-dynamic-forward-loopback-works works -D 127.0.0.1:19182 -- --socks5-hostname 127.0.0.1:19182 http://127.0.0.1:$LPORT/
    fwd_probe TP08-local-forward-non-loopback-refused refused -L 127.0.0.1:19185:$OUT_OF_SCOPE_FQDN:443 -- -k https://127.0.0.1:19185/
    probe_remote_forward_refused TP08-remote-forward-refused
    ;;
  recording)
    probe_transport_denied AG69-transport-denied-by-recording 'pilot-transport: transport disabled by recording policy'
    out=$(as_ws "ssh -F $CFG -T pilot-gw -- pilot-known-hosts-v1 $TARGET_FQDN </dev/null 2>&1; echo rc=\$?")
    ! grep -q 'rc=0' <<<"$out" && grep -q 'pilot-known-hosts: access denied' <<<"$out" && emit AG69-known-hosts-denied-by-recording pass "$(tr '\n' ' ' <<<"$out")" || emit AG69-known-hosts-denied-by-recording fail "$out"
    if [ -z "$PORTAL_KEY" ] || [ -z "${PORTAL_PASSWORD:-}" ]; then
      emit AG69-pilot-connect-still-records skip "PORTAL_KEY/PORTAL_PASSWORD unset"
    else
      since=$(on_gw "date +%s")
      wtmp=$(mktemp)
      watch_recording_file "RC-$MARK-$PORTAL_USER-$TARGET_FQDN" >"$wtmp" 2>&1 &
      wpid=$!
      out=$(run_pilot_connect "RC-$MARK" 10)
      wait "$wpid"
      file=$(tail -1 "$wtmp"); rm -f "$wtmp"
      started=$(on_gw "journalctl -t pilot-access-gateway --since @$since --no-pager -o cat | grep -c '\"kind\":\"recording_started\"' || true")
      if grep -q "RC-$MARK-$PORTAL_USER-$TARGET_FQDN" <<<"$out" && [ "${started:-0}" -ge 1 ] && [ "${file%% *}" = FILE ]; then
        emit AG69-pilot-connect-still-records pass "recorded pilot-connect reached the target shell; recording_started events=$started; ${file#FILE } (path owner mode events), output marker found in the decoded file"
      else
        emit AG69-pilot-connect-still-records fail "recording_started=$started file=[$file] out=$(tail -c 400 <<<"$out")"
      fi
    fi
    ;;
  not-ready)
    probe_transport_denied AG68-transport-denied-not-ready 'pilot-transport: transport not enabled for this target'
    out=$(as_ws "ssh -F $CFG -T pilot-gw -- pilot-known-hosts-v1 $TARGET_FQDN </dev/null 2>&1; echo rc=\$?")
    ! grep -q 'rc=0' <<<"$out" && grep -q 'pilot-known-hosts: access denied' <<<"$out" && emit AG68-known-hosts-denied-not-ready pass "$(tr '\n' ' ' <<<"$out")" || emit AG68-known-hosts-denied-not-ready fail "$out"
    r=$(ready_member); [ "$r" = NOT-MEMBER ] && emit TP06-ready-not-member pass "$TARGET_FQDN is not in pilot-transport-ready" || emit TP06-ready-not-member fail "$r"
    out=$(on_tgt "ls /etc/ssh/sshd_config.d/ | grep -c pilot-access-target-policy; sshd -t && echo SSHD-OK")
    [ "$(head -1 <<<"$out")" = 0 ] && grep -q SSHD-OK <<<"$out" && emit TP10-absent-clean pass "no pilot-access-target-policy file left under sshd_config.d; sshd -t ok" || emit TP10-absent-clean fail "$out"
    ;;
  disabled)
    probe_transport_denied AG73-transport-denied-disabled 'pilot-transport: transport not enabled for this target'
    out=$(on_gw "grep -A1 '^  transport:' /etc/pilot/access-gateway.yaml")
    grep -q 'enabled: false' <<<"$out" && emit AG73-config-disabled pass "$(tr '\n' ' ' <<<"$out")" || emit AG73-config-disabled fail "$out"
    probe_portal_tty AG73-portal-tty
    probe_pilot_connect AG73-pilot-connect
    ;;
esac

echo "SUMMARY phase=$PHASE: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped" >&2
[ "$FAIL_COUNT" -eq 0 ]
