#!/usr/bin/env bash
# scripts/minimal-poc-section4-spotcheck.sh — repeatable §4.1/§4.2 read-only
# spot-check for docs/runbooks/minimal-poc-architecture.md.
#
# Scope, deliberately narrow: only the READ-ONLY assertions in §4.1 (FreeIPA
# authorization) and §4.2's `up` metric are covered here. §4.3 (trigger a
# backup, trigger a Wazuh FIM real-time alert) and §4.4 (mutate the roster,
# reconcile, restore) are NOT — those mutate state and/or drive `pilot
# reconcile`'s wizard, which this runbook verifies live via TREC every round
# on purpose (that is the actual thing being tested, not just its end state).
# Scripting those would replace the verification with the thing it's supposed
# to verify. See the runbook's own note above §4 for the reasoning.
#
# Assumes the topology is already up and the full site + freeipa-identity
# reconcile from §3.2-§3.5 already succeeded. Also assumes the active roster
# sets `hbac.disable_allow_all: true` (required by runbook §2 / §1's aligned
# contract) — otherwise IPA's shipped `allow_all` rule makes hbactest's
# top-level "Access granted" always True regardless of the per-rule result
# (see docs/runbooks/freeipa-identity.md's own note on this gotcha). This
# script trusts the top-level result under that assumption; it does not parse
# `Matched rules:`/`Not matched rules:`.
#
# Usage:
#   ALICE_PASSWORD='...' ./scripts/minimal-poc-section4-spotcheck.sh
#
# Required env:
#   ALICE_PASSWORD    — alice's current live password. Never pass this as an
#                       argv flag or under `set -x`; this script only ever
#                       exports it as SSHPASS for `sshpass -e`. See
#                       docs/evidence/minimal-poc-architecture/2026-07-23-round-15.md
#                       for the leak this discipline exists to prevent.
#
# Optional env (defaults match the current runbook §0.5/§2 roster contract):
#   TOPOLOGY          — topology spec (default docs/topologies/minimal-poc-topology.yaml)
#   FREEIPA_NODE      — vm-target name of the FreeIPA server (default freeipa-server)
#   NEXUS_NODE        — vm-target name of the combined nexus host (default nexus)
#   ALICE_USER        — allowed user (default alice)
#   BOB_USER          — denied user (default bob)
#   ALICE_SUDO_CMD    — the roster-authorized sudo command to prove works
#                       (default: /usr/bin/systemctl status sshd — this MUST
#                       match whatever the *current* roster's sudo rule
#                       actually grants; it is not derivable from the roster
#                       automatically)
#   ALICE_DENIED_CMD  — an unlisted command to prove is refused (default: cat /etc/shadow)
#   THANOS_SITE_LABEL — site label to query (default site-nexus, matches
#                       host_vars/nexus.yml's prometheus_site_label)
#   THANOS_PORT       — Thanos Query port on nexus (default 10912)
#
# Output: one JSON line per check on stdout (id/status/detail); a one-line
# summary on stderr. Exit 0 only if every check passed.

set -uo pipefail

TOPOLOGY="${TOPOLOGY:-docs/topologies/minimal-poc-topology.yaml}"
FREEIPA_NODE="${FREEIPA_NODE:-freeipa-server}"
NEXUS_NODE="${NEXUS_NODE:-nexus}"
ALICE_USER="${ALICE_USER:-alice}"
BOB_USER="${BOB_USER:-bob}"
ALICE_SUDO_CMD="${ALICE_SUDO_CMD:-/usr/bin/systemctl status sshd}"
ALICE_DENIED_CMD="${ALICE_DENIED_CMD:-cat /etc/shadow}"
THANOS_SITE_LABEL="${THANOS_SITE_LABEL:-site-nexus}"
THANOS_PORT="${THANOS_PORT:-10912}"

if [ -z "${ALICE_PASSWORD:-}" ]; then
  echo "ERROR: ALICE_PASSWORD is required (alice's current live password)." >&2
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

NEXUS_IP="$(./pilot vm-target topology status --topology "$TOPOLOGY" | awk -v n="$NEXUS_NODE" '$1==n {print $3}')"
if [ -z "$NEXUS_IP" ]; then
  emit setup fail "could not resolve IP for node '$NEXUS_NODE' from 'topology status' (check the output format hasn't changed)"
  echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >&2
  exit 1
fi

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=no
          -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=8)

# --- §4.1 FreeIPA authorization ---

out=$(./pilot vm-target exec --name "$FREEIPA_NODE" -- ipa hbactest --user="$ALICE_USER" --host="${NEXUS_NODE}.ipa.pilot.internal" --service=sshd 2>&1)
if grep -q "Access granted: True" <<<"$out"; then
  emit 4.1-hbactest-alice-sshd pass "hbactest grants $ALICE_USER sshd on $NEXUS_NODE"
else
  emit 4.1-hbactest-alice-sshd fail "expected Access granted: True; got: $out"
fi

out=$(./pilot vm-target exec --name "$FREEIPA_NODE" -- ipa hbactest --user="$ALICE_USER" --host="${NEXUS_NODE}.ipa.pilot.internal" --service=sudo 2>&1)
if grep -q "Access granted: True" <<<"$out"; then
  emit 4.1-hbactest-alice-sudo pass "hbactest grants $ALICE_USER sudo on $NEXUS_NODE"
else
  emit 4.1-hbactest-alice-sudo fail "expected Access granted: True; got: $out"
fi

out=$(./pilot vm-target exec --name "$FREEIPA_NODE" -- ipa hbactest --user="$BOB_USER" --host="${NEXUS_NODE}.ipa.pilot.internal" --service=sshd 2>&1)
if grep -q "Access granted: False" <<<"$out"; then
  emit 4.1-hbactest-bob-sshd pass "hbactest denies $BOB_USER sshd on $NEXUS_NODE"
else
  emit 4.1-hbactest-bob-sshd fail "expected Access granted: False; got: $out"
fi

out=$(SSHPASS="$ALICE_PASSWORD" sshpass -e ssh "${SSH_OPTS[@]}" "${ALICE_USER}@${NEXUS_IP}" "sudo -n -l" 2>&1)
rc=$?
if [ $rc -eq 0 ]; then
  emit 4.1-alice-sudo-list pass "$out"
else
  emit 4.1-alice-sudo-list fail "$out"
fi

out=$(SSHPASS="$ALICE_PASSWORD" sshpass -e ssh "${SSH_OPTS[@]}" "${ALICE_USER}@${NEXUS_IP}" "sudo -n $ALICE_SUDO_CMD" 2>&1)
rc=$?
if [ $rc -eq 0 ]; then
  emit 4.1-alice-allowed-cmd pass "sudo -n $ALICE_SUDO_CMD succeeded for $ALICE_USER"
else
  emit 4.1-alice-allowed-cmd fail "sudo -n $ALICE_SUDO_CMD failed for $ALICE_USER (roster/sudo drift, or stale sssd cache — see runbook §6): $out"
fi

out=$(SSHPASS="$ALICE_PASSWORD" sshpass -e ssh "${SSH_OPTS[@]}" "${ALICE_USER}@${NEXUS_IP}" "sudo -n $ALICE_DENIED_CMD" 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
  emit 4.1-alice-denied-cmd pass "sudo -n $ALICE_DENIED_CMD correctly refused for $ALICE_USER"
else
  emit 4.1-alice-denied-cmd fail "sudo -n $ALICE_DENIED_CMD unexpectedly succeeded for $ALICE_USER: $out"
fi

out=$(SSHPASS="wrong-or-irrelevant-not-a-real-secret" sshpass -e ssh "${SSH_OPTS[@]}" "${BOB_USER}@${NEXUS_IP}" "whoami" 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
  emit 4.1-bob-login-denied pass "$BOB_USER login correctly refused"
else
  emit 4.1-bob-login-denied fail "$BOB_USER unexpectedly logged in: $out"
fi

# --- §4.2 Thanos `up` metric ---

thanos_out=$(./pilot vm-target exec --name "$NEXUS_NODE" -- curl -fsS "http://127.0.0.1:${THANOS_PORT}/api/v1/query?query=up" 2>&1)
value=""
if command -v python3 >/dev/null 2>&1; then
  value=$(printf '%s' "$thanos_out" | python3 -c '
import json, sys
label = sys.argv[1]
try:
    data = json.load(sys.stdin)
    for r in data.get("data", {}).get("result", []):
        if r.get("metric", {}).get("site") == label:
            print(r["value"][1])
            break
except Exception:
    pass
' "$THANOS_SITE_LABEL" 2>/dev/null)
elif grep -q "\"site\":\"$THANOS_SITE_LABEL\"" <<<"$thanos_out" && grep -q '"1"' <<<"$thanos_out"; then
  value=1
fi
if [ "$value" = "1" ]; then
  emit 4.2-thanos-up pass "up{site=\"$THANOS_SITE_LABEL\"} == 1"
else
  emit 4.2-thanos-up fail "up{site=\"$THANOS_SITE_LABEL\"} != 1 (got '$value'); raw: $thanos_out"
fi

echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >&2
[ "$FAIL_COUNT" -eq 0 ]
