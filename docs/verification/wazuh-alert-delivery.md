# Verification Spec — Wazuh alert delivery

Acceptance contract for fresh real Wazuh alerts reaching the designated receiver.
Actual-run outcomes are recorded in [current evidence](../evidence/wazuh-manager/LATEST.md).

## Acceptance contract

The controller uses its existing Ansible inventory connection to orchestrate a fresh
challenge across the selected `wazuh-manager` and `log-server` hosts. No new SSH trust
is installed between targets. The fixture writes a unique nonce and timestamp to a
root-owned receiver challenge under `/run`, then appends a realistic sshd failure
message to the already monitored manager `active-responses.log`. The live Wazuh analysis engine must emit
an `alerts.json` record containing that nonce (wazuh-logtest is insufficient).

The receiver checks its actual configured `siem_log_root` output for the exact nonce
in a JSON alert retaining `rule.id`, `agent.id`, and `full_log`. A challenge is valid
only within 180 seconds. Missing, malformed, stale or previously used challenges
fail closed. A new challenge is required for every trial; stale historical alerts
cannot satisfy a different challenge. The receiver check waits at most 45 seconds
for delivery, consumes the challenge, and returns a failure when transport is blocked.

After a healthy RELP receiver becomes ready following its restart, the first single
real engine alert must meet that same 45-second deadline without a second engine
alert, operator wakeup, sender restart, or queue deletion. The production sender
supplies fixed five-second native marks to its existing Wazuh action/client/queue
so a quiet stream can process replies and reconnect autonomously. These reserved
transport markers never become engine alerts or receiver log records. A valid JSON
alert containing the marker text in `full_log` remains an alert and must be stored.

Wazuh manager C11 verifies the local ingestion/transport configuration and loaded
service; this cross-host spec is the delivery oracle. Both checks are required when
forwarding is configured. Optional standalone deployments omit the delivery cross-check.

## 1. Targets

| Group | Target |
|-------|--------|
| `log-server` | Designated receiver; the fixture selects exactly one receiver and one manager from the actual inventory |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | functional | A newly generated real Wazuh alert reaches the designated receiver file before the fresh challenge expires | 0 | sh -c '/usr/local/libexec/pilot-wazuh-delivery delivery && echo 0 || echo 1' |

The fixture must run before each verification, including blocked and
recovery trials. Consuming a challenge prevents replay across separate verifies.
Missing fixture/challenge is a failure, never a skipped or assumed success.

## Scope and boundaries

Transport is host rsyslog imfile → TCP or authenticated RELP/mTLS → the existing
log-server receiver ruleset → `<siem_log_root>/<manager hostname>/wazuh-alerts.log`.
The dedicated Wazuh ruleset never enters the audit/auth forwarding rules. TCP has
no durable end-to-end acknowledgement and may duplicate the last message after
reconnect; RELP retains the existing authenticated transport requirements. The
independent capped queue preserves pending records across graceful rsyslog restarts.

Required target evidence: fresh Ubuntu check/apply/verify/idempotency; generated
real alert; positive/blocked/recovered delivery; rotation and manager recreation;
colocation without self-forward loops; optional forwarding disabled; native parser
and failure rollback; RELP security and existing audit/auth regression coverage.
Also require the single-alert quiet receiver-restart arm, marker exclusion, foreign
immark refusal, loaded-state restoration, and TCP/disabled heartbeat retirement.

Current immutable candidate evidence: [latest](../evidence/wazuh-manager/LATEST.md).
