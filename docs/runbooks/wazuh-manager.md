# Runbook — Wazuh manager and central alert delivery

## 0. Goal

Deploy the official Wazuh single-node Docker stack on Ubuntu 24.04, and optionally
send its real JSON alerts to the central log-server over host rsyslog TCP or
RELP/mTLS. The acceptance contracts are [manager](../verification/wazuh-manager.md)
and [real alert delivery](../verification/wazuh-alert-delivery.md).

## 0.5 Current facts and evidence

Issue #211 development validation passed all 23 rows and second apply changed=0.
A native source-scoped transport block left the local C11 healthy while the
fresh-nonce receiver row failed; delivery recovered after the block was removed.
These development results do not replace the final immutable candidate evidence.

The dedicated reference topology is
[wazuh-alert-delivery-topology.yaml](../topologies/wazuh-alert-delivery-topology.yaml):
one Ubuntu manager in `docker` / `wazuh-manager` and one receiver in `log-server` /
`audit-log-forwarding`. Read the actual rendered inventory before each run. The
alignment decision is A: provision this declared disposable topology; never infer
host membership from the spec alone. The manager requires 4 vCPU / 8GiB RAM /
60GiB disk; the receiver requires 2 vCPU / 2GiB RAM / 20GiB disk.

TCP mode needs no forwarding secrets. RELP mode requires CA, client/server
certificates and private keys from private deployment inputs, explicit peer DNS
names, and matching sender/receiver ports. Never print secret values.

Current immutable revision, tree, target facts and PASS/FAIL totals belong in the
[current evidence](../evidence/wazuh-manager/LATEST.md), not historical transcripts
inside this runbook. Existing July delivery anecdotes do not verify the repaired
pipeline.

## 1. Delivery behavior

The actual Docker `/var/ossec/logs` mount Source supplies
`alerts/alerts.json` to host rsyslog imfile. A dedicated local5/tag/ruleset forwards
only that input to the selected destination. The receiver writes JSON records to
`<siem_log_root>/<manager hostname>/wazuh-alerts.log`, under the existing retention
policy. Network input remains in its isolated receiver ruleset, preventing
colocated senders from forwarding their own received messages indefinitely.

The manager's optional destination follows the shared `siem_forward_host` contract:
an inventory log-server supplies the default. Without a destination and without
that dependency, the local manager/indexer/dashboard remain usable and the
managed forwarding reader is disabled. The previous managed UDP `syslog_output`
is removed on migration or disable; operator-owned outputs are preserved.

TCP uses `siem_forward_port` / `siem_receiver_tcp_port` (default 514). RELP uses
`siem_relp_port` (default 20514) with mandatory mTLS. A RELP-enabled receiver binds
its legacy TCP listener to loopback, so remote senders must select RELP. No
outbound Wazuh UDP514 path or new UDP firewall opening is used.

## 2. Apply and verify

The integrated test wrapper is
[playbooks/test/wazuh-alert-delivery.yml](../../playbooks/test/wazuh-alert-delivery.yml).
It installs manager Docker, the receiver, receiver audit/auth self-forwarding,
Wazuh manager, and the real-alert diagnostic fixture. Use an immutable candidate
and the sanctioned fresh topology test chain for check/apply/verify/idempotency.
The chain verifies manager, receiver and cross-host delivery specs on their
actual inventory groups; its immutable result is linked above.

C1–C9 prove the local Wazuh stack; C10/C11 prove the local loaded forwarding
configuration and source readability. **C11 alone is insufficient proof of
delivery.** The controller fixture creates a fresh receiver nonce challenge,
emits a real manager alert, and confirms that it exists in alerts.json. The
receiver delivery spec then waits for that exact nonce in the actual JSON output
file. It consumes the challenge whether the trial passes or fails. Each normal,
blocked or recovery trial needs a new challenge. No target-to-target SSH trust or
controller-generated PASS receipt is used.

## 3. Recovery and limitations

The apply snapshots managed configuration and narrow ACLs before mutation. Its
rescue restores captured state and reloads the affected services. Topology test
also snapshots and rolls back its own disposable targets on failure. Inspect the
original failed task and verify service availability after any recovery.

The reader uses execute-only traversal ACLs on required Docker ancestors, read
access to the alert file, inherited ACLs for rotation, and an exact-source
AppArmor grant. It never makes Docker directories world-readable. Forwarding on
SELinux is currently rejected rather than relabelling the Docker data tree;
standalone manager deployment remains available.

The reader keeps independent offsets and a bounded 256MiB disk-assisted queue.
First installation can replay the current alert file. TCP can lose in-flight
messages or duplicate the last message after reconnect; select RELP when
acknowledged authenticated transport is required. Neither mode promises survival
of queue exhaustion or arbitrary abrupt host loss.

Keep adequate disk space: Wazuh can stop generating alerts when Docker data fills
while containers remain running. Official image default credentials must be
rotated before production. Manager configuration injection requires container
recreation; the official initialization path is unsafe to assume on a plain
restart.
