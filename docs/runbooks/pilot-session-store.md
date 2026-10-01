# Runbook — Pilot Session Store upgrade to per-session ingest tokens, and rollback

> Status: VERIFIED
> Aligned spec: `docs/verification/pilot-session-store.md`,
> `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md` §21.3
> Automation: `playbooks/apply/pilot-session-store-apply.yml`
> Maintainer: SRE

## 0. Goal

Upgrade a running `pilot-session-store` from the static shared bearer token
and schema v1 to per-session PIT1 ingest tokens and schema v2 without losing
recordings. Keep a rollback that restores the previous binary, config and
database, and never leaves a host marked for recording being connected
unrecorded.

## 0.5 Current fact summary

| Item | Current verified value |
|---|---|
| Fact timestamp | 2026-10-01T16:30Z |
| Target type | Disposable KVM vm-target topology: a per-run copy of `docs/topologies/pilot-access-transport-topology.yaml` with `tx-` renamed `ys-` and a Directory node `ys-dir` added; every host in the inventory's `staging` group for the upgrade rehearsal |
| Inventory source | `pilot vm-target topology inventory` plus a `staging` group holding every host, read with `ansible-inventory --graph` before the upgrade |
| Actual targets | Session store `ys-store`, gateway `ys-gw` (`gpu-01` / `gpu`), Directory `ys-dir`, target `ys-target`, workstation `ys-ws` (Ubuntu 24.04); FreeIPA `ys-ipa` (AlmaLinux 9) |
| Vault keys (names only) | `ipa_admin_password`, `transport_fixture_user_password`, `pilot_session_store_master_key`, `pilot_session_store_ingest_signing_key`; for the previous revision and the rollback, `pilot_session_store_ingest_token` (disposable vault) |
| Previous revision used for rollback | `main` `56080a8` (schema v1, static bearer token, gateway recording `terminal_output` through a static token file) |
| Alignment | The store role group is the inventory's `pilot-session-store` group, as the spec's §1 target table expects |

Full results, candidate/tree and scenario verdicts are in the
[latest evidence record](../evidence/pilot-access-gateway/2026-10-01-fe5f9e0.md).

## 1. Scope and prerequisites

- The store host is an enrolled FreeIPA client with a forward DNS record
  (the ingest TLS certificate is issued with `ipa-getcert`).
- Both the store and every gateway that records to it get the same vault
  value `pilot_session_store_ingest_signing_key` (64 hex characters). The
  store verifies tokens with it; each gateway signs them. Neither the key nor
  a token is ever printed, logged or passed on a command line.
- Keep the previous `pilot_session_store_ingest_token` in the vault until the
  upgrade is confirmed. Rollback needs it.
- Deploy order: store before gateway. `playbooks/site.yml` already runs them
  in that order.

## 2. Upgrade procedure

1. Read the target inventory before anything else: `pilot vm-target
   show-inventory` for a vm-target, `ansible-inventory -i <inventory> --graph`
   for real hosts.
2. Apply the new store playbook. On the first start, the new binary finds a
   schema v1 database. It checks that the filesystem has at least twice the
   database's size free. Then, outside any transaction, it runs
   `VACUUM INTO index.db.pre-v1.bak` (0600, same owner). Only then does it
   migrate to v2 in one transaction, and logs one `index database migrated`
   line with `from_schema`, `to_schema` and `backup`. With too little
   space, or a backup file already present, it refuses to start and
   changes nothing.
3. Confirm the upgrade: the service is active, the backup exists, and an
   auditor can list and replay a recording made before the upgrade. On the
   store host:

   ```bash
   stat -c "%U:%G %a %n" /var/lib/pilot-session-store/index.db.pre-v1.bak
   runuser -u <auditor> -- /usr/bin/pilot session show <old-session-id>
   runuser -u <auditor> -- /usr/bin/pilot session replay --raw <old-session-id>
   ```

   `runuser` uses the auditor's cached group list. For an auditor added to
   `role-pilot-session-auditor` since their last login, use
   `su -s /bin/sh <auditor> -c '/usr/bin/pilot session list'` instead:
   `su` goes through the PAM account stack, which refreshes it.

   The playbook removes the former `/etc/pilot/session-store-ingest.token`.
4. Apply the gateway playbook with `pilot_access_gateway_recording_session_store_url` and the same
   signing key. Then set `ssh_recording` on hosts in `hosts.yml` and apply
   `freeipa-client`.
   - If the gateway already records (a previous revision with
     `pilot_access_gateway_recording_mode: terminal_output` and a static
     token file), keep that mode in group vars. Without it the apply stops
     at `Refusing to lower this gateway's session-recording policy` and
     changes nothing. The mode is the gateway default; `ssh_recording` on a
     host overrides it.
   - `pilot_access_gateway_recording_failure_policy` now defaults to
     `fail_closed` (it was `best_effort`). Set `best_effort` explicitly to
     keep the old behaviour.
   - The playbook installs the signing key (AG81) and removes the gateway's
     former static token file (AG82): the file the installed gateway config
     names in `recording.session_store_ingest_token_file` (the path the
     previous revision's `pilot_access_gateway_recording_session_store_ingest_token_file`
     set), the documented default `/etc/pilot/session-store-ingest-token`,
     and a path the inventory still sets in that variable. Before removing,
     it reads the installed config, so run the upgrade with the previous
     config still in place. It refuses a relative path, a path with `..`, or
     a directory, and removes nothing then. The variable itself is no longer
     used; when it is still set, the apply says so — drop it from the
     inventory.
5. After the upgrade is confirmed, delete `index.db.pre-v1.bak` by hand and
   remove the old token from the vault.

## 3. Verification

- `docs/verification/pilot-session-store.md`: SS24 (signing key
  `pilot-session-store:pilot-session-store 400`, legacy token absent) and
  SS26 (metrics textfile when node_exporter's textfile directory exists) are
  live rows; the rest are unit-test evidence.
- A recorded connect writes a session with `policy_source` and `last_seq`
  (`pilot session show <id>`).
- With `host-monitoring` on the store and gateway hosts, the Prometheus seed
  rules (`playbooks/apply/files/pilot-alert-rules-seed.yml`, group
  `pilot-session-recording`) alert on an incomplete recording, ingest 5xx,
  connects refused for recording reasons, and a store whose metrics
  stopped updating. Both processes start the alerted series at 0, so the
  first event after a restart alerts too.

## 4. Rollback

**Per-host recording is disabled for the whole rollback window.** The
previous gateway ignores `pilot.policy.*` markers, so a marked host would be
connected **without** recording. The operator doing the rollback must accept
that before starting.

1. Store: stop the service, then replace the database with the backup
   (drop the WAL and shared-memory files first):

   ```bash
   systemctl stop pilot-session-store
   cd /var/lib/pilot-session-store
   rm -f index.db-wal index.db-shm
   mv index.db.pre-v1.bak index.db
   ```

2. Re-apply `pilot-session-store-apply.yml` **from a checkout of the
   previous revision**, with the previous binaries and a vault that still
   holds `pilot_session_store_ingest_token`. This restores the old binary,
   the old `token_file` config and the token file. The old binary then
   opens the restored v1 database.
3. Remove every `ssh_recording` from `hosts.yml` and apply `freeipa-client`.
   Confirm that no `pilot.policy.ssh-recording=` value is left on any host
   (`ipa host-show <fqdn> --all --raw`).
4. Only then re-apply the gateway playbook from the previous revision. If
   that revision recorded through a static token file, put the file back
   first, at the path the previous revision's
   `pilot_access_gateway_recording_session_store_ingest_token_file` names
   (owner `pilot-gateway`, mode 0600): the upgrade removed it, and the
   previous playbook stops when it is missing. The current signing key file
   stays on the gateway; the previous binary ignores it. The previous
   revision's `pilot session` may need
   `--socket /run/pilot-session-store/session-store.sock`.
5. Before upgrading again, move any `index.db.pre-v1.bak` out of the state
   directory. Otherwise the new store refuses to start, by design, so an
   earlier backup is never overwritten.

Recordings made on v2 after the backup was taken are not in the restored v1
database. Keep the v2 database (for example a copy of the state directory)
if they must be retained.

## 5. Current gotchas

| Symptom | Cause | Current action |
|---|---|---|
| A recorded connect ends with "session recording could not start" | The store is down or unreachable at session start (connection refused) | Start the store; nothing reached the target, and the gateway logged `recording_failed` |
| A recorded session is ended mid-way with "recording could not be saved" | `fail_closed`: the store made no progress for `failure_grace` (10s default), for example unreachable or disk full | Fix the store; the store keeps the partial recording as `complete: false` with the missing seq range |
| Ingest 500s and the recorder fails closed | The store's filesystem is full (SQLite "database or disk is full") | The store now logs `ingest request failed` with the error; free space. `pilot_session_store_ingest_requests_total{code="5xx"}` counts them |
| New store refuses to start after an upgrade attempt | `index.db.pre-v1.bak` already exists, or less than 2× the DB size is free | Move the old backup away / free space; nothing was migrated |
| An existing user who was just added to the auditor or Portal group is denied (`unauthorized`, or `permission denied` on the socket) | The services check the connecting process's own group credentials (`identity.PeerInGroup`), which come from the login session. A brand-new user gets them fresh at first login, but an existing user's session, or a `runuser`, still carries SSSD's cached group list (`id -Gn -- <user>` lacks the group) | The user logs in again: a PAM login (`ssh`, `su`) refreshes the list, `runuser` does not. Otherwise `sss_cache -E` on that host |
| `pilot session replay` / `export` fails with `decrypt/authenticate event (session=… seq=N …): cipher: message authentication failed` (HTTP 500) | The stored ciphertext of that event was altered or damaged. The sequence number is authenticated too, so a row copied from another seq fails the same way | The store returns nothing from that session and export writes no file; the read audit event has `result: error`. Restore `index.db` from a backup to recover the recording |
| `pilot session replay` cannot reach the store | Older `pilot` builds defaulted to `/run/pilot/session-store.sock` | Current builds default to `/run/pilot-session-store/session-store.sock`, where the playbook serves it |

## 6. Latest verified evidence

| Field | Value |
|---|---|
| Verified at | 2026-10-01T16:30Z |
| Tested revision | `fe5f9e0` |
| Tested tree | `18614acb1decf82e5fcc5d77695ce8a9d2254fcc` |
| Target/inventory | `ys-store`, `ys-gw`, `ys-dir`, `ys-target`, `ys-ipa` (generated vm-target topology inventory with a `staging` group) |
| Upgrade | from `main` `56080a8` whose gateway recorded through a token file at a custom path (`/etc/pilot/custom-ingest-token`), with `stage=staging`, `confirm_staging=true`: one `index database migrated` log line, `index.db.pre-v1.bak` 0600 (schema 1), the old session shown and replayed, the store's legacy token removed. The gateway apply without the mode stopped at the downgrade guard (`changed=0`, token and config untouched); with `terminal_output` kept it changed config, signing key, AG82 (removed `/etc/pilot/custom-ingest-token`), binaries, restart; afterwards neither the custom nor the default token path exists. Marker and Directory applied; a recorded connect `policy_source host`, `complete: true` |
| Rollback | backup restored; `56080a8` store `changed=6`; marker removed, none left on any host; gateway token put back at the custom path, `56080a8` gateway `changed=4`; `56080a8` Directory; a connect recorded into the restored v1 store and the baseline replayed |
| Re-upgrade and cleanup | migrated again, both earlier sessions replay; AG82 alone (`--tags AG82`) removed the custom token; after deleting the backup and removing the old token from the vault, store and gateway re-apply `changed=0`; with the removed variable still in the inventory, `changed=0` and a message to drop it. Without `-e stage`, or without `confirm_staging`, the apply stops at its gate |
| Concurrent finish and events | store binary unchanged since `d7da805`: 200 rounds over the live ingest API never accept both; the pre-fix binary accepted both in 23 |
| Fresh topologies | store spec 27/27 on the per-host recording topology (`rec-store`), on the transport topology (`yx-store`) and at the end of the rehearsal |
| Evidence record | [2026-10-01 `fe5f9e0`](../evidence/pilot-access-gateway/2026-10-01-fe5f9e0.md) |
