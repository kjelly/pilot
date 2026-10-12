# Per-host SSH session recording — follow-up fixes and re-verification (2026-09-24)

Scope: the issues left open by the Phase 8 record
([`2026-09-24-per-host-session-recording.md`](2026-09-24-per-host-session-recording.md)),
the verification it recommended, a re-run of §35 L1–L22 on the new final
candidate, a staging-style upgrade rehearsal, and the minimal-poc topology
test.

## Tested revision

- **Final candidate: commit `bded49e`, tree `59dd5392ed545211ad02c3bc68f7523a74b4edc4`.**
  Every run below that counts as evidence ran from a clean, isolated
  checkout of this commit (`git status` empty), with the binaries built
  there.
- The previous candidate `b47ae5d` (tree `25e9d6ac466ceda07b6268a06de5b69af28ba87b`)
  failed its formal ephemeral run (see "Defects found"). `bded49e` changes
  only `playbooks/apply/tasks/apt-cache-refresh.yml`,
  `playbooks/apply/tasks/apt-scoped-refresh.yml` and a Go test. The four
  binaries built from both commits are byte-identical (sha256 prefixes
  `165f35e0…` pilot, `dfb0389e…` gateway, `e823dfc0…` Directory,
  `a08b420b…` store).

### Spec rows for the bounded refresh (candidate `8435a9b`)

`docs/verification/apt-repository-tolerance.md` gained C5
(`TestAptUpdateIsBounded`) and T12 (the `apt-stall` live check below), and
the design spec a T12 case, as a separate candidate: commit `8435a9b`,
tree `c17ec6e1649a5090f037b7880cea51b39c78c605`. Against `bded49e` it
changes only documents (these two specs, this record and the session store
runbook), so no playbook or binary differs from the tested tree. From a
clean checkout of `8435a9b`: spec lint 10 rows, 0 findings;
`pilot verify docs/verification/apt-repository-tolerance.md --local` PASS
10/10; `go test ./internal/spec/ ./cmd/pilot/cmd/` 1589 passed; `pilot
contract lint` pass.

## Fixes in this round

| Commit | Issue | How it was verified live |
|---|---|---|
| `682f0f8` | A Portal user or auditor added to a group after SSSD cached that group was rejected for up to 90 minutes: the membership check read `getent group`, which SSSD serves from the stale group entry | phr: a new user (`phruser4`) got HTTP 200 on the gateway and the Directory while `getent group` still listed only the old members. An existing user just added to the auditor group is recognized after a PAM login (`su`), not through `runuser` (runbook updated) |
| `f3cd0c6` | A fresh cloud image's cached indexes name versions the archive no longer serves; the install 404ed with no refresh | fresh vm-target: previous task file `failed=1` with the 404s; new one `rescued=1 failed=0`, `apt_mode=stale_index_refresh`; re-run `already_present`, `changed=0` |
| `c761db6` | `pilot verify -i <inv>` with no spec verified every spec in `docs/verification` against that inventory | `pilot verify -i x.yml` now exits 1 asking for a spec or `--dir` |
| `9c9d962` | Gateway spec row AG01 hardcoded the example deployment (`gpu-01`/`gpu`) | Gateway spec is now Spec v2 with required inputs `gateway_id`/`gateway_scope`. phr-gw: 35/35 with `--input phr-gw1/phr`, 35/35 with a `pilot_inputs` host var; no inputs → refused before any row; AG01 probe with `gpu-01/gpu`, `phr-gw/phr`, `phr-gw1/ph` fails |
| `4cc11d3` | After fail_closed tripped, the ssh child lived until Run had drained and tried to finish (about 5 s) | L13 below: the target's tick loop stopped at the trip |
| `1dfafaa` | The store migrated a v1 database and took its backup without logging anything | phr-store: first open of a v1 database logged `index database migrated` with `from_schema 1`, `to_schema 2`, `backup`; the second open logged nothing |
| `1d772ee` | The fresh-host topology and wrapper were per-run files under `tmp/` | Committed as `docs/topologies/per-host-recording-topology.yaml`, `playbooks/test/per-host-recording-topology.yml`, `scripts/per-host-recording-topology-test.sh` (`make recording-topology-test`); the formal run below used them |
| `e483ef6` | No alert rules for the recording series; and every labelled series appeared only after its first increment, which Prometheus's `increase()` cannot see | See "Metrics and alerts" |
| `b47ae5d` | Runbook: store behaviour on a tampered payload | See "Corrupt payload" |
| `bded49e` | The framework's `apt-get update` had no wall-clock bound | See "Defects found" |

## Metrics and alerts (phr, real node_exporter)

`host-monitoring` installed node_exporter 1.12.1 on phr-gw and phr-store
(`failed=0`). A local Prometheus v2.53.0 scraped both with basic auth and
loaded `playbooks/apply/files/pilot-alert-rules-seed.yml`.

- Both targets `up`; every alerted series present at 0 before any event.
- `promtool check rules`: 7 rules. `promtool test rules`: pass, including
  a series without the zero start that correctly does not fire.
- An invalid host marker on phr-ta, then one authorize: `PilotRecordingDeniedConnects`
  firing (`reason=recording_policy_invalid`).
- L18 disk full: `PilotSessionStoreIngestErrors` firing (10 event 5xx) and
  `PilotRecordingIncomplete` firing (`mode=terminal_output`).
- Store stopped at 03:37:19: `PilotSessionStoreMetricsStale` pending at
  03:39:49, firing at 03:44:49; store restarted.

## Corrupt payload (phr-store)

Session `71b725ef…` (complete, 10 events), store stopped around each edit:

| Tamper | Replay | Export | Read audit |
|---|---|---|---|
| none (baseline) | rc 0, 1322 bytes, sha `2058d9b4af5d` | rc 0 | `ok` |
| one ciphertext byte of seq 3 flipped | rc 1, `decrypt/authenticate event (… seq=3 …): cipher: message authentication failed`, 0 bytes | rc 1, no file | `error`, no payload |
| seq 4's nonce and ciphertext copied into seq 3 | rc 1, same error | — | `error` |
| original restored | rc 0, sha `2058d9b4af5d` | rc 0 | `ok` |

No code change was needed.

## Defects found in this round's live runs

| Where | Defect | Fix |
|---|---|---|
| formal ephemeral run on `b47ae5d` | With the wrapper's own apt refresh removed, the stale-index rescue ran the framework's global `apt-get update`, which hung on `rec-tb` for over 38 minutes with no network connection left open. The run was stopped and its VMs torn down; none of its results are used | `bded49e`: both framework refreshes run under `timeout(1)` (default 300 s) with apt's `Acquire::http(s)::Timeout` (30 s) and `Acquire::Retries` (3), and a timed-out attempt (rc 124) is retried like lock contention. Fresh vm-target: the stale-index install recovered through the bounded refresh (23 s); with outbound HTTP dropped and a 20 s cap, the refresh returned after 75 s with rc 124, `healthy=False`, instead of hanging |
| metrics | See "Metrics and alerts": first increment after a restart invisible to `increase()` | `e483ef6` |

## Fresh ephemeral topology (candidate `bded49e`, clean checkout)

`make recording-topology-test` (`scripts/per-host-recording-topology-test.sh`)
from the clean checkout: six new VMs (`rec-*`), the committed wrapper with
**no** apt pre-refresh, gateway `rec-gw1` / scope `rec`, AG01 inputs from
`PILOT_INPUT_*`.

| Step | Result |
|---|---|
| L1 syntax check | PASS |
| L3 fresh `--check --diff` | PASS — `failed=0` on all six (`rec-ipa changed=3`, `rec-gw 16`, `rec-store 15`, `rec-dir 15`, `rec-ta 4`, `rec-tb 4`) |
| L4 apply | PASS — `failed=0` on all six; each Ubuntu node `rescued=1` (the stale-index rescue: five `apt_mode=stale_index_refresh`) |
| L5 `pilot verify` | `freeipa-client.md` 60/60, `pilot-session-store.md` 27/27, `pilot-access-gateway.md` 35/35 (AG01 against `rec-gw1`/`rec`), `pilot-access-directory.md` 9/9 |
| L6 second apply | PASS — `changed=0` on all six |
| teardown | ephemeral topology removed |

## §36 required commands (clean checkout of `bded49e`)

| Command | Result |
|---|---|
| `gofmt -l .` | no output |
| `go vet ./...`, `go build ./...` | pass |
| `go test -race -count=1 ./...` | exit 0 (54 packages ok) |
| `golangci-lint run ./...` (v2.12.1) | 0 issues |
| `python3 scripts/check-yaml-duplicate-keys.py` | pass |
| `make playbook-lint` | pass (ansible-lint advisory). On the changed task files compared with `c0890f6`: `apt-cache-refresh.yml` lost its one finding; `apt-package-install.yml` gained 6 `name[template]`, the file's existing task-name convention. The new test wrapper's findings all come from the playbooks it imports |
| `pilot spec … --lint` (gateway, store, Directory, freeipa-client, apt-repository-tolerance, prometheus) | 0 errors each |
| `go test -run TestShellSyntax ./internal/spec/` | pass |
| `pilot contract lint` | pass |
| `ansible-playbook --list-tags` gateway, store, freeipa-client | listed |

## §35 live scenarios on the final candidate (phr topology)

The phr topology from Phase 8 (`phr-ipa`, `phr-gw` gateway `phr-gw1` scope
`phr`, `phr-dir`, targets A `phr-ta` inherit and B `phr-tb` marked
`terminal_output`, `phr-store`). The playbooks and binaries came from the
clean `bded49e` checkout. All of these rows also passed on `b47ae5d` first,
before the apt stall was found; the table shows the `bded49e` run.

| # | Result | Observed |
|---|---|---|
| L1 | PASS | Directory → A: gateway `metadata` / `built_in_default`, no notice, store 404 |
| L2 | PASS | `freeipa-client` with `terminal_output`: `ADD ['pilot.policy.ssh-recording=terminal_output']`; authorize `terminal_output` / `host` with store coordinates |
| L3 | PASS | Directory → B: notice with the session id; store `terminal_output`, `policy_source host`, `complete: true`, `last_seq 7`, marker in replay; every gateway audit event carries user, gateway, scope, mode and source |
| L4 | PASS | Portal list `[REC output]` on B only, detail `SSH recording: terminal output (host policy)`, confirmation `This session will be recorded.` |
| L5 | PASS | Portal → A: `SSH recording: off`, no recording line, no notice, gateway `metadata` / `built_in_default`, store 404 |
| L6 | PASS | `off`: `DELETE [=terminal_output] ADD [=off]`; authorize `metadata` / `host` |
| L7 | PASS | field removed: `DELETE [=off]`; authorize `metadata` / `built_in_default` |
| L8 | PASS | `=banana` on A: deny `recording_policy_invalid`; one-shot connect `Connection not started: this host's recording policy is misconfigured.`, exit 1; no phruser line in A's sshd journal (positive control: a real connect logs `Accepted gssapi-with-mic for phruser`) |
| L9 | PASS | `=off` + `=terminal_output`: connect denied as L8; `freeipa-client` `failed=1 changed=0`, `CONFLICT_DUPLICATE_SSH_RECORDING_POLICY` |
| L10 | PASS | only `Pilot.Policy.SSH-Recording=terminal_output`: denied; apply `failed=1 changed=0`, `CONFLICT_MALFORMED_SSH_RECORDING_POLICY` |
| L11 | PASS | `external-provisioning` survived every L2/L6/L7 change |
| L12 | PASS | store stopped, Portal → B: notice first, then `Connection not started: session recording could not start.` (connection refused); audit `gateway_authorize_allowed`, `recording_failed`, no `target_connect_started`; no phruser login on B |
| L13 | PASS | store port dropped mid-recording at 05:09:38.78; `recording_failed: sink made no progress for >= 10s` at 05:09:48.789; the last tick the target wrote was 05:09:48.762 and its loop was gone (ended at the trip, `4cc11d3`); store `complete: false`, replay prints `*** RECORDING INCOMPLETE ***` |
| L14 | PASS | recorded Portal session → B idle 20 min 47 s (04:47:07 → 05:07:54): `complete: true`, `last_seq 11`, after-idle marker in replay, no `recording_failed` / `recording_gap` |
| L15 | PASS | S1's token for S2: 403 `session_id_mismatch`; `phruser2`'s token for S1: start 409, events 403 `claims_mismatch`; events after finish: 409 `session_finished`; S1 `phruser`, `complete: true` |
| L16 | PASS | `=terminal_io`: deny `recording_policy_invalid`, no target login |
| L17 | PASS | store and gateway `changed=2` (signing key file and restart after the rehearsal vault), then `changed=0`; Directory `changed=0` twice; full `freeipa-client` on all five clients `changed=0` twice |
| L18 | PASS | state dir on a 48 MiB loop filesystem: 9 event requests 5xx `database or disk is full (13)`, fail_closed ended the session before its output finished; store `complete: false`, `last_seq 1041`; loop device and original directory restored |
| L19 | PASS | auditor `phruser`: replay contains the marker; `pilot session export` 0600, header 120x40; `asciinema cat` (2.4.0) shows the marker; `recording_replayed` / `recording_exported` with the auditor and no payload |
| L20 | PASS | A `inherit` / `metadata` / `built_in_default`; B `terminal_output` / `terminal_output` / `host`; unknown host exit 1; non-root exit 2 |
| L21 | N/A (branch R) | as in Phase 8 |
| L22 | PASS | staging rehearsal below |
| smoke | PASS | after the rehearsal: Directory → B, `terminal_output` / `host`, `complete: true`, marker in replay |

## Staging rehearsal (L22), candidate `bded49e`

No real staging environment exists for this feature, so the rehearsal
used the disposable phr hosts placed in the inventory's `staging` group,
with `-e stage=staging -e confirm_staging=true` on every apply and an
ansible-vault encrypted vault (`--vault-password-file`). The previous
revision is `c0890f6` (the branch base: static-token store, schema v1,
gateway without recording). It follows `docs/runbooks/pilot-session-store.md`
step by step.

1. Baseline: the phr store's v2 state saved and cleared; `c0890f6` store
   (`ok=41 changed=7`), gateway (`changed=5`) and Directory (`changed=3`)
   applied; B's marker removed. One session ingested with the static
   bearer token: `user_version 1`, listed and replayed.
2. Vault: the old `pilot_session_store_ingest_token` kept, a new 64-hex
   `pilot_session_store_ingest_signing_key` added (runbook §1).
3. §2 step 1: `vm-target show-inventory` for store, gateway, Directory, B.
4. §2 step 2: candidate store `ok=45 changed=7`. The journal has
   `index database migrated` (`from_schema 1`, `to_schema 2`, `backup`).
5. §2 step 3: `index.db.pre-v1.bak` 0600, schema v1; the old session
   `complete: true` and replays; legacy token file removed.
6. §2 step 4: gateway `changed=6`, B's marker `ADD [=terminal_output]`,
   Directory `changed=3`; authorize B `terminal_output` / `host`. A real
   Directory → B connect was recorded (`terminal_output`, `host`,
   `complete: true`).
7. §4 rollback: backup restored per step 1; `c0890f6` store `changed=7`,
   the old binary replays the baseline session; B's marker removed and no
   `pilot.policy.ssh-recording=` on any phr host; `c0890f6` gateway
   (`changed=5`, no `recording:` block) authorizes B as `metadata`.
8. Re-upgrade (§4 step 5: no backup left to move): store, gateway, marker
   and Directory re-applied; a second `index database migrated`; the
   baseline session still replays.
9. §2 step 5: backup deleted, old token removed from the vault; store and
   gateway re-applied with that vault: `changed=0` both; B still
   `terminal_output` / `host`.
10. Gates: the same store apply with the host in `staging` but no
    `-e stage` failed at `Gate: stage must match this host's inventory
    environment group`; with `stage=staging` but no confirm, at `Gate:
    staging or prod requires explicit confirm`; both `changed=0`.
11. The tarball and baseline files holding key material were deleted from
    the store VM.

The earlier rehearsal on `b47ae5d` gave the same results. Its first
attempt at the baseline marker removal (step 1) ran `freeipa-client` with
`--sandbox`, which does not carry `--vault-password-file` into the
container. That is a harness limit; every staging apply ran with the host
Ansible from then on.

## minimal-poc topology test (candidate `bded49e`, clean checkout)

`make poc-checkmode-test` (`scripts/topology-checkmode-test.sh`,
`docs/topologies/minimal-poc-topology.yaml`, `playbooks/site.yml`) was
re-run because `ad7c463` changed the shared `freeipa-server-apply.yml`.
The script needs a vault and a canonical roster that fit this topology;
neither exists in the repo, so both were per-run files: the vault had the
eight required keys (`thanos_aws_*` equal to the restic credentials the
SeaweedFS identity uses); the roster was the example roster with its admin
password matched to the vault, its NFS server set to
`nexus.ipa.pilot.internal`, and a `nfsclients` hostgroup holding
`client-vm`.

| Run | Result |
|---|---|
| 1 | L3 check mode stopped at `freeipa-nfs-server` `Gate: required roster and stage authorization`: the example roster's admin password did not match the vault (input) |
| 2 | L3 PASS; L4 stopped at the NFS server gate: the roster named `nfs1.ipa.pilot.internal`, not this topology's `nexus` (input). Before that, `nexus` and `client-vm` recovered the docker install through the stale-index rescue |
| 3 | L3 PASS; L4 `freeipa-server failed=0`, `nexus failed=0`; `client-vm` stopped at the NFS client gate: no roster hostgroup contained it (input) |
| 4 | L3 PASS; L4 PASS (`failed=0` on all three; `rescued=1` on `nexus` and `client-vm`); L5 `freeipa-server.md` 20/20 PASS; `freeipa-client.md` 20/24: C5 (`id pilotuser@…`) and C8 (`sudo -l -U pilotuser`) failed on both clients because `site.yml` never runs `freeipa-client-fixtures.yml`, which that spec's §7 requires before any client apply. Rolled back; L6 did not run |
| 5 | Same make target with `PLAYBOOK=` a per-run wrapper: `freeipa-server-apply.yml`, then `freeipa-client-fixtures.yml`, then `site.yml`. L3 PASS; L4 PASS (`failed=0` on all three); L5 `freeipa-server.md` 20/20, `freeipa-client.md` 24/24; `freeipa-nfs-server.md` 5/8: C5–C7 expect the fixture share `fixture-alpha` and group `data-fixture-nfs-ro` from `playbooks/test/fixtures/freeipa-identity-canonical.roster.yaml`, and the share was deferred because no `freeipa-identity` reconcile had created its groups. Rolled back; L6 did not run |

Conclusion: on fresh hosts, `freeipa-server-apply.yml` (the reason for this
re-run) passed check mode, apply and `freeipa-server.md` 20/20 in runs 4
and 5. Its idempotency was proven in the per-host recording ephemeral run
(`changed=0` on the FreeIPA server node). This run never reached its
idempotency step. `make poc-checkmode-test` cannot pass end to end as it
stands: it runs `site.yml` alone, but its verify list needs the
`freeipa-client` fixture, a topology-matched fixture roster and a
`freeipa-identity` reconcile before the NFS roles. No earlier passing run
of this make target is recorded.

## Open items

- `scripts/topology-checkmode-test.sh`: run the specs' fixtures and a
  `freeipa-identity` reconcile, and ship a roster that matches
  `docs/topologies/minimal-poc-topology.yaml`, or drop the fixture-dependent
  specs from its verify list.
- The real staging environment was not touched; the rehearsal used
  disposable hosts in a `staging` inventory group.
