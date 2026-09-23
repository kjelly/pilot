# Per-host SSH session recording — Phase 8 live verification (2026-09-24)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
§35 (L1–L22), §36 (required commands) and §37 (evidence), plus the
fresh-topology check the spec requires (AGENTS.md §4.0).

## Tested revision

- **Final candidate: commit `ad7c463`, tree `88a9a5233718a936bb25de2773a31b6e6dcdfa3b`.**
  The formal ephemeral topology test ran from a clean, isolated checkout
  of this commit (`git status` empty), with every binary built in that
  checkout. The same binaries were then deployed to the phr topology:
  re-applied twice there, idempotent, and given a final end-to-end smoke.
- The live scenarios ran while this phase's defects were being fixed, so
  each row below names the candidate whose binaries were deployed:
  - `31f5c23`: Phase 7.
  - `1de0964`: fresh-chain check mode, fail_closed relay, CLI usage.
  - `2e98ea3`: store logs the reason for ingest 500s.
  - `0173bc1`: empty `--probe` rejected; SS02 rewritten.
  - `7c72f1d`: that check made nil-safe (the race suite caught a test
    calling `runVerify(nil, …)`).
  - `ad7c463`: `freeipa-server-apply.yml` prepares the installer
    directories only before installing (found by the fresh topology's
    idempotency step). No Go change.

  Across these candidates, the recorder, gateway authorize path, ingest
  API and schema code changed only as listed. Every row whose code changed
  afterwards was re-run on the later candidate.

## Target

### Long-lived disposable topology `phr-*` (L1–L22)

| Node | Role |
|---|---|
| `phr-ipa` | FreeIPA server (`ipa-server-4.13.1-3.el9_8.2`, AlmaLinux 9) |
| `phr-gw` | Access Gateway `phr-gw1`, scope `phr` (`pilot-target-phr` = A + B) |
| `phr-dir` | Access Directory `phr-dir1` (added for this phase) |
| `phr-ta` | target **A**: no `ssh_recording` (inherit) |
| `phr-tb` | target **B**: `ssh_recording: terminal_output`; foreign userClass `external-provisioning` also present |
| `phr-store` | Session Store |

- All nodes except the FreeIPA server run Ubuntu 24.04.
- Test users come from the canonical fixture: `phruser` (Portal user and
  session auditor; SSH key first hop; password never shown or recorded) and
  `phruser2` (Portal user only, for L15(c)).
- Gateway recording config:
  - `mode` unset (built-in metadata);
  - `failure_policy: fail_closed`, `failure_grace: 10s`;
  - store `https://phr-store.ipa.pilot.internal:8443`, PIT1 signing key file.
- Store config: signing key file, schema v2.
- Metrics: the node_exporter textfile directory was created by hand on the
  gateway and the store (`root:root 1777`, as host-monitoring does).
- The signing key, the master key and the test password came from
  disposable files under `.verification/`. No real vault was used.

Source policy and FreeIPA raw value for B (read back with
`ipa host-show --all --raw`): `pilot.policy.ssh-recording=terminal_output`
next to `external-provisioning`. A has no userClass value.

An authorize response for B, as `phruser` over the gateway socket (token
replaced):

```json
{"allowed": true, "target": "phr-tb.ipa.pilot.internal", "recording_mode": "terminal_output", "recording_policy_source": "host", "deny_reason": null, "recording_failure_policy": "fail_closed", "recording_session_store_url": "https://phr-store.ipa.pilot.internal:8443", "ingest_token": "<redacted>"}
```

### Fresh ephemeral topology `eph-*`

Six brand-new VMs with the same roles:
- `eph-ipa`: FreeIPA server.
- `eph-gw`: gateway `gpu-01`, scope `gpu`.
- `eph-ta` / `eph-tb`: the two targets.
- `eph-store`: session store.
- `eph-dir`: directory.

`eph-tb` gets `pilot_ssh_recording=terminal_output`.

The per-run wrapper runs, in order:
1. apt refresh (fresh cloud images ship stale indexes, which the local apt
   proxy answers with 404);
2. `freeipa-server-apply.yml`;
3. the canonical client fixture;
4. `freeipa-client-apply.yml`;
5. `gateway-scope-apply.yml`;
6. `pilot-session-store-apply.yml`;
7. `pilot-access-gateway-apply.yml`;
8. `pilot-access-directory-apply.yml`.

## Live scenarios (§35)

| # | Result | Observed |
|---|---|---|
| L1 | PASS | Directory → A: gateway audit `metadata` / `built_in_default`; no notice in the session; the store has no such session (404) |
| L2 | PASS | `freeipa-client` with `terminal_output`: `changed=1`, `ADD ['pilot.policy.ssh-recording=terminal_output']`; authorize `terminal_output` / `host` |
| L3 | PASS | Directory → B: notice `This SSH session is recorded by Pilot (terminal output). Session ID: …`. Store session: target B, `terminal_output`, `policy_source: host`, `complete: true`, `last_seq 8`; replay contains `PILOT_RECORDING_MARKER_123`. Gateway audit carries session id, user, target, gateway, scope, mode and source on every event |
| L4 | PASS | SSH to the gateway, Portal My Hosts: `phr-tb … [REC output]`. Host Detail: `SSH recording: terminal output (host policy)`. Confirmation adds `This session will be recorded.` Session recorded, `complete: true` |
| L5 | PASS | Same Portal session → A: `SSH recording: off`, no recording line in the confirmation, nothing in the store |
| L6 | PASS | `off`: `DELETE [=terminal_output] ADD [=off]`; authorize `metadata` / `host`, no store coordinates |
| L7 | PASS | Field removed: `DELETE [=off]`; authorize `metadata` / `built_in_default` |
| L8 | PASS | Hand-written `=banana`: deny `recording_policy_invalid`. The one-shot handoff printed `Connection not started: this host's recording policy is misconfigured.` and exited 1. The target's sshd journal has no login in that window (positive control: real connects show `Accepted gssapi-with-mic for phruser`) |
| L9 | PASS | `=off` and `=terminal_output` together: connect denied as in L8. `freeipa-client` `failed=1 changed=0` with `CONFLICT_DUPLICATE_SSH_RECORDING_POLICY`; userClass unchanged |
| L10 | PASS | Only `Pilot.Policy.SSH-Recording=terminal_output`: connect denied. Apply `failed=1 changed=0` with `CONFLICT_MALFORMED_SSH_RECORDING_POLICY` |
| L11 | PASS | `external-provisioning` survived every L2/L6/L7 change. The Phase 2 run covers the annotation value |
| L12 | PASS | Store stopped, Portal → B: notice first, then `Connection not started: session recording could not start.` (connection refused). Audit has `recording_failed`, no `target_connect_started`; zero logins on B |
| L13 | PASS after fix | Store port dropped with nftables mid-recording. `recording_failed: sink made no progress for >= 10s` about 11 s after the block; session ended `recording failed closed`; the store kept it `complete: false` and replay prints `*** RECORDING INCOMPLETE ***`. **Defect found (fixed in `1de0964`):** the relay kept forwarding I/O for about 5 s after the trip, while the finish was attempted. Re-run on `1de0964`: last tick seen by the user 17:39:23.979, trip 17:39:24.084, no bytes forwarded after it |
| L14 | PASS | Recorded Portal session → B, idle 20 min 30 s (past the 900 s start window + 60 s skew and 3 × `failure_grace`), then typed and exited. `complete: true`, `last_seq 13`, marker after the idle period present, no `recording_failed` / `recording_gap` |
| L15 | PASS | Tokens minted and used inside the gateway VM, never printed. (a) S1's token on S2: 403 `session_id_mismatch`. (c) `phruser2`'s token for S1: start 409, events 403 `claims_mismatch`. (b) events after finish: 409 `session_finished`. S1 unaffected: `phruser`, `complete: true`, 1 event |
| L16 | PASS | Hand-written `=terminal_io`: deny `recording_policy_invalid`, no target login |
| L17 | PASS | Final candidate `ad7c463`: `freeipa-client` full apply `changed=0` twice. Store, gateway and Directory: `changed=3` (rebuilt binaries + restart), then `changed=0`. The same held on `2e98ea3`, `0173bc1` and `7c72f1d` |
| L18 | PASS | State dir on a 48 MiB loop filesystem filled to about 1.5 MB free (never the root filesystem). Recorded session with about 4 MB of output: 10 event requests got 5xx and fail_closed ended the session. Store: `complete: false`, 203 events, `last_seq 1018`, gap 204..1018. **Defect found (fixed in `2e98ea3`):** the store did not log why it answered 500. Repeat on `2e98ea3`: `ingest request failed … "database or disk is full (13)"`. Loop device and original directory restored both times |
| L19 | PASS | As auditor `phruser`: replay and `pilot session export --output` (0600). `recording_replayed` and `recording_exported` events with `auditor: phruser` and no payload. `asciinema cat` (asciinema 2.4.0) plays the `.cast` and shows the marker; its header size 120x40 matches the Directory terminal, via the seq 1 resize |
| L20 | PASS | Root on the gateway, real FreeIPA and gateway keytab: A `inherit`/`metadata`/`built_in_default`; B `terminal_output`/`terminal_output`/`host`; unknown host exit 1 `host not found in FreeIPA`; non-root exit 2 |
| L21 | N/A (branch R) | Phase 0 found branch R (`rights`), so there is no canary. Covered by `TestConnectAuthorize_UserClassUnreadableDenies` and `TestParseHost_UserClassUnreadableIsUnavailable` (AG56) |
| L22 | PASS | See below |
| smoke | PASS | Final candidate `ad7c463` on phr: Directory → B recorded session `7532d6c9…`, `terminal_output` / `host`, `complete: true`, marker in replay. Same on `7c72f1d` (`4bd71559…`) |

### L22 — v1 store upgrade and rollback

1. Current v2 state saved to a tarball on the VM; DB cleared.
2. Previous revision `bd21971` store playbook, previous binaries, legacy
   token vault: `ok=41 changed=7 failed=0`, `token_file` config.
3. One session ingested with the static bearer token; `user_version 1`
   (13 columns); listed and replayed with the old CLI.
4. Upgrade: current store playbook `ok=45 changed=6`.
   `index.db.pre-v1.bak` is `pilot-session-store:role-pilot-session-auditor
   600`, schema v1. Live DB is schema v2 with `recording_policy_source`,
   `last_seq`, `ingest_jti`. The old session shows `complete: true` and
   replays. Legacy token file removed.
5. Rollback per `docs/runbooks/pilot-session-store.md` §4:
   - stop the store, restore the backup;
   - previous-revision store playbook `ok=41 changed=7`;
   - the old binary opened the v1 DB and replayed the session;
   - `freeipa-client` without `ssh_recording` removed B's marker;
   - no `pilot.policy.ssh-recording=` on any phr host;
   - previous-revision gateway (`ok=64 changed=5`, no `recording:` block);
     authorize B gave `metadata`.
6. Re-upgrade: v2 tarball restored, current store, B's marker and current
   gateway re-applied. B authorized `terminal_output` / `host` again, and
   earlier recordings replay.
7. The tarball (it contained key material) was deleted from the VM.

## Fresh ephemeral topology (candidate `ad7c463`, clean checkout)

`pilot vm-target topology test --ephemeral` from the clean checkout. It
provisioned six brand-new VMs, ran the chain, and removed them afterwards.

| Step | Result |
|---|---|
| L1 syntax check | PASS |
| L3 fresh `--check --diff` (nothing applied yet) | PASS — `failed=0` on all six: `eph-ipa ok=21 changed=3`, `eph-gw ok=112 changed=16`, `eph-store ok=108 changed=15`, `eph-dir ok=105 changed=15`, `eph-ta ok=75 changed=4`, `eph-tb ok=76 changed=4` |
| cluster snapshot | created |
| L4 apply | PASS — `failed=0` on all six (`eph-ipa changed=22`, `eph-gw changed=51`, `eph-store changed=38`, `eph-dir changed=44`, `eph-ta changed=21`, `eph-tb changed=22`) |
| L5 `pilot verify` | `freeipa-client.md` 60/60, `pilot-session-store.md` 27/27, `pilot-access-gateway.md` 35/35, `pilot-access-directory.md` 9/9 — all PASS |
| L6 second apply | PASS — `changed=0` on all six |
| teardown | ephemeral topology removed |

Earlier pre-check runs of the same chain found what the candidates above
fixed, and none of their results are used as evidence:

1. `1de0964`: apt 404s from stale indexes. The wrapper got an apt refresh.
2. `2e98ea3`: C8 failed because the wrapper ran the client fixture after
   enrollment instead of before, as freeipa-client.md §7 requires. The
   wrapper order was fixed. SS02 also failed; it was rewritten in
   `0173bc1`.
3. `0173bc1`: an apt request stalled at the local proxy for 40 minutes.
   The wrapper's refresh now has a per-request timeout and bounded retries.
   This run was stopped.
4. `7c72f1d`: `changed=1` on `eph-ipa` in the idempotency step; fixed in
   `ad7c463`.

## Defects found and fixed in this phase

| Found by | Defect | Fix |
|---|---|---|
| fresh-chain `--check --diff` | Store, gateway and Directory gates asserting enrollment / DNS record / CA / SSSD group failed on hosts that the same run enrolls first. The Directory also lacked the keytab and systemd check-mode guards | `1de0964`: relaxed only for the preview of a not-yet-enrolled host; guards added |
| L13 | fail_closed relay kept forwarding unrecorded I/O while the finish was attempted | `1de0964`: queue before forwarding, forward nothing after the trip; `TestRecorderFailClosedStopsRelaying` |
| live Directory/Portal errors | `portal-session`, `directory-session`, `pilot session list/show/replay` printed cobra usage on runtime errors | `1de0964` |
| verification | Unit-test rows of the gateway spec had prose as their Command, so `pilot verify` could not run the spec on a host | `1de0964`: Command `true`, test named in the Check column; the gateway spec now verifies 35/35 |
| L18 | Store did not log the cause of ingest 500s | `2e98ea3` |
| operator error ×2 | An empty `pilot verify --probe` fell through to verifying every spec | `0173bc1`: rejected |
| fresh topology verify | SS02's Markdown-escaped `\|` reached `sh -c` literally, so the row tested nothing | `0173bc1`: pipe-free; PASS on both stores, FAIL with a wrong CA |
| Phase 7 live | `pilot session` default socket did not match the deployed one | `31f5c23` |
| race suite on `0173bc1` | The empty `--probe` check dereferenced a nil command when a test called `runVerify` directly | `7c72f1d` |
| fresh topology idempotency (`7c72f1d`) | `freeipa-server-apply.yml` recreated `/var/lib/ipa/pki-ca/publish` (removed by the installer) on every re-apply: `changed=1` | `ad7c463`: the prep task runs only before installing |

Two environment facts were recorded in `docs/runbooks/pilot-session-store.md`
rather than fixed in code:
- a user or auditor added after a host cached the group is denied until
  SSSD refreshes (`sss_cache -E`);
- fresh cloud images need an apt index refresh behind the local proxy.

## §36 required commands (on the final candidate tree)

| Command | Result |
|---|---|
| `gofmt -l .` | lists 8 files, all unchanged by this branch (last touched by `c0890f6` and earlier). No feature file |
| `go vet ./...`, `go build ./...` | pass |
| `go test -race -count=1 ./...` | exit 0 on `ad7c463` (and on each earlier candidate once its fix was in) |
| `golangci-lint run ./...` (v2.12.1) | 0 issues |
| `python3 scripts/check-yaml-duplicate-keys.py` | no duplicate keys (212 files) |
| `make playbook-lint` | pass (ansible-lint findings advisory); the gateway, store and Directory playbooks have the same or fewer findings than before this phase |
| `pilot spec --lint` | gateway 35 rows, store 27, directory 9, freeipa-client 12; 0 findings |
| `go test -run TestShellSyntax ./internal/spec/` | pass |
| `pilot contract lint` | pass |
| `ansible-playbook --list-tags` (gateway, store, freeipa-client) | pass |

## Cleanup

- nftables table removed.
- Loop device and image removed, original state directory restored.
- L22 tarball deleted.
- B's marker and the current store and gateway restored.
- The phr topology is left running on candidate `ad7c463` with the test
  users in its disposable FreeIPA.
- Raw outputs and casts are only under `.verification/`.
- This record contains no signing key, PIT1 token, master key, password or
  terminal input.
