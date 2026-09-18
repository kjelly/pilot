# Phase 8 — Session Store

Spec: `docs/tmp/now/spec.md` §28-§29/§35, Phase 8 landing gate (§44).

## What was built

- `internal/sessionstore`: `Encryptor` (AES-256-GCM, per-event unique nonce,
  AAD binds session_id/seq/stream), `Store` (`StartSession`/`IngestEvents`/
  `FinishSession`/`Replay`/`DeleteSessionPayload`/`SessionsOlderThan`),
  single-SQLite-file storage (`modernc.org/sqlite`, `PRAGMA user_version`
  schema versioning) — a deliberate deviation from spec §28.3's suggested
  per-file-per-day layout, documented in `schema.go`'s doc comment (this
  repo has been bitten before by orphaned temp files surviving process
  death; one transactional store makes retention's "update index, then
  delete payload" atomic with no second filesystem cleanup step).
- `cmd/pilot-session-store`: `serve` (TLS-mandatory ingest API +
  SO_PEERCRED/auditor-group-gated Unix-socket read/replay API, two
  listeners/two trust models/one process) and `retention-sweep` (oneshot,
  intended for a systemd timer).
- `internal/sessionrecording/httpsink.go`: batched HTTP ingest `Sink`
  implementation consumed by `cmd/pilot/cmd/portal_session_connect.go`'s
  recording-mode fork (HTTPSink when `gateway.recording.session_store_url`
  is set, else Phase 7's plain `FileSink`).
- `cmd/pilot/cmd/session_{client,list,show,replay}.go`: `pilot session
  list/show/replay`, the auditor-facing CLI.
- New this session (deployment plumbing, absent from the earlier
  mid-review state): `playbooks/apply/pilot-session-store-apply.yml`,
  `contracts/pilot-session-store.yaml`,
  `group_vars/pilot-session-store.example.yml`,
  `docs/verification/pilot-session-store.md`,
  `scripts/build-pilot-session-store.sh`, plus registration in
  `internal/inventory/{catalog,contracts}.go`, `cmd/pilot/cmd/deploy_catalog.go`,
  `playbooks/site.yml`, `images/Dockerfile.pilot-cli`,
  `cmd/pilot/cmd/{contract,tag_coverage,deploy}_test.go`,
  `internal/contract/{contract,fixture_schema}_test.go`, `AGENTS.md` §4.3.
- `internal/sessionstore/encryption_test.go` (new): `LoadMasterKeyFile` had
  **zero** test coverage anywhere in the repo before this pass (confirmed
  via `grep -rn LoadMasterKeyFile` — only `main.go` called it) despite
  being the function that enforces the master key file's 0600 permission
  requirement. Added 5 tests (valid key, world-readable rejection, invalid
  hex, wrong length, missing file) — a real, non-hypothetical gap in
  security-relevant code, not a speculative addition.

## Design decision made this session: the read socket needs its own runtime directory

Gateway/Directory's own read sockets get deterministic ownership/mode from
a systemd `.socket` unit's `SocketUser`/`SocketGroup`/`SocketMode` —
`pilot-session-store`'s read API is opened directly by the Go process
(`net.Listen("unix", ...)`, no socket activation), so that mechanism isn't
available. Sharing Gateway/Directory's `/run/pilot` was rejected: whichever
of the three services' units first creates that directory at boot owns it
with *its own* `User`/`Group`, and a later service running as a different
user could fail to bind inside it at all (systemd's `RuntimeDirectory=`
only sets ownership when it creates the directory). Fixed with a private
`RuntimeDirectory=pilot-session-store` + `UMask=0007` + the unit's
`Group=role-pilot-session-auditor` — verified live below that this
actually produces a socket auditor group members can connect to (needs
*write* permission, not just read/search) while non-members get a
filesystem-level `permission denied` before ever reaching the app's own
SO_PEERCRED check.

## Live landing-gate verification

New vm-target `ag-sessionstore01` (192.168.122.8), enrolled as a FreeIPA
client against the existing `ag-spike-ipa` realm
(`--group freeipa-server=ag-spike-ipa --group client=ag-sessionstore01
-e target_group=client`, the same gotcha this delivery's Phase 4 evidence
already documented). Then:

```
pilot vm-target run --name ag-sessionstore01 playbooks/apply/pilot-session-store-apply.yml \
  -e target_group=all \
  -e pilot_binary_path=dist/pilot-linux-amd64 \
  -e pilot_session_store_binary_path=dist/pilot-session-store-linux-amd64 \
  -e pilot_session_store_retention_days=90 \
  -e pilot_session_store_key_id=v1 \
  -e pilot_session_store_master_key=<64-hex, openssl rand -hex 32> \
  -e pilot_session_store_ingest_token=<64-hex, openssl rand -hex 32> \
  -e @~/.vault/main.yaml
```

`ok=43 changed=18 failed=0` on the first apply, including a real TLS
handshake (SS02) and a real Unix-socket existence probe (SS05) against the
just-started service.

### SS14 — second apply is a true no-op

Re-ran the identical command: `ok=39 changed=0 failed=0`.

### SS16 — site-wide deploy actually reaches the component

```
pilot vm-target run --group pilot-session-store=ag-sessionstore01 --name ag-sessionstore01 \
  playbooks/site.yml --tags freeipa,pilot-session-store <same -e's>
```

`ag-sessionstore01: ok=46 changed=0` — the component's own play inside
`site.yml` ran (not skipped) and converged to the already-applied state.

### SS03/SS06/SS08 — real ingest exercise

Started a real session via the live ingest API (`curl --cacert
/etc/ipa/ca.crt`), ingested one `tty_output` event
(`data_base64=SEVMTE9fUEhBU0U4X0xJVkVfVEVTVA==`, decodes to
`HELLO_PHASE8_LIVE_TEST`), finished it:

```
START=200  EVENT=200  FINISH=200
```

- Retried the identical event (same `session_id`/`seq`/payload): `200`
  (idempotent no-op, SS06).
- Sent the same request with a garbage bearer token: `401` (SS03).
- `grep -c HELLO_PHASE8_LIVE_TEST /var/lib/pilot-session-store/index.db`
  → `0` — the plaintext marker does not appear anywhere in the on-disk
  database file (SS08).

### SS12 — gap detection and the "RECORDING INCOMPLETE" banner

Ingested `seq=1` and `seq=3` for a session, deliberately skipping `seq=2`,
then finished with `complete=false`. `pilot session replay` on that
session printed, as the very first line:

```
*** RECORDING INCOMPLETE ***
    missing sequence 2..2
```

### SS13 — auditor-group gating, both directions, live

Added `alice` (an existing test user in this realm, already a member of
`role-pilot-portal-user` from earlier phases) to
`role-pilot-session-auditor` via `ipa group-add-member`. Confirmed SSSD
cache staleness is real and expected — `getent group
role-pilot-session-auditor` initially showed an empty member list even
though `id alice`/`groups alice` already reflected the new membership
correctly (IPA-backed group enumeration and per-user group resolution go
through different SSSD code paths); `sss_cache -u alice -g
role-pilot-session-auditor` forced an immediate refresh. This is host
cache behavior, not a bug in `internal/identity.IsMemberOfGroup` or this
delivery's code — confirmed by checking a long-standing group
(`role-pilot-portal-user`) already showed its members correctly via the
same `getent group` command.

After the cache refresh:

- `runuser -u alice -- pilot session list/show/replay` (real SO_PEERCRED
  identity, real group membership): all three succeeded, and `replay`
  produced the exact `HELLO_PHASE8_LIVE_TEST`... (see the full E2E section
  below for the fuller transcript) content, correctly decrypted.
- `runuser -u bob -- pilot session list` (bob resolves via SSSD on this
  host but is **not** a member of the auditor group): failed at the
  **socket file permission** layer itself —
  `dial unix .../session-store.sock: connect: permission denied` — before
  ever reaching the app's own SO_PEERCRED check. This is the `UMask=0007`
  design decision above working exactly as intended.

This closes a gap flagged as unverified in
`docs/verification/pilot-session-store.md`/`contracts/pilot-session-store.yaml`
at write time (no unit test anywhere in this repo exercises "auditor group
exists and resolves, caller is a real non-member" — only "group doesn't
exist" and "group unset" are covered in Go tests). The live pass above
verifies the actual missing case; the verification doc's language has
been left as-is (it correctly describes what unit tests do and do not
cover) since this evidence doc is the live-verification record spec.md
§46 calls for.

### SS18 — fresh full-topology E2E: real Gateway → HTTPSink → ingest → replay

Rebuilt `pilot`/`pilot-access-gateway` at current HEAD and redeployed to
the existing `ag-gw01` fixture (`gateway_id=gpu-01, scope=gpu`). Hand-added
(per Phase 7's own documented deferral — this wiring is not yet templated
into the apply playbook, spec.md §35 groups it with Phase 8) a
`gateway.recording` section to `/etc/pilot/access-gateway.yaml`:

```yaml
recording:
  mode: terminal_output
  failure_policy: best_effort
  session_store_url: https://ag-sessionstore01.ipa.pilot.internal:8443
  session_store_ingest_token_file: /etc/pilot/session-store-ingest-token
  session_store_ca_file: /etc/ipa/ca.crt
```

**Gotcha found**: the ingest token file must be owned by the
`pilot-access-gateway.service` unit's own `User=pilot-gateway` (mode
0400, matching the existing keytab's own ownership convention) — the
process failed closed with a clear `permission denied` error when the
file was root-owned. An operator-facing mistake on my part during manual
wiring, not a code bug; worth calling out for whoever eventually templates
this into the apply playbook.

**Gotcha found**: `pilot vm-target wire --name ag-gw01 --peer X` **replaces**
the entire previously-written wire block rather than adding to it (the
tool's own `--help` says so explicitly: "Re-running replaces the block
instead of appending"). Running it a second time with only the new peer
silently deleted `ag-gw01`'s pre-existing `ipa1.ipa.pilot.internal` and
`ag-target01.ipa.pilot.internal` entries from earlier phases, which
manifested as a FreeIPA-unreachable authorize failure and then a
`sss_ssh_knownhostsproxy: Could not resolve hostname` ControlMaster
failure. Fixed by re-running `wire` with **all** peers in one call. Not a
pilot bug — an operator (me) not re-reading the tool's own documented
semantics before a second invocation against an already-wired host.

With DNS restored, a real password-authenticated `alice` one-shot connect
straight to the Gateway's ForceCommand entry point (bypassing Directory —
Directory's own routing hop was already verified live in Phase 5; this
pass's job is proving Store persistence, not re-proving routing):

```
sshpass -p 'TestPass!2027y' ssh -tt alice@ag-gw01 "pilot-connect <uuid> ag-target01.ipa.pilot.internal"
  whoami
  echo PHASE8_E2E_MARKER_abc123
  exit
```

Real shell, `whoami` → `alice`, marker echoed, clean exit (`EXIT=0`).
`pilot session list` (as `alice`, on `ag-sessionstore01`) showed the new
session: `user=alice target=ag-target01.ipa.pilot.internal scope=gpu
mode=terminal_output complete=true event_count=5`. `pilot session replay`
reproduced the full session transcript byte-for-byte, including the MOTD,
`alice` (the `whoami` output), and `PHASE8_E2E_MARKER_abc123` — proving the
complete chain: Gateway's recorder → `HTTPSink` → TLS ingest → encrypted
storage → decrypt → replay, all real, no mocks, no fabricated output.

### store restart preserves existing sessions

`systemctl restart pilot-session-store.service` then `pilot session list`
(as `alice`): all three pre-existing sessions still listed with correct
metadata — durable SQLite index, not an in-memory cache lost on restart.

### Known gaps not exercised live in this pass

- **Disk full**: not simulated — would need either a small dedicated loop
  device mounted at `/var/lib/pilot-session-store` or filling the host's
  real root filesystem, neither of which was worth the risk/setup cost on
  a shared fixture pool for this pass. `Store.IngestEvents`'s SQLite write
  path returning a real OS error and the caller treating it as an ingest
  failure is architecturally sound (no code path swallows a write error),
  but this specific failure mode has no dedicated test, unit or live.
- **Corrupt payload**: covered at the unit level
  (`TestStoreReplayTamperedCiphertextFails`, real AES-GCM
  authentication failure on a flipped ciphertext byte) but not
  independently re-exercised against the live database file in this pass.

## Residual state / cleanup

- `ag-gw01` restored to its deployed baseline config (`recording:` section
  and the hand-placed ingest token file removed, service restarted,
  `/v1/health` reconfirmed `ok`) — no experimental config left on this
  shared, long-lived fixture.
- `ag-gw01`'s `/etc/hosts` wire block now correctly carries all three
  peers it needs (`ipa1`, `ag-target01`, `ag-sessionstore01`) in one
  combined `pilot vm-target wire` call, superseding the two accidentally-
  destructive intermediate calls made while debugging the gotcha above.
- `ag-sessionstore01` is kept running as a new, permanent addition to the
  reusable evidence-fixture pool (alongside `ag-spike-ipa`/`ag-gw01`/
  `ag-gw02`/`ag-target01`/`ag-target02`/`ag-directory01`), matching this
  delivery's established practice.
- `alice`'s FreeIPA group memberships now also include
  `role-pilot-session-auditor` (in addition to her existing
  `role-pilot-portal-user`) — a deliberate, documented, permanent test
  fixture, not an accident.
- Four test session rows remain in `ag-sessionstore01`'s
  `/var/lib/pilot-session-store/index.db` (`live-test-001`, `gap-test-001`,
  and two live-E2E UUIDs) — non-sensitive marker/placeholder content only,
  left in place because the host has no `sqlite3` CLI installed and this
  delivery intentionally does not add a `pilot session delete` command
  (deletion only happens via the retention sweep, per spec.md §28.5).
  Future reuse of this fixture should expect these rows to already exist.
- Local test secrets (`/tmp/session-store-secrets.env`) are session-scratch
  only, never committed.

## Full repo test suite

`go build ./... && go vet ./... && go test ./...`: **3868 tests passed,
0 failed, across 54 packages** (up from Phase 7's 3827/52 — includes the 5
new `internal/sessionstore/encryption_test.go` tests and the pre-existing
Phase 8 test files this evidence doc's live pass verifies against real
infrastructure for the first time).
