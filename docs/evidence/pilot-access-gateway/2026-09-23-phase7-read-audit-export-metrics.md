# Phase 7 — read audit, asciicast export, recording show and metrics (2026-09-23)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
Phase 7 — §21.5 (read audit), §28 (`pilot session export`), §29
(`pilot access recording show`) and §31 (node_exporter textfile metrics).
Verification rows: AG55, AG57, SS25, SS26.

This record also covers the Phase 6 connect core (`9e7b507`): its binaries
were deployed in the same runs. Phase 6's own rows (AG50–AG54, AD31) are
unit-test evidence, and connect-level live scenarios run in Phase 8.

## Tested revision

- Candidate commit `31f5c23`, tree `ad85698c864c4fa976b99404ffed97fea3f37f4f`.
- The deployed `pilot`, `pilot-access-gateway` and `pilot-session-store`
  binaries were built from this commit.
- These were development runs from the working tree, not a clean isolated
  checkout. The formal clean-checkout candidate test is Phase 8.

## Target

The same phr topology as Phases 0–5:

- gateway `phr-gw` and session store `phr-store` (Ubuntu 24.04);
- FreeIPA `phr-ipa` (`ipa-server-4.13.1-3.el9_8.2`);
- targets `phr-ta` (no recording marker) and `phr-tb` (host marker
  `terminal_output`, set in Phase 2).

It was run with `pilot vm-target run` on the host Ansible, using a
disposable test vault.

`host-monitoring` is not deployed on this topology. To test the enabled
metrics branch, `/var/lib/node_exporter/textfile` was created by hand on
both VMs as `root:root 1777`. That is the owner and mode
host-monitoring's Step 9b uses.

## Results

| Scenario | Result |
|---|---|
| store apply, no textfile dir (working tree) | `ok=45 changed=3 failed=0`: binaries and restart only; the "metrics stay disabled" note printed; config unchanged |
| gateway apply, no textfile dir (working tree) | `ok=70 changed=3 failed=0`: same shape |
| AG55 / SS26 probes, no textfile dir | `rc=0` PASS (no metrics file) |
| store apply after creating the textfile dir | `ok=44 changed=3 failed=0`: config (`metrics.textfile_path`), unit (`ReadWritePaths=/var/lib/node_exporter/textfile`), restart |
| gateway apply after creating the textfile dir | `ok=69 changed=3 failed=0`: Step 11 config, Step 15 unit, restart |
| AG55 / SS26 probes, textfile dir present | `rc=0` PASS: `pilot_access_gateway.prom` / `pilot_session_store.prom` are mode 0644 and hold every family's HELP/TYPE (3 gateway, 6 store) |
| committed candidate: store apply, then re-apply | `ok=43 changed=3` (binaries, restart), then `ok=42 changed=0 failed=0` |
| committed candidate: gateway apply, then re-apply | `ok=68 changed=3` (binaries, restart), then `ok=67 changed=0 failed=0` |
| committed candidate probes AG41, AG42, AG43, AG55, SS24, SS26 | all `rc=0` PASS |
| `sudo pilot access recording show phr-tb… --format json` (real FreeIPA, gateway keytab) | `host_policy: terminal_output`, `effective: terminal_output`, `policy_source: host`, rc 0 |
| `sudo pilot access recording show phr-ta…` | `inherit` → `metadata`, source `built_in_default`, rc 0 |
| `sudo pilot access recording show no-such-host…` | rc 1, `host not found in FreeIPA` (a real `host_show` NotFound, matched by `freeipaaccess.IsNotFound`) |
| the same as `nobody` | rc 2, `must run as root on a pilot-access-gateway host` |
| `sudo pilot session replay <sid>` on `phr-store` (root is not an auditor) | HTTP 401; journald has one `recording_replayed` event with `result: denied`, `auditor: root`, no payload; `read_requests_total{action="replay",result="denied"}` counted |

Two defects found during these runs were fixed before the candidate:

- `pilot session` defaulted to `/run/pilot/session-store.sock`, but the
  store playbook serves `/run/pilot-session-store/session-store.sock`.
  Replay and export failed without `--socket`. Both defaults now match
  the deployed path.
- Runtime errors from `pilot access recording show` and
  `pilot session export` printed cobra's usage text. Those commands now
  set `SilenceUsage`.

A successful auditor replay/export and connect-level recording need an
auditor account and portal users. They are Phase 8 scenarios.

## Unit and regression coverage added

- `internal/promtext`: rendering, escaping, stable order, atomic 0644
  write, write loop (start and final write).
- `internal/gatewayapi` `TestMetricsTextfileGatewayCounters`: each
  authorize decision counted once by result/reason, allowed connects by
  mode/source, no user/session/target labels.
- `cmd/pilot-session-store`:
  - `TestReadAPIAuditsReplayAndExport` (SS25): ok, not_found, error and
    denied results; auditor; session identity; no payload;
  - `TestMetricsTextfileStoreCounters`: an idempotent finish retry is not
    counted twice; gap ranges; auth failure reasons;
  - metrics path validation.
- `internal/sessionstore` `TestStoreFinishSessionResultReportsGapsAndRetries`.
- `internal/sessionrecording` `TestAsciicastExport*`: header, o/i/r,
  incomplete/gap/redacted markers, per-stream UTF-8 rejoining of a split
  CJK character, U+FFFD for invalid and trailing bytes.
- `cmd/pilot/cmd` `TestSessionExport_*`: show before replay with
  `purpose=export`, 0600, `--force`, stdout, bad arguments.
- `cmd/pilot/cmd` `TestAccessRecordingShow_*` (AG57): non-root exit 2,
  every policy state, json, host not found.
- `internal/freeipaaccess` `TestIsNotFound`, against the captured NotFound
  error.

## Checks on the candidate

- `go test -race -count=1 ./...` exited 0.
- `golangci-lint` v2.12.1 reported 0 issues on the changed packages.
- `pilot spec --lint`: gateway 35 rows, 0 findings; store 27 rows, with
  the same SS02 warning as HEAD.
- `pilot contract lint` passed.
- `ansible-lint` on both playbooks gave the same findings as HEAD.

## Candidate

| File | Blob |
|---|---|
| `playbooks/apply/pilot-access-gateway-apply.yml` | `0b1be65a6672bf21644ae1af0bb38f87f8bdaee6` |
| `playbooks/apply/pilot-session-store-apply.yml` | `7c6c0f93418a5ee58c1d93a686526571cf3fb0e7` |
| `internal/promtext/promtext.go` | `3db612af129b4d07b04759a6042538fba67c03c0` |
| `internal/gatewayapi/metrics.go` | `62460faa39ff78a947697835ab003a8d5dbac672` |
| `internal/gatewayapi/routes.go` | `2f3f26cdd1d16b5a487490f40d1bab90f04958f2` |
| `cmd/pilot-session-store/metrics.go` | `09fd02e73719a1feb71ac142887fd571c63d9e13` |
| `cmd/pilot-session-store/read_api.go` | `c02f4aa42c870b939814e0683a4e0cc3fb770e78` |
| `cmd/pilot-session-store/ingest_api.go` | `5ba012fd6502e07f26916af2d92e9fffb830aa7d` |
| `internal/sessionstore/store.go` | `2ab87bba068737edf97e3d983525f501574579ee` |
| `internal/sessionrecording/asciicast.go` | `fcffb4cb3f0c9f3de0ae193806e9ecb0dbb55635` |
| `cmd/pilot/cmd/session_export.go` | `675db21ce2b5d4fcc71168d92749906db19e8965` |
| `cmd/pilot/cmd/access_recording_cli.go` | `e226d6701f08bec3938adf8340382e4dbbb4ab88` |
| `cmd/pilot/cmd/session_list.go` | `574d9143088f2f3221848b7671edab997ff56df6` |
