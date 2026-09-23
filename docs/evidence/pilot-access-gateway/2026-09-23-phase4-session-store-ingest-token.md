# Phase 4 — per-session ingest tokens, store binding and recorder reliability (2026-09-23)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
Phase 4 — §16 (PIT1 tokens), §21.1–§21.4 (store auth, binding, schema v2
migration with backup, `last_seq`, finish rules), §27.2 (store playbook),
§19.1–§19.3/§19.5/§19.6 (recorder options, watchdog, backpressure,
cancellation, completeness), §19.7 `Finish`, and §20.1/§20.2 (HTTPSink finish
body, error classification, retry).

## Tested revision

- Candidate commit `89c5ff0`, tree `7d5c081db8b2e6cf23fe82dc971904c11a72253c`.
- Execution-affecting blobs: see "Candidate" below.
- These were development runs from the working tree, not a clean isolated
  checkout. The formal clean-checkout candidate test is Phase 8.

## Target

This is the Phase 0/2 topology. Session store on `phr-store` (Ubuntu 24.04,
FreeIPA client of `phr-ipa`, `ipa-server-4.13.1-3.el9_8.2`). Grouped
inventory: `freeipa-server=phr-ipa` and `pilot-session-store=phr-store`, run
with `pilot vm-target run` on the host ansible. `--sandbox` could not be used:
it copies only the playbook directory, so the locally built binaries were not
visible. The test vault was disposable, with a random master key and signing
key; no real vault was used.

## Results

| Scenario | Result |
|---|---|
| fresh-host `--check --diff` (never-applied `phr-store`) | first attempt failed at `Enable + start pilot-session-store.service` (unit not installed under check mode, a baseline bug) → fixed by skipping enable/start/restart in check mode for units this run would install → re-run `ok=29 changed=11 failed=0` |
| real apply | `ok=43 changed=17 failed=0` |
| second apply | `ok=40 changed=0 failed=0` |
| apply of the committed candidate playbook (after a formatting-only `when:` rewrite for ansible-lint) | `ok=40 changed=0 failed=0` |
| SS24 probe (`pilot verify --probe`, as the verify pipeline runs it) | `rc=0` PASS: signing key file `pilot-session-store:pilot-session-store 400`, the former `/etc/pilot/session-store-ingest.token` is absent |
| live PIT1 ingest against `https://phr-store…:8443` (tokens minted with the test key; token values never printed) | alice's token: start `200`, events `200`, finish `200`; mallory's token for the same sid: events `403`; a static bearer string: start `401`; events after finish: `409` |

## Unit and regression coverage added

- `internal/ingesttoken`: round trip, unique jti, every rejection reason.
  Verify does not check the start window; `CheckStartWindow` does, at
  `sby + 60s`. No token material appears in errors.
- `internal/sessionstore`:
  - real v1 → v2 migration, with the pre-migration `VACUUM INTO` backup
    (0600, taken before any ALTER);
  - refusal when free space is insufficient or a backup already exists;
  - trailing-gap completeness, finish idempotency, rejection of writes
    after finish, and jti binding.
- `cmd/pilot-session-store`:
  - the full HTTP lifecycle with real tokens;
  - SS03/SS19/SS20/SS21 rules, including another user's token for the
    same sid and a second token for a running sid;
  - the start window;
  - read API exposure of `recording_policy_source`/`last_seq`, with no
    `ingest_jti`.
- `internal/sessionrecording`:
  - an idle, healthy fail_closed session survives six times its grace (the
    F7 regression);
  - a hung sink trips the wall-clock watchdog, and so does a sink error;
  - fail_closed backpressure loses no seq;
  - best_effort sink errors and queue drops mark the recording incomplete
    and emit `recording_gap`;
  - drain timeout, and aborted context;
  - identity on the recorder's own audit events, and `InputDone`;
  - HTTPSink retry (the same body is re-sent), permanent errors with no
    retry, and a finish body that carries `ended_at`/`last_seq`.
  Repeated with `-count=5 -race` without failures.

## Candidate

| File | Blob |
|---|---|
| `playbooks/apply/pilot-session-store-apply.yml` | `4fa1bbe0cd8ef780f20aec55ead4dd6a616ba188` |
| `cmd/pilot-session-store/ingest_api.go` | `cf0e40bea1cd5f84a16d4d2e806e718e0b35d918` |
| `internal/ingesttoken/ingesttoken.go` | `70f9be064ede479485baae0e8bcc1b1062aa9f0f` |
| `internal/sessionstore/schema.go` | `2fa831a85906e5de734d838a75e4ba48193d5a24` |
| `internal/sessionstore/store.go` | `0fae768e607971c3ebf8f5e11aff91ac804fbdd0` |
| `internal/sessionrecording/recorder.go` | `612fe100a08f71d4734d204a5072c4fd0e20ef8f` |
| `internal/sessionrecording/httpsink.go` | `eafe281bf315bdb9805aa6607582541036b699c1` |

The deployed `pilot-session-store` binary was built from this same source.
The candidate apply reported `changed=0`, including for the binary copy.
After the commit, `go test -race -count=1 ./...` exited 0 and
`golangci-lint` v2.12.1 reported 0 issues on the changed packages.
`ansible-lint` on the store playbook reported the same 6 `run-once` findings
as the baseline, and nothing new.
