# Phase 5 — gateway effective recording policy and PIT1 minting (2026-09-23)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
Phase 5 — §13–§15 (precedence, resolver, gateway config), §17 (authorize
contract, deny reasons, token minting), §27.1/§27.1a (gateway playbook,
signing key, legacy token removal), §27.3 (site order) and §27.4
(contract/example). Verification rows: AG37 (rewritten), AG41–AG49, AG56.

## Tested revision

- Candidate commit `e50827d`, tree `2089210281b8ea1bc16f4172218ba007fab78590`.
- The deployed `pilot` and `pilot-access-gateway` binaries were built from
  this commit. The `pilot vm-target run` runner binary was an earlier local
  build and only drives Ansible.
- These were development runs from the working tree, not a clean isolated
  checkout. The formal clean-checkout candidate test is Phase 8.

## Target

Same Phase 0/2/4 topology: gateway `phr-gw` (Ubuntu 24.04, FreeIPA client
of `phr-ipa`, `ipa-server-4.13.1-3.el9_8.2`), session store `phr-store`
from Phase 4. Grouped inventory `freeipa-server=phr-ipa`,
`pilot-access-gateway=phr-gw`; run with `pilot vm-target run` on the host
Ansible. Vars: `gateway_id=phr-gw1`, `gateway_scope=phr`,
`pilot_session_store_url=https://phr-store.ipa.pilot.internal:8443`, no
`pilot_session_recording_mode`. The disposable test vault carried the same
signing key as the store; no real vault was used.

## Results

| Scenario | Result |
|---|---|
| `gateway-scope-apply.yml` publishing `pilot-target-phr` | `ok=12 changed=2 failed=0` |
| fresh-host `--check --diff` (gateway never applied on `phr-gw`) | two baseline check-mode bugs surfaced first: Step 8 asserted a keytab that only the real run creates, and Step 16 started/restarted a socket unit that check mode had not installed. Both are now skipped in check mode for artifacts this run would create. Re-run: `ok=33 changed=12 failed=0` |
| first real apply (working tree) | `ok=71 changed=30 failed=0` |
| second apply (working tree) | `ok=65 changed=0 failed=0` |
| apply of the committed candidate | `ok=66 changed=3 failed=0`: the two rebuilt binaries and the service restart, nothing else |
| second apply of the committed candidate | `ok=65 changed=0 failed=0` |
| AG41 probe (row command from the committed spec, `pilot verify --probe`) | `rc=0` PASS: `recording:` block present, `failure_policy: fail_closed`, no `mode:` line (built-in metadata) |
| AG42 probe | `rc=0` PASS: store configured, signing key `pilot-gateway:pilot-gateway 400` |
| AG43 probe | `rc=0` PASS: `/etc/pilot/session-store-ingest-token` absent |
| gateway startup log | `recording session store configured` with key id `6f91d10438f8be21`, the same key id `phr-store` logs |

Connect-level live scenarios (a marked host recording end to end, L9/L10
connect denials, and so on) depend on the Phase 6 connect core and run in
Phase 8.

## Unit and regression coverage added

- `internal/gatewayconfig`:
  - the new defaults: unset mode kept raw, `fail_closed`, 10s grace, 24h
    lifetime;
  - the grace/flush relation, the lifetime bounds, https-only store URL,
    and that a terminal default needs a store;
  - the legacy `session_store_ingest_token_file` is rejected with a
    migration hint;
  - signing key file: hex length, hex content, permissions, missing file.
- `internal/gatewayapi`:
  - `TestResolveRecordingMode` (every precedence row);
  - deny reasons for unknown, invalid, reserved and zero-value policies;
  - terminal mode without a store;
  - metadata responses that carry no store coordinates;
  - token claims binding and a unique `jti` per mint;
  - a fresh policy on every request;
  - `session_id` only binds the token (AG37);
  - HBAC denials carry no recording fields;
  - `/v1/access` recording JSON;
  - per-host `userclass` unreadable denial under branch R (AG56).

## Checks on the candidate

- `go test -race -count=1 ./...` exited 0.
- `golangci-lint` v2.12.1 reported 0 issues on the changed packages.
- `pilot spec --lint` reported 28 rows and 0 findings.
- `pilot contract lint` passed.
- `ansible-lint` on the gateway playbook reported nothing new against HEAD
  (one fewer `no-handler` finding).

## Candidate

| File | Blob |
|---|---|
| `playbooks/apply/pilot-access-gateway-apply.yml` | `e153a0cd5db086f76062b396695e4910e5088e4b` |
| `playbooks/site.yml` | `be1eab000f48b384ce5651e4e1d37bd8938b8a5e` |
| `internal/gatewayconfig/config.go` | `a278e2f686104f41d10dbc4e9827fa1aff9ae65f` |
| `internal/gatewayapi/recording_policy.go` | `f9ba2430ec1f694f9ddc718bb26f7b42cd6ab9da` |
| `internal/gatewayapi/routes.go` | `82211493c4444d215d707f77858a2cb25e85993c` |
| `internal/gatewayapi/server.go` | `5d23a59df36c9af675a4b96dc93be71df400f294` |
| `internal/gatewayapi/types.go` | `b9bf1d5efc98509f832ae4e744cd50909b56ceff` |
| `cmd/pilot-access-gateway/main.go` | `4726dcb33bfb53a42b308bf16b89922fe63b9b88` |
| `cmd/pilot/cmd/portal_session_connect.go` | `76f22b414cc9d923b715bea68d4b5cce857c5926` |
| `cmd/pilot/cmd/portal_client.go` | `031bce5450111117f63b28b040741d6bc5e46329` |
| `cmd/pilot/cmd/portal_ssh.go` | `f4b322df78a38ed3445e77397cef08a16ab60eeb` |

## Note

While collecting these probes, a `pilot verify --probe` call with an empty
command fell back to verifying every spec in `docs/verification/` against
`phr-gw`. Those rows are read-only apart from a few `logger` self-test lines
and a `sudo -n true`. The gateway configuration did not change, and none of
that run is used here.
