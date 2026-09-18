# Phase 6 — Session ID + metadata audit correlation

Spec: `docs/tmp/now/spec.md` §21/§22, Phase 6 landing gate (§44).

## What was built

- `internal/sessionaudit/` (new): `SessionAuditEvent` (spec.md §21.2's
  struct, field-for-field) + 10 event-kind constants (the Directory/Gateway
  half of the minimum list — `recording_*` kinds are Phase 7's), and
  `Emitter`/`NewEmitter(tag)`/`Emit(ev)` — writes single-line JSON to
  syslog facility LOCAL6 (spec.md §22), fail-soft: an unreachable local
  syslog degrades to `slog.Default()` instead of failing the caller's
  real connect/authorize/serve flow (mirrors `internal/accessportal`'s
  "annotations are enrichment, never authorization" principle and
  `internal/freeipaaccess.Client`'s lazy fail-soft credential loading).
- Wired into both hops, replacing ad-hoc `slog` calls with structured
  events: `cmd/pilot/cmd/portal_session_connect.go` (Gateway:
  `gateway_authorize_allowed`/`_denied`, `target_connect_started`,
  `session_ended`/`target_connect_failed`), `internal/directoryapi/handlers.go`'s
  `handleConnectResolve` (Directory: `directory_connect_requested` at the
  very start of every attempt — even a denied one — and
  `directory_route_resolved` on every exit path), `cmd/pilot/cmd/directory_ssh.go`'s
  `connectToGateway` (Directory: `directory_gateway_attempt` per candidate,
  `directory_gateway_connected` once one succeeds).
- `session_id` is now generated once at the top of `handleConnectResolve`
  (previously only once a ready route was found), so a denied attempt's
  `directory_route_resolved` event still carries a correlatable ID even
  though it's never returned to the client.

4 new unit tests in `internal/sessionaudit`. Full repo: build/vet clean,
3815 tests pass (up from 3811 in Phase 5).

## Landing gate verification (live)

Redeployed `pilot`/`pilot-access-gateway` on `ag-gw01` and
`pilot`/`pilot-access-directory` on `ag-directory01` with current HEAD,
then drove one real `alice` Connect (Directory → `ag-gw01` → `ag-target01`,
gpu scope) via `trec`, then reconstructed the whole chain from **one**
`session_id` (`3ec9cbeb-ac96-4597-ab7e-1e298cda7853`) across **two
different hosts/processes**:

`ag-directory01` (`journalctl -t pilot-access-directory`):

```
seq=1 directory_connect_requested   user=alice target=ag-target01...
seq=2 directory_route_resolved      scope=gpu result=ready
seq=1 directory_gateway_attempt     gateway_fqdn=ag-gw01... (new process per connect, own seq space)
seq=2 directory_gateway_connected   result=ok
```

`ag-gw01` (`journalctl -t pilot-access-gateway | grep 3ec9cbeb`):

```
seq=1 gateway_authorize_allowed  gateway_id=gpu-01 gateway_scope=gpu
seq=2 target_connect_started
seq=3 session_ended              result=ok
```

Exactly spec.md §44's Phase 6 landing gate: "用一個 session ID 從中央 log
可重建: route selected, gateway allowed, target started, target ended" —
all seven events, one session_id, two hosts.

Also confirmed the facility is genuinely LOCAL6 (not just journald's
generic capture): `journalctl -t pilot-access-directory -o verbose`
shows `SYSLOG_FACILITY=22` (LOCAL6 in standard syslog facility numbering)
— the exact facility the pre-existing, separate `audit-log-forwarding`
component's `local6.*` rsyslog rule already forwards to a central SIEM.
This phase does not touch or re-verify that forwarding pipeline itself
(D10: audit-log-forwarding is a supplement, not something this spec
re-implements) — `ag-directory01`/`ag-gw01` don't have that optional
component installed, so this evidence is "correct local LOCAL6 emission,"
not "confirmed to arrive at a real central log server," which was never
this phase's job.

## Deferred to later phases (not gaps in Phase 6 itself)

- Terminal recording lifecycle events (`recording_started`/`recording_gap`/
  `recording_failed`) — Phase 7's `SessionAuditEvent`-adjacent concern,
  deliberately excluded from this phase's event-kind constants.
- A real multi-VM run of `audit-log-forwarding` actually receiving and
  centrally aggregating these LOCAL6 lines — this phase proves emission is
  correct; end-to-end central-log aggregation is `audit-log-forwarding`'s
  own already-separately-verified job, not re-tested here.
