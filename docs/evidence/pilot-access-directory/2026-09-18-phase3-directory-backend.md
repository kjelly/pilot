# Phase 3 — Directory backend

Spec: `docs/tmp/now/spec.md` §10-§12, Phase 3 landing gate (§44).

## What was built

- `internal/accessdirectory/`: `model.go` (`ScopeRoute`/`DirectoryAccess`/
  `DirectoryTarget`/`TargetRoute`), `catalog.go` (`LoadScopeCatalog` —
  discovers scopes via `HostgroupFinder`, resolves each gateway
  hostgroup's member FQDNs via `HostgroupShow`), `resolver.go`
  (`LoadDirectoryAccess` — one `accessportal.LoadPolicySnapshot` +
  one `accessportal.ResolveScopeAccess` per discovered scope, merged by
  FQDN into `DirectoryTarget.Routes[]`). No HBAC/sudo matching logic of
  its own anywhere in this package (spec.md §9/§49.12) — every
  authorization fact comes from `accessportal`.
- `internal/directoryapi/`: HTTP-over-Unix-socket server mirroring
  `internal/gatewayapi`'s shape exactly — `SO_PEERCRED` identity resolved
  once per connection (`connctx.go`), portal-group defense-in-depth gate
  on every endpoint except `/v1/health`, `GET /v1/identity`,
  `GET /v1/access`, `GET /v1/access/{fqdn}`, `POST /v1/connect/resolve`,
  `GET /v1/health` — every user-facing response is a fresh
  `accessdirectory.LoadDirectoryAccess` call, no caching layer anywhere.
- `cmd/pilot-access-directory/`: `config.go` (YAML, `KnownFields(true)`,
  no `gateway_known_hosts`-style field — matches the spec correction
  pass), `main.go` (cobra `serve`/`version`, systemd-socket-activation
  support, `freeipaaccess.Client` doubles as both `Provider` and
  `HostgroupFinder` from Phase 0 — no new client type needed).

Fake-provider test coverage: 27 tests (`accessdirectory`: 9,
`directoryapi`: 14, `cmd/pilot-access-directory`: 4), including explicit
call-count assertions proving `UserShow`/`hbacrule_find`/`sudorule_find`
each run exactly once per `LoadDirectoryAccess` call regardless of scope
count (spec.md §9.3), and that a host shared by two scopes is `HostShow`'d
once via the snapshot's cache (inherited from Phase 1).

## A real bug found and fixed during this phase

`LoadScopeCatalog`'s first draft failed the **entire** catalog load (all
scopes, all users) if `HostgroupShow` errored for even one discovered
`pilot-gateway-<scope>` hostgroup (e.g. deleted between the `HostgroupFind`
and `HostgroupShow` calls, or a transient read glitch) — a much larger
blast radius than anything else in this call chain, and not required by
D1's fail-closed principle (which is about not treating uncertain
*authorization* state as "fall back to allow", not about maximizing how
much unrelated routing data one glitch can take down). Fixed to degrade
only that one scope to `RouteStatus: "no_gateway"`, mirroring how
`LoadDirectoryAccess` already isolates one scope's `ResolveScopeAccess`
failure from every other scope. Covered by
`TestLoadScopeCatalog_BrokenGatewayHostgroupDegradesOnlyThatScope`.

(A related, pre-existing characteristic was also reviewed and
deliberately left alone: `accessportal.LoadPolicySnapshot`'s
`expandReferencedHostgroups` already fails the whole snapshot if *any*
HBAC/sudo rule anywhere references an unreadable hostgroup — but this was
already true for every existing Gateway instance before Phase 3 existed,
since `hbacrule_find(all=true)`/`sudorule_find(all=true)` were already
global/unscoped on every single gateway. Directory reusing the same
snapshot loader does not change this failure mode's blast radius versus
the pre-existing Gateway fleet; it was not something Phase 3 introduced,
so it was left as-is rather than touched under a "byte-for-byte identical"
Phase 1 refactor mandate.)

## Real FreeIPA cross-scope verification (landing gate item: "real FreeIPA
user access cross-scope result")

Topology: the same reusable `ag-spike-ipa`/`ag-gw01`/`ag-gw02` vm-targets,
now carrying real `pilot-target-gpu`/`pilot-target-dmz` and
`pilot-gateway-gpu`(`ag-gw01`)/`pilot-gateway-dmz`(`ag-gw02`) hostgroups
from Phase 2. Built `cmd/pilot-access-directory` for linux/amd64, copied it
to `/usr/local/bin/pilot-access-directory` on `ag-gw01` via `scp` (using
the same SSH key `pilot vm-target show-inventory` reports), and ran it
standalone (not via systemd — that's Phase 4) against a throwaway config
in `/tmp/directory-test/` **reusing the existing
`pilot-access-gateway` reader keytab** (`/etc/pilot/pilot-access-gateway.keytab`,
principal `pilot-access-gateway/ag-gw01.ipa.pilot.internal@IPA.PILOT.INTERNAL`)
— matching Phase 0 §8.2's explicit instruction to use the existing
Gateway-Reader-level principal, no new FreeIPA privilege needed even for
this live smoke test.

```
$ sudo -u alice curl --unix-socket .../access-directory.sock http://localhost/v1/access
{"user":"alice", ..., "targets":[
  {"fqdn":"ag-target01...","routes":[{"scope":"gpu",...,"gateway_candidates":["ag-gw01..."],"route_status":"ready"}]},
  {"fqdn":"dmz-a...",      "routes":[{"scope":"dmz",...,"gateway_candidates":["ag-gw02..."],"route_status":"ready"}]},
  {"fqdn":"gpu-a...",      "routes":[{"scope":"gpu",...,"gateway_candidates":["ag-gw01..."],"route_status":"ready"}]},
  {"fqdn":"gpu-b...",      "routes":[{"scope":"gpu",...,"gateway_candidates":["ag-gw01..."],"route_status":"ready"}]}
]}
```

Real, live proof that one Directory call correctly aggregates access
across the **two real, independently-scoped Gateway instances** Phase 2
created — alice sees both her `gpu` targets (routed to `ag-gw01`) and her
`dmz` target (routed to `ag-gw02`) in one response, each with the correct
live `gateway_candidates`. `bob` (real FreeIPA user, not a member of
`gpu-users`/`dmz-users` on this environment) correctly got `"targets":[]`
— an empty, non-error result, not a crash.

`POST /v1/connect/resolve` for `gpu-a.ipa.pilot.internal` returned
`{"allowed":true,"session_id":"<uuid>","route":{"scope":"gpu",
"gateway_candidates":["ag-gw01..."]}}`; for a nonexistent target,
`{"allowed":false,...}` with no `session_id`.

## Stateless restart (landing gate item)

Sent SIGTERM (graceful shutdown logged), fully restarted the process, and
re-queried `/v1/access` for alice: identical target list, byte-for-byte —
no local state read or needed to reproduce the same answer.

## FreeIPA outage fail closed (landing gate item)

Restarted the server pointed at a `freeipa.servers` entry that does not
resolve (`nonexistent-ipa-host.invalid`). The process still started
cleanly (lazy credential/connection loading, same pattern as
`pilot-access-gateway`'s `NewClient`) and:

```
$ curl --unix-socket .../access-directory.sock http://localhost/v1/health
HTTP 503
{"status":"degraded","directory_id":"...","freeipa":"unreachable","scope_catalog":"unreachable"}

$ sudo -u alice curl --unix-socket .../access-directory.sock http://localhost/v1/access
HTTP 503
{"error":"access service unavailable"}
```

## Cleanup

`pkill`'d the test server, removed `/tmp/directory-test/` and
`/usr/local/bin/pilot-access-directory` from `ag-gw01`, confirmed both
gone via `ls`. No residual state left on this shared vm-target; the
`pilot-access-gateway` service itself (systemd-managed, unrelated to this
throwaway binary) was left untouched throughout.

## Gotcha (non-obvious, worth recording for the next person to smoke-test
a binary this way)

`pilot vm-target exec` runs each command as its own short-lived SSH
session with a PTY; `nohup ... &` alone does **not** survive the session
ending (the whole process group gets torn down with the PTY) — must use
`setsid nohup ... < /dev/null &` to fully detach. Also: `pkill -f
pilot-access-directory` / `pgrep -f pilot-access-directory` run **through**
`pilot vm-target exec -- bash -c '...pilot-access-directory...'` can match
their own invoking shell's command line (the search string appears
verbatim in the wrapping script text), giving a false-positive PID —
prefer killing by a specific captured PID, or `pgrep -x`, when the search
string might also appear in the command used to search for it.

## Deferred to later phases (not gaps in Phase 3 itself)

- `scripts/build-pilot-access-directory.sh`, `contracts/pilot-access-directory.yaml`,
  systemd units, `pilot-access-directory-apply.yml`, site/catalog/Dockerfile
  integration — all explicitly Phase 4 (§44) landing gate items.
- Bounded TCP/22 reachability probe for `RouteStatus` — explicitly Phase 5
  (§19); left as a `// TODO(spec.md §19 Phase 5)` in `resolver.go`.
