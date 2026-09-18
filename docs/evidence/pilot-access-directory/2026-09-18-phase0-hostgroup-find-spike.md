# Phase 0 — `hostgroup_find` FreeIPA discovery spike

Spec: `docs/tmp/now/spec.md` §8 (`internal/freeipaaccess.HostgroupFinder`), Phase 0
landing gate (§44).

## Goal

Prove, against a real FreeIPA server and the **existing** `pilot-access-gateway`
reader-level service principal (no new privilege), that:

1. `hostgroup_find` is callable and returns the real response shape.
2. The reader can already read `pilot-target-*` (and, once Phase 2 creates
   them, `pilot-gateway-*`) without any additional grant.
3. No write RPC was used anywhere in this spike.

## Topology

Reused the already-running Phase 7/8 `pilot-access-gateway` vm-targets —
no new VM provisioned:

- `ag-spike-ipa` (192.168.122.2) — FreeIPA server (`ipa1.ipa.pilot.internal`).
- `ag-gw01` (192.168.122.3) — has the existing reader keytab at
  `/etc/pilot/pilot-access-gateway.keytab`, principal
  `pilot-access-gateway/ag-gw01.ipa.pilot.internal@IPA.PILOT.INTERNAL`.

## Commands run (via `pilot vm-target exec --name ag-gw01`)

```
$ kinit -kt /etc/pilot/pilot-access-gateway.keytab pilot-access-gateway/ag-gw01.ipa.pilot.internal
$ klist
Default principal: pilot-access-gateway/ag-gw01.ipa.pilot.internal@IPA.PILOT.INTERNAL
Valid starting     Expires            Service principal
09/18/26 07:00:40  09/19/26 06:11:51  krbtgt/IPA.PILOT.INTERNAL@IPA.PILOT.INTERNAL
```

```
$ ipa hostgroup-find
--------------------
6 hostgroups matched
--------------------
  Host-group: hg-child
  Host-group: hg-parent
  Host-group: ipaservers
  Host-group: pilot-access-gateways
  Host-group: pilot-target-dmz
  Host-group: pilot-target-gpu
----------------------------
Number of entries returned 6
----------------------------

$ ipa hostgroup-find pilot-
--------------------
3 hostgroups matched
--------------------
  Host-group: pilot-access-gateways
  Host-group: pilot-target-dmz
  Host-group: pilot-target-gpu
----------------------------
Number of entries returned 3
----------------------------
```

No `pilot-gateway-*` group exists yet — expected, since Phase 2 (this
spec's Gateway scope-instance publication) hasn't landed. `pilot-target-*`
is already readable, confirming the reader role needs no new grant for
this spec's discovery needs.

## Raw JSON-RPC (same reader session, via curl + the session cookie the
Go client itself would establish)

```
$ curl -k --negotiate -u : -c cookies.txt -H "Referer: https://ipa1.ipa.pilot.internal/ipa" \
    https://ipa1.ipa.pilot.internal/ipa/session/login_kerberos -o /dev/null -w "%{http_code}\n"
200

$ curl -k -b cookies.txt -H "Referer: https://ipa1.ipa.pilot.internal/ipa" \
    -H "Content-Type: application/json" -d '{"method":"hostgroup_find","params":[["pilot-"],{"all":true}],"id":0}' \
    https://ipa1.ipa.pilot.internal/ipa/session/json
```

Full sanitized response saved verbatim (only whitespace re-indented, no
field renamed/removed/invented) as
`internal/freeipaaccess/testdata/hostgroup_find.json`. Shape matches the
existing `findResult{Result []map[string]any; Count int; Truncated bool}`
already used by `HBACRuleFind`/`SudoRuleFind` — no new envelope handling
needed. `hostgroup_find(all=true)` does return `member_host` directly, but
**not** `memberindirect_host` — so `HostgroupSummary` only carries `Name`;
a caller that needs the transitive host closure for a discovered group
must still call the existing `HostgroupShow` (§9 keeps the RPC-count model
as `HostgroupFind` once + `HostgroupShow` per discovered name).

## Result

- `HostgroupFinder` interface + `HostgroupSummary` type added to
  `internal/freeipaaccess/provider.go` (additive — `Provider` itself is
  untouched, so no existing fake provider needed a new method).
- `hostgroup_find` added to the local `allowedMethods` RPC allowlist
  (`internal/freeipaaccess/jsonrpc.go`) — nothing else in that allowlist
  changed.
- `Client.HostgroupFind` implemented in `internal/freeipaaccess/kerberos.go`,
  same `call` → `decodeFind` → per-row parse pattern as
  `HBACRuleFind`/`SudoRuleFind`.
- Fixture + `TestParseHostgroupFind` (`internal/freeipaaccess/normalize_test.go`)
  added from this capture, not hand-written from documentation.
- Only read RPCs (`hostgroup_find`, `ping` via `klist`/`kinit`) were issued
  against `ag-spike-ipa` during this spike; no `hostgroup_add`/`*_mod`/`*_del`
  was run. `go build ./...` and `go test ./internal/freeipaaccess/...` pass.

Landing gate (§44 Phase 0) met: real FreeIPA reader principal can read
`hostgroup_find`, fixture is real-capture-derived, no write privilege used.
