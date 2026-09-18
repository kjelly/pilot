# Phase 3 — Directory backend

Spec: `docs/tmp/now/spec.md` §10/§11/§12, Phase 3 landing gate (§44).

## Goal

Build the Directory backend as a pure discovery/routing projection (D1):
`internal/accessdirectory` (cross-scope resolve on top of Phase 0/1's
`HostgroupFinder`/`PolicySnapshot`), `internal/directoryapi` (HTTP-over-
Unix-socket API mirroring `internal/gatewayapi`'s shape exactly), and
`cmd/pilot-access-directory` (the binary, mirroring `cmd/pilot-access-
gateway`'s shape exactly). No FreeIPA writes anywhere; no caching layer
anywhere (every API call does a fresh resolve); no duplicated HBAC/sudo
matching logic — every bit of authorization goes through
`accessportal.LoadPolicySnapshot`/`ResolveScopeAccess`.

## What was built

- `internal/accessdirectory/{model,catalog,resolver}.go`: `ScopeRoute` /
  `DirectoryAccess` / `DirectoryTarget` / `TargetRoute`;
  `LoadScopeCatalog` (two `HostgroupFind` calls + one `HostgroupShow` per
  discovered gateway hostgroup); `LoadDirectoryAccess` (one
  `LoadScopeCatalog` + one `LoadPolicySnapshot`, then one
  `ResolveScopeAccess` per scope, merged by FQDN into one
  `DirectoryTarget` with multiple `Routes` when a target is reachable via
  more than one scope).
- `internal/directoryapi/{server,handlers,types,authz,connctx}.go`:
  `GET /v1/identity`, `GET /v1/access`, `GET /v1/access/{fqdn}`,
  `POST /v1/connect/resolve`, `GET /v1/health` — same SO_PEERCRED +
  portal-group defense-in-depth gate as `gatewayapi`, health ungated.
  `/v1/connect/resolve` does a fresh `LoadDirectoryAccess` (D1) and picks
  the lexically-first `route_status=ready` route, returning a fresh
  `uuid.NewString()` session ID — routing metadata only, never a
  capability (D6): the eventual Gateway still authorizes independently.
- `cmd/pilot-access-directory/{main,config}.go`: `/etc/pilot/access-
  directory.yaml` loader (`yaml.Decoder.KnownFields(true)`, matching
  spec.md §12.1's schema exactly — no `gateway_known_hosts` field, since
  host-key verification is SSSD/`sss_ssh_knownhostsproxy`-based per the
  Phase 2 corrected design), `serve` subcommand reusing
  `internal/systemdactivation` identically to `cmd/pilot-access-gateway`.

## Landing gate verification

```
$ go build ./...
(clean)

$ go vet ./...
(clean)

$ go test ./internal/accessdirectory/... ./internal/directoryapi/... ./cmd/pilot-access-directory/...
ok  	github.com/kjelly/pilot/internal/accessdirectory	(9 tests)
ok  	github.com/kjelly/pilot/internal/directoryapi	(14 tests)
ok  	github.com/kjelly/pilot/cmd/pilot-access-directory	(4 tests)

$ go test ./...
Go test: 3783 passed in 50 packages   # full repo, unchanged packages included
```

Fake-provider-only for this phase (no vm-target FreeIPA needed — real
`hostgroup_find` wire behavior was already proven live in Phase 0; Phase 4
is where this binary first gets deployed and exercised against a real
multi-scope FreeIPA topology).

### O(1) query-count proof (spec.md §9.3)

`TestLoadDirectoryAccess_SharedSnapshotAcrossScopes` builds a 4-scope
fixture (gpu/dmz/nogw/broken) and asserts `UserShow`/`hbacrule_find`/
`sudorule_find` are each called **exactly once** for the whole
`LoadDirectoryAccess` call, never once-per-scope. A dual-homed host
(`shared-a`, member of both `pilot-target-gpu` and `pilot-target-dmz`) is
`HostShow`'d exactly once across both scopes' resolves
(`TestLoadDirectoryAccess_SharedTargetMergesIntoOneEntryWithTwoRoutes`),
proving Phase 1's `hostAnnotationCache` sharing actually pays off here,
not just in theory.

### Two real design gaps found and fixed during test-writing

1. **`accessportal.LoadPolicySnapshot`'s pre-existing "fail hard on any
   referenced hostgroup" behavior has a much bigger blast radius once
   Directory is the caller.** `expandReferencedHostgroups` fails the
   *entire* snapshot load if *any* HBAC/sudo rule anywhere (not just
   rules relevant to scopes this request cares about) references an
   unreadable hostgroup. This predates Phase 3 (it already existed for a
   single Gateway before this package existed), but for a single Gateway
   the blast radius was "this one gateway's access breaks"; for
   Directory, which scans every global rule for every user, one bad
   hostgroup reference anywhere in FreeIPA can take down **every user's**
   Directory view. **Not fixed in this phase** — fixing it means
   changing `accessportal`'s error-handling shape, which Phase 1's "byte-
   for-byte identical to the pre-refactor behavior" mandate and existing
   regression tests intentionally freeze. Flagged here for a follow-up
   phase (making that expansion fail-soft per-hostgroup instead of
   all-or-nothing) rather than silently worked around.
2. **`LoadScopeCatalog` used to fail the whole catalog load if one
   gateway-instance hostgroup's `HostgroupShow` failed** after being
   discovered by `HostgroupFind` (e.g. deleted concurrently) — found via
   `TestLoadScopeCatalog_BrokenGatewayHostgroupDegradesOnlyThatScope`.
   **Fixed**: that one scope's route now degrades to `GatewayFQDNs: nil`
   (→ `route_status: no_gateway`) instead of erroring the entire catalog,
   consistent with the per-scope isolation `LoadDirectoryAccess` already
   applies to a broken *target* hostgroup.

### Emergent (correct, not a bug) behavior documented in tests

A host that is a member of two different scopes' target hostgroups is
reachable via **both** scope routes for a user who only belongs to one
scope's HBAC group, because HBAC rule matching is global — it doesn't
know which "scope walk" is currently checking a host, only whether the
host is a member of a hostgroup a rule names. Documented with a comment
in `TestLoadDirectoryAccess_UserWithOnlyOneScopeSeesOnlyThatScope`; not
something this phase introduces, inherited unchanged from `accessportal`.

## Deviations from the DRAFT spec's literal sketch

- `LoadScopeCatalog` takes `provider freeipaaccess.Provider` in addition
  to `HostgroupFinder` — required for the `HostgroupShow` follow-up call
  per discovered gateway hostgroup, since `hostgroup_find` does not
  return `memberindirect_host` (Phase 0 finding).
- `RouteStatus` is `"ready"` / `"no_gateway"` only — the `stale_known_host`
  value from the DRAFT's original (superseded) known_hosts design was
  already dropped when the spec was corrected; a
  `// TODO(spec.md §19 Phase 5)` marks where the bounded TCP/22
  reachability probe will raise the bar for "ready" once Phase 5 lands.
