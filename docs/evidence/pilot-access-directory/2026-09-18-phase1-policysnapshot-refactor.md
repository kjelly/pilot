# Phase 1 — Shared policy snapshot refactor

Spec: `docs/tmp/now/spec.md` §9.1/§9.2/§9.3, Phase 1 landing gate (§44).

## Goal

Split `internal/accessportal.Resolver.LoadUserAccess` into a scope-independent
`LoadPolicySnapshot` (user context, HBAC/sudo rules, referenced hostgroup/
service-group/command-group expansions) and a scope-specific
`ResolveScopeAccess` (gateway target-hostgroup expansion + per-host SSH/sudo
resolution), so `pilot-access-directory` can load one snapshot per user and
resolve it against N gateway scopes without re-running the whole
HBAC/sudo-find pipeline per scope — never a second, duplicated authorization
engine (§9's explicit prohibition).

## What changed

- `internal/accessportal/policysnapshot.go` (new): `PolicySnapshot`,
  `LoadPolicySnapshot`, `ResolveScopeAccess`, and an unexported
  `hostAnnotationCache` that memoizes `HostShow`-derived annotations by
  FQDN for the lifetime of one snapshot.
- `internal/accessportal/resolver.go`: `Resolver.LoadUserAccess` is now
  `LoadPolicySnapshot` + `ResolveScopeAccess` — no inline logic left.
  `ResolveGatewayScope`/`ResolveUserContext`/`expandReferenced*` are
  unchanged and are reused internally (via a throwaway `*Resolver`) rather
  than duplicated as free functions.
- `internal/accessportal/fake_provider_test.go`: added a `hostShowCalls`
  counter (test-only) to make the dedup claim provable, not just "looks
  right by inspection".
- `internal/accessportal/policysnapshot_test.go` (new):
  `TestResolveScopeAccess_SharesHostShowAcrossScopes` — two overlapping
  gateway scopes sharing one host, one `LoadPolicySnapshot`, two
  `ResolveScopeAccess` calls, asserts `HostShow` for the shared host is
  called exactly once.

## Landing gate verification

```
$ go build ./...
(clean)

$ go test ./internal/accessportal/... -v
... all pre-existing tests unchanged and PASS, plus the new
    TestResolveScopeAccess_SharesHostShowAcrossScopes PASS ...
PASS
ok  	github.com/kjelly/pilot/internal/accessportal	0.003s
```

- **No semantic regression**: every pre-existing `resolver_test.go` test
  (`TestResolveGatewayScope_*`, `TestResolveUserContext_*`,
  `TestLoadUserAccess_*`, `TestHBACRuleGrants_Matrix`,
  `TestSudoRuleActive_TimeWindow`, `TestSudoDisplayScope`) passes
  unmodified against the refactored `LoadUserAccess` — output is
  byte-for-byte the same code path, just factored differently.
- **No query-count blowup**: `LoadPolicySnapshot` still issues exactly
  one `UserShow`, one `hbacrule_find`, one `sudorule_find`, and one call
  per distinct referenced hostgroup/service-group/command-group — this is
  unchanged from before the refactor (it's the same calls, just grouped
  under a new name). The only new sharing behavior is the
  `hostAnnotationCache`, verified above to collapse a shared host's
  `HostShow` from N-per-scope to 1-per-snapshot.
- Fake-provider-only (no vm-target needed for this phase — it's a pure Go
  refactor of already-fixture-tested logic); Phase 3 (Directory backend)
  is where `LoadPolicySnapshot`/`ResolveScopeAccess` first get exercised
  against a real multi-scope FreeIPA topology.
