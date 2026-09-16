# My Hosts shows host annotations — vm-target Evidence (2026-09-16)

Requested: surface a host's annotations ("註解/資產資訊" — owner/project/
location/... — docs/superpowers/specs/2026-09-09-host-annotations-freeipa-
sync-spec.md) in `pilot portal`'s host list. Before this change, `pilot
portal` never fetched or displayed any of that metadata even though
`freeipa-host-annotations.yml` had already been projecting it into each
host's FreeIPA `userClass` for a week.

## Design

`internal/freeipaaccess.Provider.HostShow` already existed but was never
called from the resolver — `LoadUserAccess` built its host list purely
from HBAC/sudo rule expansion, never fetching a host object's own
attributes. Wired it up:

- `freeipaaccess.Host` gained `Annotations map[string]string`, parsed from
  `host_show(all=true)`'s `userclass` values that carry the
  `pilot.annotation.` prefix (`internal/freeipaaccess/normalize.go`'s new
  `parseAnnotations`). The prefix constant is duplicated locally rather
  than importing `internal/inventory.AnnotationUserClassPrefix` — spec.md
  §17/§18 mandate `internal/freeipaaccess`/`internal/accessportal`/
  `internal/gatewayapi` have zero roster/inventory dependency, an
  already-tested architectural boundary this feature must not cross.
- `accessportal.Resolver.LoadUserAccess` now calls `HostShow` for each
  host that already passed the SSH-allowed filter, populating
  `HostAccess.Annotations`. Treated as enrichment, not an authorization
  input: a `host_show` failure for one host (deleted mid-session,
  transient LDAP hiccup) leaves that host's `Annotations` empty rather
  than failing the whole `/v1/access` response the way an HBAC/sudo
  resolution failure would.
- `gatewayapi.HostJSON` gained `Annotations map[string]string`
  (`omitempty`), plumbed straight through from `HostAccess`.
- `pilot portal`'s My Hosts list row now appends a compact
  `[key=value, ...]` summary (sorted by key, deterministic); the host
  detail screen shows the full block under a dedicated `Annotations:`
  section. Both omit entirely when a host has none.

## Real capture, not a fabricated fixture

Set real annotations via admin `kinit` + `ipa host-mod` directly against
`ag-target01` on `ag-spike-ipa` (not through `freeipa-host-annotations.yml`
— that spec's own write-path tests already cover projection; this exercises
the read path only):

```
$ ipa host-mod ag-target01.ipa.pilot.internal --addattr='userclass=pilot.annotation.owner=ai-platform-team'
$ ipa host-mod ag-target01.ipa.pilot.internal --addattr='userclass=pilot.annotation.project=alpha'
$ ipa host-show ag-target01.ipa.pilot.internal --all | grep -i class
  Class: pilot.annotation.owner=ai-platform-team, pilot.annotation.project=alpha
```

Rebuilt and redeployed `dist/pilot-linux-amd64` + `dist/pilot-access-gateway-linux-amd64`
to `ag-gw01` via `pilot-access-gateway-apply.yml` (both binaries touch this
code path — the gateway server calls `LoadUserAccess`, the portal client
renders the response).

## Live vm-target proof, via the real `pilot portal` TUI (pure GSSAPI, `trec`)

My Hosts list row:

```
┃ Pilot Portal › My Hosts
┃ > ag-target01.ipa.pilot.internal  [IP: 192.168.122.5]  [owner=ai-platform-team, project=alpha]
┃   gpu-a.ipa.pilot.internal  ⚠ DNS lookup failed
┃   gpu-b.ipa.pilot.internal  ⚠ DNS lookup failed
┃   « Back
```

Host detail screen:

```
┃ Host: ag-target01.ipa.pilot.internal
┃
┃ SSH allowed: true
┃ SSH rules: pilot-grant-login-gpu-test
┃
┃ Sudo scope: limited
┃ ✓ Allow: /usr/bin/systemctl status nginx
┃ ✗ Deny:  /usr/bin/reboot
┃ Sudo rules: pilot-grant-sudo-gpu-test
┃
┃ Annotations:
┃   owner: ai-platform-team
┃   project: alpha
┃
┃ > Connect
┃   « Back
```

`gpu-a`/`gpu-b` (placeholder FreeIPA host objects with no real backing VM,
Phase 8 fixtures) correctly show no annotation bracket — proving the
feature degrades cleanly for hosts with none, not just the one under test.

## Also fixed while here

`runPortalMyHosts`'s empty-scope message
(`"My Hosts\n\n(no accessible hosts in this gateway's scope)"`) had the
same dead-Yes/No-confirm bug as the 2026-09-16 My Identity/Refresh fix —
missed in that earlier pass since it's a different code path. Switched to
the same `runAcknowledgePrompt` helper.

## Tests

New: `internal/freeipaaccess.TestParseAnnotations`/
`TestParseAnnotationsEmpty` (pure parsing-logic unit tests, not fixture
captures — see their doc comments for why), `TestParseHost` extended to
assert empty `Annotations` on the existing fixture (no `userclass` data);
`accessportal.TestLoadUserAccess_Annotations`/
`TestLoadUserAccess_HostShowFailureDoesNotBreakListing`;
`cmd/pilot/cmd.TestPortalHostListLabelShowsAnnotations`/
`TestPortalHostListLabelNoAnnotationsOmitsBracket`/
`TestPortalHostDetailShowsAnnotations`/
`TestPortalHostDetailNoAnnotationsOmitsSection`. Full `go build ./...`,
`ansible-playbook --syntax-check`, `pilot spec --lint`, `pilot contract
lint`, and the affected packages' full test suites (1241 tests across
`internal/freeipaaccess`/`internal/accessportal`/`internal/gatewayapi`/
`cmd/pilot/cmd`) all pass.

## Cleanup

Removed the test annotations from `ag-target01`
(`ipa host-mod ... --delattr=...`, confirmed no `Class:` line remains) and
destroyed the test Kerberos ticket cache on `ag-gw02`. `ag-gw01`/`ag-gw02`/
`ag-target01`/`ag-spike-ipa` left running per this repo's Phase 7/8
fixture-reuse convention.
