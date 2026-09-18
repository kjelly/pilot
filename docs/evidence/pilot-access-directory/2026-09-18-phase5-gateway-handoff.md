# Phase 5 — Directory → Gateway → Target handoff

Spec: `docs/tmp/now/spec.md` §16-§19, Phase 5 landing gate (§44).

## What was built

- `cmd/pilot/cmd/portal_session.go` (new): the Gateway-side sibling of
  Phase 4's `directory_session.go` — a strict, hand-rolled parser for
  `SSH_ORIGINAL_COMMAND` implementing spec.md §17's exact dispatch (empty
  → interactive `pilot portal`, exact `pilot-connect <uuid> <fqdn>` →
  one-shot connect, anything else → deny). This is a **behavior change**:
  before this phase, `/usr/local/libexec/pilot-session` unconditionally
  `exec`'d `pilot portal`, silently ignoring `SSH_ORIGINAL_COMMAND`
  entirely (harmless — never a shell — but never denied a malformed
  command either).
- `cmd/pilot/cmd/portal_session_connect.go` (new): `runPortalOneShotConnect`
  — the one-shot connect itself. Calls the existing, unmodified
  `POST /v1/connect/authorize` fresh on every invocation (D1/D6: never
  trusts what Directory decided), then reuses the exact same
  `buildConnectSSHCmd` + session-scoped Kerberos credential flow the
  interactive Connect path already used. `session_id` is accepted for
  structured-log correlation only (`slog`, event names matching spec.md
  §21's vocabulary) and never reaches the authorize call (§17.2).
- `playbooks/apply/pilot-access-gateway-apply.yml`: one-line Step 14
  change (`exec /usr/bin/pilot portal` → `exec /usr/bin/pilot
  portal-session`), tagged `AG34`.
- `docs/verification/pilot-access-gateway.md` §6 (AG34-AG40) +
  `scripts/pilot-access-gateway-lockout-test.sh` extended (not
  duplicated) with 8 new grammar-rejection probes.
- Repo-wide bookkeeping fixes (found by running the full test suite, not
  by the implementer): `contracts/pilot-access-gateway.yaml`'s
  `traceability` block needed AG34 (tagged) + AG35-AG40 (unit-test-evidence
  exemptions); `cmd/pilot/cmd/tag_coverage_test.go`'s own separate
  `exemptRows` map needed the same AG35-AG40 entries; the static row-count
  assertion in `internal/spec/pilot_access_gateway_regression_test.go`
  needed bumping from 11 to 18 rows. All three are now consistent.

9 new unit tests (`portal_session_test.go` + `portal_session_connect_test.go`),
all exercising a real `internal/gatewayapi.Server` (fake FreeIPA provider,
not a mock) — not just the parser in isolation. Full repo: build/vet
clean, all tests pass after the bookkeeping fixes above.

## Real infrastructure gap found and fixed while setting up live verification

`ag-directory01` (new in Phase 4) could not resolve `ag-gw01.ipa.pilot.internal`
via `sss_ssh_knownhostsproxy` — this test realm has no FreeIPA-integrated
DNS (`freeipa_setup_dns` false), so cross-host resolution here has always
depended on manual `/etc/hosts` pinning via `pilot vm-target wire`, and the
brand-new Directory host never got wired to the Gateway/target hosts it
needs to route to. Fixed with `pilot vm-target wire --name ag-directory01
--peer ag-gw01=... --peer ag-gw02=... --peer ag-target01=...` (and
similarly wired `ag-gw02` → `ag-target02`, see below). This is purely a
disposable-test-topology artifact (a real deployment would have actual
DNS), not a Directory code defect — recorded here so the next person
provisioning a Directory vm-target doesn't waste time on the same "which
proxy tool doesn't resolve the hostname" detour I did.

## New fixture: `ag-target02` (DMZ scope needed a second real target)

The existing `pilot-target-dmz` hostgroup's only member, `dmz-a.ipa.pilot.internal`,
is a placeholder fixture name from earlier Gateway policy testing with no
real VM behind it (see `pilot-access-gateway.md`'s own Phase 8 note about
placeholder `gpu-a`/`gpu-b` hosts). Proving the DMZ path end-to-end needed
a real, reachable second target, so:

- Provisioned `ag-target02` (192.168.122.7, fresh Ubuntu 24.04), enrolled
  as a FreeIPA client against `ag-spike-ipa`.
- Added it to `pilot-target-dmz` via `ipa hostgroup-add-member` (admin
  kinit, same vault-provided `ipa_admin_password` every apply playbook in
  this repo already uses — not a new credential path).
- Wired `ag-gw02` → `ag-target02` via `pilot vm-target wire`.

It inherits SSH access automatically through the existing
`pilot-grant-login-dmz-test` HBAC rule (which targets the whole
`pilot-target-dmz` hostgroup, not `dmz-a` specifically) — no new HBAC rule
needed. Kept running as a sixth long-lived fixture alongside
`ag-spike-ipa`/`ag-gw01`/`ag-gw02`/`ag-target01`/`ag-directory01`.

## Landing gate verification (all three, live)

Redeployed `pilot`/`pilot-access-gateway` (rebuilt from current HEAD) onto
`ag-gw01` and `ag-gw02`, and `pilot`/`pilot-access-directory` onto
`ag-directory01`, before testing (a stale pre-Phase-5 `pilot` binary on a
gateway would just 404 the new `portal-session` subcommand — caught this
the same way Phase 4 did with a stale binary, see that evidence doc).

### 1. `user → Directory → GPU Gateway → GPU Target`

Real password-authenticated `alice` SSH session into `pilot directory`
(`ag-directory01`), driven via `trec`: My Hosts → `ag-target01.ipa.pilot.internal`
[gpu] → Connect → confirm → Kerberos password prompt (session-scoped
`pilot-directory-` credential, D5) → **landed on a real shell on
`ag-target01`**:

```
$ whoami && hostname -f && id
alice
ag-target01.ipa.pilot.internal
uid=261200004(alice) gid=261200004(alice) groups=261200004(alice),261200003(gpu-users),261200009(role-pilot-portal-user)
```

`exit` → cleanly back at the Directory top-level menu (AD22).

### 2. `user → Directory → DMZ Gateway → DMZ Target`

Same session, `Refresh` (to pick up the newly-added `ag-target02`
membership) → My Hosts now shows `ag-target02.ipa.pilot.internal` [dmz],
routed via `ag-gw02` → Connect → confirm → **landed on `ag-target02`**:

```
$ whoami && hostname -f
alice
ag-target02.ipa.pilot.internal
```

`exit` → cleanly back at the Directory menu again. `Logout` → clean
connection close.

### 3. Wrong-scope injection deny

Directly SSH'd `alice` to `ag-gw01` (the **GPU-only** Gateway) with the
handoff command for the **DMZ** target she legitimately has HBAC access
to — simulating a Directory bug or a hand-crafted malicious handoff:

```
$ ssh alice@ag-gw01 -- pilot-connect <uuid> ag-target02.ipa.pilot.internal
level=WARN msg=gateway_handoff_authorize_denied session_id=<uuid> target=ag-target02.ipa.pilot.internal user=alice
Error: pilot-session: access denied for ag-target02.ipa.pilot.internal
(exit 1)
```

`ag-gw01`'s process tree showed no ssh child ever spawned toward any
target — the deny happened before any credential/SSH activity, exactly as
`runPortalOneShotConnect`'s code path requires (fresh, independent
`ConnectAuthorize` against `ag-gw01`'s own `target_hostgroup=pilot-target-gpu`,
which `ag-target02` is not a member of, regardless of what Directory or
the syntactically-valid `pilot-connect` command claims).

### Bonus: live grammar-rejection spot checks

Beyond the 9 unit tests, manually re-verified two cases directly against
`ag-gw01` over real SSH: a shell-metacharacter target (`host;id` →
`pilot-session: invalid character in target "host;id"`) and an IP literal
(`1.2.3.4` → `pilot-session: target "1.2.3.4" is an IP literal, not an
FQDN`) — both denied with the exact rejection reason, no shell ever
invoked, no ssh child spawned.

## Residual state

- `ag-target02` is a new, permanent addition to the reusable
  evidence-fixture pool (now six VMs total). Added to `pilot-target-dmz`
  in live FreeIPA — this is a real, intentional, permanent change to the
  shared test realm's hostgroup membership, not a throwaway artifact.
- `ag-directory01` and `ag-gw02` each got a `pilot vm-target wire` block
  added/replaced in `/etc/hosts` for cross-host resolution (see above) —
  re-running `wire` on either host replaces the block, so this is
  self-healing if it ever needs to be redone after a `vm-target reset`.
- The one-off admin-kinit playbook used to add `ag-target02` to
  `pilot-target-dmz` lived only in this session's scratchpad and was
  deleted after use.

## Deferred to later phases (not gaps in Phase 5 itself)

- Session ID cross-component correlation (Directory's own audit record
  carrying the *same* session_id Gateway logged) — Phase 6.
- Distinguishing an explicit Gateway deny from an ordinary transport
  failure on the *Directory* client side, so a same-scope failover
  doesn't get attempted past an explicit deny (spec.md §19 point 8) — the
  Gateway side already denies correctly (proven above); Directory's own
  `connectToGateway` failover loop still can't tell the two apart from an
  SSH exit code alone. Noted as a known gap in `docs/verification/pilot-access-directory.md`'s AD15 entry.
