# Phase 8 — Multi-Gateway E2E: vm-target Evidence (2026-09-14)

Scope: `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §60 Phase 8 — the only phase allowed to turn
on sshd ForceCommand (step 19 of §55), gated behind the §55.1 lockdown
regression test having actually run on vm-target with evidence, plus
human approval. Also covers the remaining live-fire verification items
Phase 8's own bullet list names: FreeIPA outage, reader keytab failure,
multi-gateway scope isolation, and grant/breakglass rule sourcing.

Two high-risk actions in this phase (enabling ForceCommand on a
vm-target; stopping FreeIPA's httpd to simulate an outage) were flagged
by the auto-mode classifier and required explicit human approval before
proceeding — both were granted, scoped to the disposable vm-targets used
throughout this implementation, never to a production host.

## Topology

- `ag-spike-ipa` — FreeIPA server (existing).
- `ag-gw01` — existing gateway, `gateway_id=gpu-01`, `scope=gpu`.
- `ag-gw02` — **new** in this phase, a fresh Ubuntu vm-target enrolled as
  a FreeIPA client, used first as `gateway_id=gpu-02`/`scope=gpu` (AG26),
  then reconfigured to `gateway_id=dmz-01`/`scope=dmz` (AG27).
- New FreeIPA fixtures: host `dmz-a.ipa.pilot.internal`, hostgroup
  `pilot-target-dmz` (via `gateway-scope-apply.yml`), HBAC rule
  `pilot-grant-login-dmz-test` (alice → dmz-a → sshd, mirrors the
  existing `pilot-grant-login-gpu-test` naming convention), and HBAC rule
  `pilot-access-gateway-login` (`role-pilot-portal-user` →
  `pilot-access-gateways` → sshd — see Finding 4 below).

## §55.1 ForceCommand lockdown regression test (AG20/21/25)

Run against `ag-gw01` only, after explicit human approval (the auto-mode
classifier flagged enabling `pilot_access_gateway_install_forcecommand`
as a high-risk "Blind Apply").

**Step 1 — portal user gets a captive session, never a shell.** SSH login
as `alice` (member of `role-pilot-portal-user`) landed directly in the
`pilot portal` TUI:

```
┃ Pilot Portal
┃
┃ Gateway  gpu-01
┃ Scope    gpu
┃ User     alice
```

Ctrl+C inside the session closed the whole SSH connection ("Connection to
192.168.122.3 closed"), not a shell. Separately, `ssh alice@host whoami`
(no PTY, `SSH_ORIGINAL_COMMAND=whoami`) returned no output and exit 1 —
`pilot-session`'s `[ -t 0 ] || exit 1` guard rejected it outright, proving
`SSH_ORIGINAL_COMMAND` is never parsed or executed (spec.md §33).

**Step 2 — admin (non-portal-user) is unaffected.** SSH login as `root`
(not a member of `role-pilot-portal-user`) got a completely normal
interactive shell: `whoami` → `root`, `SHELL_OK_0`. `sshd -T -C
user=root,...` independently confirmed `forcecommand none` for root vs.
`forcecommand /usr/local/libexec/pilot-session` for alice.

**Step 3 — rollback restores both.** Re-ran the apply playbook with
`pilot_access_gateway_install_forcecommand=false` (the default). The
drop-in was removed and sshd reloaded (`changed=2`). A fresh SSH login as
`alice` afterward got a normal interactive shell (`whoami` → `alice`,
`SHELL_RESTORED_0`).

All three steps are real, live SSH sessions (via `trec`), not `sshd -T`
config dry-runs alone (those were used only as a fast secondary
confirmation).

### Finding: the playbook could turn ForceCommand on but not off

The playbook only ever installed the ForceCommand drop-in when the flag
was `true`; flipping the flag back to `false` and re-applying just
*skipped* re-installing it — an already-installed drop-in was never
removed. Fixed by adding a symmetric rollback block (new tasks "Step 19
rollback" / "Step 20 rollback" / "Step 21 rollback" in
`playbooks/apply/pilot-access-gateway-apply.yml`) that removes the
drop-in, runs `sshd -t`, and reloads sshd whenever the flag is `false`.
Verified idempotent: a second apply with the flag `false` after the
drop-in was already removed reports `changed=0`.

### Finding: the gateway host itself needs its own HBAC rule

`pilot-access-gateways` is management inventory classification only
(spec.md §57: "不代表 Gateway 可以跳到哪些 target") — it does not, by
itself, grant anyone HBAC access to actually SSH into the gateway host.
The very first live-login attempt failed with `pam_sss(sshd:account):
Access denied for user alice: 6` / `PAM: User account has expired for
alice` (a misleading message — the real cause is a missing HBAC grant,
not password expiry) until an HBAC rule (`pilot-access-gateway-login`:
`role-pilot-portal-user` → `pilot-access-gateways` → `sshd`) was added.
This is a site/`freeipa-identity` provisioning precondition, not
something `pilot-access-gateway-apply.yml` itself should create (same
principle as `gateway_portal_user_group` needing to pre-exist) — recorded
in `docs/verification/pilot-access-gateway.md` §5 as a gotcha for anyone
standing up a new gateway.

## Multi-gateway scope isolation (AG26/AG27/AG28)

**AG26 — same scope, multiple instances, equivalent target set.**
`ag-gw02` installed with `gateway_id=gpu-02`, `gateway_scope=gpu` (same
`pilot-target-gpu` hostgroup as `ag-gw01`). `GET /v1/access` as `alice`
via both gateways returned an identical `hosts` array (`gpu-a`, `gpu-b`,
same HBAC/sudo rule names) — the only difference in the two JSON bodies
was `gateway.id`.

**AG27 — different scopes, isolated target sets.** `ag-gw02`
reconfigured to `gateway_id=dmz-01`, `gateway_scope=dmz` (new
`pilot-target-dmz` hostgroup, member `dmz-a`). Before granting any
dmz-specific HBAC rule, `alice` via `ag-gw02` got `"hosts":[]` (empty —
she had no HBAC grant to `dmz-a` at all). To make the isolation proof
airtight (not just "empty because nothing was ever granted"), a real HBAC
rule (`pilot-grant-login-dmz-test`) was added granting `alice` (via
`gpu-users`) sshd access to `dmz-a`. After that:

- `ag-gw01` (`scope=gpu`) → alice's `hosts` = `[gpu-a, gpu-b]` — still no
  `dmz-a`, even though she now has *real* SSH rights there.
- `ag-gw02` (`scope=dmz`) → alice's `hosts` = `[dmz-a]` — no `gpu-a`/`gpu-b`.

This proves the `HBAC(user) ∩ gateway.target_hostgroup` intersection is
strictly per-gateway: a user's rights on a host outside a given gateway's
own `target_hostgroup` never leak into that gateway's results, and rights
inside it are never hidden either.

**AG28 — service alias does not mix scopes.** Structural: `go list
-deps` over `internal/freeipaaccess`, `internal/accessportal`,
`internal/gatewayapi`, and `cmd/pilot-access-gateway` shows no DNS/VIP
package is ever imported — the software has no concept of DNS aliases at
all. Combined with AG26/27's proof that each gateway's own
`target_hostgroup` is the sole scope input, "a DNS/VIP mixes two
different-scope gateways" can only be an operator/deployment-topology
mistake (pointing a CNAME/VIP at gateways with different `gateway_scope`
values), not a software defect this repo's code could introduce or
prevent. Documented as an operational rule in the verification spec,
same treatment as AG31.

## Grant / breakglass active rule

`pilot-access-gateway` never reads grant JSON (spec.md §57) — it only
ever reads live FreeIPA HBAC/sudo state, with zero code path that
distinguishes a grant-compiler-produced rule from a hand-created one.
The AG26/27 tests above exercised this directly: `pilot-grant-login-gpu-
test` / `pilot-grant-sudo-gpu-test` (established in earlier phases, named
to match `internal/inventory`'s grant compiler convention) and the newly
created `pilot-grant-login-dmz-test` were all treated identically by the
gateway — no special-casing exists or was needed. A full round-trip
through `pilot access breakglass activate` was not exercised (it needs a
roster file with a `kind: breakglass` grant definition, a separate setup
step); the architectural claim ("the gateway is rule-source-agnostic") is
already proven by construction (`grep` shows zero references to
`internal/inventory`'s grant packages anywhere in the gateway's own
import graph) and by the live evidence above.

## FreeIPA outage fail-closed (AG16)

Stopped `httpd` on `ag-spike-ipa` (human-approved — flagged as
"Interfere With Workloads"). Immediately after:

- `GET /v1/health` on `ag-gw01` → `503`, `{"status":"degraded",
  "freeipa":"unreachable", "target_scope":"missing",
  "credential":"unknown"}`.
- `GET /v1/access` as `alice` → `503`, `{"error":"access service
  unavailable"}` — matching spec.md §34's error text exactly.

Restarted `httpd`; the very next `/v1/health` call (no gateway restart)
returned `200`, `"status":"ok"`, `"freeipa":"reachable"` — confirming the
gateway is genuinely stateless and self-healing, not caching a permanent
failure.

## Reader keytab failure — found a real crash bug, fixed it

Renamed `/etc/pilot/pilot-access-gateway.keytab` aside on `ag-gw01` and
restarted the service (human-approved, same class of action as the
FreeIPA-outage test). Expected: a graceful `503`, matching the FreeIPA-
outage behavior. Actual, before the fix:

- `cmd/pilot-access-gateway/main.go`'s `runServe` called
  `freeipaaccess.NewClient`, which loaded the keytab **synchronously at
  construction**, before the HTTP server ever started listening. A
  missing keytab made `main()` exit 1 immediately.
- Because the service is socket-activated, systemd retried starting it
  on every new connection attempt — and quickly hit systemd's
  start-rate-limit. At that point **the `.socket` unit itself** flipped
  to `failed (Result: service-start-limit-hit)`, not just the service:
  `curl --unix-socket ... ` returned connection-refused (`HTTP_STATUS=000`),
  and restoring the keytab did **not** self-heal — the socket stayed
  `failed` until an operator ran `systemctl reset-failed`.

This is strictly worse than the FreeIPA-outage case and directly
contradicts the stateless/self-healing design goal (AG29). Root cause:
`internal/freeipaaccess.NewClient` eagerly loaded the krb5.conf, keytab,
and CA bundle instead of treating them the same way the Kerberos
*session* itself was already treated — lazily, retried on every call.

**Fix** (`internal/freeipaaccess/kerberos.go`): moved the krb5.conf/
keytab/CA loading out of `NewClient` and into a new
`buildCredentialsLocked` helper, called from `ensureSession` (under the
same mutex, before the network login attempt) exactly like the session
itself. `NewClient` now only validates `len(cfg.Servers) > 0`. A load
failure is cached as "not yet built" (never as a permanent failure), so
the very next call retries the load from scratch.

Re-verified live after rebuilding and redeploying the fixed binary,
reproducing the exact same steps:

- Missing keytab + service restart → both socket **and** service stay
  `active`; `/v1/health` returns `503` degraded (not connection-refused).
- Keytab restored, **no restart** → the next `/v1/health` call (after
  the 10s provider cache TTL) returns `200 ok` on its own.

New regression tests: `internal/freeipaaccess/kerberos_test.go`'s
`TestNewClientDoesNotEagerlyLoadCredentials` (construction never fails on
a missing keytab/CA) and `TestClientRetriesCredentialLoadOnEveryCall`
(three calls against a missing → still-missing → garbage keytab each
produce the *current*, non-stale error — proving no failure is ever
memoized permanently).

## Gotchas discovered fixing the test environment itself

- libvirt reuses vm-target IPs across VM lifetimes; a stale
  `~/.ssh/known_hosts` entry from a previous VM at the same IP makes SSH
  refuse outright ("REMOTE HOST IDENTIFICATION HAS CHANGED") — fixed with
  `ssh-keygen -R <ip>` before the first connection to a freshly created
  vm-target.
- An admin-issued `ipa passwd` leaves the account in a
  "must change at next login" state that plain SSH `password`/
  `keyboard-interactive` auth cannot complete (sshd disconnects with
  `monitor_read: unpermitted request 104` instead of prompting for a new
  password) — the fix is a `kinit <user>` from any enrolled host first
  (which *does* support the interactive change-password flow), before
  attempting SSH.

## Landing gate status

Per spec.md §60 Phase 8: the §55.1 lockdown regression test ran on
`ag-gw01` (disposable vm-target) with human approval and full evidence
(trec sessions) above — this is the only phase permitted to do so.
AG16/20/21/25/26/27/28 are verified live; AG28/31/grant-breakglass are
documented as structural/operational rather than single-task-testable.
The reader-keytab-failure test additionally surfaced and fixed a real
process-crash/socket-wedge bug, independent of anything Phase 8 was
specifically looking for but directly in the spirit of this spec's
fail-closed availability requirements.
