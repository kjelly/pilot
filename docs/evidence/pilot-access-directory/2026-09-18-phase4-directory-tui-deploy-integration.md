# Phase 4 — Directory TUI + deploy integration

Spec: `docs/tmp/now/spec.md` §13/§14/§31/§33/§36, Phase 4 landing gate (§44).

## What was built

- `cmd/pilot/cmd/directory.go`/`directory_client.go`/`directory_tui.go`/
  `directory_ssh.go`/`directory_session.go` — `pilot directory` (mirrors
  `pilot portal`'s TUI framework, primitives, and error-handling shape
  exactly) plus the strict `pilot directory-session` ForceCommand handler.
- `playbooks/apply/pilot-access-directory-apply.yml` (21 steps, mirroring
  `pilot-access-gateway-apply.yml`'s conventions), `contracts/pilot-access-directory.yaml`
  (`site.order: 53`, verified unoccupied before picking it), `group_vars/pilot-access-directory.example.yml`,
  `scripts/build-pilot-access-directory.sh`, `docs/verification/pilot-access-directory.md`
  (explicitly marked DRAFT v0.1 — no fabricated PASS claims, matching AGENTS.md §5.6).
- `playbooks/site.yml` / `cmd/pilot/cmd/deploy_catalog.go` / `AGENTS.md` updated to register the new component.

Code review found this correctly reuses Phase 0-3 work throughout: `newPortalKerberosSessionWithPrefix("pilot-directory-")`
for the Directory→Gateway credential (D5), the exact `pilotSSHConfig` directive
set for `/etc/pilot/directory_ssh_config` (§15's SSSD-based host-key
verification, no `directory_gateway_known_hosts` file), and a hand-rolled
strict parser for `SSH_ORIGINAL_COMMAND` (D7) that never touches a shell —
verified live below, not just by reading the code.

Fake-provider/unit test coverage: 15 new tests across `directory_client_test.go`,
`directory_tui_test.go`, `directory_ssh_test.go`, `directory_session_test.go`.
Full repo: **3803 tests passed across 50 packages**, 0 failures.

## Topology

Provisioned a **new**, dedicated vm-target for the Directory role (D4:
`hostCardinality: exactly-one`, and Directory must never itself be a
Gateway/target) rather than reusing `ag-gw01`/`ag-gw02`/`ag-target01`:

- `ag-directory01` (192.168.122.6) — fresh Ubuntu 24.04, enrolled as a
  FreeIPA client against the existing `ag-spike-ipa` realm.

Left running afterward, joining the existing `ag-spike-ipa`/`ag-gw01`/
`ag-gw02`/`ag-target01` pool as a fifth long-lived, reusable evidence
fixture for Phase 5+.

### Gotcha: `freeipa-server-pool.yml`'s new HA-aware gate needs a real
`freeipa-server` inventory group, not just `-e ipa_server_ip=`

`freeipa-client-apply.yml`'s header comment still documents the old
single-target invocation (`pilot vm-target run --name X ... -e
ipa_server_ip=<ip>`), but the `freeipa-client-ha` work landed since
`ag-gw01` was originally enrolled added a hard gate: `groups['freeipa-server']`
must have exactly one host. Fixed by combining two already-up vm-targets
into one inventory: `--group freeipa-server=ag-spike-ipa --group
client=ag-directory01`, **and** setting `-e target_group=client` (not
`all`) — using `all` made the play also iterate over `ag-spike-ipa` itself
(now present in the combined inventory), which made a DNS-registration
gate delegated to the server evaluate `ipa_client_fqdn` as the *server's
own* fqdn during that iteration and fail
(`ipa_client_fqdn (ipa1...) == ipa_server_fqdn`). Once `target_group=client`
scoped the play to only the actual client host, enrollment completed
cleanly. Likely worth a doc update to `freeipa-client-apply.yml`'s header
for the next person hitting this — not fixed here (out of this phase's
scope; recording it here so it isn't rediscovered from scratch).

Same `--group` combination (`freeipa-server=ag-spike-ipa`,
`pilot-access-directory=ag-directory01`) was then needed to run
`playbooks/site.yml` itself, since site.yml asserts `target_group` must be
UNSET when invoked as the aggregate entrypoint (a real safety gate, not a
bug) — the component's own inventory group name
(`pilot-access-directory`, from `deploy_catalog.go`'s `DefaultGroup`) has
to be the `--group` key instead.

### Gotcha: rebuild `dist/pilot-linux-amd64` before live-testing new `pilot` subcommands

First live test of the ForceCommand path failed with `unknown command
"directory-session" for "pilot"` — the `dist/pilot-linux-amd64` binary on
disk predated Phase 4's code (built during earlier Phase 2 testing).
Rebuilt from current HEAD and redeployed (`changed=1`, binary only) before
re-testing.

## Landing gate verification (all four, live)

### 1. 真人 SSH Directory TUI

Reset `alice`'s FreeIPA password to a known test value (`ipa passwd alice`
as admin via the same vault-provided `ipa_admin_password` every other
apply task in this repo already uses, then completed the mandatory
password-change via `kinit alice`) so a real password-authenticated SSH
session could be driven end-to-end with `trec`. Full session, screen-by-screen:

```
$ ssh alice@ag-directory01   (password auth)
┃ Pilot Access Directory
┃
┃ Directory directory-01
┃ User      alice
┃ ────────────────────────
┃ > My Hosts
┃   My Identity
┃   Refresh
┃   Logout
```

→ My Hosts (real cross-scope aggregation, same alice/gpu+dmz result Phase 3
proved via the API, now rendered in the actual interactive TUI a real
login sees):

```
┃ Pilot Access Directory › My Hosts
┃ > ag-target01.ipa.pilot.internal  [gpu]
┃   dmz-a.ipa.pilot.internal  [dmz]
┃   gpu-a.ipa.pilot.internal  [gpu]
┃   gpu-b.ipa.pilot.internal  [gpu]
┃   « Back
```

→ target detail (SSH/sudo/routes all correctly rendered) → Connect confirm
→ attempted handoff to `ag-gw01` (fails with `exit status 255` — expected
and correct: Phase 5 hasn't built the Gateway-side `pilot-connect`
one-shot protocol yet, so Gateway's *existing* `pilot-session`
ForceCommand parser doesn't recognize it and rejects the connection) →
**Directory TUI recovers gracefully and returns to the menu** (proves
AD22's "target exit 回 Directory" property holds even before Phase 5
exists) → Logout → clean connection close.

### 2. arbitrary remote command 無 shell

```
$ ssh alice@ag-directory01 'whoami; id'
Error: pilot-directory-session: unrecognized command
...
pilot-directory-session: unrecognized command
```

Neither `whoami` nor `id` ever ran — no uid/username output anywhere, only
the Go binary's own rejection message. `SSH_ORIGINAL_COMMAND` was handed
straight to the strict Go parser (`parseDirectorySSHOriginalCommand`),
never to a shell.

Also verified server-side, matching `pilot-access-gateway`'s own
`sshd -T -C` lockout-test convention:

```
$ sshd -T -C user=alice,host=ag-directory01...,addr=192.168.122.6
forcecommand /usr/local/libexec/pilot-directory-session
disableforwarding yes
allowtcpforwarding no
allowagentforwarding no
x11forwarding no
permittunnel no
permituserrc no
permittty yes
```

SFTP subsystem request (`sftp alice@ag-directory01`): client sent
`Subsystem: sftp`, ForceCommand overrode it anyway, sftp client got no
working SFTP channel and reported `Connection closed` — no file transfer
capability leaked through.

### 3. idempotent apply

First apply: `ok=53 changed=24 failed=0` (fresh install). Second apply,
identical vars: `ok=46 changed=0 failed=0 skipped=10`.

### 4. site-wide deployment 實際執行 component

```
$ pilot vm-target run --name ag-directory01 \
    --group freeipa-server=ag-spike-ipa --group pilot-access-directory=ag-directory01 \
    playbooks/site.yml --tags pilot-access-directory -e directory_id=directory-01 ...
...
PLAY [Pilot Access Directory install] (via site.yml's import_playbook)
...
PLAY RECAP
ag-directory01   : ok=53  changed=0  failed=0
ag-spike-ipa     : ok=12  changed=0  failed=0
```

Every other component's play in `site.yml` correctly showed `skipping: no
hosts matched` (tag filter worked) — the aggregate entrypoint genuinely
reached and ran `pilot-access-directory-apply.yml`'s real tasks (idempotent
`changed=0`, since state already matched the direct-playbook run above),
not a tag-coverage static check standing in for a live run.

## Residual state / cleanup

- `ag-directory01` is **kept running** as a new, permanent addition to the
  reusable evidence-fixture pool (`ag-spike-ipa`/`ag-gw01`/`ag-gw02`/
  `ag-target01`/`ag-directory01`), matching this repo's established
  practice for this feature's vm-targets.
- `alice`'s FreeIPA password is now `TestPass!2027y` (no longer in a
  must-change state) — a deliberate, documented side effect of enabling
  the live SSH TUI test above, not an accident. Future sessions reusing
  this pool should know her password changed from whatever it was before.
- The throwaway single-task playbook used to reset it
  (`reset-alice-pw.yml`) lived only in this session's scratchpad and was
  deleted after use — never part of the repo.

## Deferred to later phases (not gaps in Phase 4 itself)

- The Gateway-side `pilot-connect <session-id> <fqdn>` one-shot protocol
  (spec.md §16-§18) — Phase 5. Until then, every Connect attempt from
  Directory will keep failing at the transport/parse layer on the Gateway
  side (as observed above), which is the expected, safe failure mode.
- Bounded TCP/22 reachability probe for `RouteStatus` (§19) — still Phase 5.
- `docs/verification/pilot-access-directory.md`'s AD-numbered rows stay
  DRAFT-honest per-row; this evidence doc is additional live proof for the
  four Phase 4 landing-gate items specifically, not a full AD01-AD30 sweep.
