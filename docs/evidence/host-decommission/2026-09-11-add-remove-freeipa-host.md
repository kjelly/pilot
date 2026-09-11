# FreeIPA host add/remove — real evidence + 2 bugs found+fixed — 2026-09-11

- Candidate: **uncommitted working-tree changes on top of `1040ff3`** (2026-09-08).
  This is a dirty-worktree dev-loop evidence run (AGENTS.md §1's "開發期間可以在
  dirty worktree 跑快速測試" allowance), not a frozen immutable-candidate record —
  before relying on this for a release decision, re-run from a clean checkout of
  the commit that actually lands these two fixes and record its tree ID here.
- Files changed (uncommitted at capture time):
  - `cmd/pilot/cmd/host_decommission.go` — bug #1 fix (SSH ControlPath)
  - `internal/decommission/planner.go`, `references.go`, `references_test.go` —
    bug #2 fix (roster-path fallback)
- Target: 2-VM disposable `pilot vm-target` topology (pre-existing from an
  earlier session, reused here): `hd-ipa1` (almalinux-9, FreeIPA server,
  `root@192.168.122.2`, domain `ipa.pilot.internal` / realm
  `IPA.PILOT.INTERNAL`), `hd-client1` (ubuntu-24.04, `ubuntu@192.168.122.3`).
- Toolchain: go1.24, ansible-core 2.19.2 (Homebrew), libvirt/KVM.

## 1. Bug #1 — SSH ControlPath missing in a fresh/ephemeral runtime

Found via a real production repro (`pilot-cli:latest` docker container,
`docker run --rm -v ./infra-config:/pilot/config`), then reproduced and
verified on this vm-target topology.

Symptom — `pilot host decommission plan --dir /pilot/config --host p6k-baremetal`:

```
❌ Ansible 失敗摘要
  1. host=freeipa (fatal)
     task=Kinit admin
     detail={"censored": "the output has been hidden due to the fact that 'no_log: true' was specified for this result", "changed": false}
```

Root cause: `buildHostDecommissionProviders` (`cmd/pilot/cmd/host_decommission.go`)
built its `ansible.Runner` bare, unlike every other pilot subcommand
(deploy/reconcile/edit/mcp), which all call `prepareDeployAnsibleRuntime` first.
That helper `MkdirAll`s a scratch `ansible/{home,tmp,fact-cache,ssh-control}`
tree and points `ANSIBLE_SSH_ARGS`'s `ControlPath` at it. Without it, this one
code path silently depended on `ansible.cfg`'s default `~/.ansible/cp/...`
already existing — true on a long-lived machine, false in a fresh `docker run
--rm` container. The real underlying error (confirmed via a non-`no_log`
`ansible -m ping -vvv` against the same host):

```
unix_listener: cannot bind to path /root/.ansible/cp/pilot-ubuntu@10.1.58.11:22...: No such file or directory
```

— i.e. a mundane missing-directory bug, disguised by `no_log` on
`freeipa-identity-apply.yml`'s "Kinit admin" task into an opaque
"censored"/UNREACHABLE blob that reads exactly like a Kerberos/credential
failure.

Fix: `buildHostDecommissionProviders` now calls
`prepareDeployAnsibleRuntime(resolvePilotDataDir())` and applies
`runtime.Env`/`runtime.LogPath` to the shared runner, matching every other
caller.

Verified via `pilot host decommission plan` against `hd-ipa1`/`hd-client1`,
built as two binaries (HEAD vs. HEAD+fix) run from a byte-for-byte fresh
`$HOME` with no ambient SSH control-socket state:

- Unfixed: `fatal: [hd-ipa1]: UNREACHABLE!` / `Failed to connect to the host
  via ssh` — same shape as the production failure.
- Fixed: connects cleanly; a live control socket appears under
  `<datadir>/ansible/ssh-control/pilot-root@192.168.122.2:22`, proving the
  fixed runner created and used its own managed directory rather than
  depending on ambient state. Reproduced again even with a hostile ambient
  `ANSIBLE_SSH_ARGS` pointed at a nonexistent path — the fixed runner's own
  env still won (`cmd.Env = append(os.Environ(), r.Env...)`, later entry
  wins for a real subprocess's `getenv`).

## 2. Bug #2 — roster path resolved only from the decommission target's own inventory var

Found by actually running `pilot host decommission apply` (not just `plan`)
against a genuinely-enrolled `hd-client1`, end to end.

`hosts.yml` (target host has no `freeipa_roster_file` of its own — the
normal case for a plain client; only the FreeIPA server declares it):

```yaml
hosts:
  hd-ipa1:
    ansible_host: "192.168.122.2"
    freeipa_roster_file: "/home/kjelly/github/pilot/tmp/hd-real-removal-test/roster.yaml"
    roles: [freeipa-server]
  hd-client1.ipa.pilot.internal:
    ansible_host: "192.168.122.3"
    roles: [freeipa-client]
```

`plan` came back `status=executable`; `apply` ran the real local uninstall
(confirmed: `/etc/ipa/default.conf` gone), but then deadlocked permanently:

```
STATUS blocked plan=hd-...
  blocker: freeipa-client/host_object "hd-client1.ipa.pilot.internal": active_residue (ipa host-show hd-client1.ipa.pilot.internal)
```

Root cause: `decommission.RosterPathFor`/`ScanReferences` (and, downstream,
`providers.PlanInput.RosterPath`) resolved the roster path **only** from
`host.Extra["freeipa_roster_file"]` on the decommission TARGET itself. Since
only the FreeIPA server (or an nfs-server/nfs-client host) conventionally
declares that field — never a plain client — `freeipaRosterAbsentStep`'s
`rosterPath` was always empty for the common case, so its `Execute()` was a
silent no-op (`if strings.TrimSpace(e.rosterPath) == "" { return nil }`): the
roster's `hosts[].state` was never flipped to `absent`, so
`freeipa-identity-apply.yml`'s "Compute the roster's absent host list" always
computed empty and never ran `ipa host-del`/`dnsrecord-del`. `apply` had no
way to ever converge — a permanent deadlock for any ordinary client host.

Fix: `rosterPathFor` now falls back to scanning every OTHER host in the
workspace (sorted by name, first match) for a declared `freeipa_roster_file`
— the same "look at whatever any host already carries" convention
`checkRosterCompleteness`/`discoverRosterFilePath`/`autoFillFreeIPARosterFile`
(cmd/pilot/cmd) already use. Threaded through `ScanReferences`,
`planComponent`, and `buildHostDecommissionProviders`. Regression test:
`TestReferences_RosterPathFallsBackToAnotherHostInWorkspace`
(`internal/decommission/references_test.go`).

## 3. 新增 FreeIPA host（enrollment）— real run

```
$ go run ./cmd/pilot vm-target run --name hd-client1 playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.2 -e ipa_verify_user=admin \
    -e @~/.vault/main.yaml
PLAY RECAP: hd-client1 : ok=63 changed=8 unreachable=0 failed=0 skipped=149
$ go run ./cmd/pilot vm-target exec --name hd-client1 -- bash -c 'test -f /etc/ipa/default.conf && echo ENROLLED'
ENROLLED
$ go run ./cmd/pilot vm-target exec --name hd-ipa1 -- bash -c 'echo "<admin password>" | kinit admin; ipa host-show hd-client1.ipa.pilot.internal'
  Host name: hd-client1.ipa.pilot.internal
  Principal name: host/hd-client1.ipa.pilot.internal@IPA.PILOT.INTERNAL
  Keytab: True
```

## 4. 刪除 FreeIPA host（decommission）— real run, with both fixes applied

Roster (`tmp/hd-real-removal-test/roster.yaml`, schema_version 2) declared the
client host explicitly (`hosts: [{name: hd-client1.ipa.pilot.internal, state:
present, ip_address: 192.168.122.3}]`) so the plan had a real reference to
converge — a host the roster never mentions at all is a legitimate no-op for
this step, not a bug.

```
$ pilot host decommission plan --dir tmp/hd-real-removal-test --host "hd-client1.ipa.pilot.internal"
PLAN hd-ec9b0c2c1db42e0735e90708 host=hd-client1.ipa.pilot.internal status=executable
  component role=freeipa-client id=freeipa-client supported=true

$ pilot host decommission apply --dir tmp/hd-real-removal-test \
    --id hd-ec9b0c2c1db42e0735e90708 --confirm-host "hd-client1.ipa.pilot.internal"
STATUS completed plan=hd-ec9b0c2c1db42e0735e90708
  receipt: decommission_id=hd-ec9b0c2c1db42e0735e90708 host=hd-client1.ipa.pilot.internal
           completed_at=2026-09-11T02:34:07Z final_inventory_revision=f6726d7a...
```

Independent verification against the LIVE systems (not pilot's own report),
run separately afterward:

```
$ go run ./cmd/pilot vm-target exec --name hd-ipa1 -- bash -c '
    echo "<admin password>" | kinit admin
    ipa host-show hd-client1.ipa.pilot.internal
    ipa dnsrecord-show ipa.pilot.internal hd-client1'
ipa: ERROR: hd-client1.ipa.pilot.internal: host not found
ipa: ERROR: hd-client1: DNS resource record not found

$ go run ./cmd/pilot vm-target exec --name hd-client1 -- bash -c \
    'test -f /etc/ipa/default.conf && echo STILL_ENROLLED || echo UNINSTALLED'
UNINSTALLED
```

Zero residue, confirmed. `hosts.yml` no longer contains
`hd-client1.ipa.pilot.internal` after finalization (regenerated
`inventory.yml`, `final_inventory_revision` differs from the pre-decommission
one).

## 5. Naming gotcha hit along the way (not a bug — a documented convention)

The first `plan` attempt used the short inventory host name `hd-client1`
(matching `hosts.yml`'s key) and was blocked:

```
blocker[ownership_unknown]: freeipa-client: unknown/unproven service principal blocks host deletion:
  host hd-client1 still has service principal(s) managed by it: host/hd-client1.ipa.pilot.internal@...
```

Cause: `providerFQDN` (`internal/decommission/planner.go`) deliberately
prefers `host.Name` over `host.AnsibleHost` as "this host's FreeIPA/DNS
identity" (a prior Phase 3b fix, see `2026-09-03-3b4ef4d.md` §9.1) — so
`hosts.yml`'s key for a FreeIPA-integrated host **must be the real FQDN**
(`hd-client1.ipa.pilot.internal`), not a short alias, whenever host
decommission needs to match it against live FreeIPA state. Renaming the
`hosts.yml` key to the FQDN resolved this immediately; no code change needed.
Carried into the runbook as an explicit prerequisite.

## 6. Teardown

`hd-ipa1`/`hd-client1` left running (pre-existing shared test infra from an
earlier session): `hd-client1` is now genuinely decommissioned (matches its
real post-removal state); `hd-ipa1` is unaffected. Not torn down.
