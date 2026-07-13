---
name: vm-target-spec-testing
description: |
  Use `pilot vm-target` to test any spec (`docs/verification/<x>.md`) and
  apply-playbook (`playbooks/apply/<x>.yml`) pair on disposable KVM VMs
  before committing. Covers single-VM testing (one spec, one target),
  multi-VM testing (server+client enrolled against each other), and spec
  promotion from DRAFT to v1.0 per AGENTS.md §1/§2/§3. Use when the task
  involves: (1) writing or modifying a verification spec that targets a
  real host, (2) running `pilot vm-target up/run/verify/down` on a
  playbook that has never been exercised on a VM before, (3) promoting a
  spec out of DRAFT status, or (4) debugging `skipping: no hosts matched`
  or spec-vs-inventory misalignment on any vm-target.
---

# vm-target-spec-testing

> Generic recipe for exercising **any** spec + apply playbook pair against
> `pilot vm-target` KVM targets. The freeipa-server/client work is the
> first case study; the patterns here are extracted from that experience.

## 0. Hard preconditions (always)

Read `AGENTS.md` §0, §1, §2, §4. These are non-negotiable:

- **§1.1 actual-run**: every command you write into a runbook / spec must
  have been executed on the target environment and must have the real
  captured output.
- **§0.1 read inventory facts, not spec intentions**: always `show-inventory`
  before every `run` or `verify`. The `spec-vs-inventory` regression test
  exists for a reason.
- **§2 fact snapshot**: every runbook gets a §0.5 fact snapshot with
  `vm-target list`, `show-inventory`, vault keys, and an alignment decision
  (A: fix inventory, B: fix spec).
- **§4 playbook gate**: `ansible-playbook --syntax-check` + `--list-tags`
  + `--check --diff` on the target before any commit.

The host must have `/dev/kvm`, `virsh`, `qemu-img`, `qemu-system-x86_64`,
`cloud-localds`, an active `default` libvirt network, and the user in the
`libvirt` group with ownership of `/var/lib/libvirt/images/pilot`.

## 1. Decide the test shape

Every spec test fits one of three shapes. Pick the right one before
allocating VMs.

### Shape 1: single-target, spec→verify only

You have `docs/verification/<spec>.md` but no dedicated apply playbook.
The spec's commands run directly via `vm-target verify`.

```
pilot vm-target up    --name <name> ...
pilot vm-target verify --name <name> docs/verification/<spec>.md
pilot vm-target down  --name <name>
```

No playbook is run; every check in the spec must be achievable from a
fresh cloud image (or the spec must list preconditions).

### Shape 2: apply playbook → verify spec (single VM)

Most common. You have `playbooks/apply/<role>-apply.yml` paired with
`docs/verification/<role>.md`. The playbook mutates the VM, then you
verify the spec.

```
pilot vm-target up    --name <name> --disk <N> ...
pilot vm-target run   --name <name> --sandbox playbooks/apply/<role>-apply.yml -e ...
pilot vm-target verify --name <name> docs/verification/<role>.md
pilot vm-target down  --name <name>
```

`--sandbox` (default for every `run` -- see "Best practices" below)
runs `ansible-playbook` inside a throwaway Docker container instead of
requiring ansible + collections installed on the host driving `pilot`.

### Shape 3: multi-VM (server + enrolled client)

Two or more VMs must be alive simultaneously, with cross-VM networking
(server exposes a service, client enrolls against it). See
`references/case-study-freeipa.md` for the canonical example. The
pattern extends to any pair: database server + app, DNS server + client,
etc.

```
pilot vm-target up --name <server-vm> --disk <N> ...
pilot vm-target up --name <client-vm> --disk <M> ...

# pin each VM's IP into the other's /etc/hosts (idempotent; safe to
# re-run after a `vm-target reset`) — see references/multi-vm-networking.md
pilot vm-target wire --name <server-vm> --peer <client-vm>
pilot vm-target wire --name <client-vm> --peer <server-vm>

# apply playbook to server, then enroll client against server IP
pilot vm-target run  --name <server-vm> --sandbox playbooks/apply/<server>.yml ...
# (client install — may be a playbook, may be exec steps copied from the spec)

# verify both independently, then run cross-check (getent / curl / sudo -l)
pilot vm-target verify --name <server-vm> docs/verification/<server>.md
# cross-check from client against server
pilot vm-target exec  --name <client-vm> -- <curl/getent/...>

pilot vm-target down --name <client-vm>
pilot vm-target down --name <server-vm>
```

If instead the playbook itself needs to run **against both nodes in one
play** (e.g. `hosts: "{{ target_group | default('ipa_masters') }}"` on a
primary+replica install), combine them into one grouped inventory
instead of two separate `run`s:

```bash
pilot vm-target run --group masters=<server-vm> --group replicas=<client-vm> \
  --sandbox -- playbooks/apply/<role>-replica-apply.yml -e target_group=masters ...
```

See `references/vm-target-basics.md`'s `--group` section.

**3+ named roles, or a scenario you'll bring up/reset more than once**
(e.g. FreeIPA primary+replica+client): don't hand-assemble the `up`/
`wire`/`--group` sequence above — declare it once as a
`vm-target topology` spec instead. See
`references/multi-vm-networking.md`'s "Declarative topology" section.

```bash
pilot vm-target topology up        --spec <scenario>.yaml   # concurrent, idempotent
pilot vm-target topology inventory --spec <scenario>.yaml   # real ansible groups
pilot vm-target topology down      --spec <scenario>.yaml
pilot vm-target topology reset     --spec <scenario>.yaml   # every node back to clean + re-wired, in one call
```

`snapshot`/`rollback`/`reset` also work at the topology level — every
node concurrently, with `rollback`/`reset` auto-re-wiring afterward
(the `clean` snapshot predates wiring). Don't `vm-target reset --name`
each node by hand and re-run `wire` yourself to test "does this rerun
cleanly from scratch" — that's exactly what `topology reset` automates.

## 2. Before every run: fact snapshot (AGENTS.md §2)

```bash
# 2a. Inventory facts (one per VM)
go run ./cmd/pilot vm-target list
go run ./cmd/pilot vm-target show-inventory --name <name>
# for real hosts: ansible-inventory -i <inventory> --graph

# 2b. Vault / external state
yq 'keys' ~/.vault/<role>-sandbox.yaml

# 2c. Alignment decision
# If the spec's {section}1 target group set does not match the inventory's host set,
# explicitly choose A (fix inventory by re-provisioning with the right --hosts
# or editing the inventory file) or B (fix the spec). Write the choice in the
# runbook. Never "pretend they align" (AGENTS.md §2.1).
```

Paste these five facts into the runbook _before_ you run any ansible
command. If the snapshot changes mid-run, update the runbook, not the
other way around.

## 3. Bring up the VMs

### 3.1 Pick the right vm-target flags

| Parameter     | Default       | When to override                                  |
|---------------|--------------|--------------------------------------------------|
| `--disk`      | 30 GiB        | Every spec run; 30 for servers, 20 for clients    |
| `--memory`    | 2048 MiB      | 4096 for database / Java / container-heavy roles  |
| `--vcpus`     | 2             | Heavy compiles -> 4                                |
| `--ssh-user`  | root          | Set to `ubuntu` for ubuntu-24.04 cloud image       |
| `--ssh-timeout` | 2m          | First boot -> 8m; subsequent boots -> default fine  |
| `--boot-timeout` | 3m         | First boot -> 8m                                   |

```bash
# single VM: generic
go run ./cmd/pilot vm-target up     --name <name>     --ssh-user ubuntu     --disk 30 --memory 4096 --vcpus 2     --ssh-timeout 8m --boot-timeout 8m
```

### 3.2 First-up warnings you will see (ignore them)

- `libguestfs ... supermin exited with error status 1` -- harmless; the
  fallback uncustomized image boots fine and has python3/sudo.
- `no active lease for MAC ...` for 20-30 s -- normal; dnsmasq takes a
  moment.
- `--ssh-timeout` exceeded -> the domain gets **destroyed**. Retry with
  longer timeout the first time only.

### 3.3 Verify the VM is truly ready

```bash
go run ./cmd/pilot vm-target exec --name <name> -- uname -a
go run ./cmd/pilot vm-target exec --name <name> -- sudo -n id   # passwordless sudo
```

For **Shape 3** (multi-VM), also verify cross-VM ping before applying
any playbook:

```bash
go run ./cmd/pilot vm-target exec --name <server> -- ping -c1 <client-ip>
go run ./cmd/pilot vm-target exec --name <client> -- ping -c1 <server-ip>
```

## 4. Dry-run the apply playbook (AGENTS.md §1.1, §4)

```bash
go run ./cmd/pilot vm-target run --name <name> --sandbox     playbooks/apply/<role>-apply.yml     -e <key>=<value> ...     -e @/home/ubuntu/.vault/<role>-sandbox.yaml     --check --diff
```

(`--check`/`--diff` forward straight through to `ansible-playbook`
regardless of `--sandbox` — see AGENTS.md §4.)

Expected in `--check`:
- All `assert`/gate tasks: `ok`
- `/etc/hosts` / data-dir tasks: `changed` on first run, `ok` thereafter
- Mutate tasks under `when: not ansible_check_mode`: all `skipping`
- `PLAY RECAP: failed=0 skipped>=0`

**If `changed` > expected on a re-run, stop.** Something is not
idempotent. Investigate the task's `regexp` / `state:` args.

**Debug tip**: the playbook path is a positional arg, not a flag.  
`pilot vm-target run --name <n> <playbook> [extra args...]` -- correct.  
`pilot vm-target run --name <n> -i <inv> <playbook>` -- wrong (cobra
parses `-i` as the playbook path).

## 5. Real apply

```bash
go run ./cmd/pilot vm-target run --name <name> --sandbox     playbooks/apply/<role>-apply.yml     -e <key>=<value> ...     -e @/home/ubuntu/.vault/<role>-sandbox.yaml
```

Capture the full PLAY RECAP output. If the playbook fails, capture the
failed task output and the rescue dump (if the playbook uses
`block/rescue` per AGENTS.md §4). **Paste the real output into the
runbook as the evidence block** -- never paste a hand-written
"expected" version.

Every run also writes the exact same output to
`<vm-dir>/<name>/runs/<timestamp>-<playbook>.log` (path printed on
stderr) -- `cat` that file for the evidence block instead of
re-transcribing terminal scrollback by hand; it is the actual bytes
ansible produced, not a paraphrase. Add `--json` if you first want a
quick ok/changed/failed/unreachable triage line before deciding whether
the full recap is worth capturing (not combinable with `--sandbox` in
the same invocation -- run once with `--json` to triage, then without
it to capture the real evidence, if you need both).

## 6. Verify (spec checklist run)

```bash
go run ./cmd/pilot vm-target verify --name <name>     docs/verification/<spec>.md
```

The verify playbook is generated by `pilot spec --generate`. It is
auto-tagged with spec row IDs (C1, C2, ...). Run it, capture the
`.verification/<spec>-<UTC>.ndjson` output, and paste the `status=pass`
rows into the spec's evidence-collection block.

If any row is `status=fail`, consult the spec's PASS/FAIL rules and
known deviations. **If the failure is a real bug, fix the playbook
and re-run from §5** -- do not hand-edit the spec to pretend the fail is
expected.

## 7. Cross-check (Shape 3 only)

For multi-VM specs, run the end-to-end check from the client against the
server:

```bash
go run ./cmd/pilot vm-target exec --name <client> --     <cross-check command from the spec's SOP section>
```

The check must exercise the real service path -- e.g. `getent passwd`,
`curl`, `sudo -l` -- not just port-listening. If the cross-check fails,
the server's spec is not actually green, even if §6 passed all rows.

## 8. Tear down

```bash
go run ./cmd/pilot vm-target down --name <client-vm>   # if multi-VM
go run ./cmd/pilot vm-target down --name <server-vm>
```

**Always down after the run**, even on failure. The VM overlay is a
qcow2 that grows with every mutation; leaving it running clutters the
host's `virsh list`.

**Iterating on a playbook that isn't green yet?** Don't `down`+`up`
between attempts -- `pilot vm-target reset --name <name>` reverts to the
pristine post-`up` snapshot in seconds. Fix the playbook, `reset`, `run`
again. Save `down` for when the spec is actually green (§9) or you're
switching to a different base image/disk size.

**If the apply playbook wrote shared state outside the VM's qcow2** (e.g.
a bind-mounted `--data-dir`), remove it so the next run starts clean:

```bash
sudo rm -rf /var/lib/libvirt/images/pilot/<name>
```

## 9. After a green run: promote the spec

When _all_ rows in §6 pass and the cross-check (if multi-VM) is green,
promote the spec from DRAFT to v1.0. See
`references/spec-promotion-checklist.md` -- the checklist is identical
for every spec.

## 10. Best practices (quick reference)

- **Default every `run` to `--sandbox`.** Set `sandbox.image` once in
  `~/.config/pilot/config.yaml` (e.g.
  `geerlingguy/docker-ubuntu2204-ansible:latest`, which ships
  `ansible-playbook` on `$PATH`) instead of repeating `--sandbox-image`
  on every command. This keeps the host driving `pilot` free of
  ansible/collection version drift — the container is the only thing
  that needs to match what the playbook requires. See
  `references/vm-target-basics.md`'s "Sandbox mode" section for the
  `--json` incompatibility and the multi-key mount behavior under
  `--group`.
- **Don't hand-transcribe run output into a runbook.** Every `run`
  writes the exact bytes to `<vm-dir>/<name>/runs/<timestamp>-<x>.log`
  (path printed on stderr) — `cat` that for the AGENTS.md §1.1 evidence
  block. Use `--json` only for a quick triage line, not as the evidence
  itself.
- **Multi-VM hostname resolution: use `vm-target wire`, not a
  hand-typed `>> /etc/hosts`.** It resolves peer IPs from vm-target's
  own state (never stale, never hand-copied) and replaces its block
  idempotently, so it's safe to call again after a `reset`. Reserve the
  `lineinfile`+`delegate_to` playbook pattern for playbooks that must
  also run unchanged against real, already-networked hosts.
- **A single playbook that must run against several named nodes at
  once → `run --group`, not several separate `run`s.** Only reach for
  it when the playbook's own `hosts:` pattern needs to see more than
  one vm-target VM in the same play (e.g. a primary+replica install);
  independent per-node applies (plain client/server enrollment) don't
  need it.
- **A named multi-VM scenario you'll bring up more than once → a
  `vm-target topology` spec, not a hand-typed `up`/`wire`/`--group`
  sequence.** One YAML file lists every node's image, ansible groups,
  and wire peers; `topology up` is idempotent and provisions every
  not-yet-running node **concurrently** (safe since the 2026-07-06
  state-race fix — see the `pilot-vm-target-up-concurrency-race`
  memory and AGENTS.md §5.1), and `topology inventory` gives real
  ansible groups without a `target_group=all` workaround.
- **Testing "does this reinstall cleanly from scratch?" on a multi-VM
  scenario → `topology reset`, not per-VM `reset` + manual re-`wire`.**
  `reset`/`rollback` at the topology level revert every node concurrently
  and automatically re-apply each node's `wire:` peers afterward (the
  `clean` snapshot predates wiring, so a bare per-VM `reset` silently
  drops it). See `docs/runbooks/freeipa-server-replica-ha-drill.md` §11
  for real captured output.
- **Prefer `reset` over `down`+`up` while iterating** on a playbook
  that isn't green yet (§8) — seconds instead of a full reprovision +
  boot wait.
- **`--skip-syntax-check`/`--skip-lint` are for speed during rapid
  iteration only.** Leave the (default-on) `ansible-playbook
  --syntax-check` + `ansible-lint` preflight enabled for the run whose
  output becomes runbook evidence, so a trivially broken playbook
  doesn't waste a full VM round-trip before failing.

## 11. Reference index

1. `references/vm-target-basics.md` -- vm-target lifecycle,
   `show-inventory` contract, timeout defaults, first-boot costs,
   `libguestfs` supermin warning, `dnsmasq` lease behaviour, **`--sandbox`
   mode (the default for `run`), `--json`, run transcripts, and
   `--group` multi-host inventories**.
2. `references/spec-promotion-checklist.md` -- the AGENTS.md §3
   checklist that applies to any spec: lint, `bash -n`, regression
   test, evidence swap, version bump.
3. `references/case-study-freeipa.md` -- the canonical Shape 3
   example: freeipa-server install + client enroll. Read this before
   tackling your first multi-VM spec (note: predates `wire`/`--group`;
   see its superseded-steps callout and
   `docs/runbooks/freeipa-server-replica-ha-drill.md` for the current
   `wire`-based drill).
4. `references/container-in-vmtesting.md` -- when your apply playbook
   runs `community.docker.docker_container` inside a vm-target, the
   image entrypoint, bind-mount, PATH, and pid-1 traps you will hit.
   Not to be confused with `--sandbox` (see file 1).
5. `references/multi-vm-networking.md` -- cross-VM `/etc/hosts` via
   **`vm-target wire`** (recommended) or a `delegate_to` playbook task,
   `--group` for combined multi-node inventories, **`vm-target
   topology` for declarative multi-node scenarios** (one YAML spec ->
   concurrent idempotent bring-up + auto-wire + grouped inventory),
   time sync for Kerberos, libvirt `default` network pool, hostname
   resolution in a two-node setup.
