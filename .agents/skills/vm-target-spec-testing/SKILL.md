---
name: vm-target-spec-testing
description: |
  Test a docs/verification spec and its playbooks/apply playbook on disposable
  KVM VMs: `pilot vm-target test` for one VM, `vm-target topology test`
  (`--ephemeral` for fresh hosts) for multi-host or cross-playbook runs, then
  record candidate-bound evidence. Not for feature design
  (spec-driven-feature-workflow), runbook re-verification
  (pilot-trec-verification), docker-target or real hosts.
---

# vm-target-spec-testing

Run a spec + apply-playbook pair on disposable libvirt/KVM VMs and turn the
result into evidence that meets AGENTS.md §1. The rules live in
[AGENTS.md](../../../AGENTS.md) and
[docs/actual-run-evidence.md](../../../docs/actual-run-evidence.md) and win
over this skill. Flags were checked against `--help` and
`cmd/pilot/cmd/vm_target*.go`; re-check `--help` before relying on one.
`pilot` means `go run ./cmd/pilot` in the checkout under test.

## 0. Before you start

Read the AGENTS.md sections your change touches; do not work from copies.

| Your change touches | Read |
|---|---|
| a command you will write into `docs/runbooks/` or `docs/verification/` | §1.1–§1.3, §2 |
| how to run the test | §1.4 |
| the formal evidence run | §1.2, §1.5, §7 "Evidence recordings are disposable" |
| a new or changed spec | §3.0, §3, `docs/verification-spec-template.md` |
| `playbooks/apply/*.yml` | §4.0 fresh-host check mode, §4.3 stage gate, §4.4 tags, §4.5 traps |
| state another host must provide (users, sudo rules) | §4.1 fixtures |
| a role that leaves data behind | §4.2 backup scope |
| parsing CLI output; a gate, matcher or `changed_when` | §5.6, §5.12 |
| a removal, revoke or cleanup path | §5.14 |

Host: `/dev/kvm`, `virsh`, `qemu-img`, `qemu-system-x86_64`, `cloud-localds`,
`ssh-keygen`, an active libvirt network and a writable `--vm-dir`
([docs/runbooks/vm-target.md](../../../docs/runbooks/vm-target.md) §2).
`test` and `topology test` run the host's `ansible-playbook` (from `PATH`)
and have no sandbox mode: install the collections CI installs
(`.github/workflows/ci.yml`) and run from the checkout root so its
`ansible.cfg` applies.

### 0.1 Host-local cache services

Bringing VMs up more than once? Run `pilot services up --profile dev-lite`
(apt-cacher-ng, Pulp RPM, Harbor) and `pilot services status` once, keep the
stack up all session, and pass `--services local` to `vm-target up` or set
`services: local` at a topology YAML's root. It is fail-closed: a down stack
fails `up`; fix it rather than using `--services none`. The VM-side path is
not acceptance-tested ([vm-target.md](../../../docs/runbooks/vm-target.md)
§2.2): do not cite it as verified in a spec.

### 0.2 The host is shared

`vm-target list` shows every session's VMs, not yours: clones and sessions
share libvirt, `--vm-dir` and, by default, the data dir. Use names unique to
this session (for example `<branch-abbrev>-<role>`) and write down every
name you `up`. `up` refuses a name already in pilot state or libvirt.

## 1. Pick the path

| Situation | Use |
|---|---|
| one spec, one apply playbook, one host | `up` a fresh VM, then `vm-target test` (§3) |
| several hosts in one play, `site.yml`, specs on different groups | `topology test` (§4) |
| fresh hosts required (new playbook; a check-mode-gated action in one playbook feeds another's gate) | `topology test --ephemeral` (§4); one node is fine |
| a spec with no apply playbook | `vm-target verify` (§6) |
| finding out why a run failed | `reset`/`run`/`verify` by hand (§6), then rerun the chain |

AGENTS.md §4.0 wants `--check --diff` against a target that never had the
playbook. `vm-target test` checks the VM as it is and never provisions: `up`
a new VM (or `reset` one of yours) just before it. Cross-playbook ordering
bugs only show with `--ephemeral`. Manual `run`/`verify` has no L3, no L6
and no rollback, so its output is not the evidence chain.

## 2. Read the inventory facts first

AGENTS.md §0.1, §1.3, §2: read the inventory you will run against, not what
the spec intends.

```bash
pilot vm-target show-inventory --name <vm>
pilot vm-target topology status    --topology <file>
pilot vm-target topology inventory --topology <file> --out tmp/<scenario>.inv.yaml
yq 'keys' ~/.vault/<role>-sandbox.yaml      # key names only, never values
```

`show-inventory` has one host, the VM name; each `--hosts` alias is a group
holding it. `topology inventory` needs every node running; with
`--ephemeral`, record the topology file's `groups:`. Every `-l`,
`target_group` and `--verify` limit must name a group or host from that
output. If the spec's §1 targets disagree, choose A or B (AGENTS.md §2.1).

## 3. One VM: `vm-target test`

```bash
pilot vm-target up   --name <vm> --base-image almalinux-9 --memory 4096 --hosts <group>
pilot vm-target test --name <vm> \
    --playbook playbooks/apply/<role>-apply.yml \
    --spec docs/verification/<role>.md --verify-timeout 40 \
    -- -e target_group=<group> -e @~/.vault/<role>-sandbox.yaml
```

`--base-image` defaults to `ubuntu-24.04`; it also takes `ubuntu-22.04`,
`fedora-40`, `almalinux-9`, `centos-9` or a local qcow2 path. The chain:

1. L1 `ansible-playbook --syntax-check` (`--skip-lint` skips it).
2. L3 `--check --diff` on the current state, before any snapshot.
   `--skip-checkmode` only for a playbook that cannot run in check mode;
   write the reason into the spec or runbook.
3. Snapshot `pre-test-<unix-seconds>`, then L4 apply.
4. L5 `pilot verify <spec> -i <inv> -l <limit> --allow-isolated-mutation`;
   the limit is the VM name (a Spec v2's declared roles if it has them).
   `--verify-timeout` is the per-row timeout; verify's default is 15 s.
5. L6 apply again; fails unless the PLAY RECAP `changed` counts sum to 0.
6. A failure in L4–L6 rolls back to the snapshot (`--no-rollback` keeps
   the failed state for inspection).

Arguments after `--` reach the L3, apply and idempotency runs verbatim;
`-e target_group=<g>` drops the automatic `-l <vm>`. The VM must be running.
After a pass it keeps the applied state and the snapshot. `test` writes no
transcript: capture its output (§5).

## 4. Several VMs or fresh hosts: `vm-target topology test`

```yaml
# docs/topologies/<scenario>.yaml
services: local                   # optional, §0.1
nodes:
  - name: <abbrev>-server
    base_image: almalinux-9       # default ubuntu-24.04
    memory: 4096
    groups: [<server-group>]      # the group names the playbooks and specs target
  - name: <abbrev>-client
    groups: [<client-group>]
    wire: ["<abbrev>-server=<server-fqdn>"]
```

```bash
pilot vm-target topology test --topology docs/topologies/<scenario>.yaml --ephemeral \
    --playbook playbooks/site.yml \
    --verify docs/verification/<server>.md=<server-group> \
    --verify docs/verification/<client>.md=<client-group> \
    --verify-timeout 40 -- -e stage=sandbox -e @~/.vault/<scenario>-sandbox.yaml
```

- Same chain over the rendered grouped inventory. No `-l` is added; L6 sums
  `changed` over every host. `--verify` is required and repeatable; a spec
  without `=<limit>` is verified against the whole inventory.
- Without `--ephemeral` it tests an existing topology (`topology up` first);
  a failure rolls every node back and re-wires `/etc/hosts`.
- `--ephemeral` refuses to start if a declared node name exists, provisions
  and wires every node, runs the chain, then tears down the nodes it created,
  pass or fail. It never rolls back. `--keep-on-failure` (only with
  `--ephemeral`) leaves failed nodes up for you to `topology down` later.
- The topology file (all fields:
  [references/multi-vm-networking.md](references/multi-vm-networking.md))
  carries VM shape and groups, not group_vars: pass inputs after `--`. A
  node IP is unknown before `--ephemeral` provisions;
  `scripts/topology-checkmode-test.sh` (`make poc-checkmode-test`) does
  `topology up` → `status` → `test` → `down` instead. Those adopt, then
  destroy, any existing VM with a declared name: check `vm-target list` first.

## 5. Formal run: candidate freeze and evidence

Rules: AGENTS.md §1.2, §1.5; steps and record fields:
[docs/actual-run-evidence.md](../../../docs/actual-run-evidence.md) §2–§3.
Quick runs in a dirty worktree are fine while iterating.

1. Commit the spec, playbook, regression test, fixtures and topology file as
   a local candidate commit (no push). The topology fixes images and groups,
   so it is execution-affecting.
2. Check out exactly that commit, clean and isolated, and record its IDs:
   ```bash
   git worktree add --detach <dir> <candidate-sha>
   cd <dir> && git status --short        # must print nothing
   git rev-parse HEAD 'HEAD^{tree}'
   ```
3. From that root, read the facts (§2) and run §3 or §4 against fresh
   targets, keeping raw output in the gitignored `.verification/`:
   ```bash
   mkdir -p .verification
   go run ./cmd/pilot vm-target test ... 2>&1 | tee .verification/<feature>-test.log
   echo "rc=${PIPESTATUS[0]}"
   ```
   `pilot verify` adds `.verification/<spec-stem>-<UTC>.{ndjson,md}`.
4. Read the summary first: exit code, both PLAY RECAPs, `verdict:` lines.
   On failure, search `FAILED!`, `fatal:`, `unreachable`, `PLAY RECAP`
   before reading more (AGENTS.md §7).
5. A fix means a new candidate and a rerun from step 2; old evidence is void.
6. On a pass, commit `docs/evidence/<feature>/<date>-<short-sha>.md`
   ([example](../../../docs/evidence/vm-target/2026-10-01-198fb03.md)) as an
   evidence-only commit, then replace the spec's and runbook's last-verified
   summary and link. No transcripts, no links to `.verification/`
   (AGENTS.md §7 link rule).

## 6. Debugging by hand (not evidence)

```bash
pilot vm-target reset  --name <vm>       # post-up "clean" checkpoint, in seconds
pilot vm-target run    --name <vm> playbooks/apply/<role>-apply.yml --tags C3 -e ...
pilot vm-target verify --name <vm> docs/verification/<role>.md --timeout 40
pilot vm-target exec   --name <vm> -- sh -c '<cmd> | <filter>'   # or: ssh --name <vm>
pilot verify --probe '<cmd>' --probe-expected '<expected>' -i tmp/<vm>.inv.yaml -l <vm>
```

- `run` takes the playbook as its first argument and adds `-i`/`-l` itself.
  Flag parsing is off: do not pass `-i`, and do not put `--` before the
  playbook (it becomes the playbook path). It runs `--syntax-check` with the
  host's `ansible-playbook` first and writes a transcript in
  `<vm-dir>/<vm>/runs/`. `--sandbox`, `--group`, `--json`:
  [references/vm-target-basics.md](references/vm-target-basics.md).
- `vm-target verify` does not add `--allow-isolated-mutation`; pass it for a
  Spec v2 with isolatedMutation rows. For `--probe`, save `show-inventory`
  output to `tmp/<vm>.inv.yaml`.
- `reset` and `rollback` keep cached Ansible facts. `reset` also drops `wire`
  blocks (the clean checkpoint predates wiring); `topology reset` re-wires.

## 7. Cross-host behaviour

Specs test effective behaviour (AGENTS.md §0.2): put the client-to-server
round trip (`getent passwd`, `sudo -l`, `curl`) in a spec row verified with
`--verify <client-spec>=<client-group>`; an ad-hoc `exec` is not evidence.
`wire`, time sync, NAT: [multi-vm-networking.md](references/multi-vm-networking.md).

## 8. Tear down

Tear down after the run, pass or fail, but only VMs this session created (or
that the user named as disposable): `vm-target down --name <vm>`, or
`topology down --topology <file>`, which downs every declared node.
`--ephemeral` cleans up unless `--keep-on-failure` was set. While a playbook
is not green, `reset` instead of `down` + `up`.

`down` deletes `/var/lib/libvirt/images/pilot/<vm>/` (overlay, seed ISO, SSH
key, run transcripts), the static DHCP reservation, the SSH control
directory and the cached Ansible facts. Everything a playbook writes inside
the VM, Docker bind mounts included, lives in that overlay; nothing is
shared between host and VM, and `vm-target reset` clears state that survives
a re-run. **Never `rm -rf` under `/var/lib/libvirt/images/pilot` by hand**:
other sessions' VMs and the shared base images (`images/`) live there. A
directory that survives a successful `down` is a teardown bug (AGENTS.md
§5.14): report it with `ls -la` output; do not delete it.

## 9. Promotion and references

After a green formal run, promote the spec with
[references/spec-promotion-checklist.md](references/spec-promotion-checklist.md).

- [vm-target-basics.md](references/vm-target-basics.md): command map,
  inventory contract, `--sandbox`, `--json`, transcripts, `--group`, disk,
  timeouts, first-boot warnings, host cache, clean slate, fact cache.
- [multi-vm-networking.md](references/multi-vm-networking.md): `wire`,
  `--group`, topology files, time sync, NAT reachability.
- [container-in-vmtesting.md](references/container-in-vmtesting.md): traps
  when the playbook starts containers inside the VM.
- [case-study-freeipa.md](references/case-study-freeipa.md): the first
  multi-VM attempt; the current drill is
  [freeipa-server-replica-ha-drill.md](../../../docs/runbooks/freeipa-server-replica-ha-drill.md).
