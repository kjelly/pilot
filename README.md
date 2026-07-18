# pilot

> **Coding-agent-assisted, spec-driven Ansible delivery CLI**

`pilot` keeps the delivery runtime deterministic. A coding agent turns an approved
requirement into a verification spec, an apply playbook, and regression tests;
pilot then lints, tests, deploys, verifies, and records the result. It does not
call an LLM at runtime.

The normal lifecycle is:

```text
requirement → verification spec → apply playbook → disposable-target test
            → deploy → verify → report + checkpoint history
```

The repository rules in [AGENTS.md](./AGENTS.md) are part of this workflow:
spec first, inventory facts before execution, stage gates for mutations, and
actual-run evidence for runbooks and verification documents.

## When to use pilot

| Situation | Use this |
|---|---|
| Create or revise an Ansible inventory without hand-authoring nested groups | `inventory`, or the interactive `edit` wizard |
| Validate a verification spec's structure | `spec --lint` |
| Inspect effective state on one host, a fleet, or the control node | `verify` |
| Develop a role on a fast, clean Linux test host | `docker-target` |
| Need kernel fidelity, snapshots, or SSH to an isolated host | `vm-target` |
| Test a multi-node scenario such as FreeIPA HA | `vm-target topology` |
| Deploy through a guarded, interactive flow | `deploy` |
| Diagnose Ansible or target prerequisites | `doctor` |

## Install and orient yourself

Requirements are Go 1.22+, Ansible/`ansible-playbook`, and, when applicable,
Docker or Podman for container targets, or libvirt plus libguestfs tools for VM
targets. `ansible-lint` is recommended.

```bash
go build -o pilot ./cmd/pilot
./pilot --help
```

The CLI help is the authoritative flag reference for the version you are
running. Use `pilot <command> --help` before a state-changing operation.

Global options available across commands include `--config`, `--data-dir`, and
`--log-level`. `PILOT_LOG_LEVEL` and `PILOT_LOG_FORMAT` configure diagnostics;
target binary overrides are available through `PILOT_SSH_BIN`,
`PILOT_VIRSH_BIN`, `PILOT_DOCKER_BIN`, and `PILOT_PODMAN_BIN`.

## Command map

### Authoring, inventory, and delivery

| Command | Appropriate use |
|---|---|
| `pilot edit` | Interactive editor for `hosts.yml`, role presets, `group_vars`, and vault skeletons; useful when you prefer a wizard or maintain separate environment directories. |
| `pilot inventory generate` | Render the simple host-to-roles source into the full Ansible inventory; also backfills missing role variables and vault skeletons unless disabled. |
| `pilot inventory lint` | Validate `hosts.yml` before generating or committing an inventory. |
| `pilot inventory roles` | List the valid role values accepted in the simple host source. |
| `pilot deploy` | Guided deployment: choose inventory, component(s), stage, preview, and confirmation. It preserves the same stage gates as manual deployment. |
| `pilot doctor` | Check the Ansible toolchain and target prerequisites before a deployment or target test. |

### Spec and verification

| Command | Appropriate use |
|---|---|
| `pilot spec <spec.md> --lint` | Parse and lint a verification spec before implementing or testing its apply playbook. |
| `pilot spec <spec.md> --generate <path>` | Produce a diagnostic generated playbook. It is for parser/generator work only, never the source of a production apply playbook. |
| `pilot spec <spec.md> --status` | Show compiled/applied/verified coverage for a spec. |
| `pilot spec status <spec.md>` | Equivalent status subcommand, useful for scripts and explicit command discovery. |
| `pilot verify <spec.md>` | Run every row of one spec locally by default, or use `--inventory` and `--limit` for remote/fleet verification. It writes NDJSON and Markdown reports and updates checkpoints. |
| `pilot verify --dir <directory>` | Verify every Markdown spec in a directory and print a roll-up. |
| `pilot verify --probe <command>` | Test one candidate probe through the same pipeline and matcher as a spec row before committing its `Expected` value. |

`--apply` and `--to-inventory` on `pilot spec` are retired. Production
mutation belongs in reviewed `playbooks/apply/*.yml`; inventory generation is
handled by `pilot inventory generate`; acceptance uses `pilot verify`.

### Docker disposable targets

Choose `docker-target` for a quick, low-overhead clean-host loop where a
container is faithful enough. For an independent kernel or VM-specific
behavior, use `vm-target`.

| Command | Appropriate use |
|---|---|
| `pilot docker-target up` | Create a disposable container target. |
| `pilot docker-target list` | List tracked targets and their live state. |
| `pilot docker-target show-inventory` | Print the generated inventory; inspect these real target facts before running a playbook. |
| `pilot docker-target run` | Run an Ansible apply playbook against one target. |
| `pilot docker-target verify` | Run a verification spec against one target. |
| `pilot docker-target exec` | Run one non-interactive command inside the target for diagnosis. |
| `pilot docker-target snapshot` | Commit the current state as a reusable image tag before an experiment. |
| `pilot docker-target rollback` | Recreate the target from a snapshot tag after an experiment or failure. |
| `pilot docker-target down` | Remove the container and clear its tracked state. |

### KVM virtual-machine disposable targets

Choose `vm-target` when kernel/systemd behavior, SSH access, snapshots, or a
more production-like host matters. A target starts from a per-target overlay of
an immutable base image, keeping fresh runs isolated.

| Command | Appropriate use |
|---|---|
| `pilot vm-target up` | Provision one VM and wait for SSH. |
| `pilot vm-target list` | List tracked VMs and their live state. |
| `pilot vm-target show-inventory` | Print the generated SSH inventory; inspect it before selecting a host/group. |
| `pilot vm-target run` | Run an Ansible apply playbook against one VM. |
| `pilot vm-target verify` | Run a verification spec against one VM. |
| `pilot vm-target test` | Preferred single-VM feature test: syntax check, snapshot, apply, verify, then idempotency. |
| `pilot vm-target exec` | Run one remote command without opening an interactive host shell. |
| `pilot vm-target ssh` | Open an interactive SSH session, or invoke a remote command with a PTY. |
| `pilot vm-target shell` | Convenience alias for an interactive SSH shell. |
| `pilot vm-target wire` | Pin peers into `/etc/hosts` before testing playbooks that require stable multi-host names. |
| `pilot vm-target snapshot` | Save one VM under a tag before a risky experiment. |
| `pilot vm-target rollback` | Restore one VM to a tagged snapshot. |
| `pilot vm-target reset` | Return one VM to its clean post-boot state for a fast retry. |
| `pilot vm-target resize-disk` | Grow the root disk of an existing target. |
| `pilot vm-target down` | Destroy and undefine the target when no longer needed. |

### Multi-VM topology targets

Use `pilot vm-target topology` when one spec describes several nodes, their
Ansible groups, and their peer wiring. This is the appropriate path for
cluster-level apply/verify/idempotency testing.

| Command | Appropriate use |
|---|---|
| `pilot vm-target topology up` | Provision all declared nodes concurrently and apply their peer wiring. Re-running is safe for nodes already up. |
| `pilot vm-target topology status` | Show each declared node's live status, IP, and groups. |
| `pilot vm-target topology inventory` | Render grouped inventory for the running topology; use it to verify actual group-to-host facts. |
| `pilot vm-target topology test` | Preferred cluster test: snapshot all nodes, apply, verify each mapped spec, then assert idempotency. Add `--ephemeral` to create a fresh disposable topology and remove it afterwards; add `--keep-on-failure` to retain a failed ephemeral topology for SSH debugging. |
| `pilot vm-target topology snapshot` | Snapshot every node under one tag before a drill. |
| `pilot vm-target topology rollback` | Restore all nodes to a tag and reapply declared peer wiring. |
| `pilot vm-target topology reset` | Reset all nodes to their clean post-up state and rewire them. |
| `pilot vm-target topology down` | Tear down every node declared by the topology spec. |

### Shell integration and metadata

| Command | Appropriate use |
|---|---|
| `pilot completion bash` | Emit Bash completion for a shell setup. |
| `pilot completion fish` | Emit Fish completion for a shell setup. |
| `pilot completion powershell` | Emit PowerShell completion for a shell setup. |
| `pilot completion zsh` | Emit Zsh completion for a shell setup. |
| `pilot version` | Print the installed CLI version for issue reports and automation logs. |
| `pilot help` | Show help for the root command or a requested subcommand. |

## Guardrails and working model

- A verification spec is the acceptance contract. Confirm it before authoring
  the corresponding `playbooks/apply/*.yml` implementation.
- Apply playbooks mutate hosts; use their stage/confirmation gates, take the
  required backups, and keep host-specific values in variables or vault files.
- Before executing against a target, inspect the actual inventory with
  `show-inventory` (or `ansible-inventory --graph` for a real inventory). Do
  not infer host groups from a spec.
- For a single VM, prefer `vm-target test`; for multiple VMs, prefer
  `vm-target topology test`. Both provide the apply → verify → idempotency
  chain needed for delivery evidence.
- Reports are written under `.verification/`; checkpoint history and target
  state live under the configured data directory.

## Further reading

- [AGENTS.md](./AGENTS.md) — repository hard rules for specs, playbooks,
  inventories, and evidence.
- [docs/README.md](./docs/README.md) — documentation index and layout.
- [DELIVERY.md](./DELIVERY.md) — delivery verification guidance.
- [TESTING.md](./TESTING.md) — test and version-control conventions.
- [docs/ansible-playbook-development.md](./docs/ansible-playbook-development.md)
  — playbook development workflow.
