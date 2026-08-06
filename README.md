# pilot

> **Coding-agent-assisted, spec-driven Ansible delivery CLI**

`pilot` keeps the delivery runtime deterministic. A coding agent turns an approved
requirement into a verification spec, an apply playbook, and regression tests;
pilot then lints, tests, deploys, verifies, and records the result. It does not
call an LLM at runtime.

The normal lifecycle is:

```text
requirement → verification spec → apply playbook → disposable-target test
            → deploy / reconcile → verify → report + checkpoint history
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
| Reconcile declared day-2 service configuration | `reconcile` |
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

For agent-driven TUI scenarios, use `pilot actions list` for the action names
and `pilot actions schema` for the current JSON contract. These commands are
read-only and come from the same catalog used by scenario validation.

Global options available across commands include `--config`, `--data-dir`, and
`--log-level`. `PILOT_LOG_LEVEL` and `PILOT_LOG_FORMAT` configure diagnostics;
target binary overrides are available through `PILOT_SSH_BIN`,
`PILOT_VIRSH_BIN`, `PILOT_DOCKER_BIN`, and `PILOT_PODMAN_BIN`.

## Command map

### Authoring, inventory, and delivery

| Command | Appropriate use |
|---|---|
| `pilot edit` | Interactive editor for `hosts.yml`, role presets, `group_vars`, and vault skeletons; useful when you prefer a wizard or maintain separate environment directories. |

`pilot edit --actions <scenario.json> --presentation` can also run a semantic
edit scenario through the real TUI and continue with `deploy`/`reconcile`
steps in the same terminal session. Presentation mode expands each edit action
into the logical keyboard commands it sends (for example `↓ × 2 → Enter`). For
a recording that must prove the operation, drive the ordinary `pilot edit`
wizard with TREC keyboard events instead: semantic automation updates the Tea
model internally, so its logical expansion is not a PTY input event. Use
`--trace-out` for a JSONL action trace without putting secret values in the
recording. TREC-wrapped `edit`, `deploy`, and `reconcile` commands always
include `--presentation`.

`pilot deploy --actions <deploy-scenario.json> --presentation` and
`pilot reconcile --actions <reconcile-scenario.json> --presentation` are also
available as standalone semantic TUI drivers. Each standalone scenario must
contain exactly one matching `deploy` or `reconcile` action.
| `pilot inventory generate` | Render the simple host-to-roles source into the full Ansible inventory; also backfills missing role variables and vault skeletons unless disabled. |
| `pilot inventory lint` | Validate `hosts.yml` before generating or committing an inventory. |
| `pilot inventory roles` | List the valid role values accepted in the simple host source. |
| `pilot deploy` | Guided deployment: choose inventory, component(s), stage, preview, and confirmation. It preserves the same stage gates as manual deployment. |
| `pilot reconcile` | Guided day-2 reconcile: choose a contract-backed declarative configuration component, its roster/config source, stage, preview, and confirmation. Only catalog entries explicitly marked as reconcilers appear; a future Nginx config reconciler must first supply its contract, apply playbook, schema, and verification evidence. |
| `pilot doctor` | Check the Ansible toolchain and target prerequisites before a deployment or target test. |

### MCP server for `pilot edit`

| Command | Appropriate use |
|---|---|
| `pilot mcp serve` | Serve `pilot edit`'s semantic edit actions to an external coding agent over the Model Context Protocol (stdio transport only). |

`pilot mcp serve` flags: `--dir` (workspace root the server may read/write,
default `.`), `--transport` (only `stdio` is implemented), `--audit-dir`
(plan/apply audit artifacts, default `<dir>/.pilot/audit/edit`), and
`--allow-write` (registers the mutation tool; omit it to run strictly
read-only).

Without `--allow-write` the server registers three read-only tools:

- `pilot_edit_capabilities` — list the semantic edit actions this server
  currently allows (reflects real server policy, not just the global action
  registry).
- `pilot_edit_inspect` — read the workspace's non-secret configuration
  summary (hosts, role presets, and optionally group vars, vault key names,
  the full roster graph, and the DNS manifest) an agent needs to plan
  actions or answer access questions. `include_roster` returns roster
  users/groups/hostgroups/HBAC rules/sudo command groups+rules, plus two
  server-resolved views — `effective_hbac_access` and
  `effective_sudo_access` — where nested group/hostgroup membership is
  already expanded into concrete usernames and host FQDNs (e.g. "can user X
  reach host Y" is a direct filter over `effective_hbac_access`, no client-
  side graph walk needed). `include_dns` returns DNS zones/records, with
  each record's `target_host` cross-resolved to its `resolved_ip` from the
  inventory. Never returns secret values.
- `pilot_edit_plan` — validate and rehearse a semantic action scenario
  against a temporary copy of the workspace, through the real `pilot edit`
  TUI, without touching the real workspace. Returns a diff, validation
  result, and a `plan_id` for a later apply.

`--allow-write` additionally registers:

- `pilot_edit_apply` — apply a previously-created plan's exact scenario to
  the real workspace through the real `pilot edit` TUI, under a mutation
  lock with automatic rollback on failure.

The same read-only data is also exposed as MCP *resources* (always
registered, independent of `--allow-write`), for clients that browse
`resources/list` instead of calling a tool:

- `pilot://hosts` — ansible inventory hosts (name, IP, user, env, roles).
- `pilot://roster` — the full non-secret roster graph, including the
  effective access views.
- `pilot://roster/effective-access` — just `effective_hbac_access` /
  `effective_sudo_access`, for callers that only want the "who can log in
  to / sudo on which hosts" answer.
- `pilot://dns` — DNS zones/records with `resolved_ip` cross-resolution.

Every `pilot_edit_plan`/`pilot_edit_apply` call writes an audit artifact
(asciicast recording plus scenario/diff metadata) under `--audit-dir`.
Vault/secret actions must use `value_env` (an environment variable name);
a literal secret `value` is rejected before any plan or apply is attempted.

#### Live-host diagnostics (`pilot_diagnose_*`)

Everything above is local-workspace-file read/write only — it never
touches a live host. Two additional, independently-gated flags register a
separate tool family that runs real Ansible ad-hoc commands against a real
inventory host:

- `--enable-diagnose` (requires `--diagnose-inventory`) registers five
  **fixed, code-defined, read-only** tools:
  - `pilot_diagnose_sudo` / `pilot_diagnose_dns` — a command allow-list
    (mirroring `docs/verification/freeipa-client.md` and
    `docs/verification/core-infra{,-provider}.md`) that diagnoses,
    respectively, why a user can/cannot sudo on a host, or why DNS
    resolution is failing there. The `host` argument must be an exact
    inventory hostname — never an ansible pattern/group/wildcard.
  - `pilot_diagnose_logs` / `pilot_diagnose_metrics` — run a
    caller-supplied LogQL/PromQL query against Loki / Thanos Query via an
    ansible ad-hoc `curl` against that service's own loopback (SSH is the
    only reach this server needs — see
    `docs/network-firewall-matrix.md`). Both auto-resolve their singleton
    inventory group (`dashboard` / `thanos-query`) instead of taking a
    `host` argument, since each is contractually a single central role.
    There is no time-range cap: `start`/`end`/`step`/`time` are passed
    through verbatim to Loki/Thanos — the caller decides the query window;
    `--diagnose-step-timeout` is the only backstop against a runaway
    query.
  - `pilot_diagnose_security_logs` — a convenience wrapper over
    `pilot_diagnose_logs` for security/audit events specifically: it
    auto-scopes the query to Loki's `job="pilot-siem"` label, which by
    this deployment's own design already covers nothing but
    security/audit-relevant log lines — from **either**
    `docs/verification/log-server.md`'s forwarded `auth`/`authpriv`/
    `local6` (auditd) logs **or** a co-located `wazuh-manager`'s alerts
    (whichever this deployment ships; both land under the same job label,
    so there's no separate "source" argument). `host` and `search` are
    both optional, plain-substring filters against the log line content
    (not a regex, and — unlike `pilot_diagnose_sudo`/`dns`'s `host` — not
    a precise scope: a wazuh alert's source agent name lives inside its
    JSON body, not in a per-host file path the way log-server's files do,
    so a content search is the one mechanism that finds a host either
    way).
- `--enable-diagnose-raw` (also requires `--diagnose-inventory`,
  independent of `--enable-diagnose`) registers `pilot_diagnose_run`,
  which runs a **caller-supplied** command via ansible's `command` module
  (no shell — pipes/redirects/chaining are not interpreted) against one
  inventory host. Unlike the two tools above, this is **not** a fixed
  allow-list: it can run anything the connecting `ansible_user` (and
  `become`, if configured) is permitted to run, including commands that
  mutate the target. Only enable it when that's genuinely needed.

Both flags default to off. Every `pilot_diagnose_*` call writes a
mandatory JSON audit record under `<audit-dir>/diagnose/` (there is no way
to turn this off while the flag is on), since each call is a real action
against a live host — the sudo check's own commands are exactly what
generates auditd/PAM events on the target.

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
