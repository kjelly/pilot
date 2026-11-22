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
`--log-level`. Every command resolves the data dir the same way: `--data-dir`,
then `PILOT_DATA_DIR`, then `data_dir` in the config file, then
`~/.local/share/pilot`. `PILOT_LOG_LEVEL` and `PILOT_LOG_FORMAT` configure diagnostics;
target binary overrides are available through `PILOT_SSH_BIN`,
`PILOT_VIRSH_BIN`, `PILOT_DOCKER_BIN`, and `PILOT_PODMAN_BIN`.

Pilot's controller-side Ansible log is stored below the selected data
directory as `ansible/ansible.log`. Pilot redacts common password, secret,
token, API-key, authorization, and private-key forms, restricts log files to
mode `0600`, and rotates the active log after 100 MiB while retaining three
rotated files. Override the limits with `PILOT_ANSIBLE_LOG_MAX_BYTES` and
`PILOT_ANSIBLE_LOG_RETENTION` (set retention to `0` to discard rotated logs).
This is defense in depth; playbooks must still use Ansible `no_log: true` for
secret-bearing tasks.

## Process a batch of pull requests

Run the standalone PR loop in the checkout the agents should work in:

```bash
python3 scripts/pr_loop.py 371 372 --repo kjelly/pilot
```

The agents start in that checkout of yours, not in a clone the runner makes.
`--checkout DIR` names it and defaults to the root of the git work tree that
contains the current directory; `DIR` must be the root of its work tree, not a
subdirectory. The runner refuses to start, with `pr-loop: <reason>` on stderr and
exit status 1, before it reads a pull request or starts an agent (a dry run
reports it after the PR states, below), unless: `origin` has exactly one URL,
and that URL and every push URL name the `--repo` repository; no git operation
is in progress; nothing is uncommitted or untracked and not ignored; HEAD is on a
branch: the default branch that `origin` itself reports
(`git ls-remote --symref origin HEAD`), or another clean branch that the runner
leaves for it (the paragraph after the next); the default branch is at the tip of
`origin`'s or strictly behind it (the next paragraph); and the tip has the two
helpers named below. It also refuses while another runner holds the checkout's
lock (the file `git rev-parse --git-path pilot-pr-loop.lock` names) and while a
live agent pane of an earlier run is still in the checkout (see below).

A checkout that is strictly behind the tip of `origin` is fast-forwarded by the
runner, at startup only (never again while a batch runs, when the merge train
moves `origin`). It fetches exactly the commit `origin` reported, by its SHA, into
`refs/remotes/origin/<branch>` as `git pull` does (no tags, no submodules, no
pruning, no automatic maintenance, no `FETCH_HEAD`), so a push to `origin` a
moment later cannot change what lands; then it runs `git merge --ff-only` of that
SHA, with hooks and automatic maintenance switched off, and prints
`Fast-forwarded <branch> from <L12> to <T12>, origin's tip`. The branch's reflog and
`ORIG_HEAD` name the commit it was at. Before anything reaches the work tree it
checks that the local branch is an ancestor of the tip, that the tip has the two
helpers, that it does not move a submodule, and that it would not overwrite, delete
or write into an ignored path (git does that without a word, also inside an ignored
nested repository). It refuses, and leaves the branch at its old commit and the
work tree as it was, when any of these fails, when the checkout is ahead of the tip,
has diverged from it or has no commit yet, is a partial clone, or when the fetch or
the merge fails (the message then says where git left the checkout). Run
`git pull --ff-only` yourself, or move the branch to the tip, for the refusals that
say so.

A clean checkout on another branch `<x>` is switched to the default branch `<b>`,
at startup only, and is not switched back when the run ends. `<x>` and its commits
are not touched, whether it tracks something or has commits `origin` does not have.
The runner switches only to an existing local `<b>`; if `<b>` is strictly behind the
tip, it is first moved to it by `git fetch . <tip>:refs/heads/<b>` (local, never
forced: git itself checks the fast-forward and refuses a branch that another work
tree holds), and then `git switch --no-guess --no-recurse-submodules
--no-overwrite-ignore -- <b>` makes the one tree update, with hooks and automatic
maintenance switched off. Every check that reads the tip's tree (the two helpers, no
moved submodule between `<x>` and the tip, no ignored path overwritten) runs before
any ref of yours is written. It prints, in this order, `Fast-forwarded <b> from <L12>
to <T12>, origin's tip` when `<b>` moved, and `Switched <path> from <x> (at <X12>) to
<b>; to go back: git -C <path> switch <x>`; the end of the run repeats the way back.
It refuses, with the checkout left on `<x>`, when there is no local `<b>` (it is
never created), when another work tree has `<b>` checked out (also a prunable one),
when another work tree is in the middle of a git operation, when `<b>` is ahead of
the tip or has diverged from it, when HEAD is detached or `<x>` has no commit, and
for the partial clone, submodule, helper and ignored-path cases above. A failed
`git switch` after `<b>` moved leaves the checkout on `<x>` and says that `<b>` was
fast-forwarded.

The runner uses the Python 3 standard library. Install `git`, authenticated
`gh`, `tmux`, and the coding agents, with `claude` and `codex` as defaults.
The target repository's default branch must contain Pilot's PR skills, the
result helper (`.agents/skills/_shared/scripts/pr_loop_result.py`) and the Ready
signal module (`.agents/skills/_shared/scripts/ready_signal.py`); the runner checks
both and refuses a default branch that lacks either. The merge train consumer must
be running.

The runner starts agents automatically in the checkout, which it has verified to
be on the default branch of `origin` at its tip (fast-forwarded to it, when it was
behind). An agent process is reused for its role while the same PR moves between
Draft and Ready. Before every dispatch it checks that the checkout is back on the
branch and commit it started on, clean, with no git operation in progress, and
otherwise stops without dispatching. A gate that reports a blocker, a current-HEAD
`needs-person` hand-off, a Ready PR without a valid signal (below), or a timeout
stops the batch and keeps the agent windows open for inspection. The runner prints
where the task files are when it stops.

The agents run as windows of one tmux session that belongs to the checkout, never
in one of your own sessions. Its name is `pilot-pr-<directory name>-<8 hex>`: the
checkout's directory name with every run of characters other than letters,
digits, `_` and `-` replaced by `-`, leading and trailing `-` removed, cut to at
most 24 characters (`checkout` when nothing is left), then the first 8 hex
digits of the SHA-256 of the checkout's full path. The name is the same on every run in that checkout and
differs between checkouts, also between two with the same directory name. Each
agent has one window, named `<PR>-<phase>` (for example `371-draft`). At the
start the runner prints `Agents run as windows of tmux session <session>; watch
them read-only with: tmux attach -r -t <session>`, and for each agent `PR #N
<phase> agent: %<id> in window <PR>-<phase> of tmux session <session>`; a dry
run prints `would start the agents in tmux session <session>` and calls no tmux.

The first agent creates the session and every later agent adds a window to it.
Agents the runner is done with (those of a merged PR, or one that exited and was
replaced) are closed only after the next agent has been started, and the last
ones when the run ends, so the session lasts for the whole batch. It ends with its
last window, and a client attached to it is then detached (tmux's default). Watch
from another terminal with `tmux attach -r -t <session>`, which is read-only.
Inside tmux that command fails (`sessions should be nested with care`): use
`tmux switch-client -t <session>` or `prefix s` instead. These are not read-only:
what you type in an agent's window reaches the agent, so look and do not type.
Agents run with the environment of the tmux server, except that every agent gets
the runner's own value of each variable that tmux's `update-environment` list
(`tmux show-options -gv update-environment`) names, as tmux matches it: an entry
may be a glob pattern such as `FOO_*`, and `SSH_AUTH_SOCK` and `DISPLAY` are in
the default list. So the agents use the runner's agent socket and not one left by
an earlier run or by the last client to attach. Those values are socket paths and
display names, not secrets, and they appear for a moment in the arguments of the
tmux command: do not add a name that carries a secret, or a pattern that matches
one, to `update-environment`. The session handling was verified on tmux 3.8 only.

Apart from the fast-forward at startup, the runner never deletes, resets, cleans
or stashes anything in the checkout, and it never deletes the task files. It never
kills or renames a window or a session. It adds a window to the session named for
the checkout when that exists, also one an earlier run left, and it closes only
panes it started in this run, one pane at a time (`kill-pane`, so a pane you split
off in an agent's window survives), after checking that each is still that pane on
the same tmux server: pane IDs are only unique within one server, which exits with
its last session, so a later server can give the same ID to another pane. The dead
windows of an earlier run stay where they are. A stop keeps the agent windows open. Close one with `tmux kill-pane -t %N` (`%N` is the
pane ID the runner printed), or the whole session with
`tmux kill-session -t =<session>` when nothing in it still runs; the `=` is
required, because without it tmux may pick another session whose name starts the
same. A live pane in the checkout in any session whose name starts with
`pilot-pr-` refuses the next run with `pr-loop: agent pane %N (session <session>)
is still running in <checkout>; inspect and close it before starting the runner
again`, and so does a window you open in the runner's session with its working
directory in the checkout. Dead panes do not: after a stop that left only dead windows, the next run adds new
windows to the same session. An agent that was interrupted may leave the checkout
with uncommitted work, which the next run refuses until you have put it right, or
on a clean PR branch, which the next run leaves for the default branch (the branch
and its commits stay). Nothing else may use the checkout while the runner runs:
the agents switch it to PR branches, and your own agent sessions in that directory
are not protected by the lock. A second runner on the same checkout refuses. For a
long-lived setup, use a dedicated checkout that you trust once: a second clone,
or a linked worktree when your primary checkout is not on the default branch. The
runner no longer creates or uses the clones under
`$XDG_STATE_HOME/pilot/pr-loop/batch-*` (by default
`~/.local/state/pilot/pr-loop/batch-*`); delete old ones by hand.

Use `--draft-agent` and `--ready-agent` to choose executable paths. The prompts
default to `/pr-ready {pr}` and `$pr-review-merge {pr}`; you can set them with
`--draft-command` and `--ready-command`. Quote them in the shell to preserve the
native skill syntax. Add `--dry-run` to see PR states before starting any agent:
it prints `PR #N: <phase>` for each PR, then inspects the checkout the same way,
read-only (no lock, no write, no tmux), and prints `Checkout: <path> (<branch> at
<sha12>)` and the session name above, or `pr-loop: <reason>` and exit status 1 for
a refused checkout. For a checkout behind `origin` it fetches nothing and writes
nothing, and prints `would fetch origin's <branch> at <T12> and fast-forward
<branch> from <L12> to it`; for a checkout on another branch it prints `Checkout:
<path> (<x> at <X12>)` and `would switch <path> from <x> (at <X12>) to <b>`,
switching nothing; when that commit is already in the checkout it also runs the
checks above on it, and otherwise says that it did not check them (without the
commit a dry run cannot tell that the checkout has diverged from it; the real run
fetches it and says so). It does not check whether another runner holds the lock
or whether a pane from an earlier run is still open, and only a real run notices a
tracked `.gitignore` that overrides the exclude lines below. The phase timeout
defaults to 7200 seconds.

Each dispatch writes `<checkout>/.pr-loop/<nonce>/task.json` and pastes
`--pr-loop-task=<path>` after the prompt; the skill writes `result.json` beside
it. The runner keeps `/.pr-loop/` and `/.pr-ready/` out of `git status`: for a
path that git does not already ignore, it appends the line to the checkout's git
exclude file (found with `git rev-parse --git-path info/exclude`) and prints
`Added ... to <file>`, and it refuses to start when git still does not ignore
them.

Both agents must already trust the checkout: start each of them there once
yourself and answer its trust dialog. The runner stops at a trust dialog only
when its options are numbered; claude's are not, so it takes the selected option
for the input prompt, pastes its command and presses Enter in the same second,
and nobody can answer in time. In a directory an agent does not trust, `claude`
exits at once (its default answer is "No, exit") and the runner stops with an
`agent exited` message that does not mention trust; `codex` loses the command,
may record the directory as trusted, and the runner then waits silently until
`--phase-timeout` (7200 seconds by default).

The runner dispatches the Ready phase only for a PR that carries a valid Ready
signal at its current HEAD: the label `pr-ready-verified` and a comment that starts with
the producer's heading and ends with a marker line for that HEAD and for the PR's latest Ready transition, which `pr-ready` (or issue-to-pr's `mark_ready.py`)
writes after it verified the Draft and made it Ready. The signal counts only when
the account `gh` runs as wrote it, so the runner and the skills must run as the
same GitHub account, and the label must exist in the repository (a one-time
maintainer action; nothing here creates labels). A Ready PR without a valid
signal is `unverified`, for example because it was made Ready by hand or by a
script that skipped the gate, was created Ready, was pushed to after it was
signed, went through Draft and Ready again after it was signed, or was signed by
another account. The runner reads
the phase twice like any other, dispatches nothing for it, writes nothing to
GitHub and stops with `PR #N is Ready without a valid pr-ready-verified signal at
HEAD <h12>: <reason>; ...`; `--dry-run` prints `PR #N: unverified (<reason>)`.
Unlike the `pr-review-merge` actor, the runner does not carry a signal across any
change, a base import or an evidence-only commit included. While the Draft agent
is still working, a Ready PR that is not signed yet counts as the Draft phase,
because the gate marks the PR Ready before it verifies and signs it: a blocker
it reports afterwards stops the run instead of sending the Ready agent in. A
signal that never becomes valid (for example one written by another account)
ends that phase with `timed out in draft (Ready
without a valid pr-ready-verified signal: <reason>)`. To have an unverified PR processed, convert it to
Draft and run pr-ready on it, then start the runner again (a person can also sign
it by hand, see the "Ready signal" section of
[`.agents/skills/pr-ready/README.md`](.agents/skills/pr-ready/README.md)).

The runner acts on a state only after reading it twice in a row, and retries a
failed GitHub read twice before it stops, so one lagging or failing read neither
dispatches an agent nor ends the run. An agent that is still working when
GitHub shows the next phase is given the phase timeout to return to its prompt;
a PR can therefore take up to about twice `--phase-timeout` in one phase. Every
exhausted wait stops the runner without sending a command and keeps the
agent windows open. The runner reads the finished agent's result before it
moves on, and stops on a blocker even when GitHub already shows the next phase.

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
| `pilot deploy` | Guided deployment: choose inventory, component(s), stage, preview, and confirmation. It preserves the same stage gates as manual deployment. Without a terminal (CI, cron), `--force` takes every default and applies once the `--check --diff` preview passes; `--preview-only` takes the same defaults but stops after the preview and exits 0 only if it passed. The default stage is `sandbox`; `--stage staging` or `--stage prod --staging-attested-within-hours <0-168>` selects another stage and counts as its confirmation. `--limit <hosts>` answers the limit prompt (comma-separated hosts or an Ansible pattern), so a non-interactive run can target only some hosts; the others stay in the inventory but no play runs on them. |
| `pilot reconcile` | Guided day-2 reconcile: choose a contract-backed declarative configuration component, its roster/config source, stage, preview, and confirmation. Only catalog entries explicitly marked as reconcilers appear; a future Nginx config reconciler must first supply its contract, apply playbook, schema, and verification evidence. Without a terminal, `--component <key>` (repeatable) picks the components and `--force` or `--preview-only` takes every default; `--preview-only` previews every playbook in the plan, dependencies included, and applies none; it exits 0 only if every playbook actually previewed. A playbook whose targets were all deferred as unreachable optional hosts counts as not previewed, and deferred hosts of a previewed playbook are listed. `--stage` and `--limit` work as for `deploy`. |
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

For `pilot_edit_inspect`, `include_group_vars: true` returns
`group_vars[filename][key]` strings plus `group_vars_metadata` with `present`,
`is_set`, `source`, `redacted`, and a redaction `reason`. Known secret inputs
and unknown keys return `[REDACTED]`. Only scalar values declared public in
the component contracts are disclosed; collections, aliases, embedded
configuration, and values with invalid types are conservatively redacted.
URL userinfo is also redacted in public strings, including backend-prefixed
repository URLs such as `rest:https://user:password@host/repo/`, with reason
`uri_credentials`. URLs without userinfo retain their public scalar value.
Any secret declaration wins when contracts share an input. If the contract
catalog (`PILOT_ROOT`, otherwise the server's working directory) cannot be
loaded, all values are redacted. Invalid YAML is reported only as
`group_vars_status[filename]: invalid_yaml`, without parser diagnostics.
Optional `group_vars_component` (exact contract ID), `group_vars_file`
(exact filename, including extension), and `group_vars_key` (exact top-level
key) filters combine using AND and never bypass redaction. For example,
`{"include_group_vars":true,"group_vars_component":"dns","group_vars_file":"dns.yml"}`
limits the returned group vars to DNS inputs in that file.

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

- `--enable-diagnose` (requires `--diagnose-inventory`) registers seven
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
    query. `pilot_diagnose_logs` excludes ansible/pilot's own noise by
    default (see below); pass `include_ansible_noise: true` to see it.
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
  - `pilot_diagnose_login` — a one-call composite for "why can't these
    users log in / sudo on this host", built from the same allow-listed
    steps the tools above already use rather than any new mechanism: sssd
    status, sssd domain backend online/offline, Kerberos machine identity,
    and this host's own DNS self-resolution, plus per-user NSS passwd
    resolution and a live central sudo rule check (`sudo -l -U <user>`)
    for each entry in `users`. It also reads the workspace's FreeIPA
    roster (a local config-file read, not an ad-hoc step) to report each
    user's declared HBAC/sudo authorization on this host and flags any
    drift against what was just observed live — e.g. the roster declares
    a sudo rule that hasn't reconciled onto this host yet, or a live rule
    the roster no longer declares. It also best-effort queries recent
    SSH/PAM login records for these users over the last `lookback` (a Go
    duration, default `24h`) the same way `pilot_diagnose_security_logs`
    does; a workspace with no `dashboard` role deployed gets a
    `skipped_reason` there instead of failing the whole call. This exists
    to replace the usual manual sequence of `pilot_diagnose_sudo`/`dns`/
    `security_logs` plus a separate roster lookup — a real investigation
    that took 17 separate tool calls to assemble by hand collapses to one.
  - `pilot_diagnose_detection` — engine status, the active SignalEvent
    episode list, and a bounded (`-n 200`) journal tail from the central
    Detection Engine host (auto-resolved singleton `detection-engine`
    group, no `host` argument), plus that one episode's detail when
    `signal_id` (a 26-character ULID) is supplied. At least one of
    `signal_id` or `pilot_host` is required; `pilot_host` is not a command
    parameter (the engine CLI has no per-host filter) — it's recorded for
    audit/correlation against the returned signals list's own `pilot_host`
    fields. See
    `docs/superpowers/specs/2026-08-28-detection-engine-spec.md` §46.
  - `pilot_diagnose_dns_architecture` — one read-only call for "how is DNS
    wired here": the `dns` caching tier, the FreeIPA DNS providers
    (primary/replica, canonical FQDN, zones), FreeIPA forwarding (global
    forwarders, forward policy, per-server forwarders, forward zones) and
    each managed host's resolver path. It keeps four layers apart —
    supported (component contracts), declared (inventory variables),
    effective (what the playbooks' own rules compute; a regression test
    runs those playbook tasks and fails if the tool's copy drifts) and
    observed (bounded live probes) — and lists every declared/live
    difference with evidence references, with `unknown` and `absent` kept
    separate. External resolution through the tier is never reported as
    proof that a particular forwarder answered. FreeIPA's DNS
    configuration is read only with a read-only principal the operator
    approves when starting the server (`--diagnose-freeipa-principal`,
    `--diagnose-freeipa-keytab`; `admin` is refused), in a private
    credential cache; without one the call returns `auth_required` and
    still reports everything else. Setup:
    `docs/runbooks/dns-architecture-diagnose.md`.
  - Both `pilot_diagnose_logs` and `pilot_diagnose_security_logs`
    **exclude pilot's own ansible-generated log noise by default** —
    ansible's `BECOME-SUCCESS-` become/sudo marker, and any line
    mentioning one of this inventory's configured `ansible_user` service
    accounts — since every diagnose/deploy/reconcile ad-hoc or playbook
    run against a host otherwise pollutes that same host's own logs (e.g.
    a `pilot_diagnose_sudo` call against a host would show up as a fresh
    "login" in a later "who logged into that host" query). Set
    `include_ansible_noise: true` to see it anyway (useful for auditing
    pilot's own activity specifically). This is a best-effort content
    filter, not a precise scope — see
    `internal/diagnose.ExcludeAnsibleNoise`.
- Diagnostic MCP results preserve `stdout`, `stderr` and Ansible `message`
  separately. A nonzero remote command is diagnostic data (`isError: false`),
  with its actual `rc`, `rc_known`, `failed`, `unreachable` and `outcome`.
  Ansible wrapper/module failures and requested-executable launch errors keep
  the requested-command `rc_known: false` and `outcome: unknown`.
  `module_stdout`/`module_stderr` preserve launcher diagnostics separately from
  command streams; `module_failed` and `command_start_failed` identify those
  execution failures. `launcher_rc` with `launcher_rc_known` is Ansible's
  execution-layer status (wrapper exit status or spawn errno), never the
  requested command's exit code. These streams use the same redaction,
  size limits and flags as command output.
  `outcome` distinguishes `completed`, `command_nonzero`, `auth_required`,
  `unreachable` and `unknown`; runner/decoder failures are `unknown`, retain
  any decoded facts and include `error`. An unknown or absent RC must never
  be interpreted as successful execution. Missing approved Kerberos credentials
  leave authenticated facts `auth_required` while retaining other observations.
  Every diagnostic response string, including nested reports, query payloads
  and errors, passes the common structured-secret filter and a 65,536-byte
  per-string limit; `redacted`/`truncated` flags identify filtered evidence.
  Command stream whitespace is preserved. These filters recognize common
  secret assignments and flags; operators must still avoid commands that print
  unlabelled credentials. Invalid input, pre-execution failures and internal
  tool failures use `isError: true` with a JSON error in `content`, without a
  zero-valued structured result. Successful tool calls provide structured data
  and its JSON text fallback in `content`.
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

### Remote MCP access with `pilot-mcp`

`pilot-mcp` (Linux and macOS, `go build -o <bin-dir>/pilot-mcp ./cmd/pilot-mcp`)
lets a coding agent use the MCP server above on a deploy node. It fetches the
configuration from GitHub with the user's own Git credentials, runs one
`docker run <repo>:<tag> pilot mcp remote session …` on the deploy node over
SSH, sends the snapshot, then relays MCP over stdio. Secrets stay in the
deploy node's `.vault`, mounted read-only; sessions are `observe` or `edit`,
never raw, active or repair. Spec:
`docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md`; setup and
troubleshooting: `docs/runbooks/mcp-remote-access.md`.

| Command | Appropriate use |
|---|---|
| `pilot-mcp connect --profile <name> [--image <repo>:<tag>]` | Run by the coding agent as its MCP server command. |
| `pilot-mcp doctor --profile <name>` | Check the profile, Git, SSH, the image and an MCP handshake. |
| `pilot-mcp changes --profile <name> --into <clone>` | Write an ended edit session's changes into a clean clone for review; it never commits or pushes. |
| `pilot mcp remote …` | Runs inside the container; started by `pilot-mcp`, not by hand. |

Profiles live in `~/.config/pilot-mcp/profiles.yaml` (mode `600`), one per
environment and mode:

```yaml
version: 1
profiles:
  <profile>:
    source: {url: "https://github.com/<org>/<config-repo>", ref: main, subdir: "<env dir>"}
    target: {ssh_host: "<ssh-alias>", env: prod, env_root: "<env-root>", image: "<repo>:<tag>"}
    mode: observe
```

Add it to an agent:

```bash
claude mcp add --transport stdio --scope user <name> -- <bin-dir>/pilot-mcp connect --profile <profile> --image <repo>:<tag>
codex mcp add <name> -- <bin-dir>/pilot-mcp connect --profile <profile> --image <repo>:<tag>
```

For Codex, also set `startup_timeout_sec = 90` under `[mcp_servers.<name>]` in
`~/.codex/config.toml`.

### Spec and verification

| Command | Appropriate use |
|---|---|
| `pilot spec <spec.md> --lint` | Parse and lint a verification spec before implementing or testing its apply playbook. |
| `pilot spec <spec.md> --generate <path>` | Produce a diagnostic generated playbook. It is for parser/generator work only, never the source of a production apply playbook. |
| `pilot spec <spec.md> --status` | Show compiled/applied/verified coverage for a spec. |
| `pilot spec status <spec.md>` | Equivalent status subcommand, useful for scripts and explicit command discovery. |
| `pilot verify <spec.md>` | Run every row of one spec locally by default, or use `--inventory` and `--limit` for remote/fleet verification. It writes NDJSON and Markdown reports and updates checkpoints. |
| `pilot verify --dir <directory>` | Verify every Markdown spec in a directory and print a roll-up. There is no default directory: without a spec.md, `--dir` is required. |
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
