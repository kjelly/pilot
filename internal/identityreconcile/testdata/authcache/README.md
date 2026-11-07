# Captures of the authorization-cache entry and of the identity observation

Real output, kept as it was printed, for Phase 2 P2-3 of the FreeIPA Go reconcile
(spec `docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md` §9, the
captures K16, K17 and K18). `authcache_test.go` and
`cmd/pilot/cmd/deploy_listhosts_capture_test.go` read them; nothing in them was typed in.

Each capture is up to four files: `<name>.stdout`, `<name>.stderr`, `<name>.rc` (the exit
code) and, for a run of a playbook that is handed a result file, `<name>.result.json`
(what that file held afterwards; empty when nothing was written).

## Where they come from

- Candidate: commit `e5715479e806d59b2879299bcfa04ccf64f56155`, tree
  `68f59c091514ceb7237d6dbbc4ee72959ae2bb15`, in a fresh local clone (`git status` empty;
  the binary reports `vcs.modified=false`). The playbooks and the helper the captures ran
  are unchanged in the later commits of this PR (the commit that adds these files only adds
  tests and documents).
- Run on 2026-11-06 on two disposable `vm-target` VMs: a FreeIPA 4.13.4 server on AlmaLinux 9.8
  and an Ubuntu 24.04 client enrolled in it. Controller: ansible-core 2.19.2.
- `k16-*` (but not `k16-listhosts-*`) and `k17-unwritable-dir`, `k17-dest-*`:
  `pilot vm-target run --name <server> playbooks/apply/freeipa-identity-auth-cache.yml -e target_group=<group> -e '{"pilot_identity_auth_cache_output": "<file>", "pilot_identity_auth_cache_action": "<action>"}' [...]`.
  `stdout` is ansible-playbook's; `stderr` is `vm-target run`'s own header and ansible-playbook's
  warnings. The two `--limit`-naming-no-host captures show vm-target's own syntax-check preflight
  failing (exit 1), which is ansible's error for such a limit.
- `k16-listhosts-*`: `ansible <pattern> -i <inventory> --list-hosts [--limit <host>]`, the command
  `resolvePatternHosts` in `cmd/pilot/cmd/deploy.go` runs.
- `k18-*`: `ansible-playbook -i <inventory> playbooks/apply/freeipa-identity-apply.yml --limit <server>
  -e @<vault> -e freeipa_roster_file=playbooks/test/fixtures/freeipa-identity-v2.roster.yaml
  -e '{"pilot_identity_auth_cache_output": "<file>"}'` against an inventory with the server in
  `freeipa-server` and the client in `freeipa-client`; each `stdout` is the **last 80 lines** of the
  run (the run is about 700 lines; the observation is at the end), and the first run of each
  state started from the journal state the capture's name says.

## What was changed in the text

Only identifiers, and one long string; no line was added, removed or reworded:

- the two VM names are `ipa-1` (server) and `client-1` (client); their addresses are in
  192.0.2.0/24 (documentation range) with the last octet kept;
- local paths are `<repo>/`, `<out>/` (the directory of the result files), `<inventory>`,
  `<transcript>`, `<vault>`;
- in a `fatal:` line of a failing helper task, the helper's own source (the `-c` argument of the
  `cmd` list, about 14 KB) is replaced by `<helper source elided>`.

`TestAuthCacheCapturesHoldNoLabIdentifiersOrSecrets` fails if a lab name, an address outside that
range, a home directory or one of the names of a secret reappears.

## Which capture shows what

| Capture | Shows |
|---|---|
| `k16-probe-absent`, `k16-probe-true`, `k16-probe-false` | the probe's result with the journal absent, owed, settled (`pending` true, true, false); the absent journal is not created |
| `k16-prepare-absent`, `k16-prepare-true`, `k16-prepare-false` | the prepare's `previous` (true, true, false); a prepare of a settled journal owes it again |
| `k16-nohosts-group`, `k16-nohosts-default-group`, `k16-nohosts-limit-outside-group` | no host matched: exit **0**, `skipping: no hosts matched`, an empty recap, nothing written |
| `k16-nohosts-limit` | a `--limit` naming no host at all: exit 1, nothing ran |
| `k16-refuse-*` | the gates: check mode, `--tags`, `--skip-tags`, no action, an unknown action, a relative path, no path, a stage mismatch, two hosts: exit 2, `fatal` with the gate's message, nothing written |
| `k16-fail-*` | the helper fails (another domain, a damaged journal): exit 2, `non-zero return code`, nothing written |
| `k16-listhosts-*` | what `--list-hosts` prints for an empty match without a limit (exit 0, `hosts (0):`), with a limit (exit 1, an error), an unknown limit, one host and two |
| `k17-unwritable-dir`, `k17-dest-missing-dir`, `k17-dest-is-a-directory` | the controller-side copy failing: exit 2 after the helper ran, nothing written |
| `k18-acked-true`, `k18-acked-true-rerun` | the observation of a run that acknowledged (with a refresh of the client; with nothing owed) |
| `k18-refresh-off`, `k18-deferred-client` | `acked` false: the refresh switched off; a client deferred |
| `k18-tags-settle-skipped` | `acked` false and `dirty` null: a tag selection that skipped the settle |
| `k18-earlier-failure` | a task before the observation failed: exit 2, no observation |
| `k18-checkmode`, `k18-no-output-var` | exit 0 and an empty file: skipped by a preview; the run was not given a path |

The effect of `become` on the controller-side copy (K17) is a count of `sudo -H` lines, not a
capture file; it is in `docs/evidence/freeipa-go-reconcile/pr-284.md`.
