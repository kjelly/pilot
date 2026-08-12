# Known gotchas (all discovered the hard way)

> Reference for the `pilot-trec-verification` skill.
> Skim once before a first full run; return to it whenever a step behaves
> unexpectedly. Every rule here is also one line in `../SKILL.md`'s rules table.

---

## Scripted-wizard gotchas

### A pre-filled value field appends instead of replacing

**Symptom:** the intended value typed twice, concatenated —
`site-nexussite-nexus` — saved cleanly, cast green throughout. `[live
2026-07-27, round 17: re-run of `01-edit-hosts.drive` against a workspace where
`host_vars/nexus.yml`'s `prometheus_site_label` was already set]`

**Fix:** use `REPLACE_TEXT_AND_ENTER` (sends Ctrl-U first) for every value-set
field — `ansible_host`/`ansible_user`/SSH-key-path, `host_vars`/`group_vars`
value edits. Harmless when the field is genuinely blank, immune when it isn't.
Prefer it over `TEXT_AND_ENTER` by default for anything that isn't a brand-new
item's name (host name, new variable name, new roster user/group name) — those
are the only prompts structurally guaranteed to start blank.

### A sub-editor's save/exit returns to its *immediate parent* menu

Do not assume how many menu levels a single action pops. Two instances in one
script `[live 2026-07-27, round 17]`:

- `host_vars/<host>.yml`'s `💾 存檔並離開` returns to that **host's own item
  menu** (`主機 "<host>" — 選要編輯的項目`), not the top-level host list. A
  script that jumps straight to `EXPECT <host-list text>` times out.
- The roster manager's **Users** screen's `↩ 返回` returns to the roster's own
  `管理 <roster>` submenu (`👤 Users`/`👥 Groups`/`↩ 返回`), not the top-level
  `要編輯什麼？` menu. The sibling **Groups** screen already had the correct
  two-step `EXPECT 管理` / `CHOOSE ↩ 返回` pair.

Both were caught because the script `EXPECT`ed the next screen's own unique text
rather than assuming a step count. When scripting a multi-level menu structure
for the first time, budget at least one extra "return" step per nesting level and
confirm each against the live screen (MCP exploration — see `mcp-mode.md`)
rather than counting levels from memory.

### The vault key-list screen re-renders every already-set value in plaintext

Including keys the current script isn't setting — the value renders whenever the
screen opens, regardless of which key you're there to edit.

**Symptom:** a script declaring `--secret-env` only for the keys it was adding
still leaked `ipa_admin_password` (set by an earlier bootstrap step in the same
workspace) in plaintext. Caught by `trec scan` before the cast was kept.
`[live 2026-07-27, round 17]`

**Fix:** declare `--secret-env`/`--secret-file` for **every** vault key that
already holds a real value in the target workspace, not just the ones this
script sets. Get the full current key list live — a quick MCP peek at the vault
screen, or `grep -oE '^[a-zA-Z_]+:' .vault/main.yaml` for names only, never
values.

### `TOGGLE`/`SELECT`/`CHOOSE docker` on the role checklist is ambiguous

A bare `TOGGLE docker` errors `ambiguous selectable label rows [34 40 42]` —
rows 40 and 42 are `wazuh-manager`/`seaweedfs-s3`, whose own *description* text
contains "docker" (`需先過 docker`). `[live 2026-07-25, round 16, ~21-row
checklist]`

**Fix:** `TOGGLE docker-apply.yml` — the `(docker-apply.yml)` suffix is unique
to that row. Same "unique substring" rule as elsewhere, against a source of
collision that's easy to miss: another row's description prose, not its label or
the static banner.

### A stale `pilot` binary looks exactly like a wizard bug

`$(which pilot)` may be a symlink into the repo and can predate a feature in
source. Rebuild before trusting wizard menu shape.

**One concrete tell:** builds before 2026-07-17 listed the commented YAML
*illustrations* inside group_vars example comments as editable rows (three
`prometheus_site_label` entries; phantom `expr`/`for`/`labels` rows from an
alert-rule example) — "setting" one rewrote a documentation line. Fixed in
`internal/groupvars` (top-level keys only, deduped). If the editor shows
duplicate keys, you're on a stale binary.

### MCP recording lifecycle has two separate finish steps

After a successful save/bootstrap, `pilot edit` intentionally stays alive at its
top menu. For an evidence recording: select `離開`, then poll `terminal_read`
until `running=false` and `exit_code=0`, and only then call `terminal_close` and
`cast_verify`.

Calling `terminal_close` first turns an otherwise successful edit into an
`aborted` cast; omitting both leaves the sidecar `in_progress` with no final
`SESSION_END`. Before ending a task that used MCP mode, call `session_list` to
find any session still needing this sequence.

---

## Live-host and environment gotchas

### Ansible fact-cache poisoning across VM rebuilds

If `ansible.cfg` has `fact_caching = jsonfile` keyed by `inventory_hostname`,
and a preflight/check play runs any module under `connection: local` for that
hostname, the *controller's* discovered Python interpreter gets cached under that
hostname's key. A later real-SSH play for the same hostname then fails with
`The module interpreter '...' was not found` — an error that looks entirely
unrelated to fact caching.

**Fix at the source:** use `delegate_to: localhost` for the local-only task, not
a play-level `connection: local`. And/or clear the specific
`~/.ansible/<cache-dir>/s1_<hostname>` files for hostnames being reused before a
fresh preflight.

### `known_hosts` churn

VM rebuilds at the same IP get a new host key; a stale entry breaks any direct
`ssh`/`sshpass` step with `Host key verification failed`. Expect to
`ssh-keygen -R <ip>` (or pass `-o StrictHostKeyChecking=accept-new`) before the
first real connection each rebuild.

### `ControlMaster`/`ControlPersist` silently masks an auth-layer change

A local multiplexed connection gets reused for a later "fresh" `ssh`/`sshpass`
call to the same `user@host`, so the new invocation never actually
re-authenticates — hiding a password rotation, a forced-password-change state,
or an HBAC/sudo deny behind a stale "it still works".

**Symptom:** an account genuinely in FreeIPA's "must change" state let a second
`sshpass` call straight through with no error. `[live 2026-07-16]`

**Fix:** add `-o ControlMaster=no` (or run `ssh -O exit <user>@<host>` first) to
any live-SSH re-auth check meant to prove a credential/policy state changed.

### Kerberos realm case

`kinit user@<realm>` needs the realm in the case FreeIPA actually configured
(conventionally uppercase). Check `/etc/krb5.conf`'s `default_realm`; don't
assume it matches the lowercase DNS domain string used elsewhere.

### `kinit`'s forced-password-change flow is exactly 3 lines

Old password, new password, new password repeat. A 4-line heredoc produces a
confusing `Password mismatch`/early-EOF failure that looks like a wrong password
rather than an extra line.

### Live credential mutations need fresh authorization each session

Direct SSH / `ipa passwd` / live credential mutations are treated as "Remote
Shell Writes" by this environment's safety classifier, even when the target is a
disposable sandbox VM the same session just built. A prior approval does not
carry over to a new session or rebuild — expect to ask again via
`AskUserQuestion`, scoped to the specific action.

---

## Two misdiagnosis traps

### SSSD sudo on a fresh FreeIPA client: flush the cache, don't edit `services=`

The first `sudo` attempt failing is the known cache-staleness gotcha. The fix is
`sss_cache -E && systemctl restart sssd` on the client, and **only** that.

Do **not** "fix" it by adding `sudo` to `sssd.conf`'s `services=` line.
`freeipa-client-apply.yml`'s C8 task deliberately writes
`services = nss, pam, ssh` because SSSD ≥ 2.3 socket-activates the sudo
responder; listing `sudo` there puts `sssd-sudo.socket` into a permanent
`failed` state (the responder then only survives via monitor mode). The task's
own comment block documents this with the live confirmation.

Two non-evidence traps that caused a live misdiagnosis `[2026-07-17, v8]`:

- `sssd_sudo` being absent from `ps` proves nothing — a socket-activated
  responder only appears after the first sudo lookup.
- If you apply `sss_cache` *and* a config change in the same debugging step, the
  cache flush is almost certainly what fixed it. Change one variable at a time
  before attributing the fix.

### Cross-verify three ways before reporting a "Real bug"

Against a playbook or the wizard:

1. **Read the code** around the alleged bug. An in-code comment saying the
   behavior is deliberate (like C8 above) means your finding is a misdiagnosis
   until you can refute the comment's stated evidence.
2. **Replay the cast** with `trec transcript` and confirm your keystrokes landed
   where your script assumed. The v8 vault incident reported phantom "string
   concatenation in the write path" that the transcript plainly showed never
   happened.
3. **`grep` the on-disk files** your report claims the wizard wrote. The v8
   report's §1.7 "final vault values" did not match the actual saved file.

A proposed fix that survives all three is worth reporting; one that fails any of
them goes back to being a script bug in your own run.
