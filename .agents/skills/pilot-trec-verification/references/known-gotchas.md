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

**Update `[live 2026-09-24]`:** the key list now shows a set value as
`<已設定>`, and value inputs echo `*`. Only untouched `CHANGE-ME-…` placeholders
still appear in plaintext. Keep the rule above anyway, because the typed input
events are recorded.

The masked marker brings a new trap. trec's secret scan flags
`node_exporter_basic_auth_password = <已設定>` as `inline-secret-assignment`, so
`trec verify`/`cast_verify` fails with `safe_to_share=false` even though no
secret is in the cast. Fix: export a variable holding the marker, for example
`PILOT_MASKED_MARKER='<已設定>'`, and add `--secret-env PILOT_MASKED_MARKER`
alongside the real secrets. `EXPECT`s that mention `<已設定>` still match,
because they read the live screen before redaction.

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

`pilot vm-target`/`docker-target` `up` and `down` (and `topology up/down`) now
drop the cache entries of the target's name and aliases themselves, so a
recreated target never inherits the previous one's facts
(`docs/evidence/vm-target/2026-10-01-198fb03.md`). Clearing by hand is still
needed after `vm-target rollback`/`reset`, for hosts outside those commands,
and for `pilot deploy`'s own cache under `<data-dir>/ansible`.

### `known_hosts` churn

VM rebuilds at the same IP get a new host key; a stale entry breaks any direct
`ssh`/`sshpass` step with `Host key verification failed`. Expect to
`ssh-keygen -R <ip>` (or pass `-o StrictHostKeyChecking=accept-new`) before the
first real connection each rebuild.

### A long `--data-dir` broke `pilot deploy`'s SSH (ControlPath too long) — fixed

Builds before the fix put deploy's SSH ControlPath under the data dir:
`<data-dir>/ansible/ssh-control/pilot-%r@%h:%p`. With a deep `--data-dir`, the
path exceeded the 108-byte Unix socket limit. The full preflight then failed
every host with `UNREACHABLE … ControlPath too long ('…' >= 108 bytes)` and
asked `仍要繼續佈署嗎？`. `[live 2026-09-24, --data-dir under a scratch
directory]`

**Fixed:** the ControlPath is now
`/tmp/pilot-ssh-<uid>-<hash of the data dir>/%C`, at most about 75 bytes
however deep the data dir or long the host name.
`$PILOT_SSH_CONTROL_BASE` replaces `/tmp` if you need to, and must stay
short. `ansible.cfg` uses `%C` as well, each vm-target VM has its own
`/tmp/pilot-vmt-<uid>-<hash>/%C` (set through `ansible_ssh_args`, which wins
over `ansible.cfg` and `ANSIBLE_SSH_ARGS`), and
`internal/spec/ssh_controlpath_regression_test.go` rejects any ControlPath
template that embeds the host. On an older binary, use a short `--data-dir`.

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

### Live sudo denied after the identity reconcile: a defect, not a flush step

**Symptom:** on a FreeIPA client, a live `sudo` or `sudo -n` is denied
(`sudo: a password is required`, or "not allowed"), although
`ipa hbactest --service=sudo` allows it and `ipa sudorule-show` shows the rule,
with `!authenticate` where the check needs it. It was seen in minimal-poc
rounds 13, 23 and 31
(`docs/evidence/minimal-poc-architecture/2026-07-23-round-13.md`,
`2026-08-13-round-23.md`, `2026-09-10-round-31.md`); each passed only after a
client-side `sss_cache -E` (rounds 23 and 31 also `systemctl restart sssd`).

[AGENTS.md](../../../../AGENTS.md) §5.9 point 5: a result that is correct only
after clearing a cache, restarting a service or syncing by hand is a bug
symptom. Issue #214 found and fixed the cause (live on Ubuntu 24.04 / SSSD
2.9.4 and AlmaLinux 9.8 / SSSD 2.9.8): `sss_cache -E` only expires rules a
client already holds. A rule that newly applies to a user or host (a new rule,
a host added to a hostgroup a rule names) reaches the client only through
SSSD's smart refresh (15 min), full refresh (6 h) or start-up; a user added to
a rule the client already caches is delivered by `sss_cache -E` alone. `freeipa-identity-apply.yml` therefore now restarts SSSD on
every enrolled client after an authorization change and waits, 60 s per client,
until `sudoLastFullRefreshTime` in the client's cache is a new value later
than the second the restart finished (the stopping SSSD instance's own write
in the restart's second, or an older marker after a clock step back, does not
count). It fails `Authorization cache refresh PARTIAL` naming the clients that
did not finish; the next identical apply repeats it.

So: run the live sudo checks **after** a reconcile that exited 0. Do not flush
by hand first. If a check is still denied:

1. **Capture the facts before you touch the cache:** the exact command and
   output, root's `sudo -l -U <user> -- <command>` on the client, `ipa
   hbactest` and `ipa sudorule-show`, the client's OS and `sssd --version`, the
   reconcile's exit status, and whether it printed `Report deferred
   authorization cache refresh` (a narrowing `--tags`: run the identical apply,
   or `--tags client-cache`, to deliver it) or `Authorization cache refresh
   PARTIAL`.
2. **Look for an existing issue:** `gh issue list --state all --search sssd`;
   read #95, #114 and #214. Clients enrolled before #214 lack `ldb-tools`, which
   the refresh needs; re-run `freeipa-client-apply.yml` on them.
3. **File or report the bug** per `filing-policy.md`: add your facts to a
   matching open issue or open a new one. If you may not create issues, give the
   user the facts and a draft.
4. **The run that needed the workaround is not passing evidence.** If you flush
   to keep diagnosing, record it in the evidence record as a deviation (what
   failed, what you ran, what passed afterwards) and keep that check's verdict
   failed.

Not covered, and still SSSD behavior rather than a flush step: a revoked SSH key
(#114), a rule changed outside Pilot, a client that is offline from FreeIPA (the
gate reports it PARTIAL), and IPA servers and replicas, which this refresh does
not restart.

Do **not** hand-edit `sssd.conf`'s `services=` line either.
`freeipa-client-apply.yml`'s C8 task sets it per OS family, and its comment
block documents both live confirmations. On Debian/Ubuntu it omits `sudo`,
because SSSD ≥ 2.3 socket-activates the sudo responder and listing `sudo`
breaks `sssd-sudo.socket`. On RedHat it keeps `sudo` as an explicit responder,
because the socket-activated one failed on AlmaLinux 9 (`dfb58a5f`).

Two non-evidence traps that caused a live misdiagnosis `[2026-07-17, v8]`:

- `sssd_sudo` being absent from `ps` proves nothing — a socket-activated
  responder only appears after the first sudo lookup.
- If you apply `sss_cache` *and* a config change in the same debugging step, the
  cache flush is almost certainly what changed the result. Change one variable
  at a time before attributing it.

### Cross-verify three ways before reporting a "Real bug"

Against a playbook or the wizard:

1. **Read the code** around the alleged bug. An in-code comment saying the
   behavior is deliberate (like C8 above) means your finding is a misdiagnosis
   until you can refute the comment's stated evidence.
2. **Replay the affected step** with `trec transcript` and confirm your
   keystrokes landed where your script assumed. Search the transcript for that
   step rather than reading it end to end (AGENTS.md, *Evidence recordings are
   disposable*: summary first). The v8 vault incident reported phantom "string
   concatenation in the write path" that the transcript plainly showed never
   happened.
3. **`grep` the on-disk files** your report claims the wizard wrote. The v8
   report's §1.7 "final vault values" did not match the actual saved file.

A proposed fix that survives all three is worth reporting; one that fails any of
them goes back to being a script bug in your own run.
