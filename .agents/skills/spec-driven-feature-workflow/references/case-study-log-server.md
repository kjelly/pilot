# Case study — log-server + audit-log-forwarding (2026-07-06)

The worked example `spec-driven-feature-workflow`'s `SKILL.md` was
extracted from. Request: "add setuid/setgid + sudo + config-file auditd
monitoring on hosts, forwarding to a central log server — but evaluate and
build the log server first."

## Step 1 — evaluation

Candidates considered: rsyslog central receiver, syslog-ng, Loki +
Promtail/Alloy + Grafana.

- The requirement had already fixed the client's transport (`rsyslog`
  forwarding `auth,authpriv.*` + `local6.*` via `@@host:port`, classic
  syslog protocol). That single constraint eliminated Loki as a *direct*
  receiver — Loki has no native syslog listener; it needs an agent
  (Promtail/Alloy) in front translating syslog into Loki's HTTP push API,
  which is an extra hop and an extra service just to accept what the
  client already speaks natively.
- rsyslog-on-both-ends means zero protocol/format translation risk, ships
  by default on every base image already in use in this repo (Ubuntu +
  EL), and fits the existing "one VM, one systemd service, ansible-managed
  files" shape used by every other single-purpose spec (`seaweedfs-s3`,
  `freeipa-server`) — no new multi-container stack for a need that's
  actually just "receive, retain, prove receipt."
- Recommendation: rsyslog now; Promtail→Loki can sit on top of the same
  landing directory later if dashboards/LogQL become a real need, without
  touching the client side at all.

This was delivered as a short recommendation with the main tradeoff, not
an essay, and implementation didn't start until the user confirmed.

## Step 5 — four real bugs, none guessable from the YAML

### Bug 1 — landing directory owned by the wrong user

`/var/log/siem` was created `root:root 0755`. `rsyslogd` on Ubuntu runs as
the unprivileged `syslog` user (confirmed via `ps -o user,cmd -C
rsyslogd`), which had no write permission to create the
`createDirs="on"` per-hostname subdirectory — `journalctl -u rsyslog`
showed `Permission denied`. Fix: the directory owner became a
per-`ansible_os_family` variable (`syslog` on Debian, `root` on RHEL/EL,
since EL's rsyslog traditionally runs privileged with no dedicated
`syslog` account).

### Bug 2 — `state: restarted` broke the idempotency gate

`pilot vm-target test`'s L6 idempotency check (AGENTS.md §1.4) failed:
`changed=1` on the second apply, because `ansible.builtin.systemd: state:
restarted` performs a real restart *every* run regardless of whether
anything changed — it is not an idempotent operation by construction.
Fix: split into `state: started` (idempotent) plus a second task gated on
`when: <config_render_task> is changed`.

### Bug 3 — audit rule ordering silently shadowed the specific rule

C11 ("a real sudo invocation produces a matching audit event") kept
failing even after the rules loaded correctly and `/usr/bin/sudo`
executions clearly appeared in `/var/log/audit/audit.log` — but always
tagged `key="setuid_setgid_exec"`, never the dedicated
`key="privileged-sudo"`.

Root cause: the kernel's audit `-a always,exit` filterlist evaluates rules
top-to-bottom and **stops at the first match**, like iptables — it does
not evaluate every rule and merge results. `/usr/bin/sudo` is itself a
setuid-root binary, so its execve syscall always satisfies the broader
`-C uid!=euid -F euid=0` condition; since that generic rule was listed
*before* the specific `-w /usr/bin/sudo -p x -k privileged-sudo` watch,
every sudo invocation short-circuited on the generic rule and the specific
one never got evaluated.

Fix: reorder `audit.rules.j2` so specific rules (sudo watch,
`/etc/passwd`, `/etc/sudoers`) come *before* the generic setuid/setgid
execve rules. The generic rules still catch every other setuid/setgid
binary — they just no longer intercept the one path a more specific rule
already claims. Verified with:

```bash
sudo grep -o 'key="[a-z_-]*"' /var/log/audit/audit.log | sort | uniq -c
#   19 key="privileged-sudo"
#   41 key="setuid_setgid_change"
#   45 key="setuid_setgid_exec"
```

This generalizes beyond auditd: any time you write multiple rules whose
match ranges overlap (a broad rule and a narrower subset of it), the
narrower rule must be listed first in any system with first-match-wins
semantics, or it is dead code.

### Bug 4 — `ausearch` couldn't find data that was genuinely in the log

C11's original design used `sudo ausearch -k privileged-sudo -ts recent`.
Even after fixing bug 3, `ausearch` returned `<no matches>` for every
`-ts` window tried, while `grep key="privileged-sudo"
/var/log/audit/audit.log` found the records immediately. Root cause: this
Ubuntu 24.04 audit build emits enriched (human-readable) fields
immediately adjacent to the raw `key="..."` field with **no separating
space** (`key="privileged-sudo"ARCH=x86_64...`), which breaks `ausearch`'s
own record parser even though the underlying data is well-formed. Fix:
drop `ausearch` entirely for this check and grep the raw log directly —
one fewer tool whose internal parsing behavior you depend on, and a more
direct assertion of "the record is actually in the log."

### Bug 5 — the verify tool's own matcher had a blind spot, found only by testing the negative path

After the initial four bugs shipped, `siem_forward_host` was made optional
(v1.1: local auditd monitoring shouldn't hard-depend on a log server
existing yet). Testing that change meant running `verify` for the first
time in a state where forwarding was genuinely absent — every prior apply
had a log server up before verifying, so this was the first real negative
case this spec had ever exercised.

C15 (`/etc/hosts` should have the `siem-log-server` alias) reported
**pass** even though `getent hosts siem-log-server` on the box itself
returned rc=2. Root cause, traced with `pilot verify --probe`: `pilot
vm-target verify` runs each row via `ansible <host> -m shell -a '<cmd>'
--one-line`, and ansible wraps the real output as `<host> | CHANGED | rc=0
| (stdout) <text>` (sometimes behind `[WARNING]`/`[DEPRECATION WARNING]`
lines). `internal/tools/verify_spec.go`'s `extractRC()` only recognized
bare-integer stdout (the shape you get from `--local` runs) — it had no
code path for ansible's ad-hoc wrapper format at all, so it always fell
back to comparing the *ansible process's own exit code*. For the
`cmd; echo $?` / `cmd && echo 0 || echo 1` idiom this repo's own spec
template recommends (specifically to dodge trap 1), the last command
executed is always `echo`, which always succeeds — so that fallback
comparison against expected `0` was **always true, regardless of the
real remote state**. Every numeric-expected row using that idiom, verified
via any inventory/ad-hoc `pilot verify` call, was structurally incapable
of failing.

This wasn't limited to the new spec: `log-server.md`'s C6/C7 use the same
idiom and had never been genuinely checked either — their earlier "PASS"
evidence was coincidentally correct (real state happened to match
expected), not actually verified.

Fixed in `internal/tools/verify_spec.go` by adding `unwrapAdhocOneline()`,
which scans backward from the last line for the `| rc=N` marker and
extracts the text between `(stdout)` and an optional trailing `(stderr)`
segment (ansible appends stderr right after stdout on the same line with
no separator when a command writes both — e.g. `grep` on a missing file).
`extractRC()`/`stripRunnerPrefix()` now unwrap before checking for a bare
integer. Verified against both a real captured getent failure and a real
captured grep-with-stderr line; locked in
`internal/tools/verify_spec_match_test.go`. Fixing this also surfaced a
genuine, previously-masked C14 failure (a `logrotate -d` "insecure
permissions" error that's a real Ubuntu 24.04 characteristic, fixed with a
`su root syslog` directive) — proof the fix wasn't just theoretical.

**Generalizable lesson**: a check that has only ever run against a
true-positive state can't tell you whether it's a real check or a
structurally-broken one that happens to agree with reality. When you add
an optional/conditional branch to existing behavior, actually exercise the
"off" state as a real apply+verify cycle — that's often the first time a
spec's negative path gets exercised at all, and exactly when latent
matcher/tooling bugs like this one surface. The observable signal for
"was this PASS ever really checked" ended up being visible in the NDJSON
itself: `"rc-from-stdout=N matches..."` (matcher actually parsed the
value) vs. `"rc=N matches..."` (fell back to the process exit code) — see
`docs/runbooks/audit-log-forwarding.md` §5.3 for the full before/after
evidence.

## Step 6 — what made it into the runbook

Every one of the four bugs above got its own subsection in
`docs/runbooks/log-server.md` §5 / `docs/runbooks/audit-log-forwarding.md`
§5: symptom as observed (the actual error text), root cause, fix, and (for
bug 3) the verification command proving the fix. The regression tests
(`log_server_regression_test.go`, `audit_log_forwarding_regression_test.go`)
each lock at least one of these lessons structurally — e.g. the rule-order
check reads `audit.rules.j2` directly and fails if the sudo watch ever
regresses to after the generic rules.
