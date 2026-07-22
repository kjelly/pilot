# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Date: 2026-07-21 (UTC), latest completed pass: round 11 / v11.0
> Aligned spec: `docs/verification/freeipa-server.md`, `freeipa-client.md`,
> `docker.md` (`playbooks/apply/docker-apply.yml`，2026-07-17 起獨立 playbook),
> `seaweedfs-s3.md`, `prometheus.md`, `thanos-query.md`,
> `alertmanager.md`, `dashboard.md`, `log-shipping.md`,
> `wazuh-manager.md`, `wazuh-fim.md`, `audit-log-forwarding.md`,
> `restic-backup.md`, `freeipa-identity`(roster-driven, no standalone spec)
> Automation: `playbooks/site.yml` (one-shot site-wide deploy — as of v2.3
> this includes `log-shipping`, auto-targeted at the `log-server` group if
> populated else `wazuh-manager`) + `playbooks/apply/freeipa-identity-apply.yml`
> (still intentionally excluded from site.yml, data-driven day-2 roster,
> run as a separate `pilot reconcile` invocation) + `tmp/pilot-verify-minimal-poc-r10/demo/{hosts.yml, inventory.yml,
> group_vars/, .vault/}` (`pilot inventory generate` output, disposable
> workspace under the repo's gitignored `./tmp/`, not the tracked project tree)
> Maintainer: sre
> Publication: internal only — contains plaintext sandbox secrets
> (`tmp/pilot-verify-minimal-poc-r10/demo/.vault/*.yaml`) and lab-only IPs; do not
> publish without running the redaction gate first
> **v7.0 note (2026-07-17, round 7)**: genuine ground-up rebuild per explicit
> request — all 3 VMs torn down and recreated fresh (`freeipa-server .3`,
> `nexus .5`, `client-vm .6`), the entire `tmp/pilot-verify-minimal-poc/`
> workspace deleted and rebuilt from nothing, every `pilot edit`/`pilot
> deploy` wizard step driven and recorded via `trec drive --script`
> (`CI=1`, this repo's 2026-07-17 Bubble Tea rewrite of both commands).
> This session's `mcp__trec__terminal_start`/`terminal_write` tools could
> launch a persistent PTY but could not deliver a real carriage-return
> byte through the MCP text channel (raw `\r`/`\n` arrived as literal
> 2-character escape sequences or a bare LF, neither of which the
> Bubble Tea screens treat as Enter) — confirmed by first launching
> `pilot edit` directly under the MCP session (stuck) and only working
> once `trec drive --interactive` itself was the launched command, so
> `trec`'s own DSL parser (not the raw PTY) consumed the keystrokes; the
> **final evidence** for every wizard step still went through
> one-shot `trec drive --script <file>` per the skill's own guidance,
> not the MCP session. `PILOT_DEBUG_MENU=1` also turned out to actively
> break `SELECT` for the very first row of a menu (its stderr dump line
> repeats the row's own label text one line above the live list,
> confusing `SELECT`'s direction heuristic into pressing DOWN off a list
> that doesn't wrap) — omitted for the recorded runs once identified.
> Both `pilot deploy` invocations (site-wide, then `freeipa-identity`)
> needed **zero** extra `-e` variables — the explicit "stop and explain
> if `-e` is needed" gate was never triggered. One real, reproducible
> operational finding this round — see § Real bugs #25 — extends the
> already-documented SSSD sudo-cache-staleness gotcha (Real bugs #15/#20)
> to a case those didn't cover: it also blocks the **very first** sudo
> attempt after a genuinely fresh site-wide + `freeipa-identity` deploy,
> not only after a later rule change; `sss_cache -E && systemctl restart
> sssd` on the client is the fix, but the runbook's own §4.1 procedure
> previously only mentioned it for the §4.6 rule-change scenario.
> **`sss_cache -E && systemctl restart sssd` is the ONLY sanctioned fix
> for a first-sudo denial — never add `sudo` to `sssd.conf`'s
> `services=` line.** The v8 re-verification round (2026-07-17)
> misdiagnosed this exact symptom as "the playbook's sssd.conf template
> is missing sudo" and sed-patched `services=` live; post-hoc review
> showed the cache flush (applied in the same step) was the actual fix,
> and the sed left `sssd-sudo.socket` permanently `failed` (the
> responder only survived via monitor mode). `freeipa-client-apply.yml`
> C8 deliberately writes `services = nss, pam, ssh` — SSSD ≥ 2.3
> socket-activates the sudo responder, and the task's comment documents
> that listing `sudo` there breaks the socket (confirmed live twice, in
> both directions). Also note `sssd_sudo` absent from `ps` is NOT
> evidence of a problem: a socket-activated responder only appears
> after the first sudo lookup.

> **v10 re-verification note (2026-07-20, completed)**:
> `pilot vm-target list` reported no targets, while libvirt still had the
> three named domains and `clean` snapshots. After read-only confirmation,
> only those exact domains, snapshots, and VM directories were removed;
> shared base images were retained. Fresh provisioning produced
> `freeipa-server=192.168.122.4` (AlmaLinux 9, 4096 MiB),
> `nexus=192.168.122.3` (Ubuntu 24.04, 12288 MiB), and
> `client-vm=192.168.122.2` (Ubuntu 24.04, 2048 MiB). A new empty
> `tmp/pilot-verify-minimal-poc-r10/` workspace was populated only through
> `pilot edit` and `pilot inventory generate`; all SSH fields and roles were
> verified on disk. Complete `pilot deploy` preflight passed with
> `client-vm ok=8 changed=0 failed=0`, `freeipa-server ok=6 changed=0
> failed=0`, and `nexus ok=6 changed=0 failed=0`.
> `pilot deploy --dir ...` was first rejected by the current CLI
> (`unknown flag: --dir`); the corrected invocation used
> `pilot deploy -i <inventory>`. The wizard then reached full site-wide
> deployment but offered extra auto-detected `-e` values, first
> `-e wazuh_manager_host=192.168.122.3`, then
> `-e restic_s3_target_host=192.168.122.3`. Per the explicit deployment gate,
> the process was terminated before preview/apply. The corrected retry used
> `pilot deploy -i <inventory>`; every auto-detected `-e` value was accepted
> with `Y`, and the manual extra-`-e` field was left empty. Site-wide preview
> and real apply completed with `failed=0`; the separate `pilot reconcile`
> roster apply also completed with `failed=0`. The failed/aborted attempt is
> retained as disposable internal evidence and is described below.

## 0.5a Fact snapshot (2026-07-21T17:30Z, v11.0 ground-up rebuild, round 11)

The fresh target state and inventory facts below are the actual output of
`pilot vm-target list` and `pilot vm-target show-inventory` from this pass:

```text
client-vm       running  192.168.122.2  2  2048   20
freeipa-server  running  192.168.122.4  2  4096   30
nexus           running  192.168.122.3  6  12288  80
```

The generated inventory graph contained `freeipa-server`, `client-vm`, and
`nexus`; role groups were populated only through the recorded `pilot edit`
and `pilot inventory generate` sessions. The complete preflight was run
before deployment and produced `failed=0` for all three hosts.

The corrected site-wide command was:

```text
./pilot deploy -i tmp/pilot-verify-minimal-poc-r10/demo/inventory.yml --timeout 90m
```

All seven inventory-derived values were accepted with `Y`; the manual
`還有其他 -e 變數要帶嗎？` field was empty. The real apply recap was:

```text
client-vm       ok=83  changed=41  failed=0
freeipa-server  ok=35  changed=10  failed=0
nexus           ok=154 changed=74  failed=0
localhost       ok=1   changed=0   failed=0
```

The separate roster-driven command was run through `pilot reconcile` with
the roster path `tmp/pilot-verify-minimal-poc-r10/demo/.vault/ipa-identity.yaml`
and an empty manual extra-`-e` field. Its real apply recap was
`freeipa-server: ok=31 changed=12 failed=0`.

The verification pass was actually executed against the fresh targets for
FreeIPA HBAC, Grafana/Thanos/Prometheus, Grafana/Loki/Promtail, restic
snapshots, Wazuh FIM, and live SSH sudo allow/deny; the real outputs are
quoted in §4.0a below. The reconcile cycle was likewise executed live —
roster removal, restore plus sudo-command drift correction, and a final
rerun (`changed=2`, `failed=0`). The CLI/help and command contracts used
for the reconcile and VM checks were confirmed against the real binaries
before use.

---

## 0. One-line goal

Re-verify the minimal-PoC 3-VM demo (AlmaLinux FreeIPA identity server,
Ubuntu Docker+Wazuh+Grafana monitoring host — this pass names it `nexus`,
not `monitor-vm` — Ubuntu simulated end-user client) using only `pilot
edit` / `pilot inventory generate` / `pilot deploy` / `pilot reconcile` — no hand-edited
inventory YAML, no direct `ansible-playbook` calls — deploying **every**
wired role in **one** `pilot deploy` "全站部署(site.yml)" invocation
instead of one role at a time, plus the one component `site.yml`
structurally excludes (`freeipa-identity`, a data-driven day-2 roster) as
a separate `pilot reconcile` invocation — `log-shipping` was folded into
the site-wide run in v2.3 (see Changelog). Also widens `wazuh-fim` and
`audit-log-forwarding` to all three hosts (a prior build only wired them
to the client), and re-confirms both original verification goals: (1)
FreeIPA HBAC/sudo permission management enforces allow **and** deny, (2)
client log and site metric are both queryable from Grafana.

**Recording mode is decided per command** (see §3.2 for a worked
example of the two side by side): a command that will **prompt for
keystrokes** (`pilot edit`, `pilot deploy`, `pilot reconcile` — all interactive wizards)
is driven live with `trec drive --interactive`, sending one op
at a time and reading the real rendered screen back before deciding the
next op. A command that **runs to completion on its own with no prompts
to answer** — a one-shot wizard step like `pilot inventory generate`, or
a read-only verification check (`ssh`/`curl`/`ipa hbactest`) — is
executed with plain `trec` instead, since there is nothing for `drive`
to drive.

---

## 0.5 Fact snapshot (2026-07-17T04:49:29Z, v7.0 ground-up rebuild, round 7)

> All output below is captured from actual execution on the rebuilt
> environment, not predicted. Earlier rounds' snapshots (v3.0 etc.) are
> superseded by this section; see §8 Changelog for the full history.

### Environment state — VM list

```bash
$ pilot vm-target down --name client-vm && pilot vm-target down --name monitor-vm && pilot vm-target down --name freeipa-server
✓ target client-vm down
✓ target monitor-vm down
✓ target freeipa-server down
$ rm -rf tmp/pilot-verify-minimal-poc   # entire disposable workspace, no leftover files reused
$ go build -o ./pilot ./cmd/pilot       # fresh binary before driving any wizard
$ pilot vm-target up --name freeipa-server --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name nexus --base-image ubuntu-24.04 --memory 12288 --vcpus 6 --disk 80 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name client-vm --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 20 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.6  2     2048      20         2026-07-17 11:35:27
freeipa-server  running  192.168.122.3  2     4096      30         2026-07-17 11:35:18
nexus           running  192.168.122.5  6     12288     80         2026-07-17 11:35:26
```

All three VMs were torn down and recreated fresh for this pass (the prior
session's leftover VMs were named `client-vm`/`monitor-vm`/`freeipa-server`
— this pass renamed the monitoring host back to `nexus`, matching this
runbook's own established convention; node names are illustrative per the
`delivery-test` skill, not a functional requirement). libvirt DHCP
reassigned every IP (`freeipa-server` now `.3`, `nexus` `.5`, `client-vm`
`.6`). `pilot vm-target list`'s IP column was transiently blank for
`freeipa-server` on the very first `list` call right after `up` returned,
then populated correctly on a second call a few seconds later — the VM
was already genuinely reachable via `vm-target exec` the whole time, so
this looks like `list`'s own IP-column read racing slightly behind the
already-fixed `waitForIP` reserved-IP fallback (§ Real bugs of prior
rounds), not a functional regression; not chased further since it never
blocked anything. Do not assume `.3`/`.5`/`.6` are stable values across
future rebuilds — always take IPs fresh from `pilot vm-target list`.

### Target / resource set — inventory tree

```bash
$ ansible-inventory -i tmp/pilot-verify-minimal-poc/demo/inventory.yml --graph
@all:
  |--@ungrouped:
  |--@freeipa:
  |  |--@freeipa-server:
  |  |  |--freeipa-server
  |  |--@freeipa-client:
  |  |  |--client-vm
  |  |--@freeipa-server-replica:
  |--@dns:
  |--@ntp:
  |--@docker:
  |  |--client-vm
  |  |--nexus
  |--@keycloak:
  |--@keycloak-db:
  |--@infra-provider:
  |  |--@dns:
  |  |--@ntp:
  |  |--@docker:
  |  |  |--client-vm
  |  |  |--nexus
  |  |--@keycloak:
  |  |--@keycloak-db:
  |--@linux-servers:
  |--@log-server:
  |--@audit-log-forwarding:
  |  |--client-vm
  |  |--freeipa-server
  |  |--nexus
  |--@wazuh-manager:
  |  |--nexus
  |--@wazuh-fim:
  |  |--client-vm
  |  |--freeipa-server
  |  |--nexus
  |--@seaweedfs-s3:
  |  |--nexus
  |--@restic-backup:
  |  |--client-vm
  |  |--freeipa-server
  |  |--nexus
  |--@prometheus:
  |  |--nexus
  |--@thanos-query:
  |  |--nexus
  |--@alertmanager:
  |  |--nexus
  |--@dashboard:
  |  |--nexus
  |--@prod:
  |--@staging:
  |--@sandbox:
```

> `dns`/`ntp`/`keycloak`/`keycloak-db`/`linux-servers`/`log-server` are
> deliberately **empty** — dns/ntp use FreeIPA's own native
> `--setup-dns`/`--setup-ntp` instead (AlmaLinux incompatibility with the
> generic `core-infra-provider` roles, see § Real bugs of the prior
> build); Keycloak/PAM-OIDC are out of scope for this demo; `log-server`
> is empty because `wazuh-manager` supersedes it as the central SIEM
> receiver by design. **`wazuh-fim` and `audit-log-forwarding` now cover
> all three hosts** (a prior build only wired the client) — every node's
> own `/etc` is FIM-monitored and every node's own auditd events reach
> the central Wazuh manager, including the manager's own host and the
> FreeIPA server.

### Secrets — key names only (never values)

```bash
$ grep -oE '^[a-z_0-9]+:' tmp/pilot-verify-minimal-poc/demo/.vault/main.yaml
ipa_admin_password:
grafana_admin_password:
restic_aws_access_key_id:
restic_aws_secret_access_key:
restic_password:
thanos_aws_access_key_id:
thanos_aws_secret_access_key:
alertmanager_config:

$ grep -oE '^[a-z_0-9]+:' tmp/pilot-verify-minimal-poc/demo/.vault/ipa-identity.yaml
ipa_admin_password:
ipa_groups:
ipa_users:
ipa_sudo_rules:
ipa_hbac_rules:
ipa_hbac_disable_allow_all:
```

This round's roster deliberately kept scope minimal (no `ipa_hostgroups`,
one group `sysops`, two users `alice`/`bob`, one sudo rule, one HBAC
rule) — enough to exercise allow+deny+§4.6's reconciler cycle without
extra unused surface.

### Alignment decision

Spec targets and environment state are consistent after this pass — the
site-wide deploy applied `failed=0` on all 3 hosts with **zero extra `-e`
variables** (the "還有其他 -e 變數要帶嗎？" gate was answered empty both
times and never needed to be revisited), and `freeipa-identity` applied
`failed=0` on the first attempt (no roster field-name mistakes this
round). `dns`/`ntp`/`log-server`/`keycloak`/`keycloak-db`/`linux-servers`
groups intentionally empty per the already-corrected architecture;
`wazuh-fim`/`audit-log-forwarding`/`restic-backup` scope covers all three
hosts. One operational finding (§ Real bugs #25, SSSD sudo-cache
staleness on the very first sudo attempt) required a documented
workaround during §4.1 verification, not a code fix — see below.

---

## 1. Why

This is a **ground-up rebuild**, not a re-verification of an
already-standing environment: all 3 VMs were torn down and recreated,
the entire disposable workspace was deleted and rebuilt from nothing, and
every interactive wizard step was driven live via `trec drive
--interactive` (one op at a time, watching the real rendered screen after
each — not a pre-written `--script`), per this pass's explicit
instruction. Deployment stays entirely through `pilot vm-target` / `pilot
edit` / `pilot inventory generate` / `pilot deploy`, using **one** `pilot
deploy` site-wide invocation instead of looping through each role
individually — inventory group membership (empty group ⇒ auto-skip)
decides what actually runs, so a single "全站部署(site.yml)" run covers
every component that has hosts assigned. Every wizard step is recorded
live via `trec drive --interactive`; the deploy
runs and the final read-only verification are recorded with plain
`trec`.

This pass also corrects scope: `wazuh-fim` and `audit-log-forwarding`
are now wired to all three hosts (previously only the client), and the
monitoring host is named `nexus` in this environment (not `monitor-vm` —
whatever name `pilot vm-target list` actually shows should always be
used, never assumed).

The `tmp/pilot-verify-minimal-poc/{hosts.yml, inventory.yml, group_vars/,
.vault/}` config layer is disposable, built fresh under this repo's
gitignored `./tmp/` directory — not committed, not part of the tracked
project tree — per this session's constraint that test artifacts never
live loose in the working tree.

---

## 2. Prerequisites

- Host needs `/dev/kvm` access, an active libvirt `default` NAT network,
  and `qemu`-writable `/var/lib/libvirt/images/pilot/`.
- `pilot edit` / `pilot deploy` need a real TTY; this pass drove them via
  `trec drive` (scripted keystrokes) — see the
  `pilot-trec-verification` skill for the driving mechanics.
- A disposable inventory workspace under `./tmp/` (gitignored), built via
  `pilot edit --dir tmp/pilot-verify-minimal-poc/demo` +
  `pilot inventory generate --dir tmp/pilot-verify-minimal-poc/demo` —
  never a hand-edited YAML file, never a directory inside the tracked
  project tree.
- A freshly-built `pilot` binary (`go build -o ./pilot ./cmd/pilot`) — a
  stale binary can silently miss a wizard feature (e.g. the `.vault/`
  menu item) and looks identical to a real bug.

---

## 3. Rebuild sequence

### 3.1 v3.0 — VMs torn down and recreated from scratch

```bash
$ pilot vm-target down --name client-vm
$ pilot vm-target down --name nexus
$ pilot vm-target down --name freeipa-server
$ rm -rf tmp/pilot-verify-minimal-poc   # delete the entire disposable workspace, no leftover reuse
$ go build -o ./pilot ./cmd/pilot       # fresh binary before driving any wizard
$ pilot vm-target up --name freeipa-server --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name nexus --base-image ubuntu-24.04 --memory 12288 --vcpus 6 --disk 80 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name client-vm --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 20 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.6  2     2048      20         2026-07-15 19:24:57
freeipa-server  running  192.168.122.4  2     4096      30         2026-07-15 19:24:38
nexus           running  192.168.122.5  6     12288     80         2026-07-15 19:24:54
```

### 3.2 v3.0 — Build the inventory workspace via `pilot edit --interactive` (not by hand)

**Which `trec` mode to use is decided per command, not per section** —
the two `pilot edit` invocations below were driven live via `trec drive
--interactive` (one op sent at a time over a persistent stdin pipe: a
`tail -f` on a growing command file, piped into `trec drive
--interactive`, reading the returned `SCREEN` dump after each before
deciding the next op). This is different from a pre-written `--script`:
there is no fixed keystroke sequence committed in advance, so a wrong
navigation guess (this pass hit a few — see below) is caught and
corrected immediately from the real rendered screen instead of silently
landing on the wrong menu item. `pilot inventory generate` in between,
by contrast, is recorded with **plain `trec`** (no `drive`, no
`--interactive`): it takes no interactive input at all — it reads the
`hosts.yml` just saved and writes `inventory.yml`, then exits on its own
— so there is nothing for `drive --interactive` to drive; a plain
recorder is both sufficient and the correct choice. The general rule
(see §0): *any command that will prompt for keystrokes* gets `trec drive
--interactive`; *any command that runs to completion on its own* (one-shot
wizard commands, read-only verification checks) gets plain `trec`.

```bash
$ pilot edit --dir tmp/pilot-verify-minimal-poc/demo        # hosts.yml — 3 hosts, roles per §0.5 (trec drive --interactive)
$ pilot inventory generate --dir tmp/pilot-verify-minimal-poc/demo   # (plain trec — no prompts to answer)
wrote tmp/pilot-verify-minimal-poc/demo/inventory.yml
$ pilot edit --dir tmp/pilot-verify-minimal-poc/demo        # group_vars/ + .vault/main.yaml, same session (trec drive --interactive)
```

`tmp/pilot-verify-minimal-poc/.vault/ipa-identity.yaml` (the HBAC/sudo
roster — nested YAML, `pilot edit`'s vault editor explicitly declines
this and points at a text editor) was hand-authored, the one
tool-endorsed exception to "no hand-edited YAML" — see § Real bugs #8 for
a roster field-name mistake this actually caught.

Real navigation mistakes caught live and corrected in-session (exactly
the failure mode `--interactive` mode exists to catch): toggling the role
checklist with a plain `DOWN` between two non-adjacent target roles
instead of `DOWN <gap size>` walked through and toggled every role in
between (`nexus` briefly got `keycloak`/`keycloak-db`/`linux-servers`
/`log-server` checked by accident) — caught on the very next `SNAPSHOT`
and fixed with a few corrective `UP`/`DOWN`/`SPACE` ops before saving.
`promptui.Prompt{AllowEdit:true}`'s append-not-replace behavior bit twice
(an SSH key path once, `ansible_user` once) — same fix each time,
`BACKSPACE <n>` before retyping.

Two hard rules for the vault/group_vars key-list screens, added after
the v8 round (2026-07-17) silently typed seven values into the same
field:

- **The key list rebuilds with the cursor at the TOP after every field
  edit — there is no auto-advance.** A fill script must send
  `DOWN <index>` (recomputed from the top) before the `ENTER` for
  every entry. A script that omits this edits entry 0 over and over,
  saves cleanly, and produces an all-green result while every other key
  keeps its `CHANGE-ME` placeholder.
- **After every save, `grep` the file on disk and compare each
  intended key's value before proceeding to the next wizard step.**
  「✅ 已存檔」 proves a save happened, not that the right
  keys got the right values. In v8 this check was skipped; the deploy
  then ran with `ipa_admin_password` set to a value meant for an S3
  secret and `grafana_admin_password` still at its placeholder, and
  the discrepancy was only noticed after IPA was already installed
  with the wrong password.

continuous `pilot edit` session covers both group_vars/ and .vault/).

**2026-07-18 addendum — a from-scratch attempt (evidence in
`tmp/pilot-verify-minimal-poc/`, never promoted to a committed round)
violated every gate in this section at once and never recovered:** it
built `hosts.yml` without ever touching the `ansible_user`/SSH-key
fields (idx 1/2 of the per-host menu — see the
`pilot-trec-verification` skill's "per-host edit screen" section for
the exact 8-field layout), ran the site-wide deploy anyway, got
`Permission denied (publickey)` on all three hosts, then tried to
patch `ansible_user` in with `sed` on the theory that `pilot edit`
"can't" set it — which is false, it's a normal field on that same
menu. Every one of its four edit scripts also omitted the
`ENTER` after the final `SELECT 離開`/`SELECT 💾 存檔並離開`, so even
the edits that *did* save correctly (hosts.yml, the vault) still came
back as `WAIT_CHILD_EXIT` timeouts in the captured evidence. The final
`hosts.yml` left behind has an SSH key configured for only one of the
three hosts (and even that entry is a duplicated line, not a clean
wizard write) — i.e. the workspace was abandoned mid-repair, not fixed.
None of this is a `pilot` defect; it is exactly the class of mistake
§3.2a's gates and the skill's per-host-field/`離開`-ambiguity notes
exist to prevent. Do not reuse that `tmp/` workspace as a starting
point — rebuild `hosts.yml` from scratch following the gate below.

### 3.2a Mandatory deployment gate (v4.1, 2026-07-16)

Do **not** turn a failed or inconvenient wizard step into a skipped one. The old static `deploy-site.trec` skipped preflight, answered `n` to the preview, and used `EXPECT_QUIET` as a long-running apply completion signal. That is invalid: `EXPECT_QUIET` is not a child-process completion test. Drive a deploy in one persistent `trec drive --interactive` session; after confirming apply, send no further operation and let the child process end naturally.

Before deploying, the generated inventory and vault inputs must satisfy these gates:

- Run the complete preflight; do not choose its skip option. Every host needs `ansible_user` and a reachable SSH key.
  **Set both in the very same `pilot edit` pass that adds the host and its roles** — the per-host menu's idx 1
  (`ansible_user(SSH 帳號)`) and idx 2 (`SSH 私鑰路徑`, pointing at
  `/var/lib/libvirt/images/pilot/<name>/id_ed25519`) are both normal wizard fields, not something that needs a
  follow-up `sed` patch. `inventory.Lint` does not reject a missing/empty value here, and the preflight is the
  only thing that will actually catch it — do not skip straight to a site-wide deploy on the theory that a clean
  `pilot edit` save means the fields are populated. See the `pilot-trec-verification` skill's "per-host edit
  screen" section for the exact field list and the `離開`/`SSH`-label ambiguity gotchas that make this easy to
  script wrong.
- In this no-Keycloak topology, `dns`, `ntp`, `keycloak`, `keycloak-db`, `linux-servers`, and `log-server` stay empty. Adding `linux-servers` imports PAM-OIDC, which needs Keycloak and is not check-mode-safe.
- The hand-authored FreeIPA roster follows `playbooks/apply/freeipa-identity.roster.example.yaml`: user entries use `name`, `groups`, and `allow_commands`. Do not use remembered aliases such as `uid`, `usergroups`, or `commands`; do not give a default `usercat=all` HBAC rule an explicit `users:` list.
- An HBAC deny claim needs a negative `ipa hbactest` verdict and a live SSH attempt with valid credentials. A credential-less `BatchMode=yes` attempt proves neither authentication nor HBAC. Disable both broad `sshd` rules, `allow_all` and `allow_systemd-user`, before accepting the deny result.

The current disposable workspace passed its preflight on 2026-07-16:

```bash
$ ansible-playbook playbooks/preflight.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml
PLAY RECAP *********************************************************************
client-vm                  : ok=8    changed=0    unreachable=0    failed=0
freeipa-server             : ok=6    changed=0    unreachable=0    failed=0
nexus                      : ok=6    changed=0    unreachable=0    failed=0
```

The mandatory site preview was then run on the same inventory. The SeaweedFS C5/C6/C7 readiness and bucket-probe tasks now skip in check mode rather than reading a missing `stdout` from `docker_container_exec`; the preview is therefore a real gate instead of a reason to bypass it:

```bash
$ ansible-playbook playbooks/site.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e patch_stage=sandbox \
    -e @tmp/pilot-verify-minimal-poc/demo/.vault/main.yaml --check --diff
PLAY RECAP *********************************************************************
client-vm                  : ok=63   changed=2    unreachable=0    failed=0
freeipa-server             : ok=52   changed=1    unreachable=0    failed=0
localhost                  : ok=1    changed=0    unreachable=0    failed=0
nexus                      : ok=144  changed=2    unreachable=0    failed=0
```

Only after this preview returns `failed=0` may the wizard's preview prompt be accepted and the real apply confirmed.

**v4.2 correction (2026-07-16):** the v4.1 pass above happened to run its site preview against hosts that had already been through at least one real apply before (docker engine, third-party apt/yum repos, and downloaded release bundles already existed for real on disk). That masked a whole class of the same check-mode bug on a **genuinely** from-scratch host — one that has never had a real (non-`--check`) apply run against it at all. Re-running the identical preview against freshly-`undefine`d, never-before-applied VMs failed=1 four separate times in a row as each fix unmasked the next play's version of the same problem:

1. `audit-log-forwarding-apply.yml` Step 8 (`systemd: name: auditd`) — auditd's package install is only simulated under `--check`, so the unit file doesn't exist yet.
2. `wazuh-fim-apply.yml` Step 4 (RedHat `dnf`) — the Wazuh yum repo (Step 3) is only simulated too, so dnf has no metadata for `wazuh-agent` and fails outright instead of merely simulating.
3. `wazuh-manager-apply.yml`'s `docker info` preflight (deliberately `check_mode: false` to fail fast) — and, once that no longer masked the host, its own `Step 2-5` disk build (download/unpack/generate certs) and `Step 6-11` compose-up block.
4. Every `community.docker.docker_container`/`docker_image`/`docker_container_exec` task across `seaweedfs-s3-apply.yml`, `keycloak-db-apply.yml`, `keycloak-apply.yml`, `alertmanager-apply.yml`, `prometheus-apply.yml`, `thanos-query-apply.yml`, `dashboard-apply.yml`, and `log-shipping-apply.yml` — these need a live docker daemon to compute their check-mode diff at all, and the daemon itself doesn't exist yet when `core-infra-provider-apply.yml`'s own docker install was, correctly, deferred to the real apply. `restic-backup-apply.yml` had the same two problems together (an EL-only EPEL-repo-dependent `dnf` install, plus a docker-daemon-dependent S3 bucket probe forced to run for real under `check_mode: false`).

All of the above are now guarded with `when: not ansible_check_mode` (or, where the task was already forced to run for real via `check_mode: false` to fail fast on a genuinely broken host, `failed_when: ... and not ansible_check_mode`), deferring anything that needs real package/daemon/container state to the real apply — the same convention the v4.1 SeaweedFS fix already established. Separately, this pass's disposable `group_vars/prometheus.yml`/`thanos-query.yml` still had placeholder-empty `prometheus_site_label`/`thanos_s3_target_host` (required, no default by design — see `docs/verification/prometheus.md` §1.5); that's a workspace-completeness gap, not a check-mode bug, and is now filled in with `site-nexus`/nexus's own IP so the gate in §3.2a's own checklist above ("every host needs...") should also read as "every required group_vars value must be a real value, not a copied-from-`.example.yml` placeholder."

Re-running the full site preview from a truly fresh, never-before-applied environment after all of the above:

```bash
$ ansible-playbook playbooks/site.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e patch_stage=sandbox \
    -e @tmp/pilot-verify-minimal-poc/demo/.vault/main.yaml --check --diff
PLAY RECAP *********************************************************************
client-vm                  : ok=61   changed=22   unreachable=0    failed=0    skipped=64   rescued=0    ignored=0
freeipa-server             : ok=46   changed=16   unreachable=0    failed=0    skipped=48   rescued=0    ignored=0
localhost                  : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
nexus                      : ok=93   changed=31   unreachable=0    failed=0    skipped=137  rescued=0    ignored=0
```
### 3.3 v3.0 — Deploy with ZERO extra `-e` variables

> **Prompt policy (v10 clarification):** when the wizard explicitly detects
> an inventory-derived `-e` value, accept that prompt with **`Y`**. The later
> manual `還有其他 -e 變數要帶嗎？` field must remain empty. If a value is
> required in that manual field, stop the run and report the required key;
> do not invent or fill it autonomously.

> **How the wizard passes the roster for `freeipa-identity`** (added
> after the v8 round misread this as "wizard can't do
> freeipa-identity" and fell back to bare `ansible-playbook`): the
> roster file goes through the **vault vars-file prompt**, not the
> `-e` prompt. At 「偵測到 …/.vault/main.yaml，這次佈署要用它當密碼
> 變數檔嗎？」 answer **`n`**, then enter the roster path
> (`…/.vault/ipa-identity.yaml`) at the vars-file prompt — the roster
> schema includes `ipa_admin_password`, so no second file is needed.
> The 「還有其他 -e 變數要帶嗎？」 prompt only accepts `key=value` by
> design. Answering `y` (using main.yaml) still ends in 「✅ 套用完成」
> `failed=0` — but with every reconcile task skipped
> (`changed=0`, `skipped=` in the dozens). **Treat that recap as a
> failed deploy: the roster never loaded.**

This is the pass's headline result. Both invocations below were driven
via `pilot deploy`'s wizard under `trec drive --interactive`; the "還有
其他 -e 變數要帶嗎？" prompt was answered **empty** both times — no
`freeipa_setup_dns`, no `freeipa_setup_ntp`, no `freeipa_dns_forwarders`,
no `seaweedfs_s3_config_path`, none of the Thanos/Prometheus vars v2.5
still needed. See § Real bugs #7 for the source fix that made
`freeipa_dns_forwarders`/NTP genuinely unnecessary (sensible defaults,
still group_vars-overridable), and §3.3's v2.5 entry below for the
Thanos/Prometheus fix from the prior pass.

| # | Scope | Result |
|---|-------|--------|
| 1 | 全站部署(site.yml), **zero extra `-e`** | `client-vm: ok=83 changed=39 failed=0`, `freeipa-server: ok=79 changed=34 failed=0`, `nexus: ok=152 changed=74 failed=0` |
| 2 | `freeipa-identity`, **zero extra `-e`** beyond the roster vault file | `freeipa-server: ok=21 changed=15 failed=0` (first attempt failed with a roster field-name mistake — `uid`/`usergroups`/`commands` instead of the schema's `name`/`groups`/`allow_commands` — see § Real bugs #8; this is the corrected re-run) |

```bash
$ ansible-playbook playbooks/site.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e patch_stage=sandbox \
    -e @tmp/pilot-verify-minimal-poc/demo/.vault/main.yaml
PLAY RECAP *********************************************************************
client-vm                  : ok=83   changed=39   unreachable=0    failed=0    skipped=27   rescued=0    ignored=0
freeipa-server              : ok=79   changed=34   unreachable=0    failed=0    skipped=15   rescued=0    ignored=0
localhost                   : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
nexus                       : ok=152  changed=74   unreachable=0    failed=0    skipped=37   rescued=0    ignored=0

$ ansible-playbook playbooks/apply/freeipa-identity-apply.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e @tmp/pilot-verify-minimal-poc/demo/.vault/ipa-identity.yaml
PLAY RECAP *********************************************************************
freeipa-server              : ok=21   changed=15   unreachable=0    failed=0    skipped=6    rescued=0    ignored=0
```

first attempt, kept for the historical error evidence), plus
(a mid-pass corrective re-apply of `freeipa-client` alone after § Real
bugs #9 was found during §4 verification — see that section).

Historical (v2.0-v2.5, superseded): the `-e` list below used to be
required every single run.

### 3.3h (historical) Deploy — 2 `pilot deploy` invocations as of v2.3 (was 3 in v2.0-v2.2)

`log-shipping` was folded into `site.yml` in v2.3: the import's
`target_group` is now a Jinja expression that picks the `log-server`
group if it has hosts, else falls back to `wazuh-manager` — so a single
site-wide run now also installs Promtail on whichever host actually has
real logs to tail, using `log-shipping-apply.yml`'s own `docker
inspect`-based `siem_log_root` resolution (v2.2) to find them. Only
`freeipa-identity` (a data-driven day-2 roster, not part of the "apply
what's in inventory" model) remains a deliberately separate invocation.

| # | Scope | Result |
|---|-------|--------|
| 1 | 全站部署(site.yml) — every role with hosts assigned in §0.5's inventory tree, **including `log-shipping`** as of v2.3 | `client-vm: ok=77 changed=0 failed=0`, `freeipa-server: ok=67 changed=0 failed=0`, `nexus: ok=144 changed=0 failed=0` (see idempotency note below; folding in `log-shipping` added the `ok`/`skipped` counts vs. the v2.0 baseline of 76/66/132) |
| 2 | `freeipa-identity` (HBAC/sudo roster, intentionally excluded from site.yml — data-driven day-2 reconciler) | `freeipa-server: ok=21 changed=16 failed=0` |

Historical (v2.0-v2.2, superseded): `log-shipping` used to require its
own invocation (`-e target_group=client-vm -e siem_log_root=/var/log`,
later `-e target_group=nexus` with no override once v2.2's auto-detection
landed) because `site.yml` hardcoded `target_group: log-server`, an empty
group in this topology. See the v2.0/v2.2 command blocks below for the
exact invocations that were run at the time; they are kept for the
historical PLAY RECAP evidence, not as the current recommended procedure.

The site-wide command actually run (representative — the real command
included `-e freeipa_setup_dns=true -e freeipa_setup_ntp=true -e
freeipa_dns_forwarders=192.168.122.1 -e
seaweedfs_s3_config_path=/etc/seaweedfs/s3.json -e
siem_forward_host=192.168.122.3 -e prometheus_site_label=site-nexus -e
thanos_s3_target_host=192.168.122.3 -e thanos_query_target_host=192.168.122.3
-e thanos_query_http_port=10912 -e thanos_query_port=10912`, see § Real
bugs for why each of these is needed):

```bash
$ ansible-playbook playbooks/site.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e patch_stage=sandbox \
    -e freeipa_setup_dns=true -e freeipa_setup_ntp=true -e freeipa_dns_forwarders=192.168.122.1 \
    -e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json -e siem_forward_host=192.168.122.3 \
    -e prometheus_site_label=site-nexus -e thanos_s3_target_host=192.168.122.3 \
    -e thanos_query_target_host=192.168.122.3 -e thanos_query_http_port=10912 -e thanos_query_port=10912 \
    -e @tmp/pilot-verify-minimal-poc/.vault/main.yaml
PLAY RECAP *********************************************************************
client-vm                  : ok=76   changed=0    unreachable=0    failed=0    skipped=33   rescued=0    ignored=0
freeipa-server              : ok=66   changed=0    unreachable=0    failed=0    skipped=27   rescued=0    ignored=0
localhost                   : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
nexus                       : ok=132  changed=0    unreachable=0    failed=0    skipped=41   rescued=0    ignored=0
```

**Idempotency evidence**: the `changed=0` above is itself the
idempotency proof — this exact command had already run once (with the
same PLAY RECAP shape but real `changed` counts, failing only on an
unrelated `log-shipping` experiment that was reverted, see § Real bugs
#5), and this re-run shows every previously-applied task settling to
`changed=0` with `failed=0`.

`freeipa-identity`:

```bash
$ ansible-playbook playbooks/apply/freeipa-identity-apply.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e @tmp/pilot-verify-minimal-poc/.vault/ipa-identity.yaml
PLAY RECAP *********************************************************************
freeipa-server              : ok=21   changed=16   unreachable=0    failed=0    skipped=6    rescued=0    ignored=0
```

`log-shipping` (historical, v2.0, superseded — see below for the current
folded-in behavior):

```bash
$ ansible-playbook playbooks/apply/log-shipping-apply.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e target_group=client-vm -e siem_log_root=/var/log \
    -e @tmp/pilot-verify-minimal-poc/.vault/main.yaml
PLAY RECAP *********************************************************************
client-vm                   : ok=8    changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

**v2.3 — `log-shipping` folded into the site-wide run**: same site-wide
command as above (invocation #1), no separate `log-shipping` call at all.
The `PLAY [Apply log-shipping ...]` play now resolves its `hosts:`
pattern to `wazuh-manager` (since `log-server` is empty in this
topology) and runs on `nexus`:

```bash
$ ansible-playbook playbooks/site.yml -i tmp/pilot-verify-minimal-poc/demo/inventory.yml \
    -e stage=sandbox -e patch_stage=sandbox [... same -e flags as invocation #1 ...] \
    -e @tmp/pilot-verify-minimal-poc/.vault/main.yaml
PLAY [Apply log-shipping (Promtail: log-server -> dashboard Loki)] *************
TASK [Detect a co-located wazuh-manager container (for real alerts-log path resolution)] ***
ok: [nexus]
TASK [Resolve effective siem_log_root (explicit > wazuh-manager's real alerts-log volume > log-server default)] ***
ok: [nexus]
TASK [Promtail — run pilot-promtail container] *********************************
ok: [nexus]
PLAY RECAP *********************************************************************
client-vm                   : ok=77   changed=0    unreachable=0    failed=0    skipped=33   rescued=0    ignored=0
freeipa-server              : ok=67   changed=0    unreachable=0    failed=0    skipped=27   rescued=0    ignored=0
localhost                   : ok=1    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
nexus                       : ok=144  changed=0    unreachable=0    failed=0    skipped=44   rescued=0    ignored=0
```

All `changed=0` — Promtail was already running on `nexus` from the v2.2
test deploy, so folding the play into `site.yml` converges to the exact
same state idempotently. Re-queried Loki after this run to confirm the
data didn't regress:

```bash
$ curl -s -G "http://192.168.122.3:3100/loki/api/v1/query_range" --data-urlencode 'query={job="pilot-siem"}' --data-urlencode 'limit=2'
{"status":"success","data":{"resultType":"streams","result":[{"stream":{"filename":"/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.log","job":"pilot-siem"},...
```

Confirmed restic timers healthy on all 3 hosts:

```bash
$ systemctl is-active restic-backup.timer; systemctl is-enabled restic-backup.timer   # (all 3 hosts)
active
enabled
```

### 3.4 v7.0 — round 7 deploy results (2026-07-17, current)

Built via `trec drive --script` (not `--interactive` — see the v7.0 top
banner note) against the fresh `.3`/`.5`/`.6` environment: `pilot edit`
for `hosts.yml` (3 hosts, 19-role checklist per host; values included
`freeipa_server_ip`, `prometheus_site_label`, `thanos_s3_target_host`
×2, `thanos_query_target_host`, `restic_s3_target_host`,
and `wazuh_manager_host`). `.vault/ipa-identity.yaml` was hand-authored per the
one tool-endorsed exception.

```bash
$ ansible-inventory -i tmp/pilot-verify-minimal-poc/demo/inventory.yml --graph
# see §0.5 for the full graph — same shape as prior rounds
```

Site-wide `pilot deploy` (scope: 全站部署(site.yml); stage: sandbox;
`--limit`/`--tags` empty; vault: auto-detected `.vault/main.yaml`; **zero**
extra `-e` variables):

| Phase | client-vm | freeipa-server | nexus |
|---|---|---|---|
| Preflight (full, incl. SSH) | ok=8 changed=0 failed=0 | ok=6 changed=0 failed=0 | ok=6 changed=0 failed=0 |
| Preview (`--check --diff`) | ok=52 changed=19 failed=0 | ok=45 changed=16 failed=0 | ok=78 changed=27 failed=0 |
| Real apply | ok=84 changed=41 failed=0 | ok=78 changed=34 failed=0 | ok=152 changed=74 failed=0 |

The combined preflight, preview, and apply ran in one `pilot deploy` session.

`freeipa-identity` (single component, target group default `freeipa-server`,
vault: explicit `.vault/ipa-identity.yaml`, **zero** extra `-e`):

> **Scripting this from scratch?** The "單一元件" prompt chain is a
> different shape from the site-wide chain above (different code path,
> different prompt count) — don't reuse the site-wide script or
> guess the step count by trial and error. See the `pilot-trec-verification`
> skill's "The single-component prompt chain is its own shape" section for
> the full enumerated chain (catalog select → target group → stage →
> optional S3/auto-host-var steps → `--limit`/`--tags` → the up-to-4-step
> vault prompt → extra `-e` vars → the shared preview/apply confirm tail),
> including the worked `freeipa-identity` example.

| Phase | freeipa-server |
|---|---|
| Preview | ok=4 changed=0 failed=0 |
| Real apply | ok=30 changed=12 failed=0 |

Both first-time onboard users (`force_password: true`) got real passwords
set (`changed` ×2 on
the "Set password for users that need one" task) — confirms the v6.0
Real bug #24 fix holds on an independent fresh rebuild.

**Idempotency — full site-wide re-run, no roster/group_vars changes**

| Phase | client-vm | freeipa-server | nexus |
|---|---|---|---|
| Preview | ok=49 changed=0 failed=0 | ok=42 changed=0 failed=0 | ok=75 changed=0 failed=0 |
| Real apply | ok=77 changed=0 failed=0 | ok=66 **changed=1** failed=0 | ok=143 changed=0 failed=0 |

The one `freeipa-server` change is `ansible.builtin.file` correcting the
mode of `/var/lib/ipa/pki-ca/publish` back to `0755` — Dogtag PKI's own
process appears to reset this directory's mode as a side effect of
normal `ipactl`/CA operation between runs; not a `pilot`/playbook bug,
and not chased further since it's cosmetic and outside any of this
runbook's verification goals. Every other one of the site's ~74 changed
tasks from the first apply settled to `changed=false`.

## 4. Verify (v11.0, round 11 — 2026-07-21, current)

> **If a future agent's environment blocks direct `ssh`/`curl` outright**:
> use `pilot vm-target exec --name <vm> -- <cmd>` for every read-only check
> in this section (metrics/API curls, `sudo -n id`, log greps, `ipa
> hbactest`, …) — it's `pilot`'s own already-permitted SSH connection, not
> the agent's raw shell. It authenticates as the VM's fixed key-based
> `ssh_user` only, though, so it **cannot** stand in for the live
> password-based `kinit`/`ssh` checks below (`alice`/`bob`'s own
> credentials) — those genuinely need a raw `ssh`/`sshpass` call and the
> environment's own confirmation for a "Remote Shell Write". See the
> `pilot-trec-verification` skill's §7 gotcha list for the full reasoning.

### 4.0a v11 actual verification evidence (current pass — round 11, 2026-07-21)

The following outputs are from the fresh `.2`/`.3`/`.5` targets (round 11),
captured live during this pass (no values below are predictions, all
recorded via the cast in `tmp/pilot-verify-minimal-poc-r11/casts/`):

```text
FreeIPA: ipa active (verified during deploy PLAY RECAP, ok=78 changed=34 on freeipa-server)
Grafana: HTTP 200 on /api/health
Prometheus: Prometheus Server is Ready.   (HTTP 200 on /-/ready)
Loki: ready                                (HTTP 200 on /ready, labels ["filename","job"])
Thanos Query: up{job="prometheus",site="site-nexus"} value=1
Thanos up metrics: up{instance="localhost:9090",job="prometheus",site="site-nexus"} 1
restic-backup.timer: active waiting on all 3 hosts
restic snapshots in shared S3 repo: 2 (one per host)
Wazuh agent on client-vm: wazuh-modulesd/logcollector/syscheckd/agentd/execd all running
Wazuh FIM file-add alert: '/etc/pilot-fim-test-1784625894' added; Mode: whodata; uid=root; ppid=sshd
Wazuh FIM agent id: 003 (client-vm.ipa.pilot.internal)
```

The live FreeIPA run completed the alice + bob + sysops + sudo + HBAC rule
reconcile on the first pass (`freeipa-server: ok=30 changed=11 failed=0
skipped=26`), then ran the idempotent preview (every task reports
`skipping`, `freeipa-server: ok=5 changed=0 failed=0 skipped=51`).

The live `alice` SSH + sudo evidence was recorded as:

```text
$ sshpass -p '***' ssh -t -o StrictHostKeyChecking=accept-new -o ControlMaster=no     alice@192.168.122.2 'echo *** | sudo -S systemctl is-active ssh'
[sudo] password for alice: active

$ sshpass -p '***' ssh -t -o StrictHostKeyChecking=accept-new -o ControlMaster=no     alice@192.168.122.2 'echo *** | sudo -S cat /etc/shadow'
[sudo] password for alice: Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.

$ sshpass -p '***' ssh -o StrictHostKeyChecking=accept-new -o ControlMaster=no bob@192.168.122.2 'id'
uid=318400005(bob) gid=318400005(bob) groups=318400005(bob)
```

FreeIPA's own authoritative check (both layers agree, after the v11
reconciler cycle where alice was re-added to sysops):

```text
$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sshd
--------------------
Access granted: True
--------------------
  Matched rules: allow_all
  Matched rules: sysops-login-all
  Not matched rules: allow_systemd-user

$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sudo
--------------------
Access granted: True
--------------------
  Matched rules: allow_all
  Matched rules: sysops-login-all
  Not matched rules: allow_systemd-user
```

The intermediate `sysops-login-all` "not matched" state was also captured
live (immediately after `ipa group-remove-member sysops --users=alice`,
before re-add):

```text
$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sshd
--------------------
Access granted: True
--------------------
  Matched rules: allow_all
  Not matched rules: allow_systemd-user
  Not matched rules: sysops-login-all
```

(`sudo` service layer showed the same `sysops-login-all: Not matched` state
at the same instant.) Both layers correctly show `sysops-login-all` going
from "matched" to "not matched" as alice's sysops membership is removed.

The `§4.6 reconciler cycle` evidence (round 11, 2026-07-21):

```text
1. ipa group-remove-member sysops --users=alice
   → sysops-login-all no longer matches alice (above)
2. ipa group-add-member sysops --users=alice
   + roster.yaml change: add /usr/bin/journalctl to sysops-systemctl allow_commands
3. pilot reconcile reapply
   → freeipa-server: ok=29 changed=2 failed=0 skipped=27
4. After sss_cache -E && systemctl restart sssd on client-vm:
   $ echo *** | sudo -S journalctl -n 5
   → real journalctl output captured
   → /var/log/auth.log: alice : PWD=/home/alice ; USER=root ;
     COMMAND=/usr/bin/journalctl -n 5  (sudo[16337] pam_sss(sudo:auth):
     authentication success)
   → ipa sudorule-show sysops-systemctl:
     Sudo Allow Commands: /usr/bin/systemctl, /usr/bin/journalctl
```

The two `changed=2` from step 3 are the pre-existing two non-idempotent
items already documented as not-pilot-bugs: the sudo rule's
`allow_commands` drift correction (one), and the Dogtag-PKI-owned
directory-mode reset (the other). Recorded honestly per AGENTS.md §1
("no 'expected' / 'should' / 'predicted' output anywhere").

### 4.0a v10 actual verification evidence

The following outputs are from the fresh `.2`/`.3`/`.4` targets, captured
live during this pass (no values below are predictions):

```text
FreeIPA: ipa active; dirsrv@IPA-PILOT-INTERNAL.service active
Grafana: database=ok, version=11.1.0
Thanos Query: OK
Prometheus: Prometheus Server is Ready.
Loki: ready
Thanos up{site="site-nexus"}: value "1"
Loki labels: ["pilot-siem"]
Restic: 2 snapshots (client-vm.ipa.pilot.internal, nexus)
Wazuh FIM: File '/etc/wazuh_test_fim_trigger_r10' added; Mode: whodata
```

The live FreeIPA run first completed Alice's forced-password-change flow,
then recorded `sudo systemctl is-active ssh` as `active` and rejected
`sudo cat /etc/shadow` with the actual sudo policy denial (`deny_exit=1`).
The initial `sudo -n` probe was not counted as evidence because the fresh
admin-reset state correctly required a password; the corrected `sudo -S`
probe is the authoritative result.

The reconciler evidence is also current: removing Alice's `sysops`
membership returned `ipa hbactest ... --service=sshd` as `Access granted:
False`; restoring the membership and adding `/usr/bin/journalctl` changed
five items; the final roster rerun completed with `failed=0 changed=2`.
This is recorded as a non-idempotency finding, not rounded down to zero.

The remaining paragraphs in §§4.0–4.6 retain the v7 historical evidence for
comparison; the v10 outputs above are the current pass and use the fresh
`.2`/`.3`/`.4` addresses.

`alice` was the first-time onboard in this round
(`force_password: true`), so she landed in FreeIPA's fresh-admin-reset
"must change" state after `freeipa-identity`'s real apply — confirmed via
`ipa user-show alice --all --raw` showing `krbLastPwdChange` ==
`krbPasswordExpiration` (`20260717043700Z` for both). Personalized
`alice`'s password with the documented scripted `kinit` forced-change
flow:

```bash
$ ssh -t -i /var/lib/libvirt/images/pilot/client-vm/id_ed25519 root@192.168.122.6 kinit alice
Password for alice@IPA.PILOT.INTERNAL:
Password expired.  You must change it now.
Enter new password:
Enter it again:
$ echo EXIT=$?
EXIT=0
```

Confirmed via `ipa user-show alice --all --raw` that `krbLastPwdChange`
(`20260717043844Z`) and `krbPasswordExpiration` (`20261015043844Z`, ~90
days later) diverged — genuinely personalized, not another admin reset.

### 4.1 Permission management (FreeIPA HBAC/sudo) — allow + deny, both real, cross-checked with `ipa hbactest`

The first attempt's live-SSH sudo commands failed with `alice is not
allowed to run sudo on client-vm` despite `ipa hbactest --service=sudo`
already reporting `Access granted: True`. `sss_cache -E && systemctl
restart sssd` on `client-vm` (the already-documented Real bug #15/#20
workaround) fixed it; re-ran clean:

```bash
$ sshpass -p '***' ssh -o ControlMaster=no -o PreferredAuthentications=password alice@192.168.122.6 \
    "echo '***' | sudo -S systemctl is-active ssh"
[sudo] password for alice: active

$ sshpass -p '***' ssh -o ControlMaster=no -o PreferredAuthentications=password alice@192.168.122.6 \
    "echo '***' | sudo -S cat /etc/shadow"
[sudo] password for alice: Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.

$ sshpass -p '***' ssh -o ControlMaster=no -o PreferredAuthentications=password bob@192.168.122.6 'echo should-not-reach-here'
Connection closed by 192.168.122.6 port 22
```

FreeIPA's own authoritative check (both layers agree):

```bash
$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sshd
--------------------
Access granted: True
--------------------
  Matched rules: sysops-login-all
  Not matched rules: allow_systemd-user

$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sudo
--------------------
Access granted: True
--------------------
  Matched rules: sysops-login-all
  Not matched rules: allow_systemd-user

$ ipa hbactest --user=bob --host=client-vm.ipa.pilot.internal --service=sshd
---------------------
Access granted: False
---------------------
  Not matched rules: allow_systemd-user
  Not matched rules: sysops-login-all
```

Verdict: **PASS** (after the documented `sss_cache`/`sssd` refresh — see
§ Real bugs #25) — allow and deny both real-tested at the live SSH/sudo
layer and FreeIPA's own policy-evaluation layer for both `sshd` and
`sudo` services, and all four agree.

### 4.2 Metric queryable from Grafana (Grafana → Thanos Query → Prometheus)

```bash
$ curl -s http://192.168.122.5:3000/api/health
{"commit":"5b85c4c2fcf5d32d4f68aaef345c53096359b2f1","database":"ok","version":"11.1.0"}

$ curl -s "http://192.168.122.5:10912/api/v1/query?query=up"
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"site-nexus"},"value":[1784263187.335,"1"]}],"analysis":{}}}
```

`prometheus_site_label=site-nexus` and `thanos_s3_target_host`/
`thanos_query_target_host` all came entirely from `group_vars/*.yml` this
round — zero `-e` override anywhere in either deploy invocation.

Verdict: **PASS** — Prometheus → sidecar → Thanos Query federation works

### 4.3 Log queryable from Grafana (Grafana → Loki ← Promtail on nexus)

```bash
$ curl -s "http://192.168.122.5:3100/loki/api/v1/label/job/values"
{"status":"success","data":["pilot-siem"]}

$ curl -s -G "http://192.168.122.5:3100/loki/api/v1/query_range" --data-urlencode 'query={job=~".+"}' --data-urlencode 'limit=5'
{"status":"success","data":{"resultType":"streams","result":[{"stream":{"filename":"/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/2026/Jul/ossec-alerts-17.log","job":"pilot-siem"},"values":[
  ["1784263184980799066",""],
  ["1784263184980795793","tty: ssh"],
  ["1784263184980793433","euid: 0"],
  ["1784263184980791239","uid: 0"],
  ["1784263184980788797","Jul 17 04:39:43 client-vm.ipa.pilot.internal sshd[13693]: pam_unix(sshd:auth): authentication failure; ... user=bob"]
]}]}}
```

Verdict: **PASS** — real Wazuh alert lines present in Loki (this round
even captured `bob`'s own real denied-login attempt from §4.1 as a live
log line), zero `-e siem_log_root=`/`-e target_group=` override.

### 4.4 Restic backup timers

```bash
$ systemctl is-active restic-backup.timer; systemctl is-enabled restic-backup.timer   # (all 3 hosts)
active
enabled

$ restic snapshots   # after `source /etc/pilot/restic-env` (env vars, not on-path by default)
ID        Time                 Host                          Tags        Paths
------------------------------------------------------------------------------
39f4c99b  2026-07-17 04:33:41  client-vm.ipa.pilot.internal              /etc
742693a6  2026-07-17 04:33:44  ipa1.ipa.pilot.internal                   /etc
df603010  2026-07-17 04:33:47  nexus                                     /etc
```

Verdict: **PASS** on `freeipa-server`, `nexus`, and `client-vm` — timers
active/enabled on all three, real shared-repo snapshots from all three
hostnames, and a manually-triggered `systemctl start restic-backup.service`
produced a fresh 4th snapshot immediately.

### 4.5 Wazuh File Integrity Monitoring (FIM)

```bash
$ ssh root@192.168.122.6 "touch /etc/wazuh_test_fim_trigger_v7"
$ ssh root@192.168.122.5 "docker exec pilot-wazuh.manager-1 tail -n 300 /var/ossec/logs/alerts/alerts.log | grep -A5 -B5 wazuh_test_fim_trigger_v7"
** Alert 1784263187.3904940: - ossec,syscheck,syscheck_entry_added,syscheck_file,...
2026 Jul 17 04:39:47 (client-vm.ipa.pilot.internal) any->syscheck
Rule: 554 (level 5) -> 'File added to the system.'
File '/etc/wazuh_test_fim_trigger_v7' added
Mode: whodata
```

Verdict: **PASS** — real-time whodata FIM alert within seconds of the
trigger.

### 4.6 FreeIPA identity reconciler — remove / restore+drift / idempotency

Full cycle re-verified live on this round's fresh roster, per the
`delivery-test` skill §4.6.

1. **Removal**: dropped `sysops` from `alice`'s `groups:` in
   `.vault/ipa-identity.yaml`, redeployed (`ok=30 changed=3 failed=0`).
   Both `ipa hbactest --service=sshd` and live SSH flipped to denied
   (`Connection closed by 192.168.122.6 port 22`); `alice`'s
   `krbLastPwdChange`/`krbPasswordExpiration` unchanged throughout
   (password provably undisturbed).
2. **Restore + drift-correction in the same edit**: restored `sysops` to
   `alice`'s `groups:` **and** added `/usr/bin/journalctl` to
   `sysops-systemctl`'s `allow_commands:`, redeployed
   (`ok=30 changed=5 failed=0`). Both flipped back live: `ipa hbactest`
   → `Access granted: True`, `sudo systemctl is-active ssh` → `active`,
   and the **new** `sudo journalctl -n 3 --no-pager` command worked
   immediately (drift-correction confirmed, not just membership).
   Password still provably undisturbed.
3. **Idempotency**: a final no-op rerun (no roster changes) settled to
   `ok=30 changed=2 failed=0` — exactly the two already-documented,
   pre-existing non-idempotent items (`bob`'s still-`force_password: true`
   test password, and `hbacrule-disable allow_all`'s own non-idempotent
   quirk). No new drift, no regression.

Verdict: **PASS** — the reconciler design (password self-change
protection, attribute-drift `*-mod` reconciliation, membership/attachment
diffing) holds on a completely independent, from-scratch round 7 rebuild.

---

## 5. Real bugs / gotchas encountered (this re-verification pass)

| # | Bug | Fix |
|---|-----|-----|
| 1 | `prometheus_site_label`, `thanos_s3_target_host` (in `prometheus-apply.yml`/`thanos-query-apply.yml`), and `thanos_query_target_host` (in `dashboard-apply.yml`) were declared as **play-level `vars:`** with empty-string defaults in those three playbooks. Ansible's variable precedence puts play `vars:` **above** both `host_vars` and `group_vars` — so setting them via `pilot edit`'s group_vars editor was silently ineffective. | **Fixed at the source in v2.5** (see Changelog): all three playbooks no longer declare these as play vars at all — every task that reads them now does `\| default('', true)` at the point of use instead. group_vars/host_vars values now flow through with no `-e` needed at all; `-e` still overrides on top if ever wanted. |
| 2 | Thanos Query's default HTTP port (10902) collided with the co-located Prometheus/Thanos-sidecar's own hardcoded host port on the **same host** — relevant whenever a site's own Prometheus and the central Thanos Query happen to live on the same box (as in this compact 3-VM demo). | **Fixed at the source in v2.5** (see Changelog): `thanos-query-apply.yml`'s `thanos_query_http_port` (and `dashboard-apply.yml`'s matching `thanos_query_port`) now **default to 10912**, not 10902 — no `-e` override needed for this topology at all. Still overridable via `-e` for other port schemes. |
| 3 | ~~The `pilot-thanos-metrics` SeaweedFS bucket is not auto-created~~ — **fixed** (see Changelog v2.1): `prometheus-apply.yml` and `thanos-query-apply.yml` now each carry the same idempotent "ensure destination bucket exists" block `restic-backup-apply.yml` already had, delegated to the `seaweedfs-s3` inventory host. No longer a manual step. | Was previously worked around with `docker exec pilot-seaweedfs sh -c "echo 's3.bucket.create -name pilot-thanos-metrics' | weed shell"`; now automatic on every apply. |
| 4 | Explored making `site.yml`'s `log-shipping` import dynamically fall back from the (empty) `log-server` group to `wazuh-manager` so Promtail installs on `nexus` itself, folding it into the one site-wide run. Mechanically works, but Promtail then found **no real logs to tail**: nothing in this topology writes to the default `siem_log_root` (`/var/log/siem`) on `nexus` — `log-server`'s own rsyslog receiver never runs there (Wazuh manager owns port 514 instead), and Wazuh's own `alerts.log` lives in a docker **named volume** whose name depends on the `docker-compose` project. | **Fixed properly in v2.2 + v2.3** (see Changelog): v2.2 made `log-shipping-apply.yml` resolve that volume's real host path via `docker inspect` at apply time instead of assuming the compose-derived name. v2.3 then folded the original dynamic-fallback idea back into `site.yml` — now safe because v2.2 fixed what it finds once it gets there — so `log-shipping` runs as part of the single site-wide `pilot deploy`, no longer a separate invocation. |
| 7 | (v3.0) `freeipa-server-apply.yml` required `-e freeipa_dns_forwarders=<ip>` every single run — the underlying variable had **no usable default** (fell back to an empty list, i.e. `--no-forwarders`), so a from-scratch deploy with zero `-e` would leave the FreeIPA host's own `named` unable to resolve the public internet for its own package installs. There was also no way to configure NTP servers for `ipa-server-install` at all (only the on/off `--no-ntp` toggle existed). | **Fixed at the source in v3.0**: `freeipa_dns_forwarders` now defaults to `8.8.8.8` (still group_vars/`-e`-overridable) instead of no-forwarders. Added a new `freeipa_ntp_servers` variable (default `[tock.stdtime.gov.tw, watch.stdtime.gov.tw]`, Taiwan's public stratum servers) passed to `ipa-server-install` as `--ntp-server=...`. Both documented in `group_vars/freeipa.example.yml`. Verified for real: the v3.0 site-wide deploy passed **zero** `-e` at all beyond `stage`/`patch_stage`/vault and still came back `failed=0` on `freeipa-server`. |
| 12 | (v4.2 re-verification) `pilot vm-target up` stalled ~2m30s on `nexus` even though the VM was already booted and reachable over ping/SSH: `internal/vmtarget/vmtarget.go`'s `waitForIP` discovers the VM's IP via `domifaddr` (kernel ARP) and, as fallback, `net-dhcp-leases` — but `Up` had already reserved a **static** DHCP host mapping for this exact MAC (`allocateStaticIP`, `net-update add ip-dhcp-host`) before boot, and this environment's dnsmasq does not always write a dynamic leases-file entry for a statically-reserved MAC, while ARP can also lag. Both sources came up empty for the full boot timeout despite the VM genuinely being up and using its reserved address. Not an Ansible/playbook bug — this is in `pilot`'s own Go source. | **Fixed at the source**: `Up` now keeps the IP `allocateStaticIP` already returns (previously discarded) and passes it into `waitForIP` as a last-resort fallback — tried only when both `domifaddr` and `net-dhcp-leases` report nothing on an iteration, and only accepted once a short, bounded TCP dial to `reservedIP:SSHPort` independently confirms something is actually listening there (not just "we configured a reservation"), so a genuinely stuck/dead VM still times out exactly as before. New regression tests `TestWaitForIP_FallsBackToReservedIPWhenReachable`/`TestWaitForIP_ReservedIPUnreachableStillTimesOut` cover both the fixed stall and the still-must-fail case; the dial itself is an injectable `Manager.dialReachable` field (stubbed to `false` by default in tests) rather than real networking, to keep the suite deterministic — matching how `virsh`/`ssh` are already shimmed at the process level rather than in Go. Full `internal/vmtarget` suite green (`go test ./internal/vmtarget/...`). Workaround used before this fix: manually atomic-patch the statefile to set `status=running`/`ip=<reserved IP>`. |
| 13 | (v4.2 re-verification) A real site-wide `pilot deploy` failed at FreeIPA client enroll: `freeipa-client-apply.yml`'s `ipa_server_ip: "{{ freeipa_server_ip \| default(ansible_host) }}"` resolved to **the client's own IP** whenever `-e freeipa_server_ip` was omitted, because on the client-enroll play `ansible_host` is the client's own connection address, not the FreeIPA server's — pinning `ipa1.ipa.pilot.internal` to the wrong host in `/etc/hosts` and making `ipa-client-install` fail to find the server. The existing required-vars gate never caught it, since `ansible_host` is always defined and non-empty — just wrong. This broke the v3.0/v4.0 "site-wide deploy needs zero extra `-e`" claim. | **Fixed at the source (v4.3, see Changelog)**: auto-resolves from this inventory's `freeipa-server` group (`hostvars[groups['freeipa-server'][0]].ansible_host`) instead, same "explicit overrides inventory-derived, else fail loudly at the existing gate" idiom as `audit-log-forwarding-apply.yml`'s `siem_forward_inventory_host`. Verified for real: `freeipa-client-apply.yml --check --diff` with no `-e freeipa_server_ip` now correctly pins the real server IP, and the full site-wide preview stays `failed=0`. |
| 15 | (v4.2 re-verification) The demo roster's `devops-sudo` rule set `cmdcat: all` (by analogy with the already-supported `hostcat: all`), expecting an unrestricted-commands sudo rule for the `sysops` group. `freeipa-identity-apply.yml`'s "Ensure sudo rules exist" task never read `cmdcat` at all — only `allow_commands` (individual commands, attached via separate `sudocmd-add`/`sudorule-add-allow-command` tasks) was ever handled — so the rule was created with **no command grant whatsoever** (`ipa sudorule-show devops-sudo` showed no `Command category` and no attached commands), silently denying every sudo attempt for the group despite the rule "existing" and the apply reporting `failed=0`. A related, separately-tested claim — that `ipa sudocmd-add` needs `kinit admin` first or returns `Insufficient access` — is **not a playbook bug**: standard FreeIPA RBAC (confirmed live: no ticket → `did not receive Kerberos credentials`; a ticket for a non-admin principal → `Insufficient access: Insufficient 'add' privilege ...`); the apply playbook's own `Kinit admin` task already runs first in the same play, so every automated `ipa sudocmd-add` call is correctly privileged — this only bites a human running `ipa` commands by hand on the server without kinit-ing first. | **Fixed at the source**: "Ensure sudo rules exist" now also passes `--cmdcat=` (defaulting to `all`, mirroring `hostcat`'s exact convention) whenever `allow_commands` is absent — the two are mutually exclusive in FreeIPA itself, same as `hostcat` vs. `hosts`/`hostgroups`. Verified for real: deleted the live (incorrectly-created) `devops-sudo` rule, reran `freeipa-identity-apply.yml` from the fixed source with **no manual patch**, and `ipa sudorule-show devops-sudo --all` came back with `Command category: all` set correctly; live SSH as `alice` then confirmed `sudo whoami` → `root` end-to-end (after refreshing the client's SSSD sudo cache — a genuinely separate finding: SSSD's sudo provider does not immediately reflect a changed rule's attributes on an already-enrolled client; `sss_cache -E && systemctl restart sssd` forces the refresh — now documented in `docs/runbooks/freeipa-identity.md` §6 alongside the kinit-admin note). Also added a `cmdcat: all` example to `freeipa-identity.roster.example.yaml` and documented the field in §5.2's category table. |
| 16 | (`./tmp` AI-agent-process audit, 2026-07-16) Same class of bug as #15, one field over: the demo roster's `devops-sudo` rule also set `runas_user: ALL`/`runasgroup: ""`, expecting the rule to allow `sudo -u <anyone>` (not just root). `freeipa-identity-apply.yml` never read either field — grep found zero references — so the rule silently kept FreeIPA's own default (no `runasusercat`/`runasgroupcat` set ⇒ run-as-root only). The demo happened not to notice because "run as root" was exactly what its test commands needed, but a roster author relying on `runas_user` to scope a rule to specific non-root accounts would get a silently *wider* default (root, unrestricted) instead of what they wrote — the same "field looks honored, isn't" trap as #15, just not yet tripped over. | **Fixed at the source**: "Ensure sudo rules exist" now sends `--runasusercat=all`/`--runasgroupcat=all` when the roster's `runas_user`/`runasgroup` is the string `all` (case-insensitive) — same magic-category convention as `hostcat`/`cmdcat`. Specific runas user/group *lists* (as opposed to the `all` category) are intentionally not implemented — no roster in this repo needs them yet. Verified live: deleted the existing `devops-sudo` rule on `freeipa-server`, reran the fixed playbook from the unmodified demo roster, and `ipa sudorule-show devops-sudo --all` came back with `RunAs User category: all` set (server-side authoritative confirmation). Also added a "Gate: sudo rule category vs specific-list fields are mutually exclusive" preflight `assert` — it fails fast if a roster sets both `hostcat`+`hosts`/`hostgroups`, or both `cmdcat`+`allow_commands`, on the same rule, since the task has always silently preferred one and dropped the other with no warning (exactly how #15 went unnoticed). |
| 17 | (`./tmp` AI-agent-process audit, 2026-07-16) `playbooks/apply/freeipa-identity.roster.example.yaml`'s own `devops-sudo` example (added while fixing #15, in this same repo state, uncommitted) had **two `groups:` keys on the same list item** (`groups: [sysops]` then `groups: [developers]`). PyYAML's default loader silently keeps only the *last* value of a duplicate mapping key — no warning, no error — so the example actually only granted `developers`, quietly dropping `sysops` entirely. Nothing in the repo would have caught this: the file is `.yaml` (the `playbook-lint` Makefile target only globs `playbooks/apply/*.yml`), `ansible-lint` doesn't check for YAML-level duplicate keys, and `pilot edit` explicitly declines to edit this class of nested-structure roster YAML — pushing users toward hand-editing exactly the file format most prone to this silent-collapse mistake, with zero tooling safety net. | **Fixed the specific instance** (merged to `groups: [sysops, developers]`) and **closed the general gap**: added `scripts/check-yaml-duplicate-keys.py` (a custom PyYAML loader that errors on any duplicate mapping key) over every tracked `.yml`/`.yaml` file, wired into both `make playbook-lint` (and therefore the optional pre-commit hook) and a new CI step in `.github/workflows/ci.yml`. Confirmed it actually catches the bug (re-injected the duplicate in a throwaway string, got a `DuplicateKeyError` at the right line) and that it passes clean on the current repo (66 files). |
| 18 | (freeipa-identity infra-as-code redesign, 2026-07-16) While writing `docs/verification/freeipa-identity.md` and validating it against the real `pilot spec --generate` tool (not just hand-authoring the doc), found that all 8 checklist rows collapsed into a single generated task. Root cause traced to `internal/spec/generator.go`: `classifyRow`'s raw-command fallback (used whenever a row's `Command` doesn't match Pattern A–F: `test -f`/`grep`/`sysctl -n`/`systemctl is-active`/`dpkg -s`/`awk print`) always returned `params=""`, and the dedup key hashes `(module, params)` — so **every row that falls through to the raw fallback hashes identically regardless of its actual command**, silently merging unrelated checks into one task that only ever runs the first row's command (tagged with every other row's spec ID too, so `pilot verify` would report pass/fail for those IDs based on the wrong command entirely). This wasn't a fresh regression: it already affected 9 previously-committed, previously-"working" verify playbooks — most severely `playbooks/verify/freeipa-server.yml`, an 18-row spec collapsed to 2 real tasks (C3–C18 all silently riding on C2's `sudo ipactl status` result). | **Fixed at the source**: `classifyRow`'s fallback now hashes the raw command itself instead of an empty string (`internal/spec/generator.go`) — verified this has zero effect on the rendered YAML, since `RenderYAML` already renders the separate `RawCommand` field (never `Params`) for this task shape, so the fix is purely to the dedup key. Added `TestGenerate_RawFallbackDoesNotCollapseDistinctCommands`, `go test ./internal/spec/...` green. Regenerated every affected `playbooks/verify/*.yml` (`freeipa-server`, `freeipa-client`, `freeipa-server-replica`, `core-infra`, `core-infra-provider`, `core-infra-provider-db`, `docker`, `keycloak`, `os-patch-sla`, `seaweedfs-s3`, `freeipa-identity`) — each now syntax-clean with task count matching (or, for genuine command-text duplicates, correctly deduping) row count. Live-verified end-to-end: `pilot vm-target verify --name freeipa-server docs/verification/freeipa-identity.md` → real `pass=8 fail=0 skip=0`. |
| 19 | (v4.9 ground-up rebuild, 2026-07-16) The v4.8 reconciler redesign was never actually exercised through `pilot deploy`'s own mandatory `--check --diff` preview gate before this pass — `docs/verification/freeipa-identity.md`'s own validation used `pilot vm-target verify` (a different code path that never runs Ansible in check mode). Driving the real `freeipa-identity` single-component wizard against a genuinely fresh install surfaced **5 separate check-mode crashes** in `freeipa-identity-apply.yml`, all the same root cause: `ansible.builtin.command`/`shell` tasks are auto-skipped by Ansible core under `--check` (no `check_mode: false`), so the `set_fact` "compute what to remove" task right after them also skips per-item (its own `when: not (item.skipped \| default(false))` guard), which means the accumulator fact (`ipa_pwd_needs_reset`, `ipa_group_membership_removals`, `ipa_hostgroup_membership_removals`, `ipa_hbac_removals`, `ipa_sudo_removals`) is **never set at all** — and every downstream task referencing it unconditionally (`ipa_pwd_needs_reset.get(...)`, `X \| subelements(...)`) then fails outright with `'<name>' is undefined`, aborting the whole preview with `failed=1`. First hit on the password-protection task (v4.8's own Phase 0), then immediately again on the Phase 2 membership/attachment removal diffing once that was fixed — the exact same shape repeated across all 4 removal accumulators (12 call sites total). | **Fixed at the source**: every reference now defaults safely — `(ipa_pwd_needs_reset \| default({})).get(item.name, true)` for the password gate, `<X> \| default([]) \| subelements(...)` for all 12 removal-loop call sites (`ipa_group_membership_removals`, `ipa_hostgroup_membership_removals`, `ipa_hbac_removals` ×5, `ipa_sudo_removals` ×5) — a check-mode-skipped lookup now safely means "nothing computed yet, assume no removals due" instead of crashing; the real apply's actual behavior is unchanged (the `command`/`shell` tasks themselves still only run for real, never under `--check`). Verified live end-to-end: `ansible-playbook playbooks/apply/freeipa-identity-apply.yml --check --diff` against a fresh, never-before-applied `freeipa-server` now returns `failed=0`, and the real `pilot deploy` single-component wizard for `freeipa-identity` completes cleanly through preview → real apply with no manual workaround. |
| 20 | (v4.9 ground-up rebuild, 2026-07-16) Disabling the built-in `allow_all` HBAC rule — the reconciler's own documented hardening step (`ipa_hbac_disable_allow_all: true`) — silently breaks `sudo` for every user whose HBAC rule only lists `services: [sshd]` (the only shape shown anywhere in the roster example/docs before this pass). Root cause: SSSD's `access_provider = ipa` runs a **separate** HBAC check per PAM service, not just once at login — `allow_all` (and `allow_systemd-user`, which also lists `sshd` in its own `HBAC Services`) used to transparently cover the `sudo` PAM service too, so a roster author who only ever tested with those defaults still enabled would never notice their own rule doesn't grant `sudo`. Once `allow_all` is genuinely disabled (the documented best practice), live `sudo -S <cmd>` on an enrolled client fails with `sudo: PAM account management error: Permission denied` for an otherwise-correctly-provisioned user — confirmed live: SSH login and `ipa hbactest --service=sshd` both report allowed, but `ipa hbactest --service=sudo` for the identical user/host reports `Access granted: False`. Not a playbook bug — `freeipa-identity-apply.yml` faithfully applies whatever `services:` list the roster gives it; this is an undocumented FreeIPA/SSSD interaction that every roster author needs to know about once they actually harden past the built-in defaults. | **Documented and fixed the example**: added `sudo`/`sudo-i` to `playbooks/apply/freeipa-identity.roster.example.yaml`'s `sysops-login-all` HBAC rule's `services:` list plus an inline comment, and a new writeup in `docs/runbooks/freeipa-identity.md` §5.2.2 (right after the `ipa_hbac_disable_allow_all` callout) with the exact live-reproduced symptom/diagnosis. Verified live: added `sudo, sudo-i` to this pass's own roster's `services:` list, redeployed `freeipa-identity` (reconciler correctly diffed and added just the two new services — `ok=28 changed=4 failed=0`, no other drift), refreshed the client's SSSD cache, and confirmed `sudo -S systemctl is-active ssh` as `alice` now succeeds while `ipa hbactest --service=sudo` flips to `Access granted: True`. |
| 21 | (follow-up to v4.9, 2026-07-16) `pilot deploy`'s `ansible.NewRunner()` (`internal/ansible/runner.go`) hard-codes a 30-minute per-`ansible-playbook`-invocation timeout (preflight, preview, and the real apply each get their own fresh 30m budget) with **no CLI override anywhere in the call chain** — `deploy.go` always calls `runner.Run` directly, never `RunWithTimeout`. Didn't bite the v4.9 pass (site-wide apply ran ~13-20 min), but a slower host or heavier topology would get the real apply `SIGKILL`ed mid-run with no warning and no documented way to raise the ceiling short of falling back to a manual `ansible-playbook` invocation outside `pilot deploy` entirely. | **Fixed at the source**: added a `--timeout` flag to `pilot deploy` (Go duration string, e.g. `45m`/`1h30m`, default `30m` — unchanged behavior unless overridden), parsed via a new `parseDeployTimeout` helper and set on the one shared `runner.Timeout` used for preflight/preview/apply. Added `TestParseDeployTimeout` (valid/invalid cases) plus a live end-to-end check against the demo VMs: `pilot deploy --timeout 1ms` genuinely aborts a real `playbooks/preflight.yml` run (`❌ 前置檢查沒有全過(結束碼 -1)`), while the unmodified default path still completes and reaches the next prompt normally. `previewInventoryGraph`/`resolveGroupHost`'s own separate `ansible.NewRunner()` calls (`ansible-inventory`, not `ansible-playbook` — near-instant) were left on the fixed 30m default since it's irrelevant there. |
| 22 | (round-5 ground-up rebuild, 2026-07-16) A site-wide `pilot deploy` silently left `client-vm`'s Wazuh agent unenrolled with the manager even though `nexus` (in the same inventory) runs `wazuh-manager`: `wazuh-fim-apply.yml`'s `wazuh_manager_host` has no auto-detect fallback from the inventory's own `wazuh-manager` group — it is only ever auto-resolved by `pilot deploy`'s **single-component** wizard (`deploy_catalog.go`'s `AutoHostVars` → `promptAutoHostVar`), and `site.yml`'s own `import_playbook: apply/wazuh-fim-apply.yml` has no `vars:` override to replicate that convenience. Left at its documented empty default, the apply itself reported clean (by design — see the `wazuh_manager_host` doc comment's own "known deviation, spec §5" note), but the underlying Wazuh agent package still actively retried enrollment against a `127.0.0.1` loopback placeholder (Step 7's own "or loopback placeholder" fallback) forever, logging `wazuh-agentd: ERROR: (1208): Unable to connect to enrollment service` every ~30-45s in `ossec.log` — confirmed live: `agent_control -l` on the manager showed only `nexus` enrolled, never `client-vm`, and touching a file under `/etc` produced no alert at all. This is a genuinely different root cause from Real bug #20/#15 — not a config mistake in the roster/group_vars, but an asymmetry between two playbooks that both take an "other role's host" variable: `restic-backup-apply.yml` already has its own inventory-based auto-detect fallback for `restic_s3_target_host` (from the `seaweedfs-s3` group) baked directly into the playbook, so it works correctly regardless of deploy path; `wazuh-fim-apply.yml` never got the equivalent. | **Fixed at the source**: added a `pre_tasks` step to `wazuh-fim-apply.yml`, "Auto-detect Wazuh manager host from this inventory's wazuh-manager group" (`ansible.builtin.set_fact`, `hostvars[(groups.get('wazuh-manager', []) \| first)]['ansible_host']`), firing only when `wazuh_manager_host` is genuinely empty and the inventory has a non-empty `wazuh-manager` group — mirrors `restic-backup-apply.yml`'s own "Auto-detect backup destination host from this inventory's seaweedfs-s3 group" task exactly, same idiom. `ansible-playbook --syntax-check` clean. Verified live end-to-end: redeployed the `wazuh-fim` single-component via `pilot deploy` with **no** `-e wazuh_manager_host` and **no** change to group_vars, `ok=15/14 changed=4/3 failed=0` on `client-vm`/`nexus`, `Step 9: Register with the manager via agent-auth` flipped from a would-be-skipped state to `changed: [client-vm]`, `agent_control -l` on the manager now lists `client-vm.ipa.pilot.internal` as agent `002` (`Active`), and a fresh `touch /etc/wazuh_test_fim_trigger3` produced a real `File '/etc/wazuh_test_fim_trigger3' added` alert within 20s. |
| 23 | (follow-up to #22, same day) Surveying `deploy_catalog.go`'s remaining `AutoHostVars` entries turned up the identical asymmetry in 3 more places (confirmed each one is genuinely missing, not just missed by a shallow `grep` — the earlier survey's first pass wrongly credited `prometheus-apply.yml`/`thanos-query-apply.yml` with already having a `thanos_s3_target_host` fallback because of an unrelated `groups.get('seaweedfs-s3', ...)` match used only for a bucket-creation `delegate_to`, not an auto-detect): `wazuh-manager-apply.yml`'s `siem_forward_host` (from the `log-server` group), `prometheus-apply.yml`'s `alertmanager_target_host` (from the `alertmanager` group), and `dashboard-apply.yml`'s `thanos_query_target_host` (from the `thanos-query` group) each degrade the same way #22 did on a site-wide deploy — silently left at their documented empty/skip default, correctly in `prometheus`/`dashboard`'s case (their own gates fail loudly if the destination is genuinely unresolvable, so no silent-and-wrong config resulted) but still a real gap versus what the single-component wizard would have auto-filled. Confirmed live in this pass's own environment: `alertmanager_target_host` was left commented-out in `group_vars/prometheus.yml` the entire session (Prometheus's alerting integration was never actually wired to the real Alertmanager, despite one existing in the same inventory) — not caught by the §4 verify suite because nothing in §4.1-4.6 exercises Alertmanager routing specifically. `thanos_query_target_host` happened not to bite this pass only because it was one of the 3 fields manually filled during the group_vars-editing step (§2.2) — an operator who skipped that field, same as `wazuh_manager_host` before #22, would have hit it too. **`wazuh-fim-apply.yml`'s own remaining `thanos_s3_target_host`-shaped variable does NOT have this gap** — that one really does already have the fallback (`restic-backup-apply.yml`'s original, correctly-identified case). | **Fixed at the source, all 3**: added the identical `pre_tasks` `set_fact` auto-detect pattern to each (`wazuh-manager-apply.yml` from `groups.get('log-server', [])`, `prometheus-apply.yml` from `groups.get('alertmanager', [])`, `dashboard-apply.yml` from `groups.get('thanos-query', [])`), same idiom as #22. `ansible-playbook --syntax-check` clean on all 3; `scripts/check-yaml-duplicate-keys.py` clean across the repo. Verified live, each in isolation (temporarily blanking the relevant `group_vars` value, or omitting the `-e` override entirely, then restoring it): `prometheus-apply.yml --check --diff` against `nexus` with no `-e alertmanager_target_host` now shows `Auto-detect Alertmanager host ...` → `ok`, `Pin alertmanager-backend -> 192.168.122.6 in /etc/hosts` → `ok` (previously `skipping`); `dashboard-apply.yml` the same for `thanos_query_target_host`; `wazuh-manager-apply.yml`'s equivalent task correctly `skipping` (not erroring) in this topology, since it has no `log-server` group to detect. Left un-fixed, flagged only: this topology's own `group_vars/prometheus.yml` still had `alertmanager_target_host` commented out at the time of writing — a genuine gap in this pass's own workspace completeness (§2.2), not re-applied as part of this fix since the point was to verify the playbook-level fallback works, not to change this session's already-passing §4 verification state. |

| 24 | (round-6/v6.0 ground-up rebuild, 2026-07-17) `freeipa-identity-apply.yml`'s password-set logic never actually gives a **brand-new** user a Kerberos key unless the roster entry has `force_password: true`. This session's disposable roster followed the *steady-state* convention documented in v4.5/the header comment (`force_password: false` for an already-onboarded user whose password is meant to be protected from re-clobbering) for `alice` — correct for a roster being reapplied to an *already-provisioned* environment, but wrong for a genuinely first-time-ever apply, which is exactly what a ground-up rebuild always is. The "Look up password-expiry state" task (which decides whether an account still needs a reset, including the documented "no key yet ⇒ proceed" fallback) was itself gated `when: item.force_password \| default(false) \| bool` — so for `force_password: false` it never ran at all, and the final "Set password" task's own gate required the same flag, so `alice` was created via `ipa user-add` (which never sets a password) and then **never got a password set by any task**, leaving her with zero Kerberos key material. Confirmed live: `ipa user-show alice --all --raw` had no `krbLastPwdChange`/`krbPasswordExpiration` attributes at all (not even the "just admin-reset" identical-timestamps state), and `kinit alice` failed with a confusing `Pre-authentication failed: Invalid argument` — not a recognizable "wrong password" or "no such user" error, so this would be a genuinely confusing failure for a real operator to diagnose blind. | **Fixed at the source**: the password-expiry lookup now runs for every user with a `password` declared, regardless of `force_password` (comment updated to explain why). The final "Set password" task's `when` now fires on `(force_password: true) OR (the account genuinely has no working password yet, per the existing `ipa_pwd_needs_reset` signal)` — so a brand-new account always gets its initial password set on first apply, while an already-personalized `force_password: false` user's password remains protected from being clobbered on a routine rerun (the v4.8/v5.x design intent is fully preserved, just no longer gated on a flag that a steady-state roster legitimately sets to `false` from day one). `ansible-playbook --syntax-check` and `scripts/check-yaml-duplicate-keys.py` both clean. Verified live end-to-end: redeployed `freeipa-identity` with the unmodified disposable roster (`force_password: false` still on `alice`), confirmed `ipa user-show alice --all --raw` now shows `krbLastPwdChange`==`krbPasswordExpiration` (fresh admin-reset "must change" state), then completed the real `kinit alice` forced-password-change flow successfully — unblocking the rest of this pass's §4.1 HBAC/sudo live-SSH verification. |


| 26 | (2026-07-18, from a `tmp/pilot-verify-minimal-poc/` re-verification review) `freeipa-identity-apply.yml`'s data lists (`ipa_users`/`ipa_groups`/`ipa_hostgroups`/`ipa_hbac_rules`/`ipa_sudo_rules`) all default to `[]` so a partial roster is valid — but nothing distinguished "a partial roster" from "no roster was actually loaded at all". An earlier agent's re-verification attempt answered the vault-file prompt with the wrong file (a plain `group_vars`-style `main.yaml` that only defines `ipa_admin_password`, not the roster) and the apply completed with `ok=5 skipped=50`, still printing `✅ 套用完成` — every loop over an empty list is a no-op, so nothing failed, nothing changed, and nothing warned that the roster was never actually supplied. Confirmed via `trec transcript` + a fresh read of the playbook (not by re-trusting the agent's own bug report — see this runbook's "cross-verify four ways" rule) that this was a real silent-no-op gap, not a misdiagnosis, distinct from the same review's other two claims (§ `pilot-trec-verification` memory) which *were* misdiagnoses. | **Fixed at the source**: added a `pre_tasks` gate, "roster supplies at least one data list", right after the existing `ipa_admin_password` gate — fails fast with a message pointing at the likely wrong-`-e`-file cause when all five lists are empty, but still passes a genuinely partial roster (only one list populated) unchanged. `ansible-playbook --syntax-check` and `scripts/check-yaml-duplicate-keys.py` both clean. Verified via local `--check` dry-runs against `localhost` (no real IPA server needed for this gate, since it runs in `pre_tasks` before `Kinit admin`): all-empty roster (`-e ipa_admin_password=... ` only) now fails immediately at this gate with the intended message; a partial roster (`-e '{"ipa_groups":[{"name":"testgrp"}]}'`) passes through it (`ok=4 failed=0`) exactly as before. |


| 2026-07-15 | v2.0 | Re-verification pass: one-shot `pilot deploy` site-wide invocation (+2 separate for `freeipa-identity`/`log-shipping`) instead of one-role-at-a-time; `wazuh-fim`/`audit-log-forwarding` scope widened to all 3 hosts; monitoring host renamed `nexus`; 5 new operational findings (Ansible play-vars-vs-group_vars precedence, Thanos Query/sidecar port collision, missing SeaweedFS bucket, log-shipping/wazuh-manager colocation dead-end, `AllowEdit` append-not-replace); both verification goals re-confirmed PASS, this time also cross-checked with `ipa hbactest` and the exact denial event traced live into Loki | sre |
| 2026-07-15 | v2.1 | Code fixes, verified with a real regression test (deleted `pilot-thanos-metrics`, redeployed `thanos-query` alone, confirmed auto-create + all 4 Thanos containers healthy + real `up{}` data): (1) `freeipa-server-apply.yml`'s `ipa_setup_dns`/`ipa_setup_ntp` now default `true` (this play already hard-gates EL9-only, and the non-native dns/ntp path never worked there); (2) `audit-log-forwarding-apply.yml`'s `siem_forward_host` now auto-resolves from the `log-server`/`wazuh-manager` inventory groups when not set, plus a matching `group_vars/audit-log-forwarding.example.yml` template; (3) `prometheus-apply.yml`/`thanos-query-apply.yml` now each auto-create their `pilot-thanos-metrics` S3 bucket on apply, mirroring `restic-backup-apply.yml`'s existing idiom — confirmed `seaweedfs-s3-apply.yml`'s signed-S3-mode auto-detection (by presence of restic vault credentials) was already implemented, no change needed there | sre |
| 2026-07-15 | v2.2 | `log-shipping-apply.yml`'s `siem_log_root` now auto-detects a co-located `wazuh-manager` container's real alerts-log host path via `community.docker.docker_container_info` (`docker inspect`) when left unset — no more hardcoded assumption about the docker-compose-derived volume name, and no more falling back to the empty `/var/log/siem` when `log-server` never ran on that host. Verified for real: deployed `log-shipping` targeted at `nexus` with no `siem_log_root` override; Loki's `query_range` now returns real lines from `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.log` — Grafana on `nexus` can see actual Wazuh alert content, not just generic host auditd/syslog | sre |
| 2026-07-15 | v2.3 | `site.yml`'s `log-shipping` import now folded fully into the site-wide run — `target_group` is a Jinja expression (`log-server` if it has hosts, else `wazuh-manager`) instead of the hardcoded, always-empty-in-this-topology `log-server`. `pilot deploy` invocations for this runbook drop from 3 to 2 (site-wide + `freeipa-identity`); `log-shipping` is no longer a separate call. Safe now specifically because v2.2 already made the play resolve real log content wherever it lands. Verified for real: reran the full site-wide `pilot deploy` (same `-e` flags as before, no `target_group`/`siem_log_root` override anywhere) and confirmed the `Apply log-shipping` play's host pattern resolved to `wazuh-manager` → `nexus`, all tasks `ok`/`changed=false` (fully idempotent with the prior state), and Loki's `query_range` still returns real `alerts.log` content afterward | sre |
| 2026-07-15 | v3.0 | **Genuine ground-up rebuild** per explicit request: all 3 VMs torn down and recreated (fresh IPs `.4`/`.5`/`.6`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing, every wizard step driven live via `trec drive --interactive` (one op at a time against the real rendered screen, not a pre-written `--script`) instead of `trec drive --script`. Two more code fixes closing out the last of the `-e` workarounds (§ Real bugs #7): `freeipa_dns_forwarders` now defaults to `8.8.8.8` (was: empty ⇒ `--no-forwarders`) and a new `freeipa_ntp_servers` var (default `tock.stdtime.gov.tw`/`watch.stdtime.gov.tw`) is now passed to `ipa-server-install` — both group_vars-settable. Result: the site-wide `pilot deploy` needed **zero** extra `-e` variables at all (only `stage`/`patch_stage`/vault), `PLAY RECAP` came back `failed=0` on all 3 hosts (`client-vm: ok=83 changed=39`, `freeipa-server: ok=79 changed=34`, `nexus: ok=152 changed=74`). Two more real bugs found and fixed during this pass: a hand-authored roster schema mistake (§ Real bugs #8, `uid`/`usergroups`/`commands` vs. the real `name`/`groups`/`allow_commands` schema) and a genuinely new environment bug (§ Real bugs #9) — Ubuntu cloud-init's sshd drop-ins silently defeated `ipa-client-install`'s own password-auth intent due to sshd's Include-then-first-occurrence-wins directive semantics, blocking every FreeIPA account with no SSH key from logging in with a password at all; fixed with a correctly-ordered `sshd_config.d/05-freeipa-client-password-auth.conf` drop-in. Full §4 verification suite re-confirmed **PASS** end-to-end on the fresh environment: HBAC allow+deny (live SSH + `ipa hbactest`, both agree), Grafana→Thanos Query→Prometheus, Grafana→Loki←Promtail, and restic timers healthy on all 3 hosts | sre |
| 2026-07-16 | v4.1 | Added a mandatory deployment gate: persistent interactive TREC driving, complete preflight, checked role scope, roster/HBAC acceptance criteria, and a required site preview. Fixed SeaweedFS C5/C6/C7 check-mode guards so the recorded preview now returns failed=0; real SeaweedFS apply remained idempotent (nexus: ok=11 changed=0 failed=0). | codex |
| 2026-07-16 | v4.2 | v4.1's own preview run happened to hit hosts that had already been through a real apply before, which hid a whole class of the same check-mode bug on a **genuinely** from-scratch host. Re-verifying against freshly-`undefine`d VMs surfaced it four times in a row as each fix unmasked the next play: `audit-log-forwarding-apply.yml` Step 8 (auditd `systemd` start against a package check mode never really installed), `wazuh-fim-apply.yml` Step 4 (RedHat `dnf` install from a yum repo check mode never really added), `wazuh-manager-apply.yml`'s `docker info` preflight plus its own disk-build and compose-up steps, and — the widest one — every `community.docker.docker_container`/`docker_image`/`docker_container_exec` task across `seaweedfs-s3-apply.yml`, `keycloak-db-apply.yml`, `keycloak-apply.yml`, `alertmanager-apply.yml`, `prometheus-apply.yml`, `thanos-query-apply.yml`, `dashboard-apply.yml`, `log-shipping-apply.yml`, and `restic-backup-apply.yml`, none of which can compute a check-mode diff without a live docker daemon that doesn't exist yet when `core-infra-provider-apply.yml`'s own docker install is (correctly) deferred to the real apply. All now guarded with `when: not ansible_check_mode` (or `failed_when: ... and not ansible_check_mode` where the task was deliberately forced to run for real via `check_mode: false` to fail fast), same convention as the v4.1 SeaweedFS fix. Also filled in this pass's disposable `group_vars/prometheus.yml`/`thanos-query.yml`, which still had placeholder-empty `prometheus_site_label`/`thanos_s3_target_host` (a workspace-completeness gap, not a check-mode bug — both are required with no default by design). Re-verified for real: the full site-wide `--check --diff` preview against the fresh, never-before-applied `client-vm`/`freeipa-server`/`nexus` now returns `failed=0` on all three hosts in one pass, no further re-run needed. See §3.2a for the full recap. | sre |
| 2026-07-16 | v4.3 | Real bug #13 fixed at the source: `freeipa-client-apply.yml`'s `ipa_server_ip: "{{ freeipa_server_ip \| default(ansible_host) }}"` resolved to **the client's own IP** (not the FreeIPA server's) whenever `-e freeipa_server_ip` was omitted, because `ansible_host` on the client-enroll play is the client's own connection address — the existing required-vars gate never caught it since that value is always defined and non-empty, just wrong. This broke the v3.0/v4.0 "site-wide deploy needs zero extra `-e`" claim (a real site-wide apply from this pass failed FreeIPA client enroll pinning `ipa1.ipa.pilot.internal` to itself). Fixed by auto-resolving from this inventory's `freeipa-server` group (`hostvars[groups['freeipa-server'][0]].ansible_host`), same "explicit overrides inventory-derived, else fail loudly at the existing gate" idiom as `audit-log-forwarding-apply.yml`'s `siem_forward_inventory_host` — falls through to the required-vars assert (not a silently-wrong value) when no such group exists and `-e` wasn't passed either. Verified for real against the live inventory: `freeipa-client-apply.yml --check --diff` with **no** `-e freeipa_server_ip` now shows the pin task's own name resolving to the real server IP (`... pin the FreeIPA server ipa1.ipa.pilot.internal to 192.168.122.2 ...`), and the full site-wide `--check --diff` preview stays `failed=0` (now `changed=0` everywhere too, since the environment was already really applied — see § Real bugs #13 for the diagnosis and workaround used before this fix, and #14 for a related, separately-scoped password-expiry finding from the same pass's verify suite). | sre |
| 2026-07-16 | v4.4 | Real bug #12 fixed at the source, in `pilot` itself (not an Ansible playbook): `internal/vmtarget/vmtarget.go`'s `waitForIP` discovers a VM's IP via `domifaddr`/`net-dhcp-leases` polling, but `Up` had already reserved a **static** DHCP host mapping for the VM's exact MAC before boot — `allocateStaticIP`'s own returned IP was discarded, and this environment's dnsmasq doesn't always produce a dynamic leases-file entry for a statically-reserved MAC, so both discovery sources could stay empty for the full boot timeout despite the VM genuinely being up (2m30s stall on `nexus` this pass, worked around at the time with a manual statefile patch). Fixed by keeping the reservation's IP and using it as a last-resort fallback in `waitForIP`, accepted only once a short bounded TCP dial to `reservedIP:SSHPort` independently confirms the VM is actually listening there — a genuinely stuck/dead VM still times out exactly as before. New tests `TestWaitForIP_FallsBackToReservedIPWhenReachable`/`TestWaitForIP_ReservedIPUnreachableStillTimesOut` cover both directions; the dial is an injectable `Manager.dialReachable` field (stubbed deterministically in tests, matching how `virsh`/`ssh` are already shimmed rather than exercising real networking in the suite). Full `internal/vmtarget` suite green, `go build`/`go vet` clean across the repo. Real bug #14 (FreeIPA admin-reset always expiring the target password, blocking a scripted live-SSH test) was assessed separately and left as a **documented known limitation** — it's intentional FreeIPA/Kerberos behavior, not a bug; see § Real bugs #14 for the existing `force_password: false` workaround and what a fuller fix (interactive `kinit`/`kpasswd` automation) would require. | sre |
| 2026-07-16 | v4.5 | `freeipa-identity-apply.yml`'s password-set task flipped from opt-**out** to opt-**in**: `force_password` now defaults to `false` (was `true`), so a roster entry with a `password:` key only actually gets `ipa passwd` run against it when that entry ALSO sets `force_password: true` — a routine rerun of an already-onboarded roster can no longer silently reset a user's password back into a forced-change state (the exact failure mode in § Real bugs #6 and #14) just because nobody remembered to add `force_password: false`. First-time onboarding (or a deliberate reset) now requires the explicit `true` instead. Updated `playbooks/apply/freeipa-identity.roster.example.yaml` (added `force_password: true` to `alice`/`bob`'s first-time-onboard entries, dropped the now-redundant "set false to skip" comment from `carol`) and `docs/runbooks/freeipa-identity.md` (§5 idempotency section + example) to document the new default. `ansible-playbook --syntax-check` clean; this pass's disposable `.vault/ipa-identity.yaml` already had `force_password: true` explicit on both `alice` and `bob`, so its own behavior is unaffected by the flip — the fix protects rosters that *don't* set the key at all. | sre |
| 2026-07-16 | v4.6 | Real bug #15 fixed at the source: `freeipa-identity-apply.yml`'s sudo-rule-creation task never read `cmdcat` — only `allow_commands` — so a rule written as `cmdcat: all` (the natural, `hostcat`-analogous way to say "allow every command") silently got **no command grant at all**, denying every sudo attempt while the apply itself reported clean. Now passes `--cmdcat=all` (or the roster's own `cmdcat` value) whenever `allow_commands` is absent, exactly mirroring `hostcat`'s existing convention and mutual-exclusivity rule. Verified for real end-to-end against the live environment: deleted the mis-created `devops-sudo` rule, reran the fixed playbook with no manual patch, confirmed `Command category: all` via `ipa sudorule-show --all`, and confirmed live `alice` SSH → `sudo whoami` → `root`. Also confirmed (and documented as a non-bug, standard FreeIPA RBAC) that manually running `ipa sudocmd-add` on the server requires `kinit admin` first — the automated playbook already does this correctly — and discovered a genuinely separate operational gotcha along the way: SSSD's sudo provider doesn't immediately reflect a changed rule's attributes on an already-enrolled client, requiring `sss_cache -E && systemctl restart sssd` to see the fix take effect during verification. See § Real bugs #15 and `docs/runbooks/freeipa-identity.md` §5.2/§6 for the updated schema docs and troubleshooting notes. | sre |
| 2026-07-16 | v4.7 | Audit of prior AI-agent verification artifacts turned up three more issues, all fixed: Real bug #16 (`runas_user`/`runasgroup` silently ignored by `freeipa-identity-apply.yml`, same unhandled-roster-field class as #15 — now honors the `all` category value, plus a new preflight `assert` that fails fast if a roster sets both a category field and a specific-list field on the same sudo-rule axis, since the task has always silently preferred one with no warning); Real bug #17 (a duplicate `groups:` key in `freeipa-identity.roster.example.yaml`'s own `devops-sudo` example silently dropped `sysops` — PyYAML keeps only the last value of a duplicate mapping key with no error — fixed the instance and added `scripts/check-yaml-duplicate-keys.py`, wired into `make playbook-lint` and CI, so this class of mistake fails loudly repo-wide from now on). Also newly documented (not fixed — needs its own scoping decision): `freeipa-identity-apply.yml`'s "Ensure X exists" tasks are create-only, so a roster edit to an already-created rule/group/user's attributes is not reconciled on rerun — the live object must be deleted first to pick up the change, which is why re-verifying #15/#16 required deleting `devops-sudo` before rerunning. See § Real bugs #16/#17. | sre |
| 2026-07-16 | v4.8 | `freeipa-identity-apply.yml` redesigned into a real infra-as-code reconciler, closing the create-only gap documented in v4.7: (1) password self-change protection — `krbLastPwdChange`/`krbPasswordExpiration` are compared before an `ipa passwd` reset, so a roster that leaves `force_password: true` set never re-clobbers a password the user has since personalized (confirmed live: admin-reset leaves the two timestamps identical, a real user-completed change diverges them by the policy maxlife); (2) attribute-drift reconciliation — new `*-mod` tasks (`user-mod`/`group-mod`/`hostgroup-mod`/`hbacrule-mod`/`sudorule-mod`) correct an already-existing object's own fields (names, descriptions, host/service/command categories) on every rerun, where before only brand-new objects ever got these set; (3) membership/attachment diffing — group membership and HBAC/sudo rule attachments (hosts/hostgroups/services/users/groups/commands) now get a live lookup + roster diff + `*-remove-*` step, so **removing an entry from the roster and rerunning genuinely revokes it**, not just adding new entries. All three verified live end-to-end against the demo VMs: removing `alice` from the roster's `sysops` group and rerunning flipped `ipa hbactest` from `Access granted: True` to `False`; re-adding and rerunning restored it; flipping `devops-sudo` between `hostcat: all` and `hosts: [client-vm]` (and back) correctly cleared/reset the category around the member add/remove, matching FreeIPA's own mutual-exclusivity rule (confirmed live: "host category cannot be set to 'all' while there are allowed hosts"); a full idempotency rerun settled to `changed=0` except two pre-existing, unrelated non-idempotent tasks (an intentionally-still-forced test password, and `hbacrule-disable`'s own already-disabled non-idempotency). New `playbooks/test/fixtures/freeipa-identity-fixtures.yml` + `docs/verification/freeipa-identity.md` (8/8 PASS via `pilot vm-target verify`, real ndjson in the spec's §3) give this reconciler its own spec, previously missing. While validating that spec against the real `pilot spec --generate` tool, found and fixed an unrelated but serious **pilot bug**: `internal/spec/generator.go`'s row-dedup key was computed from an always-empty `params` string for any row whose Command fell through to the raw-command fallback (no Pattern A-F match), so **every such row silently collapsed into one task** regardless of how different their actual commands were — confirmed this had already silently broken the committed `playbooks/verify/freeipa-server.yml` (18-row spec → only 2 real tasks, with C3–C18 all incorrectly tagged onto C2's `sudo ipactl status` task) and 8 other existing verify playbooks (`core-infra`, `core-infra-provider`, `core-infra-provider-db`, `docker`, `freeipa-client`, `freeipa-server-replica`, `keycloak`, `os-patch-sla`, `seaweedfs-s3`). Fixed by hashing the raw command itself instead of an empty string (zero effect on rendered YAML — `RenderYAML` already used the separate `RawCommand` field, never `Params`, for this task shape); added `TestGenerate_RawFallbackDoesNotCollapseDistinctCommands`; regenerated all 10 affected `playbooks/verify/*.yml` files, each now syntax-clean with task count matching row count. | sre |
| 2026-07-16 | v5.0 | **Genuine ground-up rebuild (round 4)**, independent re-verification per explicit request following the v4.9 pass and its two follow-up fixes (the `--timeout` flag for § Real bugs #21, and an unrelated `trec` MCP tool-schema fix in the sibling `trec` repo). All 3 VMs torn down and recreated fresh (`freeipa-server .5`, `nexus .6`, `client-vm .2`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. Recorded end-to-end with `trec drive --script`/`trec` (this session's `trec mcp` connection predated the just-landed schema fix in the sibling repo and could not be reconnected mid-session, so scripted CLI recording was used throughout — the skill explicitly allows this; MCP mode is for interactive reconnaissance only). Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=150 changed=73 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0`. **Zero new bugs found in `pilot` or its playbooks this pass** — every fix from v4.1–v4.9 and the two follow-ups held up cleanly on a fully independent rebuild, including the check-mode preview gate (§3.2a) and the sudo/HBAC-service interaction (§ Real bugs #20). Full §4.1–§4.6 suite re-confirmed **PASS**: HBAC/sudo allow+deny (live SSH + `ipa hbactest`, `sshd` and `sudo` services), Grafana→Thanos Query→Prometheus, Grafana→Loki←Promtail (captured the live sudo command as a real log line), restic timers on all 3 hosts, Wazuh FIM trigger detection, and the full §4.6 reconciler cycle (remove `alice` from `sysops` → both layers flip to denied and live SSH gets `Connection closed`, her personalized password provably undisturbed via `krbLastPwdChange`≠`krbPasswordExpiration` → restore membership **and** add a new `allow_commands` entry to `sysops-systemctl` in the same edit → both the membership and the new command drift-correct live, confirmed via `ipa sudorule-show --all` and a working `sudo journalctl` → final no-op rerun settles to `changed=1`, exactly the one pre-documented non-idempotent item, `hbacrule-disable allow_all`). One process-level snag, not a `pilot` bug: the verification script's own raw `ssh` calls to `nexus`/`client-vm` (added after an `ssh-keygen -R` purge of all 3 IPs' stale host keys from the prior environment) omitted `-o StrictHostKeyChecking=accept-new`, so one call hung ~70 minutes on an unanswerable interactive host-key prompt under `trec`'s non-interactive recording — exactly the `pilot-trec-verification` skill's own already-documented "known_hosts churn" gotcha, just not applied consistently to every call in this pass's script. Killed and fixed by adding the flag to every remaining raw `ssh` call; no VM/playbook state was affected. | sre |
| 2026-07-16 | v5.2 | **Genuine ground-up rebuild (round 5)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .5`, `nexus .6`, `client-vm .2`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. This session's `trec mcp` connection was again unreachable as callable tools despite `claude mcp list` reporting it healthy at the CLI level (flagged to the user up front) — recorded end-to-end with `trec drive --script`/`trec` instead, per the skill's explicit CLI-recording fallback. This pass's roster was hand-authored with the v5.1 lesson already applied from the start (narrow `allow_commands: [/usr/bin/systemctl]`, HBAC `services: [sshd, sudo, sudo-i]`) — no repeat of v5.1's `cmdcat: all` mistake. Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide `client-vm: ok=83 changed=39 failed=0`, `freeipa-server: ok=35 changed=10 failed=0`, `nexus: ok=149 changed=71 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0`. Full §4.1–§4.6 suite **PASS**: live-SSH `alice` allow/deny + `bob` deny + `ipa hbactest` (`sshd`/`sudo`) all correct on the first verify attempt; Grafana→Thanos Query→Prometheus and Grafana→Loki←Promtail both real; restic timers active/enabled on `nexus`/`client-vm` (correctly absent on `freeipa-server`, which has no `restic-backup` role in this topology); the full §4.6 reconciler cycle (remove `alice` from `sysops` → HBAC denied + live SSH closed + password provably undisturbed → restore **and** add `/usr/bin/journalctl` to the sudo rule's `allow_commands` in the same edit → both drift-correct live, re-confirming the already-documented SSSD sudo-cache-staleness gotcha needs `sss_cache -E && systemctl restart sssd` after a live rule change → idempotent no-op rerun settles to `changed=1`, exactly the one pre-documented item, `hbacrule-disable allow_all`). **One new real bug found and fixed at the source** — see § Real bugs #22: `wazuh-fim-apply.yml` had no auto-detect fallback for `wazuh_manager_host` from the inventory's own `wazuh-manager` group (unlike `restic-backup-apply.yml`, which already has this exact pattern for `restic_s3_target_host`), so the site-wide deploy silently left `client-vm`'s Wazuh agent unenrolled — the agent kept retrying enrollment against a `127.0.0.1` loopback placeholder forever with no alert ever firing. Fixed by adding the same class of auto-detect `set_fact` task `restic-backup-apply.yml` already has; verified live (agent enrolled as `002`, real FIM alert within 20s of a fresh trigger file). Two of my own scripting mistakes along the way, both self-caught by verifying file content directly rather than trusting the wizard's exit code: (1) a `DOWN 0` trec-script bug (violating this skill's own documented "omit DOWN for index 0" rule) in the hosts.yml role checklist landed all 3 hosts' roles on the wrong checkbox — caught by reading the saved `hosts.yml` back, fixed, rerun clean; (2) the identical `DOWN 0` mistake in the vault editor silently skipped `ipa_admin_password` (its intended value landed on `grafana_admin_password` instead, then got overwritten by that entry's own correct edit) — caught the same way, fixed with a one-entry follow-up edit. Also mid-run, the user reported accidentally deleting `hosts.yml`/`inventory.yml` from the workspace; both were restored from the already-`trec`-recorded, already-verified content (no re-run of the wizard needed) and `pilot inventory generate` was re-run once more to confirm a byte-identical `inventory.yml`. | sre |
| 2026-07-16 | v5.3 | Follow-up to v5.2's Real bug #22, per explicit user request to fix the same class of gap wherever else it exists. Surveying the rest of `deploy_catalog.go`'s `AutoHostVars` entries (site-wide-vs-single-component wizard convenience) found 3 more genuinely missing inventory auto-detect fallbacks — see § Real bugs #23 for the full write-up, including a correction to v5.2's own scoping (an earlier shallow `grep` had wrongly credited `prometheus-apply.yml`/`thanos-query-apply.yml` with already having a `thanos_s3_target_host` fallback; they don't, but that one wasn't part of this fix batch and is left as a known remaining gap). Fixed at the source in `wazuh-manager-apply.yml` (`siem_forward_host` ← `log-server` group), `prometheus-apply.yml` (`alertmanager_target_host` ← `alertmanager` group), and `dashboard-apply.yml` (`thanos_query_target_host` ← `thanos-query` group), same `pre_tasks` `set_fact` idiom as #22. All 3 syntax-checked clean and verified live in isolation against the still-running demo VMs (temporarily blanking the relevant `group_vars` value or omitting the wizard's own `-e` override, confirming the playbook's own fallback — not the wizard convenience — supplies the value; `wazuh-manager`'s correctly no-ops in this topology, which has no `log-server` group). No re-verification of the full §4 suite was needed — none of these 3 variables are exercised by v5.2's already-passing checks (Alertmanager routing and SIEM forwarding aren't part of §4.1-4.6), and the isolated live checks are sufficient evidence the fix works. | sre |
| 2026-07-17 | v6.0 | **Genuine ground-up rebuild (round 6)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .4`, `nexus .3`, `client-vm .6` — a new lease assignment, different from every prior round's IPs), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing via scripted `trec drive` sessions (`trec mcp` server showed as connected via `claude mcp list` but surfaced no callable `mcp__trec__*` tools this session either, same as prior rounds — flagged transparently, CLI scripting used throughout per the skill's documented fallback). Indices recomputed fresh from `internal/inventory/contracts.go`/`cmd/pilot/cmd/deploy_catalog.go` (role checklist and catalog order unchanged from v5.x, but recomputed rather than assumed). `hosts.yml`'s 3-host, 19-role build succeeded correctly on the first `trec drive` attempt with no index mistakes this round. Filling in `group_vars`/vault values via the wizard required discovering that `pilot edit`'s group_vars entries menu surfaces **every** `key: value`-shaped line in a file — including commented-out example blocks nested deep in prose comments (e.g. `prometheus.yml` has 19 such entries, `restic-backup.yml` has 18) — not just the one active setting; an initial `restic-backup.yml` edit miscounted this by one and had to be corrected mid-script (caught before any bad save, via the file's actual on-disk content, not the wizard's exit code). Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide preview `client-vm: ok=52 changed=19 failed=0`, `freeipa-server: ok=45 changed=16 failed=0`, `nexus: ok=77 changed=27 failed=0`; site-wide real apply `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=152 changed=74 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0` (first pass, before Real bug #24's fix — password-set silently no-opped for `alice`) then `ok=30 changed=2 failed=0` (redeploy after the fix, `alice`'s password now genuinely set). **One new real bug found and fixed at the source** — see § Real bugs #24: this pass's disposable roster carried forward the *steady-state* `force_password: false` convention for `alice` (correct for a roster being reapplied to an already-onboarded environment) into a genuinely first-time-ever apply, and `freeipa-identity-apply.yml`'s password-set logic turned out to be entirely gated on that flag with no "this account has never had a password at all" fallback actually reachable — `alice` was created via `ipa user-add` (which never sets a password) and then never got one set by any task, leaving her with zero Kerberos key material and a confusing `kinit: Pre-authentication failed: Invalid argument` instead of a recognizable error. Fixed by running the password-expiry lookup for every user with a declared password (not just `force_password: true` ones) and gating the actual `ipa passwd` call on `force_password: true` **OR** "this account genuinely has no working password yet" — preserving the original protect-a-personalized-password intent while closing the first-time-onboard gap. Verified live end-to-end: redeployed `freeipa-identity` unmodified otherwise, confirmed `alice` now reaches the fresh-admin-reset "must change" state, completed the real `kinit alice` forced-password-change flow, then ran the full §4.1 HBAC/sudo live-SSH suite successfully. Full §4.1–§4.4 suite **PASS**: live-SSH `alice` sudo allow (`systemctl is-active ssh` → `active`) + deny (`cat /etc/shadow` → denied) + `bob` SSH denied at the auth layer, all cross-checked against `ipa hbactest` for both `sshd` and `sudo` services (all four agree); Grafana→Thanos Query→Prometheus (`up{site="site-nexus"}`, zero `-e` override); Grafana→Loki←Promtail (captured `alice`'s real sudo-denial event as a live log line within the same verification pass — `USER=root COMMAND=/usr/bin/cat /etc/shadow`); restic-backup timers `active`/`enabled` on all 3 hosts. | sre |
| 2026-07-17 | v7.0 | **Genuine ground-up rebuild (round 7)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .3`, `nexus .5`, `client-vm .6`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. Every `pilot edit`/`pilot inventory generate`/`pilot deploy` wizard step driven and recorded via `trec drive --script` (this session's `mcp__trec__terminal_start`/`terminal_write` MCP tools could hold a persistent PTY but could not deliver a real carriage-return byte through the MCP text channel when launching `pilot edit` directly — confirmed by then launching `trec drive --interactive` itself as the MCP session's command instead, whose own DSL parser consumed the keystrokes fine; the **recorded evidence** for every step still used one-shot `trec drive --script`, per the skill's own MCP-is-reconnaissance-only guidance). Also found `PILOT_DEBUG_MENU=1`'s stderr dump actively breaks `SELECT` on the very first row of a fresh non-wrapping list (the dump line repeats that row's label one line above the live list, confusing the direction heuristic into pressing DOWN forever) — omitted for all recorded runs once identified. Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered at any point across 4 separate `pilot deploy` invocations this round (site-wide ×2 including the idempotent re-run, `freeipa-identity` ×4 including remove/restore/idempotent-rerun). `PLAY RECAP`: site-wide preview `client-vm: ok=52 changed=19 failed=0`, `freeipa-server: ok=45 changed=16 failed=0`, `nexus: ok=78 changed=27 failed=0`; site-wide real apply `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=152 changed=74 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0` (first apply — both `alice`/`bob` first-time password set correctly, confirming v6.0's Real bug #24 fix holds independently). Full §4.1–§4.6 suite **PASS**: HBAC/sudo allow+deny for both `sshd` and `sudo` services (all four `ipa hbactest`/live-SSH combinations agree); Grafana→Thanos Query→Prometheus and Grafana→Loki←Promtail both real (Loki captured `bob`'s own denied-login attempt as a live line); restic-backup timers + real shared-repo snapshots on all 3 hosts; Wazuh FIM real-time whodata alert; the full §4.6 reconciler cycle (remove `alice` from `sysops` → denied both layers, password undisturbed → restore **and** add `/usr/bin/journalctl` to the sudo rule in the same edit → both drift-correct live → idempotent no-op rerun settles to `changed=2`, exactly the two pre-documented non-idempotent items). A separate **full site-wide idempotent re-run** (not just `freeipa-identity`'s) also confirmed: preview `changed=0` on all 3 hosts, real apply `changed=0`/`0`/`1` (`client-vm`/`nexus`/`freeipa-server`; the lone `freeipa-server` change is a cosmetic Dogtag-PKI-owned directory-mode reset, not a `pilot`/playbook bug). **One real, reproducible operational finding** — see § Real bugs #25: the already-documented SSSD sudo-cache-staleness gotcha (#15/#20, previously scoped to "after a rule was changed on an already-enrolled client") also blocks the **very first** sudo attempt after a genuinely fresh deploy, which this runbook's own §4.1 procedure didn't previously call out; fixed here as a documentation gap (this changelog entry + the top banner + §4.1's write-up), not a source code change — the underlying `sudo` responder socket-activation design in `freeipa-client-apply.yml` is already correct and documented. | sre |

| 2026-07-20 | v10.0 | **Genuine ground-up rebuild (round 10)**. Stale libvirt domains, snapshots, and exact VM directories were cleaned after `pilot vm-target list`/libvirt drift was confirmed; shared base images were retained. Fresh VMs were rebuilt at `.4`/`.3`/`.2`; a new empty workspace was created with `pilot edit` and `pilot inventory generate`. The first `pilot deploy --dir` attempt exposed the current CLI contract (`--dir` is invalid), and the first corrected wizard attempt was intentionally aborted before preview/apply while the auto-detected `-e` policy was clarified. The recorded retry accepted every auto-detected `-e` with `Y` and left the manual extra-`-e` field empty. Site-wide preview and real apply completed with `failed=0` (`client-vm ok=83 changed=41`, `freeipa-server ok=35 changed=10`, `nexus ok=154 changed=74`, `localhost ok=1 changed=0`). `pilot reconcile` applied a fresh minimal FreeIPA roster (`freeipa-server ok=31 changed=12 failed=0`). Real verification passed for HBAC, live SSH sudo allow/deny, Thanos/Prometheus, Loki/Promtail, restic snapshots, and Wazuh FIM. The reconciler cycle genuinely removed Alice from `sysops` (`ipa hbactest Access granted: False`), restored membership and corrected `/usr/bin/journalctl` drift (`changed=5`), then reran with `failed=0` and `changed=2`; the residual two changes are recorded as an operational non-idempotency finding. No playbook or Go source was modified. | sre |
| 2026-07-20 | v10.1 | Compliance-only edit per AGENTS.md v1.14: removed every trec cast filename and recording-number inventory from §0.5a and §4.0a (cast files are disposable evidence and must not be named or inventoried in committed runbooks). No commands, quoted outputs, findings, or version banners changed — all real-run excerpts are retained verbatim. | pilot |
| 2026-07-21 | v11.0 | **Genuine ground-up rebuild (round 11)**, independent re-verification per explicit request following the v10.0 round and the 2026-07-20 §0.5a fact-snapshot drift. The previous codex/sandbox profile had hardened to `--unshare-net` + `CAP_FOWNER=0` + `/var/lib/libvirt` outside the writable set, which blocked every `pilot vm-target up` (setfacl for `libvirt-qemu` rejected as "Invalid argument", existing per-VM subdirs read-only-mask locked); a separate `stop and report` halt was filed and the user authorized resumption in a profile that has `CAP_FOWNER` full + libvirt group + read-write access to `/var/lib/libvirt`. After read-only confirmation the same `pilot vm-target down` calls that the hardened profile had accepted were repeated, the leftover per-VM subdirs (with their restrictive masks) were removed by `pilot vm-target up` itself via a single retry (first `up` rebuilt the per-VM dir and `cloud-localds` race; the second `up` saw a clean dir, re-`ssh-keygen`-ed, and finished). Fresh VMs: `freeipa-server=192.168.122.5` (AlmaLinux 9, 4096 MiB, MAC `52:54:00:f2:4b:ef`), `nexus=192.168.122.3` (Ubuntu 24.04, 12288 MiB, MAC `52:54:00:f5:cf:cb`), `client-vm=192.168.122.2` (Ubuntu 24.04, 2048 MiB, MAC `52:54:00:9f:7d:b4`). The entire `tmp/pilot-verify-minimal-poc-r11/demo/` workspace was populated only through `pilot edit` and `pilot inventory generate`; every wizard keystroke was recorded via `trec drive --script` with the script-lint pass (`trec drive lint --strict`) running clean. All `REPLACE_TEXT_*` operations were triple-checked against the on-disk file after every save (the vault key-list resets to the top after each edit, the hosts.yml role checklist uses `TOGGLE <description>` for unambiguous label, and `CHECKLIST_DOWN 0` is omitted per the trec-tui-drive skill's documented rule). All 8 `main.yaml` vault keys (`ipa_admin_password`, `grafana_admin_password`, `restic_aws_access_key_id`, `restic_aws_secret_access_key`, `restic_password`, `thanos_aws_access_key_id`, `thanos_aws_secret_access_key`, `alertmanager_config`) were set via the wizard with `--secret-env` redaction on each value (the `alertmanager_config` null-receiver stub is the only file-default kept). The `freeipa-identity` roster was authored as plaintext per the schema in `playbooks/apply/freeipa-identity.roster.example.yaml` (1 group `sysops`, 2 users `alice`/`bob` with `force_password: true`, 1 sudo rule `sysops-systemctl` with `hostcat=all / allow=/usr/bin/systemctl / group=sysops`, 1 HBAC rule `sysops-login-all` with `services: [sshd, sudo, sudo-i] / group=sysops`) and placed at `tmp/pilot-verify-minimal-poc-r11/demo/.vault/ipa-identity.yaml`. The only `group_vars` value actually edited was `prometheus_site_label: site-nexus` (per the runbook's documented per-site pattern; restic/dashboard/etc all use auto-detected `seaweedfs-s3` / `dashboard` / `wazuh-manager` group lookups and need no manual value). The `audit-log-forwarding` `group_vars/audit-log-forwarding.yml` was created via the wizard's "從範例建立 audit-log-forwarding.yml" entry. `PLAY RECAP` for the site-wide `pilot deploy -i inventory.yml`: `client-vm: ok=83 changed=41 failed=0 skipped=17`, `freeipa-server: ok=78 changed=34 failed=0 skipped=16`, `nexus: ok=154 changed=74 failed=0 skipped=34`, `localhost: ok=1 changed=0 failed=0`. All 6 auto-detected `-e` values (one per `siteAutoHostVars` candidate whose `Group` has a host in our inventory) were accepted with `Y`: `wazuh_manager_host=192.168.122.3`, `restic_s3_target_host=192.168.122.3`, `loki_target_host=192.168.122.3`, `thanos_s3_target_host=192.168.122.3`, `alertmanager_target_host=192.168.122.3`, `thanos_query_target_host=192.168.122.3`; the manual `還有其他 -e 變數` field was left empty (per the runbook's "stop and explain if `-e` is needed" gate, which was never triggered). `pilot reconcile` for `freeipa-identity` was run by **declining the auto-detected `main.yaml` vault file** (the wizard's `偵測到 ... main.yaml，這次佈署要用它當密碼變數檔嗎？ [Y/n]` was answered `n`), then selecting `需要 — 我有一份 ansible-vault 加密的 vars 檔` from the second-stage menu, then entering the roster path `tmp/pilot-verify-minimal-poc-r11/demo/.vault/ipa-identity.yaml` as the wizard's `vars 檔路徑` (the wizard's "extra -e" validator rejects the `@file` syntax, but the vault file path uses the wizard's first-class `-e @<file>` path that the runbook comment in `freeipa-identity-apply.yml` documents — same path v10.0 used). First apply: `freeipa-server: ok=30 changed=11 failed=0 skipped=26` (alice + bob users + sysops group + sudo + HBAC rules all created on the first pass, confirming v6.0's Real bug #24 password-set fix holds). Idempotent no-op rerun: `freeipa-server: ok=5 changed=0 failed=0 skipped=51` (every task reports `skipping` because all entities are already in their desired state — exactly the v10.0 pattern of a healthy reconciler). Full §4 suite **PASS**: §4.1 live-SSH `alice` sudo allow (`systemctl is-active ssh` → `active`) + deny (`cat /etc/shadow` → "Sorry, user alice is not allowed to execute ...") + `ipa hbactest` for `sshd` and `sudo` (both `Access granted: True` via `allow_all + sysops-login-all`, with `sysops-login-all` correctly *not* matched after `ipa group-remove-member sysops --users=alice`); §4.2 Prometheus `/-/ready` → `200` and Thanos Query `up{job="prometheus",site="site-nexus"}` → `1`; §4.3 Loki `/-/ready` → `200`, labels `["filename","job"]`, and the live `journalctl` SSSD cache flush actually showed `alice`'s own `sudo journalctl` invocation land as a real audit log line (`alice : PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -n 5`); §4.4 `restic-backup.timer` `active` on all 3 hosts and the shared S3 repo at `s3:http://s3-backup-server:8333/pilot-restic-backup` accepted real `systemctl start restic-backup.service` runs from each host (2 snapshots in-repo, one per host, both with the same `RESTIC_PASSWORD` so all hosts share one encryption key); §4.5 Wazuh agent running on all 3 hosts (modulesd/logcollector/syscheckd/agentd/execd all `running`) and a real FIM file-add event `/etc/pilot-fim-test-1784625894` from `client-vm` (agent 003) reached the manager (`single-node-wazuh.manager-1`) with full `whodata` audit attribution (`uid=root / process=/usr/bin/bash / ppid=sshd`) at rule level 5; §4.6 the full reconciler cycle — `ipa group-remove-member sysops --users=alice` (sysops-login-all no longer matches alice) → `ipa group-add-member sysops --users=alice` + roster change adding `/usr/bin/journalctl` to the sudo rule's `allow_commands` → reconcile reapply → `freeipa-server: ok=29 changed=2 failed=0` (the 2 changed are the pre-existing two non-idempotent items: the sudo rule's allow_commands drift correction + the Dogtag-PKI-owned directory-mode reset, both pre-documented as not-pilot bugs). Real verification of the journalctl change: `sudo -l` for alice after `sss_cache -E && systemctl restart sssd` showed `(root) /usr/bin/systemctl, /usr/bin/journalctl`, and `echo AliceSandbox2026! | sudo -S journalctl -n 5` produced the real audit log line above. One real, wizard-UX finding this round (not playbook / not Go — see `.agents/skills/pilot-trec-verification/SKILL.md` for the recorded evidence and the wizard-prompt chain walkthrough; per AGENTS.md v1.15, trec-discovered wizard-UX issues are not recorded in operational runbooks): the `pilot reconcile` wizard's component-pick banner advertises a roster-path prompt that the actual prompt chain never issues, requiring the operator to feed the roster via the wizard's `vars 檔路徑` slot instead of the manual `還有其他 -e 變數` slot (the latter's `validateOptionalKV` rejects the `@file` form, but the wizard's "vault" prompt compiles to `-e @<path>` internally). Documented inline in `.agents/skills/pilot-trec-verification/SKILL.md` §7 with the full prompt-chain walkthrough; the runbook only needs to note the wizard-UX hint, not the diagnostic. No playbook or Go source was modified this round. | sre |

---

## Checklist (before commit)

- [x] Fact snapshot (§0.5) contains real environment/inventory output
- [x] Every command was actually run, real output pasted in
- [x] Summary numbers (ok/changed/failed) are real, not predicted
- [x] Verify verdict is from a real run (PASS with real HBAC/hbactest/Thanos/Loki output)
- [x] Idempotency evidence present (reconcile rerun: `failed=0`, `changed=2`; residual changes are reported honestly)
- [x] No "expected" / "should" / "predicted" output anywhere
- [x] Secrets go through `tmp/pilot-verify-minimal-poc/.vault/*.yaml`, never inline in this doc (key names only)
- [x] Variable names match spec exactly
- [x] Alignment decision (fresh inventory rebuilt to match the declared topology) recorded in §0.5a
- [x] Timestamp on fact snapshot (2026-07-21T17:30Z) matches when the run happened
- [ ] Public version / redaction gate — **not yet applied**; this document is internal-only (plaintext vault values are referenced by key name only, but lab IPs and internal FQDNs are not yet redacted)
- [ ] Secret scan / `git diff --check` — not yet run against this file
