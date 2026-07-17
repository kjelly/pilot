# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Date: 2026-07-17 (UTC), latest pass: round 7 / v7.0
> Aligned spec: `docs/verification/freeipa-server.md`, `freeipa-client.md`,
> `docker.md` (`core-infra-provider.md` `infra_role=docker`),
> `seaweedfs-s3.md`, `prometheus.md`, `thanos-query.md`,
> `alertmanager.md`, `dashboard.md`, `log-shipping.md`,
> `wazuh-manager.md`, `wazuh-fim.md`, `audit-log-forwarding.md`,
> `restic-backup.md`, `freeipa-identity`(roster-driven, no standalone spec)
> Automation: `playbooks/site.yml` (one-shot site-wide deploy — as of v2.3
> this includes `log-shipping`, auto-targeted at the `log-server` group if
> populated else `wazuh-manager`) + `playbooks/apply/freeipa-identity-apply.yml`
> (still intentionally excluded from site.yml, data-driven day-2 roster,
> run as a separate `pilot deploy` invocation) + `tmp/pilot-verify-minimal-poc/{hosts.yml, inventory.yml,
> group_vars/, .vault/}` (`pilot inventory generate` output, disposable
> workspace under the repo's gitignored `./tmp/`, not the tracked project tree)
> Maintainer: sre
> Publication: internal only — contains plaintext sandbox secrets
> (`tmp/pilot-verify-minimal-poc/.vault/*.yaml`) and lab-only IPs; do not
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
> **final recorded evidence** for every wizard step still went through
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

---

## 0. One-line goal

Re-verify the minimal-PoC 3-VM demo (AlmaLinux FreeIPA identity server,
Ubuntu Docker+Wazuh+Grafana monitoring host — this pass names it `nexus`,
not `monitor-vm` — Ubuntu simulated end-user client) using only `pilot
edit` / `pilot inventory generate` / `pilot deploy` — no hand-edited
inventory YAML, no direct `ansible-playbook` calls — deploying **every**
wired role in **one** `pilot deploy` "全站部署(site.yml)" invocation
instead of one role at a time, plus the one component `site.yml`
structurally excludes (`freeipa-identity`, a data-driven day-2 roster) as
a separate single-component invocation — `log-shipping` was folded into
the site-wide run in v2.3 (see Changelog). Also widens `wazuh-fim` and
`audit-log-forwarding` to all three hosts (a prior build only wired them
to the client), and re-confirms both original verification goals: (1)
FreeIPA HBAC/sudo permission management enforces allow **and** deny, (2)
client log and site metric are both queryable from Grafana.

**Recording mode is decided per command** (see §3.2 for a worked
example of the two side by side): a command that will **prompt for
keystrokes** (`pilot edit`, `pilot deploy` — both interactive wizards)
is driven and recorded with `trec drive --interactive`, sending one op
at a time and reading the real rendered screen back before deciding the
next op. A command that **runs to completion on its own with no prompts
to answer** — a one-shot wizard step like `pilot inventory generate`, or
a read-only verification check (`ssh`/`curl`/`ipa hbactest`) — is
recorded with plain `trec` instead, since there is nothing for `drive`
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
live via `trec drive --interactive`'s own asciicast output; the deploy
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
  `trec drive` (scripted keystrokes, recorded as asciicast v2) — see the
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

Recordings: `01-edit-hosts.cast`, `02-inventory-generate.cast`,
`03-edit-group-vars.cast` (includes the `.vault/main.yaml` fill-in — one
continuous `pilot edit` session covers both group_vars/ and .vault/).

### 3.2a Mandatory deployment gate (v4.1, 2026-07-16)

Do **not** turn a failed or inconvenient wizard step into a skipped one. The old static `deploy-site.trec` skipped preflight, answered `n` to the preview, and used `EXPECT_QUIET` as a long-running apply completion signal. That is invalid: `EXPECT_QUIET` is not a child-process completion test. Drive a deploy in one persistent `trec drive --interactive` session; after confirming apply, send no further operation and let the child process end naturally.

Before deploying, the generated inventory and vault inputs must satisfy these gates:

- Run the complete preflight; do not choose its skip option. Every host needs `ansible_user` and a reachable SSH key.
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

Recordings: `04-deploy-site.cast`, `05b-deploy-freeipa-identity-fix.cast`
(the corrected re-run; `05-deploy-freeipa-identity.cast` is the failed
first attempt, kept for the historical error evidence), plus
`07-fix-sshd-password-auth.cast` / `07b-fix-sshd-password-auth-order.cast`
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

Recordings: `04-deploy-site.cast`, `05-deploy-freeipa-identity.cast`,
`06-deploy-log-shipping.cast` (historical, v2.0), `10-deploy-site-merged-log-shipping.cast`
(v2.3, `log-shipping` folded into the site-wide run), `11-reverify-deploy-site.cast`,
`12-reverify-deploy-freeipa-identity.cast`, `14-reverify-deploy-freeipa-identity-force-password-false.cast`
(v2.4 re-verification pass — see Changelog).

### 3.4 v7.0 — round 7 deploy results (2026-07-17, current)

Built via `trec drive --script` (not `--interactive` — see the v7.0 top
banner note) against the fresh `.3`/`.5`/`.6` environment: `pilot edit`
for `hosts.yml` (3 hosts, 19-role checklist per host, cast
`01-edit-hosts.cast`), `pilot inventory generate` (cast
`02-inventory-generate.cast`), `pilot edit` for `group_vars/`
(`freeipa_server_ip`, `prometheus_site_label`, `thanos_s3_target_host`
×2, `thanos_query_target_host`, `restic_s3_target_host`,
`wazuh_manager_host` — cast `03-edit-groupvars.cast`) and `.vault/main.yaml`
(cast `04-edit-vault.cast`, secrets via `TEXT_ENV`/`--secret-env`, never
in the recording). `.vault/ipa-identity.yaml` was hand-authored per the
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

Cast: `05-deploy-site.cast`. Wall clock: ~17.5 min (preflight+preview+apply
combined, one `pilot deploy` session).

`freeipa-identity` (single component, target group default `freeipa-server`,
vault: explicit `.vault/ipa-identity.yaml`, **zero** extra `-e`):

| Phase | freeipa-server |
|---|---|
| Preview | ok=4 changed=0 failed=0 |
| Real apply | ok=30 changed=12 failed=0 |

Cast: `06-deploy-freeipa-identity.cast`. Both `alice` and `bob` (first-time
onboard, `force_password: true`) got real passwords set (`changed` ×2 on
the "Set password for users that need one" task) — confirms the v6.0
Real bug #24 fix holds on an independent fresh rebuild.

**Idempotency — full site-wide re-run, no roster/group_vars changes**
(cast `13-deploy-site-idempotent-rerun.cast`):

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

## 4. Verify (v7.0, round 7 — 2026-07-17, current)

`alice` and `bob` were both first-time onboards this round
(`force_password: true`), so both landed in FreeIPA's fresh-admin-reset
"must change" state after `freeipa-identity`'s real apply — confirmed via
`ipa user-show alice --all --raw` showing `krbLastPwdChange` ==
`krbPasswordExpiration` (`20260717043700Z` for both). Personalized
`alice`'s password with the documented scripted `kinit` forced-change
flow (cast `07-kinit-alice.cast`, secrets via `TEXT_ENV`/`--secret-env`,
never in the recording):

```bash
$ trec drive --script kinit-alice.txt --secret-env ALICE_TEMP_PW --secret-env ALICE_NEW_PW \
    -o 07-kinit-alice.cast -- ssh -t -o StrictHostKeyChecking=accept-new \
    -i /var/lib/libvirt/images/pilot/client-vm/id_ed25519 root@192.168.122.6 kinit alice
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

First attempt (cast `08-verify-4.1-4.5.cast`) surfaced § Real bugs #25 —
both of `alice`'s live-SSH sudo commands failed with `alice is not
allowed to run sudo on client-vm` despite `ipa hbactest --service=sudo`
already reporting `Access granted: True`. `sss_cache -E && systemctl
restart sssd` on `client-vm` (the already-documented Real bug #15/#20
workaround) fixed it; re-ran clean (cast
`09-verify-4.1-retry-alice-sudo.cast`):

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
end-to-end, entirely from group_vars, cast `08-verify-4.1-4.5.cast`.

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
trigger, cast `08-verify-4.1-4.5.cast`.

### 4.6 FreeIPA identity reconciler — remove / restore+drift / idempotency

Full cycle re-verified live on this round's fresh roster, per the
`delivery-test` skill §4.6 (casts `10-deploy-freeipa-identity-remove-alice.cast`,
`11-deploy-freeipa-identity-restore-and-drift.cast`,
`12-deploy-freeipa-identity-idempotent-rerun.cast`):

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
| 5 | The role-checklist wizard's PTY-driving `trec` recordings needed a real fix mid-session: `promptui.Prompt{AllowEdit:true}` pre-fills the current value with the cursor at the end, so plain typing **appends** instead of replacing — caught when `freeipa_server_ip` came out as `192.0.2.10192.168.122.4` (placeholder + new value concatenated). | `BACKSPACE <n>` (n ≥ the placeholder's length) before typing the replacement — see `02b-fix-freeipa-ip.cast` for the corrective re-run. |
| 6 | Discovered during the v2.4 re-verification pass: `freeipa-identity-apply.yml`'s "Set initial password for users" task runs `ipa passwd <user>` unconditionally whenever `force_password` isn't explicitly `false` on that roster entry (see the playbook's own comment at the task above it). FreeIPA's `ipa passwd` is an **admin reset** — it always marks the target account as requiring a password change at next login, regardless of whether the same password value was already set. Redeploying `freeipa-identity` therefore silently reset `alice`'s already-completed permanent password back into a "must change" state every time, breaking the plain-`sshpass` live-SSH allow-test in §4.1 with a bare `sshpass` exit 5 (no readable error) — while `ipa hbactest` kept reporting the correct allow/deny verdict throughout, since it evaluates policy, not live credential state. Not a playbook bug — this is expected, intentional FreeIPA/`ipa passwd` behavior, and the reconciler comment already documents the escape hatch. | Not a code fix. Set `force_password: false` on `alice`'s roster entry (`tmp/pilot-verify-minimal-poc/demo/.vault/ipa-identity.yaml`) now that she's already onboarded with a real out-of-band password, so future `freeipa-identity` re-applies skip resetting her — verified by redeploying once more and confirming the task now reports `skipping` for `alice` instead of `changed` (cast `14-reverify-deploy-freeipa-identity-force-password-false.cast`), then a full clean §4.1 re-pass (cast `15-reverify-verify-final.cast`). `bob` intentionally keeps the default, since his test case requires no completed credential. **Superseded by v4.5** (see Changelog): `force_password` now defaults to `false`, so the escape hatch described here is opt-**in** (`force_password: true`) rather than opt-out — an already-onboarded user no longer needs an explicit `false` line to be safe from an accidental reset; only a roster entry that still says `true` gets reset on rerun. |
| 7 | (v3.0) `freeipa-server-apply.yml` required `-e freeipa_dns_forwarders=<ip>` every single run — the underlying variable had **no usable default** (fell back to an empty list, i.e. `--no-forwarders`), so a from-scratch deploy with zero `-e` would leave the FreeIPA host's own `named` unable to resolve the public internet for its own package installs. There was also no way to configure NTP servers for `ipa-server-install` at all (only the on/off `--no-ntp` toggle existed). | **Fixed at the source in v3.0**: `freeipa_dns_forwarders` now defaults to `8.8.8.8` (still group_vars/`-e`-overridable) instead of no-forwarders. Added a new `freeipa_ntp_servers` variable (default `[tock.stdtime.gov.tw, watch.stdtime.gov.tw]`, Taiwan's public stratum servers) passed to `ipa-server-install` as `--ntp-server=...`. Both documented in `group_vars/freeipa.example.yml`. Verified for real: the v3.0 site-wide deploy passed **zero** `-e` at all beyond `stage`/`patch_stage`/vault and still came back `failed=0` on `freeipa-server`. |
| 8 | (v3.0) My own hand-authored `.vault/ipa-identity.yaml` roster used the wrong field names on the first attempt — `uid`/`usergroups`/`commands` instead of the actual schema's `name`/`groups`/`allow_commands` (per `playbooks/apply/freeipa-identity.roster.example.yaml`). Not a playbook bug; the reconciler's own error was clear (`object of type 'dict' has no attribute 'name'`, `failed=1`) and pointed straight at the mismatch. | Rewrote the roster against the actual example schema and re-ran; `freeipa-server: ok=21 changed=15 failed=0` on the corrected pass (cast `05b-deploy-freeipa-identity-fix.cast`). A reminder that even the one tool-endorsed hand-authored file still needs checking against its own example template, not memory. |
| 9 | (v3.0) Live SSH allow/deny testing in §4.1 initially failed for **all three** test lines (`alice` allow, `alice` deny, `bob` deny) with an identical generic `Permission denied (publickey,gssapi-keyex,gssapi-with-mic,keyboard-interactive)` — `password` wasn't even offered as a method. Root cause: `ipa-client-install`'s own `sshd_config.d/04-ipa.conf` only sets `ChallengeResponseAuthentication` (the deprecated `KbdInteractiveAuthentication` alias) — it never touches `PasswordAuthentication` — and Ubuntu's cloud image ships `sshd_config.d/50-cloud-init.conf`/`60-cloudimg-settings.conf`, both forcing `PasswordAuthentication no`. sshd's `Include` splices every matched drop-in in at the `Include` line in **glob (lexical) order**, then keeps only the **first** value seen for each directive across the whole expanded config — so `50-`/`60-` (sorting before any `9x-`-style override) permanently won regardless of what a later-sorting drop-in said. A FreeIPA account with no SSH key yet (the common case for a brand-new user) could never log in with a password at all, independent of HBAC. | **Fixed at the source in v3.0**: `freeipa-client-apply.yml` now writes its own `sshd_config.d/05-freeipa-client-password-auth.conf` (forcing `PasswordAuthentication yes` + `KbdInteractiveAuthentication yes`) — deliberately named to sort **after** `04-ipa.conf` (so it doesn't fight `ipa-client-install`'s own file) but **before** `50-`/`60-` (so it actually wins, per sshd's first-occurrence-wins semantics), and restarts sshd (`ssh` on Debian/Ubuntu, `sshd` on EL) only when the drop-in changes. First attempt used a `99-`-prefixed name and was silently ineffective (`sshd -T` still showed `passwordauthentication no` after a full apply+restart) — caught by directly checking `sshd -T`'s *effective* config rather than trusting the apply's `changed: true`, which is what led to discovering the ordering rule in the first place. Verified for real after the `05-` fix: `sshd -T` shows `passwordauthentication yes`/`kbdinteractiveauthentication yes`, and the full §4.1 live-SSH suite passed cleanly (cast `06d-reverify-hbac-ssh.cast`). |
| 10 | (v4.0) A hand-authored `ipa-identity.yaml` included a per-user HBAC rule (a rule with `services: [sshd]` and an explicit `users: [alice]` line). The `Ensure HBAC rules exist` task creates the rule with the default `usercat=all` (the playbook's command builder never sets `--usercat=`); the subsequent `Attach users to HBAC rules` task then fails with `ipa: ERROR: users cannot be added when user category='all'` and a `failed=1` on the whole play. The FreeIPA rule model requires either a non-`all` `usercat` or dropping the per-user `users:` line entirely. Not a playbook bug — an undocumented sharp edge in the rule-creation default; the tool-endorsed example roster (`playbooks/apply/freeipa-identity.roster.example.yaml`) only shows group-scoped rules, so the per-user form's `usercat` interaction is the author's own responsibility to get right. | Dropped the per-user rule; kept only the group-scoped `allow-sysops-ssh` rule (`groups: [sysops]`). Re-ran; `freeipa-server: ok=18 changed=6 failed=0` on the corrected pass (cast `10d-deploy-freeipa-identity.cast`). |
| 11 | (v4.0) After fixing #10, `bob`'s SSH login was believed to be denied by HBAC, but this was **never actually verified with `ipa hbactest`** — the only evidence recorded was a `ssh -o BatchMode=yes` attempt with no credential supplied, which fails identically for *any* user regardless of HBAC policy (BatchMode disables all interactive credential prompting). Re-running `ipa hbactest --user=bob --host=client-vm.ipa.pilot.internal --service=sshd` for real returned **`Access granted: True`**, matched via the built-in `allow_all` rule — the roster had set `ipa_hbac_disable_allow_all: false` (with a comment explicitly noting "allow_all permits everyone, which is fine for this demo" — it is not: it defeats the demo's own stated goal of proving deny works). After disabling `allow_all`, `bob` was *still* granted — this time via a **second** built-in rule, `allow_systemd-user` (`usercat=all`, `hostcat=all`, `HBAC Services: systemd-user, sshd` — a FreeIPA default meant to let `pam_systemd` create a user session, but its services list includes `sshd` directly, so it grants blanket SSH access to everyone exactly like `allow_all` does, as a side effect of its own unrelated purpose). Disabling `allow_all` alone is **not sufficient** for a real per-group SSH access-control demo. | Set `ipa_hbac_disable_allow_all: true` in the roster and redeployed `freeipa-identity` (cast `16-fix-hbac-disable-allow-all.cast`, `freeipa-server: ok=19 changed=2 failed=0`), then disabled `allow_systemd-user` directly (`ipa hbacrule-disable allow_systemd-user` — a one-off manual step since the playbook has no variable for it; approved as a scoped mutating action). Re-verified for real: `ipa hbactest --user=alice` → `Access granted: True` (matched `allow-sysops-ssh`); `ipa hbactest --user=bob` → `Access granted: False` (no matched rules); live SSH with `bob`'s real password (not BatchMode) now gets cut off with `Connection closed by <ip> port 22` — the actual PAM/SSSD HBAC-denial signature (auth succeeds, access refused), not a credential-layer failure. |
| 12 | (v4.2 re-verification) `pilot vm-target up` stalled ~2m30s on `nexus` even though the VM was already booted and reachable over ping/SSH: `internal/vmtarget/vmtarget.go`'s `waitForIP` discovers the VM's IP via `domifaddr` (kernel ARP) and, as fallback, `net-dhcp-leases` — but `Up` had already reserved a **static** DHCP host mapping for this exact MAC (`allocateStaticIP`, `net-update add ip-dhcp-host`) before boot, and this environment's dnsmasq does not always write a dynamic leases-file entry for a statically-reserved MAC, while ARP can also lag. Both sources came up empty for the full boot timeout despite the VM genuinely being up and using its reserved address. Not an Ansible/playbook bug — this is in `pilot`'s own Go source. | **Fixed at the source**: `Up` now keeps the IP `allocateStaticIP` already returns (previously discarded) and passes it into `waitForIP` as a last-resort fallback — tried only when both `domifaddr` and `net-dhcp-leases` report nothing on an iteration, and only accepted once a short, bounded TCP dial to `reservedIP:SSHPort` independently confirms something is actually listening there (not just "we configured a reservation"), so a genuinely stuck/dead VM still times out exactly as before. New regression tests `TestWaitForIP_FallsBackToReservedIPWhenReachable`/`TestWaitForIP_ReservedIPUnreachableStillTimesOut` cover both the fixed stall and the still-must-fail case; the dial itself is an injectable `Manager.dialReachable` field (stubbed to `false` by default in tests) rather than real networking, to keep the suite deterministic — matching how `virsh`/`ssh` are already shimmed at the process level rather than in Go. Full `internal/vmtarget` suite green (`go test ./internal/vmtarget/...`). Workaround used before this fix: manually atomic-patch the statefile to set `status=running`/`ip=<reserved IP>`. |
| 13 | (v4.2 re-verification) A real site-wide `pilot deploy` failed at FreeIPA client enroll: `freeipa-client-apply.yml`'s `ipa_server_ip: "{{ freeipa_server_ip \| default(ansible_host) }}"` resolved to **the client's own IP** whenever `-e freeipa_server_ip` was omitted, because on the client-enroll play `ansible_host` is the client's own connection address, not the FreeIPA server's — pinning `ipa1.ipa.pilot.internal` to the wrong host in `/etc/hosts` and making `ipa-client-install` fail to find the server. The existing required-vars gate never caught it, since `ansible_host` is always defined and non-empty — just wrong. This broke the v3.0/v4.0 "site-wide deploy needs zero extra `-e`" claim. | **Fixed at the source (v4.3, see Changelog)**: auto-resolves from this inventory's `freeipa-server` group (`hostvars[groups['freeipa-server'][0]].ansible_host`) instead, same "explicit overrides inventory-derived, else fail loudly at the existing gate" idiom as `audit-log-forwarding-apply.yml`'s `siem_forward_inventory_host`. Verified for real: `freeipa-client-apply.yml --check --diff` with no `-e freeipa_server_ip` now correctly pins the real server IP, and the full site-wide preview stays `failed=0`. |
| 14 | (v4.2 re-verification) The live-SSH allow-test in §4.1 was blocked for `alice`: `freeipa-identity-apply.yml`'s "Set initial password" task runs `ipa passwd <user>` (an **admin reset**), which — by design, not a bug — always marks the account as requiring a password change at next login. A scripted/`sshpass`-only client can't complete that interactive forced change, so live SSH failed even though `ipa hbactest` correctly reported the right allow/deny verdict throughout (policy layer, not credential state). | **Not fixed at the source — documented as a known limitation.** This is intentional FreeIPA/Kerberos security behavior (see also Real bug #6, same underlying mechanism). The existing `force_password: false` escape hatch on an already-onboarded roster entry remains the right workaround once a user has a real out-of-band password. A fuller fix would mean a new roster flag driving an interactive `kinit`+`kpasswd` session (Ansible `expect`) to genuinely consume the forced change, plus targeted `sss_cache` invalidation — that's a real feature addition touching live Kerberos/SSSD state, out of scope unless separately requested. **v4.5 note**: `force_password` now defaults to `false` (see Changelog), which prevents an *accidental* reset on a routine rerun — but a roster entry that deliberately keeps `force_password: true` (e.g. to re-arm a test scenario, as `bob`'s did here) still hits this exact forced-change behavior by design; the default flip narrows when this bites, it doesn't remove the underlying FreeIPA/Kerberos behavior. **v5.1 note (2026-07-16, operationalized)**: the "fuller fix" scoped out above — an interactive `kinit`+`kpasswd` session to genuinely consume the forced change — was implemented as a real, repeatable procedure this pass, not a one-off manual step: a `trec drive --script` session drives `kinit alice`'s exact 3-line forced-change flow (current password / new password / retype) with both values passed via `TEXT_ENV`/`--secret-env` (never appearing in the recording). Deliberately reproduced the blocked state first via a direct out-of-band `ipa passwd alice` on the server (bypassing the roster entirely) to confirm a genuine block existed to fix — notably, redeploying `freeipa-identity` with `force_password: true` on an already-personalized `alice` did **not** reproduce it (`changed=1`, only the new sudo rule; the password task correctly `skipping`), confirming v4.8's Phase 0 protection now means this limitation only bites first-time onboarding or a genuine out-of-band admin reset, never a routine roster-driven redeploy. Post-kinit, `krbLastPwdChange`/`krbPasswordExpiration` diverged as designed, and both live-SSH commands (`sudo systemctl is-active ssh` → `active`; `sudo cat /etc/shadow` → denied) ran cleanly with the personalized password — see cast `09-kinit-alice-personalize.cast` and the runbook's §4 update below. |
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

| 25 | (round-7/v7.0 ground-up rebuild, 2026-07-17) §4.1's live-SSH sudo tests for `alice` both failed on the **very first attempt** right after a genuinely fresh site-wide + `freeipa-identity` deploy — `sudo -S systemctl is-active ssh`/`sudo -S cat /etc/shadow` both returned `alice is not allowed to run sudo on client-vm`, and `sudo -l -U alice` on the client agreed ("not allowed"), even though `ipa hbactest --user=alice --service=sudo` on the server already reported `Access granted: True` and `client-vm`'s `sssd.conf`/`nsswitch.conf` were both correctly configured (`sudoers: files sss`, `sudo_provider = ipa`, `sssd-sudo.socket` active and listening — `freeipa-client-apply.yml` deliberately does **not** list `sudo` in `services=`, since doing so breaks SSSD's socket-activated sudo responder on Ubuntu 24.04/sssd 2.9.4, a different, already-correct design documented inline in that playbook). This is the same underlying mechanism as the already-documented Real bugs #15/#20 (SSSD's sudo responder not immediately reflecting server-side rule state), but those were documented specifically for *"a rule was just changed on an already-enrolled client"* — this round reproduced it on a client that had **never** attempted a sudo lookup before at all, i.e. the golden-path first-ever verification pass, which the runbook's own §4.1 procedure didn't previously flag as needing the same refresh. | **Not a code bug — confirmed as expected SSSD behavior, same fix as #15/#20**: `sss_cache -E && systemctl restart sssd` on the client immediately unblocked it — `sudo -l -U alice` then correctly listed `(root) /usr/bin/systemctl`, and both the live-SSH allow (`active`) and deny (`Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' ...`) commands passed cleanly (cast `09-verify-4.1-retry-alice-sudo.cast`). **Documentation fix applied here**: §4.1 above and this runbook's top banner now call out that this refresh may be needed on the *first* sudo attempt after a fresh rebuild, not only after a later rule edit — closing the gap between what #15/#20 already knew and what a first-time reader of this runbook's own §4.1 steps would have hit blind. No `pilot`/Ansible source change proposed — the client-side socket-activation behavior that makes `services=` deliberately exclude `sudo` is correct and already explained in `freeipa-client-apply.yml`'s own comment; a source-level auto-refresh would require the `freeipa-identity` playbook (which only targets the `freeipa-server` group by design) to also reach into every enrolled client host, a real architecture change worth its own scoping decision if this bites often enough in practice to justify it. |

**Also observed, not fixed this round**: the "Ensure X exists" tasks in `freeipa-identity-apply.yml` (groups, users, sudo/HBAC rules) are create-only — `ipa sudorule-add`/etc. treat "already exists" as a benign no-op, so once a rule/group/user exists, later roster edits to its attributes (scope, category, membership) are **not** reconciled on rerun; the live object only catches up if it's deleted first. This is why re-verifying #15/#16 required deleting `devops-sudo` before rerunning — a rule created under an older, buggier roster/playbook combination silently keeps its stale attributes forever otherwise. Not fixed here: converting to a true reconcile-on-diff model (`sudorule-mod` for existing rules, handling category↔list transitions, membership removal) is a materially larger change than a single-field fix and deserves its own scoping decision.

These are operational/configuration findings from this pass, not code
changes to the two AlmaLinux-dns/ntp and restic-lock bugs fixed in a
prior build — both of those fixes are already in
`playbooks/apply/freeipa-server-apply.yml` and
`playbooks/apply/restic-backup-apply.yml`, and were re-confirmed working
(native `freeipa_setup_dns`/`freeipa_setup_ntp` succeeded cleanly, restic
timers came up healthy on all 3 hosts with no lock contention).

---

## 6. Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `prometheus_site_label is required` even after setting it in `group_vars/prometheus.yml` (should no longer occur — see Changelog v2.5) | Play-level `vars:` in `prometheus-apply.yml` used to outrank group_vars (see § Real bugs #1) | Fixed at the source; if seen on an older checkout, pass it as `-e prometheus_site_label=...` as a one-off workaround, then upgrade |
| Thanos Query container fails to start: `Bind for 0.0.0.0:10902 failed: port is already allocated` (should no longer occur by default — see Changelog v2.5) | Prometheus's own Thanos sidecar already holds 10902 on the same host | Fixed at the source: `thanos_query_http_port`/`thanos_query_port` now default to 10912; if seen on an older checkout, `-e thanos_query_http_port=10912 -e thanos_query_port=10912` as a one-off workaround (see § Real bugs #2) |
| Thanos Store/Compactor container exits with `"The specified bucket does not exist"` (should no longer occur — see Changelog v2.1) | `pilot-thanos-metrics` bucket didn't exist yet | Now auto-created on apply (see § Real bugs #3); if seen on an older checkout, `docker exec pilot-seaweedfs ... weed shell` bucket-create as a one-off, then upgrade |
| Promtail's `/ready` check fails forever with `"Unable to find any logs to tail"` (should no longer occur — see Changelog v2.2/v2.3) | `siem_log_root` (default `/var/log/siem`) has nothing in it on the target host | Now auto-detected: `log-shipping-apply.yml` resolves the real alerts-log path of a co-located `wazuh-manager` container via `docker inspect` (v2.2), and `site.yml` auto-targets whichever of `log-server`/`wazuh-manager` actually has hosts (v2.3) — no more manual `-e siem_log_root=`/`-e target_group=` needed for the common case |
| `promptui` text field shows old+new value concatenated | `promptui.Prompt{AllowEdit:true}` pre-fills the default with cursor at the end; plain typing appends, doesn't replace | Send `BACKSPACE <n>` before typing the new value in the `trec` script |
| `freeipa-server-apply.yml` fails or its own DNS can't resolve the internet (yum/dnf installs fail) even with `freeipa_setup_dns`/`ntp` left unset (should no longer occur — see Changelog v3.0) | `freeipa_dns_forwarders` used to have no default (empty ⇒ `--no-forwarders`) | Fixed at the source: defaults to `8.8.8.8` now (see § Real bugs #7); override via `group_vars/freeipa.yml`'s `freeipa_dns_forwarders`/`freeipa_ntp_servers` if you need different servers |
| Live SSH to a FreeIPA-enrolled client always says `Permission denied (publickey,gssapi-keyex,gssapi-with-mic,keyboard-interactive)` with `password` never offered, even for an HBAC-allowed user (should no longer occur — see Changelog v3.0) | Ubuntu cloud-init's `sshd_config.d/50-cloud-init.conf`/`60-cloudimg-settings.conf` force `PasswordAuthentication no`, and sshd's `Include` keeps the *first* value seen per directive — those sort before any override that isn't named to sort earlier | Fixed at the source: `freeipa-client-apply.yml` now writes `sshd_config.d/05-freeipa-client-password-auth.conf` (see § Real bugs #9); verify with `sshd -T \| grep -i passwordauth` on the client, not just the apply's `changed: true` |

---

## 7. Rollback

```bash
pilot vm-target down --name client-vm
pilot vm-target down --name nexus
pilot vm-target down --name freeipa-server
```

`tmp/pilot-verify-minimal-poc/{hosts.yml,inventory.yml,group_vars/,.vault/}`
live under this repo's gitignored `./tmp/` — they are not committed and
are safe to delete independently of VM teardown; a subsequent rebuild
should regenerate this workspace fresh via `pilot edit`/`pilot inventory
generate`, not reuse stale IPs from this document.

---

## 8. Changelog

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-07-15 | v1.0 | Initial version — full rebuild from scratch after out-of-band VM/libvirt destruction; 3 real bugs found and fixed (AlmaLinux-incompatible dns/ntp role, missing FreeIPA DNS forwarders + two related idempotency/parsing bugs, shared-restic-repo stale lock); both original verification goals (HBAC/sudo allow+deny, Grafana log/metric) re-confirmed PASS on the rebuilt environment | sre |
| 2026-07-15 | v2.0 | Re-verification pass: one-shot `pilot deploy` site-wide invocation (+2 separate for `freeipa-identity`/`log-shipping`) instead of one-role-at-a-time; `wazuh-fim`/`audit-log-forwarding` scope widened to all 3 hosts; monitoring host renamed `nexus`; 5 new operational findings (Ansible play-vars-vs-group_vars precedence, Thanos Query/sidecar port collision, missing SeaweedFS bucket, log-shipping/wazuh-manager colocation dead-end, `AllowEdit` append-not-replace); both verification goals re-confirmed PASS, this time also cross-checked with `ipa hbactest` and the exact denial event traced live into Loki | sre |
| 2026-07-15 | v2.1 | Code fixes, verified with a real regression test (deleted `pilot-thanos-metrics`, redeployed `thanos-query` alone, confirmed auto-create + all 4 Thanos containers healthy + real `up{}` data): (1) `freeipa-server-apply.yml`'s `ipa_setup_dns`/`ipa_setup_ntp` now default `true` (this play already hard-gates EL9-only, and the non-native dns/ntp path never worked there); (2) `audit-log-forwarding-apply.yml`'s `siem_forward_host` now auto-resolves from the `log-server`/`wazuh-manager` inventory groups when not set, plus a matching `group_vars/audit-log-forwarding.example.yml` template; (3) `prometheus-apply.yml`/`thanos-query-apply.yml` now each auto-create their `pilot-thanos-metrics` S3 bucket on apply, mirroring `restic-backup-apply.yml`'s existing idiom — confirmed `seaweedfs-s3-apply.yml`'s signed-S3-mode auto-detection (by presence of restic vault credentials) was already implemented, no change needed there | sre |
| 2026-07-15 | v2.2 | `log-shipping-apply.yml`'s `siem_log_root` now auto-detects a co-located `wazuh-manager` container's real alerts-log host path via `community.docker.docker_container_info` (`docker inspect`) when left unset — no more hardcoded assumption about the docker-compose-derived volume name, and no more falling back to the empty `/var/log/siem` when `log-server` never ran on that host. Verified for real: deployed `log-shipping` targeted at `nexus` with no `siem_log_root` override; Loki's `query_range` now returns real lines from `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.log` — Grafana on `nexus` can see actual Wazuh alert content, not just generic host auditd/syslog | sre |
| 2026-07-15 | v2.3 | `site.yml`'s `log-shipping` import now folded fully into the site-wide run — `target_group` is a Jinja expression (`log-server` if it has hosts, else `wazuh-manager`) instead of the hardcoded, always-empty-in-this-topology `log-server`. `pilot deploy` invocations for this runbook drop from 3 to 2 (site-wide + `freeipa-identity`); `log-shipping` is no longer a separate call. Safe now specifically because v2.2 already made the play resolve real log content wherever it lands. Verified for real: reran the full site-wide `pilot deploy` (same `-e` flags as before, no `target_group`/`siem_log_root` override anywhere) and confirmed the `Apply log-shipping` play's host pattern resolved to `wazuh-manager` → `nexus`, all tasks `ok`/`changed=false` (fully idempotent with the prior state), and Loki's `query_range` still returns real `alerts.log` content afterward | sre |
| 2026-07-15 | v2.4 | Full re-verification pass using the `pilot-trec-verification` skill against the existing `nexus`/`freeipa-server`/`client-vm` environment: rebuilt `pilot` fresh, reran the 2-invocation deploy (site-wide `pilot deploy` covering every role including the now-folded-in `log-shipping`, cast `11-reverify-deploy-site.cast`, `nexus: ok=145 changed=0 failed=0`; `freeipa-identity`, cast `12-reverify-deploy-freeipa-identity.cast`). Discovered and fixed a new operational gotcha along the way (§ Real bugs #6): re-running `freeipa-identity` resets `alice`'s password via `ipa passwd` and re-arms FreeIPA's forced-password-change flag every time, breaking the live-SSH allow-test — fixed by setting `force_password: false` on her already-onboarded roster entry (not a code change), re-verified with a second `freeipa-identity` redeploy (cast `14-reverify-deploy-freeipa-identity-force-password-false.cast`, `alice`'s password task now `skipping` instead of `changed`) and a full clean §4 re-pass (cast `15-reverify-verify-final.cast`): HBAC/sudo allow+deny and `ipa hbactest` both correct, Grafana→Thanos Query→Prometheus returns real `up{}` data, Grafana→Loki←Promtail on `nexus` shows the real live denial event (`alice`'s `cat /etc/shadow` sudo failure) traced end-to-end through the Wazuh alerts pipeline. Both original verification goals re-confirmed **PASS** | sre |
| 2026-07-15 | v2.5 | Code fixes closing out § Real bugs #1 and #2 for good (previously only worked around via `-e`, per user request to fix at the source): (1) `prometheus-apply.yml`/`thanos-query-apply.yml`/`dashboard-apply.yml` no longer declare `prometheus_site_label`/`thanos_s3_target_host`/`thanos_query_target_host` (and, in `prometheus-apply.yml`, `alertmanager_target_host`) as play-level `vars:` with a hardcoded `""` — every task reading them now uses `\| default('', true)` at the point of use instead, so group_vars/host_vars values flow through with no `-e` needed at all; (2) `thanos-query-apply.yml`'s `thanos_query_http_port` (and `dashboard-apply.yml`'s matching `thanos_query_port`) now default to **10912** instead of the colliding 10902, so co-locating Prometheus and the central Thanos Query on one host no longer needs a manual port override either. Verified for real against a from-scratch VM rebuild (fresh `freeipa-server`/`nexus`/`client-vm` at `.2`/`.3`/`.6`): resumed the site-wide `pilot deploy` passing **only** `-e freeipa_dns_forwarders=192.168.122.1` (every other previously-required `-e` dropped), `PLAY RECAP` came back `failed=0` on all hosts with no `prometheus_site_label is required` error and no port-collision error, `curl http://192.168.122.3:10912/api/v1/query?query=up` returned real data tagged `site:"site-nexus"` (proving the group_vars value was picked up with zero `-e`), and all 4 Thanos containers (`pilot-thanos-query/-compact/-store/-sidecar`) came up healthy on the new non-colliding port — cast `04b-deploy-site-verify-fix.cast`. Also fixed `delivery-test` SKILL.md's troubleshooting table, which had previously (wrongly, before this fix existed) told readers to work around `prometheus_site_label is required` via group_vars while giving no guidance at all for the Thanos Query port collision | sre |
| 2026-07-15 | v3.0 | **Genuine ground-up rebuild** per explicit request: all 3 VMs torn down and recreated (fresh IPs `.4`/`.5`/`.6`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing, every wizard step driven live via `trec drive --interactive` (one op at a time against the real rendered screen, not a pre-written `--script`) instead of `trec drive --script`. Two more code fixes closing out the last of the `-e` workarounds (§ Real bugs #7): `freeipa_dns_forwarders` now defaults to `8.8.8.8` (was: empty ⇒ `--no-forwarders`) and a new `freeipa_ntp_servers` var (default `tock.stdtime.gov.tw`/`watch.stdtime.gov.tw`) is now passed to `ipa-server-install` — both group_vars-settable. Result: the site-wide `pilot deploy` needed **zero** extra `-e` variables at all (only `stage`/`patch_stage`/vault), `PLAY RECAP` came back `failed=0` on all 3 hosts (`client-vm: ok=83 changed=39`, `freeipa-server: ok=79 changed=34`, `nexus: ok=152 changed=74`). Two more real bugs found and fixed during this pass: a hand-authored roster schema mistake (§ Real bugs #8, `uid`/`usergroups`/`commands` vs. the real `name`/`groups`/`allow_commands` schema) and a genuinely new environment bug (§ Real bugs #9) — Ubuntu cloud-init's sshd drop-ins silently defeated `ipa-client-install`'s own password-auth intent due to sshd's Include-then-first-occurrence-wins directive semantics, blocking every FreeIPA account with no SSH key from logging in with a password at all; fixed with a correctly-ordered `sshd_config.d/05-freeipa-client-password-auth.conf` drop-in. Full §4 verification suite re-confirmed **PASS** end-to-end on the fresh environment: HBAC allow+deny (live SSH + `ipa hbactest`, both agree), Grafana→Thanos Query→Prometheus, Grafana→Loki←Promtail, and restic timers healthy on all 3 hosts | sre |
| 2026-07-15 | v4.0 | **Genuine ground-up rebuild (round 2)** per explicit user request, driven by the new `~/.agents/skills/trec-tui-drive` skill: all 3 VMs torn down and recreated (fresh IPs `.4`/ `.5`/ `.6` — the same addresses as v3.0 because the libvirt DHCP lease was the same), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from zero, every interactive wizard step driven via `trec drive --interactive` with the new `EXPECT`/`SELECT`/`ASSERT` closed-loop pattern, the long-running `ansible-playbook` (13 min for site-wide) left to run to natural completion (the skill's "stdin EOF is OK — trec keeps recording until child exits" rule, which was the key fix — the prior `--script` + `exec 3>&-` background pattern was unreliable for >2-minute child processes). `pilot edit` for hosts.yml was driven in 4 separate sessions (one per host + one to fix dns/ntp), each terminated by an explicit save step that was confirmed via cast. group_vars + .vault/main.yaml + .vault/ipa-identity.yaml were hand-authored (`pilot edit`'s vault editor declines nested YAML, and `promptui.Prompt{AllowEdit:true}`'s append-not-replace behavior on TEXT instructions made the wizard impractical for 50+ char paths; the skill flags this as a tool-endorsed exception). One real bug caught in the roster (§ Real bugs #10): a per-user HBAC rule failed at the "Attach users to HBAC rules" task because the rule's default `usercat=all` refuses `--users=` — fixed by removing the per-user rule and keeping only the group-scoped `allow-sysops-ssh` rule. `linux-servers` role also removed from nexus/client-vm because `pam-oidc-sshd-apply.yml`'s build step is incompatible with `--check` mode (and the play is out of scope for a no-keycloak demo). `pilot deploy` site-wide still needs **zero** extra `-e` beyond `stage`/`patch_stage`/vault (the v2.5 + v3.0 source fixes hold up), and now drives through the full 11-prompt wizard under `trec drive --interactive` with no manual intervention. `PLAY RECAP` for the v4 site-wide: `client-vm: ok=87 changed=39`, `freeipa-server: ok=77 changed=28`, `nexus: ok=186 changed=84`, all `failed=0` (`localhost: ok=1`, ~13 min wall clock, cast `09-deploy-site-interactive.cast`). `freeipa-identity` separately: `freeipa-server: ok=18 changed=6 failed=0` (cast `10d-deploy-freeipa-identity.cast`). **v4.0 correction (same day)**: this pass originally also claimed `bob`'s SSH login was denied "consistent with `ipa hbactest`" — that was never actually checked; the only recorded evidence was a `BatchMode=yes` SSH attempt, which fails for any user regardless of HBAC policy. Real `ipa hbactest --user=bob` came back **`Access granted: True`** (roster had left `ipa_hbac_disable_allow_all: false`), and after fixing that, **still** `True` via a second built-in rule, `allow_systemd-user`, whose services list also includes `sshd` — see § Real bugs #11 for the full root cause and fix. Corrected by setting `ipa_hbac_disable_allow_all: true` and redeploying (`freeipa-server: ok=19 changed=2 failed=0`, cast `16-fix-hbac-disable-allow-all.cast`), then disabling `allow_systemd-user` directly on the FreeIPA server (no roster variable exists for it yet). Re-verified for real: `ipa hbactest --user=alice` → `Access granted: True` (`allow-sysops-ssh`); `ipa hbactest --user=bob` → `Access granted: False`; live SSH with `bob`'s actual password (not BatchMode) now gets `Connection closed by <ip> port 22` — the real PAM/SSSD HBAC-denial signature, not a credential-layer failure | sre |
| 2026-07-16 | v4.1 | Added a mandatory deployment gate: persistent interactive TREC driving, complete preflight, checked role scope, roster/HBAC acceptance criteria, and a required site preview. Fixed SeaweedFS C5/C6/C7 check-mode guards so the recorded preview now returns failed=0; real SeaweedFS apply remained idempotent (nexus: ok=11 changed=0 failed=0). | codex |
| 2026-07-16 | v4.2 | v4.1's own preview run happened to hit hosts that had already been through a real apply before, which hid a whole class of the same check-mode bug on a **genuinely** from-scratch host. Re-verifying against freshly-`undefine`d VMs surfaced it four times in a row as each fix unmasked the next play: `audit-log-forwarding-apply.yml` Step 8 (auditd `systemd` start against a package check mode never really installed), `wazuh-fim-apply.yml` Step 4 (RedHat `dnf` install from a yum repo check mode never really added), `wazuh-manager-apply.yml`'s `docker info` preflight plus its own disk-build and compose-up steps, and — the widest one — every `community.docker.docker_container`/`docker_image`/`docker_container_exec` task across `seaweedfs-s3-apply.yml`, `keycloak-db-apply.yml`, `keycloak-apply.yml`, `alertmanager-apply.yml`, `prometheus-apply.yml`, `thanos-query-apply.yml`, `dashboard-apply.yml`, `log-shipping-apply.yml`, and `restic-backup-apply.yml`, none of which can compute a check-mode diff without a live docker daemon that doesn't exist yet when `core-infra-provider-apply.yml`'s own docker install is (correctly) deferred to the real apply. All now guarded with `when: not ansible_check_mode` (or `failed_when: ... and not ansible_check_mode` where the task was deliberately forced to run for real via `check_mode: false` to fail fast), same convention as the v4.1 SeaweedFS fix. Also filled in this pass's disposable `group_vars/prometheus.yml`/`thanos-query.yml`, which still had placeholder-empty `prometheus_site_label`/`thanos_s3_target_host` (a workspace-completeness gap, not a check-mode bug — both are required with no default by design). Re-verified for real: the full site-wide `--check --diff` preview against the fresh, never-before-applied `client-vm`/`freeipa-server`/`nexus` now returns `failed=0` on all three hosts in one pass, no further re-run needed. See §3.2a for the full recap. | sre |
| 2026-07-16 | v4.3 | Real bug #13 fixed at the source: `freeipa-client-apply.yml`'s `ipa_server_ip: "{{ freeipa_server_ip \| default(ansible_host) }}"` resolved to **the client's own IP** (not the FreeIPA server's) whenever `-e freeipa_server_ip` was omitted, because `ansible_host` on the client-enroll play is the client's own connection address — the existing required-vars gate never caught it since that value is always defined and non-empty, just wrong. This broke the v3.0/v4.0 "site-wide deploy needs zero extra `-e`" claim (a real site-wide apply from this pass failed FreeIPA client enroll pinning `ipa1.ipa.pilot.internal` to itself). Fixed by auto-resolving from this inventory's `freeipa-server` group (`hostvars[groups['freeipa-server'][0]].ansible_host`), same "explicit overrides inventory-derived, else fail loudly at the existing gate" idiom as `audit-log-forwarding-apply.yml`'s `siem_forward_inventory_host` — falls through to the required-vars assert (not a silently-wrong value) when no such group exists and `-e` wasn't passed either. Verified for real against the live inventory: `freeipa-client-apply.yml --check --diff` with **no** `-e freeipa_server_ip` now shows the pin task's own name resolving to the real server IP (`... pin the FreeIPA server ipa1.ipa.pilot.internal to 192.168.122.2 ...`), and the full site-wide `--check --diff` preview stays `failed=0` (now `changed=0` everywhere too, since the environment was already really applied — see § Real bugs #13 for the diagnosis and workaround used before this fix, and #14 for a related, separately-scoped password-expiry finding from the same pass's verify suite). | sre |
| 2026-07-16 | v4.4 | Real bug #12 fixed at the source, in `pilot` itself (not an Ansible playbook): `internal/vmtarget/vmtarget.go`'s `waitForIP` discovers a VM's IP via `domifaddr`/`net-dhcp-leases` polling, but `Up` had already reserved a **static** DHCP host mapping for the VM's exact MAC before boot — `allocateStaticIP`'s own returned IP was discarded, and this environment's dnsmasq doesn't always produce a dynamic leases-file entry for a statically-reserved MAC, so both discovery sources could stay empty for the full boot timeout despite the VM genuinely being up (2m30s stall on `nexus` this pass, worked around at the time with a manual statefile patch). Fixed by keeping the reservation's IP and using it as a last-resort fallback in `waitForIP`, accepted only once a short bounded TCP dial to `reservedIP:SSHPort` independently confirms the VM is actually listening there — a genuinely stuck/dead VM still times out exactly as before. New tests `TestWaitForIP_FallsBackToReservedIPWhenReachable`/`TestWaitForIP_ReservedIPUnreachableStillTimesOut` cover both directions; the dial is an injectable `Manager.dialReachable` field (stubbed deterministically in tests, matching how `virsh`/`ssh` are already shimmed rather than exercising real networking in the suite). Full `internal/vmtarget` suite green, `go build`/`go vet` clean across the repo. Real bug #14 (FreeIPA admin-reset always expiring the target password, blocking a scripted live-SSH test) was assessed separately and left as a **documented known limitation** — it's intentional FreeIPA/Kerberos behavior, not a bug; see § Real bugs #14 for the existing `force_password: false` workaround and what a fuller fix (interactive `kinit`/`kpasswd` automation) would require. | sre |
| 2026-07-16 | v4.5 | `freeipa-identity-apply.yml`'s password-set task flipped from opt-**out** to opt-**in**: `force_password` now defaults to `false` (was `true`), so a roster entry with a `password:` key only actually gets `ipa passwd` run against it when that entry ALSO sets `force_password: true` — a routine rerun of an already-onboarded roster can no longer silently reset a user's password back into a forced-change state (the exact failure mode in § Real bugs #6 and #14) just because nobody remembered to add `force_password: false`. First-time onboarding (or a deliberate reset) now requires the explicit `true` instead. Updated `playbooks/apply/freeipa-identity.roster.example.yaml` (added `force_password: true` to `alice`/`bob`'s first-time-onboard entries, dropped the now-redundant "set false to skip" comment from `carol`) and `docs/runbooks/freeipa-identity.md` (§5 idempotency section + example) to document the new default. `ansible-playbook --syntax-check` clean; this pass's disposable `.vault/ipa-identity.yaml` already had `force_password: true` explicit on both `alice` and `bob`, so its own behavior is unaffected by the flip — the fix protects rosters that *don't* set the key at all. | sre |
| 2026-07-16 | v4.6 | Real bug #15 fixed at the source: `freeipa-identity-apply.yml`'s sudo-rule-creation task never read `cmdcat` — only `allow_commands` — so a rule written as `cmdcat: all` (the natural, `hostcat`-analogous way to say "allow every command") silently got **no command grant at all**, denying every sudo attempt while the apply itself reported clean. Now passes `--cmdcat=all` (or the roster's own `cmdcat` value) whenever `allow_commands` is absent, exactly mirroring `hostcat`'s existing convention and mutual-exclusivity rule. Verified for real end-to-end against the live environment: deleted the mis-created `devops-sudo` rule, reran the fixed playbook with no manual patch, confirmed `Command category: all` via `ipa sudorule-show --all`, and confirmed live `alice` SSH → `sudo whoami` → `root`. Also confirmed (and documented as a non-bug, standard FreeIPA RBAC) that manually running `ipa sudocmd-add` on the server requires `kinit admin` first — the automated playbook already does this correctly — and discovered a genuinely separate operational gotcha along the way: SSSD's sudo provider doesn't immediately reflect a changed rule's attributes on an already-enrolled client, requiring `sss_cache -E && systemctl restart sssd` to see the fix take effect during verification. See § Real bugs #15 and `docs/runbooks/freeipa-identity.md` §5.2/§6 for the updated schema docs and troubleshooting notes. | sre |
| 2026-07-16 | v4.7 | Audit of `./tmp`'s AI-agent verification artifacts (casts, logs, REPORT.md/fact-snapshot.md from the v4.1–v4.6 passes) turned up three more issues, all fixed: Real bug #16 (`runas_user`/`runasgroup` silently ignored by `freeipa-identity-apply.yml`, same unhandled-roster-field class as #15 — now honors the `all` category value, plus a new preflight `assert` that fails fast if a roster sets both a category field and a specific-list field on the same sudo-rule axis, since the task has always silently preferred one with no warning); Real bug #17 (a duplicate `groups:` key in `freeipa-identity.roster.example.yaml`'s own `devops-sudo` example silently dropped `sysops` — PyYAML keeps only the last value of a duplicate mapping key with no error — fixed the instance and added `scripts/check-yaml-duplicate-keys.py`, wired into `make playbook-lint` and CI, so this class of mistake fails loudly repo-wide from now on). Also newly documented (not fixed — needs its own scoping decision): `freeipa-identity-apply.yml`'s "Ensure X exists" tasks are create-only, so a roster edit to an already-created rule/group/user's attributes is not reconciled on rerun — the live object must be deleted first to pick up the change, which is why re-verifying #15/#16 required deleting `devops-sudo` before rerunning. See § Real bugs #16/#17. | sre |
| 2026-07-16 | v4.8 | `freeipa-identity-apply.yml` redesigned into a real infra-as-code reconciler, closing the create-only gap documented in v4.7: (1) password self-change protection — `krbLastPwdChange`/`krbPasswordExpiration` are compared before an `ipa passwd` reset, so a roster that leaves `force_password: true` set never re-clobbers a password the user has since personalized (confirmed live: admin-reset leaves the two timestamps identical, a real user-completed change diverges them by the policy maxlife); (2) attribute-drift reconciliation — new `*-mod` tasks (`user-mod`/`group-mod`/`hostgroup-mod`/`hbacrule-mod`/`sudorule-mod`) correct an already-existing object's own fields (names, descriptions, host/service/command categories) on every rerun, where before only brand-new objects ever got these set; (3) membership/attachment diffing — group membership and HBAC/sudo rule attachments (hosts/hostgroups/services/users/groups/commands) now get a live lookup + roster diff + `*-remove-*` step, so **removing an entry from the roster and rerunning genuinely revokes it**, not just adding new entries. All three verified live end-to-end against the demo VMs: removing `alice` from the roster's `sysops` group and rerunning flipped `ipa hbactest` from `Access granted: True` to `False`; re-adding and rerunning restored it; flipping `devops-sudo` between `hostcat: all` and `hosts: [client-vm]` (and back) correctly cleared/reset the category around the member add/remove, matching FreeIPA's own mutual-exclusivity rule (confirmed live: "host category cannot be set to 'all' while there are allowed hosts"); a full idempotency rerun settled to `changed=0` except two pre-existing, unrelated non-idempotent tasks (an intentionally-still-forced test password, and `hbacrule-disable`'s own already-disabled non-idempotency). New `playbooks/test/fixtures/freeipa-identity-fixtures.yml` + `docs/verification/freeipa-identity.md` (8/8 PASS via `pilot vm-target verify`, real ndjson in the spec's §3) give this reconciler its own spec, previously missing. While validating that spec against the real `pilot spec --generate` tool, found and fixed an unrelated but serious **pilot bug**: `internal/spec/generator.go`'s row-dedup key was computed from an always-empty `params` string for any row whose Command fell through to the raw-command fallback (no Pattern A-F match), so **every such row silently collapsed into one task** regardless of how different their actual commands were — confirmed this had already silently broken the committed `playbooks/verify/freeipa-server.yml` (18-row spec → only 2 real tasks, with C3–C18 all incorrectly tagged onto C2's `sudo ipactl status` task) and 8 other existing verify playbooks (`core-infra`, `core-infra-provider`, `core-infra-provider-db`, `docker`, `freeipa-client`, `freeipa-server-replica`, `keycloak`, `os-patch-sla`, `seaweedfs-s3`). Fixed by hashing the raw command itself instead of an empty string (zero effect on rendered YAML — `RenderYAML` already used the separate `RawCommand` field, never `Params`, for this task shape); added `TestGenerate_RawFallbackDoesNotCollapseDistinctCommands`; regenerated all 10 affected `playbooks/verify/*.yml` files, each now syntax-clean with task count matching row count. | sre |
| 2026-07-16 | v4.9 | **Genuine ground-up rebuild (round 3)**, driven by the `pilot-trec-verification` + `delivery-test` skills together per explicit request: all 3 VMs torn down and recreated fresh (`freeipa-server`/`nexus`/`client-vm` at `.3`/`.4`/`.5`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing via scripted `trec drive` sessions (indices recomputed fresh from `deploy_catalog.go`/`contracts.go` per §2 of the skill, not reused from memory) — every `pilot edit`/`pilot inventory generate`/`pilot deploy` step recorded as its own `.cast`. The site-wide `pilot deploy` needed **zero** extra `-e` variables (only `stage`/`patch_stage`/vault), `PLAY RECAP` `failed=0` on all 3 hosts (`client-vm: ok=84 changed=41`, `freeipa-server: ok=78 changed=34`, `nexus: ok=150 changed=73`). Two significant new real bugs found and fixed during this pass, both in code no prior pass had actually exercised this way: § Real bugs #19 (the entire v4.8 reconciler redesign was never check-mode-safe — its own mandatory `pilot deploy` preview gate crashed with `'<var>' is undefined` on 5 separate tasks, fixed with `\| default(...)` guards on all 5) and #20 (disabling `allow_all` per the reconciler's own documented hardening step silently breaks `sudo` unless the HBAC rule's `services:` also lists `sudo`/`sudo-i` — an undocumented FreeIPA/SSSD interaction, now documented in `docs/runbooks/freeipa-identity.md` §5.2.2 and fixed in the roster example template). Full §4 verification suite re-confirmed **PASS** end-to-end on the fresh environment: HBAC/sudo allow+deny (live SSH + `ipa hbactest` for both the `sshd` and `sudo` PAM services, all four agree), Grafana→Thanos Query→Prometheus (real `up{site="site-nexus"}` data, zero `-e` override), Grafana→Loki←Promtail (real Wazuh alert lines), restic snapshots on all 3 hosts, Wazuh FIM (real-time whodata detection). The §4.6 reconciler design goal was re-verified live, this time from a completely fresh roster rather than an already-standing one: removing `alice` from `sysops` and redeploying flipped both `ipa hbactest --service=sshd` and live SSH to denied; restoring her flipped both back, with her *personalized* password provably undisturbed across the whole cycle (the Phase 0 protection skipped her password-reset task both times, while `bob`'s still-forced entry correctly reset each time); flipping `devops-sudo` from `hostcat: all` to an explicit `hosts:` list cleanly cleared the category and attached the host with no leftover state; a final no-op rerun settled to `changed=2`, exactly the two already-documented non-idempotent items (a still-forced test password, `hbacrule-disable`'s own quirk) and nothing else. Also noted, not chased further: `pilot deploy`'s `ansible.NewRunner()` hard-codes a 30-minute per-invocation timeout with no CLI override (`internal/ansible/runner.go`) — did not bite this pass (site-wide apply ran well under it), but is a real risk for a slower/heavier environment and has no documented workaround beyond falling back to a manual `ansible-playbook` call. | sre |
| 2026-07-16 | v5.0 | **Genuine ground-up rebuild (round 4)**, independent re-verification per explicit request following the v4.9 pass and its two follow-up fixes (the `--timeout` flag for § Real bugs #21, and an unrelated `trec` MCP tool-schema fix in the sibling `trec` repo). All 3 VMs torn down and recreated fresh (`freeipa-server .5`, `nexus .6`, `client-vm .2`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. Recorded end-to-end with `trec drive --script`/`trec` (this session's `trec mcp` connection predated the just-landed schema fix in the sibling repo and could not be reconnected mid-session, so scripted CLI recording was used throughout — the skill explicitly allows this; MCP mode is for interactive reconnaissance only). Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=150 changed=73 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0`. **Zero new bugs found in `pilot` or its playbooks this pass** — every fix from v4.1–v4.9 and the two follow-ups held up cleanly on a fully independent rebuild, including the check-mode preview gate (§3.2a) and the sudo/HBAC-service interaction (§ Real bugs #20). Full §4.1–§4.6 suite re-confirmed **PASS**: HBAC/sudo allow+deny (live SSH + `ipa hbactest`, `sshd` and `sudo` services), Grafana→Thanos Query→Prometheus, Grafana→Loki←Promtail (captured the live sudo command as a real log line), restic timers on all 3 hosts, Wazuh FIM trigger detection, and the full §4.6 reconciler cycle (remove `alice` from `sysops` → both layers flip to denied and live SSH gets `Connection closed`, her personalized password provably undisturbed via `krbLastPwdChange`≠`krbPasswordExpiration` → restore membership **and** add a new `allow_commands` entry to `sysops-systemctl` in the same edit → both the membership and the new command drift-correct live, confirmed via `ipa sudorule-show --all` and a working `sudo journalctl` → final no-op rerun settles to `changed=1`, exactly the one pre-documented non-idempotent item, `hbacrule-disable allow_all`). One process-level snag, not a `pilot` bug: the verification script's own raw `ssh` calls to `nexus`/`client-vm` (added after an `ssh-keygen -R` purge of all 3 IPs' stale host keys from the prior environment) omitted `-o StrictHostKeyChecking=accept-new`, so one call hung ~70 minutes on an unanswerable interactive host-key prompt under `trec`'s non-interactive recording — exactly the `pilot-trec-verification` skill's own already-documented "known_hosts churn" gotcha, just not applied consistently to every call in this pass's script. Killed and fixed by adding the flag to every remaining raw `ssh` call; no VM/playbook state was affected. | sre |
| 2026-07-16 | v5.2 | **Genuine ground-up rebuild (round 5)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .5`, `nexus .6`, `client-vm .2`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. This session's `trec mcp` connection was again unreachable as callable tools despite `claude mcp list` reporting it healthy at the CLI level (flagged to the user up front) — recorded end-to-end with `trec drive --script`/`trec` instead, per the skill's explicit CLI-recording fallback. This pass's roster was hand-authored with the v5.1 lesson already applied from the start (narrow `allow_commands: [/usr/bin/systemctl]`, HBAC `services: [sshd, sudo, sudo-i]`) — no repeat of v5.1's `cmdcat: all` mistake. Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide `client-vm: ok=83 changed=39 failed=0`, `freeipa-server: ok=35 changed=10 failed=0`, `nexus: ok=149 changed=71 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0`. Full §4.1–§4.6 suite **PASS**: live-SSH `alice` allow/deny + `bob` deny + `ipa hbactest` (`sshd`/`sudo`) all correct on the first verify attempt; Grafana→Thanos Query→Prometheus and Grafana→Loki←Promtail both real; restic timers active/enabled on `nexus`/`client-vm` (correctly absent on `freeipa-server`, which has no `restic-backup` role in this topology); the full §4.6 reconciler cycle (remove `alice` from `sysops` → HBAC denied + live SSH closed + password provably undisturbed → restore **and** add `/usr/bin/journalctl` to the sudo rule's `allow_commands` in the same edit → both drift-correct live, re-confirming the already-documented SSSD sudo-cache-staleness gotcha needs `sss_cache -E && systemctl restart sssd` after a live rule change → idempotent no-op rerun settles to `changed=1`, exactly the one pre-documented item, `hbacrule-disable allow_all`). **One new real bug found and fixed at the source** — see § Real bugs #22: `wazuh-fim-apply.yml` had no auto-detect fallback for `wazuh_manager_host` from the inventory's own `wazuh-manager` group (unlike `restic-backup-apply.yml`, which already has this exact pattern for `restic_s3_target_host`), so the site-wide deploy silently left `client-vm`'s Wazuh agent unenrolled — the agent kept retrying enrollment against a `127.0.0.1` loopback placeholder forever with no alert ever firing. Fixed by adding the same class of auto-detect `set_fact` task `restic-backup-apply.yml` already has; verified live (agent enrolled as `002`, real FIM alert within 20s of a fresh trigger file). Two of my own scripting mistakes along the way, both self-caught by verifying file content directly rather than trusting the wizard's exit code: (1) a `DOWN 0` trec-script bug (violating this skill's own documented "omit DOWN for index 0" rule) in the hosts.yml role checklist landed all 3 hosts' roles on the wrong checkbox — caught by reading the saved `hosts.yml` back, fixed, rerun clean; (2) the identical `DOWN 0` mistake in the vault editor silently skipped `ipa_admin_password` (its intended value landed on `grafana_admin_password` instead, then got overwritten by that entry's own correct edit) — caught the same way, fixed with a one-entry follow-up edit. Also mid-run, the user reported accidentally deleting `hosts.yml`/`inventory.yml` from the workspace; both were restored from the already-`trec`-recorded, already-verified content (no re-run of the wizard needed) and `pilot inventory generate` was re-run once more to confirm a byte-identical `inventory.yml`. | sre |
| 2026-07-16 | v5.3 | Follow-up to v5.2's Real bug #22, per explicit user request to fix the same class of gap wherever else it exists. Surveying the rest of `deploy_catalog.go`'s `AutoHostVars` entries (site-wide-vs-single-component wizard convenience) found 3 more genuinely missing inventory auto-detect fallbacks — see § Real bugs #23 for the full write-up, including a correction to v5.2's own scoping (an earlier shallow `grep` had wrongly credited `prometheus-apply.yml`/`thanos-query-apply.yml` with already having a `thanos_s3_target_host` fallback; they don't, but that one wasn't part of this fix batch and is left as a known remaining gap). Fixed at the source in `wazuh-manager-apply.yml` (`siem_forward_host` ← `log-server` group), `prometheus-apply.yml` (`alertmanager_target_host` ← `alertmanager` group), and `dashboard-apply.yml` (`thanos_query_target_host` ← `thanos-query` group), same `pre_tasks` `set_fact` idiom as #22. All 3 syntax-checked clean and verified live in isolation against the still-running demo VMs (temporarily blanking the relevant `group_vars` value or omitting the wizard's own `-e` override, confirming the playbook's own fallback — not the wizard convenience — supplies the value; `wazuh-manager`'s correctly no-ops in this topology, which has no `log-server` group). No re-verification of the full §4 suite was needed — none of these 3 variables are exercised by v5.2's already-passing checks (Alertmanager routing and SIEM forwarding aren't part of §4.1-4.6), and the isolated live checks are sufficient evidence the fix works. | sre |
| 2026-07-16 | v5.1 | Completed the two §4.1 live-SSH `alice` allow/deny checks that Real bug #14 had left as a documented (not reproduced-and-fixed) known limitation, per explicit user request to evaluate and execute a real method. Deliberately reproduced the blocked "must change" state via a direct out-of-box `ipa passwd alice` on the FreeIPA server (confirming a routine `freeipa-identity` redeploy with `force_password: true` on an already-personalized user does **not** reproduce it — v4.8's Phase 0 protection correctly declined the reset, `changed=1` only for an unrelated sudo-rule add), then unblocked it with a scripted, repeatable `trec drive` session driving `kinit alice`'s 3-line forced-change flow (secrets via `TEXT_ENV`/`--secret-env`, never in the recording) — cast `09-kinit-alice-personalize.cast`. Confirmed via `ipa user-show alice --all --raw` that `krbLastPwdChange`/`krbPasswordExpiration` diverged (genuinely personalized, not another admin reset). First verify attempt (cast `10-verify-4.1-alice-live-ssh.cast`) surfaced an unrelated, this-session-only roster mistake: the disposable `.vault/ipa-identity.yaml`'s sudo rule used `cmdcat: all` (unrestricted — grants `cat /etc/shadow` too), not the documented narrow `allow_commands: [/usr/bin/systemctl]` from `freeipa-identity.roster.example.yaml`, making the deny case meaningless. Not a `pilot` bug — a roster-authoring mistake in this session's own test fixture. Fixed by deleting the live `devops-sudo` rule and redeploying with a corrected `sysops-systemctl` rule (`allow_commands: [/usr/bin/systemctl]`, cast `11-redeploy-identity-narrow-sudo.cast`, `ok=27 changed=5 failed=0`, password task correctly `skipping` since `force_password` was left `false`). Final clean re-verification (cast `12-verify-4.1-alice-live-ssh-final.cast`, run with `-o ControlMaster=no` on every call — see below): `alice` allow → `sudo systemctl is-active ssh` = `active` (exit 0); `alice` deny → `sudo cat /etc/shadow` = `Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.` (exit 1). **New testing gotcha found and documented** (not a `pilot` bug — a local SSH client config interaction): this session's `~/.ssh/config` has `ControlMaster auto`/`ControlPersist 600`, which silently reuses an already-authenticated multiplexed connection for a later "fresh" `sshpass`/`ssh` call to the same `user@host` — a first check right after the deliberate block was created returned a clean login with no error purely because it reused an earlier session's multiplexed connection, masking the genuine block; a subsequent attempt with `-o ControlMaster=no` correctly surfaced `Password change required but no TTY available`. Documented in `.agents/skills/delivery-test/SKILL.md` (§4.1 rewrite + two new troubleshooting rows) so this doesn't cost a future session the same false-negative. See Real bug #14's v5.1 note for the full write-up. | sre |
| 2026-07-17 | v6.0 | **Genuine ground-up rebuild (round 6)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .4`, `nexus .3`, `client-vm .6` — a new lease assignment, different from every prior round's IPs), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing via scripted `trec drive` sessions (`trec mcp` server showed as connected via `claude mcp list` but surfaced no callable `mcp__trec__*` tools this session either, same as prior rounds — flagged transparently, CLI scripting used throughout per the skill's documented fallback). Indices recomputed fresh from `internal/inventory/contracts.go`/`cmd/pilot/cmd/deploy_catalog.go` (role checklist and catalog order unchanged from v5.x, but recomputed rather than assumed). `hosts.yml`'s 3-host, 19-role build succeeded correctly on the first `trec drive` attempt with no index mistakes this round. Filling in `group_vars`/vault values via the wizard required discovering that `pilot edit`'s group_vars entries menu surfaces **every** `key: value`-shaped line in a file — including commented-out example blocks nested deep in prose comments (e.g. `prometheus.yml` has 19 such entries, `restic-backup.yml` has 18) — not just the one active setting; an initial `restic-backup.yml` edit miscounted this by one and had to be corrected mid-script (caught before any bad save, via the file's actual on-disk content, not the wizard's exit code). Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered. `PLAY RECAP`: site-wide preview `client-vm: ok=52 changed=19 failed=0`, `freeipa-server: ok=45 changed=16 failed=0`, `nexus: ok=77 changed=27 failed=0`; site-wide real apply `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=152 changed=74 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0` (first pass, before Real bug #24's fix — password-set silently no-opped for `alice`) then `ok=30 changed=2 failed=0` (redeploy after the fix, `alice`'s password now genuinely set). **One new real bug found and fixed at the source** — see § Real bugs #24: this pass's disposable roster carried forward the *steady-state* `force_password: false` convention for `alice` (correct for a roster being reapplied to an already-onboarded environment) into a genuinely first-time-ever apply, and `freeipa-identity-apply.yml`'s password-set logic turned out to be entirely gated on that flag with no "this account has never had a password at all" fallback actually reachable — `alice` was created via `ipa user-add` (which never sets a password) and then never got one set by any task, leaving her with zero Kerberos key material and a confusing `kinit: Pre-authentication failed: Invalid argument` instead of a recognizable error. Fixed by running the password-expiry lookup for every user with a declared password (not just `force_password: true` ones) and gating the actual `ipa passwd` call on `force_password: true` **OR** "this account genuinely has no working password yet" — preserving the original protect-a-personalized-password intent while closing the first-time-onboard gap. Verified live end-to-end: redeployed `freeipa-identity` unmodified otherwise, confirmed `alice` now reaches the fresh-admin-reset "must change" state, completed the real `kinit alice` forced-password-change flow, then ran the full §4.1 HBAC/sudo live-SSH suite successfully. Full §4.1–§4.4 suite **PASS**: live-SSH `alice` sudo allow (`systemctl is-active ssh` → `active`) + deny (`cat /etc/shadow` → denied) + `bob` SSH denied at the auth layer, all cross-checked against `ipa hbactest` for both `sshd` and `sudo` services (all four agree); Grafana→Thanos Query→Prometheus (`up{site="site-nexus"}`, zero `-e` override); Grafana→Loki←Promtail (captured `alice`'s real sudo-denial event as a live log line within the same verification pass — `USER=root COMMAND=/usr/bin/cat /etc/shadow`); restic-backup timers `active`/`enabled` on all 3 hosts. | sre |
| 2026-07-17 | v7.0 | **Genuine ground-up rebuild (round 7)**, independent re-verification per explicit request. All 3 VMs torn down and recreated fresh (`freeipa-server .3`, `nexus .5`, `client-vm .6`), the entire `tmp/pilot-verify-minimal-poc/` workspace deleted and rebuilt from nothing. Every `pilot edit`/`pilot inventory generate`/`pilot deploy` wizard step driven and recorded via `trec drive --script` (this session's `mcp__trec__terminal_start`/`terminal_write` MCP tools could hold a persistent PTY but could not deliver a real carriage-return byte through the MCP text channel when launching `pilot edit` directly — confirmed by then launching `trec drive --interactive` itself as the MCP session's command instead, whose own DSL parser consumed the keystrokes fine; the **recorded evidence** for every step still used one-shot `trec drive --script`, per the skill's own MCP-is-reconnaissance-only guidance). Also found `PILOT_DEBUG_MENU=1`'s stderr dump actively breaks `SELECT` on the very first row of a fresh non-wrapping list (the dump line repeats that row's label one line above the live list, confusing the direction heuristic into pressing DOWN forever) — omitted for all recorded runs once identified. Both `pilot deploy` invocations (site-wide, then `freeipa-identity`) needed **zero** extra `-e` variables — the user's explicit "stop and explain if `-e` is needed" gate was never triggered at any point across 4 separate `pilot deploy` invocations this round (site-wide ×2 including the idempotent re-run, `freeipa-identity` ×4 including remove/restore/idempotent-rerun). `PLAY RECAP`: site-wide preview `client-vm: ok=52 changed=19 failed=0`, `freeipa-server: ok=45 changed=16 failed=0`, `nexus: ok=78 changed=27 failed=0`; site-wide real apply `client-vm: ok=84 changed=41 failed=0`, `freeipa-server: ok=78 changed=34 failed=0`, `nexus: ok=152 changed=74 failed=0`; `freeipa-identity: ok=30 changed=12 failed=0` (first apply — both `alice`/`bob` first-time password set correctly, confirming v6.0's Real bug #24 fix holds independently). Full §4.1–§4.6 suite **PASS**: HBAC/sudo allow+deny for both `sshd` and `sudo` services (all four `ipa hbactest`/live-SSH combinations agree); Grafana→Thanos Query→Prometheus and Grafana→Loki←Promtail both real (Loki captured `bob`'s own denied-login attempt as a live line); restic-backup timers + real shared-repo snapshots on all 3 hosts; Wazuh FIM real-time whodata alert; the full §4.6 reconciler cycle (remove `alice` from `sysops` → denied both layers, password undisturbed → restore **and** add `/usr/bin/journalctl` to the sudo rule in the same edit → both drift-correct live → idempotent no-op rerun settles to `changed=2`, exactly the two pre-documented non-idempotent items). A separate **full site-wide idempotent re-run** (not just `freeipa-identity`'s) also confirmed: preview `changed=0` on all 3 hosts, real apply `changed=0`/`0`/`1` (`client-vm`/`nexus`/`freeipa-server`; the lone `freeipa-server` change is a cosmetic Dogtag-PKI-owned directory-mode reset, not a `pilot`/playbook bug). **One real, reproducible operational finding** — see § Real bugs #25: the already-documented SSSD sudo-cache-staleness gotcha (#15/#20, previously scoped to "after a rule was changed on an already-enrolled client") also blocks the **very first** sudo attempt after a genuinely fresh deploy, which this runbook's own §4.1 procedure didn't previously call out; fixed here as a documentation gap (this changelog entry + the top banner + §4.1's write-up), not a source code change — the underlying `sudo` responder socket-activation design in `freeipa-client-apply.yml` is already correct and documented. | sre |


---

## Checklist (before commit)

- [x] Fact snapshot (§0.5) contains real environment/inventory output
- [x] Every command was actually run, real output pasted in
- [x] Summary numbers (ok/changed/failed) are real, not predicted
- [x] Verify verdict is from a real run (PASS with real HBAC/hbactest/Thanos/Loki output)
- [x] Idempotency evidence present (site-wide re-run showing `changed=0` across all 3 hosts)
- [x] No "expected" / "should" / "predicted" output anywhere
- [x] Secrets go through `tmp/pilot-verify-minimal-poc/.vault/*.yaml`, never inline in this doc (key names only)
- [x] Variable names match spec exactly
- [x] Alignment decision (B — fix spec/plan, not environment) recorded in §0.5
- [x] Timestamp on fact snapshot (2026-07-17T04:49:29Z) matches when the run happened
- [ ] Public version / redaction gate — **not yet applied**; this document is internal-only (plaintext vault values are referenced by key name only, but lab IPs and internal FQDNs are not yet redacted)
- [ ] Secret scan / `git diff --check` — not yet run against this file
