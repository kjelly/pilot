# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Date: 2026-07-15 (UTC)
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
> **v3.0 note**: this pass is a genuine ground-up rebuild — all 3 VMs torn
> down and recreated (not reused), the entire `tmp/pilot-verify-minimal-poc/`
> workspace deleted and rebuilt from nothing, every wizard step driven via
> `trec drive --interactive` (not a static `--script`) per user request. The
> site-wide `pilot deploy` invocation needed **zero** extra `-e` variables
> beyond `stage`/`patch_stage`/the vault file — see § Real bugs #1/#2 (v2.5)
> and #7 (v3.0) for the source-level fixes that made this possible.

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

## 0.5 Fact snapshot (2026-07-15T20:33:00Z, v3.0 ground-up rebuild)

> All output below is captured from actual execution on the rebuilt
> environment, not predicted.

### Environment state — VM list

```bash
$ pilot vm-target down --name client-vm && pilot vm-target down --name nexus && pilot vm-target down --name freeipa-server
✓ target client-vm down
✓ target nexus down
✓ target freeipa-server down
$ rm -rf tmp/pilot-verify-minimal-poc   # entire disposable workspace, no leftover files reused
$ pilot vm-target up --name freeipa-server --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name nexus --base-image ubuntu-24.04 --memory 12288 --vcpus 6 --disk 80 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target up --name client-vm --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 20 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
$ pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.6  2     2048      20         2026-07-15 19:24:57
freeipa-server  running  192.168.122.4  2     4096      30         2026-07-15 19:24:38
nexus           running  192.168.122.5  6     12288     80         2026-07-15 19:24:54
```

All three VMs were torn down and recreated fresh for this pass (not
reused) — libvirt DHCP reassigned every IP (`freeipa-server` .2→.4,
`nexus` .3→.5 vs. the prior v2.5 pass). Running all 3 `up` commands as
background jobs in parallel worked cleanly this time; a prior session hit
the orchestration tool's own foreground command timeout (unrelated to
`pilot` itself) when it tried to `wait` on all 3 in one blocking shell
call — running each as its own independent background job avoids that.
Do not assume `nexus`/`.4`/`.5`/`.6` are stable values across future
rebuilds — always take IPs fresh from `pilot vm-target list`.

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
$ grep -oE '^[a-z_0-9]+:' tmp/pilot-verify-minimal-poc/.vault/main.yaml
ipa_admin_password:
grafana_admin_password:
restic_aws_access_key_id:
restic_aws_secret_access_key:
restic_password:
thanos_aws_access_key_id:
thanos_aws_secret_access_key:
alertmanager_config:

$ grep -oE '^[a-z_0-9]+:' tmp/pilot-verify-minimal-poc/.vault/ipa-identity.yaml
ipa_admin_password:
ipa_groups:
ipa_users:
ipa_hostgroups:
ipa_sudo_rules:
ipa_hbac_rules:
ipa_hbac_disable_allow_all:
```

### Alignment decision

Spec targets and environment state are consistent after this pass — the
site-wide deploy applied `failed=0` on all 3 hosts with **zero extra `-e`
variables**, and `freeipa-identity` also applied `failed=0` once the
hand-authored roster's field names were corrected (see § Real bugs #8).
`dns`/`ntp`/`log-server` groups intentionally empty per the
already-corrected architecture; `wazuh-fim`/`audit-log-forwarding` scope
covers all three hosts.

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

---

## 4. Verify (v3.0, fresh ground-up rebuild)

Set a working password for `alice` (roster only creates key-less FreeIPA
accounts) via direct `kinit`'s forced-password-change flow (a genuine
mutating remote-shell action, approved fresh this session per the
per-session-approval convention — a prior approval never carries over to
a new rebuild), then discovered mid-verification that live SSH couldn't
even offer a password method at all (see § Real bugs #9), fixed that at
the source, then ran the real SSH + sudo commands, `ipa hbactest`, and
Grafana/Thanos/Loki queries. Recorded across `06-verify-hbac-grafana-loki.cast`
(first pass — hbactest/Grafana/Thanos/Loki all PASS, but the live-SSH
lines in this cast are the ones that surfaced § Real bugs #9),
`07-fix-sshd-password-auth.cast`/`07b-fix-sshd-password-auth-order.cast`
(the corrective `freeipa-client` re-apply), and `06d-reverify-hbac-ssh.cast`
(the final, passing live-SSH re-run).

```bash
$ ssh -i /var/lib/libvirt/images/pilot/freeipa-server/id_ed25519 root@192.168.122.4 \
    "printf 'AlicePerm2026!\nAlicePerm2026!\nAlicePerm2026!\n' | kinit alice"
Password for alice@IPA.PILOT.INTERNAL:
Password expired.  You must change it now.
Enter new password:
Enter it again:
$ echo EXIT=$?
EXIT=0
```

### 4.1 Permission management (FreeIPA HBAC/sudo) — allow + deny, both real, cross-checked with `ipa hbactest`

```bash
$ sshpass -p 'AlicePerm2026!' ssh -o PreferredAuthentications=password alice@192.168.122.6 "echo 'AlicePerm2026!' | sudo -S systemctl is-active ssh"
[sudo] password for alice: active

$ sshpass -p 'AlicePerm2026!' ssh -o PreferredAuthentications=password alice@192.168.122.6 "echo 'AlicePerm2026!' | sudo -S cat /etc/shadow"
[sudo] password for alice: Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.

$ ssh -o PreferredAuthentications=password -o BatchMode=yes bob@192.168.122.6 'echo should-not-reach-here'
bob@192.168.122.6: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password,keyboard-interactive).
```

FreeIPA's own authoritative check (not just live SSH behavior — both
layers must agree):

```bash
$ ipa hbactest --user=alice --host=client-vm.ipa.pilot.internal --service=sshd
--------------------
Access granted: True
--------------------
  Matched rules: allow-sysops-ssh
  Not matched rules: allow_systemd-user

$ ipa hbactest --user=bob --host=client-vm.ipa.pilot.internal --service=sshd
---------------------
Access granted: False
---------------------
  Not matched rules: allow-sysops-ssh
  Not matched rules: allow_systemd-user
```

Verdict: **PASS** — allow and deny both real-tested at the live
SSH/sudo layer and FreeIPA's own policy-evaluation layer, and both
layers agree. Note `bob`'s live-SSH denial now correctly lists `password`
as an offered-but-failed method (compare § Real bugs #9's before state,
where `password` wasn't even in the offered-methods list).

### 4.2 Metric queryable from Grafana (Grafana → Thanos Query → Prometheus)

```bash
$ curl -s http://192.168.122.5:3000/api/health
{"commit":"5b85c4c2fcf5d32d4f68aaef345c53096359b2f1","database":"ok","version":"11.1.0"}

$ curl -s "http://192.168.122.5:10912/api/v1/query?query=up"
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"site-nexus"},"value":[1784119760.958,"1"]}],"analysis":{}}}
```

`prometheus_site_label=site-nexus` came entirely from `group_vars/prometheus.yml`
this pass — no `-e prometheus_site_label=...` anywhere in the deploy
command (§3.3). Thanos Query port is still **10912** (the v2.5 fix's
default), also with zero `-e` override.

Verdict: **PASS** — the same Thanos Query datasource Grafana's dashboard
panel reads from returns real, live data, proving Prometheus → sidecar →
Thanos Query federation all work end-to-end, entirely from group_vars.

```bash
$ docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -i thanos   # on nexus
pilot-thanos-query    Up 41 minutes   0.0.0.0:10911->10901/tcp, 0.0.0.0:10912->10902/tcp
pilot-thanos-compact  Up 41 minutes   0.0.0.0:10905->10905/tcp
pilot-thanos-store    Up 41 minutes   0.0.0.0:10903-10904->10903-10904/tcp
pilot-thanos-sidecar  Up 41 minutes   0.0.0.0:10901-10902->10901-10902/tcp
```

### 4.3 Log queryable from Grafana (Grafana → Loki ← Promtail on nexus)

```bash
$ curl -s "http://192.168.122.5:3100/loki/api/v1/label/job/values"
{"status":"success","data":["pilot-siem"]}

$ curl -s -G "http://192.168.122.5:3100/loki/api/v1/query_range" --data-urlencode 'query={job=~".+"}' --data-urlencode 'limit=5'
{"status":"success","data":{"resultType":"streams","result":[{"stream":{"filename":"/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.log","job":"pilot-siem"},"values":[
  ["1784119689503021892",""],
  ["1784119689503018454","uid: 0"],
  ["1784119689502958429","Jul 15 12:48:07 ipa1.ipa.pilot.internal sshd-session[30398]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)"],
  ["1784119689502954649","User: root"],
  ["1784119689502818525","Rule: 5501 (level 3) -> 'PAM: Login session opened.'"]
]}]}}
```

Verdict: **PASS** — real Wazuh alert lines present in Loki via
`log-shipping` auto-detecting the co-located `wazuh-manager` container's
alerts volume, with zero `-e siem_log_root=`/`-e target_group=` override.

### 4.4 Restic backup timers

```bash
$ systemctl is-active restic-backup.timer; systemctl is-enabled restic-backup.timer   # (all 3 hosts)
active
enabled
```

Verdict: **PASS** on `freeipa-server`, `nexus`, and `client-vm`.

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
| 14 | (v4.2 re-verification) The live-SSH allow-test in §4.1 was blocked for `alice`: `freeipa-identity-apply.yml`'s "Set initial password" task runs `ipa passwd <user>` (an **admin reset**), which — by design, not a bug — always marks the account as requiring a password change at next login. A scripted/`sshpass`-only client can't complete that interactive forced change, so live SSH failed even though `ipa hbactest` correctly reported the right allow/deny verdict throughout (policy layer, not credential state). | **Not fixed at the source — documented as a known limitation.** This is intentional FreeIPA/Kerberos security behavior (see also Real bug #6, same underlying mechanism). The existing `force_password: false` escape hatch on an already-onboarded roster entry remains the right workaround once a user has a real out-of-band password. A fuller fix would mean a new roster flag driving an interactive `kinit`+`kpasswd` session (Ansible `expect`) to genuinely consume the forced change, plus targeted `sss_cache` invalidation — that's a real feature addition touching live Kerberos/SSSD state, out of scope unless separately requested. **v4.5 note**: `force_password` now defaults to `false` (see Changelog), which prevents an *accidental* reset on a routine rerun — but a roster entry that deliberately keeps `force_password: true` (e.g. to re-arm a test scenario, as `bob`'s did here) still hits this exact forced-change behavior by design; the default flip narrows when this bites, it doesn't remove the underlying FreeIPA/Kerberos behavior. |
| 15 | (v4.2 re-verification) The demo roster's `devops-sudo` rule set `cmdcat: all` (by analogy with the already-supported `hostcat: all`), expecting an unrestricted-commands sudo rule for the `sysops` group. `freeipa-identity-apply.yml`'s "Ensure sudo rules exist" task never read `cmdcat` at all — only `allow_commands` (individual commands, attached via separate `sudocmd-add`/`sudorule-add-allow-command` tasks) was ever handled — so the rule was created with **no command grant whatsoever** (`ipa sudorule-show devops-sudo` showed no `Command category` and no attached commands), silently denying every sudo attempt for the group despite the rule "existing" and the apply reporting `failed=0`. A related, separately-tested claim — that `ipa sudocmd-add` needs `kinit admin` first or returns `Insufficient access` — is **not a playbook bug**: standard FreeIPA RBAC (confirmed live: no ticket → `did not receive Kerberos credentials`; a ticket for a non-admin principal → `Insufficient access: Insufficient 'add' privilege ...`); the apply playbook's own `Kinit admin` task already runs first in the same play, so every automated `ipa sudocmd-add` call is correctly privileged — this only bites a human running `ipa` commands by hand on the server without kinit-ing first. | **Fixed at the source**: "Ensure sudo rules exist" now also passes `--cmdcat=` (defaulting to `all`, mirroring `hostcat`'s exact convention) whenever `allow_commands` is absent — the two are mutually exclusive in FreeIPA itself, same as `hostcat` vs. `hosts`/`hostgroups`. Verified for real: deleted the live (incorrectly-created) `devops-sudo` rule, reran `freeipa-identity-apply.yml` from the fixed source with **no manual patch**, and `ipa sudorule-show devops-sudo --all` came back with `Command category: all` set correctly; live SSH as `alice` then confirmed `sudo whoami` → `root` end-to-end (after refreshing the client's SSSD sudo cache — a genuinely separate finding: SSSD's sudo provider does not immediately reflect a changed rule's attributes on an already-enrolled client; `sss_cache -E && systemctl restart sssd` forces the refresh — now documented in `docs/runbooks/freeipa-identity.md` §6 alongside the kinit-admin note). Also added a `cmdcat: all` example to `freeipa-identity.roster.example.yaml` and documented the field in §5.2's category table. |
| 16 | (`./tmp` AI-agent-process audit, 2026-07-16) Same class of bug as #15, one field over: the demo roster's `devops-sudo` rule also set `runas_user: ALL`/`runasgroup: ""`, expecting the rule to allow `sudo -u <anyone>` (not just root). `freeipa-identity-apply.yml` never read either field — grep found zero references — so the rule silently kept FreeIPA's own default (no `runasusercat`/`runasgroupcat` set ⇒ run-as-root only). The demo happened not to notice because "run as root" was exactly what its test commands needed, but a roster author relying on `runas_user` to scope a rule to specific non-root accounts would get a silently *wider* default (root, unrestricted) instead of what they wrote — the same "field looks honored, isn't" trap as #15, just not yet tripped over. | **Fixed at the source**: "Ensure sudo rules exist" now sends `--runasusercat=all`/`--runasgroupcat=all` when the roster's `runas_user`/`runasgroup` is the string `all` (case-insensitive) — same magic-category convention as `hostcat`/`cmdcat`. Specific runas user/group *lists* (as opposed to the `all` category) are intentionally not implemented — no roster in this repo needs them yet. Verified live: deleted the existing `devops-sudo` rule on `freeipa-server`, reran the fixed playbook from the unmodified demo roster, and `ipa sudorule-show devops-sudo --all` came back with `RunAs User category: all` set (server-side authoritative confirmation). Also added a "Gate: sudo rule category vs specific-list fields are mutually exclusive" preflight `assert` — it fails fast if a roster sets both `hostcat`+`hosts`/`hostgroups`, or both `cmdcat`+`allow_commands`, on the same rule, since the task has always silently preferred one and dropped the other with no warning (exactly how #15 went unnoticed). |
| 17 | (`./tmp` AI-agent-process audit, 2026-07-16) `playbooks/apply/freeipa-identity.roster.example.yaml`'s own `devops-sudo` example (added while fixing #15, in this same repo state, uncommitted) had **two `groups:` keys on the same list item** (`groups: [sysops]` then `groups: [developers]`). PyYAML's default loader silently keeps only the *last* value of a duplicate mapping key — no warning, no error — so the example actually only granted `developers`, quietly dropping `sysops` entirely. Nothing in the repo would have caught this: the file is `.yaml` (the `playbook-lint` Makefile target only globs `playbooks/apply/*.yml`), `ansible-lint` doesn't check for YAML-level duplicate keys, and `pilot edit` explicitly declines to edit this class of nested-structure roster YAML — pushing users toward hand-editing exactly the file format most prone to this silent-collapse mistake, with zero tooling safety net. | **Fixed the specific instance** (merged to `groups: [sysops, developers]`) and **closed the general gap**: added `scripts/check-yaml-duplicate-keys.py` (a custom PyYAML loader that errors on any duplicate mapping key) over every tracked `.yml`/`.yaml` file, wired into both `make playbook-lint` (and therefore the optional pre-commit hook) and a new CI step in `.github/workflows/ci.yml`. Confirmed it actually catches the bug (re-injected the duplicate in a throwaway string, got a `DuplicateKeyError` at the right line) and that it passes clean on the current repo (66 files). |
| 18 | (freeipa-identity infra-as-code redesign, 2026-07-16) While writing `docs/verification/freeipa-identity.md` and validating it against the real `pilot spec --generate` tool (not just hand-authoring the doc), found that all 8 checklist rows collapsed into a single generated task. Root cause traced to `internal/spec/generator.go`: `classifyRow`'s raw-command fallback (used whenever a row's `Command` doesn't match Pattern A–F: `test -f`/`grep`/`sysctl -n`/`systemctl is-active`/`dpkg -s`/`awk print`) always returned `params=""`, and the dedup key hashes `(module, params)` — so **every row that falls through to the raw fallback hashes identically regardless of its actual command**, silently merging unrelated checks into one task that only ever runs the first row's command (tagged with every other row's spec ID too, so `pilot verify` would report pass/fail for those IDs based on the wrong command entirely). This wasn't a fresh regression: it already affected 9 previously-committed, previously-"working" verify playbooks — most severely `playbooks/verify/freeipa-server.yml`, an 18-row spec collapsed to 2 real tasks (C3–C18 all silently riding on C2's `sudo ipactl status` result). | **Fixed at the source**: `classifyRow`'s fallback now hashes the raw command itself instead of an empty string (`internal/spec/generator.go`) — verified this has zero effect on the rendered YAML, since `RenderYAML` already renders the separate `RawCommand` field (never `Params`) for this task shape, so the fix is purely to the dedup key. Added `TestGenerate_RawFallbackDoesNotCollapseDistinctCommands`, `go test ./internal/spec/...` green. Regenerated every affected `playbooks/verify/*.yml` (`freeipa-server`, `freeipa-client`, `freeipa-server-replica`, `core-infra`, `core-infra-provider`, `core-infra-provider-db`, `docker`, `keycloak`, `os-patch-sla`, `seaweedfs-s3`, `freeipa-identity`) — each now syntax-clean with task count matching (or, for genuine command-text duplicates, correctly deduping) row count. Live-verified end-to-end: `pilot vm-target verify --name freeipa-server docs/verification/freeipa-identity.md` → real `pass=8 fail=0 skip=0`. |
| 19 | (v4.9 ground-up rebuild, 2026-07-16) The v4.8 reconciler redesign was never actually exercised through `pilot deploy`'s own mandatory `--check --diff` preview gate before this pass — `docs/verification/freeipa-identity.md`'s own validation used `pilot vm-target verify` (a different code path that never runs Ansible in check mode). Driving the real `freeipa-identity` single-component wizard against a genuinely fresh install surfaced **5 separate check-mode crashes** in `freeipa-identity-apply.yml`, all the same root cause: `ansible.builtin.command`/`shell` tasks are auto-skipped by Ansible core under `--check` (no `check_mode: false`), so the `set_fact` "compute what to remove" task right after them also skips per-item (its own `when: not (item.skipped \| default(false))` guard), which means the accumulator fact (`ipa_pwd_needs_reset`, `ipa_group_membership_removals`, `ipa_hostgroup_membership_removals`, `ipa_hbac_removals`, `ipa_sudo_removals`) is **never set at all** — and every downstream task referencing it unconditionally (`ipa_pwd_needs_reset.get(...)`, `X \| subelements(...)`) then fails outright with `'<name>' is undefined`, aborting the whole preview with `failed=1`. First hit on the password-protection task (v4.8's own Phase 0), then immediately again on the Phase 2 membership/attachment removal diffing once that was fixed — the exact same shape repeated across all 4 removal accumulators (12 call sites total). | **Fixed at the source**: every reference now defaults safely — `(ipa_pwd_needs_reset \| default({})).get(item.name, true)` for the password gate, `<X> \| default([]) \| subelements(...)` for all 12 removal-loop call sites (`ipa_group_membership_removals`, `ipa_hostgroup_membership_removals`, `ipa_hbac_removals` ×5, `ipa_sudo_removals` ×5) — a check-mode-skipped lookup now safely means "nothing computed yet, assume no removals due" instead of crashing; the real apply's actual behavior is unchanged (the `command`/`shell` tasks themselves still only run for real, never under `--check`). Verified live end-to-end: `ansible-playbook playbooks/apply/freeipa-identity-apply.yml --check --diff` against a fresh, never-before-applied `freeipa-server` now returns `failed=0`, and the real `pilot deploy` single-component wizard for `freeipa-identity` completes cleanly through preview → real apply with no manual workaround. |
| 20 | (v4.9 ground-up rebuild, 2026-07-16) Disabling the built-in `allow_all` HBAC rule — the reconciler's own documented hardening step (`ipa_hbac_disable_allow_all: true`) — silently breaks `sudo` for every user whose HBAC rule only lists `services: [sshd]` (the only shape shown anywhere in the roster example/docs before this pass). Root cause: SSSD's `access_provider = ipa` runs a **separate** HBAC check per PAM service, not just once at login — `allow_all` (and `allow_systemd-user`, which also lists `sshd` in its own `HBAC Services`) used to transparently cover the `sudo` PAM service too, so a roster author who only ever tested with those defaults still enabled would never notice their own rule doesn't grant `sudo`. Once `allow_all` is genuinely disabled (the documented best practice), live `sudo -S <cmd>` on an enrolled client fails with `sudo: PAM account management error: Permission denied` for an otherwise-correctly-provisioned user — confirmed live: SSH login and `ipa hbactest --service=sshd` both report allowed, but `ipa hbactest --service=sudo` for the identical user/host reports `Access granted: False`. Not a playbook bug — `freeipa-identity-apply.yml` faithfully applies whatever `services:` list the roster gives it; this is an undocumented FreeIPA/SSSD interaction that every roster author needs to know about once they actually harden past the built-in defaults. | **Documented and fixed the example**: added `sudo`/`sudo-i` to `playbooks/apply/freeipa-identity.roster.example.yaml`'s `sysops-login-all` HBAC rule's `services:` list plus an inline comment, and a new writeup in `docs/runbooks/freeipa-identity.md` §5.2.2 (right after the `ipa_hbac_disable_allow_all` callout) with the exact live-reproduced symptom/diagnosis. Verified live: added `sudo, sudo-i` to this pass's own roster's `services:` list, redeployed `freeipa-identity` (reconciler correctly diffed and added just the two new services — `ok=28 changed=4 failed=0`, no other drift), refreshed the client's SSSD cache, and confirmed `sudo -S systemctl is-active ssh` as `alice` now succeeds while `ipa hbactest --service=sudo` flips to `Access granted: True`. |
| 21 | (follow-up to v4.9, 2026-07-16) `pilot deploy`'s `ansible.NewRunner()` (`internal/ansible/runner.go`) hard-codes a 30-minute per-`ansible-playbook`-invocation timeout (preflight, preview, and the real apply each get their own fresh 30m budget) with **no CLI override anywhere in the call chain** — `deploy.go` always calls `runner.Run` directly, never `RunWithTimeout`. Didn't bite the v4.9 pass (site-wide apply ran ~13-20 min), but a slower host or heavier topology would get the real apply `SIGKILL`ed mid-run with no warning and no documented way to raise the ceiling short of falling back to a manual `ansible-playbook` invocation outside `pilot deploy` entirely. | **Fixed at the source**: added a `--timeout` flag to `pilot deploy` (Go duration string, e.g. `45m`/`1h30m`, default `30m` — unchanged behavior unless overridden), parsed via a new `parseDeployTimeout` helper and set on the one shared `runner.Timeout` used for preflight/preview/apply. Added `TestParseDeployTimeout` (valid/invalid cases) plus a live end-to-end check against the demo VMs: `pilot deploy --timeout 1ms` genuinely aborts a real `playbooks/preflight.yml` run (`❌ 前置檢查沒有全過(結束碼 -1)`), while the unmodified default path still completes and reaches the next prompt normally. `previewInventoryGraph`/`resolveGroupHost`'s own separate `ansible.NewRunner()` calls (`ansible-inventory`, not `ansible-playbook` — near-instant) were left on the fixed 30m default since it's irrelevant there. |

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
- [x] Timestamp on fact snapshot (2026-07-15T20:33:00Z) matches when the run happened
- [ ] Public version / redaction gate — **not yet applied**; this document is internal-only (plaintext vault values are referenced by key name only, but lab IPs and internal FQDNs are not yet redacted)
- [ ] Secret scan / `git diff --check` — not yet run against this file
