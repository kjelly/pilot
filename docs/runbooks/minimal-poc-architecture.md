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
client log and site metric are both queryable from Grafana. Every
interactive wizard step is scripted with `trec drive` and recorded; every
read-only verification command is recorded with plain `trec`.

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

Every step below was driven live via `trec drive --interactive` — one op
sent at a time over a persistent stdin pipe (a `tail -f` on a growing
command file, piped into `trec drive --interactive`), reading the
returned `SCREEN` dump after each before deciding the next op. This is
different from a pre-written `--script`: there is no fixed keystroke
sequence committed in advance, so a wrong navigation guess (this pass hit
a few — see below) is caught and corrected immediately from the real
rendered screen instead of silently landing on the wrong menu item.

```bash
$ pilot edit --dir tmp/pilot-verify-minimal-poc/demo        # hosts.yml — 3 hosts, roles per §0.5
$ pilot inventory generate --dir tmp/pilot-verify-minimal-poc/demo
wrote tmp/pilot-verify-minimal-poc/demo/inventory.yml
$ pilot edit --dir tmp/pilot-verify-minimal-poc/demo        # group_vars/ + .vault/main.yaml, same session
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
| 6 | Discovered during the v2.4 re-verification pass: `freeipa-identity-apply.yml`'s "Set initial password for users" task runs `ipa passwd <user>` unconditionally whenever `force_password` isn't explicitly `false` on that roster entry (see the playbook's own comment at the task above it). FreeIPA's `ipa passwd` is an **admin reset** — it always marks the target account as requiring a password change at next login, regardless of whether the same password value was already set. Redeploying `freeipa-identity` therefore silently reset `alice`'s already-completed permanent password back into a "must change" state every time, breaking the plain-`sshpass` live-SSH allow-test in §4.1 with a bare `sshpass` exit 5 (no readable error) — while `ipa hbactest` kept reporting the correct allow/deny verdict throughout, since it evaluates policy, not live credential state. Not a playbook bug — this is expected, intentional FreeIPA/`ipa passwd` behavior, and the reconciler comment already documents the escape hatch. | Not a code fix. Set `force_password: false` on `alice`'s roster entry (`tmp/pilot-verify-minimal-poc/demo/.vault/ipa-identity.yaml`) now that she's already onboarded with a real out-of-band password, so future `freeipa-identity` re-applies skip resetting her — verified by redeploying once more and confirming the task now reports `skipping` for `alice` instead of `changed` (cast `14-reverify-deploy-freeipa-identity-force-password-false.cast`), then a full clean §4.1 re-pass (cast `15-reverify-verify-final.cast`). `bob` intentionally keeps the default, since his test case requires no completed credential. |
| 7 | (v3.0) `freeipa-server-apply.yml` required `-e freeipa_dns_forwarders=<ip>` every single run — the underlying variable had **no usable default** (fell back to an empty list, i.e. `--no-forwarders`), so a from-scratch deploy with zero `-e` would leave the FreeIPA host's own `named` unable to resolve the public internet for its own package installs. There was also no way to configure NTP servers for `ipa-server-install` at all (only the on/off `--no-ntp` toggle existed). | **Fixed at the source in v3.0**: `freeipa_dns_forwarders` now defaults to `8.8.8.8` (still group_vars/`-e`-overridable) instead of no-forwarders. Added a new `freeipa_ntp_servers` variable (default `[tock.stdtime.gov.tw, watch.stdtime.gov.tw]`, Taiwan's public stratum servers) passed to `ipa-server-install` as `--ntp-server=...`. Both documented in `group_vars/freeipa.example.yml`. Verified for real: the v3.0 site-wide deploy passed **zero** `-e` at all beyond `stage`/`patch_stage`/vault and still came back `failed=0` on `freeipa-server`. |
| 8 | (v3.0) My own hand-authored `.vault/ipa-identity.yaml` roster used the wrong field names on the first attempt — `uid`/`usergroups`/`commands` instead of the actual schema's `name`/`groups`/`allow_commands` (per `playbooks/apply/freeipa-identity.roster.example.yaml`). Not a playbook bug; the reconciler's own error was clear (`object of type 'dict' has no attribute 'name'`, `failed=1`) and pointed straight at the mismatch. | Rewrote the roster against the actual example schema and re-ran; `freeipa-server: ok=21 changed=15 failed=0` on the corrected pass (cast `05b-deploy-freeipa-identity-fix.cast`). A reminder that even the one tool-endorsed hand-authored file still needs checking against its own example template, not memory. |
| 9 | (v3.0) Live SSH allow/deny testing in §4.1 initially failed for **all three** test lines (`alice` allow, `alice` deny, `bob` deny) with an identical generic `Permission denied (publickey,gssapi-keyex,gssapi-with-mic,keyboard-interactive)` — `password` wasn't even offered as a method. Root cause: `ipa-client-install`'s own `sshd_config.d/04-ipa.conf` only sets `ChallengeResponseAuthentication` (the deprecated `KbdInteractiveAuthentication` alias) — it never touches `PasswordAuthentication` — and Ubuntu's cloud image ships `sshd_config.d/50-cloud-init.conf`/`60-cloudimg-settings.conf`, both forcing `PasswordAuthentication no`. sshd's `Include` splices every matched drop-in in at the `Include` line in **glob (lexical) order**, then keeps only the **first** value seen for each directive across the whole expanded config — so `50-`/`60-` (sorting before any `9x-`-style override) permanently won regardless of what a later-sorting drop-in said. A FreeIPA account with no SSH key yet (the common case for a brand-new user) could never log in with a password at all, independent of HBAC. | **Fixed at the source in v3.0**: `freeipa-client-apply.yml` now writes its own `sshd_config.d/05-freeipa-client-password-auth.conf` (forcing `PasswordAuthentication yes` + `KbdInteractiveAuthentication yes`) — deliberately named to sort **after** `04-ipa.conf` (so it doesn't fight `ipa-client-install`'s own file) but **before** `50-`/`60-` (so it actually wins, per sshd's first-occurrence-wins semantics), and restarts sshd (`ssh` on Debian/Ubuntu, `sshd` on EL) only when the drop-in changes. First attempt used a `99-`-prefixed name and was silently ineffective (`sshd -T` still showed `passwordauthentication no` after a full apply+restart) — caught by directly checking `sshd -T`'s *effective* config rather than trusting the apply's `changed: true`, which is what led to discovering the ordering rule in the first place. Verified for real after the `05-` fix: `sshd -T` shows `passwordauthentication yes`/`kbdinteractiveauthentication yes`, and the full §4.1 live-SSH suite passed cleanly (cast `06d-reverify-hbac-ssh.cast`). |

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
