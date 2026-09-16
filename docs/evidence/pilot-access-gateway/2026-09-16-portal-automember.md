# `pilot_access_gateway_portal_automember` — vm-target Evidence (2026-09-16)

Scope: opt-in feature added to `playbooks/apply/pilot-access-gateway-apply.yml`
so every FreeIPA account automatically joins `gateway_effective_portal_user_group`
via a FreeIPA automember rule, instead of an operator hand-listing members in
the freeipa-identity roster. Requested after diagnosing why
`pilot-access-gateway` had no practical effect on a real site
(`infra-deploy`/`bastion-test`): `role-pilot-portal-user` self-provisioned
empty (2026-09-15's group/HBAC self-provisioning change), and the site's
`hbac.disable_allow_all: false` meant everyone could already SSH into the
gateway host with a normal shell — only membership in the portal group
determined whether they got routed through the ForceCommand portal session at
all.

## Topology

Reused the still-running Phase 7/8 vm-targets rather than provisioning new
ones:

- `ag-spike-ipa` (192.168.122.2) — FreeIPA server.
- `ag-gw01` (192.168.122.3) — `pilot-access-gateway`, `gateway_id=gpu-01`,
  `gateway_scope=gpu`, `pilot_access_gateway_install_forcecommand=false`
  (unchanged — this feature is orthogonal to ForceCommand).

Baseline before this session: `role-pilot-portal-user` had one member
(`alice`), no group-type automember rule existed.

## Manual `ipa` CLI capture (before writing playbook tasks)

Real captured output used to write the `changed_when`/`failed_when`
conditions — never hand-typed:

```
$ ipa automember-add role-pilot-portal-user --type=group --desc="..."
----------------------------------------------
Added automember rule "role-pilot-portal-user"
----------------------------------------------
  Automember Rule: role-pilot-portal-user
  Description: ...
RC=0

$ ipa automember-add role-pilot-portal-user --type=group --desc="..."   # rerun
ipa: ERROR: Automember rule with name "role-pilot-portal-user" already exists
RC=1
```

```
$ ipa automember-add-condition role-pilot-portal-user --type=group --key=uid --inclusive-regex=".*"
----------------------------------------------
Added condition(s) to "role-pilot-portal-user"
----------------------------------------------
  ...
  Inclusive Regex: uid=.*
----------------------------
Number of conditions added 1
----------------------------
RC=0

$ ipa automember-add-condition role-pilot-portal-user --type=group --key=uid --inclusive-regex=".*"   # rerun
----------------------------------------------
Added condition(s) to "role-pilot-portal-user"
----------------------------------------------
  Inclusive Regex: uid=.*
----------------------------
Number of conditions added 0
----------------------------
RC=0
```

Rerunning `automember-add-condition` never errors (RC=0 both times) — only
`Number of conditions added` distinguishes new vs. already-present.

## Finding 1 — `uid=.*` alone also sweeps in the built-in `admin` account

```
$ ipa user-add automembertest --first Auto --last MemberTest --password ...
  Member of groups: ipausers, role-pilot-portal-user     # ← joins immediately at creation, before any rebuild

$ ipa group-show role-pilot-portal-user | grep -i "member users"
  Member users: alice, automembertest

$ ipa automember-rebuild --type=group
Automember rebuild task finished. Processed (4) entries in 0 seconds

$ ipa group-show role-pilot-portal-user | grep -i "member users"
  Member users: alice, automembertest, bob, admin        # ← admin swept in
```

`admin` is the account this site's `admin-breakglass-access` HBAC rule
(hostcat=all) exists to give unconditional emergency SSH access to every
host, including the gateway. Sweeping it into the portal group would make
`admin`'s login to any ForceCommand-enabled gateway also get hijacked into
the restricted portal session, defeating that break-glass path. Fixed with
an exclusive-regex condition; default exclude list is
`pilot_access_gateway_portal_automember_exclude_users: ["admin"]`.

## Finding 2 — a targeted `automember-rebuild --users=<name>` ignores exclusive-regex conditions

```
$ ipa group-remove-member role-pilot-portal-user --users=admin   # undo the accidental sweep
$ ipa automember-add-condition role-pilot-portal-user --type=group --key=uid --exclusive-regex="^admin$"
----------------------------------------------
Added condition(s) to "role-pilot-portal-user"
----------------------------------------------
  Inclusive Regex: uid=.*
  Exclusive Regex: uid=^admin$
----------------------------
Number of conditions added 1
----------------------------

$ ipa automember-rebuild --type=group --users=admin      # targeted rebuild
Automember rebuild task finished. Processed (1) entries in 0 seconds
$ ipa group-show role-pilot-portal-user | grep -i "member users"
  Member users: alice, automembertest, bob, admin        # ← admin re-added despite the exclusion!

$ ipa group-remove-member role-pilot-portal-user --users=admin
$ ipa automember-rebuild --type=group                    # untargeted (full) rebuild
Automember rebuild task finished. Processed (4) entries in 0 seconds
$ ipa group-show role-pilot-portal-user | grep -i "member users"
  Member users: alice, automembertest, bob                # ← admin correctly stays excluded
```

Reproducible: targeted `--users=`/`--hosts=` rebuild bypasses exclusive-regex
evaluation on this FreeIPA version; the untargeted full rebuild honors it.
The playbook's backfill task therefore always calls the untargeted form.

## Playbook run — first apply (fresh creation)

```
$ pilot vm-target run --name ag-gw01 playbooks/apply/pilot-access-gateway-apply.yml \
    -e target_group=all -e gateway_id=gpu-01 -e gateway_scope=gpu \
    -e '{"freeipa_servers": ["ipa1.ipa.pilot.internal"]}' -e ipa_realm=IPA.PILOT.INTERNAL \
    -e pilot_binary_path=dist/pilot-linux-amd64 \
    -e pilot_access_gateway_binary_path=dist/pilot-access-gateway-linux-amd64 \
    -e pilot_access_gateway_portal_automember=true \
    -e @~/.vault/main.yaml

TASK [Automember: ensure rule exists for the portal-user group (opt-in)] *******
changed: [ag-gw01]
TASK [Automember: ensure inclusive uid=.* condition exists (matches every FreeIPA account)] ***
changed: [ag-gw01]
TASK [Automember: exclude break-glass accounts from auto-joining] **************
changed: [ag-gw01] => (item=admin)
TASK [Automember: backfill existing FreeIPA accounts into the portal-user group] ***
ok: [ag-gw01]

PLAY RECAP: ag-gw01  ok=55  changed=1  unreachable=0  failed=0  skipped=11
```

## Playbook run — second apply (idempotency)

```
TASK [Automember: ensure rule exists for the portal-user group (opt-in)] *******
ok: [ag-gw01]
TASK [Automember: ensure inclusive uid=.* condition exists (matches every FreeIPA account)] ***
ok: [ag-gw01]
TASK [Automember: exclude break-glass accounts from auto-joining] **************
ok: [ag-gw01] => (item=admin)
TASK [Automember: backfill existing FreeIPA accounts into the portal-user group] ***
ok: [ag-gw01]
```

All four automember tasks report `ok` (no `changed`) on rerun. (The `--check
--diff` dry-run before this — same extra-vars plus `--check --diff` — showed
all four `skipping`, matching `ansible.builtin.command`'s default check-mode
behavior for every other `ipa` command task in this playbook; no explicit
`not ansible_check_mode` guard needed.)

## End-to-end proof (new account + existing account + exclusion), via `pilot vm-target exec`

```
$ ipa user-add newhire01 --first New --last Hire --password ...
  Member of groups: ipausers, role-pilot-portal-user      # real-time automember at creation

# on ag-gw01 (the gateway host itself):
$ getent group role-pilot-portal-user
role-pilot-portal-user:*:261200009:alice
$ sss_cache -E && getent group role-pilot-portal-user
role-pilot-portal-user:*:261200009:alice,bob,newhire01     # SSSD caught up; bob backfilled by
                                                            # the automember=true reapply above,
                                                            # newhire01 via real-time automember
```

`admin` never reappeared in `role-pilot-portal-user` across any of the above
playbook runs.

## Addendum — default flipped to `true` same day

After this evidence was captured, the user asked for the behavior to be the
default rather than something requiring an extra `-e` flag: "FreeIPA users
should get a portal session, never a shell, on this gateway, out of the box."
`pilot_access_gateway_portal_automember`'s default changed from `false` to
`true` in `contracts/pilot-access-gateway.yaml` and the playbook's
`pilot_access_gateway_effective_portal_automember` computed var. Re-verified
on the same vm-targets, from a confirmed-clean baseline
(`ipa automember-find --type=group` → 0 rules, `role-pilot-portal-user` →
`alice` only), that a real apply **with no `pilot_access_gateway_portal_automember`
extra-var at all** now runs the automember tasks (`changed` on all three
creation tasks, `bob` correctly backfilled, `admin` correctly excluded) —
proving the Jinja `default(true)` fallback actually takes effect through
Ansible's normal precedence, not just that the contract file says `true`.
Cleaned up (`automember-del`, removed `bob`) back to the `alice`-only
baseline afterward.

## Cleanup

Restored `ag-spike-ipa`/`ag-gw01` to the pre-existing Phase 7/8 baseline:
deleted `automembertest`/`newhire01`, deleted the
`role-pilot-portal-user` automember rule (`ipa automember-del
role-pilot-portal-user --type=group`), and removed `bob` from
`role-pilot-portal-user` so the group is back to its original single member
(`alice`). Both vm-targets were left running (per this repo's convention of
reusing long-lived Phase 7/8 fixtures across sessions) rather than torn down.
