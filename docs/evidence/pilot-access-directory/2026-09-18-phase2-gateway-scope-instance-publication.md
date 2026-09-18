# Phase 2 — Gateway scope-instance publication (`pilot-gateway-<scope>`)

Spec: `docs/tmp/now/spec.md` §7, Phase 2 landing gate (§44).

## Goal

Every `pilot-access-gateway` apply must publish its own host into
`pilot-gateway-<gateway_scope>` — the live source of truth
`pilot-access-directory` will read for routing (never derived from
hostname, D3) — and self-scrub any stale membership left over from a
previous `gateway_scope` value, mirroring the existing Step 3/3b pattern
(`pilot-access-gateways` self-add + `pilot-target-<scope>` stale scrub)
exactly.

**Not to be confused with** the pre-existing `pilot gateway-scope` CLI
(`cmd/pilot/cmd/gateway_scope.go`), which manages `pilot-target-<scope>`
target-host membership and has nothing to do with this hostgroup family.

## Changes

- `playbooks/apply/pilot-access-gateway-apply.yml`:
  - new play var `gateway_instance_hostgroup: "pilot-gateway-{{ gateway_scope }}"`
  - Step 3c: ensure `pilot-gateway-<scope>` exists + self-add (same
    `hostgroup-add`/`hostgroup-add-member` shape as Step 3).
  - Step 3d: discover + remove stale `pilot-gateway-*` membership (same
    `hostgroup-find --hosts=.. --raw` / `regex_findall` shape as Step 3b),
    excluding the current `gateway_instance_hostgroup` so it doesn't
    remove what Step 3c just (re)added.

No contract/groupVar changes needed — `gateway_scope` is already a
required groupVar; `gateway_instance_hostgroup` is a derived play var,
not a new input.

## Live verification

Topology: the same reusable `ag-spike-ipa`/`ag-gw01`/`ag-gw02` vm-targets.
Baseline before this session: `ag-gw01` = `gateway_scope=gpu`, `ag-gw02` =
`gateway_scope=dmz`; no `pilot-gateway-*` hostgroup existed yet.

### 1. First apply, ag-gw01 (scope=gpu, unchanged)

```
$ pilot vm-target run --name ag-gw01 playbooks/apply/pilot-access-gateway-apply.yml \
    -e target_group=all -e gateway_id=gpu-01 -e gateway_scope=gpu ... -e @~/.vault/main.yaml
...
TASK [Step 3c: ensure pilot-gateway-<scope> hostgroup exists] -> changed
TASK [Step 3c: add this host to pilot-gateway-<scope>]        -> changed
TASK [Step 3d: discover stale pilot-gateway-<scope> membership] -> ok
TASK [Step 3d: remove stale pilot-gateway-<scope> membership]   -> skipping (none found)
PLAY RECAP: ag-gw01  ok=64  changed=5  failed=0
```

### 2. Second apply, ag-gw01 (idempotency)

```
TASK [Step 3c: ensure pilot-gateway-<scope> hostgroup exists] -> ok
TASK [Step 3c: add this host to pilot-gateway-<scope>]        -> ok
TASK [Step 3d: discover stale pilot-gateway-<scope> membership] -> ok
TASK [Step 3d: remove stale pilot-gateway-<scope> membership]   -> skipping
PLAY RECAP: ag-gw01  ok=62  changed=0  failed=0
```

### 3. Two same-scope gateways — temporarily deploy ag-gw02 as scope=gpu

```
$ pilot vm-target run --name ag-gw02 ... -e gateway_id=dmz-01 -e gateway_scope=gpu ...
TASK [Step 3c: ensure pilot-gateway-<scope> hostgroup exists] -> ok (already exists from ag-gw01)
TASK [Step 3c: add this host to pilot-gateway-<scope>]        -> changed
PLAY RECAP: ag-gw02  ok=64  changed=7  failed=0

$ ipa hostgroup-show pilot-gateway-gpu
  Member hosts: ag-gw01.ipa.pilot.internal, ag-gw02.ipa.pilot.internal
```

Two same-scope Gateway instances correctly land in the same hostgroup —
landing gate item 1.

### 4. Revert ag-gw02 to scope=dmz — stale membership scrub

```
$ pilot vm-target run --name ag-gw02 ... -e gateway_id=dmz-01 -e gateway_scope=dmz ...
TASK [Step 3c: ensure pilot-gateway-<scope> hostgroup exists] -> changed (pilot-gateway-dmz created)
TASK [Step 3c: add this host to pilot-gateway-<scope>]        -> changed
TASK [Step 3d: discover stale pilot-gateway-<scope> membership] -> ok
TASK [Step 3d: remove stale pilot-gateway-<scope> membership]   -> changed: (item=pilot-gateway-gpu)
PLAY RECAP: ag-gw02  ok=64  changed=5  failed=0

$ ipa hostgroup-show pilot-gateway-gpu
  Member hosts: ag-gw01.ipa.pilot.internal
$ ipa hostgroup-show pilot-gateway-dmz
  Member hosts: ag-gw02.ipa.pilot.internal
```

Scope change correctly moves membership: ag-gw02 left `pilot-gateway-gpu`
and joined `pilot-gateway-dmz`, ag-gw01 unaffected — landing gate item 2.

`ag-gw02`'s `/etc/pilot/access-gateway.yaml` was confirmed back to
`scope: dmz` / `target_hostgroup: pilot-target-dmz` — fully restored to
its pre-session baseline (`gateway_id=dmz-01`, `gateway_scope=dmz`), no
residual drift left on this shared vm-target for other evidence sessions.

## Result

All three Phase 2 landing gate items met: two same-scope Gateways
correctly co-resident in one hostgroup, scope change removes old
membership, second apply is `changed=0`. `ansible-playbook --syntax-check`
and `ansible-lint` on the modified playbook show no new findings beyond
pre-existing, unrelated warnings in a shared task file
(`playbooks/apply/tasks/apt-package-install.yml`).
