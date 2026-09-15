# Pilot Gateway Scope `all` keyword — actual-run evidence (2026-09-15)

## Tested revision and target

- Repository `HEAD` at test start: `a0a83754ccb7a435197ad100f24ecc11613f06d6`.
- The worktree was intentionally dirty because unrelated portal changes were
  already present; the execution-affecting files used by this run are listed
  below with their SHA-256 in the raw evidence directory.
- Target: disposable vm-targets `ag-spike-ipa` (FreeIPA server), `ag-gw01`,
  `ag-gw02`, and `ag-target01`.
- Grouped inventory was rendered from the existing VMs with
  `pilot vm-target topology inventory`; the captured inventory is
  [`inventory.yml`](../../../.verification/pilot-gateway-scope/2026-09-15-all/inventory.yml).

Execution-affecting file hashes at the successful run:

```text
cf360265dc8b2e0d223f4ba3cafea672bb6ae71dc72d4a7937ff440013528b9d  cmd/pilot/cmd/gateway_scope.go
7cac2e0a8f59d9716d40713f6fca71ec4deed7bd758874daf2ed68e2d861635b  cmd/pilot/cmd/gateway_scope_test.go
b0ed9c01e51e298b868a0d7f37fe6eb07adc0b4b24919b77dde7fb21b96ebcc9  docs/verification/pilot-gateway-scope.md
805de1c7d62554c5252591f60677e30aae75c1a9d468e8b0bd3843cb01270de1  internal/inventory/hostvars.go
7fbdab0cb325104ceffec7097b85d1d014bdf3c4270decd5b1b312e78b6f1363  internal/inventory/hostvars_test.go
eb65ceb6e60b7fa5fc48cfe78c1f5163a70b738371b81e8285eb40b9d37f5791  playbooks/apply/gateway-scope-apply.yml
```

The actual inventory fact used for expansion was:

```text
freeipa-server: ag-spike-ipa
freeipa-client: ag-gw01, ag-gw02, ag-target01
pilot-access-gateway: ag-gw01, ag-gw02
```

`ansible-inventory --graph` returned the same group membership. It emitted
only the repository's existing warning about hyphens in group names.

## `--hosts all` controller verification

Using a unique temporary scope, the real CLI reported:

```text
`--hosts all` expanded from inventory group "freeipa-client": ag-gw01, ag-gw02, ag-target01
```

The first `plan` completed without mutation:

```text
add: ag-gw01, ag-target01, ag-gw02
hostgroup_exists: false
remove: []
PLAY RECAP: ok=9 changed=0 unreachable=0 failed=0 skipped=4
```

The first `reconcile` created the temporary hostgroup and published all three
members:

```text
PLAY RECAP: ok=11 changed=2 unreachable=0 failed=0 skipped=2
Member hosts: ag-gw02.ipa.pilot.internal, ag-gw01.ipa.pilot.internal, ag-target01.ipa.pilot.internal
```

A second identical `reconcile` reported the expected stable state:

```text
add: []
keep: ag-gw02, ag-gw01, ag-target01
remove: []
PLAY RECAP: ok=10 changed=0 unreachable=0 failed=0 skipped=3
```

The temporary `pilot-target-all-keyword-20260915` hostgroup was then deleted;
the existing `gpu` scope was not changed.

## Playbook and verification contract

`pilot vm-target test` against `ag-spike-ipa` completed the full chain for
`gateway-scope-apply.yml` and `pilot-gateway-scope.md`:

```text
L1 syntax check       PASS
L3 --check --diff      PASS
L4 apply               PASS
L5 verification       PASS (C1-C3, 3/3)
L6 idempotency         PASS (changed=0)
```

The verification report and NDJSON are retained at
[`pilot-gateway-scope-20260915-030850.md`](../../../.verification/pilot-gateway-scope-20260915-030850.md)
and [`pilot-gateway-scope-20260915-030850.ndjson`](../../../.verification/pilot-gateway-scope-20260915-030850.ndjson).
The controller-side Ansible log, including the inventory snapshots and the
plan/reconcile recaps, is
[`controller-ansible.log`](../../../.verification/pilot-gateway-scope/2026-09-15-all/controller-ansible.log).

## Operational contract confirmed

- `all` expands only the selected inventory's `freeipa-client` group; it does
  not mean Ansible's `all` group or every FreeIPA host object.
- Empty `--hosts`, blank entries, and mixing `all` with explicit hosts fail
  closed.
- `gateway_scope: all` remains an ordinary scope label; the expansion happens
  only when the CLI receives `--hosts all`.
- Adding a new `freeipa-client` host requires another reconcile; this is not a
  background synchronizer.
