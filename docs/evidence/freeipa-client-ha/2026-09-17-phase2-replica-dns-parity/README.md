# Phase 2 — Replica DNS Parity, vm-target evidence (2026-09-17)

Topology: `docs/topologies/freeipa-ha-topology.yaml` (`ipa-primary`/`ipa-replica`
AlmaLinux 9, `ipa-ha-client` Ubuntu 24.04). `ipa-primary` deployed with
`freeipa-server-apply.yml` (default `ipa_setup_dns=true`).

## Scenarios (all real `pilot vm-target run`/`verify`, not simulated)

1. `1-fresh-replica-dns-false.log` — fresh `ipa-replica`, explicit
   `-e freeipa_setup_dns=false` (simulates the pre-Phase-2 asymmetric
   default / an operator who opted out at replica time). Result: `ok=18
   changed=6 failed=0`; Day-2 DNS check runs, install tasks correctly skip,
   no drift warning (desired matches actual — both absent).
2. `2-day2-reconcile-dns-true.log` — same replica, rerun WITHOUT the
   override (default now `true`). Result: `ok=20 changed=2 failed=0`; the
   Day-2 reconciliation installs `ipa-server-dns` and runs `ipa-dns-install`
   retroactively. `named.service` confirmed active afterward.
3. `3-idempotent-rerun.log` — same replica, rerun again with the same vars.
   Result: `ok=18 changed=0 failed=0` — Day-2 DNS tasks correctly no-op now
   that `named.service` is already active.
4. `4-drift-warning-not-destructive.log` — same replica, rerun with
   `-e freeipa_setup_dns=false` again while DNS is now active. Result:
   `changed=0`, the drift-warning task fires with the exact message, and
   `named.service` remains active afterward (confirmed via a separate
   `systemctl is-active` check) — Pilot does NOT auto-remove an existing DNS
   role, per spec §10.1.
5. `5-full-verify-16-rows-pass.md` — `pilot vm-target verify` against
   `docs/verification/freeipa-server-replica.md` after step 2/3, full
   **16/16 PASS** including the new C16 row.

## Real bug found during this pass (infra, not FreeIPA-specific)

`ipa-replica-install`/`ipa-client-install` failed twice with a generic
`ScriptError` (`"Configuration of client side components failed!"` /
`CLIENT_INSTALL_ERROR`) on a freshly-`vm-target reset` AlmaLinux 9 replica.
Root cause: the guest's SYSTEM clock was **54 minutes behind** its own
hardware clock (and the primary's clock) after repeated `vm-target reset`
cycles — `chronyd` was reachable (`chronyc sources` showed real NTP peers
with small ms-level offsets) but had not yet stepped the clock, and the
existing pre_task check (`systemctl is-active chronyd` → warns only if not
"active") does **not** detect this, because chronyd reports `active` (the
service is running) even while `chronyc tracking` shows `System clock
synchronized: no` / `Leap status: Not synchronised`. This is the same class
of "service running ≠ actually correct" gap AGENTS.md §5.6 warns about,
just for time sync instead of a CLI output parser. Fixed for this test
session with `sudo hwclock -s` (sync system clock from the RTC, which
tracked the host correctly) before each replica deploy attempt. Not fixed
in the playbook itself — out of scope for this HA/DNS-parity change and not
something `docs/tmp/now/freeipa-client-ha-spec.md` asked for — but worth a
follow-up: the existing `ansible.builtin.command: systemctl is-active
chronyd ntpd` precondition check in both `freeipa-server-replica-apply.yml`
and `freeipa-client-apply.yml` should arguably also check `chronyc tracking`
for `"Leap status : Not synchronised"` (or use `chronyc waitsync`) instead
of relying solely on "is the daemon running".
