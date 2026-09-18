# Replica DNS self-registration, vm-target evidence (2026-09-18)

Prompted by a real operational question while investigating a production fleet
(`ssh ubuntu@infra-deploy`): why does adding a FreeIPA replica require a manual
`ipa dnsrecord-add` for the new replica's own hostname before running
`freeipa-server-replica-apply.yml`? It shouldn't — the playbook already has
`ipa_admin_password` in scope, so it can register its own DNS record automatically.

## Fix

New first task in `playbooks/apply/freeipa-server-replica-apply.yml`'s `tasks:`:
resolves whether the selected primary provides native DNS
(`hostvars[groups['freeipa-server'][0]].freeipa_setup_dns`), and if so, delegates a
kinit + `ipa dnsrecord-add` for this replica's own FQDN/IP to the primary (which
already has a working Kerberos/admin setup — this host does not, until
`ipa-client-install` runs). Idempotent (`ipa`'s own "no modifications to be
performed" is treated as success, same convention as
`tasks/freeipa-client-host-dns.yml`'s existing DNS backfill task). Skips
gracefully (no self-registration, falls back to the pre-existing
manual-DNS/`/etc/hosts` requirement) when there is no `freeipa-server` inventory
group in this run at all — the single-VM `-e target_group=all` vm-target testing
convention this playbook's own docs already use.

## Two real bugs found live while implementing this

1. **`delegate_to: "{{ groups['freeipa-server'][0] }}"` fails outright** with a
   nonsense error (`"object of type 'dict' has no attribute 'freeipa-server'"`)
   when the bracket-subscript expression is placed directly inside
   `delegate_to:` — `delegate_to` has its own, stricter templating pass than
   ordinary task fields. Fixed by resolving the target host into a plain
   `set_fact` variable first, then referencing that plain variable name in
   `delegate_to:`.
2. **`delegate_to:` on a block is templated BEFORE that block's `when:` is
   evaluated** — even after fix #1, gating the `set_fact` itself with a `when:`
   (so the variable stayed undefined when there was no `freeipa-server` group)
   still crashed the whole play with `'freeipa_replica_primary_inventory_host'
   is undefined`, because `delegate_to`'s templating ran ahead of the `when:`
   that was supposed to skip the block entirely. Fixed by having the `set_fact`
   task run unconditionally and always assign a safe fallback value
   (`inventory_hostname` — a harmless self-reference), moving the actual
   skip/run decision into the block's own `when: ... != inventory_hostname`.

## Evidence

1. `1-single-vm-graceful-degradation.log` — single-VM `-e target_group=all` run
   (no `freeipa-server` inventory group). The 4 new self-registration tasks all
   correctly show `skipping`; the play proceeds and fails later at the
   pre-existing, expected point (`ipa-replica-install`'s conncheck, since no
   manual DNS/`/etc/hosts` step was done either) — confirming the fix does not
   change behavior for this existing testing pattern.
2. `2-real-auto-register-success.log` — real multi-role inventory
   (`pilot vm-target run --group freeipa-server=ipa-primary --group
   freeipa-server-replica=ipa-replica`), matching how a real production
   `inventory.yml` is actually shaped. `ok=23 changed=7 failed=0` — the whole
   replica join succeeds with **zero manual DNS steps**. The self-registration
   tasks show real delegation (`[ipa-replica -> ipa-primary(...)]`) and a real
   `changed` on the `dnsrecord-add`. Confirmed on the primary afterward:
   `ipa dnsrecord-show ipa.pilot.internal ipa2` → `A record: 192.168.122.6`.
   `pilot vm-target verify` against `freeipa-server-replica.md`: **16/16 PASS**.
3. `3-idempotent-rerun.log` — same command again: `changed=0` overall, the DNS
   task itself reports `ok` (not `changed`) via the pre-existing
   "no modifications to be performed" idempotency convention.
