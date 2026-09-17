# Phase 3 — Fresh client multi-server enrollment, vm-target evidence (2026-09-17)

Topology: `docs/topologies/freeipa-ha-topology.yaml` (`ipa-primary`/`ipa-replica` AlmaLinux 9,
`ipa-ha-client` Ubuntu 24.04). Used `pilot vm-target run --group freeipa-server=ipa-primary
--group freeipa-server-replica=ipa-replica --group freeipa-client=ipa-ha-client` (real
production role-group names, not the topology's own `ipa_masters`/`ipa_clients` groups) so
`freeipa-server-pool.yml`'s inventory-driven pool computation exercises the real code path.

## H1 — HA scenario (both freeipa-server and freeipa-server-replica present)

1. `1-h1-ha-enrollment-first-run.log` — full rerun after two real bugs were found+fixed
   mid-session (see below). Result: `ok=116 changed=2 failed=0`. Resulting `sssd.conf`:
   `ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal`; `/etc/hosts` pool
   block lists both `ipa1`/`ipa2`; `krb5.conf` has both KDCs. `kinit`/`id` sanity PASS.
2. `2-h1-idempotent-rerun-after-fix.log` — after the blockinfile/legacy-migration
   idempotency fix (below): `ok=116 changed=0 failed=0`.

## S1 — Single-mode scenario (only freeipa-server present, no replica)

3. `3-s1-single-mode-first-run.log` — fresh client, only `ipa-primary` in the
   `freeipa-server` group. Result: `ok=124 changed=16 failed=0`. Resulting `sssd.conf`/
   `krb5.conf` match Phase 0's Fixture A (single-server golden) byte-for-byte in content;
   `kinit`/`id` sanity PASS.
4. `4-s1-idempotent-rerun.log` — `ok=115 changed=0 failed=0`.
5. `5-s1-full-verify-12-12-pass.md` — full `pilot vm-target verify` against
   `docs/verification/freeipa-client.md`: **12/12 PASS** (after fixing a real pre-existing
   C12 bug found along the way, see below, and creating the `pilotuser`/`pilot-all` sudo
   fixture via `playbooks/test/fixtures/freeipa-client-fixtures.yml`).

## Real bugs found and fixed during this pass

1. **Jinja variable-name collision / infinite recursion** — passing
   `vars: {freeipa_domain: "{{ ipa_domain }}"}` directly on the `include_tasks` call for
   `tasks/freeipa-server-pool.yml` creates a same-named shadow of `freeipa_domain` inside
   the included task's scope. `ipa_domain` is itself defined as
   `{{ freeipa_domain | default(...) }}`, so resolving `ipa_domain` inside that scope
   re-resolves the NEW local `freeipa_domain`, which points back at `ipa_domain`: infinite
   recursion (`"Recursive loop detected in template: maximum recursion depth exceeded"`).
   Fixed by routing through an intermediate `set_fact` (`freeipa_server_pool_domain_input`)
   evaluated once, breaking the cycle.
2. **Legacy-migration lineinfile fighting the pool-aware blockinfile every run** — the
   §6.1 legacy-line-removal task's anchored regex (`^<ip> <fqdn> <shortname>$`) matches not
   only the OLD standalone pin line, but ALSO the blockinfile's own rendered primary-member
   line (same three-field text, just inside the marker block). Every run: migration task
   deletes the block's primary entry, blockinfile re-adds it — `changed` forever, never
   settling to `changed=0`. Fixed by gating the migration task on the pool-aware block NOT
   already existing (checked via a `grep -qF` probe for the `BEGIN PILOT FREEIPA SERVER
   POOL` marker) — migration is a one-time transition, and once the block exists there is
   nothing left to migrate.
3. **Pre-existing C12 matcher bug (unrelated to this phase, found along the way)** —
   `docs/verification/freeipa-client.md` row C12 used
   `ssh -G dummy.ipa.pilot.internal 2>&1 | grep -qi "..."` as a raw ad-hoc `Command` with an
   un-quoted pipe and `Expected: ~yes`. `grep -q` deliberately produces NO stdout, so the
   `~yes` contains-match against stdout was structurally guaranteed to fail regardless of
   the real GSSAPI config (confirmed live: `stdout="", expected substring "yes"`, while the
   actual `ssh -G` output on the same host correctly showed
   `gssapidelegatecredentials yes`). This is the exact "commands containing a literal `|`
   must stay inside a quoted region" trap the vm-target-spec-testing skill warns about, and
   was never exercised by the freeipa-client-ha work before this — fixed by wrapping in
   `sh -c '...'` and switching `Expected` to rc-based `0` (the whole point of `grep -q`).

## Also observed (not a bug in this code, environment-only)

- The same clock-drift (`vm-target reset` → system clock stale by up to ~90 min while
  chronyd reports "active") and stale-apt-index issues from Phase 2 recurred here; worked
  around the same way (`date -s "@$(date -u +%s)"` + a manual `apt-get update` after every
  reset). Not fixed in the playbook — out of scope for this spec, already flagged in the
  Phase 2 evidence README.
- SSSD's sudo-rule cache occasionally needed a full `rm -rf /var/lib/sss/db/*` +
  `systemctl restart sssd` (not just `sss_cache -E`) to pick up a JUST-created fixture rule
  in this heavily-reset test session — attributed to the unusually high churn of repeated
  resets/re-enrollments against the same realm within a few minutes, not a defect in the
  playbook or the fixture.
