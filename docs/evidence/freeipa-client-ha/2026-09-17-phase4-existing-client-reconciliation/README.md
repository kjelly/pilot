# Phase 4 — Existing Client Day-2 HA Reconciliation, vm-target evidence (2026-09-17)

H6 acceptance test (spec §16): an existing single-mode-enrolled client, with a replica added
to the inventory afterward, converges in place to HA on the next `freeipa-client-apply.yml`
run — no `ipa-client-install --uninstall`, no manual krb5/sssd editing.

Setup: `ipa-ha-client` was already enrolled against only `ipa-primary` (Phase 3's S1 test
state, `ipa_server = _srv_, ipa1.ipa.pilot.internal`).

## 1. `1-h6-single-to-ha-reconcile.log`

Reran `freeipa-client-apply.yml` with BOTH `freeipa-server=ipa-primary` and
`freeipa-server-replica=ipa-replica` groups present (the real production role-group names,
via `--group`). `ipa-client-install` itself skipped (`creates: /etc/ipa/default.conf`
already exists — it never runs again for an existing client), but the NEW
`tasks/freeipa-client-server-failover.yml` reconciliation ran and:

- rewrote `sssd.conf`'s `ipa_server` line to include both servers
- backed up, then atomically rewrote `krb5.conf`'s `[realms]` server-list block to include
  both KDCs (kdc/master_kdc/admin_server/kpasswd_server × 2)
- restarted SSSD, ran `sss_cache -E`
- validated with a real `kinit -k -t /etc/krb5.keytab host/<fqdn>@REALM` — passed, so the
  rollback-on-failure block correctly stayed `skipping`

Result: `ok=130 changed=6 failed=0`. Post-run: `sssctl domain-status` shows
`Discovered IPA servers: ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal`; `kinit`/`id`
sanity checks PASS.

## 2. `2-h6-idempotent-rerun.log`

Same command again, no other changes: `ok=124 changed=0 failed=0` — fully idempotent, the
reconciliation task correctly no-ops once krb5.conf/sssd.conf already match the desired pool.

## Real bug found and fixed during this pass

**Literal `\n` instead of a real newline byte** (the exact AGENTS.md §5.6 class of bug) —
the first version of `freeipa_client_krb5_desired_block` built the per-server
kdc/master_kdc/admin_server/kpasswd_server block via
`map('regex_replace', '^(.*)$', '    kdc = \1:88\n    master_kdc = ...')` inside a
SINGLE-QUOTED YAML string. Single-quoted YAML never interprets backslash escapes, so every
`\n` in that replacement string landed in `/etc/krb5.conf` as a literal two-character
backslash-n, not a line break — confirmed live:
`kpasswd_server = ipa1.ipa.pilot.internal:464\n    kdc = ipa2.ipa.pilot.internal:88` on ONE
line. `kinit -k` still happened to validate afterward in this specific test (case-by-case
luck of which line ended up malformed relative to what krb5.conf's parser tolerates), so
this would NOT have been caught by the validation step alone — it was caught by manually
inspecting the real file content, underscoring why "the mutation's own validation step
passed" is not sufficient proof of correctness; real output inspection still matters. Fixed
by rebuilding the block with a Jinja `{% for %}` template (real newlines in the rendered
YAML block scalar) instead of a regex_replace replacement string, mirroring the pattern
already used successfully for the pool-aware `/etc/hosts` blockinfile block in Phase 3.

## Not yet tested here

The rollback-on-validation-failure path (backup restore + play fail) was exercised only by
construction (simple boolean `when:` conditions, both branches read straightforwardly), not
by a deliberate failure injection — deferred to Phase 7's broader destructive drill rather
than duplicating effort here.
