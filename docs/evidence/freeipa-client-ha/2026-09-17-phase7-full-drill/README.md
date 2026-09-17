# Phase 7 — Full Destructive HA Drill, vm-target evidence (2026-09-17)

Full clean-room drill using `docs/topologies/freeipa-ha-topology.yaml` after all Phases 0-5's
code changes. This is the evidence backing the rewritten
`docs/runbooks/freeipa-server-replica-ha-drill.md`.

## Baseline build (01-04)

1. `01-fresh-primary-deploy.log` — `freeipa-server-apply.yml`, `ok=40 changed=16 failed=0`.
2. `02-fresh-replica-deploy.log` — `freeipa-server-replica-apply.yml` (default `ipa_setup_dns`
   now `true`, Phase 2), `ok=18 changed=6 failed=0` (one more `changed` than pre-Phase-2 runs:
   DNS gets installed inline during promotion instead of a separate Day-2 step).
3. `03-pilotuser-fixture.log` — `playbooks/test/fixtures/freeipa-client-fixtures.yml`,
   `ok=7 changed=4 failed=0`.
4. `04-h1-client-ha-enroll.log` — **H1**: `freeipa-client-apply.yml` with BOTH
   `freeipa-server=ipa-primary` and `freeipa-server-replica=ipa-replica` groups present (the
   real production role-group names, via `pilot vm-target run --group`, not the topology's own
   `ipa_masters`/`ipa_clients` names). `ok=146 changed=21 failed=0`. Resulting
   `sssd.conf`/`krb5.conf` list both servers; `kinit`/`id pilotuser`/`sudo -l -U pilotuser`/
   `pilot vm-target verify` (12/12) all confirmed separately.

## H2 — Primary failure, uncached principal (05)

`05-h2-primary-down-full-checks.log`. Stopped `ipa-primary`, `kdestroy`, `sss_cache -E`, used a
freshly-created `drilluser` (added to the `pilot-all` sudo rule specifically for this drill,
never looked up on this client before). All required checks PASS: `id`, `sudo -l -U drilluser`
(after a full SSSD cache rebuild — see "Gotcha" below), `kinit`, `dig @<replica> ... SRV`,
`sssctl domain-status` (`Active servers: ipa2`, `Discovered: ipa1, ipa2`).

## H3 — Replica failure, symmetric (06)

`06-h3-replica-down-full-checks.log`. Recovered primary, stopped `ipa-replica`, same checks —
`Active servers: ipa1` this time, otherwise symmetric PASS.

## H4 — Total outage negative control (07-08)

`07-h4-total-outage-negative-control.log`: stopped BOTH servers. Fresh `kinit` for `drilluser`
**FAILS** (`rc=1`, "Cannot contact any KDC"); a never-cached identity (`neverseenuser`) **FAILS**
(`rc=1`, "no such user") — the authoritative "really can't log in" proof. An
**already-cached** identity (`drilluser`, looked up in H2/H3) still answers `id`/`sudo -l`
while offline — documented SSSD resilience, not a bug; `sssctl domain-status` shows
`Online status: Offline`.

`08-h4-recovery-kinit-auto-works.log`: restarted `ipa-primary` only. `kinit` immediately
succeeds again with **no Pilot rerun**. Note: `sssctl domain-status`'s own "Online status"
field stayed `Offline` even after a successful `kinit`, and after restarting `ipa-replica` too
— it only flipped back to `Online` after an explicit `systemctl restart sssd` on the client.
**`kinit` succeeding is the authoritative recovery signal; `sssctl domain-status`'s "Online
status" field can lag behind actual functional recovery** — a gotcha worth remembering for
anyone using that field alone to judge whether a client has recovered.

## H5 — Fresh client enrollment while primary is down (09-11)

`09-h5-fresh-enroll-while-primary-down.log`: reset `ipa-ha-client` to pristine, primary still
stopped, ran `freeipa-client-apply.yml` with both server groups present. `ok=144 changed=21
failed=0` — enrollment succeeded via the replica alone.

**The key H5 assertion**: despite `ipa1` being unreachable during enrollment, the resulting
`sssd.conf`/`krb5.conf` list **BOTH** `ipa1` and `ipa2` (`ipa_server = _srv_,
ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal`) — confirmed by direct inspection after the
run. This is the Phase 4 server-failover reconciliation task doing its job: Phase 0 found that
`ipa-client-install` alone silently drops an unreachable `--server` from the resulting config;
this run proves the reconciliation step that runs unconditionally afterward puts it back.

`10-h5-sanity-checks.log`: `kinit`/`id` PASS via the replica. `11-h5-idempotent-after-
recovery.log`: after restarting `ipa-primary`, a rerun is `changed=0`.

## S2 — Single mode, DNS registration explicitly disabled (12)

`12-s2-single-no-dns-registration.log`. Reset the client, enrolled against ONLY
`freeipa-server=ipa-primary` (no replica group) with `-e freeipa_client_register_dns=false`.
`ok=117 changed=20 failed=0`; DNS plan debug output confirms `registration: DISABLED, action:
NOOP`, every DNS-mutation task correctly `skipping`. `kinit`/`id`/`sudo -l -U pilotuser` all
PASS — the client does not hard-require DNS registration to function. (Scope note: this proves
the CLIENT-side "works without DNS" behavior; it does not stand up a primary with integrated
DNS itself disabled, which would be a further, separate test.)

## Final state (13)

`13-final-ha-restore.log`: redeployed the client against both groups again (no reset — same
in-place convergence mechanism as H6), `ok=135 changed=6 failed=0`. Full `pilot vm-target
verify` against `freeipa-client.md` (12/12), `freeipa-server.md` (20/20 on primary), and
`freeipa-server-replica.md` (16/16 on replica) all PASS at the end of the whole drill — nothing
left broken.

## Gotchas found during this drill (folded into the runbook's gotcha table)

1. **SSSD sudo-rule cache can go stale after a rule membership change made moments earlier in
   the same session**, even after `sss_cache -E` — needed a full `systemctl stop sssd; rm -rf
   /var/lib/sss/db/*; systemctl start sssd` to pick up `drilluser`'s brand-new `pilot-all`
   membership (confirmed the membership had already replicated to both LDAP servers; this is
   an SSSD-side cache-refresh gap, not a replication-lag or HA-specific issue). Same pattern
   already seen in Phase 3's evidence with `pilotuser`.
2. **`sssctl domain-status`'s "Online status" field lags real recovery** — `kinit` can succeed
   immediately after a server comes back, while the status field still reports `Offline` until
   an explicit `sssd` restart. Use a real `kinit`/`id` as the recovery proof, not this field
   alone.
3. Recurring (not new this pass, already documented in Phase 2/3 evidence): `vm-target reset`
   clock drift and stale apt-cacher-ng index — same workarounds applied
   (`date -s "@$(date -u +%s)"` / `hwclock -s`, and a manual `apt-get update` after every
   reset).

## Not covered live in this drill (scoped out, not silently skipped)

- **H7 (add a third replica)** and **H8 (replica removal)** — both need a third FreeIPA server
  VM (H7) or a full decommission flow (H8); Phase 1's fact-computation logic for multi-replica
  FQDN disambiguation was already verified with a real ansible run against a synthetic 3-node
  inventory (`docs/evidence/freeipa-client-ha/2026-09-17-phase1-server-pool/`), but a live
  3-VM/decommission drill was not run in this session given time/resource constraints.
- **Phase 6 (contract provider pool)** was not implemented at all this session — see
  `docs/tmp/now/freeipa-client-ha-spec.md`'s Phase 6 section for the reasoning — so this drill
  cannot demonstrate "primary down no longer blocks a site-wide automated deploy that treats
  freeipa-client as depending on freeipa-server"; it only demonstrates the CLIENT's own runtime
  HA and Pilot's own Day-2 CLI operations (Phase 5), both of which are fully proven here.
