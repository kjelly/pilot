# Phase 5 — Control-Plane Admin Endpoint Selection, vm-target evidence (2026-09-17)

Scope actually implemented (narrower than spec.md's original Phase 5 text — see "Deliberately
deferred" below): a live-server selector (`freeipa-admin-endpoint-select.yml`) wired into every
`ipa` CLI call this playbook and its included tasks make, so Pilot's own Day-2 mutations/reads
keep working when the primary is down — even though the FreeIPA CLIENT runtime has been HA
since Phase 3/4.

## Real, iteratively-discovered evidence (each file is one full apply run)

1. `1-dns-backfill-via-selected-endpoint.log` — deleted the client's DNS A record on the
   server, reran `freeipa-client-apply.yml` with both servers UP. The DNS backfill ADD task
   (now carrying `-e xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml`) re-added it;
   confirmed on the server afterward.
2. `2-primary-down-before-dns-read-fix-FAIL.log` — stopped `ipa-primary`, deleted the DNS
   record via the replica, reran. **Failed** at the plan-phase's own authoritative-DNS gate:
   `freeipa-client-host-dns.yml`'s `dig @{{ ipa_server_ip }}` reads were still hard-coded to
   the primary specifically (not the selected endpoint), so a plain DNS backfill ADD was
   blocked even though a live replica could have answered.
3. `3-primary-down-after-dns-read-fix-still-FAIL-host-annotations.log` — fixed the 8
   `dig @{{ ipa_server_ip }}` call sites in `freeipa-client-host-dns.yml` to use a new
   `freeipa_dns_read_authority_ip` (resolved from the selected endpoint). Reran: DNS
   backfill now succeeded, but a DIFFERENT pre-existing task —
   `freeipa-host-annotations.yml`'s bare `ipa host-show` — failed with a connection error
   misreported as `HOST_ABSENT` (its implicit `/etc/ipa/default.conf` routing was still
   pinned to the down primary).
4. `4-primary-down-full-PASS.log` — added the same `-e xmlrpc_uri=` override to all 6
   `ipa host-show`/`ipa host-mod` calls in `freeipa-host-annotations.yml`. Reran: **full
   PASS**, `ok=129 changed=0 failed=0`, with the primary still down. DNS record confirmed
   registered via the replica.
5. `5-idempotent-after-primary-recovery.log` — restarted the primary, reran once more:
   `ok=129 changed=0 failed=0` — idempotent, no drift from the outage.

## What this proves

Pilot's own Day-2 operations (DNS backfill, host-annotation reconciliation) now survive a
primary outage, not just the FreeIPA client runtime itself. `pilot vm-target verify` against
`docs/verification/freeipa-client.md` stayed 12/12 PASS throughout.

## Deliberately deferred (not a silent gap — a scoped decision)

`freeipa-client-host-dns.yml`'s Day-2 IP-replacement REPLACE path (CAS re-verification,
identity proof, TOCTOU re-reads) and spec §12's full "compare >=2 authorities, fail closed on
replication-lag disagreement" split-brain guard were **not** touched. That file's existing
conflict-detection state machine (S1-S10 in its own Day-2 spec) is large and already
extensively tested; re-verifying it under a genuinely multi-authority read model is a
substantial, separate effort that risks the file's existing correctness for a benefit
(detecting DNS split-brain specifically) narrower than what was actually blocking real usage
in this session (primary-down breaking ordinary reads/writes, which the narrower fix above
already solves). The single-authority read now points at the LIVE-SELECTED endpoint instead of
always the primary, which is enough to keep it working during an outage — it does not yet
detect or refuse a genuinely split-brained pair of authorities disagreeing with each other.

Also not done: `internal/contract`/`internal/delivery` provider-pool generalization
(spec.md's Phase 6) — separate commit.
