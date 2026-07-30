# scripts/minimal-poc/ — reusable `trec drive` scripts

> Looking for a narrated, screen-by-screen walkthrough to teach from (Chinese,
> keyed to the `casts/` recordings, with an exact field-by-field breakdown of
> every `pilot edit` prompt)? See [`TEACHING-GUIDE.md`](TEACHING-GUIDE.md).

Reproduces `docs/runbooks/minimal-poc-architecture.md`'s rebuild entirely
through the real interactive `pilot edit` / `pilot deploy` / `pilot
reconcile` menus — no `--actions` JSON scenario, no hand-edited
`hosts.yml`/`inventory.yml`/`group_vars`. Originally transcribed from a
live, MCP-driven session (round 16, 2026-07-25); **as of round 17
(2026-07-27), every script below has been run at least once fully
unattended (`trec drive --script`, no live supervision) against a
genuinely fresh VM rebuild** — the standing "not yet proven end-to-end
unattended" caveat this file used to carry is resolved. Round 18
(2026-07-30) added `04b-reconcile-dns.drive` for the new `freeipa-dns`
day-2 component, also confirmed unattended against a real rebuild. Three
real script bugs surfaced round 17 and were fixed doing so (see round-17
evidence); two more real (non-script) bugs surfaced round 18 — see below.
Still
diff the resulting files against this runbook's §0.5 role table / §2
vault key list after any future rerun — a clean unattended exit proves
the script ran to completion, not that every field landed where you
intended (inspect persisted files regardless, per the
`pilot-trec-verification` skill's own discipline).

## Order

1. **`pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml`**
   (not scripted here — plain CLI, no wizard).
2. **`01-edit-hosts.drive`** — hosts.yml for all 3 hosts, including the
   role checklist, the NFS-role-add roster bootstrap (auto-fires on
   nexus), `host_vars/nexus.yml`, and the roster manager's append-only
   Users/Groups CRUD (top-menu "roster" item).
3. **`pilot inventory generate --dir <workspace>`** (not scripted — no
   wizard, just backfills group_vars/.vault skeletons).
4. **`01b-edit-group-vars.drive`** — fills the two `group_vars` keys
   `pilot edit`'s own "🔍 檢查設定完整性" report actually treats as
   hard-required for this topology (`prometheus.yml`/`thanos-query.yml`'s
   `thanos_s3_target_host` — both must point at the host running
   `seaweedfs-s3`, nexus). Re-check the completeness report fresh each
   round rather than assuming this list from memory; every other
   group_vars key either has an in-playbook auto-detect fallback or is
   genuinely optional.
5. **`02-edit-vault-secrets.drive`** — the remaining `.vault/main.yaml`
   keys.
6. **Hand-edit `.vault/ipa-identity.yaml`** for HBAC rules, sudo rules,
   group/user membership, NFS shares, and any other roster field beyond
   bare `users`/`groups` entries — the roster manager (as of round 18)
   does cover per-group/per-user field editing and membership
   checklists (see the runbook's own note), but HBAC/sudo rules and NFS
   shares are still nested-YAML-only; this is the same tool-endorsed
   nested-YAML exception the runbook already documents for the vault.
   `./pilot roster lint <roster-file>` validates the result against the
   same rules `freeipa-identity-apply.yml` enforces at real-apply time.
   As of round 17, also add `freeipa.server`/`freeipa.realm` explicitly
   (the NFS-bootstrap-generated roster omits them, which crashes
   `pilot reconcile`'s `identity_hbac_test_host` Jinja evaluation — see
   the runbook's §6 gotcha table) until that's fixed upstream. Round 18
   found and fixed a second, independent bug in the same area: the
   playbook's own top-level-key gate rejected `domain`/`realm` even
   though they're legal per the Go-side schema — see §6.
7. **`03-deploy-sitewide.drive`** — the site-wide `pilot deploy` wizard.
8. **`04-reconcile-identity.drive`** — the `pilot reconcile` wizard for
   the `freeipa-identity` day-2 component.
9. **`05-kinit-alice.drive`** — personalizes a brand-new roster user's
   password via a scripted `kinit` (forced-change flow is always exactly
   3 lines). Run this before any §4.1 password-based SSH check — FreeIPA
   arms the forced-change flag on first-ever password assignment
   regardless of the roster's `force_change` value.
10. **Author the freeipa-dns manifest** via `pilot edit`'s "freeipa-dns
    manifest" top-menu item (zone + A/AAAA/CNAME records, a
    `target.inventory_host` picker sourced from `hosts.yml`) — set
    `freeipa_dns_manifest_file` as an extra host var on `freeipa-server`
    first (same "其他變數" screen used for `freeipa_roster_file`). Not a
    checked-in `.drive` script (round 18 authored it live via MCP, one
    zone + 3 A records — grafana/wazuh/s3 resolved through nexus — takes
    under two minutes interactively; script it yourself the same way if
    you need it unattended).
11. **`04b-reconcile-dns.drive`** — the `pilot reconcile` wizard for the
    new `freeipa-dns` day-2 component (added round 18, 2026-07-30).
    Confirmed unattended (`trec drive --script`, no live supervision)
    against the real 3-VM rebuild: first apply `changed=2 failed=0`
    (3 A records created), idempotent rerun `changed=0 failed=0`. Run
    after step 10 has produced a manifest.

## Fixed implementation defects (see round-16 evidence)

Two bugs found while authoring these scripts were fixed upstream on 2026-07-26 and no longer need
a workaround — mentioned here only so an older checkout's symptoms are recognizable:

- **`ipa_dm_password`**: `pilot deploy`'s hard completeness gate used to require this key even
  though `internal/inventory/vault.go` marks it `Optional: true` and
  `docs/verification/freeipa-server.md` documents it as not required (falls back to
  `ipa_admin_password`). Fixed by making `vaultSection.keyNames()` skip `Optional: true` keys. If
  you see `inventory 完整性檢查沒過 ... ipa_dm_password 未設定` on an older checkout, upgrade rather
  than adding the key by hand.
- **`ssh_keys`**: `freeipa-identity-apply.yml`'s "Normalize canonical users for the compatibility
  reconciler" task used to crash under ansible-core 2.19.x (`Type 'method' is unsupported for
  variable storage`, `_AnsibleLazyTemplateDict.values`) for any roster user with no `ssh_keys`
  field at all — exactly what the roster manager's append-only "➕ 新增 User" produces. Fixed by
  switching `(item.ssh_keys | default({}))['values']` to `.get('values', none)` (a real dict-method
  call, immune to Jinja's item-then-attribute fallback that made the bracket form collide with the
  dict's own `.values` method). If you see this crash on an older checkout, upgrade rather than
  hand-adding an `ssh_keys` block to every user.

## Known workarounds still baked into these scripts (see round-16 evidence)

- **VM sizing**: `docs/topologies/minimal-poc-topology.yaml`'s
  `freeipa-server` node needed `memory: 4608` (not the previous `4096`) —
  a newly-enabled real-fact-based resource gate
  (`cmd/pilot/cmd/deploy_facts.go`, added 2026-07-24) correctly caught
  that AlmaLinux 9's actual usable RAM under this topology's virtualization
  overhead was ~3911 MiB, ~185 MiB short of the freeipa-server component's
  declared minimum. This was silently unenforced before that commit; it
  is not a regression, just a newly-real check.
- **Ubuntu service names**: the sudo rule you grant on `nexus` must name
  the real Ubuntu unit (`ssh`, not `sshd` — AlmaLinux/RHEL and
  Debian/Ubuntu use different unit names for the same daemon). This is
  an authoring detail, not a tool bug — pick whatever command actually
  exists on the target host.

## Suspected implementation defect found this round (see round-17 evidence)

Reported, not fixed — no Ansible/Go change was authorized this round:

- **`freeipa.server`**: `freeipa-identity-apply.yml`'s "Normalize canonical FreeIPA settings" task
  reads `freeipa_roster.freeipa.server` with no `| default(...)` fallback, unlike every sibling
  field in the same `set_fact` block. `internal/inventory/nfs_bootstrap.go`'s
  `WriteMinimalNFSServerRoster` (the function `01-edit-hosts.drive`'s NFS-role-add bootstrap calls)
  never writes `freeipa.server`, and no validator requires it — so a roster built entirely through
  sanctioned tooling crashes `pilot reconcile`'s preview with
  `object of type 'dict' has no attribute 'server'`. Workaround: add
  `freeipa.server`/`freeipa.realm` to the roster by hand (step 6 above) until this is fixed
  upstream.

## Real bugs found and fixed this round (see round-18 evidence)

Two, both found rebuilding the workspace live and fixed the same round:

- **`freeipa-identity-apply.yml`'s top-level-key gate rejected `domain`/`realm`**: the
  "Gate: canonical top-level and FreeIPA keys are known" assert's allowed `freeipa.*` key list was
  hardcoded to `['server', 'admin', 'defaults', 'safety']`, omitting `domain`/`realm` even though
  `internal/inventory/roster_validate.go`'s `knownFreeIPAKeys` explicitly allows both (its own
  comment says the apply playbook is supposed to just ignore them, not reject them).
  `WriteMinimalNFSServerRoster`'s bootstrap-generated roster always writes `freeipa.domain` — so
  any workspace built via the sanctioned NFS-role-add path failed this gate on the very first
  `freeipa-identity` reconcile, before ever reaching the round-17 `freeipa.server` defect above.
  `pilot roster lint` never caught it (the Go validator already allowed the shape). Fixed by adding
  `domain`/`realm` to the assert's allowed list.
- **`freeipa-dns-apply.yml`'s `ipa_server_fqdn_expected` default didn't match
  `freeipa-server-apply.yml`'s own default**: it fell back to a bare `inventory_hostname` (e.g.
  `freeipa-server`, the inventory's short host alias) instead of `'ipa1.' ~ ipa_domain` (the FQDN
  the server actually installed as) when `freeipa_server_fqdn` was left unset — exactly the
  "usually don't need to fill this in" convention `group_vars/freeipa.example.yml` documents. Every
  `freeipa-dns` reconcile against a workspace following that convention failed the
  manifest-vs-inventory gate. Fixed to match `freeipa-server-apply.yml`'s default exactly.

Both are one-line fixes; see `docs/verification/freeipa-identity.md` (v1.4) and
`docs/verification/freeipa-dns.md` (v1.1) changelogs for the full write-up.

## Related evidence

- `docs/evidence/minimal-poc-architecture/2026-07-30-round-18.md`
- `docs/evidence/freeipa-dns/2026-07-30.md`
- `docs/evidence/minimal-poc-architecture/2026-07-27-round-17.md`
- `docs/evidence/minimal-poc-architecture/2026-07-25-round-16.md`
- `docs/runbooks/minimal-poc-architecture.md`
