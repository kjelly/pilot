# scripts/minimal-poc/ — reusable `trec drive` scripts

Reproduces `docs/runbooks/minimal-poc-architecture.md`'s rebuild entirely
through the real interactive `pilot edit` / `pilot deploy` / `pilot
reconcile` menus — no `--actions` JSON scenario, no hand-edited
`hosts.yml`/`inventory.yml`/`group_vars`. Mechanically transcribed from a
live, MCP-driven session (round 16, 2026-07-25); each label was confirmed
against the real screen at the time, but the scripts have not yet been
proven end-to-end as unattended `trec drive --script` runs against a fresh
VM rebuild (that would need its own VM cycle). Treat the first unattended
run of each as supervised, and diff the resulting files against this
runbook's §0.5 role table / §2 vault key list before trusting a fully
unattended rerun.

## Order

1. **`pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml`**
   (not scripted here — plain CLI, no wizard).
2. **`01-edit-hosts.drive`** — hosts.yml for all 3 hosts, including the
   role checklist, the NFS-role-add roster bootstrap (auto-fires on
   nexus), `host_vars/nexus.yml`, and the roster manager's append-only
   Users/Groups CRUD (top-menu "roster" item).
3. **`pilot inventory generate --dir <workspace>`** (not scripted — no
   wizard, just backfills group_vars/.vault skeletons).
4. **`02-edit-vault-secrets.drive`** — the remaining `.vault/main.yaml`
   keys.
5. **Hand-edit `.vault/ipa-identity.yaml`** for HBAC rules, sudo rules,
   group/user membership, NFS shares, and any other roster field beyond
   bare `users`/`groups` entries — the roster manager only supports
   append-only Users/Groups creation (no membership, no HBAC/sudo, no
   NFS shares); this is the same tool-endorsed nested-YAML exception the
   runbook already documents for the vault. `./pilot roster lint
   <roster-file>` validates the result against the same rules
   `freeipa-identity-apply.yml` enforces at real-apply time.
6. **`03-deploy-sitewide.drive`** — the site-wide `pilot deploy` wizard.
7. **`04-reconcile-identity.drive`** — the `pilot reconcile` wizard for
   the `freeipa-identity` day-2 component.

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

## Related evidence

- `docs/evidence/minimal-poc-architecture/2026-07-25-round-16.md`
- `docs/runbooks/minimal-poc-architecture.md`
