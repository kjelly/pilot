# Phase 7 — Deployment Integration: vm-target Evidence (2026-09-14)

Scope: `docs/tmp/now/spec.md` §55 steps 1-18 (installing `pilot-access-gateway`
on a single gateway host), plus the repo's own governance registration
(contract/spec/tag-coverage/deploy-catalog/role-catalog/AGENTS.md). Step 19-21
(sshd ForceCommand) stay off (`pilot_access_gateway_install_forcecommand:
false`) per spec.md §0 G4/§55.1 — that gate is Phase 8's job.

## Topology

- `ag-spike-ipa` — FreeIPA server (already provisioned in earlier phases).
- `ag-gw01` — fresh Ubuntu vm-target, enrolled as a FreeIPA client
  (`freeipa-client-apply.yml`), then targeted by
  `playbooks/apply/pilot-access-gateway-apply.yml` with
  `gateway_id=gpu-01 gateway_scope=gpu`.

## Findings (bugs found + fixed via live re-apply cycles)

### 1. `ipa service-add` requires a forward DNS record

`freeipa-client-apply.yml`'s own DNS auto-registration did not trigger for
this vm-target (no A record for `ag-gw01.ipa.pilot.internal` existed at
enrollment time). The service-principal-creation task
(`ipa service-add pilot-access-gateway/<fqdn>`) failed with FreeIPA's own
"no such host" style error. Rather than duplicating `freeipa-client-apply.yml`'s
DNS logic, the playbook now gates on it explicitly and fails closed with an
actionable message:

```yaml
- name: "Step 2b: verify gateway FQDN resolves (required before ipa service-add)"
  ansible.builtin.command:
    argv: [getent, hosts, "{{ gateway_fqdn }}"]
  register: gateway_fqdn_resolves
  changed_when: false
  failed_when: false

- name: "Gate: gateway FQDN must have a forward DNS record"
  ansible.builtin.assert:
    that:
      - gateway_fqdn_resolves.rc == 0
    fail_msg: >-
      {{ gateway_fqdn }} does not resolve. `ipa service-add` requires a
      forward DNS record for the target host. Register one first
      (`ipa dnsrecord-add <zone> <host> --a-rec <ip>`), or verify
      freeipa-client-apply.yml's own DNS auto-registration actually ran.
```

Fixed short-term with a manual `ipa dnsrecord-add` on `ag-spike-ipa`; the
permanent fix is this gate, not an attempt to re-implement DNS registration
here.

### 2. `/usr/local/libexec` does not exist on Ubuntu

Copying `pilot-access-gateway` to `/usr/local/libexec/pilot-access-gateway`
failed — the directory simply isn't created by any package on a stock
Ubuntu 24.04 image. Fixed by adding an explicit directory-creation task
before the binary copy.

### 3. CRITICAL — local fallback group shadows the real FreeIPA group

An early version of this playbook created `role-pilot-portal-user` as a
**local** group "for safety" if it wasn't already resolvable. Once the real
FreeIPA group of the same name existed (created for testing), `getent group
role-pilot-portal-user` kept resolving to the **empty local group** —
`nsswitch.conf`'s `group:` line checks `files` before `sss`, so the local
group permanently won every lookup and alice's real FreeIPA membership
became invisible to the OS.

Fix: removed the local-fallback-group task entirely. The playbook now
fails closed instead:

```yaml
- name: "Verify portal user group resolves via NSS (must be a real FreeIPA group)"
  ansible.builtin.command:
    argv: [getent, group, "{{ gateway_portal_user_group }}"]
  register: gateway_portal_group_resolve
  changed_when: false
  failed_when: false

- name: "Gate: portal user group must already exist (never create a local fallback)"
  ansible.builtin.assert:
    that:
      - gateway_portal_group_resolve.rc == 0
    fail_msg: >-
      {{ gateway_portal_user_group }} does not resolve via getent. Create it
      in FreeIPA first. Do NOT create a same-named local group as a
      workaround — nsswitch's `files` source is checked before `sss` and a
      local group with the same name permanently shadows the real FreeIPA
      one (found via live testing on ag-gw01, 2026-09-14).
```

This mirrors the same "fail closed, don't paper over" philosophy already
used for the target_hostgroup existence check (step 18).

### 4. CRITICAL — `RuntimeDirectory=pilot` on the wrong systemd unit

`RuntimeDirectory=pilot` was declared on the `.service` unit, but the socket
file `/run/pilot/access-gateway.sock` (created by the `.socket` unit) lived
inside that same directory. Restarting the *service* alone (e.g. after a
binary update, without touching the socket) made systemd delete the entire
RuntimeDirectory — including the socket file — as part of the service's own
stop/start lifecycle, since `RuntimeDirectory=` ownership belongs to
whichever unit declares it.

Fix: moved `RuntimeDirectory=pilot` from `[Service]` to `[Socket]`. Verified
by restarting `pilot-access-gateway.service` repeatedly and confirming the
socket file survives and `pilot-access-gateway.socket` never needs a
restart unless its own unit file changed.

### 5. Self-correction: initial root-cause misdiagnosis

While bugs #3 and #4 were both present and interacting (a service restart
deleting the socket directory looked, at first glance, like "the socket
briefly has no listener and its `SocketGroup=` re-resolution is flaky"),
an early pass concluded that "systemd (PID 1) cannot reliably resolve
SSSD-backed groups for a `.socket` unit's `SocketGroup=`" and wrote this
into several doc comments as the reason for adding an application-layer
group check (`internal/identity.IsMemberOfGroup`,
`gatewayapi.Server.PortalUserGroup`, `authorizedPeer`).

After fixing bugs #3 and #4 and retesting, `SocketGroup=` was found to
reliably resolve the real FreeIPA group correctly across many repeated
socket restarts — the earlier conclusion was wrong. The doc comments in
`internal/identity/identity.go`, `internal/gatewayapi/server.go`,
`internal/gatewayapi/connctx.go`, and
`internal/gatewayapi/portal_group_test.go` were corrected to attribute the
real root cause (local-group shadowing, finding #3) rather than a
non-existent systemd/SSSD timing limitation. The `IsMemberOfGroup` /
`PortalUserGroup` / `authorizedPeer` code was kept — not as a workaround
for a systemd bug that doesn't exist, but as a legitimate defense-in-depth
layer that would catch a *future* reintroduction of the same class of
shadowing bug even if the filesystem `SocketGroup=` permission were
somehow bypassed or misconfigured again.

### 6. Missing restart-on-change logic

The playbook had no logic to restart the running service when the binary
or config file changed on a subsequent apply. Fixed by registering the
binary-copy and config-copy tasks (`gateway_binary_copy`,
`gateway_config_copy`) and adding two conditional restart tasks:

```yaml
- name: "Restart pilot-access-gateway.socket if its unit file changed"
  ansible.builtin.systemd:
    name: pilot-access-gateway.socket
    state: restarted
  when: gateway_socket_unit.changed

- name: "Restart pilot-access-gateway.service if the binary or config changed"
  ansible.builtin.systemd:
    name: pilot-access-gateway.service
    state: restarted
  when: gateway_binary_copy.changed or gateway_config_copy.changed
```

## Live verification results

All against `ag-gw01` (real vm-target), via `curl --unix-socket
/run/pilot/access-gateway.sock`:

| Check | Result |
|---|---|
| Full apply, first run | completes through step 18, `pilot-access-gateway.service`/`.socket` active |
| `alice` (member of `role-pilot-portal-user`) → `GET /v1/identity` | `200` |
| `root` (not a member) → `GET /v1/identity` | `401` — file permission on the socket is bypassable by root, but the application-layer `PortalUserGroup` gate still denies |
| `root` → `GET /v1/health` | `200` — health is never gated by `PortalUserGroup` (it's an ops probe, spec.md §22.5), and this playbook's own step 17 capability probe calls it as root |
| AG29 (stateless restart) | `systemctl restart pilot-access-gateway.service` preserves `/v1/health`'s `ok` status; `/var/lib/pilot` never exists before or after |
| AG30 (idempotency) | second full `ansible-playbook` run against the same host: `changed=0` |

## Governance registration

Adding this playbook triggered the same class of repo-wide checks Phase 6's
`gateway-scope-apply.yml` did, plus a couple new to a playbook with real
verification-spec rows:

- `contracts/pilot-access-gateway.yaml` (new) — `regressionTests` must list
  actual test **files**, not package directories (`internal/contract`'s
  `requireFile` rejects directories); `traceability.rows` reasons cannot
  contain a bare comma inside an unquoted YAML flow-mapping scalar (splits
  into a bogus extra key) — every `reason:` value must be quoted.
  `lifecycle.decommission` was **not** declared: `externalState: true`
  without a `playbooks.decommission` entry or a registered bespoke Go
  provider fails `validateDecommissionPolicy`'s rule 1, and building a
  decommission path for this component is out of this spec's 8 phases —
  matching the precedent set by the sibling `pilot-gateway-scope` contract,
  which also declares no `lifecycle` block.
- `docs/verification/pilot-access-gateway.md` (new) — a Command cell that
  is only a bash comment (`true # explanation`) breaks
  `TestShellSyntax_AllRowCommands`: the harness wraps every Command in
  `( <cmd> ) 2>/dev/null`, and `#` eats everything after it on the line —
  including the harness's own closing paren. Fixed by moving the
  human-readable explanation into the Check column and leaving Command as
  a bare `true`.
- `cmd/pilot/cmd/tag_coverage_test.go` — added a `specTagMap` entry with
  `exemptRows` for AG19 (structural absence, no producing task) and AG30
  (multi-run property, same reasoning as `freeipa-dns.md`'s own C12).
  AG01/02/03/04/06/09/12 each got a matching row-shaped tag
  (`AG01`..`AG12`) added alongside the playbook's existing feature-group
  tags (`AG_config`, `AG_service`, `AG_keytab`, `AG_enrollment`).
- `cmd/pilot/cmd/deploy_catalog.go` — new entry (not `Reconcile: true`; this
  is a one-shot install, not a data-driven reconciler).
- `cmd/pilot/cmd/deploy_test.go`, `internal/contract/contract_test.go`,
  `internal/contract/fixture_schema_test.go` — hardcoded catalog/contract
  counts bumped (35→36 apply playbooks, 36→37 loaded contracts) and the
  sorted contract-ID list got `pilot-access-gateway` inserted alphabetically
  before `pilot-gateway-scope`.
- `internal/inventory/catalog.go` (`topLevelOrder`) and
  `internal/inventory/contracts.go` (`roleContracts`) — registered as a
  normal per-host-assignable role (like `agent-controller`,
  `freeipa-server-replica`), not exempted like `pilot-gateway-scope` —
  the distinguishing factor is that this component designates *a specific
  host* as playing the gateway role, rather than reconciling shared FreeIPA
  state from an existing host. `VaultSections: ["freeipa"]` reuses the
  existing shared `ipa_admin_password` vault section rather than inventing
  an unused new one (an invented, unregistered section ID silently
  produces no vault skeleton at all — `vaultSections[sectionID]` lookup
  just returns `ok=false`).
- `internal/inventory/inventory_test.go`'s
  `TestRoleContracts_GroupVarsExamplesExistForDeclaredStems` required
  `group_vars/pilot-access-gateway.example.yml` to exist once
  `GroupVarsStem` was declared — added, following the existing
  `agent-controller.example.yml` template style.
- `inventory.example.yml` — added a `pilot-access-gateway: {hosts: {}}`
  leaf group entry alongside `dashboard`, for consistency (not itself
  enforced by a test, but matches the file's own documentation intent).
- `cmd/pilot/cmd/portal_ssh_config_sync_test.go` (new) — a byte-identity
  regression test between `portal_ssh.go`'s `pilotSSHConfig` Go constant
  and the apply playbook's Step 12 `content: |` block, so the two
  independently-maintained copies of `/etc/pilot/ssh_config` can never
  silently drift.

## Landing gate status

Per spec.md §60 Phase 7: contract loads successfully via
`internal/contract.Loader`; apply playbook runs through step 18
(ForceCommand still off) idempotently on a real vm-target (AG30,
`changed=0` on the second run). **ForceCommand (steps 19-21) remains
untouched — Phase 8's responsibility.**
