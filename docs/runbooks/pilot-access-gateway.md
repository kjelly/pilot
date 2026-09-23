# Runbook — Pilot Access Gateway session-scoped Kerberos Connect

> Status: VERIFIED
> Aligned spec: `docs/verification/pilot-access-gateway.md`
> Automation: `playbooks/apply/pilot-access-gateway-apply.yml`
> Maintainer: SRE

## 0. Goal

Allow a user who entered a ForceCommand Portal by SSH public key to enter their
FreeIPA password once in the Portal, obtain an ephemeral Kerberos TGT, and
connect to an authorized target using GSSAPI only—without target password,
keyboard-interactive, or public-key fallback.

## 0.5 Current fact summary

| Item | Current verified value |
|---|---|
| Fact timestamp | 2026-09-16T09:22Z |
| Target type | Disposable KVM vm-target topology |
| Inventory source | Generated `vm-target show-inventory` for `ag-gw01` and `ag-target01` |
| Actual targets | One Ubuntu gateway and one Ubuntu FreeIPA client target; FreeIPA supplied by the existing server VM |
| External dependencies | FreeIPA realm/DNS/HBAC/sudo baseline; vault key `ipa_admin_password`; Kerberos client tools |
| Alignment | Aligned through the spec's documented `target_group=all` single-host override |

Full facts and raw artifact checksums are in the
[latest evidence record](../evidence/pilot-access-gateway/2026-09-16-portal-session-ticket.md).

## 1. Scope and prerequisites

- The gateway is enrolled as a FreeIPA client and the target is in the
  gateway's `pilot-target-<scope>` hostgroup.
- The user is authorized by effective FreeIPA HBAC and is allowed into the
  Portal group.
- `pilot-access-gateway-apply.yml` receives the two built binaries and the
  existing FreeIPA admin vault by file reference.
- The role installs `kinit`, `klist`, and `kdestroy` explicitly.
- Target sshd may disable password and keyboard-interactive. It must support
  GSSAPI and possess a valid host principal/keytab.

## 2. Current procedure

1. Read the actual target inventory before apply. For vm-target, use
   `pilot vm-target show-inventory`; for a real inventory, use
   `ansible-inventory --graph`.
2. Freeze code, spec, apply playbook, fixture, and contracts into an immutable
   candidate and test from a clean checkout.
3. Run the integrated `vm-target test` chain with the gateway identity/scope,
   binary paths, FreeIPA server/realm, and vault file supplied as variables.
   The exact accepted invocation and output are retained in the linked
   evidence record; the required result is L3 PASS, checklist 11/11, and the
   second apply `changed=0`.
4. A user enters the gateway by SSH key and is forced into `pilot portal`.
   On first Connect, the Portal asks for that same peer user's Kerberos
   password with terminal echo disabled. It executes fixed-argv
   `/usr/bin/kinit -F -l 1h`, stores the ccache in a private runtime temp
   directory, and launches the controlled SSH client with only `KRB5CCNAME`.
5. Later Connect actions in the same Portal process reuse a matching valid
   cache. If it is missing, expired, or belongs to another principal, the
   Portal asks again. Logout destroys only the cache created by that Portal
   process; an inherited delegated cache is never destroyed.

The Portal-to-target SSH config is fail-closed: GSSAPI is enabled,
credential delegation is disabled, `BatchMode` is enabled, and password,
keyboard-interactive, and public-key authentication are disabled.

## 3. Verification

Acceptance is defined by
[`docs/verification/pilot-access-gateway.md`](../verification/pilot-access-gateway.md).
In addition to its 11 deterministic rows, the interactive E2E must prove:

- first hop accepted as public key;
- exactly one masked password prompt on first Connect;
- target sshd accepts `gssapi-with-mic` while password/kbd-interactive are off;
- second Connect reuses the session ticket without prompting;
- Portal logout removes its private cache.

Use the test-only
`playbooks/test/fixtures/pilot-access-gateway-session-ticket-fixtures.yml`
only on disposable vm-targets. Always rerun it with `fixture_state=absent`
after the E2E; it intentionally never changes the production role defaults.

## 4. Rollback

- Reapply the previous reviewed Pilot binaries and the previous
  `pilot-access-gateway-apply.yml` candidate.
- The Portal credential helper creates no durable application state. A normal
  Logout destroys its cache; abandoned one-hour tickets expire naturally.
- If an E2E fixture was interrupted, run its `absent` state separately on the
  gateway and target, then confirm its `00-pilot-portal-session-ticket-fixture.conf`
  drop-in and test key directory are absent before leaving the environment.
- Never disable target `PubkeyAuthentication` during vm-target testing: Pilot's
  management path uses the root VM key and would be locked out.

## 5. Current gotchas

| Symptom | Cause | Current action |
|---|---|---|
| Portal asks for the target password | Stale `/etc/pilot/ssh_config` still permits fallback | Reapply the current role and confirm AG32 |
| `No Kerberos credentials available` after SSH-key first hop | A key login cannot delegate a TGT | Use the Portal's masked session `kinit` prompt |
| `vm-target test` child opens the wrong evidence DB | Global `--data-dir` is not forwarded to child `pilot verify` | Set `PILOT_DATA_DIR` for the whole test process |
| Ansible hangs immediately after VM rollback | Stale local SSH ControlMaster references the pre-rollback connection | Close the stale mux before retrying |
| A table-row probe prints literal `| grep` text | Markdown `\|` reached `sh -c` as an escaped pipe | Keep these checks pipe-free; current AG06/AG12/AG32 do so |
| `terminal_io` recordings show no typed command text | Typed input is recorded only as redacted byte counts on the Gateway SSH relay path; terminal_io does not capture command text today (per-host recording spec §23) | Rely on the recorded terminal output; do not treat input redaction as a guarantee that secrets never reach the recording |

## 6. Latest verified evidence

| Field | Value |
|---|---|
| Verified at | 2026-09-16T09:22Z |
| Tested revision | `aa8975d05c4554ed71967f1b0c837cbcdec676b6` |
| Tested tree | `003a8daa5421e49c766b7d558d0b6a4fd8518279` |
| Target/inventory | `ag-gw01` + `ag-target01`, generated vm-target inventories |
| Dry-run | PASS |
| Apply | `ok=60 changed=2 unreachable=0 failed=0` |
| Verify | PASS 11/11 |
| Idempotency | second apply `changed=0` |
| Interactive E2E | SSH key first hop; one Portal prompt; two GSSAPI target logins; cache cleanup PASS |
| Evidence record | [2026-09-16 Portal session ticket](../evidence/pilot-access-gateway/2026-09-16-portal-session-ticket.md) |
| Raw artifact | local controlled `.verification/pilot-access-gateway/`; cast SHA-256 `36295b5c…eae205` |
