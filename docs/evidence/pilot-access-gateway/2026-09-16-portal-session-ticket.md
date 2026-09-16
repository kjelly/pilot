# Portal session-scoped Kerberos ticket — vm-target evidence (2026-09-16)

## Tested candidate

- Commit: `aa8975d05c4554ed71967f1b0c837cbcdec676b6`
- Tree: `003a8daa5421e49c766b7d558d0b6a4fd8518279`
- Clean isolated checkout: `/tmp/pilot-portal-evidence.1qGZf1/candidate`
- Targets: `ag-gw01` (Ubuntu gateway), `ag-target01` (Ubuntu FreeIPA client),
  backed by the existing `ag-spike-ipa` FreeIPA vm-target.
- Inventory decision: aligned through the documented single-host
  `target_group=all` override; both generated inventories were read before
  every mutation run.
- Secret input: `ipa_admin_password` came from the existing vault by file
  reference. The Portal user's password was entered only through trec's
  redacted environment input and `kinit` stdin. Neither value is present here.

Execution-affecting SHA-256 values:

| File | SHA-256 |
|---|---|
| `cmd/pilot/cmd/portal_kerberos.go` | `7dfc6ac5029c44810a5d4c783a12eba6cdb61eab1fdd83e82dff4e451ac7545d` |
| `cmd/pilot/cmd/portal_ssh.go` | `0805e5e0c5f7a27eaa717bdf6079201229c100d163a40f34d57e918c13e25341` |
| `cmd/pilot/cmd/portal_tui.go` | `02817ab6193c0ecc094cb9e64d4bbb20fde1a42b4f32ac8b16922f79761f6d50` |
| `playbooks/apply/pilot-access-gateway-apply.yml` | `fe63a4ade3eb464e2e0f5657e5cee09518a98a5f6a2d3042fc3cc59d435ef456` |
| `playbooks/test/fixtures/pilot-access-gateway-session-ticket-fixtures.yml` | `ba130d8451c6307a0bd140e9d8219e8ddab0b82e622eeae55f43ea7e01b4c093` |
| `docs/verification/pilot-access-gateway.md` | `c036e3593c7423ce1c8f633e4afb7df7e265afec836691a20a9db4659f6d3a93` |

## Integrated vm-target result

The formal run used `pilot vm-target test` with `PILOT_DATA_DIR` pointing at
an isolated state directory so the candidate's schema-15 binary did not open
the developer worktree's unrelated schema-16 evidence DB.

| Layer | Actual result |
|---|---|
| L1 syntax | PASS |
| L3 `--check --diff` | PASS |
| L4 apply | `ag-gw01: ok=60 changed=2 unreachable=0 failed=0` |
| L5 verify | PASS, `11/11` (`AG01`–`AG33` selected rows) |
| L6 second apply | `ag-gw01: ok=59 changed=0 unreachable=0 failed=0` |

The final verify artifacts are retained under
`.verification/pilot-access-gateway/`:

- `pilot-access-gateway-20260916-090906.md`, SHA-256
  `4cb52a5d37f209cb986a4ca9ca92ab2a550abc08ce52e29c4feaa0ada5e86a52`
- `pilot-access-gateway-20260916-090906.ndjson`, SHA-256
  `4fce671b6ddeb66d7042a79884686a8b895be1abee421e8a062c495f482797b6`

## Interactive SSH-key → Portal kinit → GSSAPI result

The test-only fixture temporarily installed Alice's disposable public key on
the gateway and set the target's effective sshd policy to:

```text
gssapiauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
```

The outer SSH invocation explicitly disabled GSSAPI, password, and
keyboard-interactive and selected only public-key authentication. Gateway
sshd independently recorded `Accepted publickey for alice`.

The recorded Portal flow then produced these observable results:

1. First Connect prompted exactly once for `Kerberos password for alice`; the
   input event is `<redacted:PORTAL_PASSWORD>`.
2. The resulting target shell returned `whoami → alice` and
   `hostname -f → ag-target01.ipa.pilot.internal`.
3. A second Connect in the same Portal process reached the target shell
   without another password prompt, proving valid-cache reuse.
4. Target sshd recorded two `Accepted gssapi-with-mic for alice` events from
   the gateway while password/kbd-interactive were disabled.
5. Normal Portal logout exited `0`; a post-run search found no
   `pilot-portal-*` directory under the user's runtime directory or `/tmp`.

The cast is retained as
`.verification/pilot-access-gateway/portal-session-ticket-aa8975d.cast`:

- status `success`, exit `0`, 238 events, final `SESSION_END`
- secret scan: `0` findings, `safe_to_share=true`
- SHA-256: `36295b5c2a626b996b9e7af8173b3a761b7ec5ed7dbc41327421d9b690eae205`
- producer warning: the locally installed trec binary reports a dirty build;
  cast integrity and secret scanning still passed.

The cache-loss/reacquisition branch is also covered by
`TestPortalKerberosSessionReacquiresLostOwnedCache`; the live run proves the
same mechanism's acquisition, reuse, and normal-exit cleanup paths.

## Findings fixed during the run

- Three pre-existing checklist probes were not shell-safe: escaped Markdown
  pipes became literal curl/printf arguments, and `0 (empty)` selected the
  wrong matcher. Candidate `f7e1233` replaced them with pipe-free checks and a
  real rc matcher; the final candidate passed 11/11.
- A VM rollback can leave an OpenSSH ControlMaster pointing at the pre-rollback
  guest connection. Closing that local mux before retry prevented Ansible from
  hanging on its first Python module.
- `vm-target test --data-dir ...` does not currently propagate that flag to its
  child `pilot verify`; `PILOT_DATA_DIR` was used so parent and child shared the
  isolated store. This does not affect deployed Portal behavior.

## Cleanup

Both fixture roles were rerun with `fixture_state=absent`. The temporary sshd
drop-ins, Alice test key, and key directory are absent. Effective target
password/kbd-interactive settings returned to the pre-test FreeIPA-client
baseline, while `/etc/pilot/ssh_config` remains the deployed GSSAPI-only
Portal policy.

Fixture idempotency was then checked explicitly for both steady states:

| Fixture target | Second `present` | Second `absent` |
|---|---|---|
| `ag-gw01` gateway role | `ok=5 changed=0 failed=0` | `ok=5 changed=0 failed=0` |
| `ag-target01` target role | `ok=3 changed=0 failed=0` | `ok=3 changed=0 failed=0` |
