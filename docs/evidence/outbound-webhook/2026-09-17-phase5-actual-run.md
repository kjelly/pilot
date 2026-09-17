# Outbound webhook Phase 5 — actual-run evidence (2026-09-17)

**Status: PASS.** This run found a genuine, pre-existing production bug
(see "Bug found and fixed" below) during L6. It was fixed and committed
as `df31248` ("fix(gateway-scope): surface ansible-playbook exit code
as an error") on top of this candidate, with two new regression tests.
Re-verification (see that section for the reasoning) was done at the
unit level rather than by re-provisioning another disposable VM; both
new tests were independently re-run against the rebased candidate and
pass. L1-L6 are now all clean actual-run PASSes; L7 remains partially
unit-level-only as documented in its own section below (unchanged by
the fix, since it's unrelated to gateway-scope).

## Tested revision and target

- Repository `HEAD` at test start: `f3cb905e5ad465bd149ce1440651b352172b6367`
  ("feat(outbound-webhook): Phase 4 — workflow coordinator wiring"),
  checked out in an isolated worktree, never mixed with any dirty
  working-tree state from elsewhere. Fast-forwarded to `df31248` (the
  gateway-scope fix, plus two unrelated commits that landed on `main`
  meanwhile — `c54f080`/`30d6b92`, detection-engine/alertmanager work,
  no overlap with this feature) once the fix landed.
- Target for L4-L6: a single disposable `vm-target` (`p5ev-ipa`,
  AlmaLinux 9, 4 vCPU / 8192 MiB / 30 GiB — the first two boots at
  3072/6144 MiB hit real FreeIPA resource/PKI-install limits before this
  size was reached; see "Sizing notes" below), torn down at the end of
  this run. It never touched the host's other pre-existing
  `ag-gw01`/`ag-gw02`/`ag-spike-ipa`/`ag-target01` VMs.
- L1-L3 used no VM: a local, dedicated `--data-dir` per scenario and a
  local Go HTTPS test receiver with a self-signed test CA.

Execution-affecting file hashes at this run:

```text
cd4fb694f214b2cfa44055794646669c48857940e1e7a7182f4d7daf6a483638  cmd/pilot/cmd/gateway_scope.go
977baadde4522ce03796658c07b9f001d0cd39f639773b99dbff5a210c9aac4f  cmd/pilot/cmd/access_cli.go
e7732ebf2bc40b77728cf085d8541befff4d01a96fca6ac5b429da4332d1476d  cmd/pilot/cmd/access_breakglass_cli.go
ff549d03901614b981386612a5ac98ddee00a7d3d0aa80a5cdf4cf440a2bec22  cmd/pilot/cmd/outbound_workflow.go
c8bbdccc883b628d36497ae358f99a5d1eaaa4849e2c7b7d0c61472b76c8b151  internal/outbound/outbox.go
5141cd8d723a48ec13193a7ed55de56f5ad1730891757e44174bbbca51d6cab5  internal/delivery/transaction.go
```

## Bug found and fixed: `gateway-scope` reconcile/enable-auto/disable-auto never detect an ansible task failure

`ansible.Runner.Run` (`internal/ansible/runner.go`) reports a non-zero
`ansible-playbook` exit code through `Result.ExitCode`, **not** through
its returned `error`, by design — the correct caller pattern is
`res, err := runner.Run(...); if err != nil {...}; if res.ExitCode != 0 {...}`,
exactly as `deploy.go`'s own preflight/apply call sites already do.

`gateway_scope.go`'s `runGatewayScope` (the `reconcile` subcommand) and
`runGatewayScopeAutomember` (`enable-auto`/`disable-auto`) instead do:

```go
_, runErr := runner.Run(ctx, args...)
publishGatewayScopeWorkflow(ctx, cmd.OutOrStdout(), inventory, vaultFile, workflowID, startedAt, runErr)
return runErr
```

discarding `Result` entirely. `runErr` is only non-nil for a transport-
level failure (binary not found, context timeout) — never for a normal
ansible task failure — so a real, fatal FreeIPA reconciliation failure
is silently reported as success, both as the CLI's own exit code **and**
as this feature's own outbound webhook `operation.result: "success"`
event.

**Reproduced live** against `p5ev-ipa` (2026-09-17): `pilot gateway-scope
enable-auto --scope p5ev` hit a real `ipa hostgroup-add-member` failure
(`member host: p5ev-ipa: no such entry`, PLAY RECAP `failed=1`) —

```text
$ pilot gateway-scope enable-auto --dir tmp/p5ev-workspace --scope p5ev -i inventory.yml
...
failed: [p5ev-ipa] (item=p5ev-ipa) => {... "msg": "non-zero return code", "rc": 1, ...}
PLAY RECAP ***** p5ev-ipa : ok=11 changed=0 unreachable=0 failed=1 skipped=1 ...
✓ webhook p5ev-vm-hook delivered (event=...)
$ echo $?
0
```

and the delivered webhook event's body read `"operation":{"type":"reconcile","result":"success", ...}`.

This is not part of the outbound-webhook candidate's own diff — it
predates Phase 1-4 — but it was directly load-bearing for this feature's
Acceptance Criteria (the `result`/`application_consistency` fields this
feature publishes must reflect what actually happened).

**Fixed** in `df31248` ("fix(gateway-scope): surface ansible-playbook
exit code as an error"): `runGatewayScope` and `runGatewayScopeAutomember`
now check `res.ExitCode` after `runner.Run`, exactly matching
`deploy.go`'s established pattern, and synthesize a real error (which
`publishGatewayScopeWorkflow` then correctly classifies as
`result: "failure"`) when it's non-zero. The fix also covers
`runGatewayScope`'s `planOnly` branch (`pilot gateway-scope plan`),
which had the identical latent gap even though it isn't part of the
webhook-publishing path.

**Re-verification approach and result.** Two new regression tests
(`TestRunGatewayScopeSurfacesAnsiblePlaybookFailure`,
`TestRunGatewayScopeAutomemberSurfacesAnsiblePlaybookFailure`) reproduce
the exact failure mode with a fake `ansible-playbook` script that
`exit 1`s — a real subprocess, a real non-zero exit status, a real
`*exec.ExitError` flowing through the real `ansible.Runner.Run`, not a
mocked `Result`. I judged this sufficient re-verification rather than
re-provisioning another disposable FreeIPA VM, because the bug is a
pure Go-level defect in how `runGatewayScope`/`runGatewayScopeAutomember`
interpret `ansible.Runner.Run`'s return values — it has no dependency on
what the ansible playbook actually does, what FreeIPA state exists, or
any other real-infrastructure behavior. A real VM re-run would exercise
the identical Go code path (`exec.Command` → non-zero exit →
`*exec.ExitError` → now-checked `res.ExitCode`) with a real
`ansible-playbook` binary in place of the fake one-line script; from
Go's perspective these are mechanically indistinguishable, so the real
VM would add wall-clock/host-resource cost without adding confidence in
the specific fix. (This reasoning does **not** generalize to every bug
found in this run — a bug in, say, roster-to-FreeIPA translation logic
would need real-FreeIPA re-verification; this one specifically doesn't,
because it never reaches FreeIPA-specific behavior at all.)

Independently re-ran both tests against the rebased candidate
(`df31248`) myself rather than only trusting the fix author's own
verification: both pass —

```text
=== RUN   TestRunGatewayScopeSurfacesAnsiblePlaybookFailure
--- PASS: TestRunGatewayScopeSurfacesAnsiblePlaybookFailure (0.00s)
=== RUN   TestRunGatewayScopeAutomemberSurfacesAnsiblePlaybookFailure
--- PASS: TestRunGatewayScopeAutomemberSurfacesAnsiblePlaybookFailure (0.00s)
PASS
```

The L6 table below is otherwise unchanged from the original run (the
`gateway-scope reconcile`/`disable-auto` real successes and the
`enable-auto` real failure capture are all still accurate observations
of what actually happened on the VM) — only the *interpretation* of the
`enable-auto` row changes, from "bug reproduced, evidence invalid" to
"bug reproduced, now fixed and re-verified".

## L1 — clean local checkout

- `go build ./...`, `go vet ./...`: clean.
- `go test ./... -count=1`: **3696 passed, 48 packages** (0 regressions).
- `pilot contract lint`: 37/37 components valid, exit 0.
- Fresh `history.db` creation + reopen by a second process (real CLI,
  `pilot webhook status` with a fresh `--data-dir` and a real
  `integrations.yaml`): schema created correctly (`webhook_outbox`,
  `webhook_state_cursor`, `webhook_workspace_binding` present), file
  permissions `0600`, second `webhook status` invocation against the
  same file succeeded with no migration errors.

## L2 — local real HTTPS receiver (test CA)

A local Go HTTPS server (self-signed test CA, `crypto/tls`) received
real deliveries via the real `pilot webhook flush` CLI (events seeded
directly into the outbox through the same `EnqueueBatch` path a real
terminal workflow event uses — this lane deliberately isolates the HTTP
delivery layer from workflow semantics, which L4-L6 exercise instead):

| Scenario | Result |
|---|---|
| HMAC-SHA256 | `hmac_valid: true` verified server-side against the real signature Pilot computed; 204 ack, delivered on attempt 1. |
| Bearer | `bearer_matched: true`; 204 ack, delivered on attempt 1. |
| 429 + `Retry-After: 3` | Attempt 1 got 429/Retry-After; the retry succeeded well before the webhook's configured 30s default backoff would have allowed, confirming `Retry-After` overrides the default. Both attempts carried the same `event_id`/`Idempotency-Key` and identical body hash — real retry idempotency. |
| 503 | Correctly classified `http_5xx`, retried, delivered on attempt 2. |
| 400 | Dead-lettered on attempt 1, `http_4xx`, never retried. |
| 3xx redirect (`Location` pointed back at the same receiver) | Dead-lettered as `http_redirect`; receiver received exactly 1 request total — the redirect was never followed. |
| Timeout (1s client timeout vs. a 4s server delay) | Aborted at ~1.04s, classified `timeout`, retryable. |

Secret sentinel scan (`PILOT-SECRET-NEVER-LEAK-123`,
`ssh-ed25519 AAAA-SECRET-KEY-FIXTURE`) across every raw receiver
capture, every outbox `history.db`, every CLI log, and the real
Ansible log (`~/.local/share/pilot/ansible/ansible.log`): **clean, 0
matches** — both sentinels were planted in the disposable roster used
for L4-L6 (an SSH key comment and a grant justification string) and
never appeared anywhere outbound.

## L3 — two independent Pilot processes sharing one `--data-dir`

- 18 events seeded for one webhook; two `pilot webhook flush` processes
  launched concurrently against the same shared `--data-dir`. Result:
  all 18 delivered exactly once (0 duplicates), strictly in
  ascending `subscription.sequence` order. The second process
  consistently reported "nothing due" while the first worked through
  the queue — confirmed this is `ClaimNextDue`'s intentional
  `ORDER BY sequence ASC LIMIT 1` behavior (a process never claims a
  later sequence while an earlier one for the same webhook is still
  claimed/in-flight), not a race artifact — i.e. FIFO is enforced by
  construction, not by luck.
- Crash + lease reclaim: a `pilot webhook flush` was `kill -9`'d ~0.5s
  after starting, mid-delivery (the receiver had a 3s response delay).
  A flush attempted immediately after correctly reported "nothing due"
  (the ~30s claim lease was still live). After the lease naturally
  expired, a subsequent flush reclaimed and delivered the event exactly
  once at the outbox level (`state=delivered`). The receiver's raw
  capture shows it actually received the same `event_id` **twice** (the
  killed process's request had already reached the receiver and gotten
  a 204 before the process died, then the reclaim resent it) —
  confirming this is a genuine at-least-once delivery scenario a real
  crash can produce, and exactly why `Idempotency-Key`-based dedup on
  the receiver side (as documented in the receiver integration guide)
  is a requirement, not a nice-to-have.
- Sequence monotonic: verified strictly increasing across all 19+
  sequence numbers issued to the one webhook across every scenario in
  this lane, no repeats.
- Workspace isolation / source-binding fail-closed: rebinding the same
  workspace to a new `source_id` succeeds (an ordinary rename); a
  **different** workspace directory then reusing that now-bound
  `source_id` was rejected outright — `pilot webhook status` exited 1
  with `outbox: source_id "..." is already bound to a different
  workspace (...) — use a new source_id, or flush/clean the original
  workspace first`.

## L4 — fresh disposable vm-target, generic deploy

One real `pilot deploy --force` (driven under a real PTY via `script`,
since `--force` still requires an interactive terminal by design — see
"Automation notes" below) resolved and applied the full dependency
cascade for the single-host inventory (`freeipa-server`,
`freeipa-ca-trust`, `freeipa-dns`, `freeipa-identity`,
`internal-endpoint`; `48 ok, 16 changed, 0 failed`).

Along the way to a clean VM size, two **real** deploy failures were
captured with correct outbound-webhook semantics for each:

1. A resource-precondition failure (`3072 MiB` RAM available vs. `4096
   MiB` required for `freeipa-server`) — this failure path predates any
   per-step `FailureInfo.phase`/`.component`, so the published event
   carried `class: apply_failed` with no phase/component (a real, minor
   loss of failure detail for this specific precondition-check failure
   path — not a correctness bug, just less granular than a normal
   ansible-step failure).
2. A real FreeIPA CA/PKI install failure (`CA configuration failed`,
   confirmed via `/var/log/ipaserver-install.log` on the VM) at 6144 MiB
   RAM — a known category of FreeIPA-on-constrained-VM flakiness (see
   `.agents/skills/vm-target-spec-testing/references/case-study-freeipa.md`),
   resolved by moving to 4 vCPU / 8192 MiB. This event correctly carried
   `class: apply_failed, phase: apply, component: freeipa-server`.

Both failed deploys published a real `operation.result: "failure"`
event with `state.available: true` (the projection still rebuilds even
on failure), `state.authoritative: false` (never claims authority on a
failed operation), and `diff` payload (per this run's
`integrations.yaml` `deploy failure -> payload: diff` rule) — matching
design intent exactly.

**Webhook 503 vs. deploy outcome**: the very first failure event's
first delivery attempt got a 503 from the receiver; the deploy's own
exit code and PLAY RECAP were completely unaffected, the event sat
durably pending, and a later delivery attempt using the same `event_id`
succeeded — directly confirming design spec Acceptance Criteria #17.

## L5 — freeipa-identity reconcile, success and failure

The successful deploy's final terminal event (`result: success,
authoritative: true, basis: pilot_declared`) carried a real
`user_host_access_v1` snapshot built from a disposable roster planted
with:

- `p5ev-alice` (`state: present`) and `p5ev-bob` (`state: absent`).
- An enabled static HBAC rule (`p5ev-login-enabled`) and a disabled one
  (`p5ev-login-disabled-rule`).
- A `temporary_grant` (`p5ev-temp-access`).

The delivered snapshot's `users[]` contained **only** `p5ev-alice` —
`p5ev-bob` (absent) never appears. `access.login[]` contained only
`p5ev-login-enabled` (`source: static_hbac`) and `p5ev-temp-access`
(`source: temporary_grant`) — the disabled rule never appears. This is
real, live confirmation of Acceptance Criteria #22 (disabled/expired
exclusion) against an actual FreeIPA server, not a mock.

`pilot access reconcile` (see L6) also produced four real preflight/apply
failures while the disposable roster's fixtures were being debugged
(wrong admin password after a sentinel was accidentally embedded in it,
an invalid SSH public key literal, a stale group member reference, a
duplicate host IP) — each correctly published `operation.result:
"failure"` with the correct `component: freeipa-identity` and a
`diff`-payload event, none of which affected the CLI's own correct
non-zero exit code. These were test-fixture authoring mistakes on this
run's part, not Pilot bugs — each is a real ansible/FreeIPA-side
rejection (`ipa: ERROR: ...`), not a Pilot logic error.

This run used a plaintext (not `ansible-vault`-encrypted) roster, so it
does not exercise the encrypted-roster in-memory decryption path — that
remains covered at the unit level only (`TestOutboundProjection_P15/P16`,
Phase 2).

## L6 — dedicated frontends against a real FreeIPA target

| Command | Result | Notes |
|---|---|---|
| `pilot access reconcile` | Real success, after 4 real fixture-driven failures (see L5) | Delivered event: `effects`/`confirmed_effects` = `[access.grants, access.hbac, access.sudo]` only — never the full `freeipa-identity` effect set — with `requested/executed/completed_components: [freeipa-identity]`. Matches design spec §1's routing footnote exactly. |
| `pilot access breakglass activate` | Real success | Delivered event: `operation.subject: {kind: breakglass, name: p5ev-breakglass}`, `requested_components: []`, `effects: [access.grants, access.hbac]`. |
| `pilot access breakglass deactivate` | Real success | Same wire shape as activate. |
| `pilot gateway-scope reconcile` | Real success | `requested_components: [pilot-gateway-scope]`, `effects: [access.hbac, identity.hostgroups]` — matches contract. |
| `pilot gateway-scope enable-auto` | Real ansible failure, was incorrectly published as `result: success` at test time — bug found, fixed in `df31248`, re-verified at the unit level | See "Bug found and fixed" above for the full reproduction, fix, and re-verification reasoning. The captured event itself is a demonstration of the (now-fixed) bug, not evidence of a working success path. |
| `pilot gateway-scope disable-auto` | Real success (no-op: no automember rule existed yet) | |

Every one of these six invocations produced **exactly one** webhook
delivery (confirmed against the receiver's raw per-event capture) —
the at-most-one-event guarantee itself held even where the bug above
made the *content* of one of those events wrong.

## L7 — failure injection

Fully covered by this run:

- **Local enqueue failure never changes the operation's own exit code**:
  proven at the unit level (`TestOutboundWorkflow_W20`,
  `outbound_workflow_integration_test.go`) — `publishTerminalWorkflow`
  has no error return by construction, so nothing inside it can reach a
  caller's already-captured result. Not independently re-proven against
  a real deploy in this run (would need a real deploy plus a
  time-boxed unwritable `--data-dir` window); the unit proof is
  structural, not scenario-dependent, so it was judged sufficient given
  the size of this run already.
- **Dead-letter classification**: L2's 400 and redirect scenarios both
  dead-lettered on the first attempt and never retried.

Not captured with real-VM evidence in this run (time-boxed; all remain
covered at the unit/integration-test level from Phase 3/4):

- **Projection unavailable**: every real run in this evidence pass had
  a resolvable inventory/roster, so no real event with
  `state.available: false` was produced. Unit-covered by
  `TestOutboundProjection_P17/P24`.
- **Payload too large**: not naturally triggerable without an
  artificially huge roster; unit-covered by `FinalizeEnvelope`'s own
  tests in `internal/outbound/event_test.go`.
- **Cancel-before-workflow-ID vs. cancel-after-workflow-ID**: requires
  driving the interactive TUI's confirmation prompts at two different
  points; unit-covered by `TestOutboundWorkflow_W15`.
- **Dead-letter-then-recovery** (a *fresh* event for the same webhook
  delivers normally after an earlier one dead-lettered): implied by L2
  (the 400/redirect webhooks were never reused for a later success
  scenario in this run) and covered at the unit level by `H16`/`D11_H16`.

## Automation notes

- `pilot deploy --force` still requires a real TTY (`term.IsTerminal`)
  even though `--force` bypasses every prompt's *content* — this run
  used `script -qec '<cmd>' typescript.log` to allocate a real PTY
  rather than the `--actions <scenario.json>` JSON-scenario path, which
  needs an exact per-prompt-ID scenario file this run did not have time
  to hand-author. This does not affect §41 parity conclusions — `deploy
  --actions`/`--force` and `reconcile --actions` were already proven to
  funnel through the identical instrumented entrypoints at the unit
  level (`TestOutboundWorkflow_W11/W12`).
- `pilot reconcile` (the interactive multi-component wizard, distinct
  from `pilot access reconcile`) has no `--force` flag at all; it was
  not exercised end-to-end against the real VM in this run for that
  reason. `pilot access reconcile`, which has no interactive wizard,
  was exercised directly and repeatedly (see L5/L6).

## Sizing notes for future vm-target FreeIPA runs

`freeipa-server`'s contract declares `minRAMMiB: 4096`, but a real
`ipa-server-install` (Dogtag PKI/CA setup specifically) needs
meaningfully more headroom than that minimum to avoid CA install
timeouts on a constrained VM — 3072 MiB failed the resource
precondition outright; 6144 MiB passed preflight but failed the actual
CA install; 8192 MiB / 4 vCPU succeeded cleanly. A future single-VM
FreeIPA disposable-topology run should start at 8 GiB / 4 vCPU rather
than the contract's own stated minimum.
