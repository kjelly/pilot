Pilot Roster v3.1 — Security Operations Specification

Status: Implementation specification
Target repository: kjelly/pilot
Baseline: main at 497e8e6ca2d074668f7d1696d76b27a25ebd6785
Date: 2026-08-27
Audience: Coding agent / maintainer implementing the change

1. Executive decision

Pilot v3.1 SHALL remain a one-shot CLI architecture.

This version MUST NOT introduce any security feature whose correctness requires Pilot to remain running, wake up periodically, poll, schedule future work, or execute a recurring reconciliation loop.

Explicitly:

DO NOT implement:
    pilot access controller run
    in-process scheduler
    recurring reconciliation loop
    systemd timer owned by this specification
    cron-based security enforcement owned by this specification
    Kubernetes CronJob-based security enforcement owned by this specification
    deadline worker
    timer queue
    generic Clock/Scheduler framework

The inclusion rule for v3.1 is:

A security control may be included only when a one-shot configuration/apply is sufficient for the enforcement to remain valid afterward, or when the feature itself is explicitly on-demand/read-only.

Examples:

Allowed in v3.1:
    FreeIPA account principal expiration
    sudoNotBefore / sudoNotAfter
    Kerberos authentication indicators
    one-shot drift inspection
    explicit/manual managed drift repair
    audit of explicit Pilot operations
    access-health inspection
    persistent SSSD/offline-login configuration if implemented as one-shot host config

Deferred from v3.1:
    automatic HBAC grant activation at not_before
    automatic HBAC grant expiration at not_after
    automatic break-glass expiration when implemented as HBAC enable/disable
    automatic recertification suspension
    periodic drift detection/repair
    periodic health execution
    automatic existing-session termination at grant expiry

Approval remains OUT OF SCOPE.

2. Baseline facts that implementation MUST preserve

At the baseline commit, Pilot v3.0 Core Access Governance is already implemented.

v3.1 SHALL build on the existing implementation rather than replace it.

2.1 Existing access CLI

The repository already has one-shot access commands equivalent to:

pilot access status <roster-file>
pilot access reconcile <roster-file> --once

pilot access reconcile --once:

reads/validates the roster;

evaluates SoD;

evaluates grant security policies;

evaluates account lifecycle policy;

compiles grants/auth policies;

invokes the existing FreeIPA identity playbook;

exits.

v3.1 SHALL keep this execution model.

2.2 Existing injected-time seam

Lifecycle-related Go code already accepts an explicit time value equivalent to:

now time.Time

through existing functions/options.

This is sufficient for deterministic testing.

v3.1 MUST NOT add a generic:

type Clock interface { ... }

solely because some policy contains timestamps.

A Clock abstraction belongs only in a future specification that truly introduces a long-running process.

2.3 Existing policy gate

The current access reconcile path already evaluates:

Separation of Duties
grant policies
account lifecycle dominance

before backend mutation.

All v3.1 write operations MUST continue to use the same fail-before-write philosophy.

2.4 Existing authorization model

HBAC simplification remains authoritative:

static login:
    users / team-* / role-* / legacy access-*
        -> HBAC
        -> hosts / hostgroups

temporary login:
    grants[]
        -> compiled Pilot-managed HBAC

temporary sudo:
    grants[]
        -> compiled Pilot-managed sudo rule

access-* is deprecated compatibility only.

No v3.1 feature may recreate it as a new authorization abstraction.

2.5 Existing account-lifecycle gap

account_policies today is validation and policy-gate only (internal/inventory/account_policy.go: checkAccountPolicies, EvaluateAccountLifecycle). It blocks a grant from reaching a user whose account is outside its validity window.

No code path compiles account_policies.validity into a live FreeIPA/Kerberos principal-expiration attribute. There is no krbPrincipalExpiration reference anywhere in this repository's Go or Ansible sources.

Phase 1 (§7, §23) is therefore net-new implementation — a new compile step plus a new apply task — not an extension of existing plumbing. It SHOULD follow the pattern already proven by CompileSudoGrant (internal/inventory/grant_compile.go) and its corresponding sudonotbefore/sudonotafter apply task (playbooks/apply/freeipa-identity-apply.yml), which are the closest existing analog and are already correct end to end.

3. Goals

v3.1 MUST provide:

native account expiration reconciliation;

native timed sudo reconciliation and verification;

authentication-indicator reconciliation and verification;

explicit classification of native vs Pilot-reconcile-dependent timing;

one-shot access drift inspection;

explicit/manual managed drift repair;

one-shot access health inspection;

audit events for explicit Pilot security operations;

optional access recertification metadata/reporting without automatic suspension;

optional persistent SSSD/offline-login hardening if implemented without a Pilot loop.

v3.1 MUST NOT promise automatic lifecycle transitions that require a later Pilot invocation.

4. Non-goals

The following are explicitly deferred.

4.1 No Pilot loop

Do not implement:

pilot access controller run
pilot access watch
pilot access daemon
background goroutine scheduler
persistent worker loop

4.2 No recurring scheduler deployment

This version does not own:

systemd timer
cron entry
Kubernetes CronJob
CI recurring workflow

Operators MAY invoke one-shot Pilot commands through external automation, but that is outside v3.1's correctness contract.

4.3 No automatic time-bound HBAC transitions

Do not claim:

temporary login grant automatically activates at not_before
temporary login grant automatically expires at not_after

unless FreeIPA itself is enforcing the exact property.

Generic HBAC rule enable/disable transitions require another Pilot run and therefore are not part of v3.1 automatic enforcement.

4.4 No automatic break-glass expiration through HBAC

If break-glass access is implemented by enabling/disabling a managed HBAC rule, automatic expiry requires a later Pilot execution.

That automation is deferred.

4.5 No automatic recertification suspension

review.on_overdue: suspend is deferred because enforcement would require a future Pilot run.

v3.1 may report overdue review state but MUST NOT promise automatic suspension.

4.6 No automatic existing-session termination

Session termination tied to a future grant-expiration event is deferred.

4.7 No periodic drift repair

pilot access drift may inspect live state on demand.

--repair-managed may explicitly repair live state on demand.

Periodic execution is not v3.1 behavior.

5. Enforcement hierarchy

v3.1 SHALL follow:

Native persistent enforcement first.
Pilot recurring execution never required.

Priority:

1. FreeIPA / Kerberos native controls
2. FreeIPA sudo native controls
3. persistent host-side configuration applied once
4. explicit one-shot Pilot inspection/repair
5. anything requiring future recurring Pilot execution -> DEFERRED

The implementation MUST document which category each feature belongs to.

6. Native-enforcement capability matrix

The following matrix is normative.

Security requirement

Backend

Native future-time enforcement

v3.1

Whole user/account expires

FreeIPA/Kerberos principal expiration

yes

implement

Sudo grant not-before/not-after

FreeIPA sudo LDAP attributes

yes

implement/verify

Strong-auth requirement on supported principals/services

FreeIPA/Kerberos auth indicator

persistent after apply

implement/verify

Static HBAC login policy

FreeIPA HBAC

persistent after apply

already supported; inspect drift

Temporary HBAC grant not_before

HBAC enable/disable

no generic native time window

no automatic enforcement

Temporary HBAC grant not_after

HBAC enable/disable

no generic native time window

no automatic enforcement

Break-glass HBAC expiry

HBAC enable/disable

no generic native expiry

no automatic enforcement

Automatic review suspension

Pilot policy

no

deferred

Existing SSH session kill at expiry

host/session layer

no

deferred

Periodic drift repair

Pilot

no

deferred

SSSD offline-login hardening

persistent host config

persists after apply

optional

7. Account lifecycle — native principal expiration

7.1 Decision

When the security requirement is:

This entire FreeIPA user identity must stop being valid after a fixed timestamp.

Pilot SHALL use the FreeIPA/Kerberos principal expiration capability rather than waiting for a future Pilot process to disable the account.

Conceptually:

roster account lifecycle
        |
        v
FreeIPA principal-expiration attribute
        |
        v
KDC enforces future expiry without Pilot

7.2 Canonical roster intent

Use the existing v3 account-lifecycle model, for example:

account_policies:
  - name: vendor01-contract
    state: present
    user: vendor01
    type: contractor

    validity:
      not_after: 2026-12-31T23:59:59+08:00

    sponsor: alice
    ticket: HR-2231

If not_before is present, see §7.7.

7.3 Compilation

Pilot SHALL normalize RFC3339 timestamps to the exact timestamp format accepted by the supported FreeIPA backend.

The implementation MUST verify the exact supported CLI/attribute mapping on the target FreeIPA version.

The implementation SHOULD centralize timestamp conversion instead of duplicating it in Ansible/Jinja and Go independently.

7.4 Idempotency

Reconcile behavior:

desired expiration == live expiration
    -> changed=0

desired expiration != live expiration
    -> update

policy state=absent / expiration intentionally removed
    -> clear only through an explicit, validated semantic path

Do not silently remove an existing expiration because a field was omitted ambiguously.

7.5 Account expiration dominates grants

The v3.0 invariant remains:

expired account
    -> no login/sudo grant may be considered sufficient to restore identity validity

Policy evaluation and explain output MUST preserve this dominance.

7.6 Existing credentials/session caveat

Principal expiration does not mean:

all already-issued Kerberos tickets disappear at that exact instant
all existing SSH sessions are forcibly terminated

v3.1 SHALL document this.

Existing-session termination remains deferred.

7.7 not_before

A whole-account not_before requirement is not assumed to be provided by the same FreeIPA principal-expiration field.

If the supported backend lacks a native account-not-before mechanism:

account validity.not_before automatic activation
    -> DEFERRED

Do not emulate it with a Pilot timer in v3.1.

Possible operational alternatives may be documented, but are not part of the enforcement contract:

create/enable account at the intended start time
or
external workflow performs an explicit one-shot apply

8. Timed sudo — native validity

8.1 Decision

Temporary sudo SHALL use backend-native validity rather than Pilot timing.

A sudo grant such as:

grants:
  - name: alice-prod-nginx
    kind: sudo

    subjects:
      users: [alice]
      groups: []

    targets:
      hosts: []
      hostgroups: [prod-web]

    privilege:
      command_groups: [web-service-manage]

    validity:
      not_before: 2026-08-27T15:00:00+08:00
      not_after: 2026-08-27T19:00:00+08:00

SHALL compile to the supported FreeIPA sudo validity attributes equivalent to:

sudoNotBefore
sudoNotAfter

After successful apply, the security boundary MUST NOT depend on Pilot running again at either timestamp.

8.2 Verification

v3.1 MUST include live verification that:

before sudoNotBefore, sudo policy is not effective;

during the window, it is effective;

after sudoNotAfter, it is no longer effective;

SSSD/cache propagation behavior is measured/documented.

Do not claim native timed sudo is correct solely from LDAP attribute presence.

8.3 Reconciliation

One-shot reconcile continues to:

create/update managed sudo rule;

set subjects/targets;

set command scope;

set run-as;

set options;

set native validity.

No future Pilot loop is required for expiration.

9. Authentication indicators — persistent native enforcement

9.1 Decision

Where FreeIPA supports Kerberos authentication indicators for the target principal/service, Pilot may reconcile them as persistent backend configuration.

Once applied, enforcement belongs to FreeIPA/Kerberos.

No periodic Pilot run is required merely to keep the requirement active.

9.2 Capability probing

Do not assume every principal can safely accept every indicator.

v3.1 SHALL preserve capability/safety checks discovered during v3.0 implementation.

If a target object rejects an indicator:

fail before mutation where predictable
or
fail the apply explicitly

Do not silently downgrade authentication strength.

9.3 Drift

Authentication-indicator drift may be inspected/repaired on demand under §12–13.

Periodic checking is deferred.

10. Temporary login grants — explicit limitation

10.1 Existing v3.0 behavior

A temporary login grant compiles to a Pilot-managed HBAC rule.

Lifecycle evaluation can determine:

pending
active
expired

at the time Pilot is invoked.

10.2 v3.1 decision

Because a generic FreeIPA HBAC rule does not provide the required native time-window semantics in the current design, v3.1 SHALL NOT promise automatic activation/expiration of temporary login grants.

The existing command may still be used explicitly:

pilot access reconcile <roster-file> --once

When invoked, it evaluates the current time and reconciles the correct HBAC state.

But:

no Pilot invocation
    ->
no guarantee that a future HBAC lifecycle boundary will be applied

10.3 Status classification

pilot access status and pilot access health SHOULD classify such grants as:

timing_enforcement: reconcile_required

Example JSON:

{
  "name": "vendor-db-maintenance",
  "kind": "temporary_grant",
  "lifecycle": "active",
  "timing_enforcement": "reconcile_required",
  "next_transition_at": "2026-08-27T18:00:00+08:00"
}

This is observability, not automation.

10.4 No false assurance

The UI/CLI/docs MUST NOT say:

expires automatically at 18:00

for a generic HBAC grant.

It SHALL say semantics equivalent to:

desired expiry: 18:00
backend transition requires another explicit Pilot reconcile

unless a future native backend capability replaces this model.

11. Break-glass — no automatic Pilot-timed expiry

11.1 Manual lifecycle only

Generic break-glass activation/deactivation may remain explicit operations:

pilot access breakglass activate ...
pilot access breakglass deactivate ...

If current implementation supports a requested duration, v3.1 SHALL distinguish:

requested duration metadata
vs
backend-native guaranteed expiration

11.2 No loop-backed promise

If expiration requires Pilot to later disable a managed HBAC rule:

automatic expiration = DEFERRED

Do not add a timer/loop to make it happen.

11.3 Native alternative

A separate design may use a dedicated emergency identity with native principal expiration when that matches the operational requirement.

That is not a generic replacement for all break-glass scopes and MUST NOT be silently substituted.

12. One-shot drift inspection

Add/keep a read-only command equivalent to:

pilot access drift <roster-file>
pilot access drift <roster-file> --format json

This command runs once and exits.

No recurring loop is introduced.

12.1 Static HBAC drift

Inspect:

enabled;

direct subject users;

subject groups;

direct target hosts;

hostgroups;

services;

hostcat.

HBAC simplification means all relationship dimensions remain independent.

12.2 Compiled login-grant HBAC drift

Inspect Pilot-managed objects for:

presence;

enabled;

users/groups;

hosts/hostgroups;

services;

orphaned Pilot-managed rules.

12.3 Sudo drift

Inspect:

users/groups;

hosts/hostgroups;

command scope;

run-as;

options;

native validity attributes.

12.4 Authentication-policy drift

Inspect the exact FreeIPA attribute/interface used by v3.0.

12.5 Account-expiration drift

Inspect desired account expiration vs live FreeIPA principal expiration.

This is a key v3.1 addition.

Example drift:

desired: 2026-12-31T15:59:59Z
live:    unset

or:

desired: 2026-12-31T15:59:59Z
live:    2027-01-31T15:59:59Z

13. Explicit managed drift repair

v3.1 MAY implement an explicit operation:

pilot access drift <roster-file> --repair-managed

or an equivalent dedicated command.

This is one-shot and operator-triggered.

13.1 Ownership boundary

Pilot may repair only policy it can prove it owns.

Ownership sources:

static policy:
    exact roster declaration

compiled policy:
    deterministic Pilot-managed name/marker

account expiration:
    exact account_policy -> user mapping

auth indicator:
    exact auth_policy -> target mapping

Do not mutate unmanaged FreeIPA objects merely because they differ from a convention.

13.2 Repair flow

inspect
-> preview
-> validate
-> policy gate
-> explicit repair
-> verify
-> exit

No background retry/loop.

13.3 Failure

A failed repair is reported and exits non-zero.

v3.1 does not schedule another attempt.

14. Access recertification — report only

v3.1 MAY support review metadata:

grants:
  - name: vendor-project-x

    review:
      interval: 30d
      last_reviewed_at: 2026-08-01T10:00:00+08:00
      reviewed_by: alice

14.1 Supported behavior

One-shot:

pilot access review list <roster-file>
pilot access review mark <roster-file> <grant> \
  --reviewer alice \
  --reason "still required"

review list may classify:

current
due
overdue

14.2 Unsupported behavior in v3.1

Do not implement:

on_overdue: suspend

as an automatic enforcement promise.

If the field already exists from earlier experiments/specs, either:

reject it in v3.1 schema/validation; or

mark it unsupported and non-enforcing.

Preferred approach: fail closed for unsupported automatic enforcement semantics.

14.3 Approval distinction

reviewed_by remains metadata.

It is not an Approval receipt.

15. Audit events

v3.1 SHALL record explicit Pilot security operations.

No recurring worker is required.

Suggested model:

type AccessAuditEvent struct {
    ID         string
    At         time.Time
    Actor      string
    Action     string
    SourceKind string
    Resource   string
    BeforeHash string
    AfterHash  string
    Reason     string
    Ticket     string
    Outcome    string
    ErrorCode  string
}

15.1 Required event types

At minimum:

account_expiration_applied
account_expiration_cleared
sudo_validity_applied
auth_indicator_applied
access_drift_detected
access_drift_repaired
access_review_marked
explicit_access_reconcile
breakglass_activated
breakglass_deactivated

Do not emit fictitious future events such as:

grant_expired

unless Pilot actually observed/processed that event during an explicit invocation.

15.2 Secret safety

Audit MUST NOT contain:

passwords;

vault plaintext;

vault password;

OTP seed;

SSH private key;

complete decrypted roster;

secret-bearing Ansible extra-vars.

15.3 Storage

Prefer existing Pilot receipt/evidence/state abstractions.

If none is suitable:

<state-dir>/access/audit.jsonl

with:

mode 0600;

stable IDs;

append-safe writes;

bounded/rotatable operational policy.

16. Access health — one-shot inspection

Add/keep:

pilot access health <roster-file>
pilot access health <roster-file> --format json

The command runs once and exits.

It does not monitor continuously.

16.1 Required fields

At minimum:

evaluated_at
FreeIPA reachable
account-expiration drift count
sudo-validity drift count
static HBAC drift count
compiled-grant HBAC drift count
auth-policy drift count
review overdue count
active breakglass count where inspectable
temporary HBAC grants with future reconcile-required transitions

16.2 Native-enforcement classification

Health output SHOULD classify active security objects.

Example:

{
  "native_enforced": [
    {
      "kind": "account_expiration",
      "name": "vendor01-contract"
    },
    {
      "kind": "sudo_grant",
      "name": "alice-prod-nginx"
    }
  ],
  "reconcile_required": [
    {
      "kind": "temporary_login_grant",
      "name": "vendor-db-maintenance",
      "next_transition_at": "2026-08-27T18:00:00+08:00"
    }
  ]
}

This makes unsupported automatic timing explicit.

16.3 Overall status

Suggested:

healthy
degraded
critical
unknown

Examples:

healthy:
    no known native-enforcement drift
    no blocking security violation

degraded:
    reconcile-required temporary grant has future transitions
    but no current known mismatch

critical:
    live native account/sudo/auth state is wider than desired
    or policy gate reports a blocking issue

unknown:
    required FreeIPA live state cannot be queried

Do not define health in terms of "last scheduler run" because v3.1 has no scheduler.

17. SSSD / offline-login hardening

This feature MAY remain in v3.1 only if implemented as persistent one-shot configuration.

Example:

security:
  offline_access:
    - name: production-no-offline-login
      hostgroups: [production-linux]
      allow_cached_authentication: false

17.1 Inclusion rule

It is allowed because:

one explicit apply
    ->
persistent SSSD configuration
    ->
no Pilot loop required

17.2 Requirements

Implementation MUST:

inspect the existing FreeIPA-client configuration path;

be OS-family aware;

validate SSSD configuration;

use safe restart/reload;

document behavior during IdM outage;

not assume distro defaults are identical.

17.3 Live verification

Where possible, verify:

IdM reachable
IdM unavailable

and record actual observed behavior.

Do not fabricate outage evidence.

18. Existing SSH session termination

Deferred.

Reason:

A future event must trigger host-side action.

Generic implementation would require:

loop / scheduler
or
external event mechanism

Therefore v3.1 MUST NOT implement expiration-triggered session termination.

One-shot manual session-management commands, if ever added, require a separate specification.

19. Temporary login grants and operator responsibility

Because v3.1 does not own a recurring execution mechanism, documentation MUST clearly distinguish:

desired validity
vs
native enforced validity
vs
reconcile-required validity

For example:

Account expiration:
    native enforced

Timed sudo:
    native enforced

Temporary HBAC login grant:
    reconcile required for future transitions

The TUI SHOULD surface a warning on a temporary login grant such as:

Timing enforcement: explicit Pilot reconcile required at lifecycle transitions

Do not hide this limitation.

20. Structured actions / MCP

At minimum expose one-shot operations equivalent to:

inspect_access_health
run_access_drift
repair_access_drift
list_access_reviews
mark_access_review
reconcile_native_account_expiration
inspect_native_enforcement

pilot access reconcile already exists as a CLI command (§2.1) but is not yet registered as an MCP structured action. Registering it as:

run_access_reconcile

is in scope for this phase as explicit one-shot write behavior — it is not a pre-existing MCP tool to merely preserve.

20.1 Do not add background actions

MUST NOT add:

start_access_controller
run_access_controller
install_access_loop
start_access_watch
schedule_access_reconcile

20.2 Side effects

Suggested:

inspect_access_health                  read
run_access_drift                       read
repair_access_drift                    write/destructive per existing taxonomy
list_access_reviews                    read
mark_access_review                     write
reconcile_native_account_expiration    write
inspect_native_enforcement             read
run_access_reconcile                   write

21. CLI / TUI wording

User-facing surfaces MUST NOT imply automation that does not exist.

Forbidden wording:

will automatically expire
Pilot will disable at 18:00
breakglass expires automatically
review overdue will suspend automatically

unless backed by a native enforcement mechanism.

Preferred wording:

FreeIPA native expiry
sudo native validity
explicit reconcile required
manual deactivation required
review overdue (report only)

22. Security properties

22.1 Fail before write

Write commands MUST fail before mutation for:

invalid roster
SoD conflict
grant policy violation
account lifecycle contradiction
unsupported backend capability required for requested native enforcement
ambiguous managed ownership

22.2 Native enforcement preferred

If a native backend capability exists and is supported, do not replace it with a Pilot-timed emulation.

22.3 No false automatic guarantee

A reconcile-dependent timestamp must never be presented as native automatic expiration.

22.4 No accidental privilege widening

Drift repair must not:

clear unrelated policy;

merge sibling HBAC dimensions;

broaden host scope;

create access groups.

22.5 No accidental revocation outside ownership

Manual repair only touches proven Pilot-owned objects.

23. Implementation phases

Phase 1 — Native account expiration

Scope note: net-new (see §2.5) — no existing compile step or apply task exists for account_policies today. This is the largest phase in this specification, not the smallest; estimate accordingly.

Implement:

account-policy compilation to FreeIPA principal expiration;

timestamp normalization;

live query;

idempotent apply;

explicit clear semantics;

explain/health visibility;

tests.

Exit criterion:

A future account expiration remains enforced by FreeIPA after Pilot exits.

Phase 2 — Native timed sudo verification

Scope note: already implemented end to end (internal/inventory/grant_compile.go's CompileSudoGrant, applied by playbooks/apply/freeipa-identity-apply.yml's sudonotbefore/sudonotafter task). This phase is live verification and test-hardening only — no new compilation logic is expected.

Strengthen/verify:

sudoNotBefore;

sudoNotAfter;

live LDAP/FreeIPA readback;

SSSD behavior;

boundary tests;

explain/health visibility.

Exit criterion:

Sudo stops being effective after the configured backend-native deadline without another Pilot invocation.

Phase 3 — Authentication-indicator verification

Scope note: capability probing, apply, and stale-indicator pruning already exist (internal/accessgrants/auth_policy_state.go; playbooks/apply/freeipa-identity-apply.yml's auth-indicator task). This phase is verification and strengthening only.

Implement/strengthen:

capability detection;

safe target mapping;

apply/readback;

explicit failure on unsupported target;

drift inspection.

Exit criterion:

Authentication strength remains enforced after Pilot exits.

Phase 4 — One-shot drift/health/audit

Scope note: delivered with a deliberately narrower drift-coverage cut than the full list below. Covered: existence/orphan drift for compiled login/sudo grant rules (§12.2/§12.3's orphan bullet), and native-attribute value drift for account-expiration (§12.5) and auth-policy indicators (§12.4) — the two axes Phases 1/3 already built desired-state compilers for, verified against synthetic --raw fixtures (no live FreeIPA target was available to confirm exact CLI output format). NOT covered: full subject/target/service attribute drift for static and compiled HBAC/sudo rules (§12.1, and §12.2/§12.3's "subject/target mutation" bullets) — that needs a full FreeIPA CLI `--raw` multi-field parse whose exact format this delivery could not verify live; implementing it on unverified assumptions risked a silently-wrong drift report, which is worse than the gap itself. See internal/accessgrants/drift.go's header comment. `--repair-managed` reuses the existing `pilot access reconcile` apply path (internal/accessgrants.RepairManaged) rather than a new narrower apply, since that path already only touches Pilot-owned managed constructs (§13.1). §20's MCP structured actions (inspect_access_health, run_access_drift, repair_access_drift, reconcile_native_account_expiration, inspect_native_enforcement) are NOT wired in this phase — CLI-only for now; MCP registration remains explicit follow-up work.

Implement:

account-expiration drift;

static HBAC drift;

compiled-grant drift;

sudo drift;

auth-policy drift;

one-shot health;

explicit managed repair;

audit events.

Exit criterion:

Intentional out-of-band native-policy mutation is detected and can be explicitly repaired.

Phase 5 — Optional review/offline hardening

Scope note: review metadata/reporting/mark (§14) is implemented — it needed no new live-FreeIPA dependency (report-only classification plus a roster write-back reusing the already-established MutateEncryptedRosterFile machinery from `pilot roster migrate`, internal/inventory/roster_vault.go). SSSD offline-access hardening (§17) is deliberately NOT implemented in this delivery: it requires new OS-family-aware Ansible role work plus live IdM-unavailable verification (§17.3) that this delivery had no live target to perform — implementing the config-writing half without the outage verification half would violate §17.2's own requirement and risked shipping unverified distro-specific SSSD behavior. Remains open follow-up work.

Implement only if scope remains justified:

review metadata/reporting;

review mark;

persistent SSSD offline-access configuration;

live verification.

No automatic review suspension.

24. Tests

24.1 Account expiration

RFC3339 -> backend timestamp conversion;

timezone normalization;

desired/live equal -> no change;

desired/live different -> update;

live unset -> update;

explicit clear;

unknown user fail;

account lifecycle dominates grants;

future expiry remains configured after Pilot exits.

24.2 Timed sudo

not-before readback;

not-after readback;

pre-window denied;

in-window allowed;

post-window denied;

SSSD cache refresh/propagation documented;

no later Pilot invocation required.

24.3 Authentication indicators

supported host/principal;

unsupported target;

indicator readback;

no silent downgrade;

drift detected.

24.4 Temporary HBAC grant classification

pending grant reports reconcile_required;

active grant reports reconcile_required;

future not-after appears as desired transition only;

no claim of automatic expiry;

explicit reconcile updates state correctly when manually invoked.

24.5 Drift

static team-HBAC direct user mutation;

static group mutation;

direct host mutation;

hostgroup mutation;

legacy access subject inspectable;

managed login grant drift;

sudo timing drift;

account expiration drift;

auth indicator drift;

unmanaged policy ignored by repair;

repair idempotent.

24.6 Review

review due;

review overdue;

mark review;

encrypted roster safe mutation;

unsupported automatic suspend rejected or clearly non-enforcing.

24.7 Audit

account expiration event;

sudo validity event;

auth indicator event;

drift event;

repair event;

review event;

no secret sentinel leakage.

24.8 Offline access

If implemented:

Red Hat-family configuration;

Debian-family configuration where supported;

config validation;

service restart/reload;

IdM outage live test.

24.9 Repository regression

At minimum:

gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./cmd/pilot

Run relevant race tests for any state/audit concurrency changes.

Run Ansible syntax checks for every changed playbook.

25. Acceptance scenarios

Scenario A — Temporary contractor account

Input:

account_policies:
  - name: vendor01-contract
    user: vendor01
    validity:
      not_after: 2026-12-31T23:59:59+08:00

Expected:

Pilot applies FreeIPA native principal expiration once.
Pilot exits.
No Pilot loop is running.
At the future backend deadline, FreeIPA/Kerberos enforces account expiry.

Scenario B — Timed sudo

Input:

grants:
  - name: alice-maintenance
    kind: sudo
    validity:
      not_before: 2026-08-27T15:00:00+08:00
      not_after: 2026-08-27T19:00:00+08:00

Expected:

Pilot writes native sudo timing once.
Pilot exits.
sudo validity transitions remain backend-enforced.

Scenario C — Temporary HBAC login grant

Input:

grants:
  - name: vendor-db-login
    kind: temporary_grant
    validity:
      not_after: 2026-08-27T18:00:00+08:00

Expected v3.1 behavior:

status/explain reports:
    desired expiry = 18:00
    timing_enforcement = reconcile_required

No background Pilot loop is created.
No promise of automatic HBAC disable at 18:00 is made.

Scenario D — Account expiration drift

Live FreeIPA expiration is manually removed.

Expected:

pilot access drift
    -> reports account-expiration drift

pilot access drift --repair-managed
    -> explicit one-shot restore

No periodic repair.

Scenario E — Review overdue

Expected:

pilot access review list
    -> reports overdue

No automatic grant suspension.

Scenario F — Authentication indicator

Expected:

one-shot apply configures supported native indicator
Pilot exits
FreeIPA/Kerberos keeps enforcing it

26. Definition of done

v3.1 is DONE only when all of the following are true.

pilot access controller run does not exist.

No v3.1 correctness property depends on a permanent Pilot process.

No v3.1 implementation requires an in-process scheduler.

No generic Clock interface is introduced solely for this version.

No systemd timer/cron/CronJob is required by the v3.1 correctness contract.

Account expiration uses verified FreeIPA/Kerberos native expiration where supported.

Account expiration is idempotently readable/reconcilable.

Timed sudo uses verified native sudoNotBefore / sudoNotAfter.

Timed sudo expiry does not require another Pilot run.

Authentication indicators remain backend-native persistent policy.

Temporary HBAC grants are explicitly labeled reconcile_required for timing.

v3.1 does not claim automatic HBAC not-before/not-after enforcement.

Break-glass generic HBAC auto-expiry is deferred.

Automatic recertification suspension is deferred.

Automatic existing-session termination is deferred.

Periodic drift detection/repair is deferred.

One-shot drift inspection exists.

Explicit managed drift repair preserves ownership boundaries.

Account-expiration drift is covered.

Access health distinguishes native enforcement from reconcile-required timing.

Audit events contain no secrets.

No new access-* authoring path exists.

HBAC users/groups/hosts/hostgroups remain independent dimensions.

go test ./... passes.

go vet ./... passes.

go build ./cmd/pilot passes.

relevant Ansible syntax checks pass.

no fabricated live-environment evidence is added.

27. Explicitly deferred follow-up

A future version may define loop/event-driven security operations.

That specification must independently solve:

process lifecycle
deployment model
scheduler ownership
restart recovery
state persistence
locking
clock abstraction
transition SLO
monitoring
failure retry
multi-instance coordination
upgrade behavior
secret access

Candidate future features:

automatic HBAC grant activation
automatic HBAC grant expiration
automatic break-glass expiration
automatic review suspension
periodic drift repair
event-driven session termination
scheduled access health

None of them are prerequisites for v3.1.

28. Final v3.1 architecture

                    Roster v3
                        |
                        v
                 explicit Pilot run
                        |
          +-------------+-------------+
          |                           |
          v                           v
   native persistent            one-shot inspection
     configuration                    |
          |                           |
   +------+------+             +------+------+
   |             |             |             |
   v             v             v             v
account       timed sudo      drift         health
expiry                          |
   |                            v
   v                      explicit repair
FreeIPA/KDC
native future
enforcement

Authentication indicators:
    one-shot apply -> persistent FreeIPA/Kerberos enforcement

Temporary HBAC validity:
    explicit reconcile only
    no Pilot loop
    no automatic timing guarantee in v3.1
