Pilot Roster v3.2 — Identity & Credential Hardening Specification

Status: Implementation specification
Target repository: kjelly/pilot
Baseline: main at 162cc153aee2d6d831e357bdd1b63beee97a7be0 (post v3.1 Phase implementation — 497e8e6 predates v3.1 §7/§8/§10.3/§9/§12-16/§14 landing in 62cdeea..dfdbe58; §2's "already-delivered v3.1" dependency requires this later baseline)
Date: 2026-08-27
Audience: Coding agent / maintainer implementing the change

1. Executive decision

Pilot v3.2 SHALL harden FreeIPA identities and credentials without introducing any Pilot loop, scheduler, daemon, recurring worker, timer queue, or background controller.

The inclusion rule is:

A v3.2 feature is allowed only when:

one explicit Pilot apply can configure a persistent FreeIPA/Kerberos/SSSD security control that remains enforced after Pilot exits; or

the feature is an explicit one-shot inspection, validation, drift report, or repair command.

Explicitly:

DO NOT implement in v3.2:
    background credential scanner
    recurring identity hygiene job
    automatic SSH-key revocation by age
    automatic stale-account disable
    automatic overdue-review suspension
    automatic password rotation
    automatic SSH-key rotation
    scheduled drift repair
    scheduled credential revalidation
    pilot identity controller run
    pilot identity watch
    generic Clock/Scheduler framework

Pilot remains:

explicit invocation
    ->
validate / configure / inspect / repair
    ->
exit

Approval remains OUT OF SCOPE.

2. Baseline and dependencies

v3.2 depends on the already-delivered authorization model and SHALL preserve it.

Required prior semantics:

HBAC simplification:
    team-*   -> organizational identity set, HBAC-eligible
    role-*   -> reusable authorization/principal set, HBAC + sudo eligible
    data-*   -> filesystem only
    access-* -> deprecated compatibility only

v3.0:
    grants
    authentication policies
    grant policies
    SoD
    break-glass definitions
    account lifecycle
    access explain

v3.1:
    no Pilot loop
    native backend enforcement preferred
    one-shot drift/health/repair only

v3.2 MUST NOT reintroduce a background execution model.

3. Goals

v3.2 MUST provide:

FreeIPA group password policies;

user authentication-type management;

privileged-identity baseline validation;

SSH public-key hygiene validation;

credential policy metadata for one-shot inspection;

FreeIPA capability probing;

one-shot identity hygiene reporting;

one-shot identity drift inspection;

explicit managed identity drift repair;

verification that configured native security controls persist after Pilot exits;

consistent TUI / structured actions / MCP representation;

clear separation between native enforcement, one-shot reporting, and deferred automation.

4. Non-goals

The following are explicitly deferred.

4.1 No recurring identity controller

Do not implement:

pilot identity controller run
pilot identity daemon
pilot identity watch

4.2 No automatic SSH-key revocation

A policy such as:

ssh:
  max_age: 365d

may be used for hygiene reporting.

It MUST NOT mean:

day 366 -> Pilot automatically deletes the key

because that requires future Pilot execution.

4.3 No automatic stale-account disable

A one-shot report may identify a stale account.

v3.2 MUST NOT automatically disable the account after an inactivity threshold.

4.4 No automatic credential review suspension

Review-overdue status may be reported.

No automatic user disable, key deletion, or privilege suspension occurs in v3.2.

4.5 No automatic rotation

Do not implement password, SSH key, OTP seed, or service credential auto-rotation.

4.6 No periodic drift repair

Drift inspection/repair is explicit and one-shot.

4.7 No continuous monitoring

pilot identity hygiene and pilot identity drift run once and exit.

5. Enforcement hierarchy

v3.2 SHALL follow:

1. FreeIPA/Kerberos native enforcement
2. persistent SSSD/host configuration
3. fail-before-write validation
4. explicit one-shot inspection
5. explicit one-shot repair
6. recurring Pilot execution -> DEFERRED

The implementation MUST document which category every feature belongs to.

6. Capability matrix

Security function

Native/persistent backend enforcement

Needs Pilot loop

v3.2

Group password policy

yes

no

implement

Password history/min length/max life

yes

no

implement

Login failure/lockout policy

yes

no

implement where supported

User auth types

yes

no

implement

Kerberos auth indicators

yes/persistent where supported

no

reuse/verify

SSH key syntax/algorithm policy

validation only

no

implement

SSH key max-age report

report only

no

implement

SSH key max-age auto-delete

no

yes

deferred

Credential review due/overdue report

report only

no

implement

Credential review auto-suspend

no

yes

deferred

Stale-account report

report only if reliable data exists

no

optional

Stale-account auto-disable

no

yes

deferred

Password auto-rotation

no generic native workflow

yes/external workflow

deferred

SSH key auto-rotation

no

yes/external workflow

deferred

Identity drift inspection

one-shot

no

implement

Identity drift auto-repair periodically

no

yes

deferred

7. Password policies

Pilot SHALL manage FreeIPA group password policies declaratively.

Example:

password_policies:
  - name: privileged-users
    state: present
    group: role-privileged
    priority: 10
    min_length: 16
    history_size: 24
    max_life: 90d
    min_life: 1h
    lockout:
      max_failures: 5
      failure_reset_interval: 15m
      lockout_duration: 15m

Requirements:

group MUST resolve.

Exact supported fields MUST map to the actual FreeIPA target.

Priority semantics MUST match real FreeIPA behavior.

Reuse one canonical duration parser where possible.

Group-specific policy creation MUST NOT silently overwrite the global default policy.

state: absent removal must be explicit and ownership-safe.

Once applied successfully, the password policy remains enforced by FreeIPA after Pilot exits.

Preferred security target groups are role-*. Do not use deprecated access-* as the new privileged grouping model.

8. User authentication types

Canonical intent:

users:
  - name: alice
    authentication:
      allowed:
        - otp
        - pkinit

Potential values include:

password
otp
pkinit
radius

but the implementation MUST verify the exact supported set.

Semantics must stay distinct:

user.authentication.allowed
    = authentication mechanisms the identity may use

auth_policies[].require_any
    = authentication indicators required by a target

A successful one-shot apply configures FreeIPA/Kerberos persistently.

Unsupported auth types must fail closed. Never silently downgrade strong authentication to password-only.

9. Privileged identity baseline

Example:

security:
  privileged_identity:
    match_groups:
      - role-privileged
      - role-production-admin
    require:
      auth_types:
        - otp
        - pkinit
      no_password_only: true
      ssh_key_policy: privileged-ssh

Requirements:

Match recursive/effective group membership.

alice -> team-sre -> role-production-admin means Alice is privileged.

Before a transaction makes a user privileged, validate the resulting baseline when the whole transaction can be evaluated safely.

Non-compliance should fail before write.

Do not add a background checker to enforce this later.

10. SSH public-key hygiene

Recommended policy:

credential_policies:
  - name: privileged-ssh
    state: present
    match:
      users: []
      groups:
        - role-privileged
    ssh:
      allowed_algorithms:
        - ssh-ed25519
        - ecdsa-sha2-nistp256
      require_comment: true
      max_age: 365d

At minimum support:

blank key reject;

malformed/truncated key reject where safely detectable;

duplicate public-key material detection;

algorithm extraction;

configured algorithm allowlist;

optional comment requirement.

Do not silently impose a hard-coded algorithm allowlist.

Duplicate detection SHOULD compare normalized public-key material, not comments.

max_age is report-only in v3.2.

If key age cannot be derived reliably, report:

unsupported
unknown

Do not infer age from roster file mtime, account creation time, Git history, or current time.

Automatic key deletion is deferred.

11. Credential review metadata

v3.2 MAY support review metadata for reporting.

Example:

credential_policies:
  - name: privileged-credentials
    review:
      interval: 180d
      last_reviewed_at: 2026-08-01T10:00:00+08:00
      reviewed_by: alice

Supported one-shot states:

current
due
overdue
unknown

An explicit review-mark operation MAY be provided.

Do not implement any automatic consequence such as:

overdue -> disable account
overdue -> delete SSH key
overdue -> remove role
overdue -> suspend grant

reviewed_by is audit metadata, not Approval proof.

12. Stale-account reporting

Pilot MAY report stale identities only when FreeIPA exposes sufficiently reliable activity data for the chosen definition.

If reliable data is unavailable:

status = unsupported

Do not invent last-login from unrelated LDAP timestamps.

Even when stale status is known:

report only

No automatic disable in v3.2.

13. FreeIPA capability probing

Recommended model:

type CapabilityState string

const (
    CapabilitySupported   CapabilityState = "supported"
    CapabilityUnsupported CapabilityState = "unsupported"
    CapabilityUnknown     CapabilityState = "unknown"
)

type FreeIPACapabilities struct {
    GroupPasswordPolicy      CapabilityState
    PasswordLockoutPolicy    CapabilityState
    UserAuthTypes            CapabilityState
    AuthenticationIndicator  CapabilityState
    PrincipalExpiration      CapabilityState
    SudoNotBeforeAfter       CapabilityState
}

Probes MUST be:

read-only;

deterministic;

cached per explicit command run;

machine-readable;

secret-safe.

Do not rely only on version strings where direct probing is possible.

If a requested native control requires a capability whose state is unknown, fail closed rather than silently skipping the control.

14. One-shot identity hygiene

Add:

pilot identity hygiene <roster-file>
pilot identity hygiene <roster-file> --format json

Report domains:

password policy coverage
user authentication-type compliance
privileged identity baseline
SSH key policy
credential review status
stale account status where supported
backend capability status

Example JSON:

{
  "evaluated_at": "2026-08-27T15:00:00+08:00",
  "users": [
    {
      "name": "alice",
      "privileged": true,
      "auth_compliance": "pass",
      "ssh_key_compliance": "pass",
      "credential_review": "current"
    }
  ]
}

Hygiene is read-only. It never mutates FreeIPA.

15. One-shot identity drift

Add:

pilot identity drift <roster-file>
pilot identity drift <roster-file> --format json

At minimum compare:

desired/live group password policies;

desired/live user auth types;

desired/live authoritative SSH public keys where readable;

desired/live authentication indicators relevant to identity policy;

desired/live principal expiration where account lifecycle owns it.

Repair MAY be explicit:

pilot identity drift <roster-file> --repair-managed

Flow:

inspect
-> preview
-> validate
-> policy gate
-> explicit repair
-> verify
-> exit

No recurring repair.

Repair only state Pilot can prove it owns.

16. Persistent SSSD / client hardening

Known blocker carried over from v3.1: v3.1 Phase 5 (commit dfdbe58) explicitly deferred its own §17 SSSD offline-access hardening because it needs new OS-family-aware Ansible role work plus live IdM-unavailable verification, and that delivery had no live target to perform it against. Nothing in the current repo state indicates this blocker has been resolved. Do not commit to landing this section in v3.2 until a live target for IdM-unavailable verification is confirmed available; otherwise scope it the same way v3.1 did — explicitly deferred, documented, not silently dropped.

Identity-hardening controls MAY be included when they are persistent after one-shot apply.

Examples:

offline/cached authentication policy
SSSD domain hardening
certificate/authentication helper configuration

Allowed:

Pilot applies config once
    ->
host service persistently enforces it

Not allowed:

Pilot must revisit the host periodically
    ->
policy remains correct

Implementation MUST be OS-family aware, validate SSSD configuration, and safely reload/restart services.

17. TUI

Recommended structure:

Identity hardening
├── Password policies
├── User authentication
├── Credential policies
├── Privileged identity
├── Hygiene report
└── Drift

Use explicit status labels:

NATIVE
PERSISTENT
REPORT ONLY
UNSUPPORTED
UNKNOWN
DRIFT

Do not imply background automation.

Do not rely on color as the only status signal.

18. Structured actions

At minimum expose actions equivalent to:

create_password_policy
set_password_policy_field
delete_password_policy

set_user_authentication_types

create_credential_policy
set_credential_policy_field
delete_credential_policy

inspect_identity_hygiene
inspect_identity_drift
repair_identity_drift

inspect_freeipa_capabilities

Optional:

mark_identity_review

Do NOT add:

start_identity_controller
schedule_identity_scan
enable_identity_watch
start_credential_rotation

19. MCP

MCP read/write surfaces SHALL expose the same sanctioned semantic model.

Read side SHOULD include:

password policies
credential policies
user auth types
privileged compliance
capabilities
hygiene findings
drift findings

Write side derives from sanctioned semantic actions.

Never expose private keys or OTP seeds.

20. Validator / backend / docs synchronization

For every new roster field update:

Go validator
Ansible canonical gate where applicable
example roster
runbook
verification docs
TUI
structured actions
MCP representation

A roster accepted by Go must not be rejected by an equivalent Ansible allowlist drift.

21. Security properties

21.1 Fail before write

Fail before mutation on:

unknown group/user
invalid password-policy field
unsupported requested auth type
unsupported required capability
privileged baseline violation
malformed SSH key
forbidden SSH algorithm under active policy
ambiguous destructive ownership

21.2 No silent downgrade

Never weaken requested security merely to make apply succeed.

21.3 No loop-dependent guarantee

Anything requiring a future Pilot invocation must be labeled:

report only
explicit action required
deferred automation

21.4 No new access groups

No v3.2 authoring surface may create category: access.

21.5 Secret safety

Never log/persist password plaintext, OTP seed, SSH private key, vault password, or a full decrypted roster.

22. Implementation phases

Phase 1 — Capability layer

Implement capability states, read-only probes, per-run caching, machine-readable output, and tests.

Exit criterion:

supported
unsupported
unknown

are distinguishable for required controls.

Phase 2 — Password policies

Implement schema, validator, compiler/backend, live readback, TUI/actions/MCP, idempotency, and tests.

Exit criterion:

A configured group password policy remains enforced after Pilot exits.

Phase 3 — User auth types + privileged baseline

Implement auth-type schema, capability-aware validation, backend apply/readback, effective-role matching, and fail-before-write baseline validation.

Exit criterion:

Privileged identities cannot be placed into a policy state that violates configured strong-auth requirements without Pilot rejecting the transaction.

Phase 4 — SSH/credential hygiene

Implement credential-policy schema, SSH parser/normalizer, duplicate detection, configurable algorithm policy, optional comment requirement, report-only max-age, and review reporting.

Exit criterion:

Findings are deterministic and never trigger hidden future mutation.

Phase 5 — One-shot hygiene/drift/repair

Implement hygiene CLI, drift CLI, explicit repair, audit, TUI/MCP views.

Exit criterion:

Out-of-band managed identity changes can be detected and explicitly repaired without a recurring Pilot process.

Phase 6 — Optional persistent client hardening (opt-in / likely deferred)

Treat as opt-in, not a committed deliverable: implement only if (a) justified and persistent after one-shot apply, AND (b) a live target for IdM-unavailable verification is actually available (see §16). If no such target is available when Phase 5 completes, defer Phase 6 explicitly in the same manner v3.1 §17 was deferred — document the gap rather than shipping unverified outage behavior.

23. Tests

Capability

supported;

unsupported;

unknown due to probe failure;

no mutation when required capability is unknown;

per-run cache;

machine-readable result.

Password policy

valid role-group policy;

unknown group;

invalid priority;

duplicate/ambiguous priority;

invalid duration;

apply/readback;

idempotent second apply;

explicit removal;

global policy protected.

User auth types

password;

otp;

pkinit;

radius where supported;

unsupported type;

no silent downgrade;

live readback;

idempotency.

Privileged identity

direct role member;

nested team -> role;

compliant user;

non-compliant user blocked;

role removal updates effective result.

SSH hygiene

blank key;

malformed key;

duplicate material with different comments;

allowed algorithm;

disallowed algorithm;

missing required comment;

max-age unavailable -> unknown;

max-age available -> report only.

Credential review

current;

due;

overdue;

mark review;

encrypted roster safe mutation;

no automatic disable/remove.

Stale account

If supported:

reliable last activity;

stale classification;

unsupported backend data -> unknown;

no automatic disable.

Hygiene

privileged auth violation;

SSH violation;

review overdue;

capability unsupported;

JSON output stable;

zero mutation.

Drift

password-policy drift;

auth-type drift;

SSH key drift;

auth-indicator drift;

principal-expiration drift;

unmanaged object ignored by repair;

managed repair idempotent.

Audit

password-policy event;

auth-type event;

credential-policy event;

review event;

drift event;

repair event;

no secret leakage.

Repository regression

At minimum:

gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./cmd/pilot

Run relevant race tests for state/audit mutation code and syntax checks for changed Ansible playbooks.

24. Acceptance scenarios

Scenario A — Privileged password policy

Pilot applies the policy once and exits. FreeIPA continues enforcing it. No loop exists.

Scenario B — Privileged strong authentication

A nested effective privileged user that does not meet the configured auth baseline is rejected during the explicit transaction.

Scenario C — SSH key age exceeds policy

pilot identity hygiene reports the violation. The key remains unchanged.

Scenario D — Key age cannot be known

Report unknown or unsupported; do not guess.

Scenario E — Review overdue

Report overdue. Do not disable account or remove credentials.

Scenario F — Out-of-band auth-type change

pilot identity drift reports the mismatch; explicit repair restores it.

Scenario G — Capability unavailable

Requested native security control fails closed before mutation.

25. Definition of done

v3.2 is DONE only when all of the following are true.

No pilot identity controller run exists.

No v3.2 correctness property requires a Pilot background process.

No generic Clock/Scheduler abstraction is introduced solely for v3.2.

Password policies are backend-native/persistent where supported.

Password-policy live readback exists.

User authentication types are capability-aware.

Authentication-type live readback exists.

Privileged identity matching uses effective nested role membership.

Privileged baseline fails safely on non-compliance.

SSH public-key hygiene is configurable.

SSH duplicate material is detected.

SSH max_age is report-only.

Unknown key age is not guessed.

Credential review is report-only.

No automatic review suspension exists.

Stale-account reporting does not auto-disable users.

No automatic password rotation exists.

No automatic SSH-key rotation exists.

One-shot pilot identity hygiene exists.

One-shot identity drift inspection exists.

Explicit managed drift repair preserves ownership boundaries.

FreeIPA capability probing distinguishes supported/unsupported/unknown.

Requested native controls fail closed when required capability is unknown.

No new access-* creation path exists.

TUI does not imply nonexistent automation.

Structured actions expose no background/scheduled operation.

Audit output contains no secrets.

go test ./... passes.

go vet ./... passes.

go build ./cmd/pilot passes.

relevant Ansible syntax checks pass.

no fabricated live-environment evidence is added.

26. Explicitly deferred follow-up

A future automation-focused version may add:

automatic SSH-key revocation by age
automatic credential rotation
automatic password rotation
automatic stale-account disable
automatic review suspension
periodic identity hygiene scan
periodic identity drift repair
event-driven identity remediation

That future specification must independently define:

process lifecycle
scheduler ownership
clock abstraction
state persistence
retry semantics
failure handling
monitoring
high availability
multi-instance behavior
secret access
upgrade compatibility

These concerns MUST NOT be introduced piecemeal into v3.2.

27. Final v3.2 architecture

                     Roster v3
                         |
                         v
                 explicit Pilot run
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
 password policy     user auth types   credential policy
       |                 |                 |
       v                 v                 v
    FreeIPA           FreeIPA          validation/report
       |                 |
       +--------+--------+
                |
                v
      persistent native enforcement
          after Pilot exits

One-shot inspection:
    pilot identity hygiene
    pilot identity drift

Explicit repair:
    pilot identity drift --repair-managed

Deferred:
    any feature that needs Pilot to wake up later
