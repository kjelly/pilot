Pilot Roster Safe User & Group Removal — Coding Agent Implementation Spec

Repository: https://github.com/kjelly/pilot

Baseline inspected: main at commit 521366e899561f7e38edc012fc88339742382468

Date: 2026-08-21

Status: implementation specification

Primary goal: add safe commands for removing accidentally-created local roster user/group definitions that have never been applied to FreeIPA.

Safety invariant: once a user or group has ever been applied to FreeIPA, Pilot must never hard-remove that resource entry from the roster.

1. Problem statement

Pilot currently supports adding and editing canonical FreeIPA roster users/groups, but intentionally does not expose a safe hard-delete operation for roster resources.

The missing workflow is:

An operator accidentally adds a user to the roster.

The roster has not yet been reconciled to FreeIPA.

The operator wants to undo the bad local edit.

The operator must have a sanctioned Pilot command instead of manually editing YAML.

The command must not allow the same operation after the user has entered the FreeIPA lifecycle.

This feature is not FreeIPA user/group deprovisioning.

These are different operations:

Operation

Meaning

FreeIPA side effect

pilot roster remove-user

Undo a never-applied local user definition

None

pilot roster remove-group

Undo a never-applied local group definition

None

user state: disabled

Keep account but disable it

FreeIPA user disabled

user state: absent

Deprovision an applied user

User is permanently deleted from FreeIPA (existing behavior, unchanged by this feature)

group state: absent

Deprovision an applied group

FreeIPA group is deleted, history marker remains

Manual permanent deletion of preserved users/history markers

Unsupported

Breaks the historical safety invariant

The implementation must keep these lifecycle concepts separate.

2. Non-negotiable safety invariant

2.1 Core invariant

If a roster user has ever existed in FreeIPA as either an active user or a preserved user, pilot roster remove-user MUST refuse to hard-remove the roster entry forever.

If a roster group has ever existed in FreeIPA, pilot roster remove-group MUST refuse to hard-remove the roster entry forever, even after the actual FreeIPA group is deleted.

For groups, this requires a separate durable FreeIPA-side history marker because FreeIPA does not provide a preserved-group lifecycle equivalent to preserved users.

This is stricter than:

“The user does not currently exist.”

The implementation must establish a durable FreeIPA-side historical signal.

2.2 Why current ipa user-show alone is not enough

A query such as:

ipa user-show alice

can prove that a user currently exists in FreeIPA.

It cannot prove historical existence after a permanent LDAP deletion.

Therefore the strict invariant is only implementable if Pilot changes its user deprovision lifecycle so that a Pilot-managed user is never permanently deleted from FreeIPA.

2.3 Required historical model: FreeIPA preserved users

FreeIPA supports preserved users:

ipa user-del alice --preserve

A preserved user is moved to the FreeIPA deleted-user container instead of being permanently removed.

FreeIPA documents that ipa user-show <name> can retrieve both:

an active user; and

a preserved/deleted user.

Therefore Pilot must treat the union:

Active FreeIPA user
    OR
Preserved FreeIPA user

as:

ever_applied = true

This would make FreeIPA itself the authoritative historical registry for Pilot-managed users, but only if Pilot actually adopted preserve semantics for its own deprovisioning. See §2.4.

2.4 Required operational policy (revised: preserve NOT adopted)

Decision: this feature does not change user deprovisioning. state: absent continues to call ipa user-del <name> without --preserve, exactly as today.

This was evaluated during spec review and explicitly rejected for this iteration, to keep the change scoped to roster-local mutation plus read-only FreeIPA probes rather than altering the live deprovisioning lifecycle.

Consequences:

Pilot may still observe a preserved user if one exists for any reason (e.g. created manually, outside Pilot, via ipa user-del --preserve), and must block remove-user in that case (§8).

Pilot MUST NOT expose a command that permanently deletes a preserved Pilot user, whether or not Pilot itself ever creates one.

Because Pilot does not create preserved users, the strict "ever_applied" guarantee holds only for roster entries that have never been reconciled at all. Once a user is deprovisioned through state: absent and permanently deleted, FreeIPA can no longer prove that user's history — see §2.5.

Documentation MUST state that this is a deliberate, permanent scope limitation, not a transitional one.

2.5 Permanent limitation (not just legacy — preserve was not adopted)

Because §2.4 keeps ipa user-del <name> as a permanent deletion (no --preserve), this limitation applies to every user Pilot ever deprovisions, forever — not only to data predating this feature.

For any user that:

was applied (reconciled into FreeIPA) at some point, and

was later permanently deleted via state: absent,

FreeIPA cannot reconstruct that history reliably once the deletion succeeds.

Do not attempt to infer this from:

missing local Pilot run history;

filesystem timestamps;

Ansible output files;

rotated FreeIPA logs;

absence from the current FreeIPA LDAP tree.

Apply these rules, permanently:

A roster user whose current roster state is absent is never eligible for remove-user. This is the sole remaining safeguard once a user has been permanently deleted from FreeIPA — it depends entirely on that roster tombstone row never being purged (§3.2: purge-user is out of scope).

A currently active/preserved user is never eligible.

A present/disabled roster user missing from FreeIPA can be removed. The implementation documentation must state plainly that the “ever applied” guarantee is provable by FreeIPA only for entries that were never reconciled at all — it does not extend across a permanent deletion, now or in the future, because Pilot does not adopt preserve semantics for users.

There must be no --force flag to bypass this guard.

3. Scope

3.1 In scope

Implement:

pilot roster remove-user <roster-file> <username>
pilot roster remove-group <roster-file> <groupname>

with:

--inventory, -i
--vault-password-file
--dry-run
--cascade-references

Both commands must:

inspect the roster;

verify that the target resource exists exactly once in the roster;

reject a target already in state: absent;

query the real FreeIPA server through an Ansible playbook;

reject hard removal if FreeIPA proves the resource has entered its managed lifecycle;

reject on any unknown/unqueryable FreeIPA state;

detect inbound roster references;

optionally remove only explicitly cascadeable local references when --cascade-references is set;

block on non-cascadeable references such as an NFS share's required ownership.group;

validate the complete candidate roster;

mutate YAML with the existing yaml.Node surgery pattern;

preserve unrelated formatting/content as far as the existing roster mutation layer permits;

support encrypted roster input through the existing vault conventions;

never call ipa user-del or ipa group-del from the roster hard-remove commands.

Additional user rule:

active or preserved FreeIPA user => hard-remove denied.

Additional group rule:

active FreeIPA group OR durable Pilot group-history marker => hard-remove denied.

3.2 Out of scope

Do not implement in this phase:

pilot roster purge-user
pilot roster purge-group

Do not add:

--force
--ignore-freeipa
--assume-never-applied

Do not use Pilot local run history as the authoritative ever-applied signal.

4. Group lifecycle and permanent history marker

4.1 remove-group is required

Implement:

pilot roster remove-group <roster-file> <groupname>

Its semantics are identical in spirit to remove-user:

remove-group == undo a never-applied local roster edit

It is not a remote FreeIPA group deletion command.

A group that has ever been applied must never be hard-removed from the roster.

4.2 Why ipa group-show alone is insufficient

For an active group:

ipa group-show team-platform

proves the group exists now.

After:

ipa group-del team-platform

FreeIPA does not provide a preserved-group lifecycle equivalent to preserved users. Therefore group-show cannot prove historical existence after deletion.

The implementation needs an independent durable history marker stored inside FreeIPA.

4.3 Do not add custom LDAP objects

Do not create a Pilot-specific LDAP schema or directly write arbitrary entries below cn=etc.

FreeIPA documentation recommends using its supported CLI/API for object mutation instead of custom LDAP writes because bypassing IPA plugins can produce inconsistent entries.

Use a standard FreeIPA object for the marker.

4.4 Marker design

For every Pilot-managed group that successfully enters FreeIPA, create a dedicated empty non-POSIX FreeIPA group whose only purpose is to record history.

Marker name:

pilot-internal-history-g-<sha256(group-name)>

Example:

logical group:
  team-platform

history marker:
  pilot-internal-history-g-<64-lowercase-hex-sha256>

Marker properties:

type: non-POSIX
members: none
description:
  pilot.group-history/v1 name=team-platform

Requirements:

marker name is deterministic;

hash input is the exact canonical roster group name encoded as UTF-8;

SHA-256 output is lowercase hexadecimal;

marker never receives users/groups/services;

marker is never added to the roster;

marker is never deleted by Pilot;

marker is created through ipa group-add --nonposix;

marker is queried through ipa group-show;

an existing marker with a non-matching description is a collision/corruption condition and must fail closed.

Current roster group category prefixes (team-, data-, access-, role-) naturally prevent this internal marker prefix from being authored as a normal canonical roster group.

4.5 Marker safety invariant

After the marker system is deployed:

actual group exists
  OR
valid deterministic history marker exists

means:

ever_applied = true

Therefore:

pilot roster remove-group

may proceed only when:

actual group == not found
AND
history marker == not found
AND
roster state != absent

Every other state denies hard removal.

4.6 Why one marker group per logical group

Do not store all historical names in one marker group's description/membership.

One deterministic marker object per group provides:

O(1) lookup;

no unbounded multivalue attribute;

no read-modify-write race on a shared marker object;

independent corruption detection;

simple idempotent Ansible behavior;

no dependency on KRA, DNS, or custom LDAP schema.

The cost is additional hidden-by-convention FreeIPA group objects. This is acceptable because they are non-POSIX and empty.

4.7 Marker deletion policy

Pilot must never delete these marker groups.

Documentation must explicitly state:

Manually deleting pilot-internal-history-g-* objects invalidates the strict historical guarantee, just as permanently deleting a preserved Pilot user does.

No Pilot command may expose marker deletion.

4.8 Applied group deletion

The existing declarative lifecycle remains:

groups:
  - name: team-platform
    state: absent

This still means the actual FreeIPA group should be deleted.

Before ipa group-del, however, the apply playbook must guarantee that a valid history marker exists.

Required lifecycle:

state: present
    |
    v
ensure actual group exists
    |
    v
ensure history marker exists
    |
    v
normal membership/policy reconciliation

state: absent
    |
    v
query actual group
    |
    +-- exists --> ensure history marker --> ipa group-del
    |
    +-- absent --> no remote group deletion

If an actual group exists but the history marker cannot be created/validated, deletion must fail closed.

4.9 Legacy groups

For a legacy roster entry with:

state: absent

and both:

actual group missing
history marker missing

history is ambiguous.

The group entry must remain a roster tombstone and remove-group must reject it.

Do not infer “never applied” from missing FreeIPA state for a legacy state: absent group.

4.10 Backfill

On the first successful identity reconcile after this feature is deployed:

every canonical group in state: present that exists/was created must receive its history marker;

every canonical group in state: absent that still exists must receive its marker before deletion.

This backfills active Pilot-managed groups without requiring Pilot local run history.

5. Existing code that this feature must reuse

5.1 Existing roster command

Current command tree includes:

pilot roster lint
pilot roster migrate

The new command belongs under the same rosterCmd.

Recommended file:

cmd/pilot/cmd/roster_remove_user.go

5.2 Existing roster mutation pattern

internal/inventory/roster.go already follows this pattern:

SimulateAddRosterUser
AppendRosterUser

SimulateSetRosterUser
SetRosterUser

The new delete path must mirror it:

SimulateRemoveRosterUser
RemoveRosterUser

Do not perform direct YAML mutation inside Cobra handlers.

5.3 Existing mutation lock

internal/inventory/roster_lock.go already provides a file mutation lock.

The final roster mutation must use the same locking discipline used by other destructive roster operations.

5.4 Existing validation

The candidate roster must pass the same complete validator:

inventory.ValidateRoster(...)

before bytes are replaced on disk.

5.5 Existing ansible runner

Reuse internal/ansible.Runner and the same deployment runtime preparation used by deploy/reconcile.

Do not shell out from the CLI implementation with an ad-hoc exec.Command("ansible-playbook", ...) if an existing runner abstraction already covers the required invocation.

6. CLI contract

6.1 Commands

pilot roster remove-user <roster-file> <username> \
  --inventory inventory.yml \
  --vault-password-file ~/.vault/vault-pass

pilot roster remove-group <roster-file> <groupname> \
  --inventory inventory.yml \
  --vault-password-file ~/.vault/vault-pass

6.2 Flags

--inventory, -i

Default:

inventory.yml

Required because the command must resolve and contact the real FreeIPA server.

--vault-password-file

Required when the roster is ansible-vault encrypted.

Follow the same user-facing conventions as:

pilot roster migrate --vault-password-file ...

--dry-run

Performs every read/probe/validation step but does not mutate the roster.

--cascade-references

Allows removal of local inbound references to the target user.

It must not bypass the FreeIPA historical guard.

6.3 No force bypass

There must be no flag that converts:

ever_applied=true

or:

probe_status=unknown

into an allowed hard removal.

7. Command result semantics

7.1 Safe removal

Example:

Removed roster-only user "typo-user".
FreeIPA history check: not found.
References removed: 0.

7.2 Applied user

Example:

refusing to remove roster user "alice":
FreeIPA reports an active or preserved user with this name.

This user has entered the FreeIPA lifecycle and must remain represented
in the roster. Use state: disabled or state: absent instead.

7.3 Unknown FreeIPA state

Example:

refusing to remove roster user "alice":
unable to prove that the user has never been applied to FreeIPA.

FreeIPA probe failed: authentication/network/server query error.
No roster bytes were changed.

7.4 Referenced user

Without --cascade-references:

cannot remove roster user "typo-user": resource is still referenced

references:
  groups[team-platform].membership.users
  hbac.rules[ssh-platform].subjects.users
  sudo.rules[sudo-build].subjects.users
  netgroups[ng-build].membership.users

rerun with --cascade-references to remove these local references

7.5 Applied group

Example:

refusing to remove roster group "team-platform":
FreeIPA history marker proves this group has entered the managed lifecycle.

marker:
  pilot-internal-history-g-...

Use state: absent for declarative FreeIPA deletion.
The roster tombstone must remain.

7.6 Non-cascadeable group reference

Example:

cannot remove roster group "data-project-alpha-rw":
the group is required by a non-cascadeable reference

references:
  nfs.servers[nfs1].shares[project-alpha].ownership.group

Change the owning group explicitly before removing this roster group.

8. FreeIPA user ever-applied probe playbook

Add:

playbooks/check/freeipa-identity-user-ever-applied.yml

The playbook must be:

read-only;

fail-closed;

machine-readable;

safe for active and preserved users;

consistent with current canonical roster credential loading.

8.1 Required input variables

freeipa_roster_file
pilot_identity_name
pilot_identity_probe_output
target_group              optional, default freeipa-server

The CLI should create pilot_identity_probe_output as a temporary controller-side file and remove it after parsing.

8.2 Required output contract

JSON schema version 1:

{
  "schema_version": 1,
  "kind": "user",
  "name": "alice",
  "ever_applied": true,
  "freeipa_state": "active_or_preserved"
}

Allowed freeipa_state values:

active_or_preserved
not_found

Do not encode unknown as a successful JSON result.

Unknown state must fail the playbook.

8.3 Complete proposed playbook

---
- name: Probe whether a roster user has ever entered the FreeIPA lifecycle
  hosts: "{{ target_group | default('freeipa-server') }}"
  become: false
  gather_facts: false

  vars:
    freeipa_roster: {}

  pre_tasks:
    - name: "Gate: probe input is complete"
      ansible.builtin.assert:
        that:
          - freeipa_roster_file is defined
          - freeipa_roster_file | string | trim | length > 0
          - pilot_identity_name is defined
          - pilot_identity_name is match('^[a-z_][a-z0-9_.-]*$')
          - pilot_identity_probe_output is defined
          - pilot_identity_probe_output | string | trim | length > 0
        fail_msg: >-
          freeipa_roster_file, pilot_identity_name, and
          pilot_identity_probe_output are required.
      run_once: true
      tags: [always]

    - name: "Load canonical roster under a namespace"
      ansible.builtin.include_vars:
        file: "{{ freeipa_roster_file }}"
        name: freeipa_roster
      no_log: true
      run_once: true
      tags: [always]

    - name: "Gate: canonical roster is available"
      ansible.builtin.assert:
        that:
          - freeipa_roster.schema_version is defined
          - freeipa_roster.freeipa is defined
          - freeipa_roster.freeipa.admin is defined
          - freeipa_roster.freeipa.admin.password is defined
          - freeipa_roster.freeipa.admin.password | length >= 8
        fail_msg: >-
          Canonical roster with FreeIPA admin credentials is required
          for an authoritative ever-applied probe.
      no_log: true
      run_once: true
      tags: [always]

    - name: "Normalize FreeIPA probe settings"
      ansible.builtin.set_fact:
        ipa_domain: "{{ freeipa_domain | default('ipa.pilot.internal') }}"
        ipa_realm: >-
          {{ freeipa_realm |
             default((freeipa_domain | default('ipa.pilot.internal')) | upper) }}
        identity_admin_principal: >-
          {{ freeipa_roster.freeipa.admin.principal | default('admin') }}
        identity_admin_password: "{{ freeipa_roster.freeipa.admin.password }}"
      no_log: true
      run_once: true
      tags: [always]

    - name: "Kinit admin for read-only identity probe"
      ansible.builtin.shell:
        cmd: |
          set -o pipefail
          printf %s "{{ identity_admin_password }}" |
            kinit "{{ identity_admin_principal }}@{{ ipa_realm }}"
        executable: /bin/bash
      changed_when: false
      no_log: true
      run_once: true
      tags: [identity, probe]

  tasks:
    - name: "Probe active or preserved FreeIPA user"
      ansible.builtin.command:
        argv:
          - ipa
          - user-show
          - "{{ pilot_identity_name }}"
          - --all
          - --raw
      register: pilot_identity_user_show
      changed_when: false
      failed_when: false
      environment:
        LC_ALL: C
      run_once: true
      tags: [identity, probe]

    - name: "Classify FreeIPA probe"
      ansible.builtin.set_fact:
        pilot_identity_probe_class: >-
          {% if pilot_identity_user_show.rc == 0 %}
          active_or_preserved
          {% elif 'not found' in
                  (pilot_identity_user_show.stderr | default('') | lower) %}
          not_found
          {% else %}
          unknown
          {% endif %}
      changed_when: false
      run_once: true
      tags: [identity, probe]

    - name: "Fail closed when FreeIPA history cannot be determined"
      ansible.builtin.assert:
        that:
          - pilot_identity_probe_class | trim != 'unknown'
        fail_msg: >-
          Unable to determine whether user {{ pilot_identity_name }} has
          ever entered the FreeIPA lifecycle. The probe failed with rc
          {{ pilot_identity_user_show.rc }}. Refusing to classify this
          user as never-applied.
      run_once: true
      tags: [identity, probe]

    - name: "Build machine-readable probe result"
      ansible.builtin.set_fact:
        pilot_identity_probe_result:
          schema_version: 1
          kind: user
          name: "{{ pilot_identity_name }}"
          ever_applied: >-
            {{ (pilot_identity_probe_class | trim) == 'active_or_preserved' }}
          freeipa_state: "{{ pilot_identity_probe_class | trim }}"
      changed_when: false
      run_once: true
      tags: [identity, probe]

    - name: "Write probe result on the Ansible controller"
      ansible.builtin.copy:
        dest: "{{ pilot_identity_probe_output }}"
        mode: "0600"
        content: "{{ pilot_identity_probe_result | to_nice_json }}\n"
      delegate_to: localhost
      become: false
      run_once: true
      tags: [identity, probe]

8.4 Playbook rules

The coding agent must not weaken these properties:

changed_when: false for all FreeIPA probe operations.

Unknown command failure is not “not found”.

Network failure is not “not found”.

Kerberos failure is not “not found”.

Permission failure is not “not found”.

Timeout is not “not found”.

No FreeIPA stdout containing user profile fields is persisted into the result JSON.

The result file is mode 0600.

The CLI removes the temporary result file after use.

9. FreeIPA group history marker playbook/tasks

Add a reusable task file:

playbooks/apply/tasks/freeipa-group-history-marker.yml

Required inputs:

pilot_group_history_name

The task file runs after admin kinit.

9.1 Marker calculation

- name: "Calculate deterministic Pilot group history marker"
  ansible.builtin.set_fact:
    pilot_group_history_marker: >-
      pilot-internal-history-g-{{
        pilot_group_history_name | hash('sha256')
      }}
    pilot_group_history_description: >-
      pilot.group-history/v1 name={{ pilot_group_history_name }}
  changed_when: false

9.2 Marker query

- name: "Inspect Pilot group history marker"
  ansible.builtin.command:
    argv:
      - ipa
      - group-show
      - "{{ pilot_group_history_marker }}"
      - --all
      - --raw
      - --no-members
  register: pilot_group_history_marker_show
  changed_when: false
  failed_when: false
  environment:
    LC_ALL: C

Classify:

rc == 0
    => marker exists

rc != 0 and stderr contains exact FreeIPA not-found condition
    => marker missing

anything else
    => unknown => fail closed

Do not treat a generic non-zero exit as missing.

9.3 Verify existing marker

If marker exists, verify that its raw output contains the exact expected description:

pilot.group-history/v1 name=<canonical-group-name>

If it does not match:

FAIL CLOSED

Reason:

deterministic marker-name collision;

manually repurposed object;

corrupted marker;

wrong hashing/canonicalization implementation.

9.4 Create missing marker

If the marker is missing:

- name: "Create durable Pilot group history marker"
  ansible.builtin.command:
    argv:
      - ipa
      - group-add
      - "{{ pilot_group_history_marker }}"
      - --nonposix
      - "--desc={{ pilot_group_history_description }}"
  register: pilot_group_history_marker_add
  changed_when: pilot_group_history_marker_add.rc == 0
  environment:
    LC_ALL: C

Creation failure must fail the play.

After creation, query the marker again and verify its description.

Do not assume successful command exit is sufficient without postcondition verification.

9.5 Present-group integration

For every canonical group whose target state is present:

ensure group
    -> verify group exists
    -> ensure history marker
    -> continue membership reconciliation

Marker creation happens only after the actual group exists so a failed group creation does not create a false “applied” marker.

9.6 Absent-group integration

For every canonical group whose target state is absent:

query actual group
    |
    +-- not found:
    |      no group-del
    |      keep any existing marker
    |
    +-- exists:
           ensure/verify marker
           ONLY THEN group-del

Never execute group-del if marker creation/verification fails.

10. FreeIPA group ever-applied probe playbook

Add:

playbooks/check/freeipa-identity-group-ever-applied.yml

It follows the same credential-loading and fail-closed conventions as the user probe.

Inputs:

freeipa_roster_file
pilot_identity_name
pilot_identity_probe_output
target_group              optional, default freeipa-server

10.1 Output contract

{
  "schema_version": 1,
  "kind": "group",
  "name": "team-platform",
  "ever_applied": true,
  "freeipa_state": "active_with_marker",
  "history_marker": "pilot-internal-history-g-..."
}

Allowed freeipa_state values:

active_with_marker
active_without_marker
historical_marker
not_found

Meaning:

active_with_marker:
  actual group exists
  marker exists and is valid
  ever_applied=true

active_without_marker:
  actual group exists
  marker missing
  ever_applied=true
  remove-group denied
  reconcile should backfill marker

historical_marker:
  actual group missing
  marker exists and is valid
  ever_applied=true

not_found:
  actual group missing
  marker missing
  ever_applied=false

An invalid marker or any unknown query error fails the playbook and produces no successful classification.

10.2 Proposed playbook skeleton

---
- name: Probe whether a roster group has ever entered the FreeIPA lifecycle
  hosts: "{{ target_group | default('freeipa-server') }}"
  become: false
  gather_facts: false

  vars:
    freeipa_roster: {}

  pre_tasks:
    - name: "Gate: group history probe input"
      ansible.builtin.assert:
        that:
          - freeipa_roster_file is defined
          - pilot_identity_name is defined
          - pilot_identity_name | string | trim | length > 0
          - pilot_identity_probe_output is defined
      run_once: true

    - name: "Load canonical roster"
      ansible.builtin.include_vars:
        file: "{{ freeipa_roster_file }}"
        name: freeipa_roster
      no_log: true
      run_once: true

    - name: "Normalize admin credentials"
      ansible.builtin.set_fact:
        ipa_domain: "{{ freeipa_domain | default('ipa.pilot.internal') }}"
        ipa_realm: >-
          {{ freeipa_realm |
             default((freeipa_domain | default('ipa.pilot.internal')) | upper) }}
        identity_admin_principal: >-
          {{ freeipa_roster.freeipa.admin.principal | default('admin') }}
        identity_admin_password: "{{ freeipa_roster.freeipa.admin.password }}"
        pilot_group_history_marker: >-
          pilot-internal-history-g-{{
            pilot_identity_name | hash('sha256')
          }}
        pilot_group_history_description: >-
          pilot.group-history/v1 name={{ pilot_identity_name }}
      no_log: true
      run_once: true

    - name: "Kinit admin"
      ansible.builtin.shell:
        cmd: |
          set -o pipefail
          printf %s "{{ identity_admin_password }}" |
            kinit "{{ identity_admin_principal }}@{{ ipa_realm }}"
        executable: /bin/bash
      changed_when: false
      no_log: true
      run_once: true

  tasks:
    - name: "Probe actual FreeIPA group"
      ansible.builtin.command:
        argv:
          - ipa
          - group-show
          - "{{ pilot_identity_name }}"
          - --all
          - --raw
          - --no-members
      register: pilot_actual_group_show
      changed_when: false
      failed_when: false
      environment:
        LC_ALL: C
      run_once: true

    - name: "Probe durable Pilot group history marker"
      ansible.builtin.command:
        argv:
          - ipa
          - group-show
          - "{{ pilot_group_history_marker }}"
          - --all
          - --raw
          - --no-members
      register: pilot_group_marker_show
      changed_when: false
      failed_when: false
      environment:
        LC_ALL: C
      run_once: true

    # Coding agent:
    # classify each query using exact known "not found" semantics.
    # Any other non-zero state must fail closed.

    - name: "Verify matching marker when present"
      ansible.builtin.assert:
        that:
          - >-
            pilot_group_marker_show.rc != 0 or
            pilot_group_history_description in
              (pilot_group_marker_show.stdout | default(''))
        fail_msg: >-
          Pilot group history marker exists but does not match the
          requested canonical group. Refusing to determine history.
      run_once: true

    # Build one of:
    # active_with_marker / active_without_marker /
    # historical_marker / not_found

    - name: "Write machine-readable group history result"
      ansible.builtin.copy:
        dest: "{{ pilot_identity_probe_output }}"
        mode: "0600"
        content: "{{ pilot_identity_probe_result | to_nice_json }}\n"
      delegate_to: localhost
      become: false
      run_once: true

The coding agent must finish the classification with explicit Ansible tasks instead of a shell script that swallows return codes.

10.3 Group probe safety rules

Existing actual group always means ever_applied=true, even if no marker exists yet.

Valid marker always means ever_applied=true, even if actual group is absent.

Actual missing + marker missing is the only successful false state.

Existing malformed marker is unknown/failure.

Query/auth/network error is unknown/failure.

No --force bypass.

11. freeipa-identity-apply.yml — user deletion behavior is unchanged

Current behavior:

- name: "Delete canonical users explicitly marked absent"
  ansible.builtin.command:
    argv: [ipa, user-del, "{{ item.name }}"]

Decision: this feature does NOT modify this task. state: absent continues to permanently delete the user via plain ipa user-del, exactly as today.

Rationale: adopting --preserve semantics for users was evaluated during spec review and explicitly rejected for this iteration. The blast radius of this feature is intentionally limited to:

roster-local mutation (remove-user / remove-group), and

new read-only FreeIPA probes (§8, §10).

It deliberately does not alter the live user-deprovisioning lifecycle.

Consequence (see §2.4/§2.5): the strict "ever applied, therefore never hard-removable" guarantee for users is fully provable only for roster entries that were never reconciled. Once a user is deprovisioned and permanently deleted, the roster tombstone (state: absent, rejected by remove-user per §16 Phase A) is the only remaining safeguard.

No real-FreeIPA repeated-preserve integration test is required by this feature, because Pilot never creates a preserved user. If a preserved user exists for any other reason (e.g. an operator manually ran ipa user-del --preserve outside Pilot), the probe in §8 must still detect it and remove-user must still refuse — see the revised "Preserved user" scenario in §22.5.

12. Go-side FreeIPA probe integration

Recommended new internal package boundary:

internal/freeipa/
  identity_probe.go
  identity_probe_test.go
  group_history.go
  group_history_test.go

Suggested API:

type UserHistoryState string

const (
    UserHistoryActiveOrPreserved UserHistoryState = "active_or_preserved"
    UserHistoryNotFound          UserHistoryState = "not_found"
)

type UserHistoryProbe struct {
    SchemaVersion int              `json:"schema_version"`
    Kind          string           `json:"kind"`
    Name          string           `json:"name"`
    EverApplied   bool             `json:"ever_applied"`
    FreeIPAState  UserHistoryState `json:"freeipa_state"`
}

type UserHistoryProbeOptions struct {
    Inventory         string
    RosterFile        string
    VaultPasswordFile string
}

func ProbeUserHistory(
    ctx context.Context,
    name string,
    opts UserHistoryProbeOptions,
) (UserHistoryProbe, error)



Add a parallel group API:

type GroupHistoryState string

const (
    GroupHistoryActiveWithMarker    GroupHistoryState = "active_with_marker"
    GroupHistoryActiveWithoutMarker GroupHistoryState = "active_without_marker"
    GroupHistoryMarkerOnly          GroupHistoryState = "historical_marker"
    GroupHistoryNotFound            GroupHistoryState = "not_found"
)

type GroupHistoryProbe struct {
    SchemaVersion int               `json:"schema_version"`
    Kind          string            `json:"kind"`
    Name          string            `json:"name"`
    EverApplied   bool              `json:"ever_applied"`
    FreeIPAState  GroupHistoryState `json:"freeipa_state"`
    HistoryMarker string            `json:"history_marker"`
}

func ProbeGroupHistory(
    ctx context.Context,
    name string,
    opts UserHistoryProbeOptions,
) (GroupHistoryProbe, error)

Parser validation must reject impossible combinations.

Examples:

active_with_marker + ever_applied=false => reject
active_without_marker + ever_applied=false => reject
historical_marker + ever_applied=false => reject
not_found + ever_applied=true => reject
marker hash does not match returned name => reject

Requirements:

Use the corresponding user/group probe playbook.

Create probe output with os.CreateTemp.

Mode must be 0600.

Remove it with defer os.Remove(...).

Parse strict JSON.

Reject unknown schema_version.

Reject mismatched kind.

Reject mismatched returned name.

Reject impossible combinations such as:

ever_applied=true + freeipa_state=not_found

ever_applied=false + freeipa_state=active_or_preserved

If Ansible exits non-zero, return an error.

Do not reinterpret Ansible failure as “not found”.

13. Roster inbound-reference scanner

Add:

internal/inventory/roster_references.go

Suggested types:

type RosterReferenceCascade string

const (
    RosterReferenceCascadeRemovable RosterReferenceCascade = "removable"
    RosterReferenceCascadeBlocked   RosterReferenceCascade = "blocked"
)

type RosterReference struct {
    Kind        string
    Path        string
    Cascade     RosterReferenceCascade
    Explanation string
}

func RosterUserReferences(
    root map[string]any,
    username string,
) []RosterReference

func RosterGroupReferences(
    root map[string]any,
    groupname string,
) []RosterReference

Sort output deterministically by Path.

13.1 User references

At minimum scan:

groups[].membership.users
hbac.rules[].subjects.users
sudo.rules[].subjects.users
netgroups[].membership.users

These are normally removable list references, subject to final full-roster validation.

13.2 Group references

At minimum scan all canonical roster locations that semantically refer to FreeIPA groups:

groups[].membership.groups
hbac.rules[].subjects.groups
sudo.rules[].subjects.groups
sudo.rules[].run_as.groups
netgroups[].membership.groups

nfs.servers[].shares[].ownership.group
nfs.servers[].shares[].acl.access.named_groups[].name
nfs.servers[].shares[].acl.default.named_groups[].name

If current schema or playbooks contain additional group-bearing fields, include them. The coding agent must search the current repository before finalizing the scanner.

13.3 Cascadeable versus blocking group references

List references can be removed when --cascade-references is set:

groups[].membership.groups
hbac.rules[].subjects.groups
sudo.rules[].subjects.groups
sudo.rules[].run_as.groups
netgroups[].membership.groups
nfs...acl...named_groups[]

They are still subject to complete validation afterward.

Required scalar references are not cascadeable.

At minimum:

nfs.servers[].shares[].ownership.group

must be classified:

CascadeBlocked

The user must explicitly assign a replacement owning group before remove-group.

Do not delete the scalar field and do not guess another group.

13.4 Validator coverage

The base validator must reject dangling user/group references independently of the remove commands.

The previously identified sudo user-reference gap must be fixed.

Also verify that all group-bearing paths above are validated against the canonical group set with the correct required category where applicable.

Examples:

HBAC subject group -> category access
sudo subject group -> category role
NFS ownership/ACL group -> category filesystem
nested group -> existing canonical group
netgroup group member -> existing canonical group

If current validation does not cover one of these paths, add the missing rule as part of this feature.

14. Roster simulation API

Add:

type RemoveRosterUserOptions struct {
    CascadeReferences bool
}

type RemoveRosterUserSimulation struct {
    Found              bool
    References         []RosterReference
    RemovedReferences  []RosterReference
    Violations         []RosterViolation
}

Suggested functions:

func SimulateRemoveRosterUser(
    path string,
    name string,
    opts RemoveRosterUserOptions,
) (RemoveRosterUserSimulation, error)

func SimulateRemoveRosterGroup(
    path string,
    name string,
    opts RemoveRosterGroupOptions,
) (RemoveRosterGroupSimulation, error)

Both simulations follow the same structural behavior.

Behavior:

Read roster.

Reject encrypted input through the existing encrypted-roster path unless the caller has already provided decrypted bytes through an existing sanctioned abstraction.

Reject ambiguous duplicate username.

If user not found:

Found=false

no mutation.

Read target user state.

If state is absent, return a dedicated lifecycle error.

Collect inbound references.

If references exist and cascade is false:

return them;

do not create a valid mutation candidate.

If cascade is true:

remove only references to this user;

remove the user entry;

validate the whole candidate using ValidateRoster.

Return all violations.

15. Roster mutation API

Add:

func RemoveRosterUser(
    path string,
    name string,
    opts RemoveRosterUserOptions,
) error

func RemoveRosterGroup(
    path string,
    name string,
    opts RemoveRosterGroupOptions,
) error

Rules:

Must not perform the FreeIPA probe itself.

Must assume the caller has already passed the historical guard.

Must still enforce structural safety:

exactly one target resource matches;

target resource is not state: absent;

reference behavior matches opts;

final roster validates.

Use yaml.Node surgery.

Do not full-remarshal the roster as a fixed Go struct.

Preserve unrelated top-level sections.

Remove the exact sequence element.

With cascade, edit the exact referring sequences.

Use atomic file replacement if the existing roster mutation layer can support it.

Use the roster mutation lock.

The command must call:

SimulateRemoveRosterUser

before:

RemoveRosterUser

matching the existing Simulate* then mutate convention.

16. Exact command algorithm

The Cobra command must execute in this order.

Phase A — local read-only checks

Resolve arguments and flags.

Validate inventory path exists.

Validate roster path exists.

Load/inspect the roster using sanctioned vault handling.

Require current supported roster schema, or run the same current-schema path already used by roster-edit/migrate.

Find exactly one target user/group.

Reject duplicate/ambiguous names.

Reject target state: absent.

Collect inbound references.

If references exist and --cascade-references is absent:

print references;

exit non-zero;

do not contact FreeIPA unnecessarily if the command has already failed locally.

Phase B — authoritative FreeIPA historical probe

Run the resource-specific probe:

user: playbooks/check/freeipa-identity-user-ever-applied.yml

group: playbooks/check/freeipa-identity-group-ever-applied.yml

Parse its temporary JSON output.

If the playbook fails:

abort;

no mutation.

If ever_applied=true:

abort;

no mutation.

Only ever_applied=false + freeipa_state=not_found may continue for either resource kind.

Phase C — candidate validation

Call SimulateRemoveRosterUser or SimulateRemoveRosterGroup.

Require:

found;

zero final violations.

If --dry-run:

print what would be removed;

exit 0;

no mutation.

Phase D — mutation

Acquire the roster mutation lock.

Re-read/revalidate enough state under lock to avoid acting on a stale local roster.

Apply RemoveRosterUser or RemoveRosterGroup.

Validate the written result.

Release lock.

Print a concise success report.

TOCTOU rule

The FreeIPA probe occurs before local mutation, so a concurrent actor could theoretically create a same-named FreeIPA user between the probe and the local write.

To fail closed, the implementation should perform a second FreeIPA probe immediately before the final write if the interval contains any operation that can materially delay execution.

Preferred sequence:

local simulation
FreeIPA probe #1
acquire roster lock
local re-read/simulation
FreeIPA probe #2
write
release lock

Both probes must report not_found.

Do not hold the roster file lock while a potentially long Ansible run if doing so would unnecessarily block unrelated roster work; if that is a concern, use a local revision/hash compare after probe #2 and fail if the roster changed.

17. Encrypted roster behavior

Encrypted roster handling must be first-class.

The command must support the same workflow as current roster migration:

pilot roster remove-user ... \
  --vault-password-file ~/.vault/vault-pass

Requirements:

Never write decrypted roster bytes to a predictable filename.

Temporary plaintext files, if unavoidable, must:

be created with 0600;

be removed with defer;

not be placed inside the repo/workspace unless an existing secure vault helper already does so.

Re-encrypt using the existing sanctioned vault implementation.

Never print:

admin password;

initial user password;

roster plaintext;

decrypted temporary path when it would reveal sensitive layout unnecessarily.

Prefer reusing the encrypted-roster mutation machinery already established by pilot roster migrate instead of inventing a second vault implementation.

18. --cascade-references rules

Cascade is intentionally narrow.

Allowed removals:

groups[].membership.users == username
hbac.rules[].subjects.users == username
sudo.rules[].subjects.users == username
netgroups[].membership.users == username

Not allowed:

deleting a group because its membership becomes empty;

deleting an HBAC rule because its subjects become empty;

deleting a sudo rule because its subjects become empty;

deleting a netgroup because its membership becomes empty;

rewriting unrelated rules to make validation pass.

If cascade makes another resource structurally invalid, the command must fail with validator output and make no changes.

Example:

hbac:
  rules:
    - name: ssh-one-user
      subjects:
        users: [typo-user]
        groups: []

Removing typo-user would leave the HBAC rule with zero subjects.

Therefore:

pilot roster remove-user ... typo-user --cascade-references

must fail and tell the user that the remaining HBAC rule is invalid.

It must not silently delete the HBAC rule.

18.1 Group-specific cascade rule

For remove-group, --cascade-references removes only references marked CascadeRemovable.

Example removable references:

groups[team-parent].membership.groups
hbac.rules[ssh-platform].subjects.groups
sudo.rules[sudo-platform].subjects.groups
netgroups[ng-platform].membership.groups
nfs...acl.access.named_groups[]
nfs...acl.default.named_groups[]

Example blocking reference:

nfs.servers[nfs1].shares[project-alpha].ownership.group

A blocking reference aborts the command even when --cascade-references is supplied.

The command must print the path and require an explicit replacement edit.

19. TUI behavior

Do not add roster hard-delete to pilot edit in the first implementation.

Reason:

the current roster editor intentionally excludes declarative delete;

a remote FreeIPA historical probe introduces a different UX and failure model;

the CLI command is easier to audit and automate safely.

A later TUI integration may call the same command/service layer, but must not reimplement the safety logic.

20. Structured-action / MCP behavior

If the project exposes roster mutations through structured actions, add a semantic action only after the CLI/core implementation is complete.

Suggested actions:

remove_roster_user
remove_roster_group

Input:

{
  "name": "typo-user",
  "cascade_references": false
}

The action must route through the exact same:

FreeIPA probe
+
simulation
+
mutation

service path.

Do not add an MCP-only bypass.

21. Error taxonomy

Add typed/sentinel errors where useful.

Suggested errors:

var ErrRosterUserAlreadyApplied = errors.New(
    "roster user has entered the FreeIPA lifecycle",
)

var ErrRosterGroupAlreadyApplied = errors.New(
    "roster group has entered the FreeIPA lifecycle",
)

var ErrRosterUserAbsentLifecycle = errors.New(
    "roster user is already in state: absent lifecycle",
)

var ErrRosterUserReferenced = errors.New(
    "roster user still has inbound references",
)

var ErrFreeIPAHistoryUnknown = errors.New(
    "unable to determine FreeIPA user history",
)

User-facing command errors should include the username and remediation.

22. Test plan

20.1 Inventory unit tests

Add tests for:

remove unreferenced user;

remove first/middle/last sequence item;

preserve other user entries;

preserve comments/unrelated sections according to current mutation guarantees;

missing user;

duplicate/ambiguous user;

state: absent rejected;

group membership reference detected;

HBAC subject reference detected;

sudo subject reference detected;

netgroup reference detected;

cascade removes every direct user reference;

cascade that invalidates HBAC fails;

cascade that invalidates sudo fails;

final candidate always runs full validation.

20.2 Validator regression test

Add a roster with:

sudo:
  rules:
    - name: sudo-bad-user
      subjects:
        users: [does-not-exist]

The validator must reject it.

20.3 Probe parser tests

Test JSON:

active/preserved + true;

not_found + false;

mismatched name;

wrong kind;

unsupported schema;

impossible boolean/state combination;

missing result file;

malformed JSON;

Ansible non-zero exit.

20.4 CLI tests

Test:

remove-user --dry-run
remove-user success
remove-user referenced without cascade
remove-user referenced with cascade
remove-user applied user denied
remove-user state: absent denied
probe failure denied
encrypted roster
lock contention

20.5 Real FreeIPA tests

Mandatory scenarios:

Never-applied user

Put pilot-never-applied into roster.

Confirm ipa user-show pilot-never-applied reports not found.

Run pilot roster remove-user.

Confirm roster user is removed.

Confirm no FreeIPA mutation occurred.

Applied active user

Reconcile pilot-applied.

Confirm ipa user-show pilot-applied succeeds.

Run pilot roster remove-user.

Command must fail.

Roster bytes must remain unchanged.

Preserved user (created out-of-band, not by Pilot)

Create pilot-preserved in FreeIPA and manually run ipa user-del pilot-preserved --preserve directly (not through Pilot, since Pilot no longer creates preserved users — §11).

Confirm ipa user-show pilot-preserved still succeeds and reports preserved.

Run pilot roster remove-user against a roster entry for pilot-preserved.

Command must fail.

Roster bytes must remain unchanged.

(The "repeated absent reconcile / preserve idempotency" scenario is removed: not applicable, since this feature keeps state: absent as a permanent ipa user-del — §11.)

FreeIPA unavailable

Make target unreachable or use an invalid Kerberos credential.

Run pilot roster remove-user.

Command must fail closed.

Roster bytes must remain unchanged.

22.6 Group history-marker unit tests

Test:

deterministic SHA-256 marker name;

marker description matches exact group;

valid marker;

missing marker;

malformed marker description;

active group without marker => ever_applied=true;

marker without active group => ever_applied=true;

both missing => ever_applied=false;

query error => fail closed.

22.7 remove-group CLI tests

Test:

remove-group --dry-run
remove-group never-applied success
remove-group active group denied
remove-group historical marker denied
remove-group state: absent denied
remove-group nested membership ref
remove-group HBAC ref
remove-group sudo ref
remove-group netgroup ref
remove-group NFS ACL ref
remove-group NFS ownership.group always blocked
remove-group cascade producing invalid roster denied
remove-group encrypted roster

22.8 Real FreeIPA group tests

Mandatory:

Never-applied group

Put team-never-applied in the roster.

Confirm actual group is absent.

Confirm deterministic history marker is absent.

Run pilot roster remove-group.

Confirm roster group is hard-removed.

Confirm no FreeIPA mutation occurred.

Applied active group

Reconcile team-applied.

Confirm actual group exists.

Confirm history marker exists and is non-POSIX.

Run pilot roster remove-group.

Command must fail.

Roster bytes remain unchanged.

Deleted applied group

Reconcile team-deleted.

Confirm group + marker exist.

Change roster group to state: absent.

Reconcile.

Confirm actual group is gone.

Confirm marker remains.

Run pilot roster remove-group.

Command must fail.

Roster state: absent tombstone remains.

Marker creation failure protects deletion

Arrange a marker-name collision or simulated marker validation failure.

Keep the actual target group present.

Reconcile state: absent.

The playbook must fail before ipa group-del.

Confirm actual group still exists.

23. Acceptance criteria

AC1 — New commands exist

pilot roster remove-user <roster-file> <username>
pilot roster remove-group <roster-file> <groupname>

AC2 — Never-applied user can be removed

A roster user missing from active/preserved FreeIPA can be hard-removed when the local candidate is valid.

AC3 — Active user can never be hard-removed

If ipa user-show succeeds, the command fails without changing the roster.

AC4 — Preserved user can never be hard-removed

If ipa user-show resolves a preserved user, the command fails without changing the roster.

AC5 — Unknown FreeIPA state fails closed

Auth/network/query errors never become “not found”.

AC6 — state: absent is never hard-removed

The command rejects a roster user already in declarative deprovision state.

AC7 — User deprovision behavior is intentionally unchanged

freeipa-identity-apply.yml continues to permanently delete canonical users marked absent via plain ipa user-del; this is a documented, deliberate scope decision (§11), not an oversight.

AC8 — (removed)

No longer applicable: this criterion existed only to prove idempotency of preserve semantics, which this feature does not implement.

AC9 — References are safe

Without cascade, inbound references block removal.

With cascade, only direct username references are removed.

AC10 — Cascade cannot delete dependent resources

The command never silently removes groups/HBAC/sudo/netgroups to make the roster valid.

AC11 — Full roster validation gates every write

No invalid candidate is persisted.

AC12 — Encrypted roster is supported safely

No secret/plaintext leakage.

AC13 — No force bypass

No command flag can override the ever-applied guard.

AC14 — remove-group exists and is safe

pilot roster remove-group hard-removes only a group proven never-applied.

AC15 — Group history survives remote deletion

Every applied group receives a deterministic non-POSIX FreeIPA history marker, and the marker remains after state: absent deletes the real group.

AC16 — Group marker gates deletion

An active group or valid marker permanently blocks remove-group.

AC17 — Group deletion cannot outrun marker creation

ipa group-del is never executed for a present actual group until its history marker has been created and verified.

AC18 — Required group references cannot be cascaded

nfs...ownership.group and any equivalent required scalar reference block hard removal until explicitly reassigned.

AC19 — Real FreeIPA evidence exists

The integration suite proves:

remove-user rejects an active user, and rejects a user found in a preserved state (created out-of-band — Pilot itself does not create preserved users; see §11).

The same integration suite also proves:

group present -> history marker -> state: absent -> actual group deleted -> marker retained

and proves remove-group rejects both active groups and marker-only historical groups.

24. Files expected to change

Minimum expected set:

cmd/pilot/cmd/roster_remove_user.go
cmd/pilot/cmd/roster_remove_user_test.go
cmd/pilot/cmd/roster_remove_group.go
cmd/pilot/cmd/roster_remove_group_test.go

internal/inventory/roster.go
internal/inventory/roster_references.go
internal/inventory/roster_remove_test.go
internal/inventory/roster_validate.go
internal/inventory/roster_validate_test.go

internal/freeipa/identity_probe.go
internal/freeipa/identity_probe_test.go
internal/freeipa/group_history.go
internal/freeipa/group_history_test.go

playbooks/check/freeipa-identity-user-ever-applied.yml
playbooks/check/freeipa-identity-group-ever-applied.yml
playbooks/apply/tasks/freeipa-group-history-marker.yml
playbooks/apply/freeipa-identity-apply.yml (group history-marker integration only — user deletion path is unchanged, §11)

docs/verification/freeipa-identity.md

If encrypted roster mutation requires reusable extraction, add a focused helper instead of duplicating migration code.

25. Implementation order

Implement in this order:

Audit and fix all user/group reference validation gaps.

Add combined roster inbound-reference scanner with cascadeable/blocking classifications.

Add pure in-memory user/group removal simulations.

Add user/group YAML mutation primitives.

Add FreeIPA user read-only history probe.

Add deterministic FreeIPA group history-marker task.

Add FreeIPA group read-only history probe.

Add Go probe wrappers/parsers.

(User state: absent is intentionally NOT modified — preserve semantics were evaluated and rejected; see §11.)

Integrate group-marker creation into present-group reconciliation.

Gate group state: absent deletion on verified marker creation.

Add the real-FreeIPA group-marker lifecycle test, plus a lighter preserved-user detection test using an out-of-band preserved user (§22.5).

Add Cobra remove-user and remove-group.

Add encrypted-roster paths.

Add CLI/integration tests.

Update verification docs.

Only then consider structured-action/MCP exposure.

The safety-critical group-marker lifecycle change must not be shipped without the real FreeIPA group-marker test (§22.8).

26. Explicit design decisions

Decision A

remove-user means:

remove a never-applied local definition

It does not mean:

delete user from FreeIPA

Decision B

FreeIPA active + preserved user namespace is the historical registry for the new invariant.

Decision C (revised)

state: absent for users continues to use permanent deletion (ipa user-del, no --preserve), unchanged from current behavior. Adopting preserve semantics for users was evaluated and explicitly rejected for this iteration; see §2.4/§2.5/§11.

Decision D

Applied/preserved users remain in the roster forever unless a future explicit archival design is approved.

Decision E

Groups use a deterministic empty non-POSIX FreeIPA history-marker group because FreeIPA has no native preserved-group lifecycle.

Decision F

state: absent may delete the actual FreeIPA group only after a valid history marker exists.

Decision G

An applied group's marker is permanent from Pilot's perspective; Pilot never deletes it.

Decision H

No local Pilot history, run DB, receipt DB, or missing receipt is sufficient to authorize hard removal.

Decision I

No --force escape hatch.

27. External behavior summary

The resulting lifecycle should be:

                    add roster user
                          |
                          v
                 +------------------+
                 | local definition |
                 | never applied    |
                 +------------------+
                    |            |
       remove-user  |            | reconcile
         allowed    |            v
                    |     +----------------+
                    +---->| active FreeIPA |
                          | user           |
                          +----------------+
                                  |
                    state: disabled / absent
                                  |
                                  v
                         +-------------------+
                         | user permanently  |
                         | deleted (unchanged|
                         | behavior)         |
                         +-------------------+
                                  |
                                  v
                     remove-user ALWAYS DENIED
                     (enforced by the local roster
                      tombstone, state: absent —
                      not by durable FreeIPA history,
                      since preserve was not adopted)

Once a user is permanently deleted, FreeIPA can no longer prove that user's history. The roster tombstone row is the only remaining safeguard, and it depends on that row never being purged (purge-user is out of scope, §3.2).

Group lifecycle:

                    add roster group
                          |
                          v
                 +------------------+
                 | local definition |
                 | never applied    |
                 +------------------+
                    |            |
       remove-group |            | reconcile
         allowed    |            v
                    |     +----------------+
                    +---->| active FreeIPA |
                          | group          |
                          +----------------+
                                  |
                                  v
                         create permanent
                         history marker
                                  |
                         state: absent
                                  |
                                  v
                    +--------------------------+
                    | actual group deleted     |
                    | history marker retained  |
                    +--------------------------+
                                  |
                                  v
                     remove-group ALWAYS DENIED

28. Reference notes for the coding agent

Repository behavior inspected:

internal/inventory/roster.go

existing SimulateAdd/SetRosterUser

existing Append/SetRosterUser

YAML node mutation pattern

internal/inventory/roster_validate.go

canonical roster validation

user/group/HBAC/sudo checks

internal/inventory/roster_netgroup.go

netgroup user/group reference validation

internal/inventory/roster_lock.go

mutation flock

cmd/pilot/cmd/roster_lint.go

current pilot roster command root

cmd/pilot/cmd/roster_migrate.go

encrypted roster/vault-password CLI precedent

cmd/pilot/cmd/edit_tui_roster.go

delete intentionally excluded from current roster editor

playbooks/apply/freeipa-identity-apply.yml

current canonical user/group reconciliation

current user permanent deletion must be changed

FreeIPA behavior relied upon:

FreeIPA supports ipa user-del <name> --preserve.

Preserved users are disabled and kept in the deleted-user container.

ipa user-show <name> can retrieve active or preserved/deleted users.

FreeIPA supports user-find --preserved=true.

A preserved user can later be permanently deleted by FreeIPA administrators — not directly relevant here, since this feature does not adopt preserve semantics for users (§11).

FreeIPA group deletion does not have the equivalent preserved-user lifecycle; deleting group-dependent delegations can be irreversible.

FreeIPA group_add supports nonposix, so history markers can use a supported API object without allocating POSIX GIDs.

FreeIPA recommends supported IPA CLI/API mutation rather than arbitrary custom LDAP writes.

Primary official references:

FreeIPA User Life-Cycle Management

https://www.freeipa.org/page/V4/User_Life-Cycle_Management.html

FreeIPA user management API

https://freeipa.readthedocs.io/en/latest/api/user_management.html

ansible-freeipa user plugin documentation

https://www.freeipa.org/ansible-freeipa.github.io/documentation/plugins/user.html

FreeIPA group_add API

https://freeipa.readthedocs.io/en/latest/api/group_add.html

FreeIPA group management examples

https://freeipa.readthedocs.io/en/latest/api/group_management.html

FreeIPA LDAP guidance

https://www.freeipa.org/page/HowTo/LDAP

29. Definition of done

The work is complete only when all of the following are true:

[ ] pilot roster remove-user exists
[ ] pilot roster remove-group exists
[ ] active user blocks hard removal
[ ] preserved user blocks hard removal
[ ] unknown FreeIPA state blocks hard removal
[ ] state: absent blocks hard removal
[ ] state: absent for users remains a permanent ipa user-del (unchanged; preserve intentionally not adopted, §11)
[ ] inbound references are reported
[ ] cascade removes only explicitly cascadeable user/group references
[ ] invalid cascades are rejected
[ ] sudo dangling-user validation is fixed
[ ] encrypted roster works
[ ] no --force bypass exists
[ ] active FreeIPA group blocks hard removal
[ ] historical group marker blocks hard removal
[ ] every applied present group receives a history marker
[ ] group state: absent cannot delete an existing group before marker verification
[ ] history marker remains after group deletion
[ ] NFS ownership.group blocks cascade until explicitly reassigned
[ ] unit tests pass
[ ] real FreeIPA integration tests pass
[ ] go test ./... passes
[ ] go test -race on touched Go packages passes
[ ] go vet ./... passes
[ ] gofmt is clean
[ ] Ansible syntax-check passes
[ ] verification documentation is updated
