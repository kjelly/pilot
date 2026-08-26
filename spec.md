Pilot HBAC Authorization Simplification Specification

Status: Implementation specification
Target repository: kjelly/pilot
Baseline: main at 521366e899561f7e38edc012fc88339742382468
Date: 2026-08-21
Audience: Coding agent / maintainer implementing the change

1. Executive decision

Pilot SHALL simplify its FreeIPA HBAC authoring model so that an HBAC rule can directly reference:

roster users;

team-* groups;

role-* groups;

legacy access-* groups for backward compatibility only;

direct enrolled host FQDNs;

hostgroups;

PAM services.

category: access SHALL no longer be required to author HBAC access.

Sanctioned Pilot authoring surfaces SHALL stop creating new access-* groups:

pilot edit;

structured --actions;

MCP edit tools;

examples;

agent authoring guidance.

Existing rosters containing category: access SHALL continue to validate and reconcile. This delivery SHALL not bump the roster schema version and SHALL not automatically delete, rename, or convert existing FreeIPA access-* groups.

The target authorization model is:

Subjects                                  Targets

User --------------------┐          ┌---- Host
                         │          │
Team --------------------┼-> HBAC <-┼---- Hostgroup
                         │          │
Role --------------------┘          │
                                    └---- hostcat: all

Role ---------------------------> sudo
Filesystem group ---------------> POSIX/NFS only

The resulting semantics are:

team-*: organizational identity set; may be referenced directly by HBAC.

role-*: reusable authorization/principal set; may be referenced by HBAC and sudo.

data-*: filesystem/POSIX/NFS authorization only; MUST NOT be accepted as an HBAC subject group.

access-*: deprecated compatibility group; existing declarations remain valid but sanctioned tooling MUST NOT create new ones.

direct HBAC users/hosts: first-class supported subjects/targets, useful for one-off or exception access.

2. Why this change exists

The current authoring model commonly creates two names for effectively the same login intent:

access-webhosts-ssh
        |
        v
webhosts-ssh-access (HBAC rule)

Typical current roster shape:

groups:
  - name: team-developers
    category: team
    membership:
      users: [alice, bob]
      groups: []

  - name: access-webhosts-ssh
    category: access
    membership:
      users: []
      groups: [team-developers]

hbac:
  rules:
    - name: webhosts-ssh-access
      subjects:
        users: []
        groups: [access-webhosts-ssh]
      targets:
        hosts: []
        hostgroups: [webhosts]
      services: [sshd]

The access-* group carries only the subject membership set. The actual authorization decision is the HBAC rule because only the HBAC rule defines all of:

who;

where;

which PAM service;

enabled/disabled state.

Pilot's backend already models HBAC generically:

subjects:
  users: [...]
  groups: [...]

targets:
  hosts: [...]
  hostgroups: [...]

The effective-access resolver also expands arbitrary referenced group membership and merges direct users/hosts. The main restriction is currently imposed by validator/UI policy, not by FreeIPA or Pilot's underlying reconciler.

The desired normal case therefore becomes:

groups:
  - name: team-developers
    category: team
    membership:
      users: [alice, bob]
      groups: []

hbac:
  rules:
    - name: webhosts-ssh-access
      subjects:
        users: []
        groups: [team-developers]
      targets:
        hosts: []
        hostgroups: [webhosts]
      services: [sshd]

A reusable operational role can serve both HBAC and sudo:

groups:
  - name: role-production-operator
    category: role
    membership:
      users: [contractor01]
      groups: [team-sre]

hbac:
  rules:
    - name: production-ssh
      subjects:
        users: []
        groups: [role-production-operator]
      targets:
        hosts: []
        hostgroups: [production]
      services: [sshd]

sudo:
  rules:
    - name: production-administration
      subjects:
        users: []
        groups: [role-production-operator]
      targets:
        hosts: []
        hostgroups: [production]
      allow:
        command_groups: [production-admin]
        commands: []

A one-off exception can be expressed without creating a wrapper group:

hbac:
  rules:
    - name: vendor-db-maintenance
      subjects:
        users: [vendor01]
        groups: []
      targets:
        hosts: [db-special.ipa.pilot.internal]
        hostgroups: []
      services: [sshd]

3. Current code facts that the implementation MUST preserve

The implementation SHALL work with the code structure present at the baseline commit.

3.1 Roster schema version

Current code defines:

RosterSchemaV1 = 1
RosterSchemaV2 = 2
CurrentRosterSchemaVersion = RosterSchemaV2

This change MUST NOT introduce RosterSchemaV3.

Do not modify migration behavior solely for this feature.

In particular, do not change:

CurrentRosterSchemaVersion;

the v1 -> v2 automatic migration contract;

encrypted roster migration behavior;

semantic fingerprint guarantees.

3.2 Existing backend capability

The existing model already supports:

hbac.rules[].subjects.users
hbac.rules[].subjects.groups
hbac.rules[].targets.hosts
hbac.rules[].targets.hostgroups

The Ansible reconciler already has direct user/group and host/hostgroup add/remove operations.

The effective HBAC resolver already:

adds direct subjects.users;

recursively expands subjects.groups;

adds direct targets.hosts;

recursively expands targets.hostgroups.

Do not replace that resolver with a second authorization engine.

3.3 Current UI restriction

At baseline:

HBAC creation selects only access groups;

HBAC creation selects only hostgroups;

created rules explicitly set subjects.users: [];

created rules explicitly set targets.hosts: [];

editing targets.hostgroups currently clears targets.hosts.

The last behavior is a data-loss bug once direct hosts are exposed and MUST be fixed.

3.4 Current structured action restriction

At baseline:

create_hbac_rule
  optional: groups, hostgroups, services

set_hbac_groups
set_hbac_targets
set_hbac_services

editAction.Users already exists.

A plural direct-host field does not exist yet; the singular Host field is already used for inventory-host actions and MUST NOT be repurposed.

4. Goals

This delivery MUST accomplish all of the following.

A new HBAC rule can be authored with any valid non-empty combination of:

direct users;

allowed subject groups;

direct hosts;

hostgroups;

services.

HBAC subject groups accept:

team;

role;

legacy access.

HBAC subject groups reject:

filesystem;

unknown group names.

New access groups cannot be created through sanctioned Pilot authoring surfaces.

Existing access groups:

remain valid;

remain editable as existing group objects;

remain reconciled by Ansible;

remain valid HBAC subject references;

generate a deprecation notice/warning in lint output.

Direct HBAC users are editable from the TUI and structured automation.

Direct HBAC hosts are editable from the TUI and structured automation.

Editing one HBAC relationship field MUST preserve all sibling relationship fields.

Existing v1/v2 rosters continue working without migration.

pilot_edit_inspect / MCP roster resources continue exposing the full non-secret HBAC graph and effective access.

5. Non-goals

This delivery MUST NOT do any of the following.

5.1 No hard deletion of access groups

Do not automatically:

rename access-* to role-*;

delete access-* from the roster;

emit state: absent;

delete live FreeIPA groups;

flatten access-group membership into static direct-user lists;

rewrite an existing access group into another category.

Reason: an access group is a real FreeIPA group and may be referenced outside HBAC, including nested group membership, netgroups, or systems not represented in the roster. Automatic transformation cannot prove that deletion or rename is safe.

5.2 No schema v3

Do not introduce a schema version only to express deprecation.

The current schema can safely become less restrictive for HBAC group categories while remaining backward compatible.

5.3 No host enrollment from HBAC editor

targets.hosts means an already enrolled FreeIPA host FQDN.

The HBAC editor MUST NOT:

create a FreeIPA host;

run enrollment;

change DNS;

manage host principals.

5.4 No user creation from HBAC editor

The HBAC editor selects existing roster users, plus the built-in FreeIPA admin principal where currently supported.

Identity lifecycle remains in the user editor.

5.5 No filesystem group reuse for login

data-* groups SHALL remain a distinct privilege domain.

Do not make HBAC accept filesystem groups for convenience.

6. Group-category policy

6.1 Active authoring categories

Sanctioned creation surfaces SHALL expose exactly:

team
filesystem
role

Corresponding prefixes remain:

team       -> team-
filesystem -> data-
role       -> role-

6.2 Legacy compatibility category

access remains valid only for backward compatibility:

access -> access-

Global roster validation SHALL continue accepting existing category: access.

This is intentional.

The validator cannot reliably distinguish "legacy object already present" from "new hand-authored object". Preventing new creation belongs to Pilot authoring surfaces, while lint reports the deprecation.

6.3 HBAC subject-group policy

Implement one canonical policy function/source of truth equivalent to:

HBAC-allowed:
  team
  role
  access (legacy)

HBAC-forbidden:
  filesystem

Do not duplicate this policy independently in:

Go validator;

TUI;

structured actions;

Ansible gate;

without a test proving synchronization.

Where practical, centralize Go-side category policy in internal/inventory.

Suggested API shape; exact names may vary:

func GroupCategoryPrefix(category string) (string, bool)
func IsCreatableGroupCategory(category string) bool
func IsHBACSubjectGroupCategory(category string) bool
func IsSudoSubjectGroupCategory(category string) bool
func IsDeprecatedGroupCategory(category string) bool

Required semantics:

IsCreatableGroupCategory:
  team=true
  filesystem=true
  role=true
  access=false

IsHBACSubjectGroupCategory:
  team=true
  role=true
  access=true
  filesystem=false

IsSudoSubjectGroupCategory:
  role=true
  all others=false

IsDeprecatedGroupCategory:
  access=true

The existing access group must still pass structural validation.

7. Go roster validation changes

Primary file:

internal/inventory/roster_validate.go

7.1 Group validation

Keep access in the structural category/prefix allowlist so legacy rosters validate.

Do not remove:

access -> access-

from compatibility validation.

7.2 HBAC group validation

Replace the current effective rule:

subjects.groups must be category: access

with:

subjects.groups must be category: team, role, or legacy access

Expected test cases:

team-*         PASS
role-*         PASS
access-*       PASS + deprecation warning at lint layer
data-*         FAIL
unknown group  FAIL

7.3 HBAC users

Preserve the current rule:

subjects.users must reference a declared roster user or "admin"

No weakening of user reference validation.

7.4 HBAC targets

Preserve:

hostcat: all

as mutually exclusive with explicit:

hosts
hostgroups

A rule without hostcat: all MUST have at least one direct host or hostgroup.

7.5 Direct-host authoring validation

Because direct host targets will become user-facing, sanctioned authoring SHOULD reject obviously invalid direct host strings before writing.

Use the same FQDN-shaped expectation already used elsewhere for FreeIPA hosts.

Do not make a new direct-host roster reference rule requiring the target to be present in top-level hosts:. Pilot already allows enrolled host FQDNs that are not roster-declared in hostgroup membership, and HBAC direct-host semantics should remain consistent with that model.

Recommended behavior:

TUI/action input:
  require non-empty FQDN-shaped values
  trim whitespace
  deduplicate
  sort deterministically

global legacy roster validation:
  do not introduce a breaking "must exist in roster.hosts" constraint

8. Lint deprecation reporting

Primary file:

cmd/pilot/cmd/roster_lint.go

Add a non-fatal deprecation report for every category: access group.

Example output after the existing successful result:

ok: schema v2; no issues found
warning: group "access-webhosts-ssh" uses deprecated category "access"; new HBAC policies should reference team-/role- groups or direct users instead

Requirements:

exit status remains success when there are only deprecation warnings;

warnings MUST NOT be returned as RosterViolation;

invalid rosters still fail exactly as before;

--upgrade remains about schema migration only;

do not imply that pilot roster migrate removes access groups;

warning order is deterministic.

Prefer an inventory helper returning structured warnings, e.g.:

type RosterWarning struct {
    Rule   string
    Detail string
}

or a narrower deprecation helper if adding a generic warning framework would be excessive.

At minimum test:

no warning without access groups;

one warning per access group;

multiple warning order deterministic;

warnings do not change exit status.

9. Ansible canonical gate changes

Primary file:

playbooks/apply/freeipa-identity-apply.yml

The Go validator and Ansible gate MUST continue to agree.

Change canonical HBAC group validation from:

selectattr('category', 'equalto', 'access')

to semantics equivalent to:

category in [team, role, access]

Do not allow filesystem.

Do not remove group reconciliation for access.

Do not change direct user/host normalization: it already maps:

subjects.users  -> ipa_hbac_rules[].users
subjects.groups -> ipa_hbac_rules[].groups
targets.hosts   -> ipa_hbac_rules[].hosts
targets.hostgroups -> ipa_hbac_rules[].hostgroups

Preserve authoritative removal:

hbacrule-remove-user --users
hbacrule-remove-user --groups
hbacrule-remove-host --hosts
hbacrule-remove-host --hostgroups

Update comments that claim HBAC is necessarily:

access group -> hostgroup

to the generic model:

users/groups -> hosts/hostgroups

10. TUI group creation changes

Primary file:

cmd/pilot/cmd/edit_tui_roster.go

At baseline rosterGroupCategories contains:

team
filesystem
access
role

Change sanctioned add-group UI to:

team
filesystem
role

Update labels:

team-*(團隊/team)
data-*(檔案系統存取/filesystem)
role-*(授權角色/role，可供 HBAC / sudo 使用)

Do not display an "access" creation option.

Existing access-* groups MUST remain visible in the Groups list and editable in their existing detail screen.

Do not silently reclassify them.

If a user opens an existing access group, its category remains read-only and the screen SHOULD show a short deprecation note, for example:

category：access（legacy；新 HBAC 不再需要 access group）

This note is presentation only.

11. HBAC TUI redesign

Primary file:

cmd/pilot/cmd/edit_tui_roster_access.go

11.1 Terminology

Change titles/comments that imply:

group -> hostgroup

to:

users/groups -> hosts/hostgroups

Suggested list title:

HBAC rules — 誰可以透過哪些服務登入哪些主機

11.2 Replace accessGroupChoices

Replace the access-only helper with a helper that returns HBAC-valid group choices:

team
role
legacy access

Do not include filesystem groups.

The UI SHOULD distinguish legacy access groups visually, without changing their underlying stable ID.

Example label:

access-webhosts-ssh [legacy access]

Stable Choice ID MUST remain the actual group name.

11.3 HBAC creation flow

The creation wizard SHALL collect:

rule name;

subject groups;

direct subject users;

target hostgroups;

direct target hosts;

services.

A valid rule needs:

len(users) + len(groups) > 0

and either:

hostcat: all

or:

len(hosts) + len(hostgroups) > 0

The normal interactive creation flow does not need to expose hostcat: all in this delivery if it currently does not; existing break-glass/manual support remains unchanged.

Suggested screens and stable IDs:

roster.hbac.add_name
roster.hbac.add_groups
roster.hbac.add_users
roster.hbac.add_hostgroups
roster.hbac.add_hosts
roster.hbac.add_services

Subject groups

Multi-select HBAC-valid groups:

team-*
role-*
legacy access-*

Empty selection is allowed because users may satisfy the subject requirement later.

Subject users

Multi-select:

admin
<all roster users>

Requirements:

no duplicate admin;

deterministic ordering;

use user name as stable choice ID;

empty selection allowed if groups are non-empty.

Hostgroups

Use existing roster-declared hostgroups.

Empty selection allowed because direct hosts may satisfy target requirement.

Direct hosts

Use a free-form comma-separated enrolled-FQDN input, consistent with the hostgroup member-host editor.

Example title:

Direct hosts / exceptions（可留空；逗號分隔已 enroll FQDN）

Normalize:

split on comma;

trim;

remove empty values;

validate FQDN shape;

deduplicate;

sort.

Services

Keep the existing configured/default PAM-service choice logic.

Default sshd remains appropriate.

11.4 HBAC detail screen

The detail screen SHALL expose all four relationship dimensions independently:

subjects.groups
subjects.users
targets.hostgroups
targets.hosts
services

Suggested stable IDs:

roster.hbac.detail.subjects_groups
roster.hbac.detail.subjects_users
roster.hbac.detail.targets_hostgroups
roster.hbac.detail.targets_hosts
roster.hbac.detail.services
roster.hbac.detail.back

11.5 Sibling-preservation invariant

This is mandatory.

Editing:

subjects.groups

MUST preserve:

subjects.users

Editing:

subjects.users

MUST preserve:

subjects.groups

Editing:

targets.hostgroups

MUST preserve:

targets.hosts

Editing:

targets.hosts

MUST preserve:

targets.hostgroups

The current behavior that sets:

t["hosts"] = []string{}

when editing hostgroups MUST be removed.

Do not replace one target dimension as a side effect of editing the other.

11.6 Simulation before write

Every TUI mutation must continue using the existing pattern:

read current rule
-> clone/mutate field
-> SimulateSetRosterHBACRule
-> only write if validation passes
-> SetRosterHBACRule

Do not bypass the roster validator.

12. Structured --actions contract

Primary files:

cmd/pilot/cmd/edit_automation.go
cmd/pilot/cmd/edit_actions_registry.go
cmd/pilot/cmd/edit_automation_driver_roster_access.go

12.1 Add plural hosts field

Add a new edit-action field:

Hosts []string `json:"hosts,omitempty"`

Do not reuse:

Host string `json:"host,omitempty"`

The singular Host has existing inventory semantics.

Update comments documenting the shared action fields.

12.2 Extend create_hbac_rule

New contract:

{
  "action": "create_hbac_rule",
  "name": "production-ssh",
  "users": ["alice"],
  "groups": ["team-sre", "role-production-operator"],
  "hosts": ["db-special.ipa.pilot.internal"],
  "hostgroups": ["production"],
  "services": ["sshd"]
}

Required:

name

Optional:

users
groups
hosts
hostgroups
services

The driver MUST replay the same TUI flow and must not directly mutate YAML behind the router.

Update the semantic action description from:

access group -> hostgroup -> PAM service

to generic HBAC semantics.

12.3 Add set_hbac_users

Add:

set_hbac_users

Contract:

{
  "action": "set_hbac_users",
  "name": "production-ssh",
  "users": ["alice", "bob"]
}

Semantics:

bulk replace the complete subjects.users set;

preserve subjects.groups;

validation occurs against the resulting whole rule.

12.4 Keep and generalize set_hbac_groups

Keep the existing action name for compatibility.

Update description/behavior to accept:

team
role
legacy access

and reject filesystem groups.

It continues to bulk replace only subjects.groups and MUST preserve subjects.users.

12.5 Extend set_hbac_targets

The existing action is already generically named and may be extended without introducing another action.

New contract:

{
  "action": "set_hbac_targets",
  "name": "production-ssh",
  "hosts": ["db-special.ipa.pilot.internal"],
  "hostgroups": ["production"]
}

Semantics:

bulk replace both explicit target collections:

targets.hosts;

targets.hostgroups;

remove hostcat when explicit target lists are being set;

validate the resulting whole rule.

Backward compatibility:

Existing action input containing only:

{"hostgroups": [...]}

continues to produce the same explicit hostgroup-only target set it produced previously.

12.6 Action validation

Action-level validation SHALL reject obvious malformed direct-host values before driving the TUI.

Entity/referential validation remains authoritative in Simulate* / roster validation.

12.7 Scenario version

Do not bump edit scenario version.

This is a backward-compatible expansion of optional action fields/actions.

Existing scenario v1 files must continue to load.

13. Automation driver requirements

Primary file:

cmd/pilot/cmd/edit_automation_driver_roster_access.go

Update navigation for the new Huh-backed screens.

The baseline repository has already migrated production TUI construction to tui.Factory and stable choice IDs. New automation SHOULD prefer stable IDs over label substring matching when selecting:

users;

groups;

hostgroups;

services.

Direct-host input is text input and should submit normalized comma-separated content.

Required driver behavior:

createHBACRule(...)
  name
  -> groups
  -> users
  -> hostgroups
  -> hosts
  -> services

Update method signature to include direct users/hosts.

Example:

createHBACRule(
    r,
    name,
    users,
    groups,
    hosts,
    hostgroups,
    services,
)

Exact argument ordering is implementation-defined, but tests must make it unambiguous.

14. MCP behavior

Relevant files include:

cmd/pilot/cmd/mcp_edit_resources.go
cmd/pilot/cmd/mcp_edit_tools.go
cmd/pilot/cmd/mcp_edit_tools_test.go
cmd/pilot/cmd/mcp_test.go

14.1 Read side

The inspect/resource model already exposes:

SubjectUsers
SubjectGroups
TargetHosts
TargetHostgroups
EffectiveHBACAccess

Preserve this.

Do not create a second "simplified" HBAC representation.

14.2 Write side

Because MCP edit actions are derived from the semantic action registry, ensure new/extended action fields are reflected in the published action specs and tool schema.

Required MCP-visible capability:

create_hbac_rule(users, groups, hosts, hostgroups, services)
set_hbac_users(users)
set_hbac_groups(groups)
set_hbac_targets(hosts, hostgroups)
set_hbac_services(services)

No secret-bearing fields are introduced.

15. Effective-access behavior

Primary file:

internal/inventory/roster_effective.go

No semantic redesign is needed.

The existing algorithm already represents the desired model:

effective users =
  direct subjects.users
  UNION recursively expanded subjects.groups

effective hosts =
  direct targets.hosts
  UNION recursively expanded targets.hostgroups

Add/adjust tests to prove the resolver works when HBAC references:

a team-* group directly;

a role-* group directly;

a legacy access-* group;

direct users plus groups;

direct hosts plus hostgroups.

Do not special-case access groups in the resolver.

16. Example roster after implementation

The primary example SHOULD demonstrate the new model without creating any access-* group.

Recommended shape:

schema_version: 2

users:
  - name: alice
    state: present
    first: Alice
    last: Wang
    enabled: true

  - name: vendor01
    state: present
    first: Vendor
    last: Operator
    enabled: true

groups:
  - name: team-developers
    state: present
    category: team
    type: posix
    description: Application development team
    membership:
      authoritative: true
      users: [alice]
      groups: []

  - name: role-production-operator
    state: present
    category: role
    type: posix
    description: Production operators
    membership:
      authoritative: true
      users: []
      groups: [team-developers]

  - name: data-project-alpha-rw
    state: present
    category: filesystem
    type: posix
    description: Project Alpha filesystem access
    membership:
      authoritative: true
      users: []
      groups: [team-developers]

hostgroups:
  - name: production-web
    state: present
    description: Production web hosts
    membership:
      authoritative: true
      hosts:
        - web01.ipa.pilot.internal
        - web02.ipa.pilot.internal
      hostgroups: []

hbac:
  disable_allow_all: true
  services:
    - {name: sshd, state: present}

  rules:
    - name: production-web-ssh
      state: present
      enabled: true
      subjects:
        users: []
        groups:
          - team-developers
      targets:
        hosts: []
        hostgroups:
          - production-web
      services:
        - sshd

    - name: vendor-emergency-maintenance
      state: present
      enabled: true
      subjects:
        users:
          - vendor01
        groups: []
      targets:
        hosts:
          - db-special.ipa.pilot.internal
        hostgroups: []
      services:
        - sshd

    - name: breakglass-admin-access
      state: present
      enabled: true
      subjects:
        users:
          - admin
        groups: []
      targets:
        hostcat: all
        hosts: []
        hostgroups: []
      services:
        - sshd

The example MUST NOT imply that team membership itself grants login.

Documentation wording must say:

A team is only an identity set. Login is granted only when an enabled HBAC rule explicitly references that team.

17. Documentation changes

Update every maintained document that states or strongly implies:

HBAC requires access-* groups

or:

access group -> hostgroup

At minimum inspect/update:

playbooks/apply/freeipa-identity.roster.example.yaml
docs/runbooks/freeipa-identity.md
docs/verification/freeipa-identity.md
freeipa-config.md
.agents/skills/freeipa-roster-authoring/SKILL.md
contracts/freeipa-identity.yaml

17.1 Agent authoring skill

The FreeIPA roster authoring skill SHALL say:

new groups use team, filesystem, role;

never generate a new category: access;

legacy access groups may be preserved when editing existing rosters;

HBAC group subjects may reference team or role;

legacy access references may be retained;

direct HBAC users are valid;

direct HBAC hosts are valid enrolled FQDN targets;

filesystem groups remain forbidden as HBAC subjects.

17.2 Verification contract

Verification docs SHALL explicitly cover direct-user and direct-host HBAC membership, not only group/hostgroup membership.

Do not claim a test was executed on a live VM unless it actually was.

18. Tests

The change is incomplete without regression coverage.

18.1 Validator tests

Add table-driven tests for:

HBAC team group                 PASS
HBAC role group                 PASS
HBAC legacy access group        PASS
HBAC filesystem group           FAIL
HBAC unknown group              FAIL
HBAC direct known user          PASS
HBAC unknown direct user        FAIL
HBAC users + groups             PASS
HBAC hosts + hostgroups         PASS
hostcat all + explicit host     FAIL
hostcat all + hostgroup         FAIL

Existing legacy access tests MUST continue passing.

18.2 Lint tests

Test:

legacy access group -> warning + exit success
no access group     -> no warning
invalid roster      -> violation/failure unchanged

18.3 TUI tests

Add coverage proving:

group creation no longer offers access;

existing access group remains visible/editable;

HBAC group picker includes team;

HBAC group picker includes role;

HBAC group picker includes legacy access;

HBAC group picker excludes filesystem;

HBAC user picker includes roster users and admin;

direct-host input round-trips;

editing groups does not erase direct users;

editing users does not erase groups;

editing hostgroups does not erase direct hosts;

editing hosts does not erase hostgroups.

18.4 Structured action tests

Add scenarios for:

{
  "action": "create_hbac_rule",
  "name": "mixed",
  "users": ["alice"],
  "groups": ["team-developers", "role-ops"],
  "hosts": ["special.ipa.pilot.internal"],
  "hostgroups": ["production"],
  "services": ["sshd"]
}

Verify resulting roster contains all requested dimensions.

Test set_hbac_users.

Test generalized set_hbac_groups.

Test extended set_hbac_targets.

Test old create_hbac_rule scenarios containing only groups/hostgroups/services still pass unchanged.

18.5 Effective access tests

Expected example:

team-developers -> alice
role-ops -> team-developers + bob

rule subjects:
  users: [carol]
  groups: [role-ops]

effective users:
  alice
  bob
  carol

Target equivalent:

direct host + nested hostgroup -> union of all FQDNs

18.6 Ansible tests

Update canonical fixtures so the main modern fixture uses direct team/role HBAC references.

Keep at least one explicit legacy access-group fixture proving backward compatibility.

The compatibility fixture MUST be real coverage, not dead example data.

19. Compatibility matrix

Input / behavior

Before

After

Existing category: access roster

valid

valid + deprecation warning

New access group via TUI

allowed

not offered

New access group via structured action

allowed

rejected

HBAC references access group

valid

valid, legacy

HBAC references team group

rejected

valid

HBAC references role group

rejected

valid

HBAC references filesystem group

rejected

rejected

HBAC direct user in raw roster

supported backend

supported backend + TUI/actions

HBAC direct host in raw roster

supported backend

supported backend + TUI/actions

Editing HBAC hostgroups with direct hosts present

direct hosts cleared

direct hosts preserved

Roster schema

v1/v2

unchanged v1/v2

v1 -> v2 migration

automatic/current

unchanged

20. Structured action compatibility details

20.1 create_group

If structured actions currently accept:

category=access

change action-level validation to reject it with a useful message:

create_group: category "access" is deprecated and cannot be created; use team or role for HBAC subjects

Do not make ValidateRoster reject an existing access group.

20.2 Existing action replay

Existing scenarios must not break.

For example:

{
  "action": "create_hbac_rule",
  "name": "legacy-flow",
  "groups": ["access-old"],
  "hostgroups": ["webhosts"],
  "services": ["sshd"]
}

remains valid if access-old already exists in the roster.

The goal is to stop new access-group creation, not to make existing authorization uneditable.

21. Source-of-truth and duplication constraints

This change specifically removes an unnecessary authorization abstraction. Do not replace it with new duplicated policy tables.

21.1 Go category policy

Prefer one Go source of truth for:

known category;

prefix;

creatable status;

HBAC allowed status;

sudo allowed status;

deprecation status.

TUI and structured-action validation should consume that policy rather than hand-maintaining separate category arrays where practical.

21.2 Go / Ansible synchronization

The Ansible gate must independently enforce the same final policy because users can run the playbook without first invoking the Go CLI.

Add regression tests or comments tying the two together.

A roster accepted by Go must not be rejected by the equivalent Ansible HBAC category gate.

22. Safety properties

The final implementation MUST preserve these properties.

22.1 Fail before write

Any invalid TUI/structured action:

filesystem group as HBAC subject
unknown user
unknown HBAC group
empty subject set
empty target set
hostcat collision
empty services

must fail simulation before roster mutation.

22.2 No accidental revocation

Editing one part of a rule must not erase another valid access path.

This is particularly important for:

direct user + group
direct host + hostgroup

22.3 No accidental privilege widening

Do not permit data-* in HBAC.

Do not interpret omission of all explicit targets as hostcat: all inside the editor unless that behavior is explicitly requested through the existing supported mechanism.

22.4 Break-glass invariant

Keep the current invariant:

hbac.disable_allow_all: true

requires an enabled admin break-glass rule targeting:

hostcat: all

No changes in this feature may weaken it.

23. Implementation phases

The coding agent SHOULD implement in this order so every phase has a coherent test boundary.

Phase 1 — Central category policy + validator

Introduce/refactor centralized Go group-category policy.

Keep access structurally valid but mark deprecated.

Allow team/role/access in HBAC subjects.

Keep filesystem rejected.

Add validator unit tests.

Exit criterion:

go test ./internal/inventory/...

passes with new category tests.

Phase 2 — Ansible gate alignment

Update canonical HBAC group gate.

Update comments.

Preserve direct user/host reconciliation.

Update fixture coverage.

Exit criterion:

Go and Ansible rules match;

syntax check passes;

legacy access fixture remains accepted.

Phase 3 — TUI

Remove access from new-group choices.

Generalize HBAC group picker.

Add direct-user screen.

Add direct-host screen.

Add fields to HBAC detail.

Fix sibling-preservation bug.

Add TUI tests.

Exit criterion:

go test ./cmd/pilot/cmd/...

passes.

Phase 4 — Structured actions / MCP

Add Hosts []string.

Extend create_hbac_rule.

Add set_hbac_users.

Generalize set_hbac_groups.

Extend set_hbac_targets.

Update automation driver.

Update action specs/MCP tests.

Exit criterion:

Existing and new scenario tests pass.

Phase 5 — Lint deprecation + docs

Add non-fatal access warning.

Remove access from modern example authoring.

Keep explicit legacy compatibility fixture.

Update runbook/spec/agent skill.

Exit criterion:

No maintained documentation instructs users to create an access group merely to use HBAC.

Phase 6 — Full regression/evidence

Run repository-required regression and inspect changed behavior.

At minimum:

go test ./...
go vet ./...
go build ./cmd/pilot

Also run repository-prescribed formatting/static checks.

If a real FreeIPA test target is available, run the canonical apply/check/verify flow against it and capture actual evidence per repository documentation rules.

Do not fabricate live-run evidence.

24. Acceptance scenarios

Scenario A — Team directly grants login

Input:

groups:
  - name: team-dev
    category: team
    membership:
      users: [alice]
      groups: []

hbac:
  rules:
    - name: dev-ssh
      subjects:
        users: []
        groups: [team-dev]
      targets:
        hosts: []
        hostgroups: [dev-hosts]
      services: [sshd]

Expected:

valid
effective users includes alice

Scenario B — Role reused by HBAC and sudo

Input:

role-ops -> [team-sre]
HBAC -> role-ops
sudo -> role-ops

Expected:

valid
same role can be used by both policy types

Scenario C — Direct exception

Input:

subjects.users: [vendor01]
targets.hosts: [db-special.ipa.pilot.internal]

Expected:

valid
no wrapper access group required

Scenario D — Mixed normal + exception

Input:

subjects:
  users: [vendor01]
  groups: [team-sre]

targets:
  hosts: [db-special.ipa.pilot.internal]
  hostgroups: [production-db]

Expected:

valid
effective result is union
editing any one list preserves the other three lists

Scenario E — Filesystem group rejected

Input:

subjects.groups: [data-project-alpha-rw]

Expected:

validation failure before write

Scenario F — Legacy access survives

Input:

groups:
  - name: access-webhosts-ssh
    category: access

hbac:
  rules:
    - subjects:
        groups: [access-webhosts-ssh]

Expected:

validation passes
lint emits deprecation warning
apply still reconciles
TUI can edit existing rule/group
new-group UI does not offer category access

25. Definition of done

The change is DONE only when all of the following are true.

New HBAC rules can use direct roster users.

New HBAC rules can use direct enrolled host FQDNs.

HBAC can directly reference team-*.

HBAC can directly reference role-*.

HBAC still accepts legacy access-*.

HBAC rejects data-*.

New group TUI does not offer access.

create_group structured action rejects new access.

Existing access groups remain editable and reconcilable.

Lint reports access deprecation without failing.

Editing HBAC groups preserves users.

Editing HBAC users preserves groups.

Editing HBAC hostgroups preserves direct hosts.

Editing HBAC direct hosts preserves hostgroups.

create_hbac_rule supports users/groups/hosts/hostgroups/services.

set_hbac_users exists.

set_hbac_groups accepts team/role/legacy access.

set_hbac_targets supports hosts + hostgroups.

MCP action/tool schemas expose the new behavior.

Effective access tests cover mixed direct/nested relationships.

Modern examples create no access groups.

At least one legacy access fixture remains as compatibility coverage.

Roster schema version remains unchanged.

Existing v1 -> v2 migration tests remain green.

go test ./... passes.

go vet ./... passes.

go build ./cmd/pilot passes.

No fake live-environment evidence is added.

26. Explicitly deferred follow-up

A future, separate specification may remove category: access from the schema entirely.

That future migration must first solve all of:

detecting access-group references outside HBAC;

nested access-group dependencies;

netgroup references;

live FreeIPA group cleanup;

external/unmanaged consumers;

preserving dynamic team/role membership semantics;

safe rollback;

encrypted roster migration;

semantic-equivalence proof.

Until that exists, the correct lifecycle is:

now:
  access = deprecated compatibility

new authoring:
  team / role / direct user -> HBAC

later:
  explicit audited access-group retirement workflow

Do not fold that destructive migration into this implementation.

27. Integration contract with the Pilot v3 specification set

This specification is a v2-compatible prerequisite to the v3 work. It deliberately does not bump the roster schema.

The integrated delivery order is:

v2 HBAC authorization simplification
        ↓
v2 -> v3 migration
        ↓
v3.0 lifecycle-aware grants / policy
        ↓
v3.1 security operations
        ↓
v3.2 identity hardening
        ↓
optional forced Approval gate

The following rules are binding on all later v3 specifications.

27.1 Static login authorization

A static login authorization is an HBAC rule.

The modern static authoring model is:

direct user ─┐
team-*      ─┼──> HBAC ──> direct host
role-*      ─┘          └─> hostgroup

access-* is not a normal v3 entitlement abstraction. It is deprecated compatibility data only.

27.2 Modern group meanings

team-*  = organizational identity set; may be an HBAC subject
role-*  = reusable authorization/principal set; may be used by HBAC and sudo
data-*  = filesystem/POSIX/NFS only
access-* = deprecated compatibility category; never newly authored

Team membership by itself never grants login. Only an enabled HBAC rule referencing that team grants login.

27.3 Temporary authorization

v3 grants[] MUST NOT recreate the removed wrapper abstraction.

Login grants SHALL use the same relationship geometry as HBAC:

subjects:
  users: [...]
  groups: [...]

targets:
  hosts: [...]
  hostgroups: [...]

For login grants:

team, role, and legacy access groups are accepted;

filesystem groups are forbidden;

direct users are first-class;

direct enrolled host FQDNs are first-class.

For sudo grants:

direct users are accepted;

subject groups must remain role;

direct hosts and hostgroups are accepted.

27.4 Migration

The v2 -> v3 schema migration MUST NOT:

create access-*;

convert access-* to role-*;

flatten legacy access membership;

rewrite static HBAC into grants;

delete legacy access groups.

Both of these v2 shapes must migrate with identical authorization semantics:

HBAC -> team/role/direct user
HBAC -> legacy access group

27.5 Explain / inspection

v3 access explanation MUST distinguish at least:

static_hbac
temporary_grant
breakglass
sudo_grant

and preserve the actual provenance path through direct users/groups and direct hosts/hostgroups.

27.6 Approval independence

The optional forced Approval mechanism MUST wrap mutation/activation plans. It MUST NOT reintroduce access-* or require changes to the HBAC/grant subject-target model.
