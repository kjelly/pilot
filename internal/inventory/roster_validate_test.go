package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParseRoster(t *testing.T, doc string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return root
}

func ruleNames(violations []RosterViolation) []string {
	out := make([]string, len(violations))
	for i, v := range violations {
		out[i] = v.Rule
	}
	return out
}

// TestValidateRoster_RealShippedExamplePassesClean ties the validator to
// the actual canonical roster shipped in this repo — the source of truth
// every check above mirrors from freeipa-identity-apply.yml's "Gate:
// canonical ..." assert chain. A future edit to the example that silently
// drifts from what the Ansible gates actually accept should fail here.
func TestValidateRoster_RealShippedExamplePassesClean(t *testing.T) {
	path := filepath.Join("..", "..", "playbooks", "apply", "freeipa-identity.roster.example.yaml")
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Skipf("real roster example not found: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the real shipped roster example to pass clean, got: %v", violations)
	}
}

func TestValidateRosterFile_EncryptedRosterReturnsErrRosterEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRosterFile(path); err != ErrRosterEncrypted {
		t.Fatalf("ValidateRosterFile() error = %v, want ErrRosterEncrypted", err)
	}
}

const minimalValidRoster = `
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: alice
    ssh_keys: {authoritative: true, values: []}
groups:
  - name: team-devs
    category: team
    membership: {users: [alice], groups: []}
hosts: []
hostgroups: []
hbac:
  rules:
    - name: breakglass
      subjects: {users: [alice], groups: []}
      targets: {hostcat: all}
      services: [sshd]
sudo:
  rules: []
`

func TestValidateRoster_MinimalValidRosterPassesClean(t *testing.T) {
	if v := ValidateRoster(mustParseRoster(t, minimalValidRoster)); len(v) != 0 {
		t.Fatalf("expected minimalValidRoster to pass clean, got: %v", v)
	}
}

func TestValidateRoster_MissingSchemaVersion(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "users: []\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
	}
}

func TestValidateRoster_MinimalValidV2RosterPassesClean(t *testing.T) {
	if v := ValidateRoster(mustParseRoster(t, "schema_version: 2\n")); len(v) != 0 {
		t.Fatalf("expected a minimal schema_version: 2 roster to pass clean, got: %v", v)
	}
}

func TestValidateRoster_V1RejectsNetgroupsTopLevelKey(t *testing.T) {
	// netgroups is a v2-only key; a v1 document declaring it must still
	// fail closed as unknown, exactly like any other unrecognized field.
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nnetgroups: []\n"))
	if !contains(ruleNames(v), "top-level keys") {
		t.Fatalf("expected a top-level keys violation for netgroups under v1, got: %v", v)
	}
}

func TestValidateRoster_V2AllowsNetgroupsTopLevelKey(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 2\nnetgroups: []\n"))
	if contains(ruleNames(v), "top-level keys") {
		t.Fatalf("did not expect a top-level keys violation for netgroups under v2, got: %v", v)
	}
}

func TestValidateRoster_UnsupportedFutureSchemaVersion(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 999\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
	}
}

func TestValidateRoster_InvalidZeroSchemaVersion(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 0\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
	}
}

func TestValidateRoster_InvalidNegativeSchemaVersion(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: -1\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
	}
}

func TestValidateRosterV1_RejectsSchemaVersion2(t *testing.T) {
	v := ValidateRosterV1(mustParseRoster(t, "schema_version: 2\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation calling ValidateRosterV1 directly on a v2 document, got: %v", v)
	}
}

func TestValidateRosterV2_RejectsSchemaVersion1(t *testing.T) {
	v := ValidateRosterV2(mustParseRoster(t, "schema_version: 1\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation calling ValidateRosterV2 directly on a v1 document, got: %v", v)
	}
}

func TestValidateRoster_UnknownTopLevelKey(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nnot_a_real_key: true\n"))
	if !contains(ruleNames(v), "top-level keys") {
		t.Fatalf("expected a top-level keys violation, got: %v", v)
	}
}

func TestValidateRoster_MigrationMustBeEmpty(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nmigration: {legacy_users: [bob]}\n"))
	if !contains(ruleNames(v), "migration") {
		t.Fatalf("expected a migration violation, got: %v", v)
	}
}

func TestValidateRoster_UserNameMustBeLowercase(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: Alice\n"))
	if !contains(ruleNames(v), "user name") {
		t.Fatalf("expected a user name violation, got: %v", v)
	}
}

func TestValidateRoster_UserUnknownField(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: alice\n    nickname: al\n"))
	if !contains(ruleNames(v), "user keys") {
		t.Fatalf("expected a user keys violation, got: %v", v)
	}
}

func TestValidateRoster_UserSSHKeysNotAuthoritative(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: alice\n    ssh_keys: {authoritative: false, values: []}\n"))
	if !contains(ruleNames(v), "user ssh_keys authoritative") {
		t.Fatalf("expected a ssh_keys authoritative violation, got: %v", v)
	}
}

func TestValidateRoster_DisabledUserWithEnabledTrueConflict(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: alice\n    state: disabled\n    enabled: true\n"))
	if !contains(ruleNames(v), "user disabled+enabled") {
		t.Fatalf("expected a disabled+enabled violation, got: %v", v)
	}
}

func TestValidateRoster_DisabledUserWithoutEnabledIsFine(t *testing.T) {
	// mirrors the Ansible gate's own default: enabled | default(false) —
	// omitting `enabled` on a disabled user must NOT be flagged.
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: alice\n    state: disabled\n"))
	if contains(ruleNames(v), "user disabled+enabled") {
		t.Fatalf("did not expect a disabled+enabled violation when enabled is simply omitted, got: %v", v)
	}
}

func TestValidateRoster_DuplicateUserNames(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nusers:\n  - name: alice\n  - name: alice\n"))
	if !contains(ruleNames(v), "unique user names") {
		t.Fatalf("expected a unique user names violation, got: %v", v)
	}
}

func TestValidateRoster_GroupCategoryPrefixMismatch(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\ngroups:\n  - name: not-prefixed\n    category: team\n"))
	if !contains(ruleNames(v), "group category prefix") {
		t.Fatalf("expected a group category prefix violation, got: %v", v)
	}
}

func TestValidateRoster_GroupUnknownCategory(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\ngroups:\n  - name: team-x\n    category: bogus\n"))
	if !contains(ruleNames(v), "group category") {
		t.Fatalf("expected a group category violation, got: %v", v)
	}
}

func TestValidateRoster_GroupSelfMembership(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\ngroups:\n  - name: team-x\n    category: team\n    membership: {groups: [team-x]}\n"))
	if !contains(ruleNames(v), "group self-membership") {
		t.Fatalf("expected a group self-membership violation, got: %v", v)
	}
}

func TestValidateRoster_GroupMembershipReferencesUnknownUser(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\ngroups:\n  - name: team-x\n    category: team\n    membership: {users: [ghost]}\n"))
	if !contains(ruleNames(v), "group membership user reference") {
		t.Fatalf("expected a dangling user reference violation, got: %v", v)
	}
}

// TestValidateRoster_SudoSubjectUserReferenceUnknown pins the fix for the
// dangling sudo-user reference gap spec.md §13.4 calls out: checkSudo used
// to validate subjects.groups against category: role but never checked
// subjects.users against the known user set at all.
func TestValidateRoster_SudoSubjectUserReferenceUnknown(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nsudo:\n  rules:\n    - name: sudo-bad-user\n      subjects: {users: [does-not-exist], groups: []}\n      targets: {hostcat: all}\n"))
	if !contains(ruleNames(v), "sudo subject user reference") {
		t.Fatalf("expected a dangling sudo subject user reference violation, got: %v", v)
	}
}

func TestValidateRoster_SudoSubjectAdminUserAlwaysAllowed(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nsudo:\n  rules:\n    - name: sudo-admin\n      subjects: {users: [admin], groups: []}\n      targets: {hostcat: all}\n"))
	if contains(ruleNames(v), "sudo subject user reference") {
		t.Fatalf("expected admin to be an always-allowed sudo subject user, got: %v", v)
	}
}

func TestValidateRoster_NFSOwnershipGroupWrongCategory(t *testing.T) {
	doc := "schema_version: 1\n" +
		"groups:\n  - name: team-not-filesystem\n    category: team\n" +
		"nfs:\n  servers:\n    - host: nfs1.ipa.pilot.internal\n      shares:\n        - name: share1\n          ownership: {group: team-not-filesystem}\n"
	v := ValidateRoster(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "nfs ownership group reference") {
		t.Fatalf("expected an nfs ownership group reference violation, got: %v", v)
	}
}

func TestValidateRoster_NFSOwnershipGroupCorrectCategoryPasses(t *testing.T) {
	doc := "schema_version: 1\n" +
		"groups:\n  - name: data-project-alpha-rw\n    category: filesystem\n" +
		"nfs:\n  servers:\n    - host: nfs1.ipa.pilot.internal\n      shares:\n        - name: share1\n          ownership: {group: data-project-alpha-rw}\n          acl: {access: {named_groups: [{name: data-project-alpha-rw}]}, default: {named_groups: []}}\n"
	v := ValidateRoster(mustParseRoster(t, doc))
	if contains(ruleNames(v), "nfs ownership group reference") || contains(ruleNames(v), "nfs acl named_group reference") {
		t.Fatalf("expected a correctly-categorized nfs group reference to pass clean, got: %v", v)
	}
}

func TestValidateRoster_NFSACLNamedGroupUnknown(t *testing.T) {
	doc := "schema_version: 1\n" +
		"nfs:\n  servers:\n    - host: nfs1.ipa.pilot.internal\n      shares:\n        - name: share1\n          acl: {access: {named_groups: [{name: ghost-group}]}}\n"
	v := ValidateRoster(mustParseRoster(t, doc))
	if !contains(ruleNames(v), "nfs acl named_group reference") {
		t.Fatalf("expected an nfs acl named_group reference violation, got: %v", v)
	}
}

func TestValidateRoster_HostInvalidFQDNAndIP(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 1\nhosts:\n  - name: not-an-fqdn\n    ip_address: not-an-ip\n"))
	names := ruleNames(v)
	if !contains(names, "host name") || !contains(names, "host ip_address") {
		t.Fatalf("expected both host name and host ip_address violations, got: %v", v)
	}
}

func TestValidateRoster_HBACSubjectGroupWrongCategory(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: data-x
    category: filesystem
hbac:
  rules:
    - name: r1
      subjects: {groups: [data-x]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac subject group category") {
		t.Fatalf("expected an hbac subject group category violation, got: %v", v)
	}
}

func TestValidateRoster_HBACSubjectGroupUnknownName(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
hbac:
  rules:
    - name: r1
      subjects: {groups: [no-such-group]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac subject group category") {
		t.Fatalf("expected an hbac subject group category violation for an unknown group, got: %v", v)
	}
}

func TestValidateRoster_HBACSubjectGroupAllowedCategories(t *testing.T) {
	cases := []struct {
		category, groupName string
	}{
		{"team", "team-x"},
		{"role", "role-x"},
		{"access", "access-x"},
	}
	for _, c := range cases {
		roster := `
schema_version: 1
groups:
  - name: ` + c.groupName + `
    category: ` + c.category + `
hbac:
  rules:
    - name: r1
      subjects: {groups: [` + c.groupName + `]}
      targets: {hostcat: all}
      services: [sshd]
`
		v := ValidateRoster(mustParseRoster(t, roster))
		if contains(ruleNames(v), "hbac subject group category") {
			t.Fatalf("category %q: expected no hbac subject group category violation, got: %v", c.category, v)
		}
	}
}

func TestValidateRoster_HBACSubjectGroupRejectsFilesystem(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: data-fs
    category: filesystem
hbac:
  rules:
    - name: r1
      subjects: {groups: [data-fs]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac subject group category") {
		t.Fatalf("expected filesystem group to be rejected as an hbac subject, got: %v", v)
	}
}

func TestValidateRoster_HBACTargetsHostcatAllCombinedWithHosts(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
hbac:
  rules:
    - name: r1
      subjects: {users: [admin]}
      targets: {hostcat: all, hosts: [nexus.ipa.pilot.internal]}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac targets") {
		t.Fatalf("expected an hbac targets violation (hostcat: all + hosts), got: %v", v)
	}
}

func TestValidateRoster_HBACTargetHostgroupUnresolved(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
hbac:
  rules:
    - name: r1
      subjects: {users: [admin]}
      targets: {hostgroups: [ghost-group]}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac target hostgroup reference") {
		t.Fatalf("expected an hbac target hostgroup reference violation, got: %v", v)
	}
}

func TestValidateRoster_HBACDisableAllowAllRequiresAdminBreakGlass(t *testing.T) {
	withoutBreakGlass := ValidateRoster(mustParseRoster(t, `
schema_version: 1
hbac:
  disable_allow_all: true
  rules:
    - name: user-access
      subjects: {users: [alice]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if !contains(ruleNames(withoutBreakGlass), "hbac break-glass") {
		t.Fatalf("expected break-glass violation, got: %v", withoutBreakGlass)
	}

	withBreakGlass := ValidateRoster(mustParseRoster(t, `
schema_version: 1
hbac:
  disable_allow_all: true
  rules:
    - name: admin-breakglass
      enabled: true
      subjects: {users: [admin]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if contains(ruleNames(withBreakGlass), "hbac break-glass") {
		t.Fatalf("did not expect break-glass violation, got: %v", withBreakGlass)
	}
}

func TestValidateRoster_SudoSubjectGroupWrongCategory(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: team-x
    category: team
sudo:
  rules:
    - name: r1
      subjects: {groups: [team-x]}
      targets: {hostcat: all}
`))
	if !contains(ruleNames(v), "sudo subject group category") {
		t.Fatalf("expected a sudo subject group category violation, got: %v", v)
	}
}

func TestValidateRoster_SudoCommandGroupReferenceMustResolve(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: role-ops
    category: role
sudo:
  command_groups: []
  rules:
    - name: ops-sudo
      subjects: {groups: [role-ops]}
      targets: {hostcat: all}
      allow: {command_groups: [missing-group], commands: []}
`))
	if !contains(ruleNames(v), "sudo command group reference") {
		t.Fatalf("expected unresolved sudo command group violation, got: %v", v)
	}
}

func TestValidateRoster_SudoAllowCommandCategoryAllIsExclusive(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: role-ops
    category: role
sudo:
  rules:
    - name: ops-sudo
      subjects: {groups: [role-ops]}
      targets: {hostcat: all}
      allow: {command_category: all, command_groups: [], commands: [/usr/bin/id]}
`))
	if !contains(ruleNames(v), "sudo allow command category") {
		t.Fatalf("expected allow-all/list mutual-exclusion violation, got: %v", v)
	}
}

func TestValidateRoster_SudoAllowCommandCategoryRejectsUnknownValue(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: role-ops
    category: role
sudo:
  rules:
    - name: ops-sudo
      subjects: {groups: [role-ops]}
      targets: {hostcat: all}
      allow: {command_category: none, command_groups: [], commands: []}
`))
	if !contains(ruleNames(v), "sudo allow command category") {
		t.Fatalf("expected invalid command-category violation, got: %v", v)
	}
}

func TestValidateRoster_SudoAllowCommandCategoryAllIsValid(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
groups:
  - name: role-ops
    category: role
sudo:
  rules:
    - name: ops-sudo
      subjects: {groups: [role-ops]}
      targets: {hostcat: all}
      allow: {command_category: all, command_groups: [], commands: []}
`))
	if contains(ruleNames(v), "sudo allow command category") {
		t.Fatalf("explicit allow-all must validate, got: %v", v)
	}
}

func TestValidateRoster_SudoCommandDenylistBinary(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
sudo:
  command_groups:
    - name: dangerous
      commands: ["/bin/bash"]
`))
	if !contains(ruleNames(v), "sudo command denylist") {
		t.Fatalf("expected a sudo command denylist violation for /bin/bash, got: %v", v)
	}
}

func TestValidateRoster_SudoCommandDenylistMetacharacter(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
sudo:
  command_groups:
    - name: dangerous
      commands: ["/usr/bin/systemctl restart nginx; rm -rf /"]
`))
	if !contains(ruleNames(v), "sudo command denylist") {
		t.Fatalf("expected a sudo command denylist violation for a command with a shell metacharacter, got: %v", v)
	}
}

func TestValidateRoster_SudoCommandSafeIsNotFlagged(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 1
sudo:
  command_groups:
    - name: safe
      commands: ["/usr/bin/systemctl status nginx"]
`))
	if contains(ruleNames(v), "sudo command denylist") {
		t.Fatalf("did not expect a sudo command denylist violation for a safe command, got: %v", v)
	}
}

func TestValidateRoster_MultipleViolationsAllCollected(t *testing.T) {
	// proves violations accumulate across independent checks rather than
	// short-circuiting on the first one found. schema_version: 2 is itself
	// valid here — an *invalid* version deliberately short-circuits (see
	// TestValidateRoster_UnsupportedFutureSchemaVersion) since there's no
	// version-specific rule set left to check anything else against.
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 2
users:
  - name: Alice
groups:
  - name: not-prefixed
    category: team
`))
	names := ruleNames(v)
	for _, want := range []string{"user name", "group category prefix"} {
		if !contains(names, want) {
			t.Fatalf("expected violation %q among %v", want, names)
		}
	}
}

func TestValidateRosterFile_ReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(minimalValidRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, err := ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got: %v", violations)
	}
}

func TestRosterViolation_StringIncludesRuleAndDetail(t *testing.T) {
	v := RosterViolation{Rule: "test-rule", Detail: "test detail"}
	if got := v.String(); !strings.Contains(got, "test-rule") || !strings.Contains(got, "test detail") {
		t.Fatalf("String() = %q, want it to include both the rule and detail", got)
	}
}

func TestDetectRosterSchemaVersion_V1(t *testing.T) {
	v, err := DetectRosterSchemaVersion([]byte("schema_version: 1\n"))
	if err != nil {
		t.Fatalf("DetectRosterSchemaVersion() error = %v", err)
	}
	if v != RosterSchemaV1 {
		t.Fatalf("DetectRosterSchemaVersion() = %v, want RosterSchemaV1", v)
	}
}

func TestDetectRosterSchemaVersion_V2(t *testing.T) {
	v, err := DetectRosterSchemaVersion([]byte("schema_version: 2\n"))
	if err != nil {
		t.Fatalf("DetectRosterSchemaVersion() error = %v", err)
	}
	if v != RosterSchemaV2 {
		t.Fatalf("DetectRosterSchemaVersion() = %v, want RosterSchemaV2", v)
	}
}

func TestDetectRosterSchemaVersion_MissingVersion(t *testing.T) {
	if _, err := DetectRosterSchemaVersion([]byte("users: []\n")); err == nil {
		t.Fatal("expected an error for a document with no schema_version")
	}
}

func TestDetectRosterSchemaVersion_NonIntegerVersion(t *testing.T) {
	if _, err := DetectRosterSchemaVersion([]byte("schema_version: banana\n")); err == nil {
		t.Fatal("expected an error for a non-integer schema_version")
	}
}

func TestDetectRosterSchemaVersion_EncryptedReturnsErrRosterEncrypted(t *testing.T) {
	_, err := DetectRosterSchemaVersion([]byte("$ANSIBLE_VAULT;1.1;AES256\n633864363...\n"))
	if err != ErrRosterEncrypted {
		t.Fatalf("DetectRosterSchemaVersion() error = %v, want ErrRosterEncrypted", err)
	}
}

func TestDetectRosterSchemaVersion_UnsupportedFutureVersionStillDetects(t *testing.T) {
	// Detection alone doesn't reject an unsupported version — that's
	// ValidateRoster's job. A migration engine deciding whether it even
	// knows how to handle this file needs the raw detected value first.
	v, err := DetectRosterSchemaVersion([]byte("schema_version: 999\n"))
	if err != nil {
		t.Fatalf("DetectRosterSchemaVersion() error = %v", err)
	}
	if v != RosterSchemaVersion(999) {
		t.Fatalf("DetectRosterSchemaVersion() = %v, want 999", v)
	}
}
