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

func TestValidateRoster_WrongSchemaVersion(t *testing.T) {
	v := ValidateRoster(mustParseRoster(t, "schema_version: 2\n"))
	if !contains(ruleNames(v), "schema_version") {
		t.Fatalf("expected a schema_version violation, got: %v", v)
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
  - name: team-x
    category: team
hbac:
  rules:
    - name: r1
      subjects: {groups: [team-x]}
      targets: {hostcat: all}
      services: [sshd]
`))
	if !contains(ruleNames(v), "hbac subject group category") {
		t.Fatalf("expected an hbac subject group category violation, got: %v", v)
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
	// short-circuiting on the first one found.
	v := ValidateRoster(mustParseRoster(t, `
schema_version: 2
users:
  - name: Alice
groups:
  - name: not-prefixed
    category: team
`))
	names := ruleNames(v)
	for _, want := range []string{"schema_version", "user name", "group category prefix"} {
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
