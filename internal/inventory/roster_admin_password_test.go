package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const rosterAdminFixture = `---
# canonical roster
schema_version: 3
freeipa:
  server: ipa1.example.test
  admin:
    principal: admin
    password: %s  # rotated with the vault
  defaults:
    group_type: posix
users:
  - name: alice
    password:
      initial: "user-initial-secret"
netgroups: []
grants: []
`

func writeRoster(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ipa-identity.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rosterAdminPassword(t *testing.T, data []byte) any {
	t.Helper()
	var roster map[string]any
	if err := yaml.Unmarshal(data, &roster); err != nil {
		t.Fatalf("roster no longer parses: %v\n%s", err, data)
	}
	return roster["freeipa"].(map[string]any)["admin"].(map[string]any)["password"]
}

func TestSyncRosterAdminPasswordRewritesOnlyThatScalar(t *testing.T) {
	newPassword := `New "pa$$#word' \ 密碼 {x}`
	for name, oldScalar := range map[string]string{
		"double-quoted": `"Old-pass_1"`,
		"single-quoted": `'Old-pass_1'`,
		"plain":         `Old-pass_1`,
	} {
		t.Run(name, func(t *testing.T) {
			before := strings.Replace(rosterAdminFixture, "%s", oldScalar, 1)
			path := writeRoster(t, before)

			got, err := SyncRosterAdminPassword(path, "Old-pass_1", newPassword)
			if err != nil || got != RosterAdminUpdated {
				t.Fatalf("SyncRosterAdminPassword() = %v, %v; want RosterAdminUpdated", got, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if pw := rosterAdminPassword(t, after); pw != newPassword {
				t.Fatalf("freeipa.admin.password = %q, want the new password", pw)
			}
			// Every other line, the comment on the rewritten one included, is
			// byte-for-byte what it was.
			beforeLines, afterLines := strings.Split(before, "\n"), strings.Split(string(after), "\n")
			if len(beforeLines) != len(afterLines) {
				t.Fatalf("line count changed:\n%s", after)
			}
			for i := range beforeLines {
				if strings.Contains(beforeLines[i], "password: "+oldScalar) {
					if !strings.HasPrefix(afterLines[i], "    password: \"") || !strings.HasSuffix(afterLines[i], "  # rotated with the vault") {
						t.Errorf("rewritten line = %q", afterLines[i])
					}
					continue
				}
				if beforeLines[i] != afterLines[i] {
					t.Errorf("line %d changed: %q -> %q", i+1, beforeLines[i], afterLines[i])
				}
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("roster mode = %v, %v; want 0600", info.Mode().Perm(), err)
			}
		})
	}
}

func TestSyncRosterAdminPasswordKeepsCRLF(t *testing.T) {
	before := strings.ReplaceAll(strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1), "\n", "\r\n")
	path := writeRoster(t, before)
	if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword() = %v, %v", got, err)
	}
	after, _ := os.ReadFile(path)
	if want := strings.Replace(before, `"Old-pass_1"`, `"New-pass_2"`, 1); string(after) != want {
		t.Fatalf("roster =\n%q\nwant\n%q", after, want)
	}
}

// Anything but "still holds the old literal password" leaves the file alone.
func TestSyncRosterAdminPasswordLeavesOtherRostersAlone(t *testing.T) {
	for name, tt := range map[string]struct {
		body string
		want RosterAdminSync
	}{
		"already current": {strings.Replace(rosterAdminFixture, "%s", `"New-pass_2"`, 1), RosterAdminCurrent},
		"a third value":   {strings.Replace(rosterAdminFixture, "%s", `"Other-pass_3"`, 1), RosterAdminDiffers},
		"vault reference": {strings.Replace(rosterAdminFixture, "%s", `"{{ ipa_admin_password }}"`, 1), RosterAdminNotLiteral},
		"empty":           {strings.Replace(rosterAdminFixture, "%s", `""`, 1), RosterAdminNotLiteral},
		"null":            {strings.Replace(rosterAdminFixture, "%s", `null`, 1), RosterAdminNotLiteral},
		"no admin":        {"schema_version: 3\nfreeipa:\n  server: ipa1.example.test\n", RosterAdminNotLiteral},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, tt.body)
			got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2")
			if err != nil || got != tt.want {
				t.Fatalf("SyncRosterAdminPassword() = %v, %v; want %v", got, err, tt.want)
			}
			if after, _ := os.ReadFile(path); string(after) != tt.body {
				t.Fatalf("roster changed:\n%s", after)
			}
		})
	}
}

// A layout that cannot be rewritten on its own line fails without writing.
func TestSyncRosterAdminPasswordRefusesLayoutsItCannotRewrite(t *testing.T) {
	for name, body := range map[string]string{
		"flow mapping":         "schema_version: 3\nfreeipa:\n  admin: {principal: admin, password: Old-pass_1}\n",
		"block scalar":         "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: |-\n      Old-pass_1\n",
		"multi-line plain":     "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: Old-pass_1\n      continued\n",
		"encrypted (sentinel)": "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, body)
			oldPassword := "Old-pass_1"
			if name == "multi-line plain" {
				oldPassword = "Old-pass_1 continued"
			}
			got, err := SyncRosterAdminPassword(path, oldPassword, "New-pass_2")
			if err == nil {
				t.Fatalf("SyncRosterAdminPassword() = %v, nil; want an error", got)
			}
			if name == "encrypted (sentinel)" && !errors.Is(err, ErrRosterEncrypted) {
				t.Fatalf("error = %v, want ErrRosterEncrypted", err)
			}
			if strings.Contains(err.Error(), "Old-pass_1") || strings.Contains(err.Error(), "New-pass_2") {
				t.Fatalf("error leaks a password: %v", err)
			}
			if after, _ := os.ReadFile(path); string(after) != body {
				t.Fatalf("roster changed:\n%s", after)
			}
		})
	}
}

func TestRosterAdminPasswordDiffers(t *testing.T) {
	for name, tt := range map[string]struct {
		scalar string
		want   bool
	}{
		"same":      {`"Vault-pass_1"`, false},
		"stale":     {`"Old-pass_1"`, true},
		"reference": {`"{{ ipa_admin_password }}"`, false},
		"empty":     {`""`, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", tt.scalar, 1))
			got, err := RosterAdminPasswordDiffers(path, "Vault-pass_1")
			if err != nil || got != tt.want {
				t.Fatalf("RosterAdminPasswordDiffers() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	path := writeRoster(t, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	if _, err := RosterAdminPasswordDiffers(path, "Vault-pass_1"); !errors.Is(err, ErrRosterEncrypted) {
		t.Fatalf("encrypted roster error = %v, want ErrRosterEncrypted", err)
	}
}

func TestVaultAdminPassword(t *testing.T) {
	for name, tt := range map[string]struct{ data, want string }{
		"plaintext":    {"---\n# FreeIPA\nipa_admin_password: \"Vault-pass_1\"\n", "Vault-pass_1"},
		"encrypted":    {"$ANSIBLE_VAULT;1.1;AES256\n6162636465\n", ""},
		"missing":      {"grafana_admin_password: x\n", ""},
		"not a string": {"ipa_admin_password: [a]\n", ""},
		"not yaml":     {"ipa_admin_password: [\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := VaultAdminPassword([]byte(tt.data)); got != tt.want {
				t.Fatalf("VaultAdminPassword() = %q, want %q", got, tt.want)
			}
		})
	}
}
