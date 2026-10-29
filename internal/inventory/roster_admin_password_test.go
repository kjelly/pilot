package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func decodedAdminPassword(t *testing.T, data []byte) any {
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
			if pw := decodedAdminPassword(t, after); pw != newPassword {
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
			// No lock files beside a roster that did not change.
			if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
				t.Fatalf("left %d files beside the roster: %v", len(entries)-1, entries)
			}
		})
	}
}

// A roster that migration or removal holds is not rewritten under it.
func TestSyncRosterAdminPasswordRespectsRosterLocks(t *testing.T) {
	for _, suffix := range []string{".pilot-migrate.lock", ".pilot-remove.lock"} {
		t.Run(suffix, func(t *testing.T) {
			body := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
			path := writeRoster(t, body)
			lock, err := acquireMutationLock(path + suffix)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.release() //nolint:errcheck
			if _, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); !errors.Is(err, ErrMutationLocked) {
				t.Fatalf("error = %v, want ErrMutationLocked", err)
			}
			if after, _ := os.ReadFile(path); string(after) != body {
				t.Fatalf("roster changed under the lock:\n%s", after)
			}
		})
	}
}

// The atomic replacement keeps the roster's own mode.
func TestSyncRosterAdminPasswordKeepsMode(t *testing.T) {
	path := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword() = %v, %v", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("roster mode = %v, %v; want 0640", info.Mode().Perm(), err)
	}
}

// A symlinked roster is updated where it points; the link stays a link.
func TestSyncRosterAdminPasswordWritesThroughSymlink(t *testing.T) {
	target := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1))
	link := filepath.Join(t.TempDir(), "ipa-identity.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := SyncRosterAdminPassword(link, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword() = %v, %v", got, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the roster link was replaced: %v, %v", info, err)
	}
	after, _ := os.ReadFile(target)
	if pw := decodedAdminPassword(t, after); pw != "New-pass_2" {
		t.Fatalf("link target freeipa.admin.password = %q", pw)
	}
}

// Rosters that hold the old password where it cannot be rewritten by
// itself — encrypted inline, behind an alias or merge key — fail without
// writing and without a password in the error. Drift is still judged on the
// value YAML resolves. (A new password holding a Jinja delimiter is no
// longer refused: it is written !unsafe, see
// TestSyncRosterAdminPasswordWritesADelimiterBearingPasswordUnsafe.)
func TestSyncRosterAdminPasswordRefusesValuesItCannotOwn(t *testing.T) {
	inlineVault := "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6162636465\n"
	alias := "schema_version: 3\nshared: &pw Old-pass_1\nfreeipa:\n  admin:\n    principal: admin\n    password: *pw\n"
	merge := "schema_version: 3\nbase: &base\n  principal: admin\n  password: Old-pass_1\nfreeipa:\n  admin:\n    <<: *base\n"
	for name, tt := range map[string]struct {
		body, newPassword string
		encrypted         bool
		differs           bool // against vault password "Vault-pass_9"
	}{
		"inline !vault": {inlineVault, "New-pass_2", true, false},
		"alias":         {alias, "New-pass_2", false, true},
		"merge key":     {merge, "New-pass_2", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, tt.body)
			got, err := SyncRosterAdminPassword(path, "Old-pass_1", tt.newPassword)
			if err == nil {
				t.Fatalf("SyncRosterAdminPassword() = %v, nil; want an error", got)
			}
			if errors.Is(err, ErrRosterEncrypted) != tt.encrypted {
				t.Fatalf("error = %v; want ErrRosterEncrypted %v", err, tt.encrypted)
			}
			if strings.Contains(err.Error(), "Old-pass_1") || strings.Contains(err.Error(), "New") {
				t.Fatalf("error leaks a password: %v", err)
			}
			if after, _ := os.ReadFile(path); string(after) != tt.body {
				t.Fatalf("roster changed:\n%s", after)
			}
			if differs, err := RosterAdminPasswordDiffers(path, "Vault-pass_9"); err != nil || differs != tt.differs {
				t.Fatalf("RosterAdminPasswordDiffers() = %v, %v; want %v", differs, err, tt.differs)
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

// A password written over several lines — quoted or plain — is refused,
// the roster unchanged, and the error names neither password: rewriting
// only its first line would leave the rest of the old password in the
// file, as a comment where the next line starts with '#' (PR #148 review,
// F4: the sync wrote that and reported success).
func TestSyncRosterAdminPasswordRefusesAPasswordOverSeveralLines(t *testing.T) {
	const head = "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n"
	for name, tc := range map[string]struct{ value, old string }{
		"double-quoted, continued as a comment":  {`"Old-pass` + "\n      #_1\"", "Old-pass #_1"},
		"single-quoted, continued as a comment":  {`'Old-pass` + "\n      #_1'", "Old-pass #_1"},
		"double-quoted, escaped line break":      {`"Old-pass\` + "\n      _1\"", "Old-pass_1"},
		"double-quoted, comment after the close": {`"Old-pass` + "\n      _1\" # rotated", "Old-pass _1"},
		"plain":                                  {"Old-pass\n      _1", "Old-pass _1"},
	} {
		t.Run(name, func(t *testing.T) {
			body := head + "    password: " + tc.value + "\n  defaults:\n    group_type: posix\n"
			if got := decodedAdminPassword(t, []byte(body)); got != tc.old {
				t.Fatalf("fixture password = %q, want %q", got, tc.old)
			}
			path := writeRoster(t, body)
			got, err := SyncRosterAdminPassword(path, tc.old, "New-pass_2")
			if err == nil {
				t.Fatalf("SyncRosterAdminPassword() = %v, nil; want it refused\n%s", got, mustRead(t, path))
			}
			for _, secret := range []string{"Old-pass", "New-pass_2"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks a password: %v", err)
				}
			}
			if after := mustRead(t, path); string(after) != body {
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
		"plaintext":     {"---\n# FreeIPA\nipa_admin_password: \"Vault-pass_1\"\n", "Vault-pass_1"},
		"encrypted":     {"$ANSIBLE_VAULT;1.1;AES256\n6162636465\n", ""},
		"missing":       {"grafana_admin_password: x\n", ""},
		"not a string":  {"ipa_admin_password: [a]\n", ""},
		"inline !vault": {"ipa_admin_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465\n", ""},
		"template":      {"ipa_admin_password: \"{{ lookup('env', 'X') }}\"\n", ""},
		"number":        {"ipa_admin_password: 12345678\n", ""},
		"alias":         {"shared: &pw \"Vault-pass_1\"\nipa_admin_password: *pw\n", "Vault-pass_1"},
		"not yaml":      {"ipa_admin_password: [\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := VaultAdminPassword([]byte(tt.data)); got != tt.want {
				t.Fatalf("VaultAdminPassword() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A vault value Ansible would template is returned for comparison, so
// pilot edit can report it; anything else is not a template.
func TestVaultAdminPasswordTemplate(t *testing.T) {
	for name, tt := range map[string]struct{ data, want string }{
		"expression":    {"ipa_admin_password: \"{{ lookup('env', 'X') }}\"\n", "{{ lookup('env', 'X') }}"},
		"statement":     {"ipa_admin_password: \"pre{% raw %}x\"\n", "pre{% raw %}x"},
		"comment":       {"ipa_admin_password: \"a{#b\"\n", "a{#b"},
		"literal":       {"ipa_admin_password: \"Vault-pass_1\"\n", ""},
		"lone brace":    {"ipa_admin_password: \"pa{ss}\"\n", ""},
		"encrypted":     {"$ANSIBLE_VAULT;1.1;AES256\n6162636465\n", ""},
		"inline !vault": {"ipa_admin_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465\n", ""},
		"missing":       {"grafana_admin_password: \"{{ x }}\"\n", ""},
		"not yaml":      {"ipa_admin_password: [\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := VaultAdminPasswordTemplate([]byte(tt.data)); got != tt.want {
				t.Fatalf("VaultAdminPasswordTemplate() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Ansible compares typed values: an unquoted number or boolean roster
// password never equals the vault's string, even "12345678" against
// 12345678. Go judges it the same way — it differs, the sync reports it
// and writes nothing (PR #148 re-review, F5).
func TestRosterAdminPasswordNonStringNeverMatchesTheVault(t *testing.T) {
	for name, scalar := range map[string]string{
		"int":   `12345678`,
		"float": `1234.5678`,
		"bool":  `true`,
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(rosterAdminFixture, "%s", scalar, 1)
			path := writeRoster(t, body)
			if got, err := CompareRosterAdminPassword(path, scalar); err != nil || got != RosterAdminNotString {
				t.Fatalf("CompareRosterAdminPassword() = %v, %v; want RosterAdminNotString", got, err)
			}
			if differs, err := RosterAdminPasswordDiffers(path, scalar); err != nil || !differs {
				t.Fatalf("RosterAdminPasswordDiffers(same text) = %v, %v; want true", differs, err)
			}
			if got, err := SyncRosterAdminPassword(path, scalar, "New-pass_2"); err != nil || got != RosterAdminNotString {
				t.Fatalf("SyncRosterAdminPassword() = %v, %v; want RosterAdminNotString", got, err)
			}
			if after, _ := os.ReadFile(path); string(after) != body {
				t.Fatalf("roster changed:\n%s", after)
			}
			if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
				t.Fatalf("left %d files beside the roster", len(entries)-1)
			}
		})
	}
	quoted := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", `"12345678"`, 1))
	if got, err := CompareRosterAdminPassword(quoted, "12345678"); err != nil || got != RosterAdminCurrent {
		t.Fatalf("quoted number: CompareRosterAdminPassword() = %v, %v; want RosterAdminCurrent", got, err)
	}
}

// A first look that catches another writer between truncating the roster
// and writing it reads an empty file; the sync must not take that for a
// roster without a password and skip it, but decide under the lock
// (PR #148 re-review). The hook plays the writer finishing before the lock
// is taken.
func TestSyncRosterAdminPasswordDecidesAnEmptyReadUnderTheLock(t *testing.T) {
	path := writeRoster(t, "")
	full := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
	afterRosterLockHook = func() {
		if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterRosterLockHook = nil })
	if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword(empty first read) = %v, %v; want RosterAdminUpdated", got, err)
	}
	if after, _ := os.ReadFile(path); decodedAdminPassword(t, after) != "New-pass_2" {
		t.Fatalf("roster not synced:\n%s", after)
	}
}

// The first look decides "empty" from the bytes it read, not from a second
// read: a writer that finishes between the two would otherwise turn the
// empty read into a roster without a password, skipped without the lock,
// and the roster would keep the old password while pilot edit reports
// nothing for it (issue #146). The hook plays the writer finishing in
// exactly that window.
func TestSyncRosterAdminPasswordDecidesAnEmptyReadFromTheBytesItRead(t *testing.T) {
	path := writeRoster(t, "")
	full := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
	afterRosterAdminLookHook = func() {
		if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterRosterAdminLookHook = nil })
	if got, err := SyncRosterAdminPassword(path, "Old-pass_1", "New-pass_2"); err != nil || got != RosterAdminUpdated {
		t.Fatalf("SyncRosterAdminPassword(empty first read) = %v, %v; want RosterAdminUpdated", got, err)
	}
	if after, _ := os.ReadFile(path); decodedAdminPassword(t, after) != "New-pass_2" {
		t.Fatalf("roster not synced:\n%s", after)
	}
}

// A new password holding a Jinja delimiter — only a vault's !unsafe value
// is one pilot syncs — is written tagged !unsafe, so Ansible uses it as
// written; and a roster's !unsafe tag survives a rotation to a password
// without one (PR #148 re-review, round 4: replaceScalar dropped it).
func TestSyncRosterAdminPasswordWritesADelimiterBearingPasswordUnsafe(t *testing.T) {
	for name, tt := range map[string]struct{ oldScalar, newPassword string }{
		"delimiters in the new password": {`"Old-pass_1"`, "New{{pass}}"},
		"roster already !unsafe":         {`!unsafe "Old-pass_1"`, "New-pass_2"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", tt.oldScalar, 1))
			if got, err := SyncRosterAdminPassword(path, "Old-pass_1", tt.newPassword); err != nil || got != RosterAdminUpdated {
				t.Fatalf("SyncRosterAdminPassword() = %v, %v; want RosterAdminUpdated", got, err)
			}
			after, _ := os.ReadFile(path)
			if pw := decodedAdminPassword(t, after); pw != tt.newPassword {
				t.Fatalf("freeipa.admin.password = %q, want the new password", pw)
			}
			_, doc, err := readRosterNode(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, value, _ := rosterAdminPassword(doc); value.ShortTag() != "!unsafe" || !strings.Contains(string(after), "  # rotated with the vault") {
				t.Fatalf("rewritten line lost !unsafe or its comment:\n%s", after)
			}
			if got, err := CompareRosterAdminPassword(path, tt.newPassword); err != nil || got != RosterAdminCurrent {
				t.Fatalf("CompareRosterAdminPassword() = %v, %v; want RosterAdminCurrent", got, err)
			}
		})
	}
}

// One classifier judges every password form on both sides
// (ansibleScalarKind): what the roster compare and sync, and the vault's
// readers, make of each (PR #148 re-review, round 4: !unsafe was skipped
// silently on both sides).
func TestAdminPasswordFormsAreJudgedAlikeOnBothSides(t *testing.T) {
	for name, tt := range map[string]struct {
		scalar  string
		roster  RosterAdminSync // CompareRosterAdminPassword against "Pass-1"
		vault   string          // VaultAdminPassword
		tmpl    bool            // VaultAdminPasswordTemplate != ""
		notStr  bool            // VaultAdminPasswordNotString
		reusing string          // VaultAdminPasswordReusable
	}{
		"double-quoted":         {`"Pass-1"`, RosterAdminCurrent, "Pass-1", false, false, "Pass-1"},
		"plain string":          {`Pass-1`, RosterAdminCurrent, "Pass-1", false, false, "Pass-1"},
		"explicit !!str":        {`!!str Pass-1`, RosterAdminCurrent, "Pass-1", false, false, "Pass-1"},
		"!unsafe":               {`!unsafe "Pass-1"`, RosterAdminCurrent, "Pass-1", false, false, "Pass-1"},
		"!unsafe with Jinja":    {`!unsafe "Pa{{ss"`, RosterAdminDiffers, "Pa{{ss", false, false, ""},
		"!unsafe digits":        {`!unsafe 12345678`, RosterAdminDiffers, "12345678", false, false, "12345678"},
		"template":              {`"{{ ipa_admin_password }}"`, RosterAdminNotLiteral, "", true, false, ""},
		"unquoted number":       {`12345678`, RosterAdminNotString, "", false, true, ""},
		"unquoted base 60":      {`190:20:30`, RosterAdminNotString, "", false, true, ""},
		"explicit !!int":        {`!!int 7`, RosterAdminNotString, "", false, true, ""},
		"quoted number":         {`"12345678"`, RosterAdminDiffers, "12345678", false, false, "12345678"},
		"!!str unquoted number": {`!!str 012345678`, RosterAdminDiffers, "012345678", false, false, "012345678"},
		"null":                  {`null`, RosterAdminNotLiteral, "", false, false, ""},
		"empty":                 {`""`, RosterAdminNotLiteral, "", false, false, ""},
		"inline !vault":         {"!vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6162636465", RosterAdminNotLiteral, "", false, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", tt.scalar, 1))
			if got, err := CompareRosterAdminPassword(path, "Pass-1"); err != nil || got != tt.roster {
				t.Errorf("roster: CompareRosterAdminPassword = %v, %v; want %v", got, err, tt.roster)
			}
			vault := []byte("ipa_admin_password: " + strings.ReplaceAll(tt.scalar, "\n      ", "\n  ") + "\n")
			if got := VaultAdminPassword(vault); got != tt.vault {
				t.Errorf("vault: VaultAdminPassword = %q, want %q", got, tt.vault)
			}
			if got := VaultAdminPasswordTemplate(vault) != ""; got != tt.tmpl {
				t.Errorf("vault: template = %v, want %v", got, tt.tmpl)
			}
			if got := VaultAdminPasswordNotString(vault); got != tt.notStr {
				t.Errorf("vault: not a string = %v, want %v", got, tt.notStr)
			}
			if got := VaultAdminPasswordReusable(vault); got != tt.reusing {
				t.Errorf("vault: reusable = %q, want %q", got, tt.reusing)
			}
		})
	}
}

// An empty ipa_admin_password filled in by the NFS bootstrap is written as
// a string: the old empty value resolved to null, and keeping its tag
// wrote !!null "pw", which Ansible reads as no password (PR #148
// re-review, round 4).
func TestFillFreeIPAAdminPasswordEmptyKeyWritesAString(t *testing.T) {
	for _, body := range []string{"ipa_admin_password:\nother: x\n", "ipa_admin_password: CHANGE-ME\n"} {
		path := filepath.Join(t.TempDir(), "main.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if filled, err := FillFreeIPAAdminPassword(path, "Admin-pass_1"); err != nil || !filled {
			t.Fatalf("FillFreeIPAAdminPassword(%q) = %v, %v", body, filled, err)
		}
		data, _ := os.ReadFile(path)
		if VaultAdminPassword(data) != "Admin-pass_1" || strings.Contains(string(data), "!!") {
			t.Fatalf("filled vault does not hold the password as a string:\n%s", data)
		}
	}
}

// A prepared sync holds the roster's lock until Commit or Release: no other
// roster writer gets in between the decision and the write, and Release
// leaves the roster as it was (PR #148 re-review, round 4: pilot edit's
// vault save prepares every roster before it writes the vault).
func TestPreparedRosterAdminSyncHoldsTheLockUntilCommit(t *testing.T) {
	for _, commit := range []bool{true, false} {
		body := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
		path := writeRoster(t, body)
		prepared, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
		if err != nil || prepared.Result != RosterAdminUpdated {
			t.Fatalf("PrepareRosterAdminSync() = %+v, %v", prepared, err)
		}
		if err := AppendRosterUser(path, "erin"); !errors.Is(err, ErrMutationLocked) {
			t.Fatalf("another writer between Prepare and Commit: error = %v, want ErrMutationLocked", err)
		}
		if after, _ := os.ReadFile(path); string(after) != body {
			t.Fatalf("Prepare wrote the roster:\n%s", after)
		}
		want := "Old-pass_1"
		if commit {
			if err := prepared.Commit(); err != nil {
				t.Fatal(err)
			}
			want = "New-pass_2"
		} else {
			prepared.Release()
		}
		prepared.Release() // safe again
		if after, _ := os.ReadFile(path); decodedAdminPassword(t, after) != want {
			t.Fatalf("commit=%v: freeipa.admin.password = %v, want %s", commit, decodedAdminPassword(t, after), want)
		}
		if err := AppendRosterUser(path, "erin"); err != nil {
			t.Fatalf("commit=%v: the lock was not released: %v", commit, err)
		}
	}
}

// Prepare refuses, under the lock and before its caller writes anything
// else, a roster writeLockedRoster would refuse: the vault save must not
// write the vault and then find the roster unwritable (PR #148 round 5,
// F2). Nothing stays locked. Root writes a 0400 roster, so it is
// prepared as usual.
func TestPrepareRosterAdminSyncRefusesAnUnwritableRoster(t *testing.T) {
	body := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
	path := writeRoster(t, body)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
	if os.Geteuid() == 0 {
		if err != nil || prepared.Result != RosterAdminUpdated {
			t.Fatalf("PrepareRosterAdminSync() as root = %+v, %v; want it prepared", prepared, err)
		}
		prepared.Release()
		return
	}
	if !errors.Is(err, ErrRosterNotWritable) || !strings.Contains(err.Error(), "is not writable by this user") {
		t.Fatalf("PrepareRosterAdminSync() = %+v, %v; want ErrRosterNotWritable", prepared, err)
	}
	// Refused before any lock file was created (PR #148 review, P2-1), so
	// nothing can stay locked; once writable, the roster locks at once.
	assertNoLockFiles(t, path)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	lk, err := lockRosterFile(path)
	if err != nil {
		t.Fatalf("Prepare left the roster locked: %v", err)
	}
	lk.release() //nolint:errcheck
	if after, _ := os.ReadFile(path); string(after) != body {
		t.Fatalf("roster changed:\n%s", after)
	}
}

// As root (pilot-cli under `docker run`), a 0400 roster is writable, as
// root's writer finds it: the probe and Prepare let it through and the
// commit writes it, so a rotation syncs it instead of refusing the save.
func TestRootWritesA0400RosterThroughPrepareAndProbe(t *testing.T) {
	requireRoot(t)
	body := strings.Replace(rosterAdminFixture, "%s", `"Old-pass_1"`, 1)
	path := writeRoster(t, body)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := ProbeRosterWrite(path); err != nil {
		t.Fatalf("ProbeRosterWrite() as root = %v, want nil", err)
	}
	prepared, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
	if err != nil || prepared.Result != RosterAdminUpdated {
		t.Fatalf("PrepareRosterAdminSync() as root = %+v, %v", prepared, err)
	}
	if err := prepared.Commit(); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); decodedAdminPassword(t, after) != "New-pass_2" {
		t.Fatalf("roster after the commit:\n%s", after)
	}
}

// Cyclic alias and merge graphs. yaml.v3 refuses them only when decoding into
// a Go value; a yaml.Node keeps every alias unexpanded, so the walk that
// follows merge keys looped until the stack overflowed (PR #148 round 11).
var cyclicYAMLFixtures = map[string]string{
	"self merge":               "schema_version: 3\nfreeipa: &f\n  <<: *f\n",
	"merge in a sequence":      "schema_version: 3\nfreeipa: &f\n  <<: [*f]\n",
	"two-node cycle":           "schema_version: 3\nfreeipa: &f\n  admin: &a\n    <<: *f\n  <<: *a\n",
	"explicit-key cycle":       "schema_version: 3\nfreeipa: &f\n  admin: *f\n",
	"explicit-key merge cycle": "schema_version: 3\nfreeipa: &f\n  admin: *f\n  <<: *f\n",
	"cycle outside the lookup": "schema_version: 3\nother: &o\n  <<: *o\nfreeipa:\n  admin:\n    password: Old-pass_1\n",
	"cycle through a sequence": "schema_version: 3\nlist: &l [*l]\nfreeipa:\n  admin:\n    password: Old-pass_1\n",
}

// fanOutYAML is a document of n levels, each merging the one below it twice:
// acyclic, but 2^n paths from the top to the bottom. top is the node the
// last line anchors the chain under.
func fanOutYAML(n int, indent string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%sl0: &a0 {k: 1}\n", indent)
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "%sl%d: &a%d {<<: [*a%d, *a%d]}\n", indent, i, i, i-1, i-1)
	}
	return b.String()
}

func TestRosterAdminCyclicYAMLDoesNotCrash(t *testing.T) {
	for name, body := range cyclicYAMLFixtures {
		t.Run(name, func(t *testing.T) {
			runIsolated(t, 20*time.Second, func(t *testing.T) {
				path := writeRoster(t, body)
				dir := filepath.Dir(path)

				got, err := CompareRosterAdminPassword(path, "Vault-pass_1")
				if err == nil || errors.Is(err, ErrRosterEncrypted) {
					t.Fatalf("CompareRosterAdminPassword() = %v, %v; want the cycle reported", got, err)
				}
				if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "refer to themselves") || !strings.Contains(err.Error(), "by hand") {
					t.Fatalf("error does not name the roster, the cycle and the hand edit: %v", err)
				}
				if differs, err := RosterAdminPasswordDiffers(path, "Vault-pass_1"); err == nil || differs {
					t.Fatalf("RosterAdminPasswordDiffers() = %v, %v; want the cycle reported", differs, err)
				}

				prepared, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
				if !errors.Is(err, ErrRosterNeedsHandEdit) || errors.Is(err, ErrRosterEncrypted) {
					t.Fatalf("PrepareRosterAdminSync() error = %v; want a hand-edit report", err)
				}
				if prepared != nil {
					prepared.Release()
				}
				for _, secret := range []string{"Old-pass_1", "New-pass_2", "Vault-pass_1"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("error leaks a password: %v", err)
					}
				}
				if after := mustRead(t, path); string(after) != body {
					t.Fatalf("roster changed:\n%s", after)
				}
				if entries, _ := os.ReadDir(dir); len(entries) != 1 {
					t.Fatalf("PrepareRosterAdminSync left files beside the roster: %v", entries)
				}
			})
		})
	}
	for name, body := range map[string]string{
		"cyclic vault root":      "&r\n<<: *r\nk: 1\n",
		"cyclic value":           "ipa_admin_password: &p\n  <<: *p\n",
		"cycle beside the value": "other: &o [*o]\nipa_admin_password: \"Vault-pass_1\"\n",
		"merge cycle, no value":  "base: &b\n  <<: *b\nipa_admin_password: *b\n",
	} {
		t.Run("vault "+name, func(t *testing.T) {
			runIsolated(t, 20*time.Second, func(t *testing.T) {
				data := []byte(body)
				if got := VaultAdminPassword(data); got != "" {
					t.Fatalf("VaultAdminPassword() = %q, want \"\"", got)
				}
				if got := VaultAdminPasswordReusable(data); got != "" {
					t.Fatalf("VaultAdminPasswordReusable() = %q, want \"\"", got)
				}
				if got := VaultAdminPasswordTemplate(data); got != "" {
					t.Fatalf("VaultAdminPasswordTemplate() = %q, want \"\"", got)
				}
				if VaultAdminPasswordNotString(data) || VaultAdminPasswordEncrypted(data) {
					t.Fatal("a cyclic vault is neither not-a-string nor encrypted")
				}
				if got := VaultAdminPasswordText(data); got != "" {
					t.Fatalf("VaultAdminPasswordText() = %q, want \"\"", got)
				}
			})
		})
	}
}

// An acyclic document may share one anchor over and over — each level here
// merges the one below it twice, so 2^40 paths lead to the bottom — and is
// read in linear time: the answer is the same as for a document that shares
// nothing (a roster without a password to keep in step).
func TestRosterAdminFanOutAliasesStayLinear(t *testing.T) {
	t.Run("roster", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			body := "schema_version: 3\nlevels:\n" + fanOutYAML(40, "  ") + "freeipa:\n  admin: {<<: *a39}\n"
			path := writeRoster(t, body)
			got, err := CompareRosterAdminPassword(path, "Vault-pass_1")
			if err != nil || got != RosterAdminNotLiteral {
				t.Fatalf("CompareRosterAdminPassword() = %v, %v; want RosterAdminNotLiteral, nil", got, err)
			}
			prepared, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
			if err != nil || prepared.Result != RosterAdminNotLiteral {
				t.Fatalf("PrepareRosterAdminSync() = %+v, %v; want RosterAdminNotLiteral, nil", prepared, err)
			}
			prepared.Release()
			if after := mustRead(t, path); string(after) != body {
				t.Fatalf("roster changed")
			}
		})
	})
	t.Run("vault", func(t *testing.T) {
		runIsolated(t, 10*time.Second, func(t *testing.T) {
			data := []byte(fanOutYAML(40, "") + "<<: *a39\n")
			if VaultAdminPassword(data) != "" || VaultAdminPasswordText(data) != "" || VaultAdminPasswordNotString(data) {
				t.Fatal("a vault without ipa_admin_password reported one")
			}
		})
	})
}

// A password supplied through a merge key, or through the same anchor merged
// twice, is found as before — a diamond is not a cycle — and reported for a
// hand edit, never rewritten.
func TestRosterAdminPasswordThroughSharedMergeSources(t *testing.T) {
	for name, body := range map[string]string{
		"base merged once":  "schema_version: 3\nbase: &base\n  password: Old-pass_1\nfreeipa:\n  admin:\n    <<: *base\n",
		"base merged twice": "schema_version: 3\nbase: &base\n  password: Old-pass_1\nfreeipa:\n  admin:\n    <<: [*base, *base]\n",
		"diamond":           "schema_version: 3\nbase: &base {password: Old-pass_1}\nl: &l {<<: [*base, *base]}\nfreeipa:\n  admin: {<<: [*l, *l]}\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoster(t, body)
			if got, err := CompareRosterAdminPassword(path, "Vault-pass_1"); err != nil || got != RosterAdminDiffers {
				t.Fatalf("CompareRosterAdminPassword() = %v, %v; want RosterAdminDiffers, nil", got, err)
			}
			if got, err := CompareRosterAdminPassword(path, "Old-pass_1"); err != nil || got != RosterAdminCurrent {
				t.Fatalf("CompareRosterAdminPassword(old) = %v, %v; want RosterAdminCurrent, nil", got, err)
			}
			_, err := PrepareRosterAdminSync(path, "Old-pass_1", "New-pass_2")
			if !errors.Is(err, ErrRosterNeedsHandEdit) || !strings.Contains(err.Error(), "YAML alias or merge key") {
				t.Fatalf("PrepareRosterAdminSync() error = %v; want the alias hand-edit report", err)
			}
		})
	}
}

func TestVaultAdminPasswordThroughSharedMergeSources(t *testing.T) {
	for name, data := range map[string]string{
		"merged once":  "base: &base {ipa_admin_password: Vault-pass_1}\n<<: *base\n",
		"merged twice": "base: &base {ipa_admin_password: Vault-pass_1}\n<<: [*base, *base]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := VaultAdminPassword([]byte(data)); got != "Vault-pass_1" {
				t.Fatalf("VaultAdminPassword() = %q, want Vault-pass_1", got)
			}
		})
	}
}

func TestCheckAliasGraph(t *testing.T) {
	for name, tc := range map[string]struct {
		doc    string
		cyclic bool
	}{
		"no aliases":             {"a: 1\nb: [x, y]\n", false},
		"alias to a scalar":      {"a: &x 1\nb: *x\n", false},
		"shared anchor":          {"a: &x {k: 1}\nb: *x\nc: *x\n", false},
		"diamond":                {"base: &b {k: 1}\nl: &l {<<: *b}\nr: &r {<<: *b}\ntop: {<<: [*l, *r]}\n", false},
		"same source twice":      {"base: &b {k: 1}\ntop: {<<: [*b, *b]}\n", false},
		"anchor reused in a seq": {"x: &s [1]\ny: [*s, *s, *s]\n", false},
		"self merge":             {"f: &f\n  <<: *f\n", true},
		"merge in a sequence":    {"f: &f\n  <<: [*f]\n", true},
		"two nodes":              {"f: &f\n  a: &a\n    <<: *f\n  <<: *a\n", true},
		"explicit key":           {"f: &f\n  a: *f\n", true},
		"sequence of itself":     {"s: &s [*s]\n", true},
		"cyclic document root":   {"&r\n<<: *r\nk: 1\n", true},
		"cycle after a diamond":  {"b: &b {k: 1}\nd: {<<: [*b, *b]}\nf: &f\n  <<: *f\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := parseYAMLDocument([]byte(tc.doc))
			if tc.cyclic {
				if !errors.Is(err, errCyclicYAML) || doc != nil {
					t.Fatalf("parseYAMLDocument() = %v, %v; want errCyclicYAML", doc, err)
				}
				if strings.Contains(err.Error(), tc.doc) {
					t.Fatalf("error repeats the document: %v", err)
				}
				return
			}
			if err != nil || doc == nil {
				t.Fatalf("parseYAMLDocument() = %v, %v; want the document", doc, err)
			}
		})
	}
	if _, err := parseYAMLDocument([]byte("a: [unclosed\n")); err == nil || errors.Is(err, errCyclicYAML) {
		t.Fatalf("invalid YAML error = %v; want the parser's, not the cycle's", err)
	}
	if err := checkAliasGraph(nil); err != nil {
		t.Fatalf("checkAliasGraph(nil) = %v", err)
	}
}

// The guard follows yaml.v3's own semantics: every cyclic fixture is one the
// library refuses to decode into a Go value, and every acyclic aliased
// document the library decodes passes the guard — so pilot neither accepts a
// graph the library would call self-containing nor rejects one it reads.
func TestCyclicFixturesAreRejectedByYAMLv3Too(t *testing.T) {
	for name, body := range cyclicYAMLFixtures {
		t.Run(name, func(t *testing.T) {
			var v any
			if err := yaml.Unmarshal([]byte(body), &v); err == nil || !strings.Contains(err.Error(), "contains itself") {
				t.Fatalf("yaml.Unmarshal() error = %v; want \"contains itself\"", err)
			}
		})
	}
	for name, body := range map[string]string{
		"cyclic vault root":      "&r\n<<: *r\nk: 1\n",
		"cyclic value":           "ipa_admin_password: &p\n  <<: *p\n",
		"merge cycle, no value":  "base: &b\n  <<: *b\nipa_admin_password: *b\n",
		"cycle beside the value": "other: &o [*o]\nipa_admin_password: \"Vault-pass_1\"\n",
	} {
		t.Run("vault "+name, func(t *testing.T) {
			var v any
			if err := yaml.Unmarshal([]byte(body), &v); err == nil || !strings.Contains(err.Error(), "contains itself") {
				t.Fatalf("yaml.Unmarshal() error = %v; want \"contains itself\"", err)
			}
		})
	}
	for name, body := range map[string]string{
		"merge once":         "base: &b {password: x}\nadmin: {<<: *b}\n",
		"merge twice":        "base: &b {password: x}\nadmin: {<<: [*b, *b]}\n",
		"shared scalar":      "pw: &p secret\nfreeipa: {admin: {password: *p}}\nother: {password: *p}\n",
		"shared list":        "xs: &s [1, 2]\na: *s\nb: [*s, *s]\n",
		"nested diamond":     "b: &b {k: 1}\nl: &l {<<: *b}\nr: &r {<<: *b}\ntop: {<<: [*l, *r]}\n",
		"anchor in a anchor": "a: &a {x: &b 1}\nc: *b\nd: *a\n",
	} {
		t.Run("acyclic "+name, func(t *testing.T) {
			var v any
			if err := yaml.Unmarshal([]byte(body), &v); err != nil {
				t.Fatalf("yaml.Unmarshal() error = %v; the fixture is not acyclic YAML", err)
			}
			if _, err := parseYAMLDocument([]byte(body)); err != nil {
				t.Fatalf("parseYAMLDocument() error = %v; yaml.v3 reads this document", err)
			}
		})
	}
}

// mappingValue is bounded on its own, for a caller that skips
// parseYAMLDocument: a cycle ends the lookup and a graph with 2^40 paths is
// searched once per mapping.
func TestMappingValueIsBoundedWithoutTheGraphCheck(t *testing.T) {
	for name, tc := range map[string]struct{ doc, key, want string }{
		"cycle":            {"&r\n<<: *r\nk: 1\n", "missing", ""},
		"cycle, key found": {"&r\n<<: *r\nk: 1\n", "k", "1"},
		"fan-out":          {fanOutYAML(40, "") + "<<: *a39\n", "missing", ""},
		"fan-out, found":   {fanOutYAML(40, "") + "<<: *a39\n", "k", "1"},
	} {
		t.Run(name, func(t *testing.T) {
			runIsolated(t, 10*time.Second, func(t *testing.T) {
				var doc yaml.Node
				if err := yaml.Unmarshal([]byte(tc.doc), &doc); err != nil {
					t.Fatal(err)
				}
				got, _ := mappingValue(documentRoot(&doc), tc.key)
				if (got == nil) != (tc.want == "") || got != nil && got.Value != tc.want {
					t.Fatalf("mappingValue(%q) = %v, want %q", tc.key, got, tc.want)
				}
			})
		})
	}
}
