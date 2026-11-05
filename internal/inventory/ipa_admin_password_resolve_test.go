package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIPAAdminPasswordFollowsThePlaybook(t *testing.T) {
	const secret = "Sample-Admin-1"
	roster := []byte("schema_version: 3\nfreeipa:\n  admin:\n    password: \"" + secret + "-roster\"\n")
	for _, tc := range []struct {
		name          string
		vault, roster []byte
		want          string
		unusable      bool
	}{
		{name: "vault wins", vault: []byte("ipa_admin_password: \"" + secret + "\"\n"), roster: roster, want: secret},
		{name: "unsafe vault value is literal", vault: []byte("ipa_admin_password: !unsafe \"{{" + secret + "\"\n"), roster: roster, want: "{{" + secret},
		{name: "no vars file falls back to the roster", roster: roster, want: secret + "-roster"},
		{name: "empty vault value falls back (default(..., true))", vault: []byte("ipa_admin_password: \"\"\n"), roster: roster, want: secret + "-roster"},
		{name: "vault template", vault: []byte("ipa_admin_password: \"{{ lookup('env', 'X') }}\"\n"), roster: roster, unusable: true},
		{name: "inline vault value", vault: []byte("ipa_admin_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  3132\n"), roster: roster, unusable: true},
		{name: "unquoted number", vault: []byte("ipa_admin_password: 123456789\n"), roster: roster, unusable: true},
		{name: "roster template", roster: []byte("freeipa:\n  admin:\n    password: \"{{ x }}\"\n"), unusable: true},
		{name: "too short", vault: []byte("ipa_admin_password: \"short\"\n"), roster: roster, unusable: true},
		{name: "none anywhere", roster: []byte("schema_version: 3\n"), unusable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveIPAAdminPassword(tc.vault, tc.roster)
			if tc.unusable {
				if !errors.Is(err, ErrIPAAdminPasswordUnusable) {
					t.Fatalf("err = %v, want ErrIPAAdminPasswordUnusable", err)
				}
				if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "short") || strings.Contains(err.Error(), "123456789") {
					t.Fatalf("error shows the value: %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// The two failures ansible-vault view reports, from real stderr
// (ansible-core 2.19.2, captured 2026-10-30): with no secret it prompts,
// and closed stdin ends the prompt with EOFError.
func TestClassifyVaultViewUsesRealStderr(t *testing.T) {
	for file, want := range map[string]error{
		"ansible-vault-view-no-secret.stderr":    ErrNoVaultSecret,
		"ansible-vault-view-wrong-secret.stderr": ErrVaultDecryptFailed,
	} {
		stderr, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		if got := classifyVaultView("vars.yml", errors.New("exit status 1"), string(stderr)); !errors.Is(got, want) {
			t.Fatalf("%s: %v, want %v", file, got, want)
		}
	}
	if got := classifyVaultView("vars.yml", errors.New("exit status 1"), "[ERROR]: something else"); errors.Is(got, ErrNoVaultSecret) || errors.Is(got, ErrVaultDecryptFailed) {
		t.Fatalf("an unknown failure was classified: %v", got)
	}
}
