package cmd

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A freeipa_roster_file under the home directory (~/...), which Ansible's
// include_vars expands, is the file pilot considers too: a roster
// candidate, and checked by the deploy preflight (AGENTS.md §5.11; PR #148
// review, P3).
func TestRosterReferencesUnderTheHomeDirectoryAreFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	roster := filepath.Join(home, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, roster, syncTestRoster(`"Stale-pass_1"`))
	dir := t.TempDir()
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Vault-pass_2\"\n")
	const ref = "~/.vault/ipa-identity.yaml"

	if got := rosterCandidates(dir, "", []string{ref}); !slices.Contains(got, roster) {
		t.Fatalf("rosterCandidates() = %v, want %s among them", got, roster)
	}
	if got := resolveRosterPath(dir, ref); got != roster {
		t.Fatalf("resolveRosterPath() = %s, want %s", got, roster)
	}
	var out bytes.Buffer
	warnFreeIPARosterAdminDrift(&out, filepath.Join(dir, "inventory.yml"), map[string]map[string]any{"h1": {"freeipa_roster_file": ref}})
	if !strings.Contains(out.String(), "warning: "+roster+" ") {
		t.Fatalf("no preflight warning for the ~/ roster:\n%s", out.String())
	}
}
