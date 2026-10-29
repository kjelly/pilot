package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// A roster or a vault whose YAML aliases refer to themselves is skipped by
// the deploy preflight like invalid YAML: it neither crashes nor hangs
// `pilot deploy`, prints no warning it cannot back up, and never shows a
// password (PR #148 round 11). The child process keeps a stack overflow
// from taking the package with it.
func TestWarnRosterAdminDriftSurvivesCyclicInputs(t *testing.T) {
	const cyclicRoster = "schema_version: 3\nfreeipa: &f\n  <<: *f\n"
	const cyclicVault = "&r\n<<: *r\nipa_admin_password: \"Vault-pass_2\"\n"
	for name, tc := range map[string]struct{ roster, vault string }{
		"cyclic roster":  {cyclicRoster, "ipa_admin_password: \"Vault-pass_2\"\n"},
		"cyclic vault":   {syncTestRoster(`"Stale-pass_1"`), cyclicVault},
		"fan-out roster": {"schema_version: 3\n" + fanOutRosterLevels(40) + "freeipa:\n  admin: {<<: *a39}\n", "ipa_admin_password: \"Vault-pass_2\"\n"},
		"fan-out vault":  {syncTestRoster(`"Stale-pass_1"`), fanOutRosterLevels(40) + "<<: *a39\n"},
		"cyclic both":    {cyclicRoster, cyclicVault},
	} {
		t.Run(name, func(t *testing.T) {
			runIsolated(t, 20*time.Second, func(t *testing.T) {
				dir := t.TempDir()
				writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), tc.vault)
				writeSyncFile(t, filepath.Join(dir, ".vault", "ipa-identity.yaml"), tc.roster)
				var out bytes.Buffer
				warnFreeIPARosterAdminDrift(&out, filepath.Join(dir, "inventory.yml"), map[string]map[string]any{"h1": {}})
				for _, secret := range []string{"Vault-pass_2", "Stale-pass_1"} {
					if strings.Contains(out.String(), secret) {
						t.Fatalf("output shows a password:\n%s", out.String())
					}
				}
				if strings.Contains(out.String(), "不同") {
					t.Fatalf("a roster that could not be read was reported as differing:\n%s", out.String())
				}
				// Nothing was changed.
				if got, _ := os.ReadFile(filepath.Join(dir, ".vault", "ipa-identity.yaml")); string(got) != tc.roster {
					t.Fatalf("roster changed:\n%s", got)
				}
			})
		})
	}
}

// fanOutRosterLevels is n anchored mappings, each merging the one below it
// twice: acyclic, with 2^n paths from the last to the first.
func fanOutRosterLevels(n int) string {
	var b strings.Builder
	b.WriteString("l0: &a0 {k: 1}\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "l%d: &a%d {<<: [*a%d, *a%d]}\n", i, i, i-1, i-1)
	}
	return b.String()
}
