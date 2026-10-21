package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// Keep the existing controlled history runner and its established result
// fixtures; only the filesystem changes during the authoritative probe here.
type rosterRemoveAliasProbeRunner struct {
	fakeProbeRunner
	before func(int)
}

func (r *rosterRemoveAliasProbeRunner) Run(ctx context.Context, args ...string) (*ansible.Result, error) {
	if r.before != nil {
		r.before(len(r.calls) + 1)
	}
	return r.fakeProbeRunner.Run(ctx, args...)
}

func TestRosterRemoveCmd_SelectedInventorySecretBoundary(t *testing.T) {
	for _, kind := range []string{"user", "group"} {
		for _, tree := range []string{"group_vars", "host_vars"} {
			for _, encrypted := range []bool{false, true} {
				for _, aliasAt := range []int{0, 1, 2} {
					t.Run(fmt.Sprintf("%s/%s/encrypted=%t/aliasAt=%d", kind, tree, encrypted, aliasAt), func(t *testing.T) {
						roster, inventoryPath, _, runner, args := setupRosterRemoveExternalSource(t, kind, encrypted)
						alias := filepath.Join(filepath.Dir(inventoryPath), tree)
						installAlias := func() {
							if err := os.Symlink(filepath.Dir(roster), alias); err != nil {
								t.Fatal(err)
							}
						}
						if aliasAt == 0 {
							installAlias()
						} else {
							runner.before = func(call int) {
								if call == aliasAt {
									installAlias()
								}
							}
						}
						before, err := os.ReadFile(roster)
						if err != nil {
							t.Fatal(err)
						}
						out, err := execRosterRemove(t, args)
						if err == nil || !strings.Contains(err.Error(), "outside group_vars/ and host_vars/") {
							t.Errorf("expected secret-source refusal, got err=%v output=%q", err, out)
						}
						after, readErr := os.ReadFile(roster)
						if readErr != nil {
							t.Fatal(readErr)
						}
						if !bytes.Equal(before, after) {
							t.Error("refused command changed original roster bytes")
						}
						if aliasAt == 0 && len(runner.calls) != 0 {
							t.Errorf("initial alias must be rejected before history probe, got %d calls", len(runner.calls))
						}
						if aliasAt > 0 {
							wantCalls := 2
							if encrypted && aliasAt == 1 {
								wantCalls = 1 // rejected before creating the encrypted candidate
							}
							if len(runner.calls) != wantCalls {
								t.Errorf("history probe calls=%d, want %d before refusal", len(runner.calls), wantCalls)
							}
						}
					})
				}
			}
		}
	}
}

func TestRosterRemoveCmd_LegitimateExternalSource(t *testing.T) {
	for _, kind := range []string{"user", "group"} {
		for _, encrypted := range []bool{false, true} {
			for _, dryRun := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/encrypted=%t/dryRun=%t", kind, encrypted, dryRun), func(t *testing.T) {
					roster, _, password, runner, args := setupRosterRemoveExternalSource(t, kind, encrypted)
					before, err := os.ReadFile(roster)
					if err != nil {
						t.Fatal(err)
					}
					if dryRun {
						args = append(args, "--dry-run")
					}
					out, err := execRosterRemove(t, args)
					if err != nil {
						t.Fatalf("remove failed: %v output=%q", err, out)
					}
					after, err := os.ReadFile(roster)
					if err != nil {
						t.Fatal(err)
					}
					if dryRun {
						if !bytes.Equal(before, after) {
							t.Fatal("dry-run changed roster bytes")
						}
						if len(runner.calls) != 1 {
							t.Fatalf("dry-run history calls=%d, want 1", len(runner.calls))
						}
						return
					}
					if len(runner.calls) != 2 {
						t.Fatalf("history calls=%d, want 2", len(runner.calls))
					}
					if encrypted {
						if !bytes.HasPrefix(after, []byte("$ANSIBLE_VAULT")) {
							t.Fatal("roster lost encryption")
						}
						after = viewFileForTest(t, roster, password)
					}
					name := "alice"
					if kind == "group" {
						name = "team-never-applied"
					}
					if bytes.Contains(after, []byte("name: "+name)) {
						t.Fatalf("entry %s remains after removal", name)
					}
				})
			}
		}
	}
}

func setupRosterRemoveExternalSource(t *testing.T, kind string, encrypted bool) (roster, inventoryPath, password string, runner *rosterRemoveAliasProbeRunner, args []string) {
	t.Helper()
	// Both the selected inventory and roster live outside cwd and outside
	// each other's ancestry, so cwd/destination checks cannot discover aliases.
	workspace := t.TempDir()
	external := t.TempDir()
	inventoryPath = filepath.Join(workspace, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte("all:\n  hosts:\n    localhost:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roster = filepath.Join(external, "roster.yaml")
	fixture, name := removeUserCLIFixture, "alice"
	result := `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`
	if kind == "group" {
		fixture, name = removeGroupCLIFixture, "team-never-applied"
		result = `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`
	}
	if err := os.WriteFile(roster, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	args = []string{"roster", "remove-" + kind, roster, name, "-i", inventoryPath, "--cascade-references"}
	if encrypted {
		requireAnsibleVault(t)
		password = writeVaultPasswordFile(t, filepath.Join(workspace, "vault-pass"), "s3cret-pw")
		encryptFileForTest(t, roster, password)
		args = append(args, "--vault-password-file", password)
	}
	runner = &rosterRemoveAliasProbeRunner{fakeProbeRunner: fakeProbeRunner{result: result}}
	oldRunner := rosterRemoveTestProbeRunner
	rosterRemoveTestProbeRunner = runner
	t.Cleanup(func() { rosterRemoveTestProbeRunner = oldRunner })
	return
}
