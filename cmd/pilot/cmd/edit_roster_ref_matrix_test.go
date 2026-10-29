package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

// rosterRefForm is one way a workspace can name a roster: by a
// freeipa_roster_file in hosts.yml (absolute or relative, inside .vault/ or
// not, through a symlink either way), in group_vars/ or host_vars/, or not
// at all (the default .vault/ipa-identity.yaml).
type rosterRefForm struct {
	// inScope: the roster is one of the session's own .vault/ files, by
	// the spelling pilot edit writes it under, so plan and apply write it.
	inScope bool
	// setup returns the hosts.yml freeipa_roster_file for host nexus (""
	// for none), the file holding the roster, and the name a warning
	// gives it. It writes group_vars/host_vars and symlinks itself.
	setup func(t *testing.T, dir, ext string) (hostRef, file, shown string)
	// nfs: what enabling freeipa-nfs-server writes for this form, when
	// it differs from file (it only reads hosts.yml's host vars).
	nfsFile func(dir string) string
	// dangling: a symlink form, so a "missing" roster leaves a dangling
	// link. Pilot cannot resolve it, on main as here: enabling the role
	// fails on every front-end with nothing written, and a dangling link
	// in .vault/ (inVault) stops a plan or an apply before any step,
	// since the workspace cannot be snapshotted.
	dangling, inVault bool
}

func rosterRefForms() map[string]rosterRefForm {
	vaultRoster := func(dir string) string { return filepath.Join(dir, ".vault", "ipa-identity.yaml") }
	return map[string]rosterRefForm{
		"default .vault/ipa-identity.yaml": {inScope: true, setup: func(t *testing.T, dir, _ string) (string, string, string) {
			return "", vaultRoster(dir), ".vault/ipa-identity.yaml"
		}},
		"absolute inside .vault/": {inScope: true, setup: func(t *testing.T, dir, _ string) (string, string, string) {
			f := filepath.Join(dir, ".vault", "nfs.yaml")
			return f, f, ".vault/nfs.yaml"
		}},
		"relative inside .vault/": {inScope: true, setup: func(t *testing.T, dir, _ string) (string, string, string) {
			return ".vault/nfs.yaml", filepath.Join(dir, ".vault", "nfs.yaml"), ".vault/nfs.yaml"
		}},
		"absolute outside": {setup: func(t *testing.T, _, ext string) (string, string, string) {
			f := filepath.Join(ext, "ipa-identity.yaml")
			return f, f, f
		}},
		"relative outside .vault/": {setup: func(t *testing.T, dir, _ string) (string, string, string) {
			return "rosters/ipa-identity.yaml", filepath.Join(dir, "rosters", "ipa-identity.yaml"), "rosters/ipa-identity.yaml"
		}},
		"symlink in .vault/ to outside": {inScope: true, dangling: true, inVault: true, setup: func(t *testing.T, dir, ext string) (string, string, string) {
			target := filepath.Join(ext, "ipa-identity.yaml")
			mustSymlink(t, target, filepath.Join(dir, ".vault", "linked.yaml"))
			return ".vault/linked.yaml", target, ".vault/linked.yaml"
		}},
		"symlink outside to .vault/": {inScope: true, dangling: true, setup: func(t *testing.T, dir, _ string) (string, string, string) {
			mustSymlink(t, "../.vault/ipa-identity.yaml", filepath.Join(dir, "rosters", "link.yaml"))
			return "rosters/link.yaml", vaultRoster(dir), "rosters/link.yaml"
		}},
		"group_vars, relative outside": {setup: func(t *testing.T, dir, _ string) (string, string, string) {
			writeSyncFile(t, filepath.Join(dir, "group_vars", "freeipa-client.yml"), "freeipa_roster_file: rosters/ipa-identity.yaml\n")
			return "", filepath.Join(dir, "rosters", "ipa-identity.yaml"), "rosters/ipa-identity.yaml"
		}, nfsFile: vaultRoster},
		"host_vars, absolute outside": {setup: func(t *testing.T, dir, ext string) (string, string, string) {
			f := filepath.Join(ext, "ipa-identity.yaml")
			writeSyncFile(t, filepath.Join(dir, "host_vars", "nexus.yml"), "freeipa_roster_file: "+f+"\n")
			return "", f, f
		}, nfsFile: vaultRoster},
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// refWorkspace builds a workspace whose host nexus names its roster as
// form does; it returns the workspace, the outside directory, the roster
// file and its shown name.
func refWorkspace(t *testing.T, form rosterRefForm) (dir, ext, file, shown string) {
	t.Helper()
	dir, ext = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rosters"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Old-pass_1\"\n")
	hostRef, file, shown := form.setup(t, dir, ext)
	host := "hosts:\n  nexus:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n"
	if hostRef != "" {
		host += "    freeipa_roster_file: " + hostRef + "\n"
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), host)
	return dir, ext, file, shown
}

// seedNFSEntry gives the roster at file nexus's nfs.servers entry, as the
// step itself would, and removes the lock files that left behind.
func seedNFSEntry(t *testing.T, file string) {
	t.Helper()
	if _, err := inventory.EnsureRosterCurrent(file, inventory.RosterMigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.AppendMissingNFSServerStub(file, "nexus", "ipa.pilot.internal"); err != nil {
		t.Fatal(err)
	}
	target, _ := filepath.EvalSymlinks(file)
	for _, suffix := range []string{".pilot-migrate.lock", ".pilot-remove.lock"} {
		os.Remove(target + suffix)
	}
}

// refFrontEnds run a scenario the four ways pilot edit does and return
// its error (the scenario error of a rolled-back apply).
func refFrontEnds() map[string]func(t *testing.T, dir string, scenario editScenario) error {
	return map[string]func(t *testing.T, dir string, scenario editScenario) error{
		"plan": func(t *testing.T, dir string, scenario editScenario) error {
			_, err := planEditScenario(dir, scenario, editAgentSessionOptions{})
			return err
		},
		"apply": func(t *testing.T, dir string, scenario editScenario) error {
			result, err := applyEditScenario(dir, "issue-146-ref-matrix", scenario, editAgentSessionOptions{})
			if err != nil {
				return err
			}
			if result.RolledBack {
				return result.ScenarioErr
			}
			return nil
		},
		"terminal router": func(t *testing.T, dir string, scenario editScenario) error {
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			return d.run(&r, scenario)
		},
		"--actions": func(t *testing.T, dir string, scenario editScenario) error {
			var stdout, stderr bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			oldDir := editDir
			editDir = dir
			t.Cleanup(func() { editDir = oldDir })
			return runAutomatedEditWorkflow(cmd, scenario, false, "")
		},
	}
}

// Enabling freeipa-nfs-server, for every way the host can name its roster,
// every state the roster can be in and every front-end (PR #148 round 6,
// P2-2): a roster outside the session's .vault/ is refused under a plan or
// an apply only when the step would change it, the plan and the apply
// agree, the outside file is byte-identical with no lock files beside it,
// and the terminal and --actions write it as on main.
func TestEnableNFSRosterRefMatrix(t *testing.T) {
	for formName, form := range rosterRefForms() {
		for _, need := range []string{"needs no write", "needs a write", "missing"} {
			for feName, run := range refFrontEnds() {
				t.Run(formName+"/"+need+"/"+feName, func(t *testing.T) {
					if feName != "--actions" {
						// Each cell has its own workspace; only --actions
						// reads a package global (editDir). Run the rest
						// side by side: under -race the matrix is the
						// package's slowest test otherwise.
						t.Parallel()
					}
					dir, ext, file, _ := refWorkspace(t, form)
					inScope := form.inScope
					if form.nfsFile != nil {
						// The NFS step reads only hosts.yml's host vars: it
						// sets and uses the default .vault roster.
						file, inScope = form.nfsFile(dir), true
					}
					switch need {
					case "needs no write":
						writeSyncFile(t, file, syncTestRoster(`"Old-pass_1"`))
						seedNFSEntry(t, file)
					case "needs a write":
						writeSyncFile(t, file, syncTestRoster(`"Old-pass_1"`))
					}
					beforeDir, beforeExt := dirContents(t, dir), dirContents(t, ext)

					err := run(t, dir, enableNFSScenario())

					if form.dangling && need == "missing" {
						if err == nil {
							t.Fatal("enabling the role through a dangling link succeeded")
						}
						assertDirUnchanged(t, dir, beforeDir)
						assertDirUnchanged(t, ext, beforeExt)
						return
					}
					automated := feName == "plan" || feName == "apply"
					refused := automated && !inScope && need != "needs no write"
					switch {
					case refused:
						if !errors.Is(err, errRosterOutsideEditScope) {
							t.Fatalf("error = %v; want errRosterOutsideEditScope", err)
						}
						if strings.Contains(err.Error(), "pilot-edit-plan-") {
							t.Errorf("error names the plan's scratch copy: %v", err)
						}
					case err != nil:
						t.Fatalf("error = %v; want success", err)
					}
					if feName == "plan" || refused || need == "needs no write" && !inScope {
						assertDirUnchanged(t, ext, beforeExt)
					}
					if feName == "plan" {
						assertDirUnchanged(t, dir, beforeDir)
						return
					}
					if refused {
						return
					}
					data, rerr := os.ReadFile(file)
					if rerr != nil || !strings.Contains(string(data), "nexus") {
						t.Fatalf("roster %s has no nexus entry (err=%v):\n%s", file, rerr, data)
					}
				})
			}
		}
	}
}

// A vault rotation, for every way a workspace can name a roster, every
// state the roster can be in and every front-end (PR #148 round 6, P2-2):
// a .vault/ roster holding the old password is synced (a plan previews it
// and writes nothing real); a roster outside .vault/ holding it is
// reported "pilot edit 只改…" under the same name on every front-end and
// left byte-identical; a roster already on the new password, or missing,
// gives no line.
func TestVaultRotationRosterRefMatrix(t *testing.T) {
	for formName, form := range rosterRefForms() {
		for _, need := range []string{"holds the old password", "holds the new password", "missing"} {
			for feName := range parityFrontEnds() {
				t.Run(formName+"/"+need+"/"+feName, func(t *testing.T) {
					dir, ext, file, shown := refWorkspace(t, form)
					switch need {
					case "holds the old password":
						writeSyncFile(t, file, syncTestRoster(`"Old-pass_1"`))
					case "holds the new password":
						writeSyncFile(t, file, syncTestRoster(`"New-pass_2"`))
					}
					t.Setenv(parityEnv, "New-pass_2")
					beforeDir, beforeExt := dirContents(t, dir), dirContents(t, ext)
					beforeFile, _ := os.ReadFile(file)

					run := parityFrontEnds()[feName](t, dir)
					if form.inVault && need == "missing" && (feName == "plan" || feName == "apply") {
						if run.err == nil || !strings.Contains(run.err.Error(), "compute workspace revision") {
							t.Fatalf("error = %v; want the workspace refused before any step", run.err)
						}
						assertDirUnchanged(t, dir, beforeDir)
						return
					}
					if run.err != nil {
						t.Fatalf("error = %v", run.err)
					}
					warnings := rosterWarnings(run.warnings)
					stale := need == "holds the old password"
					wantLine := ""
					if stale && !form.inScope {
						wantLine = "未同步 " + shown + "：pilot edit 只改這個 workspace .vault/ 目錄裡的"
					}
					found := false
					for _, w := range warnings {
						switch {
						case wantLine != "" && strings.HasPrefix(w, wantLine):
							found = true
						case w == rosterSyncOnlyOnChange.text && wantLine != "":
						default:
							t.Errorf("unexpected warning %q", w)
						}
					}
					if wantLine != "" && !found {
						t.Errorf("no %q among %q", wantLine, warnings)
					}
					if feName == "plan" {
						assertDirUnchanged(t, dir, beforeDir)
						assertDirUnchanged(t, ext, beforeExt)
						return
					}
					after, _ := os.ReadFile(file)
					switch {
					case stale && form.inScope:
						if pw := syncRosterPassword(t, file); pw != "New-pass_2" {
							t.Errorf("in-scope roster not synced: %q", pw)
						}
					default:
						if !bytes.Equal(after, beforeFile) {
							t.Errorf("roster %s changed:\n%s", file, after)
						}
						if !form.inScope || need != "holds the old password" {
							assertDirUnchanged(t, ext, beforeExt)
						}
					}
				})
			}
		}
	}
}
