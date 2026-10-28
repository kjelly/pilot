package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

// paritySetup is one way a vault rotation meets the workspace's rosters.
type paritySetup struct {
	// password is the new ipa_admin_password the rotation saves.
	password string
	// prepare builds the workspace in dir and returns the files a refused
	// save must leave byte-identical, and how to free a busy roster.
	prepare func(t *testing.T, dir string) (watched []string, unblock func())
	// busy: every automation front-end fails and nothing is written.
	busy bool
	// warnings each appear in exactly one of the run's roster warnings.
	warnings []string
	// synced: .vault/ipa-identity.yaml ends up with the new password.
	synced bool
}

const parityEnv = "PILOT_TEST_PARITY_ADMIN_PASSWORD"

func parityRotation(steps ...editAction) editScenario {
	return editScenario{Version: 1, Steps: append([]editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", ValueEnv: parityEnv},
		{Action: "save_vault", File: "main.yaml"},
	}, steps...)}
}

func parityWorkspace(t *testing.T, dir, roster string) (vault, defaultRoster string) {
	t.Helper()
	vault = filepath.Join(dir, ".vault", "main.yaml")
	defaultRoster = filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, vault, "ipa_admin_password: \"Old-pass_1\"\n")
	if roster != "" {
		writeSyncFile(t, defaultRoster, roster)
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n")
	return vault, defaultRoster
}

func paritySetups() map[string]paritySetup {
	busy := func(block func(t *testing.T, roster string) (string, func())) func(t *testing.T, dir string) ([]string, func()) {
		return func(t *testing.T, dir string) ([]string, func()) {
			vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
			_, unblock := block(t, roster)
			return []string{vault, roster}, unblock
		}
	}
	return map[string]paritySetup{
		"synced": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				return []string{vault, roster}, func() {}
			},
			synced: true,
		},
		"encrypted roster": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
				return []string{vault, roster}, func() {}
			},
			warnings: []string{"未同步 .vault/ipa-identity.yaml：ansible-vault 加密", rosterSyncOnlyOnChange.text},
		},
		"external roster": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, _ := parityWorkspace(t, dir, "")
				external := filepath.Join(t.TempDir(), "ipa-identity.yaml")
				writeSyncFile(t, external, syncTestRoster(`"Old-pass_1"`))
				writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: "+external+"\n")
				return []string{vault, external}, func() {}
			},
			warnings: []string{"：pilot edit 只改這個 workspace .vault/ 目錄裡的", rosterSyncOnlyOnChange.text},
		},
		"busy roster (held)":                 {password: "New-pass_2", prepare: busy(busyRosterCases()["held"]), busy: true},
		"busy roster (lock file not usable)": {password: "New-pass_2", prepare: busy(busyRosterCases()["lock file not openable"]), busy: true},
		// A roster this user cannot write refuses the save like a busy one
		// (PR #148 round 5, F2); root writes a 0400 roster, so as root the
		// rotation syncs it.
		"unwritable roster": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				if err := os.Chmod(roster, 0o400); err != nil {
					t.Fatal(err)
				}
				return []string{vault, roster}, func() {}
			},
			busy:   os.Geteuid() != 0,
			synced: os.Geteuid() == 0,
		},
		// An old value pilot cannot read leaves it unable to tell which
		// rosters held it, so the rotation names the hand check instead of
		// returning silently (PR #148 round 5, P3-c).
		"inline !vault old value": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				writeSyncFile(t, vault, "ipa_admin_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465\n")
				return []string{vault, roster}, func() {}
			},
			warnings: []string{"未同步名冊：ipa_admin_password 原本或現在是 !vault 加密值"},
		},
		"templated old value": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				writeSyncFile(t, vault, "ipa_admin_password: \"{{ lookup('env', 'IPA_ADMIN') }}\"\n")
				return []string{vault, roster}, func() {}
			},
			warnings: []string{"未同步名冊：原本的 ipa_admin_password 含 {{、{% 或 {#"},
		},
		// The old value was unquoted, the new one is saved quoted: the line
		// is about the old value, never "add quotes" (PR #148 round 6,
		// P3-6).
		"unquoted old value": {
			password: "New-pass_2",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				writeSyncFile(t, vault, "ipa_admin_password: 12345678\n")
				return []string{vault, roster}, func() {}
			},
			warnings: []string{"未同步名冊：原本的 ipa_admin_password 沒加引號"},
		},
		"templated value": {
			password: "{{ lookup('env', 'IPA_ADMIN') }}",
			prepare: func(t *testing.T, dir string) ([]string, func()) {
				vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
				return []string{vault, roster}, func() {}
			},
			warnings: []string{"未同步名冊：新的 ipa_admin_password 含 {{、{% 或 {#"},
		},
	}
}

// rosterWarnings keeps the warnings about rosters, dropping the
// workspace validation's.
func rosterWarnings(warnings []string) []string {
	var out []string
	for _, w := range warnings {
		if strings.Contains(w, "名冊") || strings.Contains(w, "freeipa.admin.password") {
			out = append(out, w)
		}
	}
	slices.Sort(out)
	return out
}

// parityRun is what one front-end reported for a rotation.
type parityRun struct {
	warnings []string
	err      error
}

// parityFrontEnds run the rotation the ways pilot edit runs a scenario:
// the router driven step by step (the terminal), --actions, an MCP plan
// and an MCP apply.
func parityFrontEnds() map[string]func(t *testing.T, dir string) parityRun {
	return map[string]func(t *testing.T, dir string) parityRun{
		"terminal router": func(t *testing.T, dir string) parityRun {
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			err := d.run(&r, parityRotation())
			return parityRun{warnings: r.rosterSyncWarnings, err: err}
		},
		"--actions": func(t *testing.T, dir string) parityRun {
			var stdout, stderr bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			oldDir := editDir
			editDir = dir
			t.Cleanup(func() { editDir = oldDir })
			err := runAutomatedEditWorkflow(cmd, parityRotation(), false, "")
			return parityRun{warnings: stderrWarnings(stderr.String()), err: err}
		},
		"plan": func(t *testing.T, dir string) parityRun {
			result, err := planEditScenario(dir, parityRotation(), editAgentSessionOptions{})
			if err != nil {
				return parityRun{err: err}
			}
			return parityRun{warnings: result.Warnings}
		},
		"apply": func(t *testing.T, dir string) parityRun {
			result, err := applyEditScenario(dir, "issue-146-parity", parityRotation(), editAgentSessionOptions{})
			switch {
			case err != nil:
				return parityRun{err: err}
			case result.RolledBack:
				return parityRun{err: result.ScenarioErr}
			}
			return parityRun{warnings: result.Warnings}
		},
	}
}

// stderrWarnings is --actions' "warning: " lines, without the prefix.
func stderrWarnings(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if w, ok := strings.CutPrefix(line, "warning: "); ok {
			out = append(out, w)
		}
	}
	return out
}

// Every front-end treats a vault rotation alike (PR #148 round 4, R1 and
// R8): a busy roster refuses the save on each automation front-end and
// leaves the vault and the roster byte-identical; the automation
// front-ends report the same roster warnings; and a synced rotation
// writes the same files under apply as under --actions.
func TestVaultSaveRosterSyncParity(t *testing.T) {
	for name, setup := range paritySetups() {
		t.Run(name, func(t *testing.T) {
			t.Setenv(parityEnv, setup.password)
			var reference []string
			var referenceFrom string
			written := map[string]map[string][]byte{}
			for _, frontEnd := range []string{"terminal router", "--actions", "plan", "apply"} {
				dir := t.TempDir()
				watched, _ := setup.prepare(t, dir)
				before := snapshotFiles(t, watched...)
				run := parityFrontEnds()[frontEnd](t, dir)
				if setup.busy {
					if !errors.Is(run.err, inventory.ErrMutationLocked) && !errors.Is(run.err, inventory.ErrRosterLockFile) && !errors.Is(run.err, inventory.ErrRosterNotWritable) {
						t.Errorf("%s: error = %v; want the busy roster to refuse the save", frontEnd, run.err)
					}
					if !strings.Contains(errString(run.err), "was not saved") {
						t.Errorf("%s: error %v does not say the vault was not saved", frontEnd, run.err)
					}
					assertUnchanged(t, before)
					continue
				}
				if run.err != nil {
					t.Fatalf("%s: error = %v", frontEnd, run.err)
				}
				got := rosterWarnings(run.warnings)
				// Each run has its own directories; compare the warnings
				// with the watched files' paths named alike.
				for i := range got {
					for j, path := range watched {
						got[i] = strings.ReplaceAll(got[i], path, fmt.Sprintf("<watched %d>", j))
					}
				}
				for _, want := range setup.warnings {
					if n := len(slices.DeleteFunc(slices.Clone(got), func(w string) bool { return !strings.Contains(w, want) })); n != 1 {
						t.Errorf("%s: %d warnings contain %q, want 1: %q", frontEnd, n, want, got)
					}
				}
				if len(setup.warnings) == 0 && len(got) != 0 {
					t.Errorf("%s: unexpected roster warnings %q", frontEnd, got)
				}
				if reference == nil {
					reference, referenceFrom = got, frontEnd
				} else if !slices.Equal(got, reference) {
					t.Errorf("%s warns %q, %s warned %q", frontEnd, got, referenceFrom, reference)
				}
				if frontEnd == "plan" {
					assertUnchanged(t, before)
					continue
				}
				roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
				if setup.synced {
					if pw := syncRosterPassword(t, roster); pw != setup.password {
						t.Errorf("%s: roster password = %q, want the new one", frontEnd, pw)
					}
				}
				written[frontEnd] = map[string][]byte{}
				for _, rel := range []string{".vault/main.yaml", ".vault/ipa-identity.yaml"} {
					data, _ := os.ReadFile(filepath.Join(dir, rel))
					written[frontEnd][rel] = data
				}
			}
			if setup.synced {
				for rel, data := range written["apply"] {
					if !bytes.Equal(written["--actions"][rel], data) {
						t.Errorf("%s differs between apply and --actions:\n%s\n---\n%s", rel, data, written["--actions"][rel])
					}
				}
			}
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// At the terminal a busy roster keeps the editor open on the unsaved edit
// with a banner saying the save was refused; saving again once the roster
// is free saves the vault and carries the password into the roster.
func TestVaultSaveOnABusyRosterKeepsTheEditAtTheTerminal(t *testing.T) {
	for name, block := range busyRosterCases() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
			_, unblock := block(t, roster)
			before := snapshotFiles(t, vault, roster)

			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			if err := d.run(&r, rotationSteps("New-pass_2")); err == nil {
				t.Fatal("save on a busy roster succeeded")
			}
			assertUnchanged(t, before)
			if r.err != nil || r.quit {
				t.Fatalf("session ended: err=%v quit=%v", r.err, r.quit)
			}
			if !strings.Contains(r.banner, "⚠️  未存檔 .vault/main.yaml（修改還在）") || !strings.Contains(r.banner, "未寫入 .vault/ipa-identity.yaml") {
				t.Fatalf("banner does not report the refused save:\n%s", r.banner)
			}
			if title := automationState(&r).Title; !strings.HasPrefix(title, "編輯 ") || !strings.Contains(title, "main.yaml") {
				t.Fatalf("left the vault editor for %q", title)
			}

			unblock()
			if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{{Action: "save_vault", File: "main.yaml"}}}); err != nil {
				t.Fatalf("saving again: %v", err)
			}
			if pw := syncRosterPassword(t, roster); pw != "New-pass_2" {
				t.Fatalf("roster password after saving again = %q", pw)
			}
			if data, _ := os.ReadFile(vault); !strings.Contains(string(data), "New-pass_2") {
				t.Fatalf("vault after saving again:\n%s", data)
			}
		})
	}
}

// The reviewer's scenario (PR #148 round 4, R1): with the roster's
// .pilot-remove.lock held, --actions [set_vault_value, save_vault,
// create_user] fails at the save and writes nothing — no rotated vault
// beside an old roster.
func TestEditActionsBusyRotationWritesNothing(t *testing.T) {
	dir := t.TempDir()
	vault, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
	busyRosterCases()["held"](t, roster)
	before := snapshotFiles(t, vault, roster)
	t.Setenv(parityEnv, "New-pass_2")

	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	oldDir := editDir
	editDir = dir
	t.Cleanup(func() { editDir = oldDir })
	err := runAutomatedEditWorkflow(cmd, parityRotation(editAction{Action: "create_user", User: "alice"}), false, "")
	if !errors.Is(err, inventory.ErrMutationLocked) || !strings.Contains(err.Error(), "step 2 (save_vault)") {
		t.Fatalf("runAutomatedEditWorkflow() error = %v; want save_vault refused on the held roster", err)
	}
	assertUnchanged(t, before)
}

// --actions prints the roster warnings on stderr, after a run that
// succeeds and after one that fails later: --actions keeps the steps that
// ran (no rollback), so the rotation they warn about stays (PR #148 round
// 4, R1).
func TestEditActionsPrintsRosterSyncWarnings(t *testing.T) {
	for name, tc := range map[string]struct {
		extra   []editAction
		wantErr bool
	}{
		"success":            {},
		"a later step fails": {extra: []editAction{{Action: "delete_vault_key", File: "main.yaml", Key: "no_such_key"}}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			vault, _ := parityWorkspace(t, dir, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
			t.Setenv(parityEnv, "New-pass_2")
			var stdout, stderr bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			oldDir := editDir
			editDir = dir
			t.Cleanup(func() { editDir = oldDir })

			err := runAutomatedEditWorkflow(cmd, parityRotation(tc.extra...), false, "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("runAutomatedEditWorkflow() error = %v, want error %v", err, tc.wantErr)
			}
			warnings := stderrWarnings(stderr.String())
			if !slices.ContainsFunc(warnings, func(w string) bool {
				return strings.HasPrefix(w, "未同步 .vault/ipa-identity.yaml：ansible-vault 加密")
			}) ||
				!slices.Contains(warnings, rosterSyncOnlyOnChange.text) {
				t.Fatalf("stderr warnings = %q", warnings)
			}
			if strings.Contains(stdout.String(), "warning: ") {
				t.Errorf("warnings on stdout:\n%s", stdout.String())
			}
			if data, _ := os.ReadFile(vault); !strings.Contains(string(data), "New-pass_2") {
				t.Errorf("--actions rolled back the rotation:\n%s", data)
			}
			for _, secret := range []string{"Old-pass_1", "New-pass_2"} {
				if strings.Contains(stderr.String(), secret) {
					t.Fatal("stderr leaks a password")
				}
			}
		})
	}
}
