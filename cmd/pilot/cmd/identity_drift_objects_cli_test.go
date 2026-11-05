package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/accessgrants/fakeipatest"
)

const (
	objectsCLIVaultSentinel = "Pr204VaultAdminSentinel-CLI-31"
	objectsCLILeakSentinel  = "Pr204ExceptionTextSentinel-CLI-55"
)

// objectsCLIWorkspace is a drift workspace whose roster is the captured-fixture
// roster, whose inventory is one local host in freeipa-server, and whose
// auto-detected vault holds the admin password sentinel; the fake FreeIPA serves
// scenario. It needs real ansible-playbook (`make identity-secret-test` runs it
// with PILOT_REQUIRE_CONTAINER_TESTS=1).
func objectsCLIWorkspace(t *testing.T, roster string, scenario fakeipatest.Scenario) driftWorkspace {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	// The probe playbook path is relative to the working directory.
	t.Chdir(repoRootForTest(t))
	ws := newDriftWorkspace(t, "ipa_admin_password: "+objectsCLIVaultSentinel+"\n")
	inv := "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n          ansible_connection: local\n"
	for path, body := range map[string]string{ws.inventory: inv, ws.roster: roster} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scenario.Install(t)
	return ws
}

// runObjectsCLI runs one command and returns everything an operator sees: stdout
// and the error, plus the diagnostic log on stderr (--log-level debug).
func runObjectsCLI(t *testing.T, ws driftWorkspace, args ...string) (string, error) {
	t.Helper()
	resetDriftCmdState(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	out, runErr := runDriftCmd(t, append([]string{"identity", "drift", ws.roster, "-i", ws.inventory, "--log-level", "debug"}, args...)...)
	os.Stderr = oldStderr
	_ = w.Close()
	logs, _ := io.ReadAll(r)
	seen := out + string(logs)
	if runErr != nil {
		seen += "\nERROR: " + runErr.Error()
	}
	for _, sentinel := range []string{objectsCLIVaultSentinel, fakeipatest.RosterInitialSentinel, objectsCLILeakSentinel} {
		if strings.Contains(seen, sentinel) {
			t.Errorf("%v leaked %q:\n%s", args, sentinel, seen)
		}
	}
	return out + "\n" + string(logs), runErr
}

func driftExitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var coded ExitCoder
	if !errors.As(err, &coded) {
		t.Fatalf("not a coded exit: %v", err)
	}
	return coded.ExitCode()
}

// TestIdentitySecretDriftCommandsUsersGroupsFromCapturedFixtures drives the real
// `pilot identity drift --include-users-groups` (table, json, --exit-code)
// through real ansible-playbook, the real probe and observer and the captured
// FreeIPA replies: the perturbed state lists exactly the operations apply would
// perform, a converged state is empty, the exit code never claims full parity
// while coverage is partial, a failing observation is an error rather than an
// empty report, and neither the roster's initial password nor the vault's admin
// password appears in any output.
func TestIdentitySecretDriftCommandsUsersGroupsFromCapturedFixtures(t *testing.T) {
	want := []string{
		"group_member_extra:team-p1:remove_member",
		"group_member_extra:team-p1:remove_member",
		"group_member_missing:team-p1:add_member",
		"group_missing:team-p1-new:create",
		"group_unexpected:team-p1-nonposix:report",
		"user_enabled:p1-off:update",
		"user_missing:p1-new:create",
		"user_should_be_absent:p1-reset:delete",
		"user_ssh_keys:p1-keys:update",
		"user_unexpected:p1-nopw:report",
		"user_unexpected:p1-self:report",
	}
	keys := fakeipatest.CapturedKeys(t)

	t.Run("perturbed: table with --exit-code is actionable (2) and lists the operations", func(t *testing.T) {
		ws := objectsCLIWorkspace(t, fakeipatest.Roster(t, keys[:1]), fakeipatest.Captured(t))
		out, err := runObjectsCLI(t, ws, "--include-users-groups", "--exit-code")
		if got := driftExitCodeOf(t, err); got != 2 {
			t.Fatalf("exit code = %d, want 2\n%s", got, out)
		}
		for _, item := range want {
			parts := strings.Split(item, ":")
			line := parts[0] + "\tname=" + parts[1] + "\taction=" + parts[2] + "\t"
			if !strings.Contains(out, line) {
				t.Errorf("table lacks %q:\n%s", line, out)
			}
		}
		if !strings.Contains(out, "partial coverage; not inspected: [hbac_sudo_attachments hosts_hostgroups_netgroups password_actions]") {
			t.Errorf("table does not state what is still not inspected:\n%s", out)
		}
		for _, material := range []string{"ssh-ed25519", "AAAAC3NzaC1", "SHA256:"} {
			if strings.Contains(out, material) {
				t.Errorf("output carries key material %q:\n%s", material, out)
			}
		}
	})

	t.Run("perturbed: json is the v1 envelope with the same items", func(t *testing.T) {
		ws := objectsCLIWorkspace(t, fakeipatest.Roster(t, keys[:1]), fakeipatest.Captured(t))
		out, err := runObjectsCLI(t, ws, "--include-users-groups", "--format", "json", "--exit-code")
		if got := driftExitCodeOf(t, err); got != 2 {
			t.Fatalf("exit code = %d, want 2\n%s", got, out)
		}
		jsonPart := out[:strings.LastIndex(out, "}")+1]
		var doc identityDriftOutput
		if err := json.Unmarshal([]byte(jsonPart[strings.Index(jsonPart, "{"):]), &doc); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if doc.SchemaVersion != 1 || doc.Complete {
			t.Errorf("schema_version=%d complete=%v, want 1 and false", doc.SchemaVersion, doc.Complete)
		}
		if !containsString(doc.Covered, "users_groups") || containsString(doc.Uncovered, "users_groups") {
			t.Errorf("covered=%v uncovered=%v: users_groups must be covered with the flag", doc.Covered, doc.Uncovered)
		}
		var got []string
		for _, item := range doc.Items {
			got = append(got, item.Category+":"+item.Name+":"+item.Action)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("items:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})

	// The staged scope never reports 0: a clean subset is not full parity.
	for _, tc := range []struct {
		name           string
		keepUnexpected bool
	}{
		{"converged", false},
		{"converged except objects outside the roster (report-only)", true},
	} {
		t.Run(tc.name+": --exit-code is 3, never 0", func(t *testing.T) {
			scenario, roster := fakeipatest.Converged(t, tc.keepUnexpected)
			ws := objectsCLIWorkspace(t, roster, scenario)
			out, err := runObjectsCLI(t, ws, "--include-users-groups", "--exit-code")
			if got := driftExitCodeOf(t, err); got != 3 {
				t.Fatalf("exit code = %d, want 3\n%s", got, out)
			}
			if tc.keepUnexpected != strings.Contains(out, "_unexpected\tname=") {
				t.Errorf("report-only objects shown = %v, want %v:\n%s", !tc.keepUnexpected, tc.keepUnexpected, out)
			}
			for _, bad := range []string{"group_member_extra", "user_enabled", "user_ssh_keys", "user_missing", "group_missing", "user_attribute"} {
				if strings.Contains(out, bad) {
					t.Errorf("a converged state still reports %s:\n%s", bad, out)
				}
			}
		})
	}

	t.Run("an observation that fails is an error with fixed text, not an empty report", func(t *testing.T) {
		scenario := fakeipatest.Captured(t)
		scenario.Fail = &fakeipatest.Failure{Where: "user_find", Error: "NetworkError", Text: objectsCLILeakSentinel}
		ws := objectsCLIWorkspace(t, fakeipatest.Roster(t, keys[:1]), scenario)
		out, err := runObjectsCLI(t, ws, "--include-users-groups", "--exit-code")
		var coded ExitCoder
		if err == nil || errors.As(err, &coded) {
			t.Fatalf("a failed observation must be a plain error (exit 1), got %v\n%s", err, out)
		}
		if !strings.Contains(err.Error(), "The users/groups observer could not complete a FreeIPA API call") {
			t.Errorf("the failing class is not named: %v", err)
		}
		if strings.Contains(out, "no drift found") {
			t.Errorf("a failed observation printed a drift report:\n%s", out)
		}
	})

	t.Run("without the flag the same state reports nothing about users or groups", func(t *testing.T) {
		ws := objectsCLIWorkspace(t, fakeipatest.Roster(t, keys[:1]), fakeipatest.Captured(t))
		out, err := runObjectsCLI(t, ws)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, line := range []string{"user_", "group_"} {
			if strings.Contains(out, "\n"+line) {
				t.Errorf("users/groups reported without --include-users-groups:\n%s", out)
			}
		}
		if !strings.Contains(out, "users_groups") {
			t.Errorf("the output must say users_groups was not inspected:\n%s", out)
		}
	})
}
