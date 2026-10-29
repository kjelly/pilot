package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIdentitySecretDriftCommandsShowTheGateAndHideTheVault drives the three
// real cobra commands (`pilot identity drift`, `pilot access drift`, `pilot
// access health`) through the production probe playbook with REAL
// ansible-playbook (issue #179). The inventory group is the hyphenated
// freeipa-server, so ansible's stderr carries only its group-name warning while
// the gate's message is on stdout; the operator must still see the gate's
// message. A vault vars file that is not valid YAML must never be echoed.
// `make identity-secret-test` runs it with PILOT_REQUIRE_CONTAINER_TESTS=1.
func TestIdentitySecretDriftCommandsShowTheGateAndHideTheVault(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	// The probe playbook path is relative to the working directory.
	t.Chdir(repoRootForTest(t))

	const sentinel = "Sup3rS3cretPw"
	const gate = "No usable FreeIPA admin password"
	rosterNoPassword := strings.Replace(accessCLIFixtureRoster, "{principal: admin, password: x}", "{principal: admin}", 1)
	if rosterNoPassword == accessCLIFixtureRoster {
		t.Fatal("the fixture roster no longer has the admin password line this test strips")
	}

	commands := []struct {
		name string
		args func(ws driftWorkspace, extra ...string) []string
	}{
		{"access drift", func(ws driftWorkspace, extra ...string) []string {
			return append([]string{"access", "drift", ws.roster, "-i", ws.inventory}, extra...)
		}},
		{"identity drift", func(ws driftWorkspace, extra ...string) []string {
			return append([]string{"identity", "drift", ws.roster, "-i", ws.inventory}, extra...)
		}},
		{"access health", func(ws driftWorkspace, extra ...string) []string {
			return append([]string{"access", "health", ws.roster, "-i", ws.inventory}, extra...)
		}},
	}
	for _, c := range commands {
		workspace := func(t *testing.T, vaultBody string) driftWorkspace {
			t.Helper()
			ws := newDriftWorkspace(t, vaultBody)
			inv := "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n          ansible_connection: local\n"
			for path, body := range map[string]string{ws.inventory: inv, ws.roster: rosterNoPassword} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return ws
		}
		// run returns everything an operator sees: stdout, stderr and the
		// returned error.
		run := func(t *testing.T, ws driftWorkspace, extra ...string) string {
			t.Helper()
			resetDriftCmdState(t)
			out, err := runDriftCmd(t, c.args(ws, extra...)...)
			if err != nil {
				out += "\nERROR: " + err.Error()
			}
			return out
		}

		t.Run(c.name+"/no password anywhere shows the gate message", func(t *testing.T) {
			out := run(t, workspace(t, ""))
			for _, want := range []string{gate, "ipa_admin_password", "freeipa.admin.password", "Both are missing or too short"} {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "Invalid characters") {
				t.Errorf("the group-name warning must not stand in for the reason:\n%s", out)
			}
		})

		t.Run(c.name+"/a vault without the key shows the gate message", func(t *testing.T) {
			out := run(t, workspace(t, "unrelated: 1\n"))
			if !strings.Contains(out, gate) {
				t.Errorf("output does not contain %q:\n%s", gate, out)
			}
		})

		malformed := "ipa_admin_password: " + sentinel + ": oops\nother: 1\n"
		t.Run(c.name+"/a malformed auto-detected vault is never echoed", func(t *testing.T) {
			out := run(t, workspace(t, malformed))
			for _, leak := range []string{sentinel, "oops", "Colons in unquoted values"} {
				if strings.Contains(out, leak) {
					t.Errorf("output leaked %q:\n%s", leak, out)
				}
			}
			if !strings.Contains(out, "could not parse") || !strings.Contains(out, "valid YAML") {
				t.Errorf("output should say the file could not be parsed:\n%s", out)
			}
		})

		t.Run(c.name+"/a malformed --vars-file is never echoed", func(t *testing.T) {
			ws := workspace(t, "")
			other := filepath.Join(ws.dir, "custom-vars.yaml")
			if err := os.WriteFile(other, []byte(malformed), 0o600); err != nil {
				t.Fatal(err)
			}
			out := run(t, ws, "--vars-file", other)
			for _, leak := range []string{sentinel, "oops", "Colons in unquoted values"} {
				if strings.Contains(out, leak) {
					t.Errorf("output leaked %q:\n%s", leak, out)
				}
			}
			if !strings.Contains(out, "custom-vars.yaml") {
				t.Errorf("output should name the file that could not be parsed:\n%s", out)
			}
		})
	}
}
