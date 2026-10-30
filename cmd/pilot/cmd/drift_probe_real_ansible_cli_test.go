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

// TestIdentitySecretDriftCommandsDefaultScopeSurvivesAVaultTargetGroup drives the three real
// cobra commands with REAL ansible-playbook on a server + client inventory
// whose auto-detected .vault/main.yaml carries target_group (issue #179
// review). Default freeipa-server scope survives conflicting auto-loaded
// target_group: all: client1 refuses every connection, so any run that
// targets it shows a connection error. The explicit-flag cases prove
// --target-group is still honoured, and the unreachable-group case proves the
// probe really contacts the group it targets.
func TestIdentitySecretDriftCommandsDefaultScopeSurvivesAVaultTargetGroup(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatalf("required %s not installed: %v", tool, err)
			}
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
	t.Chdir(repoRootForTest(t))

	dead := "          ansible_connection: ssh\n          ansible_host: 127.0.0.1\n          ansible_port: 1\n" +
		"          ansible_ssh_common_args: \"-o ConnectTimeout=3 -o BatchMode=yes\"\n"
	live := "          ansible_connection: local\n"
	serverAndClient := "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n" + live +
		"    ipa-alt:\n      hosts:\n        ipa2:\n" + live + "    clients:\n      hosts:\n        client1:\n" + dead
	deadServer := "all:\n  children:\n    freeipa-server:\n      hosts:\n        client1:\n" + dead +
		"    ipa-alt:\n      hosts:\n        ipa2:\n" + live

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
	const pw = "ipa_admin_password: Vault-Passing-Pw-31\n"
	cases := []struct {
		name, inventory, vault string
		flags                  []string
		reachesClient          bool // the run must fail on the unreachable client1
	}{
		{name: "omitted flag, vault target_group: all", inventory: serverAndClient, vault: pw + "target_group: all\n"},
		{name: "omitted flag, vault target_group: clients", inventory: serverAndClient, vault: pw + "target_group: clients\n"},
		{name: "explicit freeipa-server, vault target_group: all", inventory: serverAndClient, vault: pw + "target_group: all\n", flags: []string{"--target-group", "freeipa-server"}},
		{name: "explicit alternate group wins over the vault", inventory: deadServer, vault: pw + "target_group: all\n", flags: []string{"--target-group", "ipa-alt"}},
		// Should trigger.
		{name: "explicit unreachable group fails", inventory: serverAndClient, vault: pw, flags: []string{"--target-group", "clients"}, reachesClient: true},
		{name: "omitted flag targets freeipa-server, not the vault's group", inventory: deadServer, vault: pw + "target_group: ipa-alt\n", reachesClient: true},
	}

	for _, c := range commands {
		for _, tc := range cases {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				bin := t.TempDir()
				for name, body := range map[string]string{"kinit": "cat >/dev/null\n", "ipa": "exit 0\n"} {
					if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				ws := newDriftWorkspace(t, tc.vault)
				rosterNoPassword := strings.Replace(accessCLIFixtureRoster, "{principal: admin, password: x}", "{principal: admin}", 1)
				for path, body := range map[string]string{ws.inventory: tc.inventory, ws.roster: rosterNoPassword} {
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				resetDriftCmdState(t)
				out, err := runDriftCmd(t, c.args(ws, tc.flags...)...)
				if err != nil {
					out += "\nERROR: " + err.Error()
				}
				if tc.reachesClient {
					if !strings.Contains(out, "client1") {
						t.Fatalf("the run should have failed on the unreachable client1:\n%s", out)
					}
					return
				}
				for _, bad := range []string{"client1", "drift-probe playbook", "unreachable", "UNREACHABLE", "status: unknown", "\"unknown\""} {
					if strings.Contains(out, bad) {
						t.Fatalf("the probe reached the wrong group (%q in output):\n%s", bad, out)
					}
				}
			})
		}
	}
}

// TestIdentitySecretDriftCommandsNeverEchoExpandedVaultValues drives the three
// real cobra commands (access health with --format json too) with REAL
// ansible-playbook and an auto-detected .vault/main.yaml whose keys are
// templates over ipa_admin_password (issue #179 review): ansible puts the
// expanded password into its failure message, so what the operator sees (stdout,
// stderr, the returned error, probe_error) must carry our fixed diagnosis and
// none of that value. Controls: a valid vault passes, and a missing password
// still names both sources.
func TestIdentitySecretDriftCommandsNeverEchoExpandedVaultValues(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatalf("required %s not installed: %v", tool, err)
			}
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
	t.Chdir(repoRootForTest(t))

	const sentinel = "Sup3rS3cretPw"
	const pw = "ipa_admin_password: " + sentinel + "\n"
	local := "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n          ansible_connection: local\n"
	ssh := "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n          ansible_connection: ssh\n          ansible_port: 1\n          ansible_ssh_common_args: \"-o ConnectTimeout=3 -o BatchMode=yes\"\n"

	cases := []struct {
		name, inventory, vault string
		wantFail               bool
		want                   []string
	}{
		{"templated ansible_connection", local, pw + "ansible_connection: \"{{ ipa_admin_password }}\"\n", true,
			[]string{"ansible_connection names a connection plugin ansible does not have", "the value is withheld"}},
		{"templated ansible_python_interpreter", local, pw + "ansible_python_interpreter: \"/nonexistent/{{ ipa_admin_password }}\"\n", true,
			[]string{"ansible_python_interpreter points at an interpreter that does not exist"}},
		{"templated ansible_host over ssh", ssh, pw + "ansible_host: \"{{ ipa_admin_password }}\"\n", true,
			[]string{"ipa1 is unreachable", "Could not resolve hostname (check ansible_host)"}},
		{"control: valid ansible_connection", local, pw + "ansible_connection: local\n", false, nil},
		{"control: no password names both sources", local, "unrelated: 1\n", true,
			[]string{"No usable FreeIPA admin password", "ipa_admin_password", "freeipa.admin.password", "Both are missing or too short"}},
	}
	commands := []struct {
		name  string
		args  func(ws driftWorkspace) []string
		isRun bool // true when a probe failure is the command's error
	}{
		{"access drift", func(ws driftWorkspace) []string { return []string{"access", "drift", ws.roster, "-i", ws.inventory} }, true},
		{"identity drift", func(ws driftWorkspace) []string { return []string{"identity", "drift", ws.roster, "-i", ws.inventory} }, true},
		{"access health", func(ws driftWorkspace) []string { return []string{"access", "health", ws.roster, "-i", ws.inventory} }, false},
		{"access health --format json", func(ws driftWorkspace) []string {
			return []string{"access", "health", ws.roster, "-i", ws.inventory, "--format", "json"}
		}, false},
	}
	rosterNoPassword := strings.Replace(accessCLIFixtureRoster, "{principal: admin, password: x}", "{principal: admin}", 1)

	for _, c := range commands {
		for _, tc := range cases {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				bin := t.TempDir()
				for name, body := range map[string]string{"kinit": "cat >/dev/null\n", "ipa": "exit 0\n"} {
					if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				ws := newDriftWorkspace(t, tc.vault)
				for path, body := range map[string]string{ws.inventory: tc.inventory, ws.roster: rosterNoPassword} {
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				resetDriftCmdState(t)
				out, err := runDriftCmd(t, c.args(ws)...)
				seen := out
				if err != nil {
					seen += "\nERROR: " + err.Error()
				}
				if strings.Contains(strings.ToLower(seen), strings.ToLower(sentinel)) {
					t.Fatalf("the vault value reached what the operator sees (rc %v):\n%s", err != nil, seen)
				}
				if !tc.wantFail {
					if strings.Contains(seen, "probe_error") || strings.Contains(seen, "unknown") || strings.Contains(seen, "drift-probe playbook") {
						t.Fatalf("control failed:\n%s", seen)
					}
					return
				}
				// rc: drift commands return the probe failure; health reports
				// it as status unknown with rc 0, as on main.
				if c.isRun && err == nil {
					t.Fatalf("%s should fail when the probe fails:\n%s", c.name, out)
				}
				if !c.isRun && err != nil {
					t.Fatalf("%s must report a failed probe, not error: %v\n%s", c.name, err, out)
				}
				for _, w := range tc.want {
					if !strings.Contains(seen, w) {
						t.Errorf("output does not contain %q:\n%s", w, seen)
					}
				}
			})
		}
	}
}
