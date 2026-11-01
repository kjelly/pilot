package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDriftAnsible puts an ansible-playbook on PATH that records its argv,
// writes an empty (schema 1) probe result to the pilot_drift_output named in
// whichever -e @file carries it, and exits $FAKE_ANSIBLE_RC after printing
// $FAKE_ANSIBLE_STDERR and the contents of the files named by
// $FAKE_ANSIBLE_STDOUT_FILE / $FAKE_ANSIBLE_STDERR_FILE (real captures, see
// internal/accessgrants/testdata/ansible). It returns the argv file.
func fakeDriftAnsible(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	argsFile := filepath.Join(t.TempDir(), "argv")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$FAKE_ANSIBLE_ARGS"
prev=""
for a in "$@"; do
  if [ "$prev" = "-e" ]; then
    case "$a" in
      @*) out=$(sed -n 's/.*"pilot_drift_output":"\([^"]*\)".*/\1/p' "${a#@}" 2>/dev/null)
          [ -n "$out" ] && printf '{"schema_version":1}' > "$out" ;;
    esac
  fi
  prev="$a"
done
[ -n "$FAKE_ANSIBLE_STDERR" ] && printf '%s\n' "$FAKE_ANSIBLE_STDERR" >&2
[ -n "$FAKE_ANSIBLE_STDOUT_FILE" ] && cat "$FAKE_ANSIBLE_STDOUT_FILE"
[ -n "$FAKE_ANSIBLE_STDERR_FILE" ] && cat "$FAKE_ANSIBLE_STDERR_FILE" >&2
exit "${FAKE_ANSIBLE_RC:-0}"
`
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_ANSIBLE_ARGS", argsFile)
	t.Setenv("FAKE_ANSIBLE_RC", "0")
	t.Setenv("FAKE_ANSIBLE_STDERR", "")
	t.Setenv("FAKE_ANSIBLE_STDOUT_FILE", "")
	t.Setenv("FAKE_ANSIBLE_STDERR_FILE", "")
	return argsFile
}

// resetDriftCmdState snapshots and zeroes the package-level flag variables
// the three drift-probe commands read: cobra keeps a flag's last value in
// them across rootCmd.Execute calls, so one test's --vars-file would leak
// into the next.
func resetDriftCmdState(t *testing.T) {
	t.Helper()
	ptrs := []*string{
		&accessDriftFormat, &accessDriftInventory, &accessDriftTargetGroup, &accessDriftVaultPasswordFile, &accessDriftVarsFile,
		&identityDriftFormat, &identityDriftInventory, &identityDriftTargetGroup, &identityDriftVaultPasswordFile, &identityDriftVarsFile,
		&accessHealthFormat, &accessHealthInventory, &accessHealthTargetGroup, &accessHealthVaultPasswordFile, &accessHealthVarsFile,
		&dataDir,
	}
	bools := []*bool{&accessDriftRepairManaged, &identityDriftRepairManaged, &identityDriftIncludeObjects, &identityDriftExitCode}
	saved := make([]string, len(ptrs))
	for i, p := range ptrs {
		saved[i] = *p
	}
	savedBools := make([]bool, len(bools))
	for i, p := range bools {
		savedBools[i] = *p
	}
	t.Cleanup(func() {
		for i, p := range ptrs {
			*p = saved[i]
		}
		for i, p := range bools {
			*p = savedBools[i]
		}
		rootCmd.SetArgs(nil)
	})
	for _, p := range ptrs {
		*p = ""
	}
	for _, p := range bools {
		*p = false
	}
	for _, p := range []*string{&accessDriftFormat, &identityDriftFormat, &accessHealthFormat} {
		*p = "table"
	}
	dataDir = t.TempDir()
}

type driftWorkspace struct {
	dir, roster, inventory, vault string
}

// newDriftWorkspace makes <dir>/{inventory.yml,roster.yaml} and, when
// vaultBody != "", <dir>/.vault/main.yaml.
func newDriftWorkspace(t *testing.T, vaultBody string) driftWorkspace {
	t.Helper()
	dir := t.TempDir()
	ws := driftWorkspace{dir: dir, roster: filepath.Join(dir, "roster.yaml"), inventory: filepath.Join(dir, "inventory.yml")}
	for path, body := range map[string]string{ws.roster: accessCLIFixtureRoster, ws.inventory: "all: {}\n"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if vaultBody != "" {
		if err := os.Mkdir(filepath.Join(dir, ".vault"), 0o700); err != nil {
			t.Fatal(err)
		}
		ws.vault = filepath.Join(dir, ".vault", "main.yaml")
		if err := os.WriteFile(ws.vault, []byte(vaultBody), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ws
}

func runDriftCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	err := rootCmd.Execute()
	return out.String(), err
}

func readArgv(t *testing.T, argsFile string) []string {
	t.Helper()
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("ansible-playbook never ran: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// envIndex returns the position of "-e <value>" in argv, or -1.
func envIndex(argv []string, value string) int {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-e" && argv[i+1] == value {
			return i + 1
		}
	}
	return -1
}

// paramsIndex returns the position of the pilot params "-e @file" (the only
// JSON one): not the vault file, which is YAML.
func paramsIndex(argv []string) int {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "-e" && strings.HasPrefix(argv[i+1], "@") && !strings.Contains(argv[i+1], ".vault") && !strings.HasSuffix(argv[i+1], "other.yaml") {
			return i + 1
		}
	}
	return -1
}

// TestDriftProbeCommandsPassTheVaultFile drives the real cobra commands
// (`pilot access drift`, `pilot identity drift`, `pilot access health`)
// against a fake ansible-playbook and checks which vault vars file reaches
// the probe (issue #179). The vault's content is a sentinel that must never
// show up in argv or output: pilot only passes the file by reference.
func TestDriftProbeCommandsPassTheVaultFile(t *testing.T) {
	const secret = "Vault-Sentinel-pw-5d2a"
	const header = "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n"

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
		t.Run(c.name+"/auto-detects .vault/main.yaml before the params file", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "ipa_admin_password: "+secret+"\n")
			out, err := runDriftCmd(t, c.args(ws)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			argv := readArgv(t, argsFile)
			vaultIdx, paramsIdx := envIndex(argv, "@"+ws.vault), paramsIndex(argv)
			if vaultIdx < 0 || paramsIdx < 0 || vaultIdx > paramsIdx {
				t.Fatalf("want -e @%s before the params file, argv = %v", ws.vault, argv)
			}
			if strings.Contains(strings.Join(argv, "\n"), secret) || strings.Contains(out, secret) {
				t.Fatal("the vault value reached argv or the output")
			}
			for _, a := range argv {
				if a == "--vault-password-file" {
					t.Fatalf("an unencrypted vault must not need a password file: %v", argv)
				}
			}
		})

		t.Run(c.name+"/runs without a vault file", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "")
			if out, err := runDriftCmd(t, c.args(ws)...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			argv := readArgv(t, argsFile)
			for _, a := range argv {
				if strings.Contains(a, ".vault") {
					t.Fatalf("no vault exists, argv = %v", argv)
				}
			}
			if n := strings.Count(strings.Join(argv, "\n"), "\n-e\n"); n != 1 {
				t.Fatalf("want exactly the params -e, got %d in %v", n, argv)
			}
		})

		t.Run(c.name+"/--vars-file overrides the auto-detected file", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "ipa_admin_password: "+secret+"\n")
			other := filepath.Join(t.TempDir(), "other.yaml")
			if err := os.WriteFile(other, []byte("ipa_admin_password: "+secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := runDriftCmd(t, c.args(ws, "--vars-file", other)...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			argv := readArgv(t, argsFile)
			if envIndex(argv, "@"+other) < 0 || envIndex(argv, "@"+ws.vault) >= 0 {
				t.Fatalf("want only the explicit file, argv = %v", argv)
			}
			if envIndex(argv, "@"+other) > paramsIndex(argv) {
				t.Fatalf("the vars file must precede the params file: %v", argv)
			}
		})

		t.Run(c.name+"/a missing --vars-file is an early error", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "ipa_admin_password: "+secret+"\n")
			out, err := runDriftCmd(t, c.args(ws, "--vars-file", filepath.Join(ws.dir, "nope.yaml"))...)
			if err == nil {
				t.Fatalf("want an error, output: %s", out)
			}
			if _, statErr := os.Stat(argsFile); statErr == nil {
				t.Fatal("ansible-playbook ran despite an unusable --vars-file")
			}
		})

		t.Run(c.name+"/an encrypted explicit --vars-file needs --vault-password-file, early", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, header)
			out, err := runDriftCmd(t, c.args(ws, "--vars-file", ws.vault)...)
			if err == nil || !strings.Contains(err.Error(), "--vault-password-file") || !strings.Contains(err.Error(), "encrypted") {
				t.Fatalf("want a clear encrypted-vault error, got %v\n%s", err, out)
			}
			if _, statErr := os.Stat(argsFile); statErr == nil {
				t.Fatal("ansible-playbook ran with an encrypted vars file and no password file")
			}

			resetDriftCmdState(t)
			passFile := filepath.Join(t.TempDir(), "vault-pass")
			if err := os.WriteFile(passFile, []byte("pw\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := runDriftCmd(t, c.args(ws, "--vars-file", ws.vault, "--vault-password-file", passFile)...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			argv := readArgv(t, argsFile)
			found := false
			for i, a := range argv {
				if a == "--vault-password-file" && i+1 < len(argv) && argv[i+1] == passFile {
					found = true
				}
			}
			if !found || envIndex(argv, "@"+ws.vault) < 0 {
				t.Fatalf("want the vault file and the password file, argv = %v", argv)
			}
		})

		// An unreadable default (chmod 000) must not turn a roster-literal
		// user's working command into a failure; an unreadable explicit
		// --vars-file is an early error. chmod does not stop root.
		t.Run(c.name+"/an unreadable auto-detected vault is skipped with a note, an unreadable explicit one is an early error", func(t *testing.T) {
			resetDriftCmdState(t)
			if os.Geteuid() == 0 {
				t.Skip("root can read a chmod 000 file")
			}
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "ipa_admin_password: "+secret+"\n")
			if err := os.Chmod(ws.vault, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(ws.vault, 0o600) })

			out, err := runDriftCmd(t, c.args(ws)...)
			if err != nil {
				t.Fatalf("an unreadable default vault must not fail the command: %v\n%s", err, out)
			}
			if !strings.Contains(out, "skipping unreadable "+ws.vault) || !strings.Contains(out, "permission denied") || !strings.Contains(out, "--vars-file") {
				t.Fatalf("want a one-line skip note naming the file, the reason and --vars-file, got:\n%s", out)
			}
			if strings.Contains(out, secret) {
				t.Fatal("the vault value reached the output")
			}
			for _, a := range readArgv(t, argsFile) {
				if strings.Contains(a, ".vault") {
					t.Fatalf("the unreadable vault reached ansible: %s", a)
				}
			}

			resetDriftCmdState(t)
			if err := os.Remove(argsFile); err != nil {
				t.Fatal(err)
			}
			out, err = runDriftCmd(t, c.args(ws, "--vars-file", ws.vault)...)
			if err == nil || !strings.Contains(err.Error(), "--vars-file") || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("want an early permission error for the explicit file, got %v\n%s", err, out)
			}
			if _, statErr := os.Stat(argsFile); statErr == nil {
				t.Fatal("ansible-playbook ran with an unreadable --vars-file")
			}
		})

		// F3: the auto-detected default is a convenience and never fails the
		// command. A roster-literal user whose .vault/main.yaml is encrypted
		// and who passes no password file keeps working (before --vars-file
		// existed the vault was never given to ansible), and `access health`
		// still reports instead of erroring.
		t.Run(c.name+"/an encrypted auto-detected vault without a password file is skipped with a note", func(t *testing.T) {
			resetDriftCmdState(t)
			argsFile := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, header)
			out, err := runDriftCmd(t, c.args(ws)...)
			if err != nil {
				t.Fatalf("an encrypted default vault must not fail the command: %v\n%s", err, out)
			}
			if !strings.Contains(out, "skipping encrypted "+ws.vault) || !strings.Contains(out, "--vault-password-file") || !strings.Contains(out, "--vars-file") {
				t.Fatalf("want a one-line skip note naming the file and both flags, got:\n%s", out)
			}
			argv := readArgv(t, argsFile)
			for _, a := range argv {
				if strings.Contains(a, ".vault") {
					t.Fatalf("the skipped vault reached ansible: %v", argv)
				}
			}

			// With a password file the same default vault IS used.
			resetDriftCmdState(t)
			passFile := filepath.Join(t.TempDir(), "vault-pass")
			if err := os.WriteFile(passFile, []byte("pw\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := runDriftCmd(t, c.args(ws, "--vault-password-file", passFile)...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if envIndex(readArgv(t, argsFile), "@"+ws.vault) < 0 {
				t.Fatal("the default vault was not used although a password file was given")
			}
		})
	}
}

// TestAccessHealthShowsWhyTheProbeCouldNotRun: a probe failure stays status
// unknown, but the reason (for example no usable admin password, issue #179)
// is printed on its own line instead of looking like an unreachable FreeIPA,
// and never contains the vault's value. The fake ansible replays a REAL
// capture of both streams: the gate message is on stdout while stderr only
// carries ansible's hyphenated-group warning.
func TestAccessHealthShowsWhyTheProbeCouldNotRun(t *testing.T) {
	const secret = "Vault-Sentinel-pw-9b4f"
	resetDriftCmdState(t)
	fakeDriftAnsible(t)
	capture := filepath.Join(repoRootForTest(t), "internal", "accessgrants", "testdata", "ansible")
	t.Setenv("FAKE_ANSIBLE_RC", "2")
	t.Setenv("FAKE_ANSIBLE_STDOUT_FILE", filepath.Join(capture, "gate_missing.stdout"))
	t.Setenv("FAKE_ANSIBLE_STDERR_FILE", filepath.Join(capture, "gate_missing.stderr"))
	ws := newDriftWorkspace(t, "unrelated: "+secret+"\n")

	out, err := runDriftCmd(t, "access", "health", ws.roster, "-i", ws.inventory)
	if err != nil {
		t.Fatalf("a failed probe is status unknown, not a command error: %v", err)
	}
	if !strings.Contains(out, "status=unknown") || !strings.Contains(out, "probe_error=") || !strings.Contains(out, "No usable FreeIPA admin password") {
		t.Fatalf("want status=unknown with a probe_error line, got:\n%s", out)
	}
	if strings.Contains(out, "Invalid characters") {
		t.Fatalf("the group-name warning must not be the reason shown:\n%s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatal("the vault value reached the output")
	}
}
