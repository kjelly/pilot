package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func withSSHLauncher(t *testing.T, fn func(cmd *exec.Cmd) error) {
	t.Helper()
	old := sshLauncher
	sshLauncher = fn
	t.Cleanup(func() { sshLauncher = old })
}

// TestConnectToHostAllowed verifies a fresh, allowed authorize launches
// ssh with exactly the fixed argv spec.md §31 requires — no user/port/
// options/remote-command, target only from the ConnectAuthorize response.
func TestConnectToHostAllowed(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	var launched *exec.Cmd
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = cmd
		return nil
	})
	if err := connectToHost(context.Background(), client, "/etc/pilot/ssh_config", "gpu-a.example.com"); err != nil {
		t.Fatalf("connectToHost: %v", err)
	}
	if launched == nil {
		t.Fatalf("expected sshLauncher to be invoked")
	}
	wantArgs := []string{sshBinaryPath, "-F", "/etc/pilot/ssh_config", "gpu-a.example.com"}
	if strings.Join(launched.Args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("Args = %v, want %v", launched.Args, wantArgs)
	}
}

// TestConnectToHostDenied verifies a fresh denial (target outside gateway
// scope) never invokes ssh at all, and shows the "Access changed" notice
// instead — this is the fresh-authorize path, independent of whatever
// My Hosts displayed earlier.
func TestConnectToHostDenied(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	launched := false
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})
	withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
		{Prompt: "Access changed", Confirm: boolPtr(true)},
	}}, func() {
		if err := connectToHost(context.Background(), client, "/etc/pilot/ssh_config", "not-in-scope.example.com"); err != nil {
			t.Fatalf("connectToHost: %v", err)
		}
	})
	if launched {
		t.Fatalf("ssh must not be launched for a denied target")
	}
}

// TestConnectToHostRejectsAlternateUserAndIPTargets covers spec.md §40
// S3 (alternate user, "root@host") and S4 (IP literal) — both are
// rejected by the same mechanism as any other out-of-scope string: the
// gateway's access list only ever contains bare FQDNs from the resolved
// gateway scope, so a target string using either form simply matches
// nothing and is denied, exactly like TestConnectToHostDenied's plain
// case. No special-case parsing of "user@host" or IP syntax exists
// anywhere in this path — there is nothing to bypass.
func TestConnectToHostRejectsAlternateUserAndIPTargets(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	for _, target := range []string{"root@gpu-a.ipa.pilot.internal", "10.0.0.1"} {
		launched := false
		withSSHLauncher(t, func(cmd *exec.Cmd) error {
			launched = true
			return nil
		})
		withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
			{Prompt: "Access changed", Confirm: boolPtr(true)},
		}}, func() {
			if err := connectToHost(context.Background(), client, "/etc/pilot/ssh_config", target); err != nil {
				t.Fatalf("connectToHost(%q): %v", target, err)
			}
		})
		if launched {
			t.Fatalf("ssh must not be launched for target %q", target)
		}
	}
}

// TestConnectToHostSSHFailureReturnsToPortal proves a failed ssh launch
// (host unreachable, name resolution failure, wrong host key, ...) is
// reported to the user and returns control to the portal loop — it must
// never propagate as an error, which used to unwind all the way out of
// runPortal and kill the whole interactive session (found live: picking
// a placeholder demo host with no real machine behind it crashed the
// entire `pilot portal` process with a raw ssh exit-status error and
// cobra's usage dump instead of just failing that one Connect attempt).
func TestConnectToHostSSHFailureReturnsToPortal(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		return errors.New("ssh: Could not resolve hostname gpu-b.ipa.pilot.internal: Name or service not known")
	})
	withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
		{Prompt: "SSH session ended with an error", Confirm: boolPtr(true)},
	}}, func() {
		if err := connectToHost(context.Background(), client, "/etc/pilot/ssh_config", "gpu-a.example.com"); err != nil {
			t.Fatalf("connectToHost must return nil on an ssh launch failure, got: %v", err)
		}
	})
}

// TestPortalHostDetailConnectFlow drives the actual TUI: My Hosts -> host
// detail -> Connect, with sshLauncher stubbed, proving the full menu path
// reaches connectToHost with the right target.
func TestPortalHostDetailConnectFlow(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	var launchedTarget string
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launchedTarget = cmd.Args[len(cmd.Args)-1]
		return nil
	})
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: portalActionConnect},
		{Prompt: "Connect to gpu-a.example.com", Confirm: boolPtr(true)},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if launchedTarget != "gpu-a.example.com" {
		t.Fatalf("launchedTarget = %q", launchedTarget)
	}
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestBuildConnectSSHCmdNeverUsesAShell proves target injection (spec.md
// §40 S2) is inert by construction: exec.Command with an argv slice never
// invokes a shell, so a shell-metacharacter-laden target is just an
// opaque (and, for ssh, simply invalid/nonexistent) hostname argument —
// never interpreted.
func TestBuildConnectSSHCmdNeverUsesAShell(t *testing.T) {
	cmd := buildConnectSSHCmd("/etc/pilot/ssh_config", "gpu01.example.com; rm -rf /tmp/x")
	if filepath.Base(cmd.Path) == "sh" || filepath.Base(cmd.Path) == "bash" {
		t.Fatalf("Path = %q, must never be a shell", cmd.Path)
	}
	if cmd.Path != sshBinaryPath {
		t.Fatalf("Path = %q, want %q", cmd.Path, sshBinaryPath)
	}
	// The whole malicious string must survive as ONE argv element, not be
	// split/interpreted by any shell.
	if got := cmd.Args[len(cmd.Args)-1]; got != "gpu01.example.com; rm -rf /tmp/x" {
		t.Fatalf("last arg = %q", got)
	}
}

// TestPilotSSHConfigDirectives is spec.md §32's own prescribed
// verification method, run for real: `ssh -G -F <this config> <target>`
// against the actual installed OpenSSH client, asserting every directive
// took effect exactly as intended. Also proves a poisoned ~/.ssh/config
// has zero effect once -F is given (spec.md §40 S5).
func TestPilotSSHConfigDirectives(t *testing.T) {
	if _, err := exec.LookPath(sshBinaryPath); err != nil {
		t.Skipf("%s not available in this environment: %v", sshBinaryPath, err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(cfgPath, []byte(pilotSSHConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// A "poisoned" ~/.ssh/config with a malicious ProxyCommand and
	// ForwardAgent yes — -F must cause this to be ignored entirely.
	fakeHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fakeHome, ".ssh"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	poisoned := "Host *\n    ProxyCommand /bin/echo POISONED\n    ForwardAgent yes\n"
	if err := os.WriteFile(filepath.Join(fakeHome, ".ssh", "config"), []byte(poisoned), 0o644); err != nil {
		t.Fatalf("write poisoned config: %v", err)
	}

	cmd := exec.Command(sshBinaryPath, "-F", cfgPath, "-G", "somehost.example.com")
	cmd.Env = append(os.Environ(), "HOME="+fakeHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh -G: %v", err)
	}
	effective := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(fields) == 2 {
			effective[fields[0]] = fields[1]
		}
	}

	want := map[string]string{
		"forwardagent":                 "no", // NOT "yes" from the poisoned config
		"clearallforwardings":          "yes",
		"permitlocalcommand":           "no",
		"enableescapecommandline":      "no",
		"escapechar":                   "none",
		"stricthostkeychecking":        "true", // ssh -G normalizes "yes" -> "true"
		"userknownhostsfile":           "/dev/null",
		"proxycommand":                 "/usr/bin/sss_ssh_knownhostsproxy -p %p %h",
		"globalknownhostsfile":         "/var/lib/sss/pubconf/known_hosts",
		"gssapiauthentication":         "yes",
		"gssapidelegatecredentials":    "yes",
		"kbdinteractiveauthentication": "yes",
		"passwordauthentication":       "yes",
		"requesttty":                   "force",
	}
	for key, wantValue := range want {
		got, ok := effective[key]
		if !ok {
			t.Errorf("effective config missing %q (want %q)", key, wantValue)
			continue
		}
		if got != wantValue {
			t.Errorf("%s = %q, want %q", key, got, wantValue)
		}
	}
	// proxycommand is asserted above (want map) to be exactly
	// sss_ssh_knownhostsproxy — never the poisoned config's
	// "/bin/echo POISONED" (proving -F still overrides ~/.ssh/config for
	// this directive too, now that ProxyCommand is no longer "none").
	// ProxyJump "none" means OpenSSH omits it from -G output entirely
	// rather than echoing "none" — its absence IS the pass condition.
	if v, ok := effective["proxyjump"]; ok {
		t.Errorf("proxyjump = %q, want absent (none)", v)
	}
}
