package cmd

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func withDirectorySSHLauncher(t *testing.T, fn func(cmd *exec.Cmd) error) {
	t.Helper()
	old := directorySSHLauncher
	directorySSHLauncher = fn
	t.Cleanup(func() { directorySSHLauncher = old })
}

// TestConnectToGatewayAllowed verifies a fresh, allowed resolve launches
// ssh with exactly the fixed argv spec.md §16 requires — no user/port/
// options, and the remote command is the fixed pilot-connect grammar.
func TestConnectToGatewayAllowed(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectory(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-directory-test/krb5cc"}
	var launched *exec.Cmd
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = cmd
		return nil
	})
	if err := connectToGateway(context.Background(), client, credentials, "/etc/pilot/directory_ssh_config", username, "gpu-a.example.com"); err != nil {
		t.Fatalf("connectToGateway: %v", err)
	}
	if launched == nil {
		t.Fatalf("expected directorySSHLauncher to be invoked")
	}
	wantPrefix := []string{sshBinaryPath, "-F", "/etc/pilot/directory_ssh_config", "gw-gpu-01.example.com", "--", "pilot-connect"}
	if strings.Join(launched.Args[:len(wantPrefix)], " ") != strings.Join(wantPrefix, " ") {
		t.Fatalf("Args = %v, want prefix %v", launched.Args, wantPrefix)
	}
	if got := launched.Args[len(launched.Args)-1]; got != "gpu-a.example.com" {
		t.Fatalf("last arg (target fqdn) = %q, want gpu-a.example.com", got)
	}
	if len(credentials.users) != 1 || credentials.users[0] != username {
		t.Fatalf("credential users = %v, want [%s]", credentials.users, username)
	}
	if got := envValue(launched.Env, "KRB5CCNAME"); got != credentials.cache {
		t.Fatalf("KRB5CCNAME = %q, want %q", got, credentials.cache)
	}
}

// TestConnectToGatewayDenied verifies a fresh denial never invokes ssh at
// all — the fresh-resolve path, independent of whatever My Hosts showed
// earlier.
func TestConnectToGatewayDenied(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectory(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/should-not-be-used"}
	launched := false
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})
	withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
		{Prompt: "Access changed", Confirm: boolPtr(true)},
	}}, func() {
		if err := connectToGateway(context.Background(), client, credentials, "/etc/pilot/directory_ssh_config", username, "not-in-scope.example.com"); err != nil {
			t.Fatalf("connectToGateway: %v", err)
		}
	})
	if launched {
		t.Fatalf("ssh must not be launched for a denied target")
	}
	if len(credentials.users) != 0 {
		t.Fatalf("credentials must not be requested before resolve, got users %v", credentials.users)
	}
}

// TestConnectToGatewaySSHFailureReturnsToDirectory mirrors
// TestConnectToHostSSHFailureReturnsToPortal: a failed ssh launch must be
// reported and return control to the Directory loop, never propagate as
// an error.
func TestConnectToGatewaySSHFailureReturnsToDirectory(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectory(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-directory-test/krb5cc"}
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		return errors.New("ssh: Could not resolve hostname gw-gpu-01.example.com: Name or service not known")
	})
	withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
		{Prompt: "SSH session ended with an error", Confirm: boolPtr(true)},
	}}, func() {
		if err := connectToGateway(context.Background(), client, credentials, "/etc/pilot/directory_ssh_config", username, "gpu-a.example.com"); err != nil {
			t.Fatalf("connectToGateway must return nil on an ssh launch failure, got: %v", err)
		}
	})
}

func TestConnectToGatewayCredentialFailureReturnsToDirectory(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectory(t, username)
	credentials := &fakePortalCredentialSession{err: errors.New("ticket unavailable")}
	launched := false
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})
	withPromptAutomation(t, &promptAutomation{answers: []promptAnswer{
		{Prompt: "Kerberos authentication failed", Confirm: boolPtr(true)},
	}}, func() {
		if err := connectToGateway(context.Background(), client, credentials, "/etc/pilot/directory_ssh_config", username, "gpu-a.example.com"); err != nil {
			t.Fatalf("connectToGateway must return nil on credential failure, got: %v", err)
		}
	})
	if launched {
		t.Fatal("ssh must not launch without a valid Kerberos credential")
	}
}

// TestConnectToGatewayFailoverTriesNextCandidate proves spec.md §19's
// sequential failover: a transport-level failure connecting to the first
// gateway candidate must try the next one, not give up immediately.
func TestConnectToGatewayFailoverTriesNextCandidate(t *testing.T) {
	username := currentOSUsername(t)
	client := startFakeDirectoryMultiGateway(t, username)
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-directory-test/krb5cc"}
	var attempted []string
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		gatewayFQDN := cmd.Args[3]
		attempted = append(attempted, gatewayFQDN)
		if gatewayFQDN == "gw-gpu-01.example.com" {
			return errors.New("ssh: connection refused")
		}
		return nil
	})
	if err := connectToGateway(context.Background(), client, credentials, "/etc/pilot/directory_ssh_config", username, "gpu-a.example.com"); err != nil {
		t.Fatalf("connectToGateway: %v", err)
	}
	want := []string{"gw-gpu-01.example.com", "gw-gpu-02.example.com"}
	if strings.Join(attempted, ",") != strings.Join(want, ",") {
		t.Fatalf("attempted gateways = %v, want %v", attempted, want)
	}
}

// TestBuildDirectoryConnectSSHCmdNeverUsesAShell proves target injection
// is inert by construction, mirroring
// TestBuildConnectSSHCmdNeverUsesAShell for the Directory hop.
func TestBuildDirectoryConnectSSHCmdNeverUsesAShell(t *testing.T) {
	cmd := buildDirectoryConnectSSHCmd("/etc/pilot/directory_ssh_config", "gw01.example.com; rm -rf /tmp/x", "sess-id", "target.example.com", "FILE:/run/user/1000/pilot-test/krb5cc")
	if filepath.Base(cmd.Path) == "sh" || filepath.Base(cmd.Path) == "bash" {
		t.Fatalf("Path = %q, must never be a shell", cmd.Path)
	}
	if cmd.Path != sshBinaryPath {
		t.Fatalf("Path = %q, want %q", cmd.Path, sshBinaryPath)
	}
	// The whole malicious string must survive as ONE argv element, not be
	// split/interpreted by any shell.
	if got := cmd.Args[3]; got != "gw01.example.com; rm -rf /tmp/x" {
		t.Fatalf("gateway arg = %q", got)
	}
	wantTail := []string{"--", "pilot-connect", "sess-id", "target.example.com"}
	if strings.Join(cmd.Args[len(cmd.Args)-4:], " ") != strings.Join(wantTail, " ") {
		t.Fatalf("remote command tail = %v, want %v", cmd.Args[len(cmd.Args)-4:], wantTail)
	}
}
