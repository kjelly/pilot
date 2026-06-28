package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestInspectExistingContainer_NoDocker(t *testing.T) {
	// Pass a CLI name that's definitely not in PATH.
	_, err := InspectExistingContainer(context.Background(), "definitely-not-docker-12345", "nope")
	if err == nil {
		t.Error("expected error when docker CLI is missing")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Errorf("error should mention docker: %v", err)
	}
}

func TestInspectExistingContainer_NotFound(t *testing.T) {
	// Skip if docker isn't installed; otherwise run with a name we
	// know doesn't exist.
	cliPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	_, err = InspectExistingContainer(context.Background(), cliPath, "pilot-nonexistent-container-xyz")
	if err == nil {
		t.Error("expected error for non-existent container")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no such") {
		t.Errorf("error should mention 'no such', got: %v", err)
	}
}

func TestIsImageCached_NoDocker(t *testing.T) {
	_, err := IsImageCached(context.Background(), "definitely-not-docker-12345", "alpine:3.20")
	if err == nil {
		t.Error("expected error when docker CLI is missing")
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"simple", "'simple'"},
		{"with space", "'with space'"},
		{"it's", "'it'\\''s'"},
		{"/etc/ssh/sshd_config", "'/etc/ssh/sshd_config'"},
		{"", "''"},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
