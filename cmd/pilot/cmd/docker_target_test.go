package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestDockerTargetCmdRegistered is the regression guard for "I added
// the subcommand but forgot to rootCmd.AddCommand(dockerTargetCmd)".
// Without the registration, `pilot docker-target` errors out and the
// CI smoke test catches it.
func TestDockerTargetCmdRegistered(t *testing.T) {
	root := rootCmd
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "docker-target" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("docker-target subcommand not registered on rootCmd")
	}
}

// TestDockerTargetSubCommandsAllRegistered walks the seven
// subcommands we promised in the parent Long doc and ensures each
// one is wired. If anyone refactors and drops one, this trips.
func TestDockerTargetSubCommandsAllRegistered(t *testing.T) {
	want := []string{
		"up",
		"down",
		"list",
		"show-inventory",
		"run",
		"verify",
		"exec",
	}
	var have []string
	for _, c := range dockerTargetCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("subcommand %q missing; have %v", w, have)
		}
	}
}

// TestRunDtUp_RequiresName is the regression guard for the previous
// "accepts empty --name and silently picked default" bug — which
// produced a target named "" that broke ansible inventory keys.
func TestRunDtUp_RequiresName(t *testing.T) {
	dtName = ""; dtImage = ""
	rootCmd.SetArgs([]string{"docker-target", "up"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("want --name-required error, got %v", err)
	}
}

// TestRunDtUp_RequiresImage mirrors the name check.
func TestRunDtUp_RequiresImage(t *testing.T) {
	dtName = ""; dtImage = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--image is required") {
		t.Fatalf("want --image-required error, got %v", err)
	}
}

// TestRunDtDown_RequiresName is the matching guard.
func TestRunDtDown_RequiresName(t *testing.T) {
	dtName = ""
	rootCmd.SetArgs([]string{"docker-target", "down"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("want --name-required error, got %v", err)
	}
}

// TestShortCID_MatchesDockerFormat ensures our 12-char prefix matches
// what `docker ps --format "{{.ID}}"` prints, so users can paste the
// value into other docker commands without surprise.
func TestShortCID_MatchesDockerFormat(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"abc123def456789012345678901234567890", "abc123def456"},
		{"short", "short"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := shortCID(tc.in); got != tc.want {
			t.Errorf("shortCID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveDataDir_RespectsFlag covers the precedence rule:
// --data-dir flag wins over the default $HOME/.local/share/pilot.
func TestResolveDataDir_RespectsFlag(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home")
	old := dataDir
	dataDir = "/tmp/explicit-data"
	defer func() { dataDir = old }()
	got := resolveDataDir()
	if got != "/tmp/explicit-data" {
		t.Errorf("resolveDataDir = %q, want /tmp/explicit-data", got)
	}
}
