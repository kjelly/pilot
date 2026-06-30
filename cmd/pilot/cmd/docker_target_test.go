package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
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
	if err == nil || !strings.Contains(err.Error(), "--image or --image-pilot is required") {
		t.Fatalf("want --image-or-image-pilot-required error, got %v", err)
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

// TestRunDtUp_ImageAndImagePilotExclusive is the regression guard:
// the previous "both flags accepted" silently picked the last one
// bound, masking CLI flag wiring bugs.
func TestRunDtUp_ImageAndImagePilotExclusive(t *testing.T) {
	dtName = ""; dtImage = ""; dtImagePilot = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x", "--image", "u", "--image-pilot", "u"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutex error, got %v", err)
	}
}

// TestRunDtUp_RequiresImageOrImagePilot mirrors the name check.
func TestRunDtUp_RequiresImageOrImagePilot(t *testing.T) {
	dtName = ""; dtImage = ""; dtImagePilot = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--image or --image-pilot is required") {
		t.Fatalf("want image-required error, got %v", err)
	}
}


// TestDockerTargetSubCommandsAllRegistered_AfterSnapshotRollback
// walks the new command set. If anyone refactors and drops
// snapshot / rollback, this trips.
func TestDockerTargetSubCommandsAllRegistered_AfterSnapshotRollback(t *testing.T) {
	want := []string{
		"up", "down", "list", "show-inventory",
		"run", "verify", "exec",
		"snapshot", "rollback",
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

// TestRunDtSnapshot_RequiresTag is the regression guard: a previous
// "snapshots to 'latest' by default" silently overwrote whatever
// 'latest' pointed at.
func TestRunDtSnapshot_RequiresTag(t *testing.T) {
	dtName = ""; dtSnapshotTag = ""
	rootCmd.SetArgs([]string{"docker-target", "snapshot", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || (!strings.Contains(err.Error(), "--tag") && !strings.Contains(err.Error(), "required")) {
		t.Fatalf("want --tag-required error, got %v", err)
	}
}

// TestRunDtRollback_RequiresImage is the matching guard.
func TestRunDtRollback_RequiresImage(t *testing.T) {
	dtName = ""; dtRollbackImage = ""
	rootCmd.SetArgs([]string{"docker-target", "rollback", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || (!strings.Contains(err.Error(), "--image") && !strings.Contains(err.Error(), "required")) {
		t.Fatalf("want --image-required error, got %v", err)
	}
}

// TestRunTargetFlagRegistered ensures `pilot run --target` is wired.
func TestRunTargetFlagRegistered(t *testing.T) {
	var found bool
	runCmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "target" {
			found = true
		}
	})
	if !found {
		t.Fatal("--target flag not registered on runCmd")
	}
}

// TestResolveTargetInventory_NoTarget is the regression guard for
// "we always called resolveTargetInventory and it touched state"
// — should be a no-op when --target is empty.
func TestResolveTargetInventory_NoTarget(t *testing.T) {
	old := runTarget
	runTarget = ""
	defer func() { runTarget = old }()
	if got := resolveTargetInventory(); got != "" {
		t.Errorf("resolveTargetInventory with no --target should return \"\", got %q", got)
	}
}
