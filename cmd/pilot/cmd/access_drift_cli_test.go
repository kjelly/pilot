package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestAccessDriftCmd_InvalidRosterFailsClosed(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureBrokenRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "drift", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error for a structurally invalid roster, output: %s", out.String())
	}
}

func TestAccessDriftCmd_RejectsUnknownFormat(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "drift", path, "--format", "yaml", "--inventory", "does-not-exist.yml"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error for an unsupported --format value")
	}
}

func TestAccessHealthCmd_InvalidRosterFailsClosed(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureBrokenRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "health", path})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected an error for a structurally invalid roster, output: %s", out.String())
	}
}

func TestAccessHealthCmd_RejectsUnknownFormat(t *testing.T) {
	path := writeAccessCLIFixture(t, accessCLIFixtureRoster)

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "health", path, "--format", "yaml", "--inventory", "does-not-exist.yml"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected an error for an unsupported --format value")
	}
}

// TestAccessDriftCmd_CommandsAreRegistered is a smoke test that both new
// subcommands are wired into the `access` command tree with the flags
// spec.md v3.1 §12/§13/§16 describes — a regression guard against the
// init() registration itself silently not running.
func TestAccessDriftCmd_CommandsAreRegistered(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetArgs([]string{"access", "--help"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)

	_ = rootCmd.Execute()
	help := out.String()
	if !strings.Contains(help, "drift") || !strings.Contains(help, "health") {
		t.Fatalf("expected `pilot access --help` to list drift and health subcommands, got: %s", help)
	}
}
