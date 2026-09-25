package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// executeRootForTest runs rootCmd with args and returns its error and
// everything it wrote to stdout/stderr.
func executeRootForTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		dataDir = ""
	})
	err := rootCmd.Execute()
	return out.String(), err
}

// TestRootRuntimeErrorPrintsNeitherUsageNorCobraPrefix covers the double
// report a failing pilot command used to produce: cobra printed
// "Error: <msg>" plus the whole usage text, then cmd/pilot/main.go printed
// <msg> again. It showed up when an operator declined to continue after a
// failed deploy preflight. A runtime error is now left to main.go alone.
// Outside a terminal, `pilot deploy` returns such an error before asking
// anything.
func TestRootRuntimeErrorPrintsNeitherUsageNorCobraPrefix(t *testing.T) {
	dir := t.TempDir()
	out, err := executeRootForTest(t, "--data-dir", t.TempDir(), "deploy", "--dir", dir)
	if err == nil {
		t.Fatalf("pilot deploy without a TTY should fail; output:\n%s", out)
	}
	if strings.Contains(out, "Usage:") {
		t.Fatalf("a runtime error printed the usage text:\n%s", out)
	}
	if strings.Contains(out, "Error:") {
		t.Fatalf("cobra printed the error itself; main.go already prints it once:\n%s", out)
	}
}

// TestRootFlagErrorStillPrintsUsage keeps usage for mistakes in the
// command line itself, which cobra reports before any command runs.
func TestRootFlagErrorStillPrintsUsage(t *testing.T) {
	origDeploy := deployCmd.SilenceUsage
	deployCmd.SilenceUsage = false // a previous in-process run may have set it
	t.Cleanup(func() { deployCmd.SilenceUsage = origDeploy })

	out, err := executeRootForTest(t, "deploy", "--no-such-flag")
	if err == nil || !strings.Contains(err.Error(), "no-such-flag") {
		t.Fatalf("expected an unknown-flag error, got %v", err)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("an unknown flag should still print the usage text:\n%s", out)
	}
}

// TestDeployForceHelpSaysItApplies: --force answers the apply confirmations
// with yes (promptAutomation.forceApply), although the wizard's own default
// there is No. The help text has to say so.
func TestDeployForceHelpSaysItApplies(t *testing.T) {
	flag := deployCmd.Flags().Lookup("force")
	if flag == nil {
		t.Fatal("pilot deploy has no --force flag")
	}
	if !strings.Contains(flag.Usage, "正式套用") {
		t.Fatalf("--force help does not say it runs the real apply: %q", flag.Usage)
	}
}
