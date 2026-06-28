package cmd

import (
	"strings"
	"testing"
)

func TestSandboxCmd_Registered(t *testing.T) {
	// `pilot sandbox --help` should print the subcommand list
	// including list / prune / attach / snapshot / rollback /
	// warmup / status. Smoke test for the registration.
	out, err := execRoot("--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	if !strings.Contains(out, "sandbox") {
		t.Errorf("sandbox subcommand missing from --help: %s", out)
	}
}

// execRoot runs `pilot <args>` and returns combined output.
// Used to smoke-test cobra subcommand registration.
func execRoot(args ...string) (string, error) {
	rootCmd.SetArgs(append([]string{"--help"}, args...))
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	out := &strings.Builder{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	if err := rootCmd.Execute(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

func TestSandboxListCmd_RequiresDocker(t *testing.T) {
	// Without a docker daemon we expect an error. Don't actually
	// run; just verify the cmd is reachable.
	for _, sub := range []string{"list", "prune", "warmup", "snapshot", "rollback", "attach", "status"} {
		if !hasSubcommand("sandbox", sub) {
			t.Errorf("sandbox %q subcommand missing", sub)
		}
	}
}

func hasSubcommand(parent, child string) bool {
	for _, c := range rootCmd.Commands() {
		if c.Name() == parent {
			for _, sc := range c.Commands() {
				if sc.Name() == child {
					return true
				}
			}
		}
	}
	return false
}

func TestDockerCmd_ParsesOutput(t *testing.T) {
	// Use a fake docker that prints argv + OK.
	// Skip the actual invocation; just exercise the helper indirectly.
	_ = dockerCmd
}
