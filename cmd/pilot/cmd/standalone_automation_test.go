package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestStandalonePromptWorkflowRejectsWrongActionBeforeTTY(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"steps":[{"action":"reconcile","inventory":"inventory.yml","answers":[{"prompt":"x","select":"y"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runStandalonePromptWorkflow(&cobra.Command{}, "deploy", path, false, "")
	if err == nil || !strings.Contains(err.Error(), "requires exactly one deploy action") {
		t.Fatalf("error = %v", err)
	}
}

func TestStandalonePromptWorkflowRejectsUnknownPromptIDBeforeTTY(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.json")
	contents := `{"version":1,"steps":[{"action":"deploy","inventory":"inventory.yml","answers":[{"prompt_id":"localized.inventory","text":"inventory.yml"}]}]}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runStandalonePromptWorkflow(&cobra.Command{}, "deploy", path, false, "")
	if err == nil || !strings.Contains(err.Error(), "unknown prompt_id") {
		t.Fatalf("error = %v, want unknown prompt_id before workflow execution", err)
	}
}

func TestDeployAndReconcileExposeAutomationFlags(t *testing.T) {
	for _, command := range []*cobra.Command{deployCmd, reconcileCmd} {
		for _, name := range []string{"actions", "presentation", "trace-out", "force"} {
			if name == "force" && command != deployCmd {
				continue
			}
			if command.Flag(name) == nil {
				t.Fatalf("%s missing --%s", command.Name(), name)
			}
		}
	}
}

func TestAutomatedDeployAndReconcileBypassTTYGate(t *testing.T) {
	previous := activePromptAutomation
	activePromptAutomation = &promptAutomation{action: "deploy"}
	t.Cleanup(func() { activePromptAutomation = previous })

	if !promptWorkflowAllowsNonTTY(false) {
		t.Fatal("automated workflow must be allowed without a TTY")
	}
	activePromptAutomation = nil
	if promptWorkflowAllowsNonTTY(false) {
		t.Fatal("ordinary interactive workflow must still require a TTY")
	}
	if !promptWorkflowAllowsNonTTY(true) {
		t.Fatal("interactive terminal workflow must be allowed")
	}
}

// TestDeployForceRunsWithoutTTY locks the order in runDeployInteractive:
// --force installs its automation driver before the TTY gate, so a
// non-interactive `pilot deploy --force` passes the gate, while a plain
// `pilot deploy` without a terminal is still refused.
func TestDeployForceRunsWithoutTTY(t *testing.T) {
	prevTTY, prevForce, prevTimeout, prevPrompt := deployStdinIsTerminal, deployForceFlag, deployTimeoutFlag, activePromptAutomation
	t.Cleanup(func() {
		deployStdinIsTerminal, deployForceFlag, deployTimeoutFlag, activePromptAutomation = prevTTY, prevForce, prevTimeout, prevPrompt
	})
	deployStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	// --timeout is parsed right after the TTY gate, so an invalid value stops
	// the run there, before it touches a data dir or an inventory.
	deployTimeoutFlag = "not-a-duration"

	deployForceFlag = false
	err := runDeployInteractive(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "TTY") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("plain deploy without a TTY: error = %v, want the TTY error that names --force", err)
	}

	deployForceFlag = true
	err = runDeployInteractive(&cobra.Command{}, nil)
	if err == nil || strings.Contains(err.Error(), "TTY") || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("deploy --force without a TTY: error = %v, want to pass the TTY gate and stop at --timeout", err)
	}
	if activePromptAutomation != nil {
		t.Fatal("the --force automation driver outlived runDeployInteractive")
	}
}
