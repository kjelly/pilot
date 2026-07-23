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

func TestDeployAndReconcileExposeAutomationFlags(t *testing.T) {
	for _, command := range []*cobra.Command{deployCmd, reconcileCmd} {
		for _, name := range []string{"actions", "presentation", "trace-out"} {
			if command.Flag(name) == nil {
				t.Fatalf("%s missing --%s", command.Name(), name)
			}
		}
	}
}
