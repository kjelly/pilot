package cmd

import (
	"strings"
	"testing"
)

// A plan's refused vault save names the workspace file, never the plan's
// scratch copy, in its error (PR #148 review, P3).
func TestEditPlanRefusedVaultSaveNamesTheWorkspaceFile(t *testing.T) {
	dir := t.TempDir()
	_, roster := parityWorkspace(t, dir, syncTestRoster(`"Old-pass_1"`))
	busyRosterCases()["held"](t, roster)
	t.Setenv(parityEnv, "New-pass_2")
	_, err := planEditScenario(dir, parityRotation(), editAgentSessionOptions{})
	if err == nil || !strings.Contains(err.Error(), ".vault/main.yaml was not saved") {
		t.Fatalf("planEditScenario() error = %v; want the refused save named", err)
	}
	if strings.Contains(err.Error(), "pilot-edit-plan-") {
		t.Fatalf("plan error names its scratch copy: %v", err)
	}
}
