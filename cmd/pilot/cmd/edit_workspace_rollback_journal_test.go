package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kjelly/pilot/internal/inventory"
)

// Two applies running at once in one process — pilot edit's MCP server
// handles tool calls concurrently — on two workspaces that share a roster
// (one's .vault/ entry links to the other's roster) cannot both record its
// writes, or each rollback would take the other's writes for its own. The
// second is refused before it writes anything, with an error that says
// why; the first goes on, and an apply after it is accepted.
func TestEditApplyRefusesARosterAnotherApplyIsRecording(t *testing.T) {
	first, roster := busyRosterWorkspace(t)
	second := t.TempDir()
	if err := os.MkdirAll(filepath.Join(second, ".vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(roster, filepath.Join(second, ".vault", "ipa-identity.yaml")); err != nil {
		t.Fatal(err)
	}

	inFirst, releaseFirst := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		result, err := applyEditScenario(first, "issue-146-first", editScenario{Version: 1, Steps: []editAction{
			{Action: "create_user", User: "alice"},
		}}, editAgentSessionOptions{BeforeStep: func() {
			close(inFirst)
			<-releaseFirst
		}})
		if err == nil && (result == nil || result.RolledBack) {
			err = errors.New("the first apply did not apply")
		}
		done <- err
	}()
	<-inFirst

	before, _ := os.ReadFile(roster)
	result, err := applyEditScenario(second, "issue-146-second", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "bob"},
	}}, editAgentSessionOptions{})
	if !errors.Is(err, inventory.ErrRosterJournalBusy) || result != nil {
		t.Errorf("second apply = %+v, %v; want it refused with ErrRosterJournalBusy", result, err)
	} else if !strings.Contains(err.Error(), "nothing written") || !strings.Contains(err.Error(), "retry") {
		t.Errorf("refusal %q does not say nothing was written and to retry", err)
	}
	if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
		t.Errorf("the refused apply wrote the shared roster:\n%s", after)
	}

	close(releaseFirst)
	if err := <-done; err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if got, _ := os.ReadFile(roster); !bytes.Contains(got, []byte("name: alice")) {
		t.Fatalf("first apply's write is missing:\n%s", got)
	}
	if result, err := applyEditScenario(second, "issue-146-second-again", editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "bob"},
	}}, editAgentSessionOptions{}); err != nil || result.RolledBack {
		t.Fatalf("apply once the first finished = %+v, %v", result, err)
	}
}

// Through the MCP apply tool the refusal is workspace_locked — retry
// later, nothing written — not a failed rollback.
func TestApplyHandler_RosterAnotherApplyIsRecordingIsWorkspaceLocked(t *testing.T) {
	dir, roster := busyRosterWorkspace(t)
	auditDir := t.TempDir()
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatal(err)
	}
	scenario := editScenario{Version: 1, Steps: []editAction{{Action: "create_user", User: "alice"}}}
	_, planOut, err := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil || planOut.PlanID == "" {
		t.Fatalf("planHandler() = %+v, %v", planOut, err)
	}
	other, err := inventory.JournalRosterWrites([]string{roster}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	before, _ := os.ReadFile(roster)

	result, out, err := applyHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir, WriteEnabled: true})(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planOut.PlanID, ExpectedRevision: rev})
	if err != nil || result == nil || !result.IsError || out.Result == "applied" {
		t.Fatalf("applyHandler() = %+v / %+v, %v; want an error result", result, out, err)
	}
	if toolErr := decodeToolError(t, result); toolErr.Code != mcpErrWorkspaceLocked || toolErr.RolledBack {
		t.Fatalf("toolErr = %+v; want workspace_locked, nothing to roll back", toolErr)
	}
	if after, _ := os.ReadFile(roster); !bytes.Equal(after, before) {
		t.Fatalf("roster written:\n%s", after)
	}
}
