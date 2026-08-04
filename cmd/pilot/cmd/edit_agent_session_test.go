package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAgentSession_IsolatesTwoWorkspaceDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	scenarioA := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "a-host"},
		{Action: "save_hosts"},
	}}
	scenarioB := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "b-host"},
		{Action: "save_hosts"},
	}}

	sessionA := newEditAgentSession(dirA, editAgentSessionOptions{})
	if err := sessionA.Run(scenarioA); err != nil {
		t.Fatalf("session A Run() error = %v", err)
	}
	sessionB := newEditAgentSession(dirB, editAgentSessionOptions{})
	if err := sessionB.Run(scenarioB); err != nil {
		t.Fatalf("session B Run() error = %v", err)
	}

	hfA := readHostsFileForTest(t, dirA)
	hfB := readHostsFileForTest(t, dirB)
	if len(hfA.Hosts) != 1 || hfA.Hosts[0].Name != "a-host" {
		t.Fatalf("dir A hosts = %+v, want only a-host", hfA.Hosts)
	}
	if len(hfB.Hosts) != 1 || hfB.Hosts[0].Name != "b-host" {
		t.Fatalf("dir B hosts = %+v, want only b-host", hfB.Hosts)
	}
}

// TestEditAgentSession_DoesNotReadEditDirGlobal proves the session
// isolation edit_agent_session.go's package doc comment describes:
// pointing the editDir CLI global at a bogus path must have no effect
// on where a session actually reads/writes, since editAgentSession
// never touches that global — only runAutomatedEditWorkflow's single
// call to newEditAgentSession(editDir, ...) does, and this test bypasses
// that call entirely.
func TestEditAgentSession_DoesNotReadEditDirGlobal(t *testing.T) {
	prevEditDir := editDir
	editDir = "/nonexistent-sentinel-path-should-never-be-read-or-written"
	defer func() { editDir = prevEditDir }()

	dir := t.TempDir()
	session := newEditAgentSession(dir, editAgentSessionOptions{})
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "x"},
		{Action: "save_hosts"},
	}}
	if err := session.Run(scenario); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err != nil {
		t.Fatalf("expected hosts.yml written under the session's own dir %s, not the editDir global: %v", dir, err)
	}
}

func TestEditAgentSession_ViewShowsTopMenuBeforeRun(t *testing.T) {
	session := newEditAgentSession(t.TempDir(), editAgentSessionOptions{})
	if got := session.View(); got == "" {
		t.Fatal("expected a non-empty initial view")
	}
}

func readHostsFileForTest(t *testing.T, dir string) *inventory.HostsFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml under %s: %v", dir, err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml under %s: %v", dir, err)
	}
	return hf
}
