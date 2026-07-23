package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/spf13/cobra"
)

func TestEditAutomationDriverHostsFlow(t *testing.T) {
	dir := t.TempDir()
	role := inventory.Roles()[0].Name
	scenario := editScenario{
		Version: 1,
		Title:   "Create a web host",
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "set_host_field", Host: "web-1", Field: "ansible_host", Value: "10.0.0.5"},
			{Action: "enable_role", Host: "web-1", Role: role},
			{Action: "save_hosts"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if !r.quit {
		t.Fatal("driver did not finish the edit session")
	}
	if len(events) != len(scenario.Steps) {
		t.Fatalf("trace events = %d, want %d", len(events), len(scenario.Steps))
	}
	for _, event := range events {
		if event.Result != "ok" || len(event.Keys) == 0 {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "web-1" || hf.Hosts[0].AnsibleHost != "10.0.0.5" || !hasRole(hf.Hosts[0].Roles, role) {
		t.Fatalf("hosts = %+v", hf.Hosts)
	}
}

func TestEditAutomationWorkflowPresentationAndTrace(t *testing.T) {
	dir := t.TempDir()
	tracePath := filepath.Join(dir, "trace.jsonl")
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	scenario := editScenario{Version: 1, Title: "Teaching flow", Steps: []editAction{
		{Action: "create_host", Host: "web-1"},
		{Action: "save_hosts"},
	}}
	oldDir := editDir
	editDir = dir
	t.Cleanup(func() { editDir = oldDir })
	if err := runAutomatedEditWorkflow(cmd, scenario, true, tracePath); err != nil {
		t.Fatalf("runAutomatedEditWorkflow() error = %v", err)
	}
	if !strings.Contains(out.String(), "── create_host ──") || !strings.Contains(out.String(), "── save_hosts ──") || !strings.Contains(out.String(), "✅ 已存檔") {
		t.Fatalf("presentation output missing screen/action:\n%s", out.String())
	}
	trace, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}
	if got := strings.Count(string(trace), "\"result\":\"ok\""); got != 2 {
		t.Fatalf("trace success events = %d, want 2:\n%s", got, trace)
	}
}

func TestEditAutomationDriverStopsAfterFailure(t *testing.T) {
	dir := t.TempDir()
	r := newEditRouterModel(dir)
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "set_host_field", Host: "missing", Field: "ansible_host", Value: "10.0.0.5"},
			{Action: "save_hosts"},
		},
	}

	var events []automationTraceEvent
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err == nil {
		t.Fatal("driver.run() unexpectedly succeeded")
	}
	if len(events) != 1 || events[0].Result != "error" {
		t.Fatalf("events = %+v, want one failed event", events)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("hosts.yml exists after failed scenario, err=%v", err)
	}
}
