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
	// save_hosts lands at the top menu without quitting the session (r.quit
	// stays false) — a later group_vars/vault action in the same scenario
	// must still be able to navigate from here.
	if list, ok := r.current.(selectModel); !ok || list.title != "要編輯什麼？" {
		t.Fatalf("expected top menu after save_hosts, got %s", automationScreenID(&r))
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

func TestEditAutomationDriverMultiHostFlow(t *testing.T) {
	dir := t.TempDir()
	role := inventory.Roles()[0].Name
	scenario := editScenario{
		Version: 1,
		Title:   "Create two hosts",
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "set_host_field", Host: "web-1", Field: "ansible_host", Value: "10.0.0.5"},
			{Action: "enable_role", Host: "web-1", Role: role},
			{Action: "create_host", Host: "web-2"},
			{Action: "set_host_field", Host: "web-2", Field: "ansible_host", Value: "10.0.0.6"},
			{Action: "enable_role", Host: "web-2", Role: role},
			{Action: "save_hosts"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if len(events) != len(scenario.Steps) {
		t.Fatalf("trace events = %d, want %d", len(events), len(scenario.Steps))
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 2 {
		t.Fatalf("hosts = %+v, want 2 hosts", hf.Hosts)
	}
	byName := map[string]inventory.Host{}
	for _, h := range hf.Hosts {
		byName[h.Name] = h
	}
	if byName["web-1"].AnsibleHost != "10.0.0.5" || !hasRole(byName["web-1"].Roles, role) {
		t.Fatalf("web-1 = %+v", byName["web-1"])
	}
	if byName["web-2"].AnsibleHost != "10.0.0.6" || !hasRole(byName["web-2"].Roles, role) {
		t.Fatalf("web-2 = %+v", byName["web-2"])
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

func TestEditAutomationDriverDisableRole(t *testing.T) {
	dir := t.TempDir()
	roles := inventory.Roles()
	roleA, roleB := roles[0].Name, roles[1].Name
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "enable_role", Host: "web-1", Role: roleA},
			{Action: "enable_role", Host: "web-1", Role: roleB},
			{Action: "disable_role", Host: "web-1", Role: roleA},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want 1 host", hf.Hosts)
	}
	if hasRole(hf.Hosts[0].Roles, roleA) {
		t.Fatalf("role %q still present after disable_role: %+v", roleA, hf.Hosts[0].Roles)
	}
	if !hasRole(hf.Hosts[0].Roles, roleB) {
		t.Fatalf("role %q missing, disable_role removed the wrong role: %+v", roleB, hf.Hosts[0].Roles)
	}
}

func TestEditAutomationDriverSetHostFieldEnv(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "set_host_field", Host: "web-1", Field: "env", Value: "prod"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Env != "prod" {
		t.Fatalf("hosts = %+v, want env=prod", hf.Hosts)
	}
}

func TestEditAutomationDriverSetHostFieldEnvEmptyRoundTrips(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "set_host_field", Host: "web-1", Field: "env", Value: "prod"},
			{Action: "set_host_field", Host: "web-1", Field: "env", Value: ""},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Env != "" {
		t.Fatalf("hosts = %+v, want env cleared back to empty", hf.Hosts)
	}
}

func TestAutomationDriverConfirmYesNo(t *testing.T) {
	r := &editRouterModel{}
	r.current = newConfirmModel("q?", false)
	d := automationDriver{}
	if err := d.confirmYesNo(r, true); err != nil {
		t.Fatalf("confirmYesNo(true) error = %v", err)
	}
	cm, ok := r.current.(confirmModel)
	if !ok || !cm.Finished() || !cm.Value() {
		t.Fatalf("confirmModel not resolved to yes: %+v", r.current)
	}

	r2 := &editRouterModel{}
	r2.current = newConfirmModel("q?", true) // defaultYes=true, but we still expect an explicit "no" to win
	if err := d.confirmYesNo(r2, false); err != nil {
		t.Fatalf("confirmYesNo(false) error = %v", err)
	}
	cm2, ok := r2.current.(confirmModel)
	if !ok || !cm2.Finished() || cm2.Value() {
		t.Fatalf("confirmModel did not override defaultYes: %+v", r2.current)
	}
}

func TestEditAutomationDriverDeleteHost(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "create_host", Host: "web-2"},
			{Action: "delete_host", Host: "web-1"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "web-2" {
		t.Fatalf("hosts = %+v, want exactly web-2", hf.Hosts)
	}
}

func TestEditAutomationDriverDiscardHosts(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "discard_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("hosts.yml exists after discard_hosts, err=%v", err)
	}
}

func TestEditAutomationDriverExtraVarCRUD(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "a", Value: "1"},
			{Action: "add_extra_var", Host: "web-1", Key: "b", Value: "2"},
			{Action: "edit_extra_var", Host: "web-1", Key: "a", Value: "10"},
			{Action: "delete_extra_var", Host: "web-1", Key: "b"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want 1 host", hf.Hosts)
	}
	extra := hf.Hosts[0].Extra
	if len(extra) != 1 || extra["a"] != "10" {
		t.Fatalf("extra vars = %+v, want exactly a=10", extra)
	}
}

// TestEditAutomationDriverExtraVarKeyPrefixDisambiguation proves the
// "key + \" = \"" navigation fix: bare-substring matching would make
// "region" ambiguous against "region_id"'s own row ("region_id = 42"
// contains "region" as a substring), but "region = " does not appear
// inside "region_id = 42", so editing "region" resolves cleanly.
func TestEditAutomationDriverExtraVarKeyPrefixDisambiguation(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "region_id", Value: "42"},
			{Action: "add_extra_var", Host: "web-1", Key: "region", Value: "prod"},
			{Action: "edit_extra_var", Host: "web-1", Key: "region", Value: "staging"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	extra := hf.Hosts[0].Extra
	if extra["region_id"] != "42" || extra["region"] != "staging" {
		t.Fatalf("extra vars = %+v, want region_id=42 region=staging", extra)
	}
}

func TestEditAutomationDriverExtraVarValueEnv(t *testing.T) {
	t.Setenv("PILOT_TEST_EXTRA_SECRET", "s3cr3t-value")
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "api_key", ValueEnv: "PILOT_TEST_EXTRA_SECRET"},
			{Action: "save_hosts"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if hf.Hosts[0].Extra["api_key"] != "s3cr3t-value" {
		t.Fatalf("extra vars = %+v, want api_key=s3cr3t-value", hf.Hosts[0].Extra)
	}

	for _, event := range events {
		if event.Action != "add_extra_var" {
			continue
		}
		for _, k := range event.Keys {
			if strings.Contains(k, "s3cr3t-value") {
				t.Fatalf("trace leaked the secret value: %+v", event.Keys)
			}
		}
		found := false
		for _, k := range event.Keys {
			if k == "«redacted»" {
				found = true
			}
		}
		if !found {
			t.Fatalf("trace did not record a redacted placeholder for the secret step: %+v", event.Keys)
		}
	}
}

func TestEditAutomationDriverExtraVarValueEnvMissingErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "api_key", ValueEnv: "PILOT_TEST_UNSET_SECRET_VAR"},
			{Action: "save_hosts"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil || !strings.Contains(err.Error(), "PILOT_TEST_UNSET_SECRET_VAR") {
		t.Fatalf("driver.run() error = %v, want value_env-not-set error", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(statErr) {
		t.Fatalf("hosts.yml exists after a value_env failure, err=%v", statErr)
	}
}

func TestEditAutomationWorkflowRejectsValueEnvWithPresentation(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-1"},
		{Action: "add_extra_var", Host: "web-1", Key: "api_key", ValueEnv: "PILOT_TEST_EXTRA_SECRET"},
		{Action: "save_hosts"},
	}}
	oldDir := editDir
	editDir = dir
	t.Cleanup(func() { editDir = oldDir })
	err := runAutomatedEditWorkflow(cmd, scenario, true, "")
	if err == nil || !strings.Contains(err.Error(), "value_env") || !strings.Contains(err.Error(), "presentation") {
		t.Fatalf("runAutomatedEditWorkflow() error = %v, want value_env+presentation rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(statErr) {
		t.Fatalf("hosts.yml exists after a rejected value_env+presentation run, err=%v", statErr)
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
