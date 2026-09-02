package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
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
	// must still be able to navigate from here. Checked via the screen-ID
	// contract rather than a concrete type assertion: pushTopMenu's screen
	// is now built through r.uiFactory() (Huh-backed in production), not
	// necessarily this package's selectModel.
	if got := automationScreenID(&r); got != "edit.top" {
		t.Fatalf("expected top menu after save_hosts, got %s", got)
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
	if !strings.Contains(out.String(), "⌨ 按鍵：") || !strings.Contains(out.String(), `TEXT "web-1"`) {
		t.Fatalf("presentation output missing expanded keyboard commands:\n%s", out.String())
	}
	trace, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace: %v", err)
	}
	if got := strings.Count(string(trace), "\"result\":\"ok\""); got != 2 {
		t.Fatalf("trace success events = %d, want 2:\n%s", got, trace)
	}
}

func TestEditAutomationDriverPresentationPausesBetweenRenderedSteps(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-1"},
		{Action: "save_hosts"},
	}}
	var pauses []time.Duration
	r := newEditRouterModel(dir)
	d := automationDriver{
		presentation:      true,
		out:               &bytes.Buffer{},
		pausePresentation: func(duration time.Duration) { pauses = append(pauses, duration) },
	}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if len(pauses) != len(scenario.Steps) {
		t.Fatalf("presentation pauses = %d, want %d", len(pauses), len(scenario.Steps))
	}
	for _, got := range pauses {
		if got != time.Second {
			t.Fatalf("presentation pause = %s, want %s", got, time.Second)
		}
	}
}

func TestFormatKeyboardCommands(t *testing.T) {
	got := formatKeyboardCommands([]string{"down", "down", "enter", "ctrl+u", "web-1", "space", "«redacted»"})
	want := `↓ × 2 → Enter → Ctrl+U → TEXT "web-1" → Space → TEXT «redacted»`
	if got != want {
		t.Fatalf("formatKeyboardCommands() = %q, want %q", got, want)
	}
	if got := formatKeyboardCommands(nil); got != "（無；此操作未送出按鍵）" {
		t.Fatalf("formatKeyboardCommands(nil) = %q", got)
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

// TestEditAutomationDriverEnableRolePrometheusRequiresHostVars proves the
// fix for the gap where enabling "prometheus" (the only role with
// inventory.roleContract.HostVarsKeys) on a host with no
// prometheus_site_label value used to fail with the opaque
// `cannot choose "✅ 完成" on text-input screen` — pushForcedHostVarsPrompt
// (edit_tui_hostvars.go) detours the interactive router into a text-input
// screen that setRoleChecked's unconditional choose("✅ 完成") never
// accounted for. Omitting host_vars must now fail with an error that names
// the missing key, not that opaque screen-type mismatch.
func TestEditAutomationDriverEnableRolePrometheusRequiresHostVars(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "nexus"},
			{Action: "enable_role", Host: "nexus", Role: "prometheus"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the missing host_vars key")
	}
	if strings.Contains(err.Error(), "text-input screen") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "prometheus_site_label") {
		t.Fatalf("driver.run() error = %v, want it to name prometheus_site_label", err)
	}
}

// TestEditAutomationDriverEnableRolePrometheusFillsHostVars is the same
// scenario's happy path: supplying host_vars answers the forced prompt the
// same way a human would type "site-nexus" into it, and enable_role
// completes normally, leaving the router back at the host menu ready for
// the next step (save_hosts here).
func TestEditAutomationDriverEnableRolePrometheusFillsHostVars(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "nexus"},
			{Action: "enable_role", Host: "nexus", Role: "prometheus", HostVars: map[string]string{"prometheus_site_label": "site-nexus"}},
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
	if len(hf.Hosts) != 1 || !hasRole(hf.Hosts[0].Roles, "prometheus") {
		t.Fatalf("hosts = %+v, want role prometheus", hf.Hosts)
	}

	hvData, err := os.ReadFile(filepath.Join(dir, "host_vars", "nexus.yml"))
	if err != nil {
		t.Fatalf("read host_vars/nexus.yml: %v", err)
	}
	if !strings.Contains(string(hvData), "prometheus_site_label: site-nexus") {
		t.Fatalf("host_vars/nexus.yml = %q, want prometheus_site_label: site-nexus", hvData)
	}
}

// TestEditAutomationDriverEnableFreeipaNFSServerWithoutPasswordErrors proves
// the fix for the automation driver not knowing how to answer
// pushNFSRoleBootstrap's own FreeIPA admin password prompt
// (nfsRosterBootstrapPasswordScreenID, edit_tui.go): newly enabling
// freeipa-nfs-server on a workspace with no reusable .vault/main.yaml
// ipa_admin_password used to fail with the opaque `unexpected text-input
// screen "text-input" after role checklist confirm` the moment
// resolveRoleChangeFollowUp's loop hit that screen. Omitting value/value_env
// must now fail with an error that names the missing admin password.
func TestEditAutomationDriverEnableFreeipaNFSServerWithoutPasswordErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "nexus"},
			{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the missing admin password")
	}
	if strings.Contains(err.Error(), "text-input screen") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "admin password") {
		t.Fatalf("driver.run() error = %v, want it to name the missing FreeIPA admin password", err)
	}
}

// TestEditAutomationDriverEnableFreeipaNFSServerBootstrapsWithPassword is the
// happy path: supplying value answers pushNFSRoleBootstrap's password
// prompt the same way a human would type it in, and enable_role completes
// normally, actually writing the minimal NFS roster.
func TestEditAutomationDriverEnableFreeipaNFSServerBootstrapsWithPassword(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "nexus"},
			{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server", Value: "Sup3rSecret!"},
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
	if len(hf.Hosts) != 1 || !hasRole(hf.Hosts[0].Roles, "freeipa-nfs-server") {
		t.Fatalf("hosts = %+v, want nexus with freeipa-nfs-server", hf.Hosts)
	}
	rosterFile := hf.Hosts[0].Extra["freeipa_roster_file"]
	if rosterFile == "" {
		t.Fatalf("freeipa_roster_file not set on host: %+v", hf.Hosts[0])
	}
	if _, err := os.Stat(rosterFile); err != nil {
		t.Fatalf("roster file not created at %s: %v", rosterFile, err)
	}
}

// TestEditAutomationDriverApplyRolePresetBootstrapsNFSAndFillsForcedHostVars
// proves two fixes at once by applying a preset containing both
// freeipa-nfs-server and prometheus in a single commit:
//
//  1. applyRolePreset (edit_automation_driver_presets.go) now resolves the
//     same NFS-bootstrap/forced-host-vars detours enable_role does, instead
//     of blindly choose("✅ 完成") — which used to fail with `cannot choose
//     "✅ 完成" on text-input screen` the instant a preset newly enabled NFS.
//  2. pushNFSRoleBootstrapWithPassword (edit_tui.go) now chains into
//     pushForcedHostVarsPrompt for the *other* newly-checked role
//     (prometheus) instead of returning straight to the roles menu — before
//     the fix, prometheus_site_label would never get asked for at all when
//     NFS was enabled in the same commit, silently leaving it unset.
func TestEditAutomationDriverApplyRolePresetBootstrapsNFSAndFillsForcedHostVars(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "template"},
			{Action: "create_role_preset", Host: "template", Label: "nfs-plus-prometheus", Roles: []string{"freeipa-nfs-server", "prometheus"}},
			{Action: "create_host", Host: "nexus"},
			{
				Action:   "apply_role_preset",
				Host:     "nexus",
				Preset:   "nfs-plus-prometheus",
				Value:    "Sup3rSecret!",
				HostVars: map[string]string{"prometheus_site_label": "site-nexus"},
			},
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
	var nexus *inventory.Host
	for i := range hf.Hosts {
		if hf.Hosts[i].Name == "nexus" {
			nexus = &hf.Hosts[i]
		}
	}
	if nexus == nil || !hasRole(nexus.Roles, "freeipa-nfs-server") || !hasRole(nexus.Roles, "prometheus") {
		t.Fatalf("nexus = %+v, want both freeipa-nfs-server and prometheus", nexus)
	}
	rosterFile := nexus.Extra["freeipa_roster_file"]
	if rosterFile == "" {
		t.Fatalf("freeipa_roster_file not set on nexus: %+v", nexus)
	}
	if _, err := os.Stat(rosterFile); err != nil {
		t.Fatalf("roster file not created at %s: %v", rosterFile, err)
	}

	hvData, err := os.ReadFile(filepath.Join(dir, "host_vars", "nexus.yml"))
	if err != nil {
		t.Fatalf("read host_vars/nexus.yml: %v", err)
	}
	if !strings.Contains(string(hvData), "prometheus_site_label: site-nexus") {
		t.Fatalf("host_vars/nexus.yml = %q, want prometheus_site_label: site-nexus", hvData)
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

// TestEditAutomationDriver_HostSettingsRoundTrip drives every editable
// first-class host setting through the real router, saves it, then re-parses
// hosts.yml. This is intentionally a disk assertion rather than an
// in-memory screen assertion: Render is a separate writer from Generate and
// previously dropped deployment_availability only at this final boundary.
func TestEditAutomationDriver_HostSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "sentinel"},
			{Action: "set_host_field", Host: "sentinel", Field: "ansible_host", Value: "10.0.0.42"},
			{Action: "set_host_field", Host: "sentinel", Field: "ansible_user", Value: "operator"},
			{Action: "set_host_field", Host: "sentinel", Field: "ssh_key_file", Value: "~/.ssh/sentinel"},
			{Action: "set_host_field", Host: "sentinel", Field: "env", Value: "staging"},
			{Action: "set_host_field", Host: "sentinel", Field: "deployment_availability", Value: "optional"},
			{Action: "enable_role", Host: "sentinel", Role: "docker"},
			{Action: "add_extra_var", Host: "sentinel", Key: "custom_setting", Value: "preserved"},
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
		t.Fatalf("Parse(saved hosts.yml) error: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want one host", hf.Hosts)
	}
	h := hf.Hosts[0]
	if h.AnsibleHost != "10.0.0.42" || h.AnsibleUser != "operator" || h.SSHKeyFile != "~/.ssh/sentinel" || h.Env != "staging" || h.DeploymentAvailability != inventory.DeploymentAvailabilityOptional || !hasRole(h.Roles, "docker") || h.Extra["custom_setting"] != "preserved" {
		t.Fatalf("saved host lost a TUI setting: %+v\n%s", h, data)
	}
}

func TestAutomationDriverConfirmYesNo(t *testing.T) {
	r := &editRouterModel{}
	r.current = tui.NewHuhFactory().Confirm(tui.ConfirmSpec{Title: "q?", Default: false})
	d := automationDriver{}
	if err := d.confirmYesNo(r, true); err != nil {
		t.Fatalf("confirmYesNo(true) error = %v", err)
	}
	cm, ok := r.current.(tui.ConfirmScreen)
	if !ok || !cm.Finished() || !cm.Value() {
		t.Fatalf("ConfirmScreen not resolved to yes: %+v", r.current)
	}

	r2 := &editRouterModel{}
	r2.current = tui.NewHuhFactory().Confirm(tui.ConfirmSpec{Title: "q?", Default: true}) // defaultYes=true, but we still expect an explicit "no" to win
	if err := d.confirmYesNo(r2, false); err != nil {
		t.Fatalf("confirmYesNo(false) error = %v", err)
	}
	cm2, ok := r2.current.(tui.ConfirmScreen)
	if !ok || !cm2.Finished() || cm2.Value() {
		t.Fatalf("ConfirmScreen did not override defaultYes: %+v", r2.current)
	}
}

func TestEditAutomationDriverDeleteHost(t *testing.T) {
	// delete_host now drives the decommission flow (spec.md §7.2/§11),
	// which plans from hosts.yml as it exists ON DISK (INV-2/INV-3) — it
	// is no longer a pure in-memory mutation deferred to a later
	// save_hosts step. So this fixture seeds hosts.yml directly (as if a
	// prior session had already saved it), rather than creating the hosts
	// in-memory first: a host created earlier in the SAME unsaved session
	// cannot be decommissioned before it has ever been persisted, exactly
	// like the interactive wizard.
	dir := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", filepath.Join(t.TempDir(), "pilot-data"))
	origDataDir := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = origDataDir })

	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(
		"hosts:\n  web-1:\n    ansible_host: \"10.0.0.1\"\n  web-2:\n    ansible_host: \"10.0.0.2\"\n",
	), 0o644); err != nil {
		t.Fatalf("seed hosts.yml: %v", err)
	}

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
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

// TestEditAutomationDriverAddExtraVarDuplicateKeyErrors proves the fix for
// the driver silently treating a rejected "新增變數" Enter as successful:
// pushAddExtraVar's validate() (edit_tui.go) rejects a key that already
// exists in h.Extra and leaves the router on the same, not-yet-confirmed
// text-input screen with its own local err set. Before the fix, send()/
// enter() only checked editRouterModel.err (reserved for I/O/vault
// failures) and never looked at that local err, so the driver typed the
// next step's characters into the still-active key field and only failed
// much later with an opaque "cannot choose ... on text-input screen".
// textInputRejectionError (edit_automation_driver.go) now surfaces the
// duplicate-key message the moment the Enter is rejected.
func TestEditAutomationDriverAddExtraVarDuplicateKeyErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "a", Value: "1"},
			{Action: "add_extra_var", Host: "web-1", Key: "a", Value: "2"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the duplicate key")
	}
	if strings.Contains(err.Error(), "cannot choose") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("driver.run() error = %v, want it to say the key already exists", err)
	}
}

// TestEditAutomationDriverEnableNFSServerThenDuplicateExtraVarErrors
// reproduces the exact real-world collision: enabling freeipa-nfs-server
// auto-creates the host's freeipa_roster_file extra var
// (pushNFSRoleBootstrap, edit_tui.go), so a scenario step that also tries
// to add_extra_var that same key must fail with a clear "already exists"
// message rather than the opaque screen-type error from a later,
// unrelated step.
func TestEditAutomationDriverEnableNFSServerThenDuplicateExtraVarErrors(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("mkdir .vault: %v", err)
	}
	// Pre-seed the admin password so pushNFSRoleBootstrap skips its own
	// password prompt and writes the roster straight away, matching a
	// scenario where an earlier step already populated .vault/main.yaml.
	vaultContent := "ipa_admin_password: Sup3rSecret!\n"
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte(vaultContent), 0o600); err != nil {
		t.Fatalf("seed .vault/main.yaml: %v", err)
	}

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "nexus"},
			{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server"},
			{Action: "add_extra_var", Host: "nexus", Key: "freeipa_roster_file", Value: "/tmp/should-not-be-used.yaml"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the already-set freeipa_roster_file key")
	}
	if strings.Contains(err.Error(), "cannot choose") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "freeipa_roster_file") || !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("driver.run() error = %v, want it to name freeipa_roster_file as already existing", err)
	}
}

// TestEditAutomationDriverExtraVarPresentationShowsContent proves that a
// presentation recording captures each extra var's actual key/value —
// pushExtraVarsMenu (edit_tui.go) is presented as an interior sub-step right
// before the driver navigates back to the host menu, whose own listing only
// ever shows a count ("其他變數(共 N 個)") and never the content.
func TestEditAutomationDriverExtraVarPresentationShowsContent(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "add_extra_var", Host: "web-1", Key: "ipa_server_ip", Value: "10.0.0.9"},
			{Action: "edit_extra_var", Host: "web-1", Key: "ipa_server_ip", Value: "10.0.0.10"},
			{Action: "delete_extra_var", Host: "web-1", Key: "ipa_server_ip"},
			{Action: "save_hosts"},
		},
	}

	var out bytes.Buffer
	r := newEditRouterModel(dir)
	d := automationDriver{presentation: true, out: &out}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"新增變數：ipa_server_ip", "ipa_server_ip = 10.0.0.9",
		"修改變數：ipa_server_ip", "ipa_server_ip = 10.0.0.10",
		"刪除變數：ipa_server_ip",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("presentation output missing %q:\n%s", want, got)
		}
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
