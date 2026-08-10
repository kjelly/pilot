package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// writeMinimalRosterFixture seeds dir's default roster path
// (.vault/ipa-identity.yaml, matching pushRosterPathPrompt's prefilled
// default — automation only ever accepts that default in this
// increment) with a minimal, valid, empty-users roster.
func writeMinimalRosterFixture(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	fixture := "schema_version: 1\nfreeipa: {domain: ipa.pilot.internal}\nusers: []\n"
	writeTestFile(t, path, fixture)
	return path
}

// TestEditAutomationDriverCreateUserBootstrapsRosterOnFreshWorkspace proves
// the fix for the automation driver not knowing how to answer
// pushRosterCreateConfirm's "no roster yet, create a minimal skeleton?"
// confirm (rosterCreateConfirmScreenID, edit_tui_roster.go): running
// create_user against a genuinely brand-new workspace — no
// writeMinimalRosterFixture call, unlike every other roster test in this
// file — used to fail with `cannot navigate to roster users list from
// confirm screen: cannot choose "返回" on confirm screen` the instant
// ensureRosterUsersList hit that confirm. resolveRosterCreatePrompt
// (edit_automation_driver_roster.go) now answers "yes" the same way
// openVaultFile already does for its own analogous ".vault/" bootstrap
// confirm, reusing .vault/main.yaml's ipa_admin_password when one is
// already on file so no password prompt is even shown.
func TestEditAutomationDriverCreateUserBootstrapsRosterOnFreshWorkspace(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("mkdir .vault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte("ipa_admin_password: Sup3rSecret!\n"), 0o600); err != nil {
		t.Fatalf("seed .vault/main.yaml: %v", err)
	}

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	rosterPath := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	names, err := inventory.RosterUserNames(rosterPath)
	if err != nil {
		t.Fatalf("read roster user names: %v", err)
	}
	found := false
	for _, n := range names {
		if n == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatalf("roster users = %v, want alice", names)
	}
}

// TestEditAutomationDriverCreateUserWithoutRosterOrPasswordErrorsClearly
// covers the other half of the same gap: a brand-new workspace with no
// reusable .vault/main.yaml ipa_admin_password can't auto-bootstrap the
// roster non-interactively (there is no scenario field yet to source a
// fresh password from), so this must fail with an actionable message
// naming that requirement, not the opaque screen-type mismatch it used to.
func TestEditAutomationDriverCreateUserWithoutRosterOrPasswordErrorsClearly(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("driver.run() error = nil, want an error naming the missing admin password")
	}
	if strings.Contains(err.Error(), "confirm screen") {
		t.Fatalf("driver.run() error = %v, still the opaque screen-type mismatch", err)
	}
	if !strings.Contains(err.Error(), "admin password") {
		t.Fatalf("driver.run() error = %v, want it to name the missing FreeIPA admin password", err)
	}
}

func TestEditAutomationDriverRosterFlow_CreateUserAndSetFields(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "set_user_field", User: "alice", Field: "email", Value: "alice@example.com"},
			{Action: "set_user_field", User: "alice", Field: "uid", Value: "10001"},
			{Action: "set_user_field", User: "alice", Field: "enabled", Value: "false"},
			{Action: "set_user_field", User: "alice", Field: "state", Value: "disabled"},
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
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	fields, found, err := inventory.RosterUser(path, "alice")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found {
		t.Fatal("expected user alice to exist after create_user")
	}
	if fields["email"] != "alice@example.com" {
		t.Fatalf("email = %v, want alice@example.com", fields["email"])
	}
	if uid, ok := fields["uid"].(int); !ok || uid != 10001 {
		t.Fatalf("uid = %v (%T), want int 10001", fields["uid"], fields["uid"])
	}
	if fields["enabled"] != false {
		t.Fatalf("enabled = %v, want false", fields["enabled"])
	}
	if fields["state"] != "disabled" {
		t.Fatalf("state = %v, want disabled", fields["state"])
	}
}

func TestEditAutomationDriverRosterFlow_SetUserFieldRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "bob"},
		{Action: "set_user_field", User: "bob", Field: "not_a_real_field", Value: "x"},
	}}
	err := validateEditScenario(scenario)
	if err == nil {
		t.Fatal("expected validateEditScenario to reject an unknown user field")
	}
}

func TestEditAutomationDriverRosterFlow_SetUserFieldRejectsBadEnumValues(t *testing.T) {
	cases := []editAction{
		{Action: "set_user_field", User: "x", Field: "state", Value: "absent"}, // not offered by this wizard
		{Action: "set_user_field", User: "x", Field: "enabled", Value: "yes"},
		{Action: "set_user_field", User: "x", Field: "uid", Value: "not-a-number"},
	}
	for _, step := range cases {
		if err := validateSetUserField(step); err == nil {
			t.Fatalf("expected validateSetUserField to reject %+v", step)
		}
	}
}

func TestEditAutomationDriverRosterFlow_CreateUserRejectsEmptyName(t *testing.T) {
	if err := validateCreateUser(editAction{Action: "create_user"}); err == nil {
		t.Fatal("expected validateCreateUser to reject an empty user name")
	}
}

func TestEditAutomationDriverRosterFlow_SetPasswordAndSSHKeys(t *testing.T) {
	const envVar = "PILOT_TEST_ROSTER_PASSWORD_DRIVER"
	t.Setenv(envVar, "s3cr3t-init-pw")

	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "carol"},
			{Action: "set_user_password", User: "carol", ValueEnv: envVar},
			{Action: "add_ssh_key", User: "carol", Value: "ssh-ed25519 AAAAFIRST carol@laptop"},
			{Action: "add_ssh_key", User: "carol", Value: "ssh-ed25519 AAAASECOND carol@phone"},
			{Action: "delete_ssh_key", User: "carol", Value: "ssh-ed25519 AAAAFIRST carol@laptop"},
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
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	fields, found, err := inventory.RosterUser(path, "carol")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found {
		t.Fatal("expected user carol to exist")
	}
	pw, _ := fields["password"].(map[string]any)
	if pw == nil || pw["initial"] != "s3cr3t-init-pw" {
		t.Fatalf("password = %+v, want initial=s3cr3t-init-pw", pw)
	}
	ssh, _ := fields["ssh_keys"].(map[string]any)
	values, _ := ssh["values"].([]any)
	if len(values) != 1 || values[0] != "ssh-ed25519 AAAASECOND carol@phone" {
		t.Fatalf("ssh_keys.values = %+v, want exactly the second key", values)
	}
}

func TestEditAutomationDriverRosterFlow_SetPasswordRejectsMissingValue(t *testing.T) {
	if err := validateSetUserPassword(editAction{Action: "set_user_password", User: "x"}); err == nil {
		t.Fatal("expected validateSetUserPassword to reject a step with neither value nor value_env")
	}
	if err := validateSetUserPassword(editAction{Action: "set_user_password"}); err == nil {
		t.Fatal("expected validateSetUserPassword to reject an empty user")
	}
}

func TestEditAutomationDriverRosterFlow_SSHKeyActionsRejectMissingFields(t *testing.T) {
	for _, name := range []string{"add_ssh_key", "delete_ssh_key"} {
		validate := validateUserSSHKeyAction(name)
		if err := validate(editAction{Action: name, User: "x"}); err == nil {
			t.Fatalf("expected %s to reject a step with no value", name)
		}
		if err := validate(editAction{Action: name, Value: "ssh-ed25519 AAAA"}); err == nil {
			t.Fatalf("expected %s to reject a step with no user", name)
		}
	}
}

// TestApplyEditScenario_RosterPasswordSentinelNeverLeaksIntoAuditArtifacts
// mirrors TestApplyEditScenario_VaultSentinelNeverLeaksIntoAuditArtifacts
// (edit_audit_artifact_vault_test.go) for set_user_password — the roster
// file is already IsSecret:true at file granularity (it lives under
// .vault/), so diff.patch redaction was already covered; this confirms
// scenario.redacted.json's Value field is also cleared for this action
// specifically now that it's in mcpSecretActionNames.
func TestApplyEditScenario_RosterPasswordSentinelNeverLeaksIntoAuditArtifacts(t *testing.T) {
	const envVar = "PILOT_TEST_ROSTER_PASSWORD_SENTINEL_APPLY"
	t.Setenv(envVar, vaultSentinelValue)

	dir := t.TempDir()
	auditDir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	scenario := editScenario{Version: 1, Title: "roster password sentinel test", Steps: []editAction{
		{Action: "create_user", User: "dana"},
		{Action: "set_user_password", User: "dana", ValueEnv: envVar},
	}}

	var castBuf bytes.Buffer
	recorder, err := newCastAuditRecorder(&castBuf, scenario.Title, castTerminalWidth, castTerminalHeight)
	if err != nil {
		t.Fatalf("newCastAuditRecorder() error = %v", err)
	}
	tracePath := filepath.Join(auditDir, "trace.jsonl")
	sink, err := newAutomationTraceSink(tracePath)
	if err != nil {
		t.Fatalf("newAutomationTraceSink() error = %v", err)
	}

	opts := editAgentSessionOptions{
		Trace:    func(event automationTraceEvent) { sink.add(event) },
		Recorder: recorder,
	}
	result, err := applyEditScenario(dir, "roster-password-sentinel-session", scenario, opts)
	if err != nil {
		t.Fatalf("applyEditScenario() error = %v", err)
	}
	if err := sink.close(); err != nil {
		t.Fatalf("sink.close() error = %v", err)
	}
	if result.RolledBack {
		t.Fatalf("expected a clean apply, got rolled back (ScenarioErr=%v)", result.ScenarioErr)
	}

	meta := auditMetadata{SessionID: "roster-password-sentinel-session", Kind: "apply", Workspace: dir}
	if err := writeApplyAuditArtifacts(auditDir, meta, scenario, result); err != nil {
		t.Fatalf("writeApplyAuditArtifacts() error = %v", err)
	}

	rosterData, err := os.ReadFile(filepath.Join(dir, ".vault", "ipa-identity.yaml"))
	if err != nil {
		t.Fatalf("read real roster file: %v", err)
	}
	if !strings.Contains(string(rosterData), vaultSentinelValue) {
		t.Fatalf("expected the real roster file to contain the sentinel value, got:\n%s", rosterData)
	}

	assertSentinelAbsent(t, "session.cast", castBuf.String(), vaultSentinelValue)

	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read trace.jsonl: %v", err)
	}
	assertSentinelAbsent(t, "trace.jsonl", string(traceData), vaultSentinelValue)

	for _, name := range []string{
		"metadata.json", "scenario.redacted.json", "diff.patch", "validation.json",
		"managed-files-before.json", "managed-files-after.json", "result.json",
	} {
		data, err := os.ReadFile(filepath.Join(auditDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		assertSentinelAbsent(t, name, string(data), vaultSentinelValue)
	}

	assertSentinelAbsent(t, "in-memory result.Diff", result.Diff, vaultSentinelValue)
	if !result.RedactedDiff {
		t.Fatal("expected RedactedDiff = true for a scenario that touched the roster file")
	}
}
