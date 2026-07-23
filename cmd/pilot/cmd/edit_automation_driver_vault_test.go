package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/vaultfile"
	"github.com/spf13/cobra"
)

func TestEditAutomationDriverVaultCreateFileAddKeySave(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "ipa_admin_password", Value: "plain-value"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read .vault/main.yaml: %v", err)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatalf("parse vault file: %v\n%s", err, data)
	}
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Key != "ipa_admin_password" || entries[0].Value.Value != "plain-value" {
		t.Fatalf("entries = %+v, want ipa_admin_password=plain-value\n%s", entries, data)
	}
}

func TestEditAutomationDriverVaultSetAndDeleteKey(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "a", Value: "1"},
		{Action: "add_vault_key", File: "main.yaml", Key: "b", Value: "2"},
		{Action: "set_vault_value", File: "main.yaml", Key: "a", Value: "10"},
		{Action: "delete_vault_key", File: "main.yaml", Key: "b"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read .vault/main.yaml: %v", err)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatalf("parse vault file: %v\n%s", err, data)
	}
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Key != "a" || entries[0].Value.Value != "10" {
		t.Fatalf("entries = %+v, want exactly a=10\n%s", entries, data)
	}
}

func TestEditAutomationDriverVaultAddKeyFromValueEnv(t *testing.T) {
	t.Setenv("PILOT_TEST_VAULT_SECRET", "s3cr3t-vault-value")
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "ipa_admin_password", ValueEnv: "PILOT_TEST_VAULT_SECRET"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir, trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read .vault/main.yaml: %v", err)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatalf("parse vault file: %v\n%s", err, data)
	}
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Value.Value != "s3cr3t-vault-value" {
		t.Fatalf("entries = %+v, want the resolved secret written to disk\n%s", entries, data)
	}

	for _, event := range events {
		if event.Action != "add_vault_key" {
			continue
		}
		found := false
		for _, k := range event.Keys {
			if strings.Contains(k, "s3cr3t-vault-value") {
				t.Fatalf("trace leaked the secret value: %+v", event.Keys)
			}
			if k == "«redacted»" {
				found = true
			}
		}
		if !found {
			t.Fatalf("trace did not record a redacted placeholder for the secret step: %+v", event.Keys)
		}
	}
}

func TestEditAutomationDriverVaultSetValueMissingEnvErrors(t *testing.T) {
	dir := t.TempDir()
	// Setup: create the file and persist a known baseline value.
	setup := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "ipa_admin_password", Value: "placeholder"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, setup); err != nil {
		t.Fatalf("setup driver.run() error = %v", err)
	}

	// The actual test: a set_vault_value naming an unset env var must fail
	// before ever typing anything, leaving the saved value untouched.
	failing := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", ValueEnv: "PILOT_TEST_UNSET_VAULT_VAR"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r2 := newEditRouterModel(dir)
	d2 := automationDriver{dir: dir}
	err := d2.run(&r2, failing)
	if err == nil || !strings.Contains(err.Error(), "PILOT_TEST_UNSET_VAULT_VAR") {
		t.Fatalf("driver.run() error = %v, want value_env-not-set error", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read .vault/main.yaml: %v", err)
	}
	if !strings.Contains(string(data), "placeholder") {
		t.Fatalf("vault file mutated despite the value_env failure:\n%s", data)
	}
}

func TestEditAutomationWorkflowRejectsVaultValueEnvWithPresentation(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "ipa_admin_password", ValueEnv: "PILOT_TEST_VAULT_SECRET"},
		{Action: "save_vault", File: "main.yaml"},
		{Action: "save_hosts"},
	}}
	oldDir := editDir
	editDir = dir
	t.Cleanup(func() { editDir = oldDir })
	err := runAutomatedEditWorkflow(cmd, scenario, true, "")
	if err == nil || !strings.Contains(err.Error(), "value_env") || !strings.Contains(err.Error(), "presentation") {
		t.Fatalf("runAutomatedEditWorkflow() error = %v, want value_env+presentation rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".vault", "main.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf(".vault/main.yaml exists after a rejected value_env+presentation run, err=%v", statErr)
	}
}

func TestEditAutomationDriverVaultDiscardKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	// First scenario: create the file with a baseline key.
	setup := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "a", Value: "1"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, setup); err != nil {
		t.Fatalf("setup driver.run() error = %v", err)
	}

	// Second scenario: edit then discard — the on-disk file must be unchanged.
	discard := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "a", Value: "changed"},
		{Action: "discard_vault", File: "main.yaml"},
	}}
	r2 := newEditRouterModel(dir)
	d2 := automationDriver{dir: dir}
	if err := d2.run(&r2, discard); err != nil {
		t.Fatalf("discard driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("read .vault/main.yaml: %v", err)
	}
	if strings.Contains(string(data), "changed") {
		t.Fatalf("discard_vault should have kept the original on-disk value:\n%s", data)
	}
}

// TestEditAutomationDriverHostsGroupVarsVaultOneScenario proves the full
// cross-workspace chain works in a single scenario: hosts.yml -> save_hosts
// -> group_vars -> save_group_vars -> vault -> save_vault. save_hosts must
// land at the top menu (not quit) for the group_vars step to go anywhere,
// and each workspace's file picker must be a safe hop-off point back to the
// top menu for the next workspace's action to reach it.
func TestEditAutomationDriverHostsGroupVarsVaultOneScenario(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-1"},
		{Action: "save_hosts"},
		{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", Value: "1.1.1.1"},
		{Action: "save_group_vars", File: "dns.yml"},
		{Action: "add_vault_key", File: "main.yaml", Key: "a", Value: "1"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err != nil {
		t.Fatalf("hosts.yml not written: %v", err)
	}
	gvData, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gvData), "1.1.1.1") {
		t.Fatalf("dns.yml not updated:\n%s", gvData)
	}
	if _, err := os.Stat(filepath.Join(dir, ".vault", "main.yaml")); err != nil {
		t.Fatalf(".vault/main.yaml not written: %v", err)
	}
}

func TestEditAutomationDriverVaultNestedYamlFileFails(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A roster-shaped file (nested map) — doc.Editable() rejects this even
	// for a human; automation must surface the same fatal error, not a
	// silent no-op or a crash.
	nested := "users:\n  - name: alice\n    roles: [admin]\n"
	if err := os.WriteFile(filepath.Join(vaultDir, "roster.yaml"), []byte(nested), 0o600); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "roster.yaml", Key: "x", Value: "1"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	err := d.run(&r, scenario)
	if err == nil || !strings.Contains(err.Error(), "複雜 YAML") {
		t.Fatalf("driver.run() error = %v, want the doc.Editable() rejection to surface", err)
	}
}
