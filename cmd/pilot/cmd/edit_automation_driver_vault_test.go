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

// TestEditAutomationDriverVaultCreateFileBareNameGetsYamlExtension proves the
// fix for openVaultFile (edit_automation_driver_vault.go) treating a bare
// file name verbatim: on a fresh workspace with no .vault/main.yaml yet, a
// scenario step using file: "main" (no extension) used to create a literal
// ".vault/main" — invisible to every other .vault/main.yaml-hardcoded
// convention (deploy's defaultVaultFile, checkVaultCompleteness, `pilot
// inventory generate`'s --vault-out default). normalizeVaultFileName now
// makes the automation driver produce the exact same ".vault/main.yaml" a
// human accepting pushVaultPathPrompt's prefilled default would.
func TestEditAutomationDriverVaultCreateFileBareNameGetsYamlExtension(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main", Key: "ipa_admin_password", Value: "plain-value"},
		{Action: "save_vault", File: "main"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".vault", "main")); !os.IsNotExist(err) {
		t.Fatalf(".vault/main (extension-less) exists, want it not to: err=%v", err)
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

func TestEditAutomationDriverVaultCanonicalFilePaths(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{name: "bare name", file: "main", want: "main.yaml"},
		{name: "bare yaml", file: "main.yaml", want: "main.yaml"},
		{name: "vault-prefixed bare name", file: ".vault/main", want: "main.yaml"},
		{name: "vault-prefixed yaml", file: ".vault/main.yaml", want: "main.yaml"},
		{name: "vault-prefixed yml", file: ".vault/foo.yml", want: "foo.yml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			scenario := editScenario{Version: 1, Steps: []editAction{
				{Action: "add_vault_key", File: tt.file, Key: "a", Value: "1"},
				{Action: "save_vault", File: tt.file},
			}}
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			if err := d.run(&r, scenario); err != nil {
				t.Fatalf("driver.run() error = %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, ".vault", tt.want)); err != nil {
				t.Fatalf("canonical vault file not written: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, ".vault", ".vault", tt.want)); !os.IsNotExist(err) {
				t.Fatalf("double-prefixed vault file exists, err=%v", err)
			}

			// Start again from the picker to prove a canonical spelling also
			// selects an already-existing file rather than only creating it.
			r2 := newEditRouterModel(dir)
			d2 := automationDriver{dir: dir}
			if err := d2.run(&r2, editScenario{Version: 1, Steps: []editAction{
				{Action: "set_vault_value", File: tt.file, Key: "a", Value: "2"},
				{Action: "save_vault", File: tt.file},
			}}); err != nil {
				t.Fatalf("reopen existing canonical vault file: %v", err)
			}
		})
	}
}

func TestEditAutomationDriverVaultPrefixedMainReusedByNFSServer(t *testing.T) {
	dir := t.TempDir()
	vaultScenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: ".vault/main.yaml", Key: "ipa_admin_password", Value: "test-password"},
		{Action: "save_vault", File: ".vault/main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, vaultScenario); err != nil {
		t.Fatalf("save prefixed main vault file: %v", err)
	}

	// A fresh router models the later scenario phase. NFS reads its default
	// .vault/main.yaml directly, so this must not request a second password.
	nfsScenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "nexus"},
		{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server"},
	}}
	r2 := newEditRouterModel(dir)
	d2 := automationDriver{dir: dir}
	if err := d2.run(&r2, nfsScenario); err != nil {
		t.Fatalf("enable NFS server with saved vault password: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".vault", ".vault", "main.yaml")); !os.IsNotExist(err) {
		t.Fatalf("double-prefixed vault file exists, err=%v", err)
	}
}

func TestEditAutomationDriverVaultRejectsEscapingPaths(t *testing.T) {
	for _, file := range []string{"../main.yaml", ".vault/../main.yaml", "/tmp/main.yaml"} {
		t.Run(file, func(t *testing.T) {
			err := validateEditScenario(editScenario{Version: 1, Steps: []editAction{{
				Action: "add_vault_key", File: file, Key: "a", Value: "1",
			}}})
			if err == nil || !strings.Contains(err.Error(), "vault file") {
				t.Fatalf("validateEditScenario() error = %v, want unsafe vault path rejection", err)
			}
		})
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

func TestEditAutomationDriverVaultSNMPMapBackfillsAndSetsAgentControllerSecret(t *testing.T) {
	t.Setenv("PILOT_TEST_AGENT_CONTROLLER_SECRET", "agent-controller-test-secret")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(`hosts:
  it-core:
    roles: [agent-controller]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vaultDir, "main.yaml")
	initial := "ipa_admin_password: placeholder\nsnmp_exporter_credentials:\n  switch-v3:\n    username: operator\n    authPassword: auth\n    privPassword: priv\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "agent_controller_webhook_secret", ValueEnv: "PILOT_TEST_AGENT_CONTROLLER_SECRET"},
		{Action: "save_vault", File: "main.yaml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `agent_controller_webhook_secret: "agent-controller-test-secret"`) {
		t.Fatalf("agent-controller secret was not saved:\n%s", data)
	}
	if !strings.Contains(string(data), "snmp_exporter_credentials:\n  switch-v3:\n    username: operator") {
		t.Fatalf("SNMP credentials mapping was not preserved:\n%s", data)
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

func TestEditAutomationDriverVaultSetValueEnvPreservesMultilineValue(t *testing.T) {
	const envName = "PILOT_TEST_MULTILINE_VAULT_VALUE"
	want := "global:\n  resolve_timeout: 5m\nreceivers:\n  - name: teams\n"
	t.Setenv(envName, want)
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vaultDir, "main.yaml")
	if err := os.WriteFile(path, []byte("alertmanager_config: initial\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "alertmanager_config", ValueEnv: envName},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatalf("parse saved vault: %v\n%s", err, data)
	}
	entries := doc.ScalarEntries()
	if len(entries) != 1 || entries[0].Key != "alertmanager_config" || entries[0].Value.Value != want {
		t.Fatalf("multiline vault value = %#v, want %#v\n%s", entries, want, data)
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
