package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditScenarioLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scenario.json")
	contents := `{
  "version": 1,
  "title": "Create a web host",
  "steps": [
    {"action": "create_host", "host": "web-1"},
    {"action": "set_host_field", "host": "web-1", "field": "ansible_host", "value": "10.0.0.5"},
    {"action": "enable_role", "host": "web-1", "role": "docker"},
    {"action": "save_hosts"}
  ]
}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	scenario, err := loadEditScenario(path)
	if err != nil {
		t.Fatalf("loadEditScenario() error = %v", err)
	}
	if err := validateEditScenario(scenario); err != nil {
		t.Fatalf("validateEditScenario() error = %v", err)
	}
	if scenario.Title != "Create a web host" || len(scenario.Steps) != 4 {
		t.Fatalf("scenario = %+v", scenario)
	}
}

func TestValidateEditScenarioRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		s    editScenario
		want string
	}{
		{name: "unsupported version", s: editScenario{Version: 2, Steps: []editAction{{Action: "save_hosts"}}}, want: "version"},
		{name: "empty steps", s: editScenario{Version: 1}, want: "steps"},
		{name: "unknown action", s: editScenario{Version: 1, Steps: []editAction{{Action: "delete_everything"}}}, want: "unknown action"},
		{name: "missing host", s: editScenario{Version: 1, Steps: []editAction{{Action: "create_host"}}}, want: "host"},
		{name: "secret field", s: editScenario{Version: 1, Steps: []editAction{{Action: "set_host_field", Host: "web-1", Field: "admin_password", Value: "secret"}}}, want: "secret"},
		{name: "unsupported env value", s: editScenario{Version: 1, Steps: []editAction{{Action: "set_host_field", Host: "web-1", Field: "env", Value: "qa"}}}, want: "env value"},
		{name: "delete_host missing host", s: editScenario{Version: 1, Steps: []editAction{{Action: "delete_host"}}}, want: "host"},
		{name: "add_extra_var missing key", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_extra_var", Host: "web-1", Value: "1"}}}, want: "key"},
		{name: "add_extra_var secret key", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_extra_var", Host: "web-1", Key: "api_token", Value: "1"}}}, want: "secret"},
		{name: "add_extra_var value and value_env", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_extra_var", Host: "web-1", Key: "a", Value: "1", ValueEnv: "X"}}}, want: "not both"},
		{name: "add_extra_var neither value nor value_env", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_extra_var", Host: "web-1", Key: "a"}}}, want: "value or value_env"},
		{name: "discard_hosts with parameters", s: editScenario{Version: 1, Steps: []editAction{{Action: "discard_hosts", Host: "web-1"}}}, want: "does not accept parameters"},
		{name: "set_group_var missing file", s: editScenario{Version: 1, Steps: []editAction{{Action: "set_group_var", Key: "dns_forwarders", Value: "1.1.1.1"}}}, want: "file"},
		{name: "set_group_var rejects value_env", s: editScenario{Version: 1, Steps: []editAction{{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", ValueEnv: "X"}}}, want: "value_env"},
		{name: "create_role_preset missing label", s: editScenario{Version: 1, Steps: []editAction{{Action: "create_role_preset", Host: "web-1", Roles: []string{"docker"}}}}, want: "label"},
		{name: "add_vault_key missing key", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_vault_key", File: "main.yaml", Value: "x"}}}, want: "key"},
		{name: "add_vault_key value and value_env", s: editScenario{Version: 1, Steps: []editAction{{Action: "add_vault_key", File: "main.yaml", Key: "a", Value: "1", ValueEnv: "X"}}}, want: "not both"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEditScenario(tt.s)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.want)) {
				t.Fatalf("validateEditScenario() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestValidateAddVaultKeyAllowsSecretLikeKeyName proves vault key names are
// deliberately exempt from hasSecretName, unlike set_host_field/enable_role/
// create_host — .vault/ exists specifically to hold secret-shaped names.
func TestValidateAddVaultKeyAllowsSecretLikeKeyName(t *testing.T) {
	err := validateEditScenario(editScenario{Version: 1, Steps: []editAction{
		{Action: "add_vault_key", File: "main.yaml", Key: "ipa_admin_password", Value: "x"},
	}})
	if err != nil {
		t.Fatalf("validateEditScenario() error = %v, want a secret-shaped vault key name to be accepted", err)
	}
}

func TestLoadEditScenarioRejectsUnknownJSONFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scenario.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"steps":[{"action":"save_hosts"}],"secret":"do-not-echo"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadEditScenario(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadEditScenario() error = %v, want unknown field", err)
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("error leaked rejected value: %v", err)
	}
}

func TestValidateEditScenarioAcceptsDeployAndReconcileSteps(t *testing.T) {
	answers := []promptAnswer{{Prompt: "要佈署什麼？", Select: "全站部署"}}
	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_host", Host: "web-1"},
		{Action: "save_hosts"},
		{Action: "deploy", Inventory: "inventory.yml", Answers: answers},
		{Action: "reconcile", Inventory: "inventory.yml", Answers: []promptAnswer{{Prompt: "挑一個", Select: "identity"}}},
	}}
	if err := validateEditScenario(scenario); err != nil {
		t.Fatalf("validateEditScenario() error = %v", err)
	}
}
