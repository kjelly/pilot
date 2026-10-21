package delivery

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"go.yaml.in/yaml/v3"
)

// Exercise canonical contracts after the same Ansible inventory decoding used
// by deploy. Before #81 these malformed optional inputs passed unnoticed.
func TestSpecInventoryInputsPreflight(t *testing.T) {
	if _, err := exec.LookPath("ansible-inventory"); err != nil {
		t.Skip(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, name string
		value    any
	}{
		{"alertmanager", "alertmanager_teams_proxy_port", "9095"},
		{"dashboard", "dashboard_config_dir", "/srv/dashboard"},
		{"dns", "dns_zones", []any{map[string]any{"name": "example.test", "stub_addr": "192.0.2.1"}}},
		{"dns", "dns_upstream", "1.1.1.1,9.9.9.9"},
		{"freeipa-client", "ipa_client_fqdn", "node.example.test"},
		{"freeipa-dns-client", "freeipa_setup_dns", false},
		{"freeipa-dns", "freeipa_realm", "EXAMPLE.TEST"},
		{"freeipa-identity", "freeipa_roster_file", "/tmp/roster.yml"},
		{"freeipa-realm-replacement", "freeipa_realm_replacement_verify_user", "canary"},
		{"freeipa-server-replica", "freeipa_dns_forwarders", []any{"1.1.1.1"}},
		{"freeipa-server", "ipa_dns_forwarders", nil},
		{"prometheus", "thanos_s3_port", 9443},
		{"restic-backup", "restic_backup_timer_persistent", false},
		{"thanos-query", "thanos_query_sidecar_grpc_port", 11901},
		{"wazuh-fim", "wazuh_repo_channel", "4.x"},
	} {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			t.Parallel()
			component, err := loader.LoadFile("contracts/" + tc.id + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]any{}
			if tc.id == "restic-backup" {
				values["restic_s3_target_host"] = "192.0.2.9"
			}
			declared := false
			for _, input := range component.GroupVars {
				declared = declared || input.Name == tc.name
				if input.Required {
					values[input.Name] = "test-input-password"
				}
			}
			if !declared {
				t.Fatal("input is absent from the canonical contract")
			}
			values[tc.name] = tc.value
			inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{"test-host": values}}}
			raw, err := yaml.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "inventory.yml")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("ansible-inventory", "-i", path, "--list").Output()
			if err != nil {
				t.Fatal(err)
			}
			var resolved struct {
				Meta struct {
					HostVars map[string]map[string]any `json:"hostvars"`
				} `json:"_meta"`
			}
			if err := json.Unmarshal(out, &resolved); err != nil {
				t.Fatal(err)
			}
			values = resolved.Meta.HostVars["test-host"]
			if err := validateInputs(component, values); err != nil {
				t.Fatalf("valid inventory rejected: %v", err)
			}
			values[tc.name] = map[string]any{"invalid": true}
			if err := validateInputs(component, values); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("malformed input should fail its own preflight check: %v", err)
			}
		})
	}
}
