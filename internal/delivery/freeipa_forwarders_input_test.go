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

// Keep the actual forwarder input forms through Ansible's inventory decoder
// and the production contract loader/preflight. Declaring a list-only input
// would fix the consistency lint while breaking existing scalar/null inputs.
func TestFreeIPAForwardersContractPreflight(t *testing.T) {
	ansible, err := exec.LookPath("ansible-inventory")
	if err != nil {
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
	component, err := loader.LoadFile("contracts/freeipa-server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	declared := false
	for _, input := range component.GroupVars {
		if input.Name == "freeipa_dns_forwarders" {
			declared = true
			if input.Type != "stringOrStringList" || input.Required || input.Default != nil {
				t.Fatalf("forwarders must preserve scalar/list/null and unset semantics: %#v", input)
			}
		}
	}
	if !declared {
		t.Fatal("freeipa_dns_forwarders is absent from the canonical contract")
	}
	for _, tc := range []struct {
		name       string
		value      any
		omit, want bool
	}{
		{name: "unset", omit: true, want: true},
		{name: "null clears", value: nil, want: true},
		{name: "empty scalar clears", value: "", want: true},
		{name: "scalar", value: "1.1.1.1 port 53 9.9.9.9", want: true},
		{name: "list", value: []any{"1.1.1.1", "9.9.9.9 port 53"}, want: true},
		{name: "empty list clears", value: []any{}, want: true},
		{name: "boolean", value: true},
		{name: "number", value: 53},
		{name: "mixed list", value: []any{"1.1.1.1", 53}},
		{name: "mapping", value: map[string]any{"address": "1.1.1.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{"ipa_admin_password": strings.Repeat("a", 16)}
			if !tc.omit {
				vars["freeipa_dns_forwarders"] = tc.value
			}
			inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{"ipa": vars}}}
			raw, err := yaml.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "inventory.yaml")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(ansible, "-i", path, "--list")
			out, err := cmd.Output()
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
			_, err = ValidateContractPreflight(PreflightRequest{
				Selected: []contract.Contract{component},
				Scope:    Scope{HostsByRole: map[string][]string{"freeipa-server": {"ipa"}}},
				Inputs:   map[string]map[string]any{"freeipa-server": resolved.Meta.HostVars["ipa"]},
			})
			if (err == nil) != tc.want {
				t.Fatalf("preflight error=%v, want accepted=%v", err, tc.want)
			}
		})
	}
}
