package cmd

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

func TestInspectGroupVars_NoSecretValues(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "group_vars", "dashboard.yml"), `grafana_admin_password: DUMMY_KNOWN_SECRET
custom_setting: DUMMY_UNKNOWN_SECRET
thanos_query_url: http://query.example:10902
dashboard_config_dir: {password: DUMMY_NESTED_SECRET}
custom_nested:
  password: DUMMY_BLOCK_SECRET
empty_secret: ""
null_secret: null
false_secret: false
# commented_secret: DUMMY_COMMENT_SECRET
`)
	_, out, err := inspectHandler(editMCPToolsOptions{Dir: dir})(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeGroupVars: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "DUMMY_") {
		t.Fatal("inspect response contains a dummy secret")
	}
	if got := out.GroupVars["dashboard.yml"]["thanos_query_url"]; got != "http://query.example:10902" {
		t.Fatalf("public setting = %q", got)
	}
	for _, key := range []string{"grafana_admin_password", "custom_setting", "dashboard_config_dir", "custom_nested"} {
		meta, present := out.GroupVarsMetadata["dashboard.yml"][key]
		if !present || !meta.Present || !meta.IsSet || !meta.Redacted || meta.Source != "group_vars/dashboard.yml" {
			t.Fatalf("metadata for %s = %+v", key, meta)
		}
		if out.GroupVars["dashboard.yml"][key] != inspectRedactedValue {
			t.Fatalf("missing redaction for %s", key)
		}
	}
	for _, key := range []string{"empty_secret", "null_secret", "false_secret"} {
		meta := out.GroupVarsMetadata["dashboard.yml"][key]
		if !meta.Present || !meta.Redacted || meta.IsSet != (key == "false_secret") {
			t.Fatalf("metadata for %s = %+v", key, meta)
		}
	}
	if _, exists := out.GroupVars["dashboard.yml"]["commented_secret"]; exists {
		t.Fatal("commented field should not be present")
	}
}

func TestInspectGroupVars_Filters(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "group_vars", "dns.yml"), "dns_cache_max_ttl: 300\ncustom_setting: DUMMY_UNKNOWN\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "all.yaml"), "dns_cache_max_ttl: 600\ngrafana_admin_password: DUMMY_PASSWORD\n")
	for _, tc := range []struct {
		name        string
		in          inspectInput
		files, keys int
	}{
		{"component", inspectInput{GroupVarsComponent: "dns"}, 2, 2},
		{"file", inspectInput{GroupVarsFile: "dns.yml"}, 1, 2},
		{"key", inspectInput{GroupVarsKey: "dns_cache_max_ttl"}, 2, 2},
		{"combined", inspectInput{GroupVarsComponent: "dns", GroupVarsFile: "all.yaml", GroupVarsKey: "dns_cache_max_ttl"}, 1, 1},
		{"unknown component", inspectInput{GroupVarsComponent: "does-not-exist"}, 0, 0},
		{"no intersection", inspectInput{GroupVarsComponent: "dns", GroupVarsKey: "grafana_admin_password"}, 0, 0},
		{"secret key", inspectInput{GroupVarsComponent: "dashboard", GroupVarsFile: "all.yaml", GroupVarsKey: "grafana_admin_password"}, 1, 1},
		{"path is not filename", inspectInput{GroupVarsFile: "../dns.yml"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.IncludeGroupVars = true
			_, out, err := inspectHandler(editMCPToolsOptions{Dir: dir})(context.Background(), &mcp.CallToolRequest{}, in)
			if err != nil {
				t.Fatal(err)
			}
			keys := 0
			for _, values := range out.GroupVars {
				keys += len(values)
			}
			if len(out.GroupVars) != tc.files || keys != tc.keys {
				t.Fatalf("files=%d keys=%d, want %d/%d", len(out.GroupVars), keys, tc.files, tc.keys)
			}
			data, _ := json.Marshal(out)
			if strings.Contains(string(data), "DUMMY_") {
				t.Fatal("filter bypassed redaction")
			}
		})
	}
}

func TestInspectGroupVars_FailsClosedWithoutCatalog(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "invalid"}[broken], func(t *testing.T) {
			root := t.TempDir()
			if broken {
				writeTestFile(t, filepath.Join(root, "contracts", "invalid.yaml"), "DUMMY_CONTRACT_SECRET: [\n")
			}
			t.Setenv("PILOT_ROOT", root)
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "group_vars", "dns.yml"), "dns_cache_max_ttl: 300\n")
			out := buildInspectGroupVars(dir, inspectInput{})
			if out.Values["dns.yml"]["dns_cache_max_ttl"] != inspectRedactedValue {
				t.Fatal("missing catalog must redact")
			}
			if out.Metadata["dns.yml"]["dns_cache_max_ttl"].Reason != "unknown_input" {
				t.Fatal("expected unknown input")
			}
		})
	}
}

func TestInspectGroupVars_YAMLForms(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "group_vars", "all.yml"), `grafana_admin_password: &password DUMMY_ANCHORED_SECRET
thanos_query_url: *password
dashboard_config_dir: |
  DUMMY_EMBEDDED_SECRET
dns_zones: [{password: DUMMY_NESTED_SECRET}]
dns_freeipa_zones: [DUMMY_LIST_SECRET]
docker_network_name: !vault DUMMY_VAULT_SECRET
alertmanager_config: '{"smtp_auth_password": "DUMMY_QUOTED_CONFIG_SECRET"}'
grafana_host_data_dir: "path\nDUMMY_MULTILINE_SECRET"
loki_host_data_dir: "password: DUMMY_ENCODED_MAP_SECRET"
dns_cache_max_ttl: 10 # DUMMY_COMMENT_SECRET
`)
	writeTestFile(t, filepath.Join(dir, "group_vars", "invalid.yml"), "thanos_query_url: [DUMMY_BAD_YAML\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "duplicate.yml"), "thanos_query_url: DUMMY_DUPLICATE\nthanos_query_url: DUMMY_DUPLICATE\n")
	writeTestFile(t, filepath.Join(dir, "group_vars", "multiple.yml"), "dns_cache_min_ttl: 1\n---\ngrafana_admin_password: DUMMY_DOCUMENT_SECRET\n")
	_, out, err := inspectHandler(editMCPToolsOptions{Dir: dir})(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeGroupVars: true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), "DUMMY_") {
		t.Fatal("YAML form exposed secret or parser diagnostic")
	}
	for _, file := range []string{"invalid.yml", "duplicate.yml", "multiple.yml"} {
		if out.GroupVarsStatus[file] != "invalid_yaml" {
			t.Fatalf("status for %s = %q", file, out.GroupVarsStatus[file])
		}
	}
	if out.GroupVars["all.yml"]["dns_cache_max_ttl"] != "10" {
		t.Fatal("lost public scalar or retained comment")
	}
}

func TestInspectGroupVarPolicy_SecretWins(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "DUMMY_SECRET"}
	public := contract.GroupVar{Type: "string"}
	secret := contract.GroupVar{Type: "string", Secret: true}
	for _, inputs := range [][]contract.GroupVar{{public, secret}, {secret, public}} {
		if got := inspectGroupVarRedaction(inspectGroupVarPolicy{Inputs: inputs}, node); got != "secret" {
			t.Fatalf("mixed declarations reason = %q", got)
		}
	}
}
