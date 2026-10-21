package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

// Use the production resolver and canonical dependency closure, including the
// newly declared secrets. Ansible, rather than a second YAML scalar parser,
// determines the meaning and precedence of -e arguments.
func TestDeployPreflightExtraVarsTypes(t *testing.T) {
	if _, err := exec.LookPath("ansible-inventory"); err != nil {
		t.Skipf("ansible-inventory not installed: %v", err)
	}
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	t.Setenv("ANSIBLE_CACHE_PLUGIN", "memory")
	loader, err := contract.NewLoader(repoRootForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	var selected []contract.Contract
	scope := delivery.Scope{HostsByRole: map[string][]string{}}
	for _, id := range []string{"dashboard", "prometheus", "thanos-query", "docker", "seaweedfs-s3", "alertmanager", "dns"} {
		component, err := loader.LoadFile("contracts/" + id + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		selected = append(selected, component)
		scope.HostsByRole[component.Role] = []string{"test-host"}
	}
	for _, tc := range []struct {
		name    string
		extra   []string
		file    string
		vault   bool
		want    map[string]any
		wantErr string
	}{
		{name: "inventory typed values", want: map[string]any{"dns_cache_max_ttl": float64(600), "freeipa_setup_dns": false}},
		{name: "numeric secrets", extra: []string{"grafana_admin_password=12345678", "thanos_aws_access_key_id=123456789", "thanos_aws_secret_access_key=00123456"}, want: map[string]any{"grafana_admin_password": "12345678", "thanos_aws_access_key_id": "123456789", "thanos_aws_secret_access_key": "00123456"}},
		{name: "boolean-looking secrets", extra: []string{"grafana_admin_password=true", "thanos_aws_access_key_id=false"}, want: map[string]any{"grafana_admin_password": "true", "thanos_aws_access_key_id": "false"}},
		{name: "null-looking secrets", extra: []string{"grafana_admin_password=null", "thanos_aws_secret_access_key=~"}, want: map[string]any{"grafana_admin_password": "null", "thanos_aws_secret_access_key": "~"}},
		{name: "collection-looking secrets", extra: []string{"grafana_admin_password=[1,2]", "thanos_aws_access_key_id={a:1}"}, want: map[string]any{"grafana_admin_password": "[1,2]", "thanos_aws_access_key_id": "{a:1}"}},
		{name: "not a YAML scalar", extra: []string{"grafana_admin_password=[unfinished"}, want: map[string]any{"grafana_admin_password": "[unfinished"}},
		{name: "multiple assignments", extra: []string{"grafana_admin_password=12345678 thanos_aws_access_key_id=false"}, want: map[string]any{"grafana_admin_password": "12345678", "thanos_aws_access_key_id": "false"}},
		{name: "last assignment wins", extra: []string{"grafana_admin_password=12345678", "grafana_admin_password=null"}, want: map[string]any{"grafana_admin_password": "null"}},
		{name: "JSON wins over assignment", extra: []string{"grafana_admin_password=12345678", `{"grafana_admin_password":"false"}`}, want: map[string]any{"grafana_admin_password": "false"}},
		{name: "vars file wins over assignment", extra: []string{"grafana_admin_password=12345678"}, file: "grafana_admin_password: 'null'\n", want: map[string]any{"grafana_admin_password": "null"}},
		{name: "vault input file wins over assignment", extra: []string{"grafana_admin_password=12345678"}, file: "grafana_admin_password: 'true'\n", vault: true, want: map[string]any{"grafana_admin_password": "true"}},
		{name: "integer and boolean assignments", extra: []string{"dns_cache_max_ttl=900", "freeipa_setup_dns=true", "prometheus_host_health_alert_rules_enabled=false"}, want: map[string]any{"dns_cache_max_ttl": "900", "freeipa_setup_dns": true, "prometheus_host_health_alert_rules_enabled": false}},
		{name: "case-insensitive boolean", extra: []string{"freeipa_setup_dns=TRUE"}, want: map[string]any{"freeipa_setup_dns": true}},
		{name: "JSON typed inputs", extra: []string{`{"dns_cache_max_ttl":900,"freeipa_setup_dns":true,"dns_zones":[{"name":"example.test","stub_addr":"192.0.2.1"}]}`}, want: map[string]any{"dns_cache_max_ttl": float64(900), "freeipa_setup_dns": true, "dns_zones": []any{map[string]any{"name": "example.test", "stub_addr": "192.0.2.1"}}}},
		{name: "file typed inputs", file: "dns_cache_max_ttl: 900\nfreeipa_setup_dns: true\n", want: map[string]any{"dns_cache_max_ttl": float64(900), "freeipa_setup_dns": true}},
		{name: "fractional integer rejected", extra: []string{"dns_cache_max_ttl=14.5"}, wantErr: `input "dns_cache_max_ttl": must be integer`},
		{name: "invalid boolean rejected", extra: []string{"freeipa_setup_dns=not-a-boolean"}, wantErr: `input "freeipa_setup_dns": must be boolean`},
		{name: "typed numeric secret rejected", extra: []string{`{"grafana_admin_password":12345678}`}, wantErr: `input "grafana_admin_password": must be string`},
		{name: "typed boolean secret rejected", extra: []string{`{"grafana_admin_password":true}`}, wantErr: `input "grafana_admin_password": must be string`},
		{name: "typed null secret rejected", extra: []string{`{"grafana_admin_password":null}`}, wantErr: `requires input "grafana_admin_password"`},
		{name: "malformed object list rejected", extra: []string{`{"dns_zones":["example.test"]}`}, wantErr: `input "dns_zones": must be objectList`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			inv := filepath.Join(dir, "inventory.yml")
			const inventory = `all:
  hosts:
    test-host:
      grafana_admin_password: fixture-password
      thanos_aws_access_key_id: fixture-access
      thanos_aws_secret_access_key: fixture-secret
      thanos_query_target_host: test-host
      thanos_s3_target_host: test-host
      alertmanager_target_host: test-host
      prometheus_site_label: test-site
      dns_cache_max_ttl: 600
      freeipa_setup_dns: false
`
			if err := os.WriteFile(inv, []byte(inventory), 0o600); err != nil {
				t.Fatal(err)
			}
			extra := append([]string(nil), tc.extra...)
			var vault vaultInput
			if tc.file != "" {
				path := filepath.Join(dir, "vars.yml")
				if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
				if tc.vault {
					vault.ExtraVarsFile = path
				} else {
					extra = append(extra, "@"+path)
				}
			}
			inputs, err := resolveDeploymentInputs(context.Background(), selected, scope, inv, extra, vault)
			if err != nil {
				t.Fatal(err)
			}
			_, err = delivery.ValidateContractPreflight(delivery.PreflightRequest{Selected: selected, Scope: scope, Inputs: inputs})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("preflight error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid Ansible input rejected: %v", err)
			}
			for name, want := range tc.want {
				found := false
				for _, component := range selected {
					if got, ok := inputs[component.ID][name]; ok {
						found = true
						if !reflect.DeepEqual(got, want) {
							t.Errorf("%s.%s = %#v (%T), want %#v (%T)", component.ID, name, got, got, want, want)
						}
					}
				}
				if !found {
					t.Errorf("input %s was not resolved", name)
				}
			}
		})
	}
}
