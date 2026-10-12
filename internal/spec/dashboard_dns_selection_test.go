package spec

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Exercise the actual Ansible pre_tasks, including Jinja short-circuiting,
// variable precedence and inventory auto-discovery. No remote connections or
// mutation tasks run; the assertions lock externally meaningful URL choices.
func TestRegression_DashboardDatasourceSelection(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook unavailable")
	}
	raw, err := os.ReadFile("../../playbooks/apply/dashboard-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	play := plays[0]
	play["hosts"], play["become"], play["gather_facts"] = "all", false, false
	play["tasks"] = []any{map[string]any{
		"name":                   "Check the selected datasource URL",
		"ansible.builtin.assert": map[string]any{"that": []string{"dashboard_thanos_url == expected_url"}},
	}}
	data, err := yaml.Marshal([]any{play})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "selection.yml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		provider string
		vars     map[string]any
		want     string
		reject   bool
	}{
		{name: "no-provider-yet", want: "http://thanos-query-backend:10902"},
		{name: "co-located-inventory", provider: "consumer", want: "http://thanos-query-backend:10902"},
		{name: "legacy-local-address", vars: map[string]any{"thanos_query_target_host": "192.0.2.10"}, want: "http://thanos-query-backend:10902"},
		{name: "remote-inventory", provider: "remote", want: "http://metrics.example.internal:10912"},
		{name: "remote-fqdn", vars: map[string]any{"thanos_query_target_host": "metrics.example.internal"}, want: "http://metrics.example.internal:10912"},
		{name: "remote-ipv6", vars: map[string]any{"thanos_query_target_host": "2001:db8::10"}, want: "http://[2001:db8::10]:10912"},
		{name: "inventory-url-override", vars: map[string]any{"thanos_query_url": "https://metrics.example.internal"}, want: "https://metrics.example.internal"},
		{name: "custom-alias-and-port", vars: map[string]any{"thanos_query_alias": "metrics-query", "thanos_query_port": 10922}, want: "http://metrics-query:10922"},
		{name: "reject-non-http", vars: map[string]any{"thanos_query_url": "file:///etc/hosts"}, reject: true},
		{name: "reject-credentials", vars: map[string]any{"thanos_query_url": "http://fixture:fixture@metrics.example.internal"}, reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := map[string]any{
				"consumer": map[string]any{"ansible_connection": "local", "ansible_host": "192.0.2.10", "ansible_fqdn": "consumer.example.internal"},
				"remote":   map[string]any{"ansible_host": "metrics.example.internal"},
			}
			// Put inputs in host_vars, not extra-vars: play-level defaults
			// must not silently shadow configuration authored by pilot edit.
			for key, value := range tc.vars {
				hosts["consumer"].(map[string]any)[key] = value
			}
			all := map[string]any{"hosts": hosts}
			if tc.provider != "" {
				all["children"] = map[string]any{"thanos-query": map[string]any{"hosts": map[string]any{tc.provider: map[string]any{}}}}
			}
			inventory, err := yaml.Marshal(map[string]any{"all": all})
			if err != nil {
				t.Fatal(err)
			}
			invPath := filepath.Join(dir, tc.name+".yml")
			if err := os.WriteFile(invPath, inventory, 0600); err != nil {
				t.Fatal(err)
			}
			vars, _ := json.Marshal(map[string]any{"grafana_admin_password": "unused-disposable-fixture", "expected_url": tc.want})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, ansible, "-i", invPath, "--limit", "consumer", path, "-e", string(vars))
			cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+dir, "ANSIBLE_REMOTE_TEMP="+dir, "ANSIBLE_CACHE_PLUGIN=memory")
			out, err := cmd.CombinedOutput()
			if tc.reject {
				if err == nil || !strings.Contains(string(out), "thanos_query_url must be") {
					t.Fatalf("invalid URL did not fail at the input gate: %v\n%s", err, out)
				}
			} else if err != nil {
				t.Fatalf("effective datasource selection: %v\n%s", err, out)
			}
		})
	}
}
