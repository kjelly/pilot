package spec

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Exercise Ansible's actual tag selection and the real pinned Prometheus
// process. Only disposable names, bind paths and the host port are adapted.
func TestRegression_PrometheusTaggedRuntime(t *testing.T) {
	requireContainerImage(t, hostHealthPromImage)
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	dir, err := os.MkdirTemp("", "pilot-prom-tagged-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANSIBLE_LOCAL_TEMP", filepath.Join(dir, "ansible-tmp"))
	t.Setenv("ANSIBLE_REMOTE_TEMP", filepath.Join(dir, "ansible-remote"))
	name := fmt.Sprintf("pilot-prom-tagged-%d", time.Now().UnixNano())
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	plays := loadYAML(t, hostHealthApply).([]any)
	var tasks []any
	var collect func([]any)
	collect = func(all []any) {
		for _, item := range all {
			task := item.(map[string]any)
			if block, ok := task["block"].([]any); ok {
				collect(block)
				continue
			}
			n, _ := task["name"].(string)
			selected := false
			for _, prefix := range []string{"Compute the rule_files list", "Render prometheus.yml", "Render host-health-alert-rules.yml", "Remove host-health-alert-rules.yml", "Check whether pilot-prometheus", "Prometheus — run pilot-prometheus", "Wait for Prometheus", "Runtime: Prometheus"} {
				selected = selected || strings.HasPrefix(n, prefix)
			}
			if !selected {
				continue
			}
			if args, ok := task["ansible.builtin.template"].(map[string]any); ok {
				args["src"], _ = filepath.Abs("../../playbooks/apply/templates/pilot-host-health-alert-rules.yml.j2")
			}
			if args, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok {
				args["file"], _ = filepath.Abs("../../playbooks/apply/tasks/container-file-mount-drift.yml")
				args["apply"].(map[string]any)["become"] = true
				task["vars"].(map[string]any)["container_mount_drift_name"] = name
			}
			if args := dockerContainerArgs(task); args != nil {
				args["name"] = name
				delete(args, "networks")
				args["ports"] = []string{fmt.Sprintf("127.0.0.1:%d:9090", port)}
			}
			if args, ok := task["ansible.builtin.uri"].(map[string]any); ok {
				args["url"] = strings.ReplaceAll(args["url"].(string), "http://127.0.0.1:9090", base)
			}
			if args, ok := task["ansible.builtin.command"].(map[string]any); ok {
				if argv, ok := args["argv"].([]any); ok {
					for i, v := range argv {
						if v == "pilot-prometheus" {
							argv[i] = name
						}
					}
				}
			}
			tasks = append(tasks, task)
		}
	}
	play := plays[0].(map[string]any)
	collect(play["pre_tasks"].([]any))
	collect(play["tasks"].([]any))
	// community.docker requires requests in the target interpreter. Local
	// developer machines may run Ansible from a separate Python environment.
	interpreter := ""
	for _, candidate := range []string{"python3", "/usr/bin/python3"} {
		absolute, err := exec.LookPath(candidate)
		if err == nil && exec.Command(absolute, "-c", "import requests").Run() == nil {
			interpreter = absolute
			break
		}
	}
	if interpreter == "" {
		t.Fatal("community.docker requires a Python interpreter with requests")
	}
	vars := map[string]any{"ansible_python_interpreter": interpreter}
	for k, v := range hostHealthContractDefaults(t) {
		vars[k] = v
	}
	for k, v := range map[string]any{
		"prometheus_config_dir":                      dir,
		"prometheus_host_data_dir":                   filepath.Join(dir, "data"),
		"prometheus_version":                         strings.TrimPrefix(hostHealthPromImage, "prom/prometheus:"),
		"prometheus_retention_time":                  "1h",
		"prometheus_scrape_interval":                 "15s",
		"prometheus_site_label":                      "tagged-test",
		"alertmanager_target_host":                   "fixture",
		"alertmanager_alias":                         "127.0.0.1",
		"alertmanager_port":                          9093,
		"prometheus_host_health_alert_rules_enabled": true,
		"prometheus_node_exporter_targets":           []any{},
		"prometheus_dcgm_exporter_targets":           []any{},
		"monitoring_profiles_resolved":               map[string]any{},
		"monitoring_auth":                            map[string]any{},
		"prometheus_has_snmp_profile":                false,
		"prometheus_scrape_configs":                  "  []",
		"prometheus_node_exporter_scrape_block":      "",
		"prometheus_dcgm_exporter_scrape_block":      "",
		"prometheus_external_scrape_block":           "",
		"login_probe_expected_hosts":                 []any{},
	} {
		vars[k] = v
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "data"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alert-rules.yml"), []byte("groups: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dir, "data", "preserve-test")
	if err := os.WriteFile(sentinel, []byte("existing-data"), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "connection": "local", "gather_facts": false, "vars": vars, "tasks": tasks}})
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(dir, "apply.yml")
	if err := os.WriteFile(pb, data, 0600); err != nil {
		t.Fatal(err)
	}
	apply := func(tag string, enabled bool, threshold string) string {
		t.Helper()
		t.Logf("apply tag=%s enabled=%v threshold=%s", tag, enabled, threshold)
		am := ""
		if tag == "" {
			am = "fixture"
		}
		extra, _ := json.Marshal(map[string]any{"prometheus_host_health_alert_rules_enabled": enabled, "host_io_stall_ratio_threshold": threshold, "alertmanager_target_host": am})
		args := []string{"-i", "localhost,", pb, "-e", string(extra)}
		if tag != "" {
			args = append(args, "--tags", tag)
		}
		out, err := exec.Command("ansible-playbook", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("apply %s: %v\n%s", tag, err, out)
		}
		return string(out)
	}
	rules := func() string {
		t.Helper()
		client := http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(base + "/api/v1/rules")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct {
			Status string `json:"status"`
			Data   struct {
				Groups []struct {
					Rules []struct {
						Name  string `json:"name"`
						Query string `json:"query"`
					} `json:"rules"`
				} `json:"groups"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || body.Status != "success" {
			t.Fatalf("rules API status %d/%s", resp.StatusCode, body.Status)
		}
		for _, group := range body.Data.Groups {
			for _, rule := range group.Rules {
				if rule.Name == "HostIOStall" {
					return rule.Query
				}
			}
		}
		return ""
	}
	assertRules := func(enabled bool, threshold string) {
		t.Helper()
		got := rules()
		if enabled {
			if !strings.HasSuffix(got, "> "+threshold) {
				t.Fatalf("loaded rules missing desired threshold %s: %s", threshold, got)
			}
		} else if got != "" {
			t.Fatalf("disabled rules still loaded: %s", got)
		}
	}
	// Fresh check mode must be safe before any Prometheus container exists.
	check := exec.Command("ansible-playbook", "-i", "localhost,", pb, "--check", "--diff")
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("fresh check mode: %v\n%s", err, out)
	}
	apply("", true, "0.27")
	assertRules(true, "0.27")
	apply("C23", true, "0.29")
	assertRules(true, "0.29")
	apply("C23", false, "0.29")
	assertRules(false, "")
	cfg, err := os.ReadFile(filepath.Join(dir, "prometheus.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "host-health-alert-rules.yml") {
		t.Fatal("disabled config still references host rules")
	}
	// Both row tags must support disabling and enabling, independently.
	apply("C23", true, "0.30")
	assertRules(true, "0.3")
	apply("C24", false, "0.30")
	assertRules(false, "")
	apply("C24", true, "0.31")
	assertRules(true, "0.31")
	// Update the mounted inode in place, so neither changed results nor bind
	// drift can distinguish this old runtime from a healthy one.
	path := filepath.Join(dir, "host-health-alert-rules.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(string(raw), "0.31", "0.33"))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	assertRules(true, "0.31")
	before := docker("inspect", "--format", "{{.State.StartedAt}}", name)
	out := apply("C23", true, "0.33")
	assertRules(true, "0.33")
	if !strings.Contains(out, "changed=0") {
		t.Fatalf("unchanged render should reconcile without mutation: %s", out)
	}
	if after := docker("inspect", "--format", "{{.State.StartedAt}}", name); after != before {
		t.Fatal("in-place stale runtime should be healed by reload")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "existing-data" {
		t.Fatalf("container reconciliation lost persistent data mount: %q %v", data, err)
	}
	out = apply("C24", true, "0.33")
	assertRules(true, "0.33")
	if !strings.Contains(out, "changed=0") {
		t.Fatal("no-op changed state: " + out)
	}
}
