package spec

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// inventoryInputContract is the part of contracts/*.yaml the play-vars lint
// needs. internal/contract imports this package, so it cannot be used here.
type inventoryInputContract struct {
	ID        string `yaml:"id"`
	Role      string `yaml:"role"`
	Playbooks struct {
		Apply string `yaml:"apply"`
	} `yaml:"playbooks"`
	GroupVars []struct {
		Name string `yaml:"name"`
	} `yaml:"groupVars"`
}

// exampleKeyLine matches a top-level key in group_vars/<role>.example.yml,
// commented out ("# key: value") or not.
var exampleKeyLine = regexp.MustCompile(`^(?:# ?)?([a-z][a-z0-9_]*):(?:\s|$)`)

// inventoryInputs returns, for every contract with an apply playbook, the
// variables an operator sets in inventory: the contract's groupVars and the
// keys of group_vars/<role>.example.yml, the template operators copy into
// their inventory's group_vars/<role>.yml.
func inventoryInputs(t *testing.T) (map[string]inventoryInputContract, map[string]map[string]string) {
	t.Helper()
	paths, err := filepath.Glob("../../contracts/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contracts := map[string]inventoryInputContract{}
	inputs := map[string]map[string]string{} // contract id -> var -> where it is documented
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var c inventoryInputContract
		if err := yaml.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if c.Playbooks.Apply == "" {
			continue
		}
		contracts[c.ID] = c
		in := map[string]string{}
		for _, gv := range c.GroupVars {
			in[gv.Name] = "contracts/" + filepath.Base(path) + " groupVars"
		}
		example := "../../group_vars/" + c.Role + ".example.yml"
		if f, err := os.Open(example); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if m := exampleKeyLine.FindStringSubmatch(sc.Text()); m != nil {
					if _, ok := in[m[1]]; !ok {
						in[m[1]] = "group_vars/" + c.Role + ".example.yml"
					}
				}
			}
			_ = f.Close()
			if err := sc.Err(); err != nil {
				t.Fatal(err)
			}
		}
		inputs[c.ID] = in
	}
	return contracts, inputs
}

// playVarsShadowingInputs returns one message per play-level vars: key in
// playbook that is also an inventory input.
func playVarsShadowingInputs(playbook []byte, inputs map[string]string) ([]string, error) {
	var plays []map[string]any
	if err := yaml.Unmarshal(playbook, &plays); err != nil {
		return nil, err
	}
	var out []string
	for i, play := range plays {
		vars, _ := play["vars"].(map[string]any)
		for name := range vars {
			if where, ok := inputs[name]; ok {
				out = append(out, fmt.Sprintf("play %d declares %s in vars:, which outranks the group_vars/host_vars value an operator sets (%s)", i, name, where))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs is a repo-wide lint
// (AGENTS.md §4.5 point 3, §5.10): no apply playbook may declare, in a
// play's vars:, a variable its contract lists under groupVars or its
// group_vars/<role>.example.yml documents. Play vars outrank group_vars and
// host_vars, so the operator's value was silently replaced by the play's
// default while `pilot deploy`'s preflight read the inventory value. On
// 2026-10-13 this found 60 such variables in 15 playbooks (snmp-exporter's
// group_vars example had no effect at all). Default them in an
// `always`-tagged set_fact instead (`x: "{{ x | default(...) }}"`), or read
// them with `| default(...)` where they are used.
func TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs(t *testing.T) {
	contracts, inputs := inventoryInputs(t)
	checked := 0
	ids := make([]string, 0, len(contracts))
	for id := range contracts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c := contracts[id]
		if len(inputs[id]) == 0 {
			continue
		}
		raw, err := os.ReadFile("../../" + c.Playbooks.Apply)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		violations, err := playVarsShadowingInputs(raw, inputs[id])
		if err != nil {
			t.Fatalf("%s: %v", c.Playbooks.Apply, err)
		}
		checked++
		for _, v := range violations {
			t.Errorf("%s (%s): %s", c.Playbooks.Apply, id, v)
		}
	}
	// 33 contracts had groupVars on 2026-10-13; far fewer means the loader
	// stopped finding them.
	if checked < 30 {
		t.Fatalf("only %d contracts with inventory inputs checked; the loader is broken", checked)
	}
}

func TestPlayVarsShadowingInputs(t *testing.T) {
	inputs := map[string]string{"x_port": "contract", "x_user": "example"}
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"both inputs in play vars", "- hosts: x\n  vars:\n    x_port: 1\n    x_user: a\n    x_dir: /d\n", 2},
		{"only an internal variable", "- hosts: x\n  vars:\n    x_dir: /d\n", 0},
		{"defaulted by set_fact", "- hosts: x\n  vars:\n    x_dir: /d\n  pre_tasks:\n    - ansible.builtin.set_fact:\n        x_port: \"{{ x_port | default(1) }}\"\n", 0},
		{"second play", "- hosts: a\n- hosts: x\n  vars:\n    x_port: 1\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := playVarsShadowingInputs([]byte(tc.yaml), inputs)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d violations %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// playVarsCase is one apply playbook whose inventory inputs moved out of
// play vars: the inventory group it runs on, and each moved variable's
// default as it was in the play's vars: (nil: none; the playbook gates or
// defaults it where it is read).
type playVarsCase struct {
	playbook string
	group    string
	defaults map[string]any
}

var playVarsCases = []playVarsCase{
	{"agent-controller-apply.yml", "agent-controller", map[string]any{
		"agent_controller_listen_port": 8090, "agent_controller_max_concurrent_runs": 4,
		"agent_controller_max_runs_per_host": 1, "agent_controller_max_body_bytes": 1048576,
		"agent_controller_dispatcher_kind": "fake", "agent_controller_dispatcher_endpoint": "",
		"agent_controller_dispatcher_timeout_seconds": 30}},
	{"dashboard-apply.yml", "dashboard", map[string]any{"grafana_admin_password": nil}},
	{"dcgm-exporter-apply.yml", "dcgm-exporter", map[string]any{
		"dcgm_exporter_version": "3.3.9-3.6.1-ubuntu22.04", "dcgm_exporter_port": 9400,
		"dcgm_exporter_basic_auth_user": "prometheus"}},
	{"detection-engine-apply.yml", "detection-engine", map[string]any{
		"detection_cycle_interval": "15s", "detection_evaluation_delay": "20s",
		"detection_log_source_enabled": false, "detection_log_source_base_url": "",
		"detection_log_source_query": "", "detection_log_source_current_window": "10m",
		"detection_log_source_baseline_window": "6h"}},
	{"freeipa-client-apply.yml", "freeipa-client", map[string]any{"freeipa_client_dns_addresses": []any{}}},
	{"gateway-scope-apply.yml", "freeipa-server", map[string]any{"gateway_scope_plan_only": false}},
	{"host-monitoring-apply.yml", "host-monitoring", map[string]any{
		"node_exporter_version": "1.12.1", "node_exporter_port": 9100,
		"node_exporter_user": "node_exporter", "node_exporter_basic_auth_user": "prometheus"}},
	{"log-shipping-apply.yml", "log-server", map[string]any{"loki_target_host": nil, "siem_log_root": nil}},
	{"pilot-session-store-apply.yml", "pilot-session-store", map[string]any{"pilot_session_store_ingest_port": 8443}},
	{"prometheus-apply.yml", "prometheus", map[string]any{
		"prometheus_scrape_interval": "15s", "thanos_s3_bucket": "pilot-thanos-metrics",
		"thanos_s3_endpoint": "thanos-s3-backend:8333", "alertmanager_alias": "alertmanager-backend",
		"alertmanager_port": 9093, "node_exporter_basic_auth_user": "prometheus",
		"dcgm_exporter_basic_auth_user": "prometheus"}},
	{"restic-backup-apply.yml", "restic-backup", map[string]any{
		"restic_s3_port": 8333, "restic_s3_bucket": "pilot-restic-backup",
		"restic_repository":   "s3:http://s3-backup-server:8333/pilot-restic-backup",
		"restic_backup_paths": []any{"/etc"}, "restic_backup_pre_hook": "",
		"restic_backup_schedule": "*-*-* 02:00:00", "restic_retention_daily": 7,
		"restic_retention_weekly": 4, "restic_retention_monthly": 6}},
	{"snmp-exporter-apply.yml", "snmp-exporter", map[string]any{
		"snmp_exporter_version": "v0.30.1", "snmp_exporter_image": "quay.io/prometheus/snmp-exporter",
		"snmp_exporter_container_name": "pilot-snmp-exporter", "snmp_exporter_port": "9116",
		"snmp_exporter_listen_address": "127.0.0.1", "snmp_exporter_module_concurrency": "1",
		"snmp_exporter_config_dir": "/etc/pilot/snmp-exporter", "snmp_exporter_data_dir": "/var/lib/pilot/snmp-exporter",
		"snmp_catalog_file": "", "snmp_exporter_credentials": map[string]any{},
		"snmp_insecure_auth_profile_exceptions": map[string]any{}}},
	{"thanos-query-apply.yml", "thanos-query", map[string]any{
		"thanos_s3_bucket": "pilot-thanos-metrics", "thanos_s3_endpoint": "thanos-s3-backend:8333",
		"thanos_query_store_group": "prometheus", "thanos_query_sidecar_grpc_port": 10901}},
	{"wazuh-fim-apply.yml", "wazuh-fim", map[string]any{
		"wazuh_fim_directories": []any{"/etc", "/boot"}, "wazuh_repo_channel": "4.x"}},
	{"wazuh-manager-apply.yml", "wazuh-manager", map[string]any{
		"siem_forward_port": "514", "wazuh_docker_version": "4.14.1"}},
}

// overrideFor returns a value of def's type that differs from def.
func overrideFor(name string, def any) any {
	switch def.(type) {
	case bool:
		return true
	case int:
		return 4242
	case []any:
		return []any{"/override/" + name}
	case map[string]any:
		return map[string]any{"override": name}
	default:
		return "override-" + name
	}
}

// TestRegression_InventoryInputsReachThePlay runs, for each playbook in
// playVarsCases, its play vars and its "Resolve ... default" set_fact tasks
// through Ansible on localhost, with the host in the playbook's inventory
// group. With group_vars/<group>.yml setting every moved variable, the play
// must see those values; without it, the old defaults. Against the old
// playbooks, the play vars replace every group_vars value.
func TestRegression_InventoryInputsReachThePlay(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	for _, tc := range playVarsCases {
		t.Run(tc.playbook, func(t *testing.T) {
			raw, err := os.ReadFile("../../playbooks/apply/" + tc.playbook)
			if err != nil {
				t.Fatal(err)
			}
			var plays []map[string]any
			if err := yaml.Unmarshal(raw, &plays); err != nil {
				t.Fatal(err)
			}
			play := plays[0]
			var resolve []any
			for _, section := range []string{"pre_tasks", "tasks"} {
				tasks, _ := play[section].([]any)
				for _, task := range tasks {
					m, _ := task.(map[string]any)
					if name, _ := m["name"].(string); strings.HasPrefix(name, "Resolve inventory-overridable defaults") ||
						strings.HasPrefix(name, "Resolve the restic_repository default") ||
						strings.HasPrefix(name, "Resolve the snmp_exporter_credentials default") {
						c := map[string]any{}
						for k, v := range m {
							if k != "no_log" {
								c[k] = v
							}
						}
						resolve = append(resolve, c)
					}
				}
			}
			names := make([]string, 0, len(tc.defaults))
			for name := range tc.defaults {
				names = append(names, name)
			}
			sort.Strings(names)
			var show []string
			for _, name := range names {
				show = append(show, fmt.Sprintf("%q: (%s | default('__undefined__'))", name, name))
			}
			tasks := append(resolve, map[string]any{
				"name":                  "show",
				"ansible.builtin.debug": map[string]any{"msg": "{{ {" + strings.Join(show, ", ") + "} | to_json }}"},
			})

			overrides := map[string]any{}
			for name, def := range tc.defaults {
				overrides[name] = overrideFor(name, def)
			}
			got := runInventoryPlay(t, tc.group, play["vars"], tasks, overrides)
			for _, name := range names {
				if !jsonEqual(got[name], overrides[name]) {
					t.Errorf("with group_vars %s=%v the play sees %v", name, overrides[name], got[name])
				}
			}
			got = runInventoryPlay(t, tc.group, play["vars"], tasks, nil)
			for _, name := range names {
				want := tc.defaults[name]
				if want == nil {
					want = "__undefined__"
				}
				if !jsonEqual(got[name], want) {
					t.Errorf("without group_vars, %s = %v, want the old default %v", name, got[name], want)
				}
			}
		})
	}
}

// runInventoryPlay runs one play on localhost as a member of group, with
// group_vars/<group>.yml holding groupVars (none when nil), and returns the
// JSON object the last task's msg printed.
func runInventoryPlay(t *testing.T, group string, playVars any, tasks []any, groupVars map[string]any) map[string]any {
	t.Helper()
	dir := t.TempDir()
	inv := map[string]any{"all": map[string]any{"children": map[string]any{
		group: map[string]any{"hosts": map[string]any{"localhost": map[string]any{
			"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3"}}},
	}}}
	write := func(path string, v any) {
		body, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "inventory.yml"), inv)
	if groupVars != nil {
		write(filepath.Join(dir, "group_vars", group+".yml"), groupVars)
	}
	if playVars == nil {
		playVars = map[string]any{}
	}
	write(filepath.Join(dir, "play.yml"), []map[string]any{{
		"name": "inventory inputs", "hosts": group, "gather_facts": false, "become": false,
		"vars": playVars, "tasks": tasks,
	}})
	cmd := exec.Command("ansible-playbook", "-i", filepath.Join(dir, "inventory.yml"), filepath.Join(dir, "play.yml"))
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Msg string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			if task.Task.Name != "show" {
				continue
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(task.Hosts["localhost"].Msg), &got); err != nil {
				t.Fatalf("decode %q: %v", task.Hosts["localhost"].Msg, err)
			}
			return got
		}
	}
	t.Fatalf("no output from the show task:\n%s", out)
	return nil
}

// jsonEqual compares a decoded JSON value with a Go value by their JSON.
func jsonEqual(got, want any) bool {
	a, errA := json.Marshal(got)
	b, errB := json.Marshal(want)
	return errA == nil && errB == nil && string(a) == string(b)
}
