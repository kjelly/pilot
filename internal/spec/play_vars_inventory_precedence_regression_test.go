package spec

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// inventoryInputContract is the part of contracts/*.yaml the play-vars lint
// needs. internal/contract imports this package, so it cannot be used here.
type inventoryInputContract struct {
	ID    string `yaml:"id"`
	Role  string `yaml:"role"`
	Specs []struct {
		Path string `yaml:"path"`
	} `yaml:"specs"`
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

// ipaRealmDerived is why the FreeIPA playbooks may keep ipa_realm in their
// play vars although pilot-access-gateway/-directory list it as an input.
const ipaRealmDerived = "derived from freeipa_realm/ipa_domain (group_vars/freeipa.yml) in the play vars; " +
	"ipa_realm is an inventory input only of pilot-access-gateway and pilot-access-directory, " +
	"which read it as an override of the same derivation"

// playVarsInputAllowlist holds play vars, keyed "<playbook> <variable>", that
// are another component's inventory input but are derived on purpose in that
// playbook. The lint fails when an entry no longer matches a play var that is
// an inventory input.
var playVarsInputAllowlist = map[string]string{
	"playbooks/apply/freeipa-client-apply.yml ipa_realm":         ipaRealmDerived,
	"playbooks/apply/freeipa-dns-apply.yml ipa_realm":            ipaRealmDerived,
	"playbooks/apply/freeipa-identity-apply.yml ipa_realm":       ipaRealmDerived,
	"playbooks/apply/freeipa-server-apply.yml ipa_realm":         ipaRealmDerived,
	"playbooks/apply/freeipa-server-replica-apply.yml ipa_realm": ipaRealmDerived,
}

// TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs is a repo-wide lint
// (AGENTS.md §4.5 point 3, §5.10): no apply playbook may declare, in a
// play's vars:, a variable that any contract lists under groupVars or any
// group_vars/<role>.example.yml documents. Play vars outrank group_vars and
// host_vars, so the operator's value was silently replaced by the play's
// default while `pilot deploy`'s preflight read the inventory value. On
// 2026-10-13 this found 60 such variables in 15 playbooks (snmp-exporter's
// group_vars example had no effect at all). Default them in an
// `always`-tagged set_fact instead (`x: "{{ x | default(...) }}"`), or read
// them with `| default(...)` where they are used.
//
// The inputs of every contract are checked against every apply playbook, not
// only the playbook's own contract: a variable has one value per host, and
// two playbooks on the same host must resolve it the same way. When only
// log-shipping read siem_log_root from inventory, log-server kept writing to
// its play-vars default while Promtail tailed the operator's directory.
func TestRegression_ApplyPlayVarsDoNotShadowInventoryInputs(t *testing.T) {
	contracts, inputs := inventoryInputs(t)
	all := map[string]string{}
	withInputs := 0
	for _, in := range inputs {
		if len(in) > 0 {
			withInputs++
		}
		for name, where := range in {
			all[name] = joinWhere(all[name], where)
		}
	}
	// 33 contracts had groupVars on 2026-10-13; far fewer means the loader
	// stopped finding them.
	if withInputs < 30 {
		t.Fatalf("only %d contracts with inventory inputs found; the loader is broken", withInputs)
	}
	playbooks := map[string]bool{}
	for _, c := range contracts {
		playbooks[c.Playbooks.Apply] = true
	}
	paths := make([]string, 0, len(playbooks))
	for path := range playbooks {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		in := map[string]string{}
		for name, where := range all {
			if _, ok := playVarsInputAllowlist[path+" "+name]; !ok {
				in[name] = where
			}
		}
		violations, err := playVarsShadowingInputs(raw, in)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, v := range violations {
			t.Errorf("%s: %s", path, v)
		}
	}
	for key := range playVarsInputAllowlist {
		path, name, _ := strings.Cut(key, " ")
		raw, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Errorf("stale playVarsInputAllowlist entry %q: %v", key, err)
			continue
		}
		still, err := playVarsShadowingInputs(raw, map[string]string{name: all[name]})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if all[name] == "" || len(still) == 0 {
			t.Errorf("stale playVarsInputAllowlist entry %q: no longer a play var that is an inventory input", key)
		}
	}
}

// specInputName matches a backticked variable name in a table cell.
var specInputName = regexp.MustCompile("`([a-z][a-z0-9_]*)`")

// specInputs returns the variables a contract's specs list as inputs: every
// backticked name in the first cell of a table row under a level-2 heading
// containing 變數契約 ("## 1.5 依賴變數契約" in most specs, "## 3. Apply
// 變數契約" in dns.md). Tables of verify-time inputs (dns.md "## 4. Verify
// inputs") are not inventory inputs and are not read.
func specInputs(t *testing.T, c inventoryInputContract) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, s := range c.Specs {
		raw, err := os.ReadFile("../../" + s.Path)
		if err != nil {
			t.Fatal(err)
		}
		inTable := false
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "## ") {
				inTable = strings.Contains(line, "變數契約")
				continue
			}
			cells := strings.Split(line, "|")
			if !inTable || !strings.HasPrefix(line, "|") || len(cells) < 3 {
				continue
			}
			for _, m := range specInputName.FindAllStringSubmatch(cells[1], -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

// undeclaredSpecInputsAllowlist lists, per contract, the variables its
// specs list as inputs (see specInputs) that its contract's groupVars does
// not declare (issue #81). Some are play vars that shadow inventory, some
// are only in a group_vars example (which `pilot deploy`'s preflight does
// not read), some are derived from other inputs or are roster/manifest
// fields and should leave the table. The list may only shrink: the test
// fails for an entry that is declared or no longer listed.
var undeclaredSpecInputsAllowlist = map[string][]string{
	"alertmanager":              {"alertmanager_config", "alertmanager_config_dir", "alertmanager_host_data_dir", "alertmanager_receiver_mode", "alertmanager_teams_proxy_image", "alertmanager_teams_proxy_port", "alertmanager_teams_webhook_url", "alertmanager_version", "docker_network_name"},
	"dashboard":                 {"dashboard_config_dir", "grafana_admin_password", "grafana_host_data_dir", "loki_host_data_dir"},
	"dns":                       {"dns_listen_addr", "dns_provider", "dns_zones", "freeipa_client_topology_mode", "freeipa_domain", "freeipa_server_fqdn", "freeipa_setup_dns"},
	"freeipa-client":            {"ipa_client_fqdn", "ipa_domain", "ipa_enroll_principal", "ipa_realm", "ipa_server_fqdn", "ipa_server_ip", "ipa_verify_user", "pilot_annotations"},
	"freeipa-dns-client":        {"freeipa_setup_dns"},
	"freeipa-dns":               {"freeipa_domain", "freeipa_realm", "freeipa_server_fqdn", "freeipa_setup_dns"},
	"freeipa-identity":          {"freeipa_roster_file", "groups", "ipa_domain", "ipa_groups", "ipa_hbac_rules", "ipa_hostgroups", "ipa_realm", "ipa_sudo_rules", "ipa_users", "netgroups", "schema_version", "users"},
	"freeipa-realm-replacement": {"freeipa_realm_replacement_client_fqdn", "freeipa_realm_replacement_confirm", "freeipa_realm_replacement_new_domain", "freeipa_realm_replacement_new_realm", "freeipa_realm_replacement_new_server_fqdn", "freeipa_realm_replacement_new_server_ip", "freeipa_realm_replacement_old_realm", "freeipa_realm_replacement_ticket", "freeipa_realm_replacement_verify_user"},
	"freeipa-server-replica":    {"freeipa_dns_forwarders", "ipa_dns_forwarders", "ipa_domain", "ipa_realm", "ipa_replica_fqdn", "ipa_replica_ip", "ipa_replica_setup_ca", "ipa_server_fqdn", "ipa_server_ip", "ipa_setup_dns", "ipa_setup_ntp"},
	"freeipa-server":            {"ipa_dm_password", "ipa_dns_allow_any_recursion", "ipa_dns_forwarders", "ipa_domain", "ipa_ds_instance", "ipa_enable_audit_log", "ipa_realm", "ipa_server_fqdn", "ipa_server_ip", "ipa_setup_dns", "ipa_setup_ntp"},
	"pilot-access-gateway":      {"pilot_access_gateway_recording_session_store_ingest_token_file"},
	"prometheus":                {"alertmanager_alias", "alertmanager_port", "prometheus_alert_rules_file", "prometheus_retention_time", "prometheus_scrape_configs", "prometheus_scrape_interval", "thanos_aws_access_key_id", "thanos_aws_secret_access_key", "thanos_s3_alias", "thanos_s3_bucket", "thanos_s3_endpoint", "thanos_s3_port"},
	"restic-backup":             {"restic_backup_randomized_delay", "restic_backup_timer_persistent", "restic_lock_retry"},
	"thanos-query":              {"thanos_aws_access_key_id", "thanos_aws_secret_access_key", "thanos_compact_retention_1h", "thanos_compact_retention_5m", "thanos_compact_retention_raw", "thanos_query_sidecar_grpc_port", "thanos_query_store_group", "thanos_s3_alias", "thanos_s3_bucket", "thanos_s3_endpoint", "thanos_s3_port"},
	"wazuh-fim":                 {"wazuh_fim_directories", "wazuh_repo_channel"},
}

// TestRegression_SpecInputsAreDeclaredContractInputs closes the gap between
// a spec's variable table and the inputs `pilot deploy`'s preflight and the
// play-vars lint know about. log-server's §1.5 named siem_receiver_tcp_port,
// but only contracts' groupVars and example keys counted as inputs, so the
// play vars kept shadowing it: with siem_forward_port and
// siem_receiver_tcp_port both set to 2514 in inventory, clients sent to 2514
// while rsyslog still listened on 514. A variable a spec lists as an input
// (see specInputs) must be declared in its contract's groupVars; a group_vars
// example key alone does not count, because preflight reads only groupVars.
// undeclaredSpecInputsAllowlist holds the ones not done yet.
func TestRegression_SpecInputsAreDeclaredContractInputs(t *testing.T) {
	contracts, _ := inventoryInputs(t)
	ids := make([]string, 0, len(contracts))
	for id := range contracts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	listed := 0
	for _, id := range ids {
		pending := map[string]bool{}
		for _, name := range undeclaredSpecInputsAllowlist[id] {
			pending[name] = true
		}
		spec := specInputs(t, contracts[id])
		listed += len(spec)
		names := make([]string, 0, len(spec))
		for name := range spec {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			declared := slices.ContainsFunc(contracts[id].GroupVars, func(gv struct {
				Name string `yaml:"name"`
			}) bool {
				return gv.Name == name
			})
			switch {
			case declared && pending[name]:
				t.Errorf("%s: %s is declared now; remove it from undeclaredSpecInputsAllowlist", id, name)
			case !declared && !pending[name]:
				t.Errorf("%s: its spec lists %s as an input, but contracts/%s.yaml groupVars does not declare it", id, name, id)
			}
		}
		for name := range pending {
			if !spec[name] {
				t.Errorf("%s: undeclaredSpecInputsAllowlist entry %s is no longer listed in its spec", id, name)
			}
		}
	}
	for id := range undeclaredSpecInputsAllowlist {
		if _, ok := contracts[id]; !ok {
			t.Errorf("undeclaredSpecInputsAllowlist names unknown contract %s", id)
		}
	}
	// The tables named 227 variables on 2026-10-14; far fewer means the
	// parser stopped finding them.
	if listed < 200 {
		t.Fatalf("only %d spec input variables found; the parser is broken", listed)
	}
}

// joinWhere adds where to a "; "-separated, sorted list of places a variable
// is documented as an inventory input.
func joinWhere(list, where string) string {
	parts := []string{where}
	if list != "" {
		parts = append(parts, strings.Split(list, "; ")...)
	}
	sort.Strings(parts)
	return strings.Join(slices.Compact(parts), "; ")
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
	{"audit-log-forwarding-apply.yml", "audit-log-forwarding", map[string]any{
		"siem_forward_port": "514", "audit_logrotate_rotate": 14, "audit_logrotate_maxage": 90,
		"syslog_logrotate_rotate": 14, "syslog_logrotate_maxage": 90}},
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
	{"log-shipping-apply.yml", "log-server", map[string]any{
		"loki_target_host": nil, "siem_log_root": nil,
		"loki_alias": "pilot-loki-backend", "loki_port": 3100, "loki_endpoint": "pilot-loki-backend:3100",
		"promtail_job_label": "pilot-siem", "promtail_wazuh_job_label": "pilot-siem-wazuh-alerts"}},
	{"log-server-apply.yml", "log-server", map[string]any{
		"siem_log_root": "/var/log/siem", "siem_receiver_tcp_port": "514",
		"siem_logrotate_rotate": 14, "siem_logrotate_maxage": 90}},
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

// isDefaultsTask reports whether a task is one of the set_fact tasks that
// default inventory inputs after the stage gates.
func isDefaultsTask(name string) bool {
	for _, prefix := range []string{
		"Resolve inventory-overridable defaults",
		"Resolve the restic_repository default",
		"Resolve the snmp_exporter_credentials default",
		"Resolve the loki_endpoint and promtail_wazuh_job_label defaults",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// pickTasks returns, in order, the pre_tasks and tasks of play whose name
// matches keep, without no_log so their results can be printed.
func pickTasks(play map[string]any, keep func(name string) bool) []any {
	var picked []any
	for _, section := range []string{"pre_tasks", "tasks"} {
		tasks, _ := play[section].([]any)
		for _, task := range tasks {
			m, _ := task.(map[string]any)
			if name, _ := m["name"].(string); keep(name) {
				c := map[string]any{}
				for k, v := range m {
					if k != "no_log" {
						c[k] = v
					}
				}
				picked = append(picked, c)
			}
		}
	}
	return picked
}

// loadFirstPlay reads the first play of playbooks/apply/<playbook>.
func loadFirstPlay(t *testing.T, playbook string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/" + playbook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	return plays[0]
}

// showTask prints names as one JSON object, "__undefined__" for an unset
// variable.
func showTask(names []string) map[string]any {
	var show []string
	for _, name := range names {
		show = append(show, fmt.Sprintf("%q: (%s | default('__undefined__'))", name, name))
	}
	return map[string]any{
		"name":                  "show",
		"ansible.builtin.debug": map[string]any{"msg": "{{ {" + strings.Join(show, ", ") + "} | to_json }}"},
	}
}

// TestRegression_InventoryInputsReachThePlay runs, for each playbook in
// playVarsCases, its play vars and its "Resolve ... default" set_fact tasks
// through Ansible on localhost, with the host in the playbook's inventory
// group. With group_vars/<group>.yml setting every moved variable, the play
// must see those values; without it, the old defaults. Against the old
// playbooks, the play vars replace every group_vars value.
func TestRegression_InventoryInputsReachThePlay(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	for _, tc := range playVarsCases {
		t.Run(tc.playbook, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile("../../playbooks/apply/" + tc.playbook)
			if err != nil {
				t.Fatal(err)
			}
			var plays []map[string]any
			if err := yaml.Unmarshal(raw, &plays); err != nil {
				t.Fatal(err)
			}
			play := plays[0]
			resolve := pickTasks(play, isDefaultsTask)
			names := make([]string, 0, len(tc.defaults))
			for name := range tc.defaults {
				names = append(names, name)
			}
			sort.Strings(names)
			tasks := append(resolve, showTask(names))

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
// JSON object the show task printed.
func runInventoryPlay(t *testing.T, group string, playVars any, tasks []any, groupVars map[string]any) map[string]any {
	t.Helper()
	got, failed := tryInventoryPlay(t, group, playVars, tasks, groupVars)
	if failed != "" {
		t.Fatalf("ansible-playbook failed: %s", failed)
	}
	return got
}

// tryInventoryPlay is runInventoryPlay for a play that may fail: it returns
// the failed task's name and message instead of failing the test.
func tryInventoryPlay(t *testing.T, group string, playVars any, tasks []any, groupVars map[string]any) (map[string]any, string) {
	t.Helper()
	inv := map[string]any{"all": map[string]any{"children": map[string]any{
		group: map[string]any{"hosts": map[string]any{"localhost": localHostVars()}},
	}}}
	var files map[string]map[string]any
	if groupVars != nil {
		files = map[string]map[string]any{group: groupVars}
	}
	return tryInventoryPlayIn(t, inv, files, group, playVars, tasks)
}

// batchedTaskPrefix marks a task whose failure a block's rescue records;
// tryInventoryPlayIn does not stop at it.
const batchedTaskPrefix = "batched: "

// localHostVars connects an inventory host to the local machine.
func localHostVars() map[string]any {
	return map[string]any{"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3"}
}

// tryInventoryPlayIn runs one play on hosts of inv, with
// group_vars/<group>.yml for every entry of groupVars and extra
// ansible-playbook arguments, and returns the show task's JSON object, or the
// failed task's name and message.
func tryInventoryPlayIn(t *testing.T, inv map[string]any, groupVars map[string]map[string]any, hosts string, playVars any, tasks []any, args ...string) (map[string]any, string) {
	t.Helper()
	dir := t.TempDir()
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
	for group, vars := range groupVars {
		write(filepath.Join(dir, "group_vars", group+".yml"), vars)
	}
	if playVars == nil {
		playVars = map[string]any{}
	}
	write(filepath.Join(dir, "play.yml"), []map[string]any{{
		"name": "inventory inputs", "hosts": hosts, "gather_facts": false, "become": false,
		"vars": playVars, "tasks": tasks,
	}})
	cmd := exec.Command("ansible-playbook", append([]string{"-i", filepath.Join(dir, "inventory.yml"), filepath.Join(dir, "play.yml")}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, runErr := cmd.Output()
	if _, isExit := runErr.(*exec.ExitError); runErr != nil && !isExit {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed bool   `json:"failed"`
					Msg    string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output (%v): %v\n%s", runErr, err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			host := task.Hosts["localhost"]
			// A task named with batchedTaskPrefix runs inside a block whose
			// rescue records the failure, so the play goes on.
			if host.Failed && !strings.HasPrefix(task.Task.Name, batchedTaskPrefix) {
				return nil, task.Task.Name + ": " + host.Msg
			}
			if task.Task.Name != "show" {
				continue
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(host.Msg), &got); err != nil {
				t.Fatalf("decode %q: %v", host.Msg, err)
			}
			return got, ""
		}
	}
	if runErr != nil {
		t.Fatalf("ansible-playbook: %v\n%s", runErr, out)
	}
	t.Fatalf("no output from the show task:\n%s", out)
	return nil, ""
}

// jsonEqual compares a decoded JSON value with a Go value by their JSON.
func jsonEqual(got, want any) bool {
	a, errA := json.Marshal(got)
	b, errB := json.Marshal(want)
	return errA == nil && errB == nil && string(a) == string(b)
}
