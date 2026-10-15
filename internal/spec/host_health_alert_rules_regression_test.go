package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The host-health + login-probe alert rules (GitHub issue kjelly/pilot#11)
// are one Jinja template whose thresholds come from the prometheus role's
// group vars. Three places must agree on those inputs (AGENTS.md §5.7):
// contracts/prometheus.yaml groupVars, prometheus-apply.yml's default()
// resolution and the template itself. The rendered rules must also be
// accepted by the Prometheus version the playbook pins, and every rule must
// demonstrably fire and stay quiet (AGENTS.md §5.12).
const (
	hostHealthTemplate = "../../playbooks/apply/templates/pilot-host-health-alert-rules.yml.j2"
	hostHealthApply    = "../../playbooks/apply/prometheus-apply.yml"
	hostHealthContract = "../../contracts/prometheus.yaml"
	hostHealthPromTest = "testdata/host-health-alert-rules.promtest.yml"
	alertRulesSeed     = "../../playbooks/apply/files/pilot-alert-rules-seed.yml"
	// Must stay the image prometheus-apply.yml runs (prometheus_version).
	hostHealthPromImage = "prom/prometheus:v2.53.0"
)

// hostHealthRuleNames is every alert the template defines.
var hostHealthRuleNames = []string{
	"HostIOStall", "HostDiskLatencyHigh", "HostDiskQueueDeep", "HostPSIUnavailable",
	"HostMetricsMissing",
	"PilotLoginProbeAccountDenied", "PilotLoginProbeAuthFailed", "PilotLoginProbeLoginStalled",
	"PilotLoginProbeHostKeyMismatch", "PilotLoginProbeSessionFailed", "PilotLoginProbeTransportFailed",
	"PilotLoginProbeStale", "PilotLoginProbeNoTargets",
}

// hostHealthContractDefaults returns the template inputs and their contract
// defaults (everything the template references through {{ var }}).
func hostHealthContractDefaults(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(hostHealthContract)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		GroupVars []struct {
			Name    string `yaml:"name"`
			Default any    `yaml:"default"`
		} `yaml:"groupVars"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range c.GroupVars {
		if strings.HasPrefix(v.Name, "host_") || strings.HasPrefix(v.Name, "login_probe_") {
			out[v.Name] = strings.TrimSpace(hostHealthScalar(v.Default))
		}
	}
	return out
}

func hostHealthScalar(v any) string {
	b, _ := yaml.Marshal(v)
	return strings.Trim(strings.TrimSpace(string(b)), `"'`)
}

var templateVarRe = regexp.MustCompile(`\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}`)

func TestRegression_HostHealthRulesInputsAgreeAcrossContractPlaybookTemplate(t *testing.T) {
	tmpl, err := os.ReadFile(hostHealthTemplate)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := os.ReadFile(hostHealthApply)
	if err != nil {
		t.Fatal(err)
	}
	defaults := hostHealthContractDefaults(t)

	used := map[string]bool{}
	for _, m := range templateVarRe.FindAllStringSubmatch(stripRaw(string(tmpl)), -1) {
		used[m[1]] = true
	}
	if len(used) == 0 {
		t.Fatal("template references no inputs")
	}
	for name := range used {
		if _, ok := defaults[name]; !ok {
			t.Errorf("template input %s is not declared in contracts/prometheus.yaml groupVars", name)
		}
	}
	for name, def := range defaults {
		if !used[name] {
			t.Errorf("contract declares %s but the template never uses it", name)
		}
		// prometheus-apply.yml resolves each with default(<contract default>).
		re := regexp.MustCompile(regexp.QuoteMeta(name) + `: "\{\{ ` + regexp.QuoteMeta(name) + ` \| default\('?` + regexp.QuoteMeta(def) + `'?, true\)`)
		if !re.Match(apply) {
			t.Errorf("prometheus-apply.yml must resolve %s with default(%s) (the contract default)", name, def)
		}
	}
	// The playbook must actually render and mount the file it loads.
	for _, want := range []string{
		"src: templates/pilot-host-health-alert-rules.yml.j2",
		"'/etc/prometheus/host-health-alert-rules.yml'",
		"/host-health-alert-rules.yml:/etc/prometheus/host-health-alert-rules.yml:ro",
		"(host_health_alert_rules_result | default({})) is changed",
	} {
		if !strings.Contains(string(apply), want) {
			t.Errorf("prometheus-apply.yml is missing %q", want)
		}
	}
}

// stripRaw removes {% raw %}...{% endraw %} sections (Prometheus's own
// template syntax), leaving only what Ansible's Jinja pass evaluates.
func stripRaw(s string) string {
	re := regexp.MustCompile(`(?s)\{%\s*raw\s*%\}.*?\{%\s*endraw\s*%\}`)
	return re.ReplaceAllString(s, "")
}

func TestRegression_HostHealthRulesKeepPrometheusTemplatesRaw(t *testing.T) {
	tmpl, err := os.ReadFile(hostHealthTemplate)
	if err != nil {
		t.Fatal(err)
	}
	outside := stripRaw(string(tmpl))
	if strings.Contains(outside, "$labels") || strings.Contains(outside, "$value") {
		t.Error("a Prometheus {{ $labels }}/{{ $value }} reference sits outside a {% raw %} block: Ansible would fail on it")
	}
	if !strings.Contains(string(tmpl), "{{ $labels.pilot_host }}") {
		t.Error("annotations must name the host via {{ $labels.pilot_host }}")
	}
}

func TestRegression_HostIOStallUsesFullPressureOnly(t *testing.T) {
	tmpl, err := os.ReadFile(hostHealthTemplate)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(hostHealthPromTest)
	if err != nil {
		t.Fatal(err)
	}
	// node_exporter publishes PSI without a kind label:
	// node_pressure_io_stalled_seconds_total is the "full" line of
	// /proc/pressure/io and node_pressure_io_waiting_seconds_total the
	// "some" line (captured from node_exporter 1.12.1). A kind matcher
	// selects nothing, so HostIOStall could never fire.
	if !strings.Contains(string(tmpl), "rate(node_pressure_io_stalled_seconds_total{job=\"node\"}[5m])") {
		t.Error("HostIOStall must rate node_pressure_io_stalled_seconds_total (PSI full) with no kind matcher")
	}
	if strings.Contains(string(tmpl), "kind=") || strings.Contains(string(fixture), "kind=") {
		t.Error("node_exporter's PSI series have no kind label; neither the rules nor the promtool fixture may use one")
	}
	if strings.Contains(string(tmpl), "node_pressure_io_waiting_seconds_total{") {
		t.Error("HostIOStall must not read node_pressure_io_waiting_seconds_total (PSI some)")
	}
	if !strings.Contains(string(fixture), "node_pressure_io_waiting_seconds_total{job=\"node\",instance=\"io-some:9100\",pilot_host=\"io-some\"}") {
		t.Error("promtool fixture must include a high PSI some (waiting) series on io-some to prove it stays out of HostIOStall")
	}
}

// renderHostHealthRules renders the template with Ansible's own template
// module (the engine prometheus-apply.yml uses) into dir.
func renderHostHealthRules(t *testing.T, dir string, vars map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("ansible-playbook not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	src, err := filepath.Abs(hostHealthTemplate)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "host-health-alert-rules.yml")
	var b strings.Builder
	b.WriteString("- hosts: localhost\n  connection: local\n  gather_facts: false\n  vars:\n")
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("    " + k + ": \"" + vars[k] + "\"\n")
	}
	b.WriteString("  tasks:\n    - ansible.builtin.template:\n        src: " + src + "\n        dest: " + out + "\n")
	pb := filepath.Join(dir, "render.yml")
	if err := os.WriteFile(pb, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	if outp, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render template: %v\n%s", err, outp)
	}
	return out
}

type renderedRules struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert         string            `yaml:"alert"`
			Expr          string            `yaml:"expr"`
			For           string            `yaml:"for"`
			KeepFiringFor string            `yaml:"keep_firing_for"`
			Labels        map[string]string `yaml:"labels"`
			Annotations   map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func TestRegression_HostHealthRulesRenderFromTheirInputs(t *testing.T) {
	defaults := hostHealthContractDefaults(t)
	dir := t.TempDir()
	path := renderHostHealthRules(t, dir, defaults)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rr renderedRules
	if err := yaml.Unmarshal(data, &rr); err != nil {
		t.Fatalf("rendered rules are not YAML: %v\n%s", err, data)
	}
	got := map[string]int{}
	for _, g := range rr.Groups {
		for _, r := range g.Rules {
			got[r.Alert]++
			if r.Labels["severity"] == "" || r.Labels["pilot_alert_source"] == "" {
				t.Errorf("%s needs severity and pilot_alert_source labels", r.Alert)
			}
			if !strings.Contains(r.Annotations["summary"], "{{ $labels.pilot_host }}") {
				t.Errorf("%s summary lost its Prometheus template: %q", r.Alert, r.Annotations["summary"])
			}
			if strings.HasPrefix(r.Alert, "PilotLoginProbe") && r.Alert != "PilotLoginProbeStale" && r.Alert != "PilotLoginProbeNoTargets" {
				if r.KeepFiringFor != defaults["login_probe_alert_keep_firing_for"] {
					t.Errorf("%s keep_firing_for = %q, want %q", r.Alert, r.KeepFiringFor, defaults["login_probe_alert_keep_firing_for"])
				}
				if !strings.Contains(r.Expr, `"pilot_host", "$1", "probe_target"`) {
					t.Errorf("%s must project probe_target onto pilot_host (the up{job=\"node\"} joins and dashboards key on it)", r.Alert)
				}
			}
			// HostMetricsMissing holds the inhibit on HostDown{job="node"}: it
			// must not drop on one failed probe round or a probe restart.
			// Probe freshness must not depend on the probe host's clock.
			if r.Alert == "HostMetricsMissing" && r.KeepFiringFor != defaults["login_probe_alert_keep_firing_for"] {
				t.Errorf("HostMetricsMissing keep_firing_for = %q, want %q", r.KeepFiringFor, defaults["login_probe_alert_keep_firing_for"])
			}
			if (r.Alert == "HostMetricsMissing" || r.Alert == "PilotLoginProbeStale") && (strings.Contains(r.Expr, "time()") || !strings.Contains(r.Expr, "changes(pilot_login_probe_metrics_last_write_timestamp_seconds[")) {
				t.Errorf("%s must judge probe freshness with changes() of the write timestamp, not time(): %s", r.Alert, r.Expr)
			}
			// Alertmanager's Stale inhibit matches on probe_host, so every
			// login-probe alert must keep the probe host as probe_host
			// (docs/verification/alertmanager.md §1.7).
			if strings.HasPrefix(r.Alert, "PilotLoginProbe") {
				if !strings.Contains(r.Expr, `"probe_host", "$1", "pilot_host"`) || !strings.Contains(r.Expr, "by (pilot_host, probe_host)") {
					t.Errorf("%s must keep the probe host as probe_host and aggregate by (pilot_host, probe_host)", r.Alert)
				}
			}
		}
	}
	for _, name := range hostHealthRuleNames {
		if got[name] != 1 {
			t.Errorf("rendered rules define %s %d times, want 1", name, got[name])
		}
	}
	if len(got) != len(hostHealthRuleNames) {
		t.Errorf("rendered %d alerts, want exactly %v", len(got), hostHealthRuleNames)
	}

	// An override must reach the rendered rule (the issue's "configurable
	// thresholds and durations" — AC1).
	over := map[string]string{}
	for k, v := range defaults {
		over[k] = v
	}
	over["host_io_stall_ratio_threshold"] = "0.6"
	over["login_probe_alert_for"] = "7m"
	data2, err := os.ReadFile(renderHostHealthRules(t, t.TempDir(), over))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data2), ") > 0.6\n") || !strings.Contains(string(data2), "for: 7m\n") {
		t.Errorf("overridden threshold/duration did not reach the rendered rules:\n%s", data2)
	}
}

// TestRegression_HostHealthRulesPromtool runs the pinned Prometheus image's
// promtool: `check rules` on the rendered file (annotation templates
// included) and `test rules` on testdata/host-health-alert-rules.promtest.yml,
// which makes every rule fire for one host and stay quiet for another.
func TestRegression_HostHealthRulesPromtool(t *testing.T) {
	requireContainerImage(t, hostHealthPromImage)
	apply, err := os.ReadFile(hostHealthApply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(apply), `prometheus_version: "`+strings.TrimPrefix(hostHealthPromImage, "prom/prometheus:")+`"`) {
		t.Fatalf("hostHealthPromImage %s no longer matches prometheus-apply.yml's prometheus_version", hostHealthPromImage)
	}

	dir := t.TempDir()
	full := renderHostHealthRules(t, dir, hostHealthContractDefaults(t))
	promtool := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("docker", append([]string{"run", "--rm", "--user", "65534", "-v", dir + ":/w:ro", "--entrypoint", "promtool", hostHealthPromImage}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("promtool %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	out := promtool("check", "rules", "/w/host-health-alert-rules.yml")
	if !strings.Contains(out, "SUCCESS: 13 rules found") {
		t.Errorf("promtool check rules: %s", out)
	}

	// promtool compares expanded annotations verbatim; the unit tests assert
	// labels and timing, so they run against annotation-free copies. The
	// seed rules go along: HostDown's timing is part of the contract.
	testDir := t.TempDir()
	for src, dst := range map[string]string{full: "host-health-alert-rules.yml", alertRulesSeed: "seed-alert-rules.yml"} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testDir, dst), stripRuleAnnotations(t, data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unit, err := os.ReadFile(hostHealthPromTest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "unit.yml"), unit, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(testDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dir = testDir
	out = promtool("test", "rules", "/w/unit.yml")
	if !strings.Contains(out, "SUCCESS") {
		t.Errorf("promtool test rules: %s", out)
	}
	for _, name := range append([]string{"HostDown"}, hostHealthRuleNames...) {
		if !strings.Contains(string(unit), "alertname: "+name+"\n") {
			t.Errorf("promtest has no case for %s", name)
		}
	}
}

// stripRuleAnnotations returns a Prometheus rule file without annotations.
func stripRuleAnnotations(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, g := range doc["groups"].([]any) {
		for _, r := range g.(map[string]any)["rules"].([]any) {
			delete(r.(map[string]any), "annotations")
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRegression_HostMetricsMissingFiresBeforeSeedHostDown locks the timing
// the Alertmanager inhibit HostMetricsMissing -> HostDown{job="node"}
// depends on (docs/verification/alertmanager.md §1.7): the data-gap alert
// must fire before the seed HostDown rule, so HostDown never pages a host
// that still answers SSH. prometheus-apply.yml refuses a longer
// host_metrics_missing_for with a gate whose 600 s must stay HostDown's for.
func TestRegression_HostMetricsMissingFiresBeforeSeedHostDown(t *testing.T) {
	data, err := os.ReadFile(alertRulesSeed)
	if err != nil {
		t.Fatal(err)
	}
	var seed renderedRules
	if err := yaml.Unmarshal(data, &seed); err != nil {
		t.Fatal(err)
	}
	var hostDownFor string
	for _, g := range seed.Groups {
		for _, r := range g.Rules {
			if r.Alert == "HostDown" {
				if strings.TrimSpace(r.Expr) != "up != 1" {
					t.Errorf("seed HostDown expr = %q; the inhibit and TransportFailed's up{job=\"node\"} exclusion assume `up != 1`", r.Expr)
				}
				hostDownFor = r.For
			}
		}
	}
	if hostDownFor != "10m" {
		t.Fatalf("seed HostDown for = %q; the prometheus-apply.yml gate (600 s), the rules' comments and §1.7 assume 10m", hostDownFor)
	}
	apply, err := os.ReadFile(hostHealthApply)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"Gate: host_metrics_missing_for is shorter than the seed HostDown rule's 10m"`,
		`(_hmm_count | int) * (_duration_seconds[_hmm_unit] | float) < 600`,
	} {
		if !strings.Contains(string(apply), want) {
			t.Errorf("prometheus-apply.yml is missing %q", want)
		}
	}
	def, err := time.ParseDuration(hostHealthContractDefaults(t)["host_metrics_missing_for"])
	if err != nil {
		t.Fatal(err)
	}
	if def >= 10*time.Minute {
		t.Errorf("default host_metrics_missing_for %s must be shorter than HostDown's 10m", def)
	}
}

// hostHealthPromtest renders the rules with vars, loads them with the seed
// rules into the pinned promtool and runs unit, returning promtool's
// output and whether every case passed.
func hostHealthPromtest(t *testing.T, vars map[string]string, unit string) (string, bool) {
	t.Helper()
	requireContainerImage(t, hostHealthPromImage)
	full := renderHostHealthRules(t, t.TempDir(), vars)
	dir := t.TempDir()
	for src, dst := range map[string]string{full: "host-health-alert-rules.yml", alertRulesSeed: "seed-alert-rules.yml"} {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), stripRuleAnnotations(t, data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "unit.yml"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "run", "--rm", "--user", "65534", "-v", dir+":/w:ro", "--entrypoint", "promtool", hostHealthPromImage, "test", "rules", "/w/unit.yml").CombinedOutput()
	return string(out), err == nil
}

// TestRegression_HostHealthTimingHazardsBehindTheGates proves, with the
// pinned promtool, what prometheus-apply.yml's two freshness gates prevent
// (TestRegression_HostHealthTimingGates runs the gates themselves):
//
//   - host_metrics_missing_for shorter than login_probe_stale_seconds: a
//     probe that stalls as its target dies keeps a fresh-looking success=1
//     long enough for HostMetricsMissing to call the dead host reachable;
//   - a scrape interval longer than a third of login_probe_stale_seconds:
//     a healthy probe's changes() window holds too few samples, so
//     PilotLoginProbeStale fires for it (and mutes all its alerts).
func TestRegression_HostHealthTimingHazardsBehindTheGates(t *testing.T) {
	short := map[string]string{}
	for k, v := range hostHealthContractDefaults(t) {
		short[k] = v
	}
	short["host_metrics_missing_for"] = "1m"
	frozen := `rule_files: [host-health-alert-rules.yml, seed-alert-rules.yml]
evaluation_interval: 1m
tests:
  - interval: 15s
    input_series:
      - series: 'up{job="node",instance="dead2:9100",pilot_host="dead2"}'
        values: '1x8 0x60'
      - series: 'pilot_login_probe_success{job="node",instance="mon-s:9100",pilot_host="mon-s",probe_target="dead2"}'
        values: '1x68'
      - series: 'pilot_login_probe_metrics_last_write_timestamp_seconds{job="node",instance="mon-s:9100",pilot_host="mon-s"}'
        values: '0+15x8 120x60'
    alert_rule_test:
      - eval_time: 4m
        alertname: HostMetricsMissing
        exp_alerts:
          - exp_labels: {pilot_host: dead2, severity: warning, action_required: "true", pilot_alert_source: host-health}
`
	if out, ok := hostHealthPromtest(t, short, frozen); !ok {
		t.Errorf("with host_metrics_missing_for=1m the stalled probe should make HostMetricsMissing fire for the dead host (the hazard the gate refuses):\n%s", out)
	}
	slow := `rule_files: [host-health-alert-rules.yml, seed-alert-rules.yml]
evaluation_interval: 1m
tests:
  - interval: 4m
    input_series:
      - series: 'pilot_login_probe_metrics_last_write_timestamp_seconds{job="node",instance="mon:9100",pilot_host="mon"}'
        values: '0+240x10'
    alert_rule_test:
      - eval_time: 30m
        alertname: PilotLoginProbeStale
        exp_alerts:
          - exp_labels: {pilot_host: mon, probe_host: mon, severity: warning, action_required: "true", pilot_alert_source: login-probe}
`
	if out, ok := hostHealthPromtest(t, hostHealthContractDefaults(t), slow); !ok {
		t.Errorf("a healthy probe scraped every 4m should look stale with the 180 s window (the hazard the gate refuses):\n%s", out)
	}
}

// TestRegression_HostHealthTimingGates runs prometheus-apply.yml's own
// timing gates with ansible-playbook: the defaults pass; a scrape interval
// above a third of login_probe_stale_seconds, a host_metrics_missing_for
// shorter than login_probe_stale_seconds or not shorter than HostDown's
// 10m, and a compound scrape interval are refused.
func TestRegression_HostHealthTimingGates(t *testing.T) {
	tasks := playbookPreTasks(t, hostHealthApply,
		"Gate: host_metrics_missing_for is shorter than the seed HostDown rule's 10m",
		"Gate: login_probe_stale_seconds spans at least three node scrapes",
		"Gate: host_metrics_missing_for is at least login_probe_stale_seconds")
	for _, c := range []struct {
		name               string
		hmm, scrape, stale string
		ok                 bool
	}{
		{"defaults", "3m", "15s", "180", true},
		{"1m scrape", "3m", "1m", "180", true},
		{"61s scrape", "3m", "61s", "180", false},
		{"4m scrape", "3m", "4m", "180", false},
		{"compound scrape interval", "3m", "1m30s", "600", false},
		{"HostMetricsMissing faster than the stale window", "1m", "15s", "180", false},
		{"HostMetricsMissing as slow as HostDown", "10m", "15s", "180", false},
		{"short stale window, short for", "1m", "15s", "60", true},
	} {
		vars := map[string]any{
			"prometheus_host_health_alert_rules_enabled": true,
			"host_metrics_missing_for":                   c.hmm,
			"prometheus_scrape_interval":                 c.scrape,
			"login_probe_stale_seconds":                  c.stale,
		}
		out, ok := runLocalPlay(t, vars, tasks)
		if ok != c.ok {
			t.Errorf("%s: gates passed = %v, want %v\n%s", c.name, ok, c.ok, out)
		}
	}
}
