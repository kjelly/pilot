package spec

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
			if r.Alert == "PilotLoginProbeStale" && (strings.Contains(r.Expr, "time()") || !strings.Contains(r.Expr, "changes(pilot_login_probe_metrics_last_write_timestamp_seconds[")) {
				t.Errorf("PilotLoginProbeStale must judge probe freshness with changes() of the write timestamp, not time(): %s", r.Expr)
			}
			// HostMetricsMissing trusts only a login to the target itself that
			// succeeded within host_metrics_missing_success_window: a frozen
			// or slow probe's success=1 must not count (alertmanager.md §1.7).
			if r.Alert == "HostMetricsMissing" && (strings.Contains(r.Expr, "time()") || !strings.Contains(r.Expr, "changes(pilot_login_probe_last_success_timestamp_seconds["+defaults["host_metrics_missing_success_window"]+"]) > 0") || !strings.Contains(r.Expr, "on (job, instance, probe_target)")) {
				t.Errorf("HostMetricsMissing must require a recent success of the target itself (changes of its last-success timestamp, joined per probe_target): %s", r.Expr)
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
		t.Fatalf("seed HostDown for = %q; the prometheus-apply.yml gate (9m, one evaluation interval below it), the rules' comments and §1.7 assume 10m", hostDownFor)
	}
	apply, err := os.ReadFile(hostHealthApply)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"Gate: host_metrics_missing_for leaves one evaluation interval before the seed HostDown rule's 10m"`,
		`(_hmm_count | int) * (_duration_seconds[_hmm_unit] | float) <= 540`,
	} {
		if !strings.Contains(string(apply), want) {
			t.Errorf("prometheus-apply.yml is missing %q", want)
		}
	}
	def, err := time.ParseDuration(hostHealthContractDefaults(t)["host_metrics_missing_for"])
	if err != nil {
		t.Fatal(err)
	}
	if def > 9*time.Minute {
		t.Errorf("default host_metrics_missing_for %s must be at most 9m, one evaluation interval below HostDown's 10m", def)
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
// pinned promtool, what prometheus-apply.yml's timing gates prevent
// (TestRegression_HostHealthTimingGates runs the gates themselves):
//
//   - host_metrics_missing_success_window + the 15 s textfile write longer
//     than host_metrics_missing_for: the dead host's last success is
//     published 15 s after it happened and still counts, so
//     HostMetricsMissing calls the dead host reachable. At the boundary
//     (165 s + 15 s = 3m, which the gate accepts) it never fires; one
//     window 5 s longer (refused) fires at 4m;
//   - a scrape interval longer than a third of login_probe_stale_seconds:
//     a healthy probe's changes() window holds too few samples, so
//     PilotLoginProbeStale fires for it (and mutes all its alerts);
//   - a host_metrics_missing_success_window that covers the gap between
//     two seen changes but not one more scrape. changes(ts[W]) counts a
//     change only while the sample before it is in the range, so one seen
//     change holds for W - scrape. With a 1m scrape off the evaluation
//     grid and changes seen 120 s apart (the probe-round model's
//     interval + timeout + 15 s + one scrape), the one-scrape bound the
//     gate used to apply accepts W = 120 s: HostMetricsMissing never fires
//     and HostDown pages a host that answers SSH. W = 180 s (+ 2 scrapes,
//     the gate's bound now) holds.
func TestRegression_HostHealthTimingHazardsBehindTheGates(t *testing.T) {
	// 1 s samples: logins succeed every minute; the previous one was
	// published at 14 s, the last one (at 59 s) by the 74 s textfile write.
	// The first failed node scrape is at 60 s; success stays 1 (the probe
	// has not reached the target again).
	dead := func(want string) string {
		return `rule_files: [host-health-alert-rules.yml, seed-alert-rules.yml]
evaluation_interval: 1m
tests:
  - interval: 1s
    input_series:
      - series: 'up{job="node",instance="dead1:9100",pilot_host="dead1"}'
        values: '1x59 0x900'
      - series: 'pilot_login_probe_success{job="node",instance="mon-s:9100",pilot_host="mon-s",probe_target="dead1"}'
        values: '1x960'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon-s:9100",pilot_host="mon-s",probe_target="dead1"}'
        values: '0x13 1x59 59x900'
    alert_rule_test:
      - eval_time: 4m
        alertname: HostMetricsMissing
        exp_alerts:` + want + `
      - eval_time: 10m
        alertname: HostMetricsMissing
        exp_alerts: []
`
	}
	fires := `
          - exp_labels: {pilot_host: dead1, severity: warning, action_required: "true", pilot_alert_source: host-health}`
	for _, c := range []struct {
		window, want string
	}{
		{"170s", fires}, // 170 + 15 > 180: the gate refuses it
		{"165s", " []"}, // 165 + 15 = 180: the gate accepts it, and it holds
	} {
		vars := map[string]string{}
		for k, v := range hostHealthContractDefaults(t) {
			vars[k] = v
		}
		vars["host_metrics_missing_success_window"] = c.window
		if out, ok := hostHealthPromtest(t, vars, dead(c.want)); !ok {
			t.Errorf("window %s, host_metrics_missing_for 3m: unexpected HostMetricsMissing for the dead host:\n%s", c.window, out)
		}
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
	// 1 s steps; the target and the probe host are scraped every 60 s at
	// 7 s past each minute (`_` elsewhere), so window edges fall between
	// evaluations. The target's last-success timestamp is seen to change
	// at every other scrape.
	offGrid := func(value func(j int) string) string {
		var b strings.Builder
		for sec := 0; sec <= 780; sec++ {
			if sec > 0 {
				b.WriteByte(' ')
			}
			if (sec-7)%60 == 0 && sec >= 7 {
				b.WriteString(value((sec - 7) / 60))
			} else {
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	roundBoundary := func(want string) string {
		return `rule_files: [host-health-alert-rules.yml, seed-alert-rules.yml]
evaluation_interval: 1m
tests:
  - interval: 1s
    input_series:
      - series: 'up{job="node",instance="gap1:9100",pilot_host="gap1"}'
        values: '` + offGrid(func(int) string { return "0" }) + `'
      - series: 'pilot_login_probe_success{job="node",instance="mon-r:9100",pilot_host="mon-r",probe_target="gap1"}'
        values: '` + offGrid(func(int) string { return "1" }) + `'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon-r:9100",pilot_host="mon-r",probe_target="gap1"}'
        values: '` + offGrid(func(j int) string { return strconv.Itoa(120 * ((j + 1) / 2)) }) + `'
    alert_rule_test:
      - eval_time: 12m
        alertname: HostMetricsMissing
        exp_alerts:` + want + `
      - eval_time: 12m
        alertname: HostDown
        exp_alerts:
          - exp_labels: {instance: "gap1:9100", job: node, pilot_host: gap1, severity: critical}
`
	}
	holds := `
          - exp_labels: {pilot_host: gap1, severity: warning, action_required: "true", pilot_alert_source: host-health}`
	for _, c := range []struct {
		window, want string
	}{
		{"120s", " []"}, // seen gap + one scrape: the old bound accepted it, and it drops out
		{"180s", holds}, // seen gap + two scrapes: the gate's bound now
	} {
		vars := map[string]string{}
		for k, v := range hostHealthContractDefaults(t) {
			vars[k] = v
		}
		vars["host_metrics_missing_for"] = "4m"
		vars["host_metrics_missing_success_window"] = c.window
		if out, ok := hostHealthPromtest(t, vars, roundBoundary(c.want)); !ok {
			t.Errorf("window %s, changes seen 120 s apart at a 1m scrape: unexpected HostMetricsMissing outcome:\n%s", c.window, out)
		}
	}
}

// TestRegression_HostMetricsMissingExpressionParts evaluates
// HostMetricsMissing's own expression (from the rendered rules) with
// promtool's promql_expr_test, and proves each of its two guards matters
// by mutating it (AGENTS.md §5.12):
//
//   - the per-target join `on (job, instance, probe_target)`: dead5 shares
//     its probe with live5, whose timestamp keeps moving; joined only on
//     the probe, live5's successes would count for dead5;
//   - `success == 1`: fail6's last attempt failed right after a success,
//     so its timestamp has just changed but it does not answer now.
func TestRegression_HostMetricsMissingExpressionParts(t *testing.T) {
	data, err := os.ReadFile(renderHostHealthRules(t, t.TempDir(), hostHealthContractDefaults(t)))
	if err != nil {
		t.Fatal(err)
	}
	var rr renderedRules
	if err := yaml.Unmarshal(data, &rr); err != nil {
		t.Fatal(err)
	}
	var expr string
	for _, g := range rr.Groups {
		for _, r := range g.Rules {
			if r.Alert == "HostMetricsMissing" {
				expr = r.Expr
			}
		}
	}
	if expr == "" {
		t.Fatal("no HostMetricsMissing rule")
	}
	unit := func(e string) string {
		return `rule_files: [host-health-alert-rules.yml]
evaluation_interval: 1m
tests:
  - interval: 15s
    input_series:
      - series: 'up{job="node",instance="dead5:9100",pilot_host="dead5"}'
        values: '0x40'
      - series: 'pilot_login_probe_success{job="node",instance="mon:9100",pilot_host="mon",probe_target="dead5"}'
        values: '1x40'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon:9100",pilot_host="mon",probe_target="dead5"}'
        values: '0x40'
      - series: 'up{job="node",instance="live5:9100",pilot_host="live5"}'
        values: '1x40'
      - series: 'pilot_login_probe_success{job="node",instance="mon:9100",pilot_host="mon",probe_target="live5"}'
        values: '1x40'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon:9100",pilot_host="mon",probe_target="live5"}'
        values: '0+15x40'
      - series: 'up{job="node",instance="fail6:9100",pilot_host="fail6"}'
        values: '0x40'
      - series: 'pilot_login_probe_success{job="node",instance="mon:9100",pilot_host="mon",probe_target="fail6"}'
        values: '1x32 0x8'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon:9100",pilot_host="mon",probe_target="fail6"}'
        values: '0+15x32 480x8'
      - series: 'up{job="node",instance="gap7:9100",pilot_host="gap7"}'
        values: '0x40'
      - series: 'pilot_login_probe_success{job="node",instance="mon:9100",pilot_host="mon",probe_target="gap7"}'
        values: '1x40'
      - series: 'pilot_login_probe_last_success_timestamp_seconds{job="node",instance="mon:9100",pilot_host="mon",probe_target="gap7"}'
        values: '0+15x40'
    promql_expr_test:
      - expr: ` + strconv.Quote(e) + `
        eval_time: 9m
        exp_samples:
          - labels: '{pilot_host="gap7"}'
            value: 0
`
	}
	run := func(e string) (string, bool) {
		t.Helper()
		requireContainerImage(t, hostHealthPromImage)
		dir := t.TempDir()
		stripped := stripRuleAnnotations(t, data)
		for name, content := range map[string][]byte{"host-health-alert-rules.yml": stripped, "unit.yml": []byte(unit(e))} {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("docker", "run", "--rm", "--user", "65534", "-v", dir+":/w:ro", "--entrypoint", "promtool", hostHealthPromImage, "test", "rules", "/w/unit.yml").CombinedOutput()
		return string(out), err == nil
	}
	if out, ok := run(expr); !ok {
		t.Fatalf("HostMetricsMissing's expression should select only gap7 at 9m:\n%s", out)
	}
	for name, mutated := range map[string]string{
		"join on the probe only": strings.Replace(expr, "on (job, instance, probe_target)", "on (job, instance)", 1),
		"success ignored":        strings.Replace(expr, "(pilot_login_probe_success == 1)", "(pilot_login_probe_success >= 0)", 1),
	} {
		if mutated == expr {
			t.Fatalf("mutation %q did not apply to %s", name, expr)
		}
		if out, ok := run(mutated); ok {
			t.Errorf("mutation %q still passes; the case does not exercise it:\n%s", name, out)
		}
	}
}

const (
	hostMetricsMissingRoundGate = "../../playbooks/apply/tasks/host-metrics-missing-probe-round-gate.yml"
	loginProbeApply             = "../../playbooks/apply/login-probe-apply.yml"
)

// contractGroupVarDefaults returns every groupVars default of a contract.
func contractGroupVarDefaults(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
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
		out[v.Name] = strings.TrimSpace(hostHealthScalar(v.Default))
	}
	return out
}

// TestRegression_HostHealthTimingConstantsAgree ties the numbers the timing
// gates assume to their sources (AGENTS.md §5.7):
//
//   - the 15 s textfile write interval of cmd/pilot-login-probe, used by
//     prometheus-apply.yml's window gate and by the shared probe-round gate;
//   - the login-probe defaults (contracts/login-probe.yaml, as
//     login-probe-apply.yml resolves them) that prometheus-apply.yml assumes
//     for login-probe hosts that do not set them;
//   - the Prometheus defaults (contracts/prometheus.yaml and
//     prometheus-apply.yml) that login-probe-apply.yml assumes for
//     Prometheus hosts that do not set them;
//   - both callers include the same gate file, which holds the arithmetic.
func TestRegression_HostHealthTimingConstantsAgree(t *testing.T) {
	main, err := os.ReadFile("../../cmd/pilot-login-probe/main.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const textfileWriteInterval = (\d+) \* time\.Second`).FindSubmatch(main)
	if m == nil {
		t.Fatal("cmd/pilot-login-probe/main.go: no `const textfileWriteInterval = N * time.Second`")
	}
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	apply, probe, gate := read(hostHealthApply), read(loginProbeApply), read(hostMetricsMissingRoundGate)
	want := "_textfile_write_seconds: " + string(m[1]) + "\n"
	if got := strings.Count(apply, want); got != 1 {
		t.Errorf("prometheus-apply.yml's window gate must use %q (textfileWriteInterval); found %d", strings.TrimSpace(want), got)
	}
	if got := strings.Count(gate, want); got != 1 {
		t.Errorf("the probe-round gate must use %q (textfileWriteInterval); found %d", strings.TrimSpace(want), got)
	}
	for _, src := range []struct{ name, text string }{{"prometheus-apply.yml", apply}, {"login-probe-apply.yml", probe}} {
		if got := strings.Count(src.text, "file: tasks/host-metrics-missing-probe-round-gate.yml"); got != 1 {
			t.Errorf("%s must include tasks/host-metrics-missing-probe-round-gate.yml once; found %d", src.name, got)
		}
	}
	for _, msg := range probeRoundArithmeticOutsideGate(t, hostHealthApply, loginProbeApply) {
		t.Error(msg)
	}
	// The check catches a playbook that computes the bound itself (§5.12).
	gateTask := "    - name: \"Gate: every login-probe host records a success inside host_metrics_missing_success_window\"\n"
	ownGate := "    - name: \"Gate: own probe-round arithmetic\"\n" +
		"      ansible.builtin.assert:\n" +
		"        that: [\"(hostvars[h].login_probe_interval | regex_search('^[0-9]+') | int) <= 90\"]\n" +
		"      tags: [always]\n\n"
	for _, m := range []struct{ name, apply, probe string }{
		{"a second probe-round gate in prometheus-apply.yml", strings.Replace(apply, gateTask, ownGate+gateTask, 1), probe},
		{"arithmetic in prometheus-apply.yml's include", strings.Replace(apply,
			"'interval': hostvars[h].login_probe_interval | default('60s', true) | string,",
			"'interval': (hostvars[h].login_probe_interval | default('60s', true) | regex_search('^[0-9]+') | int) * 1,", 1), probe},
		{"a window read outside login-probe-apply.yml's include", apply, strings.Replace(probe,
			"    - name: \"Gate: artifact path is supplied\"\n",
			"    - name: \"Window\"\n      ansible.builtin.debug: {msg: \"{{ hostvars[groups.prometheus[0]].host_metrics_missing_success_window }}\"}\n      tags: [always]\n\n    - name: \"Gate: artifact path is supplied\"\n", 1)},
	} {
		if m.apply == apply && m.probe == probe {
			t.Fatalf("mutation %q changed nothing", m.name)
		}
		if got := probeRoundArithmeticIn(t, map[string]string{"prometheus-apply.yml": m.apply, "login-probe-apply.yml": m.probe}); len(got) == 0 {
			t.Errorf("mutation %q: the single-source check found nothing", m.name)
		} else {
			t.Logf("mutation %q caught: %s", m.name, got[0])
		}
	}
	lp := contractGroupVarDefaults(t, "../../contracts/login-probe.yaml")
	for _, name := range []string{"login_probe_interval", "login_probe_total_timeout"} {
		def := lp[name]
		if def == "" {
			t.Fatalf("contracts/login-probe.yaml has no default for %s", name)
		}
		if !strings.Contains(probe, name+`: "{{ `+name+` | default('`+def+`', true) }}"`) {
			t.Errorf("login-probe-apply.yml must default %s to the contract's %s", name, def)
		}
		if !strings.Contains(apply, "hostvars[h]."+name+" | default('"+def+"', true)") {
			t.Errorf("prometheus-apply.yml's probe-round gate must default %s to the contract's %s", name, def)
		}
	}
	pr := contractGroupVarDefaults(t, hostHealthContract)
	for _, c := range []struct{ playbook, gate string }{
		{`host_metrics_missing_success_window: "{{ host_metrics_missing_success_window | default('` + pr["host_metrics_missing_success_window"] + `', true) }}"`,
			"hostvars[h].host_metrics_missing_success_window | default('" + pr["host_metrics_missing_success_window"] + "', true)"},
		{`prometheus_scrape_interval: "{{ prometheus_scrape_interval | default('15s') }}"`,
			"hostvars[h].prometheus_scrape_interval | default('15s')"},
		{`prometheus_host_health_alert_rules_enabled: "{{ prometheus_host_health_alert_rules_enabled | default(` + pr["prometheus_host_health_alert_rules_enabled"] + `) | bool }}"`,
			"hostvars[h].prometheus_host_health_alert_rules_enabled | default(" + pr["prometheus_host_health_alert_rules_enabled"] + ") | bool"},
	} {
		if !strings.Contains(apply, c.playbook) {
			t.Errorf("prometheus-apply.yml no longer resolves %q", c.playbook)
		}
		if !strings.Contains(probe, c.gate) {
			t.Errorf("login-probe-apply.yml's probe-round gate must read %q, the default prometheus-apply.yml uses", c.gate)
		}
	}
}

var jinjaStringLiteral = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// stringLeaves returns every string inside v (maps and lists walked).
func stringLeaves(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, stringLeaves(e)...)
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, stringLeaves(e)...)
		}
		return out
	}
	return nil
}

// probeRoundGateInclude marks the task that hands one side's settings to
// the shared probe-round gate.
const probeRoundGateInclude = "tasks/host-metrics-missing-probe-round-gate.yml"

// probeRoundArithmeticOutsideGate checks that only the shared gate file
// computes the probe-round bound (AGENTS.md §5.7). Each playbook reads the
// other side's settings — prometheus-apply.yml the login-probe hosts'
// interval and timeout, login-probe-apply.yml the Prometheus hosts' window
// and scrape interval — only in its include of the gate, and passes them
// through there as strings, without parsing or arithmetic.
func probeRoundArithmeticOutsideGate(t *testing.T, prometheusApply, loginProbeApply string) []string {
	t.Helper()
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	return probeRoundArithmeticIn(t, map[string]string{
		filepath.Base(prometheusApply): read(prometheusApply),
		filepath.Base(loginProbeApply): read(loginProbeApply),
	})
}

// probeRoundArithmeticIn is probeRoundArithmeticOutsideGate on the playbooks'
// contents, keyed by file name.
func probeRoundArithmeticIn(t *testing.T, playbooks map[string]string) []string {
	t.Helper()
	numeric := regexp.MustCompile(`\|\s*(int|float|round)\b|regex_(search|findall|replace)|[)\]0-9a-z_]\s*[-+*/]\s*[(0-9a-z_]`)
	var out []string
	for _, side := range []struct {
		path  string
		other []string
	}{
		{"prometheus-apply.yml", []string{"login_probe_interval", "login_probe_total_timeout"}},
		{"login-probe-apply.yml", []string{"host_metrics_missing_success_window", "prometheus_scrape_interval"}},
	} {
		src, ok := playbooks[side.path]
		if !ok {
			t.Fatalf("no contents for %s", side.path)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal([]byte(src), &plays); err != nil {
			t.Fatal(err)
		}
		var walk func(tasks []any)
		walk = func(tasks []any) {
			for _, raw := range tasks {
				task, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				for _, k := range []string{"block", "rescue", "always"} {
					if sub, ok := task[k].([]any); ok {
						walk(sub)
					}
				}
				data, err := yaml.Marshal(task)
				if err != nil {
					t.Fatal(err)
				}
				text := string(data)
				if inc, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok && inc["file"] == probeRoundGateInclude {
					for _, v := range stringLeaves(task["vars"]) {
						// Jinja whitespace markers ({%- -%}) and string
						// literals ('login-probe', '60s') are not arithmetic.
						plain := strings.NewReplacer("{%-", "{%", "-%}", "%}", "{{-", "{{", "-}}", "}}").Replace(v)
						plain = jinjaStringLiteral.ReplaceAllString(plain, "''")
						if m := numeric.FindString(plain); m != "" {
							out = append(out, fmt.Sprintf("%s: the include of the probe-round gate converts or computes (%q); pass the settings through as strings", side.path, m))
						}
					}
					continue
				}
				for _, name := range side.other {
					if regexp.MustCompile(`\b` + name + `\b`).MatchString(text) {
						n, _ := task["name"].(string)
						out = append(out, fmt.Sprintf("%s: task %q reads %s outside the include of the probe-round gate", side.path, n, name))
					}
				}
			}
		}
		for _, play := range plays {
			for _, k := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				if tasks, ok := play[k].([]any); ok {
					walk(tasks)
				}
			}
		}
	}
	return out
}

// runnableTasks rewrites the relative include_tasks paths of tasks taken
// from a playbook, so they run from a temporary play.
func runnableTasks(t *testing.T, tasks []map[string]any) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(tasks))
	for _, task := range tasks {
		c := map[string]any{}
		for k, v := range task {
			c[k] = v
		}
		if inc, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok {
			n := map[string]any{}
			for k, v := range inc {
				n[k] = v
			}
			abs, err := filepath.Abs(filepath.Join("../../playbooks/apply", inc["file"].(string)))
			if err != nil {
				t.Fatal(err)
			}
			n["file"] = abs
			c["ansible.builtin.include_tasks"] = n
		}
		out = append(out, c)
	}
	return out
}

// TestRegression_HostHealthTimingGates runs prometheus-apply.yml's own
// timing gates with ansible-playbook, against an inventory with login-probe
// hosts. The defaults pass. These are refused:
//
//   - a scrape interval above a third of login_probe_stale_seconds, or a
//     compound one;
//   - a host_metrics_missing_for over 9m (HostDown fires at 10m, and the
//     rule groups are evaluated up to 1m apart);
//   - a host_metrics_missing_success_window that, plus the probe's 15 s
//     textfile write, exceeds host_metrics_missing_for (a dead host would
//     fire), or that is shorter than two scrapes;
//   - a window shorter than some login-probe host's login_probe_interval +
//     login_probe_total_timeout + 15 s + 2 scrapes (a data gap would drop
//     out and HostDown would page a live host). The second login-probe
//     host is the bad one in those cases, so a gate that reads only the
//     first host fails here.
func TestRegression_HostHealthTimingGates(t *testing.T) {
	tasks := runnableTasks(t, playbookPreTasks(t, hostHealthApply,
		"Gate: host_metrics_missing_for leaves one evaluation interval before the seed HostDown rule's 10m",
		"Gate: login_probe_stale_seconds spans at least three node scrapes",
		"Gate: host_metrics_missing_success_window plus one textfile write fits in host_metrics_missing_for",
		"Gate: every login-probe host records a success inside host_metrics_missing_success_window"))
	inventory := func(interval, timeout string) string {
		probe2 := "probe2: {}"
		if interval != "" {
			probe2 = "probe2: {login_probe_interval: \"" + interval + "\", login_probe_total_timeout: \"" + timeout + "\"}"
		}
		return "all:\n  hosts:\n    localhost: {ansible_connection: local}\n  children:\n    login-probe:\n      hosts:\n        probe1: {}\n        " + probe2 + "\n"
	}
	for _, c := range []struct {
		name                       string
		hmm, window, scrape, stale string
		interval, timeout          string // probe2's; "" = the login-probe defaults (60s / 30s)
		ok                         bool
	}{
		{"defaults", "3m", "150s", "15s", "180", "", "", true},
		{"1m scrape", "3m", "150s", "1m", "180", "", "", false}, // 60+30+15+120 > 150
		{"61s scrape", "3m", "150s", "61s", "180", "", "", false},
		{"4m scrape", "3m", "150s", "4m", "180", "", "", false},
		{"compound scrape interval", "3m", "150s", "1m30s", "600", "", "", false},
		{"window + 15 s exactly the for", "3m", "165s", "15s", "180", "", "", true},
		{"window + 15 s past the for (dead host fires at 4m)", "3m", "170s", "15s", "180", "", "", false},
		{"window + 15 s past a 9m for (dead host mutes HostDown)", "9m", "530s", "15s", "180", "", "", false},
		{"window longer than the for", "3m", "6m", "15s", "180", "", "", false},
		{"window shorter than two scrapes", "3m", "20s", "15s", "180", "5s", "2s", false},
		{"window exactly the default probe round", "3m", "135s", "15s", "180", "", "", true}, // 60+30+15+2x15 = 135
		{"window one second short of the default probe round", "3m", "134s", "15s", "180", "", "", false},
		{"the old one-scrape bound at a 15s scrape", "3m", "120s", "15s", "180", "", "", false}, // 60+30+15+15
		{"the old one-scrape bound at a 30s scrape", "3m", "135s", "30s", "180", "", "", false}, // 60+30+15+30
		{"the old one-scrape bound at a 1m scrape", "3m", "165s", "1m", "180", "", "", false},   // 60+30+15+60
		{"short for, shorter window, default probe", "1m", "45s", "15s", "60", "", "", false},
		{"3m probe interval", "9m", "8m", "15s", "180", "3m", "30s", true},
		{"3m probe interval, default window", "3m", "150s", "15s", "180", "3m", "30s", false},
		{"fast second probe, window at the first probe's round", "150s", "135s", "15s", "180", "30s", "20s", true},
		{"compound Go duration probe interval", "3m", "150s", "15s", "180", "1m0s", "30s", true},
		{"fractional Go duration probe interval", "3m", "150s", "15s", "180", "0.75m", "30s", true}, // 45+30+15+30 = 120
		{"compound Go duration over the window", "3m", "150s", "15s", "180", "1m30s", "30s", false}, // 90+30+15+30 = 165
		{"unparsable probe interval", "3m", "150s", "15s", "180", "60", "30s", false},
		{"zero probe timeout", "3m", "150s", "15s", "180", "60s", "0s", false},
		{"9m for", "9m", "8m", "15s", "180", "", "", true},
		{"590s for (HostDown could notify first)", "590s", "8m", "15s", "180", "", "", false},
		{"HostMetricsMissing as slow as HostDown", "10m", "150s", "15s", "180", "", "", false},
	} {
		vars := map[string]any{
			"prometheus_host_health_alert_rules_enabled": true,
			"host_metrics_missing_for":                   c.hmm,
			"host_metrics_missing_success_window":        c.window,
			"prometheus_scrape_interval":                 c.scrape,
			"login_probe_stale_seconds":                  c.stale,
		}
		out, ok := runLocalPlayInventory(t, inventory(c.interval, c.timeout), vars, tasks)
		if ok != c.ok {
			t.Errorf("%s: gates passed = %v, want %v\n%s", c.name, ok, c.ok, out)
		}
	}
	// Without login-probe hosts the probe-round gate does not apply.
	vars := map[string]any{"prometheus_host_health_alert_rules_enabled": true, "host_metrics_missing_for": "3m",
		"host_metrics_missing_success_window": "60s", "prometheus_scrape_interval": "15s", "login_probe_stale_seconds": "180"}
	if out, ok := runLocalPlay(t, vars, tasks); !ok {
		t.Errorf("no login-probe hosts: gates refused a 60s window\n%s", out)
	}
}

// TestRegression_LoginProbeChecksTheHostMetricsMissingWindow runs
// login-probe-apply.yml's copy of the probe-round gate (the same task file
// prometheus-apply.yml runs): a probe whose interval no longer fits a
// Prometheus host's window is refused by the login-probe apply itself, so
// `pilot deploy` of login-probe alone cannot silently disable
// HostMetricsMissing (PR #80 review). The second Prometheus host is the
// short one, and one with the host-health rules off is ignored.
func TestRegression_LoginProbeChecksTheHostMetricsMissingWindow(t *testing.T) {
	tasks := runnableTasks(t, playbookPreTasks(t, loginProbeApply,
		"Gate: this probe records a success inside every Prometheus host's host_metrics_missing_success_window"))
	inventory := func(prom2 string) string {
		return "all:\n  hosts:\n    localhost: {ansible_connection: local}\n  children:\n    prometheus:\n      hosts:\n        prom1: {}\n        prom2: " + prom2 + "\n        prom3: {prometheus_host_health_alert_rules_enabled: false, host_metrics_missing_success_window: 10s}\n"
	}
	for _, c := range []struct {
		name, prom2, interval, timeout string
		ok                             bool
	}{
		{"defaults", "{}", "60s", "30s", true},
		{"a 3m probe interval", "{}", "3m", "30s", false},
		{"a 3m probe interval, a long window", "{host_metrics_missing_success_window: 8m, host_metrics_missing_for: 9m}", "3m", "30s", false}, // prom1 still has 150s
		{"a short window on the second Prometheus", "{host_metrics_missing_success_window: 120s}", "60s", "30s", false},
		{"a 1m scrape on the second Prometheus", "{prometheus_scrape_interval: 1m}", "60s", "30s", false},
		{"a compound Go duration", "{}", "1m0s", "30s", true},
	} {
		vars := map[string]any{"login_probe_interval": c.interval, "login_probe_total_timeout": c.timeout}
		out, ok := runLocalPlayInventory(t, inventory(c.prom2), vars, tasks)
		if ok != c.ok {
			t.Errorf("%s: gate passed = %v, want %v\n%s", c.name, ok, c.ok, out)
		}
	}
	if out, ok := runLocalPlay(t, map[string]any{"login_probe_interval": "3m", "login_probe_total_timeout": "30s"}, tasks); !ok {
		t.Errorf("no Prometheus host: the gate refused\n%s", out)
	}
}

// TestRegression_HostHealthProbeRoundGateParsesGoDurations ties the gate's duration
// parser to the format contracts/login-probe.yaml allows (AGENTS.md §5.7):
// the login-probe durations are Go durations, so every value
// time.ParseDuration accepts with a positive result must parse to the same
// number of seconds, and every other value must be refused — with two
// known exceptions, locked at their actual outcome below and tracked as gate
// hardening in GitHub issue #123:
//
//   - "60s\n": the gate's `$` also matches before a trailing newline, so it
//     parses as 60 s, which time.ParseDuration rejects. An inventory value
//     reaches the gate without it (a plain YAML scalar has no trailing
//     newline);
//   - "2562048h": time.ParseDuration rejects the overflow, while the gate
//     parses it and then refuses it, because it needs a window far longer
//     than any Prometheus host has.
func TestRegression_HostHealthProbeRoundGateParsesGoDurations(t *testing.T) {
	values := []string{"60s", "1m", "1m30s", "1.5m", "0.75m", "90s", "1h", "500ms", "2m0s", "1m30.5s", ".5h", "1.s",
		"100us", "100µs", "1h2m3s4ms", "60", "1d", "-1s", "+1s", "1m30", "0s", "0", "s", "1 m", "1M", "",
		"60s\n", "2562048h"}
	// The exceptions: what the gate does with them (parsed, seconds, pair ok).
	type outcome struct {
		parsed  bool
		seconds float64
		ok      bool
	}
	known := map[string]outcome{
		"60s\n":    {true, 60, true},
		"2562048h": {true, 2562048 * 3600, false},
	}
	gate, err := filepath.Abs(hostMetricsMissingRoundGate)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "pairs.json")
	probes := []map[string]any{}
	for i, v := range values {
		probes = append(probes, map[string]any{"name": "p" + strconv.Itoa(i), "interval": v, "timeout": "1s"})
	}
	tasks := []map[string]any{
		{"ansible.builtin.include_tasks": gate, "vars": map[string]any{
			"hmm_gate_windows": []map[string]any{{"name": "prom", "window": "1d", "scrape": "15s"}},
			"hmm_gate_probes":  probes}},
	}
	// The assert fails (some values are refused); write the pairs first.
	tasks = []map[string]any{{"block": tasks, "always": []map[string]any{
		{"ansible.builtin.copy": map[string]any{"content": "{{ _hmm_round_pairs | to_json }}", "dest": out}}}}}
	runLocalPlay(t, map[string]any{}, tasks)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the gate wrote no result: %v", err)
	}
	var pairs []struct {
		Probe           string  `json:"probe"`
		IntervalSeconds float64 `json:"interval_seconds"`
		Parsed          bool    `json:"parsed"`
		OK              bool    `json:"ok"`
	}
	if err := json.Unmarshal(data, &pairs); err != nil {
		t.Fatal(err)
	}
	if len(pairs) != len(values) {
		t.Fatalf("got %d pairs, want %d", len(pairs), len(values))
	}
	for i, v := range values {
		if want, ok := known[v]; ok {
			if _, err := time.ParseDuration(v); err == nil {
				t.Errorf("%q: time.ParseDuration now accepts it; it is no longer an exception", v)
			}
			got := outcome{pairs[i].Parsed, pairs[i].IntervalSeconds, pairs[i].OK}
			if got.parsed != want.parsed || math.Abs(got.seconds-want.seconds) > 1e-3 || got.ok != want.ok {
				t.Errorf("%q: gate gave parsed=%v seconds=%v ok=%v, want %+v", v, got.parsed, got.seconds, got.ok, want)
			}
			continue
		}
		d, err := time.ParseDuration(v)
		goOK := err == nil && d > 0
		if pairs[i].Parsed != goOK {
			t.Errorf("%q: gate parsed = %v, time.ParseDuration ok and > 0 = %v", v, pairs[i].Parsed, goOK)
			continue
		}
		if goOK && math.Abs(pairs[i].IntervalSeconds-d.Seconds()) > 1e-6 {
			t.Errorf("%q: gate = %v s, time.ParseDuration = %v s", v, pairs[i].IntervalSeconds, d.Seconds())
		}
	}
}

// hostHealthTimingAssumptionViolations checks the Prometheus settings the
// timing gates assume against prometheus-apply.yml (apply), the seed rules
// (seed) and the host-health rules template (template):
//
//   - the 9m cap on host_metrics_missing_for assumes the default 1m
//     evaluation interval: neither rendered prometheus.yml sets
//     evaluation_interval, and no rule group sets interval:;
//   - the probe-round gate uses the global prometheus_scrape_interval as the
//     node job's: each rendered prometheus.yml has exactly one
//     scrape_interval, `{{ prometheus_scrape_interval }}`, and the node
//     scrape job sets none of its own.
func hostHealthTimingAssumptionViolations(t *testing.T, apply, seed, template string) []string {
	t.Helper()
	var out []string
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(apply), &plays); err != nil {
		t.Fatal(err)
	}
	var renders []string
	nodeBlock := ""
	var walk func(tasks []any)
	walk = func(tasks []any) {
		for _, raw := range tasks {
			task, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			for _, k := range []string{"block", "rescue", "always"} {
				if sub, ok := task[k].([]any); ok {
					walk(sub)
				}
			}
			name, _ := task["name"].(string)
			if copyArgs, ok := task["ansible.builtin.copy"].(map[string]any); ok && strings.HasPrefix(name, "Render prometheus.yml") {
				content, _ := copyArgs["content"].(string)
				renders = append(renders, content)
			}
			if facts, ok := task["ansible.builtin.set_fact"].(map[string]any); ok {
				if v, ok := facts["prometheus_node_exporter_scrape_block"].(string); ok {
					nodeBlock = v
				}
			}
		}
	}
	for _, play := range plays {
		for _, k := range []string{"pre_tasks", "tasks"} {
			if tasks, ok := play[k].([]any); ok {
				walk(tasks)
			}
		}
	}
	if len(renders) != 2 {
		out = append(out, fmt.Sprintf("prometheus-apply.yml: found %d \"Render prometheus.yml\" tasks, want 2", len(renders)))
	}
	evalRe := regexp.MustCompile(`(?m)^\s*evaluation_interval:`)
	scrapeRe := regexp.MustCompile(`(?m)^\s*scrape_interval:\s*(.*?)\s*$`)
	for i, c := range renders {
		if evalRe.MatchString(c) {
			out = append(out, fmt.Sprintf("rendered prometheus.yml #%d sets evaluation_interval; the 9m host_metrics_missing_for cap assumes the 1m default", i+1))
		}
		got := scrapeRe.FindAllStringSubmatch(c, -1)
		if len(got) != 1 || got[0][1] != "{{ prometheus_scrape_interval }}" {
			out = append(out, fmt.Sprintf("rendered prometheus.yml #%d scrape_interval lines = %v; the probe-round gate assumes exactly the global `{{ prometheus_scrape_interval }}`", i+1, got))
		}
	}
	if nodeBlock == "" {
		out = append(out, "prometheus-apply.yml: no set_fact of prometheus_node_exporter_scrape_block")
	} else if strings.Contains(nodeBlock, "scrape_interval") || strings.Contains(nodeBlock, "evaluation_interval") {
		out = append(out, "the node scrape job sets its own scrape_interval; the probe-round gate uses the global prometheus_scrape_interval")
	}
	var seedRules struct {
		Groups []map[string]any `yaml:"groups"`
	}
	if err := yaml.Unmarshal([]byte(seed), &seedRules); err != nil {
		t.Fatal(err)
	}
	for _, g := range seedRules.Groups {
		if _, ok := g["interval"]; ok {
			out = append(out, fmt.Sprintf("seed rule group %v sets interval:; the 9m cap assumes the 1m default", g["name"]))
		}
	}
	// Group keys sit at four spaces in the template (rule keys at eight).
	if m := regexp.MustCompile(`(?m)^    interval:`).FindString(template); m != "" {
		out = append(out, "a host-health rule group sets interval:; the 9m cap assumes the 1m default")
	}
	return out
}

// TestRegression_HostHealthTimingAssumptionsMatchTheRenderedConfig ties the
// timing gates' Prometheus assumptions to the config prometheus-apply.yml
// actually renders (AGENTS.md §5.7, PR #80 review): no evaluation_interval
// and no rule-group interval (the 9m cap assumes the 1m default), and no
// node-job scrape_interval (the probe-round gate's scrape input is the
// global prometheus_scrape_interval). Each assumption is also broken on
// purpose, to show the check catches it (§5.12).
func TestRegression_HostHealthTimingAssumptionsMatchTheRenderedConfig(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	apply, seed, template := read(hostHealthApply), read(alertRulesSeed), read(hostHealthTemplate)
	for _, msg := range hostHealthTimingAssumptionViolations(t, apply, seed, template) {
		t.Error(msg)
	}
	mutate := func(s, old, new string) string {
		t.Helper()
		if !strings.Contains(s, old) {
			t.Fatalf("mutation anchor %q not found", old)
		}
		return strings.ReplaceAll(s, old, new)
	}
	for _, m := range []struct {
		name                  string
		apply, seed, template string
	}{
		{"evaluation_interval in prometheus.yml", mutate(apply,
			"                scrape_interval: {{ prometheus_scrape_interval }}\n",
			"                scrape_interval: {{ prometheus_scrape_interval }}\n                evaluation_interval: 30s\n"), seed, template},
		{"a literal global scrape_interval", mutate(apply,
			"                scrape_interval: {{ prometheus_scrape_interval }}\n",
			"                scrape_interval: 30s\n"), seed, template},
		{"a node-job scrape_interval", mutate(apply,
			"{{ ([{'job_name': 'node',",
			"{{ ([{'job_name': 'node', 'scrape_interval': '30s',"), seed, template},
		{"a seed rule-group interval", apply, mutate(seed,
			"  - name: pilot-seed\n",
			"  - name: pilot-seed\n    interval: 30s\n"), template},
		{"a host-health rule-group interval", apply, seed, mutate(template,
			"  - name: pilot-host-telemetry\n",
			"  - name: pilot-host-telemetry\n    interval: 30s\n")},
	} {
		if got := hostHealthTimingAssumptionViolations(t, m.apply, m.seed, m.template); len(got) == 0 {
			t.Errorf("mutation %q: the check found nothing", m.name)
		} else {
			t.Logf("mutation %q caught: %s", m.name, got[0])
		}
	}
}
