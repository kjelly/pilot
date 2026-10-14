package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

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
					t.Errorf("%s must project probe_target onto pilot_host (inhibit rules and dashboards key on it)", r.Alert)
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
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	if err := exec.Command("docker", "image", "inspect", hostHealthPromImage).Run(); err != nil {
		t.Skipf("%s not present locally (docker pull it to run promtool): %v", hostHealthPromImage, err)
	}
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
	// labels and timing, so they run against an annotation-free copy.
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, g := range doc["groups"].([]any) {
		for _, r := range g.(map[string]any)["rules"].([]any) {
			delete(r.(map[string]any), "annotations")
		}
	}
	stripped, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	testDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(testDir, "host-health-alert-rules.yml"), stripped, 0o644); err != nil {
		t.Fatal(err)
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
	for _, name := range hostHealthRuleNames {
		if !strings.Contains(string(unit), "alertname: "+name+"\n") {
			t.Errorf("promtest has no case for %s", name)
		}
	}
}
