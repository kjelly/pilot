package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// alertmanagerImage must stay the image alertmanager-apply.yml runs.
const alertmanagerImage = "prom/alertmanager:v0.27.0"

// builtinAlertmanagerConfigs returns the null and teams configs exactly as
// alertmanager-apply.yml declares them.
func builtinAlertmanagerConfigs(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("../../playbooks/apply/alertmanager-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		Vars map[string]any `yaml:"vars"`
	}
	if err := yaml.Unmarshal(data, &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) == 0 {
		t.Fatal("alertmanager-apply.yml has no play")
	}
	out := map[string]string{}
	for _, name := range []string{"alertmanager_default_config", "alertmanager_teams_config"} {
		v, ok := plays[0].Vars[name].(string)
		if !ok || v == "" {
			t.Fatalf("play var %s missing", name)
		}
		out[name] = v
	}
	if !strings.Contains(string(data), `alertmanager_version: "`+strings.TrimPrefix(alertmanagerImage, "prom/alertmanager:")+`"`) {
		t.Fatalf("alertmanagerImage %s no longer matches alertmanager-apply.yml", alertmanagerImage)
	}
	return out
}

// requireContainerImage skips the test when docker or image is missing.
// With PILOT_REQUIRE_CONTAINER_TESTS=1 (`make alert-rules-test`, which CI's
// "Playbook lint" job runs) it pulls a missing image instead, and fails
// rather than skips, so these tests can never pass there by skipping.
func requireContainerImage(t *testing.T, image string) {
	t.Helper()
	strict := os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1"
	missing := func(format string, args ...any) {
		t.Helper()
		if strict {
			t.Fatalf(format+" (PILOT_REQUIRE_CONTAINER_TESTS=1)", args...)
		}
		t.Skipf(format, args...)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		missing("docker not installed: %v", err)
	}
	if err := exec.Command("docker", "image", "inspect", image).Run(); err == nil {
		return
	}
	if strict {
		if out, err := exec.Command("docker", "pull", "-q", image).CombinedOutput(); err != nil {
			missing("docker pull %s: %v\n%s", image, err, out)
		}
		return
	}
	missing("%s not present locally (docker pull it, or run make alert-rules-test)", image)
}

// TestRegression_AlertmanagerBuiltinConfigsCarryIssue11Inhibits locks the
// two inhibit rules docs/verification/alertmanager.md §1.7/C10 promise in
// both built-in receiver modes.
func TestRegression_AlertmanagerBuiltinConfigsCarryIssue11Inhibits(t *testing.T) {
	for name, cfg := range builtinAlertmanagerConfigs(t) {
		var doc struct {
			InhibitRules []struct {
				SourceMatchers []string `yaml:"source_matchers"`
				TargetMatchers []string `yaml:"target_matchers"`
				Equal          []string `yaml:"equal"`
			} `yaml:"inhibit_rules"`
			Receivers []map[string]any `yaml:"receivers"`
		}
		if err := yaml.Unmarshal([]byte(cfg), &doc); err != nil {
			t.Fatalf("%s is not YAML: %v", name, err)
		}
		type rule struct{ source, target, equal string }
		want := []rule{
			{`alertname="HostMetricsMissing"`, `alertname="HostDown",job="node"`, "pilot_host"},
			{`alertname="PilotLoginProbeStale"`, `PilotLoginProbe(AccountDenied|AuthFailed|LoginStalled|HostKeyMismatch|SessionFailed|TransportFailed|NoTargets)`, "probe_host"},
		}
		if len(doc.InhibitRules) != len(want) {
			t.Fatalf("%s has %d inhibit rules, want %d", name, len(doc.InhibitRules), len(want))
		}
		for i, w := range want {
			got := doc.InhibitRules[i]
			if strings.Join(got.SourceMatchers, ",") != w.source || !strings.Contains(strings.Join(got.TargetMatchers, ","), w.target) || strings.Join(got.Equal, ",") != w.equal {
				t.Errorf("%s inhibit rule %d = %+v, want source %s target ~%s equal %s", name, i, got, w.source, w.target, w.equal)
			}
		}
		// The agent-controller mirror appends a webhook to the end of the
		// teams config text, so receivers must stay its last block.
		if name == "alertmanager_teams_config" {
			trimmed := strings.TrimRight(cfg, "\n ")
			if !strings.HasSuffix(trimmed, "send_resolved: true") {
				t.Errorf("teams config must still end with the webhook list (agent-controller mirror appends to it); tail: %q", trimmed[max(0, len(trimmed)-80):])
			}
		}
	}
}

// TestRegression_AlertmanagerBuiltinConfigsPassAmtool validates both built-in
// configs with the pinned amtool (skips without docker/the image).
func TestRegression_AlertmanagerBuiltinConfigsPassAmtool(t *testing.T) {
	requireContainerImage(t, alertmanagerImage)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range builtinAlertmanagerConfigs(t) {
		if err := os.WriteFile(filepath.Join(dir, name+".yml"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("docker", "run", "--rm", "-v", dir+":/w:ro", "--entrypoint", "amtool", alertmanagerImage, "check-config", "/w/"+name+".yml").CombinedOutput()
		if err != nil {
			t.Fatalf("amtool check-config %s: %v\n%s", name, err, out)
		}
		if !strings.Contains(string(out), " - 2 inhibit rules") {
			t.Errorf("amtool did not load 2 inhibit rules from %s:\n%s", name, out)
		}
	}
}

// amAlert is one alert as the host-health rules and the seed HostDown rule
// label it (the promtool cases in testdata/host-health-alert-rules.promtest.yml
// lock those labels).
type amAlert map[string]string

// TestRegression_AlertmanagerInhibitBehaviour runs the pinned Alertmanager
// with each built-in config, posts the alerts of the issue #11 scenarios and
// reads back which ones Alertmanager itself suppresses
// (docs/verification/alertmanager.md §1.7):
//
//   - data gap: HostMetricsMissing mutes HostDown{job="node"} of the same
//     host, never a HostDown of another job;
//   - a host that is really down keeps its HostDown;
//   - two probes: a stalled probe mutes only its own alerts (probe_host);
//   - a HostDown of a non-node job mutes nothing.
//
// In teams mode it also checks that the alerts which replace a muted one
// (HostMetricsMissing, PilotLoginProbeStale) reach the teams receiver.
func TestRegression_AlertmanagerInhibitBehaviour(t *testing.T) {
	requireContainerImage(t, alertmanagerImage)
	alerts := map[string]amAlert{
		"gap-metrics":   {"alertname": "HostMetricsMissing", "pilot_host": "gap", "severity": "warning", "action_required": "true", "pilot_alert_source": "host-health"},
		"gap-down":      {"alertname": "HostDown", "instance": "gap:9100", "job": "node", "pilot_host": "gap", "severity": "critical"},
		"gap-dcgm":      {"alertname": "HostDown", "instance": "gap:9400", "job": "dcgm", "pilot_host": "gap", "severity": "critical"},
		"dead-down":     {"alertname": "HostDown", "instance": "dead:9100", "job": "node", "pilot_host": "dead", "severity": "critical"},
		"a-stale":       {"alertname": "PilotLoginProbeStale", "pilot_host": "mon-a", "probe_host": "mon-a", "severity": "warning", "action_required": "true", "pilot_alert_source": "login-probe"},
		"a-denied-t1":   {"alertname": "PilotLoginProbeAccountDenied", "pilot_host": "t1", "probe_host": "mon-a", "severity": "critical", "pilot_alert_source": "login-probe"},
		"b-denied-t2":   {"alertname": "PilotLoginProbeAccountDenied", "pilot_host": "t2", "probe_host": "mon-b", "severity": "critical", "pilot_alert_source": "login-probe"},
		"gpu-dcgm":      {"alertname": "HostDown", "instance": "gpu1:9400", "job": "dcgm", "pilot_host": "gpu1", "severity": "critical"},
		"gpu-transport": {"alertname": "PilotLoginProbeTransportFailed", "pilot_host": "gpu1", "probe_host": "mon-b", "severity": "warning", "pilot_alert_source": "login-probe"},
	}
	wantSuppressed := map[string]bool{"gap-down": true, "a-denied-t1": true}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range builtinAlertmanagerConfigs(t) {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, name+".yml"), []byte(cfg), 0o644); err != nil {
				t.Fatal(err)
			}
			base := startAlertmanager(t, dir, name+".yml")
			var post []map[string]any
			for _, a := range alerts {
				post = append(post, map[string]any{"labels": a})
			}
			body, _ := json.Marshal(post)
			resp, err := http.Post(base+"/api/v2/alerts", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("POST alerts: %s", resp.Status)
			}

			// Alertmanager computes inhibition asynchronously; poll until
			// every posted alert is listed with the expected state.
			var got map[string]string
			deadline := time.Now().Add(30 * time.Second)
			for {
				got = alertmanagerStates(t, base, alerts)
				ok := len(got) == len(alerts)
				for key := range alerts {
					want := "active"
					if wantSuppressed[key] {
						want = "suppressed"
					}
					ok = ok && got[key] == want
				}
				if ok || time.Now().After(deadline) {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			for key := range alerts {
				want := "active"
				if wantSuppressed[key] {
					want = "suppressed"
				}
				if got[key] != want {
					t.Errorf("%s %v: state %q, want %q", key, alerts[key], got[key], want)
				}
			}

			if name != "alertmanager_teams_config" {
				return
			}
			for _, key := range []string{"gap-metrics", "a-stale", "dead-down", "b-denied-t2"} {
				if r := amtoolRoute(t, dir, name+".yml", alerts[key]); r != "teams" {
					t.Errorf("teams mode routes %s %v to %q, want teams", key, alerts[key], r)
				}
			}
			if r := amtoolRoute(t, dir, name+".yml", amAlert{"alertname": "HostIOStall", "pilot_host": "x", "severity": "warning"}); r != "null" {
				t.Errorf("teams mode routes a plain warning to %q, want null", r)
			}
		})
	}
}

// startAlertmanager runs the pinned image with dir/config on a random local
// port and returns its base URL once it is ready.
func startAlertmanager(t *testing.T, dir, config string) string {
	t.Helper()
	out, err := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::9093", "-v", dir+":/w:ro",
		alertmanagerImage, "--config.file=/w/"+config, "--storage.path=/tmp/am").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run alertmanager: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	port, err := exec.Command("docker", "port", id, "9093/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(port), "\n")[0])
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(base + "/-/ready")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Fatalf("alertmanager not ready: %v\n%s", err, logs)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// alertmanagerStates maps each posted alert key to the state
// /api/v2/alerts reports for it.
func alertmanagerStates(t *testing.T, base string, alerts map[string]amAlert) map[string]string {
	t.Helper()
	resp, err := http.Get(base + "/api/v2/alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var listed []struct {
		Labels map[string]string `json:"labels"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for key, a := range alerts {
		for _, l := range listed {
			if fmt.Sprint(l.Labels) == fmt.Sprint(map[string]string(a)) {
				out[key] = l.Status.State
			}
		}
	}
	return out
}

// amtoolRoute returns the receiver `amtool config routes test` picks for a.
func amtoolRoute(t *testing.T, dir, config string, a amAlert) string {
	t.Helper()
	args := []string{"run", "--rm", "-v", dir + ":/w:ro", "--entrypoint", "amtool", alertmanagerImage, "config", "routes", "test", "--config.file=/w/" + config}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k+"="+a[k])
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("amtool config routes test: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
