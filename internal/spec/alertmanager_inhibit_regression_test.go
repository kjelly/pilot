package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
			{`alertname="HostDown"`, `PilotLoginProbeTransportFailed|HostMetricsMissing`, "pilot_host"},
			{`alertname="PilotLoginProbeStale"`, `PilotLoginProbe(AccountDenied|AuthFailed|LoginStalled|HostKeyMismatch|SessionFailed|TransportFailed|NoTargets)`, "site"},
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
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	if err := exec.Command("docker", "image", "inspect", alertmanagerImage).Run(); err != nil {
		t.Skipf("%s not present locally: %v", alertmanagerImage, err)
	}
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
