package spec

// Render harness for host annotations → Prometheus target labels
// (docs/superpowers/specs/2026-09-23-host-annotations-prometheus-labels-spec.md
// §20, cases V1–V14). The label builder and its validation gates are
// Jinja/Ansible logic, so a Go string check cannot prove their behaviour:
// every case here runs the REAL prometheus-apply.yml pre_tasks against a
// localhost fixture inventory (`--check --tags always`, JSON callback) and
// asserts on the rendered node/dcgm scrape blocks the play actually
// computed. Skipped when ansible-playbook is not on PATH (the CI go-test
// job has no Ansible; the playbook-lint job does).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const hostMetadataFixtureInventory = `all:
  children:
    prometheus:
      hosts:
        meta-prom: {ansible_connection: local, ansible_host: 127.0.0.1}
    host-monitoring:
      hosts:
        gpu-a01:
          ansible_host: 10.20.30.41
          pilot_annotations:
            location: "DC1/Rack A-03/U18"
            project: llm-training
            owner: ai-platform
            note: temp
        cpu-b02:
          ansible_host: 10.20.30.42
          pilot_annotations:
            project: llm-training
        raw-c03:
          ansible_host: 10.20.30.43
          pilot_annotations:
            project: 12
            owner: ""
    dcgm-exporter:
      hosts:
        gpu-a01: {}
`

type hostMetadataStaticConfig struct {
	Targets []string          `yaml:"targets"`
	Labels  map[string]string `yaml:"labels"`
}

type hostMetadataJob struct {
	JobName       string                     `yaml:"job_name"`
	StaticConfigs []hostMetadataStaticConfig `yaml:"static_configs"`
}

type hostMetadataRender struct {
	rc       int
	failures []string          // "<task name>: <msg>" of every failed task
	node     []hostMetadataJob // parsed prometheus_node_exporter_scrape_block
	dcgm     []hostMetadataJob // parsed prometheus_dcgm_exporter_scrape_block
	raw      string            // full JSON callback output, for failure messages
	nodeText string            // raw rendered node block, for byte-stability checks
}

// runHostMetadataRender runs prometheus-apply.yml's always-tagged
// pre_tasks against the fixture inventory with extraVars (a JSON object
// string) layered on top, and returns what the play rendered.
func runHostMetadataRender(t *testing.T, extraVars string, tags string) hostMetadataRender {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	playbook, err := filepath.Abs("../../playbooks/apply/prometheus-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(inv, []byte(hostMetadataFixtureInventory), 0o644); err != nil {
		t.Fatal(err)
	}
	if tags == "" {
		tags = "always"
	}
	args := []string{
		"-i", inv, playbook, "--check", "--tags", tags,
		"-e", "ansible_become=false",
		"-e", "prometheus_site_label=t",
		"-e", "thanos_aws_access_key_id=x",
		"-e", "thanos_aws_secret_access_key=y",
		"-e", "thanos_s3_target_host=192.0.2.1",
		"-e", "node_exporter_basic_auth_password=p",
		"-e", "dcgm_exporter_basic_auth_password=p",
	}
	if extraVars != "" {
		args = append(args, "-e", extraVars)
	}
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1")
	cmd.Stdin = nil
	out, runErr := cmd.Output()
	res := hostMetadataRender{raw: string(out)}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}

	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed bool           `json:"failed"`
					Msg    any            `json:"msg"`
					Facts  map[string]any `json:"ansible_facts"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				if h.Failed {
					msg, _ := json.Marshal(h.Msg)
					res.failures = append(res.failures, task.Task.Name+": "+string(msg))
				}
				if v, ok := h.Facts["prometheus_node_exporter_scrape_block"].(string); ok {
					res.nodeText = v
					res.node = parseHostMetadataJobs(t, v)
				}
				if v, ok := h.Facts["prometheus_dcgm_exporter_scrape_block"].(string); ok {
					res.dcgm = parseHostMetadataJobs(t, v)
				}
			}
		}
	}
	return res
}

func parseHostMetadataJobs(t *testing.T, block string) []hostMetadataJob {
	t.Helper()
	var jobs []hostMetadataJob
	if strings.TrimSpace(block) == "" {
		return nil
	}
	if err := yaml.Unmarshal([]byte(block), &jobs); err != nil {
		t.Fatalf("rendered scrape block is not valid YAML: %v\n%s", err, block)
	}
	return jobs
}

// labelsFor returns the labels of the single static_configs entry whose
// pilot_host is host.
func labelsFor(t *testing.T, jobs []hostMetadataJob, host string) map[string]string {
	t.Helper()
	if len(jobs) != 1 {
		t.Fatalf("expected exactly one job, got %d", len(jobs))
	}
	for _, sc := range jobs[0].StaticConfigs {
		if sc.Labels["pilot_host"] == host {
			return sc.Labels
		}
	}
	t.Fatalf("no static_configs entry for pilot_host=%s in job %s", host, jobs[0].JobName)
	return nil
}

func assertLabels(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("labels = %v, want exactly %v", got, want)
		return
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("labels[%s] = %q, want %q (full: %v)", k, got[k], v, got)
		}
	}
}

const hostMetadataStandardMapping = `{"prometheus_host_annotation_labels": {"project": "pilot_project", "location": "pilot_location", "owner": "pilot_owner"}}`

// V1 / V11-compat: unset and {} both keep the pre-feature render (only pilot_host).
func TestHostMetadataRender_EmptyMappingIsNoOp(t *testing.T) {
	t.Parallel()
	for _, ev := range []string{"", `{"prometheus_host_annotation_labels": {}}`} {
		r := runHostMetadataRender(t, ev, "")
		if r.rc != 0 {
			t.Fatalf("extra vars %q: rc=%d failures=%v", ev, r.rc, r.failures)
		}
		for _, h := range []string{"gpu-a01", "cpu-b02", "raw-c03"} {
			assertLabels(t, labelsFor(t, r.node, h), map[string]string{"pilot_host": h})
		}
		assertLabels(t, labelsFor(t, r.dcgm, "gpu-a01"), map[string]string{"pilot_host": "gpu-a01"})
	}
}

// V2 / V3 / V10 / V12 / V13: selected annotations only, missing/empty
// omitted, values verbatim and stringified, node and dcgm identical.
func TestHostMetadataRender_SelectedAnnotations(t *testing.T) {
	t.Parallel()
	r := runHostMetadataRender(t, hostMetadataStandardMapping, "")
	if r.rc != 0 {
		t.Fatalf("rc=%d failures=%v", r.rc, r.failures)
	}
	gpu := map[string]string{
		"pilot_host":     "gpu-a01",
		"pilot_location": "DC1/Rack A-03/U18", // V12: spaces/slashes kept verbatim
		"pilot_owner":    "ai-platform",
		"pilot_project":  "llm-training",
	}
	assertLabels(t, labelsFor(t, r.node, "gpu-a01"), gpu) // V2: no pilot_note
	// V3: cpu-b02 has no location/owner → those labels absent, not "".
	assertLabels(t, labelsFor(t, r.node, "cpu-b02"), map[string]string{"pilot_host": "cpu-b02", "pilot_project": "llm-training"})
	// V13: raw inventory int is stringified; empty string is treated as missing.
	assertLabels(t, labelsFor(t, r.node, "raw-c03"), map[string]string{"pilot_host": "raw-c03", "pilot_project": "12"})
	// V10: dcgm carries exactly the same labels as node for the same host.
	assertLabels(t, labelsFor(t, r.dcgm, "gpu-a01"), gpu)
	if strings.Contains(r.raw, "pilot_note") {
		t.Errorf("unmapped annotation leaked as pilot_note")
	}
	// Targets unchanged by the feature (I12).
	for _, sc := range r.node[0].StaticConfigs {
		if sc.Labels["pilot_host"] == "gpu-a01" && (len(sc.Targets) != 1 || sc.Targets[0] != "10.20.30.41:9100") {
			t.Errorf("gpu-a01 node targets = %v", sc.Targets)
		}
	}
}

// V11: mapping key order does not change the rendered bytes.
func TestHostMetadataRender_DeterministicOrder(t *testing.T) {
	t.Parallel()
	a := runHostMetadataRender(t, `{"prometheus_host_annotation_labels": {"project": "pilot_project", "location": "pilot_location", "owner": "pilot_owner"}}`, "")
	b := runHostMetadataRender(t, `{"prometheus_host_annotation_labels": {"owner": "pilot_owner", "location": "pilot_location", "project": "pilot_project"}}`, "")
	if a.rc != 0 || b.rc != 0 {
		t.Fatalf("rc a=%d b=%d", a.rc, b.rc)
	}
	if a.nodeText == "" || a.nodeText != b.nodeText {
		t.Errorf("node block not byte-stable across mapping key order:\n--- a\n%s\n--- b\n%s", a.nodeText, b.nodeText)
	}
}

// V9: explicit node_exporter_targets override stays flat/unlabeled.
func TestHostMetadataRender_ExplicitOverrideNotGuessed(t *testing.T) {
	t.Parallel()
	r := runHostMetadataRender(t, `{"node_exporter_targets": ["10.20.30.41:9100"], "prometheus_host_annotation_labels": {"project": "pilot_project"}}`, "")
	if r.rc != 0 {
		t.Fatalf("rc=%d failures=%v", r.rc, r.failures)
	}
	if len(r.node) != 1 || len(r.node[0].StaticConfigs) != 1 {
		t.Fatalf("expected one flat static_configs entry, got %+v", r.node)
	}
	if sc := r.node[0].StaticConfigs[0]; len(sc.Labels) != 0 {
		t.Errorf("explicit override must stay unlabeled (no pilot_host, no metadata), got labels %v", sc.Labels)
	}
}

// V14: a tag-scoped apply (AGENTS.md §4.4) still renders promoted labels.
func TestHostMetadataRender_TagScopedApply(t *testing.T) {
	t.Parallel()
	r := runHostMetadataRender(t, hostMetadataStandardMapping, "C13")
	if r.rc != 0 {
		t.Fatalf("rc=%d failures=%v", r.rc, r.failures)
	}
	if got := labelsFor(t, r.node, "gpu-a01")["pilot_project"]; got != "llm-training" {
		t.Errorf("--tags C13: pilot_project = %q, want llm-training", got)
	}
}

// V4–V8 + §7.1/§7.2: invalid mappings fail closed in pre_tasks, naming the
// offending key/label and never an annotation value.
func TestHostMetadataRender_InvalidMappingsFailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, mapping, wantInMsg string
	}{
		{"not a mapping", `["project"]`, "must be a mapping"},
		{"secret-like source", `{"token": "pilot_token"}`, "secret-like source keys: ['token']"},
		{"dotted secret-like source", `{"service.api_key": "pilot_service_api_key"}`, "secret-like source keys: ['service.api_key']"},
		{"invalid source key", `{"Bad": "pilot_bad"}`, "source keys not matching ^[a-z][a-z0-9_.-]{0,62}$: ['Bad']"},
		{"invalid destination", `{"project": "project-name"}`, "destination labels not matching ^pilot_[a-z][a-z0-9_]*$: ['project-name']"},
		{"no pilot namespace", `{"project": "project"}`, "destination labels not matching ^pilot_[a-z][a-z0-9_]*$: ['project']"},
		{"dunder destination", `{"project": "__meta_x"}`, "destination labels not matching ^pilot_[a-z][a-z0-9_]*$: ['__meta_x']"},
		{"reserved identity", `{"project": "pilot_host"}`, "reserved destination labels: ['pilot_host']"},
		{"reserved external-target label", `{"project": "pilot_target"}`, "reserved destination labels: ['pilot_target']"},
		{"duplicate destination", `{"project": "pilot_group", "owner": "pilot_group"}`, "duplicate destination labels: ['pilot_group']"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := runHostMetadataRender(t, `{"prometheus_host_annotation_labels": `+tc.mapping+`}`, "")
			if r.rc == 0 {
				t.Fatalf("expected a non-zero exit for mapping %s", tc.mapping)
			}
			joined := strings.Join(r.failures, "\n")
			if !strings.Contains(joined, tc.wantInMsg) {
				t.Errorf("failure message missing %q; got:\n%s", tc.wantInMsg, joined)
			}
			for _, v := range []string{"llm-training", "ai-platform", "Rack A-03"} {
				if strings.Contains(joined, v) {
					t.Errorf("failure message leaked annotation value %q:\n%s", v, joined)
				}
			}
			if r.node != nil {
				t.Errorf("scrape block must not be rendered when validation fails")
			}
		})
	}
}
