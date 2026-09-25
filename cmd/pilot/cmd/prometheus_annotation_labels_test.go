package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The Go-side validation must stay identical to prometheus-apply.yml's
// gates, or pilot edit would write mappings the apply rejects (or accept
// ones it should not). Lock the reserved list and both patterns against
// the playbook source itself.
func TestPrometheusAnnotationLabels_ParityWithPlaybookGates(t *testing.T) {
	raw, err := os.ReadFile("../../../playbooks/apply/prometheus-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		Vars map[string]any `yaml:"vars"`
	}
	if err := yaml.Unmarshal(raw, &plays); err != nil || len(plays) == 0 {
		t.Fatalf("parse playbook: %v", err)
	}
	list, _ := plays[0].Vars["_pilot_prometheus_reserved_target_labels"].([]any)
	var got []string
	for _, v := range list {
		got = append(got, v.(string))
	}
	if strings.Join(got, ",") != strings.Join(prometheusReservedTargetLabels, ",") {
		t.Errorf("reserved labels drifted:\n playbook %v\n go       %v", got, prometheusReservedTargetLabels)
	}
	pb := string(raw)
	if !strings.Contains(pb, "reject('match', '"+prometheusAnnotationLabelNamePattern.String()+"')") {
		t.Errorf("destination pattern %q not the one the playbook gate uses", prometheusAnnotationLabelNamePattern)
	}
	if !strings.Contains(pb, "reject('match', '^[a-z][a-z0-9_.-]{0,62}$')") {
		t.Error("playbook source-key pattern changed — re-check inventory.ValidateAnnotationKey parity")
	}
}

func TestValidatePrometheusAnnotationLabels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		m       map[string]string
		wantErr string
	}{
		{"ok", map[string]string{"project": "pilot_project", "hw.pool": "pilot_hw_pool"}, ""},
		{"empty", map[string]string{}, ""},
		{"secret-like source", map[string]string{"service.api_key": "pilot_x"}, "secret"},
		{"bad source", map[string]string{"Project": "pilot_project"}, "invalid"},
		{"no namespace", map[string]string{"project": "project"}, "pilot_"},
		{"dash in label", map[string]string{"project": "pilot-project"}, "pilot_"},
		{"dunder", map[string]string{"project": "__meta"}, "pilot_"},
		{"reserved", map[string]string{"project": "pilot_host"}, "reserved"},
		{"duplicate", map[string]string{"project": "pilot_group", "owner": "pilot_group"}, "used by both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePrometheusAnnotationLabels(tc.m)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	if got := defaultPrometheusAnnotationLabel("hw.pool-a"); got != "pilot_hw_pool_a" {
		t.Errorf("default label = %q", got)
	}
}

// Save must touch only the mapping's own block: the real example file
// (comments, commented example of this very key, other settings) must
// survive byte-for-byte, and removing the mapping restores the original.
func TestSavePrometheusAnnotationLabels_PreservesFileAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	example, err := os.ReadFile("../../../group_vars/prometheus.example.yml")
	if err != nil {
		t.Fatal(err)
	}
	orig := strings.Replace(string(example), `prometheus_site_label: ""`, `prometheus_site_label: "site-a"`, 1)
	path := filepath.Join(dir, prometheusAnnotationLabelsRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	if m, err := loadPrometheusAnnotationLabels(dir); err != nil || len(m) != 0 {
		t.Fatalf("commented example must load as empty mapping, got %v, %v", m, err)
	}
	want := map[string]string{"project": "pilot_project", "location": "pilot_location"}
	if err := savePrometheusAnnotationLabels(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadPrometheusAnnotationLabels(dir)
	if err != nil || len(got) != 2 || got["project"] != "pilot_project" || got["location"] != "pilot_location" {
		t.Fatalf("round-trip = %v, %v", got, err)
	}
	written, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(written), strings.TrimRight(orig, "\n")) {
		t.Error("existing content was modified; only an appended block is allowed")
	}
	if !strings.Contains(string(written), "prometheus_host_annotation_labels:\n  location: pilot_location\n  project: pilot_project\n") {
		t.Errorf("mapping not rendered sorted as a block:\n%s", written)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(written, &parsed); err != nil || parsed["prometheus_site_label"] != "site-a" {
		t.Fatalf("file no longer valid YAML / lost other settings: %v", err)
	}

	// Replace in place (not a second copy).
	if err := savePrometheusAnnotationLabels(dir, map[string]string{"owner": "pilot_owner"}); err != nil {
		t.Fatal(err)
	}
	written, _ = os.ReadFile(path)
	if n := len(regexp.MustCompile(`(?m)^prometheus_host_annotation_labels:`).FindAll(written, -1)); n != 1 {
		t.Fatalf("expected exactly one active mapping block, found %d:\n%s", n, written)
	}
	if regexp.MustCompile(`(?m)^  project: pilot_project$`).Match(written) {
		t.Error("old mapping lines left behind")
	}

	// Empty mapping removes the block entirely.
	if err := savePrometheusAnnotationLabels(dir, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	written, _ = os.ReadFile(path)
	if strings.TrimRight(string(written), "\n") != strings.TrimRight(orig, "\n") {
		t.Errorf("clearing the mapping did not restore the original file")
	}
}

func TestSavePrometheusAnnotationLabels_RejectsInvalidAndNonMapping(t *testing.T) {
	dir := t.TempDir()
	if err := savePrometheusAnnotationLabels(dir, map[string]string{"project": "pilot_host"}); err == nil {
		t.Fatal("reserved label must be rejected before writing")
	}
	if _, err := os.Stat(filepath.Join(dir, prometheusAnnotationLabelsRelPath)); !os.IsNotExist(err) {
		t.Fatal("nothing may be written for an invalid mapping")
	}
	path := filepath.Join(dir, prometheusAnnotationLabelsRelPath)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte("prometheus_host_annotation_labels: [project]\n"), 0o644)
	if _, err := loadPrometheusAnnotationLabels(dir); err == nil {
		t.Fatal("a non-mapping value must be reported, not silently overwritten")
	}
}

// Drive the real router through the semantic actions: add via the
// hosts.yml pick-list, add via manual entry, rename, delete.
func TestAutomationDriver_PrometheusAnnotationLabels(t *testing.T) {
	dir := t.TempDir()
	hosts := "hosts:\n  web-1:\n    ansible_host: \"10.0.0.1\"\n    roles: [host-monitoring]\n    annotations:\n      project: \"alpha\"\n      location: \"DC1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hosts), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(steps ...editAction) error {
		r := newEditRouterModel(dir)
		d := automationDriver{}
		return d.run(&r, editScenario{Version: 1, Steps: steps})
	}
	if err := run(
		editAction{Action: "set_prometheus_annotation_label", Key: "project", Value: "pilot_project"},
		editAction{Action: "set_prometheus_annotation_label", Key: "owner", Value: "pilot_owner"},
		editAction{Action: "set_prometheus_annotation_label", Key: "project", Value: "pilot_team_project"},
	); err != nil {
		t.Fatalf("set scenario: %v", err)
	}
	m, err := loadPrometheusAnnotationLabels(dir)
	if err != nil || len(m) != 2 || m["project"] != "pilot_team_project" || m["owner"] != "pilot_owner" {
		t.Fatalf("after set: %v, %v", m, err)
	}
	if err := run(editAction{Action: "delete_prometheus_annotation_label", Key: "owner"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if m, _ = loadPrometheusAnnotationLabels(dir); len(m) != 1 || m["project"] != "pilot_team_project" {
		t.Fatalf("after delete: %v", m)
	}
	// Duplicate destination is caught by the input's validation at run time.
	if err := run(editAction{Action: "set_prometheus_annotation_label", Key: "location", Value: "pilot_team_project"}); err == nil {
		t.Fatal("duplicate label must fail")
	}
	if m, _ = loadPrometheusAnnotationLabels(dir); len(m) != 1 {
		t.Fatalf("failed action must not write: %v", m)
	}
	if err := run(editAction{Action: "delete_prometheus_annotation_label", Key: "nope"}); err == nil {
		t.Fatal("deleting a missing mapping must fail")
	}
}

func TestSemanticValidate_PrometheusAnnotationLabelRejectsReserved(t *testing.T) {
	for _, def := range editActionRegistry() {
		if def.Spec.Name != "set_prometheus_annotation_label" {
			continue
		}
		if err := def.Validate(editAction{Action: def.Spec.Name, Key: "project", Value: "pilot_host"}); err == nil {
			t.Fatal("reserved label must be rejected at scenario validation")
		}
		if err := def.Validate(editAction{Action: def.Spec.Name, Key: "project", Value: "pilot_project"}); err != nil {
			t.Fatalf("valid step rejected: %v", err)
		}
		return
	}
	t.Fatal("set_prometheus_annotation_label not registered")
}
