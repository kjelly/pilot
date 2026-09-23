package spec

// Static regression locks for host annotations → Prometheus target labels
// (docs/superpowers/specs/2026-09-23-host-annotations-prometheus-labels-spec.md
// §19). Behaviour is proven by prometheus_host_metadata_render_test.go
// (real ansible-playbook); these locks catch structural drift even where
// Ansible is not installed (the CI go-test job).

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func readPrometheusApply(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/prometheus-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// §6.1: the mapping must NOT be declared in play-level vars (it would
// shadow group_vars/host_vars), and every use must default to {}.
func TestRegression_HostMetadata_MappingNotDeclaredInPlayVars(t *testing.T) {
	pb := readPrometheusApply(t)
	if regexp.MustCompile(`(?m)^    prometheus_host_annotation_labels:`).MatchString(pb) {
		t.Error("prometheus_host_annotation_labels must not be declared in play-level vars: (spec §6.1)")
	}
	for _, m := range regexp.MustCompile(`prometheus_host_annotation_labels[^\n]*`).FindAllString(pb, -1) {
		if strings.Contains(m, "{{") || strings.HasPrefix(strings.TrimSpace(m), "prometheus_host_annotation_labels |") {
			if !strings.Contains(m, "default({}, true)") {
				t.Errorf("every templated use must be `| default({}, true)`; got %q", m)
			}
		}
	}
}

// §8.1 / I6: one shared builder; both node and dcgm loops read it, and
// neither still hardcodes the pre-feature {'pilot_host': item} labels.
func TestRegression_HostMetadata_SharedLabelBuilder(t *testing.T) {
	pb := readPrometheusApply(t)
	if n := strings.Count(pb, "_pilot_prometheus_host_labels: >-"); n != 1 {
		t.Errorf("expected exactly one label-builder set_fact, found %d", n)
	}
	if n := strings.Count(pb, "'labels': _pilot_prometheus_host_labels[item]"); n != 2 {
		t.Errorf("node AND dcgm auto-discovery must both read _pilot_prometheus_host_labels[item]; found %d uses", n)
	}
	if strings.Contains(pb, "'labels': {'pilot_host': item}") {
		t.Error("a scrape loop still hardcodes {'pilot_host': item}, bypassing the shared builder")
	}
	if n := strings.Count(pb, "map('extract', _ann)"); n != 1 {
		t.Errorf("annotation → label expression must appear exactly once (no copy per exporter); found %d", n)
	}
	// The builder loops over the union of both groups, so a dcgm-only
	// host still gets its labels.
	if !strings.Contains(pb, "(groups.get('host-monitoring', []) + groups.get('dcgm-exporter', [])) | unique | sort") {
		t.Error("label builder must loop over host-monitoring ∪ dcgm-exporter, sorted")
	}
}

// §16.1 / AGENTS.md §4.4: every host-metadata task is always-tagged and
// the builder precedes both scrape loops.
func TestRegression_HostMetadata_TasksAlwaysTaggedAndOrdered(t *testing.T) {
	pb := readPrometheusApply(t)
	names := []string{
		"Gate: prometheus_host_annotation_labels must be a mapping",
		"Resolve host-annotation label mapping, sorted by source key",
		"Gate: host-annotation label mapping is valid",
		"Reset per-host managed target labels",
		"Build managed-host target labels: pilot_host + allowlisted annotations",
	}
	tasks := splitPlaybookTasks(pb)
	prev := -1
	for _, n := range names {
		idx := -1
		for i, body := range tasks {
			if strings.Contains(body, n) {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Errorf("task %q not found", n)
			continue
		}
		if !strings.Contains(tasks[idx], "tags: [always]") {
			t.Errorf("task %q must be tags: [always] (prerequisite of always-tagged scrape blocks)", n)
		}
		if idx < prev {
			t.Errorf("task %q is out of order", n)
		}
		prev = idx
	}
	builder := strings.Index(pb, "Build managed-host target labels")
	if i := strings.Index(pb, "'labels': _pilot_prometheus_host_labels[item]"); i >= 0 && i < builder {
		t.Error("a scrape loop reads _pilot_prometheus_host_labels before the builder runs")
	}
}

// §7.3–§7.6: the gates exist with the exact contract patterns.
func TestRegression_HostMetadata_ValidationGates(t *testing.T) {
	pb := readPrometheusApply(t)
	for _, want := range []string{
		`reject('match', '^[a-z][a-z0-9_.-]{0,62}$')`,
		`select('search', '(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|vault|credential)')`,
		`reject('match', '^pilot_[a-z][a-z0-9_]*$')`,
		`select('in', _pilot_prometheus_reserved_target_labels)`,
		`groupby('value') | selectattr('1.1', 'defined')`,
	} {
		if !strings.Contains(pb, want) {
			t.Errorf("validation gate missing %q", want)
		}
	}
	// The secret pattern must stay equal to the canonical one in
	// internal/inventory/secret.go (spec §7.3).
	secretGo, err := os.ReadFile("../../internal/inventory/secret.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(secretGo), "(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|vault|credential)") {
		t.Error("internal/inventory/secret.go pattern changed — update the prometheus-apply.yml gate to match")
	}
	// Reserved list declared once, and includes the canonical identity labels.
	if n := strings.Count(pb, "_pilot_prometheus_reserved_target_labels:"); n != 1 {
		t.Errorf("reserved-label list must be declared exactly once, found %d", n)
	}
	for _, l := range []string{"pilot_host", "pilot_target", "pilot_source", "pilot_protocol", "pilot_subject", "pilot_subject_kind"} {
		if !regexp.MustCompile(`(?m)^      - ` + l + `$`).MatchString(pb) {
			t.Errorf("reserved-label list missing %s", l)
		}
	}
}

// §9.1 / §10: explicit overrides stay flat/unlabeled.
func TestRegression_HostMetadata_ExplicitOverridePreserved(t *testing.T) {
	pb := readPrometheusApply(t)
	for _, want := range []string{
		"[{'targets': prometheus_node_exporter_targets}]",
		"[{'targets': prometheus_dcgm_exporter_targets}]",
	} {
		if !strings.Contains(pb, want) {
			t.Errorf("explicit override path %q is gone", want)
		}
	}
}

// splitPlaybookTasks splits a playbook into chunks starting at each
// 4-space-indented `- name:` line (pre_tasks/tasks list items).
func splitPlaybookTasks(pb string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(pb, "\n") {
		if strings.HasPrefix(line, "    - name:") && cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteString(line)
		cur.WriteString("\n")
	}
	out = append(out, cur.String())
	return out
}
