package cmd

// Workspace-side editing of prometheus_host_annotation_labels — the
// allowlist that promotes hosts.yml annotations to node/DCGM target labels
// (docs/superpowers/specs/2026-09-23-host-annotations-prometheus-labels-spec.md).
// The playbook's pre_tasks gates stay the authority at apply time; the
// validation here mirrors them one-for-one so `pilot edit` never writes a
// mapping the apply would reject (locked by
// prometheus_annotation_labels_test.go against the playbook source).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/inventory"
)

const (
	prometheusAnnotationLabelsKey     = "prometheus_host_annotation_labels"
	prometheusAnnotationLabelsRelPath = "group_vars/prometheus.yml"
)

// prometheusReservedTargetLabels mirrors prometheus-apply.yml's
// _pilot_prometheus_reserved_target_labels (spec §7.5).
var prometheusReservedTargetLabels = []string{
	"pilot_host",
	"pilot_target",
	"pilot_source",
	"pilot_protocol",
	"pilot_subject",
	"pilot_subject_kind",
}

var prometheusAnnotationLabelNamePattern = regexp.MustCompile(`^pilot_[a-z][a-z0-9_]*$`)

// validatePrometheusAnnotationLabel checks one source→label pair against
// the same rules as the playbook gates (spec §7.2–§7.5).
func validatePrometheusAnnotationLabel(source, label string) error {
	if err := inventory.ValidateAnnotationKey(source); err != nil {
		return err
	}
	if !prometheusAnnotationLabelNamePattern.MatchString(label) {
		return fmt.Errorf("label %q is invalid: must match ^pilot_[a-z][a-z0-9_]*$", label)
	}
	for _, r := range prometheusReservedTargetLabels {
		if label == r {
			return fmt.Errorf("label %q is reserved (canonical identity / monitoring label)", label)
		}
	}
	return nil
}

// validatePrometheusAnnotationLabels validates every pair plus the
// duplicate-destination rule (spec §7.6).
func validatePrometheusAnnotationLabels(m map[string]string) error {
	byLabel := map[string]string{}
	for _, src := range sortedKeysOf(m) {
		if err := validatePrometheusAnnotationLabel(src, m[src]); err != nil {
			return err
		}
		if other, dup := byLabel[m[src]]; dup {
			return fmt.Errorf("label %q is used by both %q and %q", m[src], other, src)
		}
		byLabel[m[src]] = src
	}
	return nil
}

// defaultPrometheusAnnotationLabel suggests a label name for an annotation
// key: pilot_ + the key with '.'/'-' turned into '_'.
func defaultPrometheusAnnotationLabel(source string) string {
	return "pilot_" + strings.NewReplacer(".", "_", "-", "_").Replace(source)
}

// loadPrometheusAnnotationLabels reads the mapping from
// group_vars/prometheus.yml. A missing file or key is an empty mapping; a
// key holding anything but a string→string mapping is an error so the
// editor never silently overwrites something it does not understand.
func loadPrometheusAnnotationLabels(dir string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, prometheusAnnotationLabelsRelPath))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", prometheusAnnotationLabelsRelPath, err)
	}
	node, ok := doc[prometheusAnnotationLabelsKey]
	if !ok || (node.Kind == yaml.ScalarNode && node.Tag == "!!null") {
		return map[string]string{}, nil
	}
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s in %s is not a mapping", prometheusAnnotationLabelsKey, prometheusAnnotationLabelsRelPath)
	}
	out := map[string]string{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s in %s must map annotation keys to label names", prometheusAnnotationLabelsKey, prometheusAnnotationLabelsRelPath)
		}
		out[k.Value] = v.Value
	}
	return out, nil
}

// savePrometheusAnnotationLabels validates m and writes it to
// group_vars/prometheus.yml, replacing only the key's own top-level block
// (every other byte — comments, other settings — is preserved). An empty
// mapping removes the key, i.e. the feature's default no-op.
func savePrometheusAnnotationLabels(dir string, m map[string]string) error {
	if err := validatePrometheusAnnotationLabels(m); err != nil {
		return err
	}
	path := filepath.Join(dir, prometheusAnnotationLabelsRelPath)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		data = []byte("---\n")
	}
	out := replaceTopLevelYAMLBlock(string(data), prometheusAnnotationLabelsKey, renderPrometheusAnnotationLabels(m))
	var check map[string]any
	if err := yaml.Unmarshal([]byte(out), &check); err != nil {
		return fmt.Errorf("refusing to write %s: result would not be valid YAML: %w", prometheusAnnotationLabelsRelPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o644)
}

func renderPrometheusAnnotationLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(prometheusAnnotationLabelsKey + ":\n")
	for _, k := range sortedKeysOf(m) {
		fmt.Fprintf(&sb, "  %s: %s\n", k, m[k])
	}
	return sb.String()
}

// replaceTopLevelYAMLBlock replaces the active top-level `key:` line and
// its indented continuation lines with block (empty block = delete). When
// the key is absent, block is appended. Commented-out examples of the key
// (`# key:`) are left untouched.
func replaceTopLevelYAMLBlock(content, key, block string) string {
	lines := strings.Split(content, "\n")
	head := regexp.MustCompile(`^` + regexp.QuoteMeta(key) + `\s*:`)
	start := -1
	for i, l := range lines {
		if head.MatchString(l) {
			start = i
			break
		}
	}
	if start < 0 {
		if block == "" {
			return content
		}
		trimmed := strings.TrimRight(content, "\n")
		return trimmed + "\n\n" + block
	}
	end := start + 1
	for end < len(lines) && (strings.HasPrefix(lines[end], " ") || strings.HasPrefix(lines[end], "\t")) {
		end++
	}
	var repl []string
	if block != "" {
		repl = strings.Split(strings.TrimRight(block, "\n"), "\n")
	}
	outLines := append(append(append([]string{}, lines[:start]...), repl...), lines[end:]...)
	return strings.Join(outLines, "\n")
}

// workspaceAnnotationKeys returns every annotation key used by any host in
// dir/hosts.yml, sorted — the candidates offered when adding a mapping.
// A missing or unparseable hosts.yml yields no candidates (manual entry
// still works).
func workspaceAnnotationKeys(dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return nil
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, h := range hf.Hosts {
		for k := range h.Annotations {
			set[k] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
