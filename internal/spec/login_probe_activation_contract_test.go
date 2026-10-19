package spec

import (
	"fmt"
	"strings"
	"testing"
)

// The query consumes the activation writer's protocol. A path, ordering or
// marker-format change must update both sides, rather than silently making
// a disk-only observation appear authoritative.
func TestRegression_LoginProbeActivationProofContract(t *testing.T) {
	apply := loadYAML(t, "../../playbooks/apply/login-probe-apply.yml").([]any)[0].(map[string]any)
	query := loadYAML(t, "../../playbooks/decommission/login-probe-target-query.yml").([]any)[0].(map[string]any)
	paths := query["vars"].(map[string]any)["login_probe_query_paths"].([]any)
	var fingerprint, writer map[string]any
	var visit func([]any)
	visit = func(tasks []any) {
		for _, v := range tasks {
			task := v.(map[string]any)
			if children, ok := task["block"].([]any); ok {
				visit(children)
			}
			if task["register"] == "login_probe_runtime_files" {
				fingerprint = task
			}
			if task["name"] == "Runtime: record the proven activation for idempotent retries" {
				writer = task
			}
		}
	}
	visit(apply["tasks"].([]any))
	if fingerprint == nil || writer == nil {
		t.Fatal("activation producer missing")
	}
	check := func(paths []any) error {
		ordered := append(append([]any{}, fingerprint["loop"].([]any)...), "{{ login_probe_runtime_marker_path }}")
		if len(paths) != len(ordered) {
			return fmt.Errorf("query path count %d != writer %d", len(paths), len(ordered))
		}
		for i, v := range ordered {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(v.(string), "{{"), "}}"))
			path, _ := paths[i].(string)
			def, _ := apply["vars"].(map[string]any)[name].(string)
			if !strings.HasPrefix(path, "{{ "+name+" | default(") || !strings.Contains(path, "'"+def+"'") {
				return fmt.Errorf("query path %d disagrees with writer %s", i, name)
			}
		}
		return nil
	}
	if err := check(paths); err != nil {
		t.Fatal(err)
	}
	// Deliberately put the ordering regression back into the consumed
	// contract: this exact checker must reject it.
	bad := append([]any{}, paths...)
	bad[0], bad[1] = bad[1], bad[0]
	if err := check(bad); err == nil {
		t.Fatal("checker accepted config/binary order drift")
	}
	copy := writer["ansible.builtin.copy"].(map[string]any)
	if copy["owner"] != "root" || copy["mode"] != "0600" || copy["content"] != "{{ login_probe_runtime_fingerprint }} {{ login_probe_runtime_invocation_after.stdout | trim }}\n" {
		t.Fatal("activation marker producer format/security changed; update the consumer contract")
	}
	if fingerprint["ansible.builtin.stat"].(map[string]any)["checksum_algorithm"] != "sha256" {
		t.Fatal("activation hash algorithm changed")
	}
}
