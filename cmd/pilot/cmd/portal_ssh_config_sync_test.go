package cmd

// TestPilotSSHConfigMatchesApplyPlaybook keeps pilotSSHConfig (this
// package's single source of truth, verified against real OpenSSH in
// portal_ssh_test.go's TestPilotSSHConfigDirectives) byte-identical to
// what playbooks/apply/pilot-access-gateway-apply.yml's Step 12 task
// actually installs at /etc/pilot/ssh_config. The two are independently
// maintained (a Go string constant vs. a YAML `content: |` block), so a
// future edit to one without the other must fail CI rather than drift
// silently — see spec.md §32.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPilotSSHConfigMatchesApplyPlaybook(t *testing.T) {
	root := repoRootForTest(t)
	path := filepath.Join(root, "playbooks", "apply", "pilot-access-gateway-apply.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got, err := extractStep12SSHConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got != pilotSSHConfig {
		t.Fatalf("playbook's Step 12 ssh_config content does not match pilotSSHConfig.\n--- playbook ---\n%s\n--- pilotSSHConfig ---\n%s", got, pilotSSHConfig)
	}
}

// extractStep12SSHConfig pulls the de-indented body of the "Step 12"
// task's `content: |` block scalar out of the playbook's raw YAML,
// mirroring how a YAML parser would strip the block's leading indent —
// without pulling in a full YAML parse, since the value we need is a
// fixed, known-shape literal block.
func extractStep12SSHConfig(playbook string) (string, error) {
	const marker = `- name: "Step 12: install root-owned SSH config (spec.md §32)"`
	lines := strings.Split(playbook, "\n")

	start := -1
	for i, line := range lines {
		if strings.Contains(line, marker) {
			start = i
			break
		}
	}
	if start == -1 {
		return "", errNotFound("Step 12 task not found in playbook")
	}

	contentIdx := -1
	for i := start; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "content: |" {
			contentIdx = i
			break
		}
	}
	if contentIdx == -1 {
		return "", errNotFound("Step 12 task has no `content: |` block")
	}

	var body []string
	indent := ""
	for i := contentIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			body = append(body, "")
			continue
		}
		if indent == "" {
			indent = line[:len(line)-len(trimmed)]
		}
		if !strings.HasPrefix(line, indent) {
			break
		}
		body = append(body, strings.TrimPrefix(line, indent))
	}
	// Trailing blank lines from the split belong to the YAML document,
	// not the block scalar; trim them the way `|` (clip) chomping does,
	// keeping exactly one final newline.
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	return strings.Join(body, "\n") + "\n", nil
}

type errNotFound string

func (e errNotFound) Error() string { return string(e) }
