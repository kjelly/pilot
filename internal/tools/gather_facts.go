package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/sandbox"
)

type GatherFactsTool struct {
	Runner               *ansible.Runner
	AllowedPlaybookRoots []string
	DefaultInventory     string
	DefaultLimit         string
	Env                  sandbox.Environment
}

func (t *GatherFactsTool) Spec() *Spec {
	return &Spec{
		Name:        "gather_facts",
		Description: "Gather system facts (OS, CPU, memory, mounts, network etc.) from target hosts using Ansible setup module. Pass filter (e.g. 'ansible_mounts') to limit data size.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  gatherFactsArgs,
	}
}

func (t *GatherFactsTool) ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	roots := t.AllowedPlaybookRoots
	if len(roots) == 0 {
		roots = DefaultAllowedPlaybookRoots
	}
	if len(roots) == 0 {
		return fmt.Errorf("inventory path %q rejected: no allowed roots configured", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("inventory path %q rejected: %v", path, err)
	}
	if rl, err := filepath.EvalSymlinks(abs); err == nil {
		abs = rl
	}
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if !strings.HasSuffix(rootAbs, "/") {
			rootAbs += "/"
		}
		if strings.HasPrefix(abs, rootAbs) {
			return nil
		}
	}
	return fmt.Errorf("inventory path %q (resolved %s) is outside the allowed roots %v", path, abs, roots)
}

func (t *GatherFactsTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Inventory string `json:"inventory"`
		Limit     string `json:"limit"`
		Filter    string `json:"filter"`
		Become    *bool  `json:"become"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("gather_facts: invalid args: %w", err)
	}

	if a.Inventory == "" && t.DefaultInventory != "" {
		a.Inventory = t.DefaultInventory
	}
	if a.Limit == "" && t.DefaultLimit != "" {
		a.Limit = t.DefaultLimit
	}

	if a.Inventory != "" {
		if err := t.ValidatePath(a.Inventory); err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
		}
	}

	// Create a temp playbook to gather facts
	playbookContent := `---
- name: Gather facts dynamically
  hosts: all
  gather_facts: no
  tasks:
    - name: Gather setup facts
      ansible.builtin.setup:
        filter: "{{ fact_filter | default(omit) }}"
      register: setup_output
    - name: Print facts
      ansible.builtin.debug:
        var: setup_output.ansible_facts
`
	tmpPlaybook, err := os.CreateTemp("", "pilot-gather-facts-*.yml")
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: create temp playbook: %v", err), IsError: true}, nil
	}
	defer os.Remove(tmpPlaybook.Name())
	if _, err := tmpPlaybook.WriteString(playbookContent); err != nil {
		tmpPlaybook.Close()
		return &Result{Content: fmt.Sprintf("ERROR: write temp playbook: %v", err), IsError: true}, nil
	}
	tmpPlaybook.Close()

	// Handle extra vars for filter
	var extraVarsFile string
	if a.Filter != "" {
		ev := map[string]any{"fact_filter": a.Filter}
		data, err := json.Marshal(ev)
		if err == nil {
			f, ferr := os.CreateTemp("", "pilot-gather-facts-vars-*.json")
			if ferr == nil {
				_ = f.Chmod(0o600)
				if _, werr := f.Write(data); werr == nil {
					f.Close()
					extraVarsFile = f.Name()
					defer os.Remove(extraVarsFile)
				} else {
					f.Close()
					os.Remove(f.Name())
				}
			}
		}
	}

	effectiveInventory := a.Inventory
	if t.Env != nil {
		conn := t.Env.ConnectionInfo()
		if conn.ConnectionType == "docker" {
			inv, err := buildSandboxInventory(conn, a.Limit)
			if err != nil {
				return &Result{
					Content: fmt.Sprintf("ERROR: build sandbox inventory: %v", err),
					IsError: true,
				}, nil
			}
			f, err := os.CreateTemp("", "pilot-sandbox-inv-*.yml")
			if err != nil {
				return &Result{
					Content: fmt.Sprintf("ERROR: create sandbox inventory tmpfile: %v", err),
					IsError: true,
				}, nil
			}
			if _, err := f.WriteString(inv); err != nil {
				f.Close()
				os.Remove(f.Name())
				return &Result{
					Content: fmt.Sprintf("ERROR: write sandbox inventory: %v", err),
					IsError: true,
				}, nil
			}
			f.Close()
			effectiveInventory = f.Name()
			defer os.Remove(effectiveInventory)
		}
	}

	runner := t.Runner
	if runner == nil {
		runner = ansible.NewRunner()
	}

	allArgs := ansible.BuildArgs(ansible.PlaybookArgs{
		Playbook:      tmpPlaybook.Name(),
		Inventory:     effectiveInventory,
		Limit:         a.Limit,
		ExtraVarsFile: extraVarsFile,
		Become:        a.Become,
	})

	res, err := runner.Run(ctx, allArgs...)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v\nStderr: %s", err, res.Stderr), IsError: true}, nil
	}

	var sb strings.Builder
	if res.Stdout != "" {
		sb.WriteString(res.Stdout)
	}
	if res.Stderr != "" {
		sb.WriteString("\n--- stderr ---\n")
		sb.WriteString(res.Stderr)
	}

	content := sb.String()
	if len(content) > 6000 {
		content = content[:6000] + "\n... [truncated for context window]"
	}

	if res.ExitCode != 0 {
		return &Result{Content: content, IsError: true}, nil
	}
	return &Result{Content: content}, nil
}
