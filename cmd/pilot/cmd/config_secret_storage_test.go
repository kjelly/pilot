package cmd

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConfigSecretStorage_GroupVarActionRejectsLiteral(t *testing.T) {
	const value = "ISSUE130_DUMMY_PASSWORD"
	err := validateSetGroupVar(editAction{File: "dashboard.yml", Key: "grafana_admin_password", Value: value})
	if err == nil {
		t.Fatal("secret literal was accepted for group_vars")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatal("secret appeared in validation error")
	}
}

func TestConfigSecretStorage_ExistingSecretsBlockedBeforeUIAndDeployment(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	for _, tree := range []string{"group_vars", "host_vars"} {
		t.Run(tree, func(t *testing.T) {
			dir := t.TempDir()
			const value = "ISSUE130_DUMMY_PASSWORD"
			writeTestFile(t, filepath.Join(dir, tree, "all", "nested.yaml"), "grafana_admin_password: "+value+"\n")
			router := newEditRouterModel(dir)
			if router.err == nil {
				t.Fatal("existing secret allowed into editor")
			}
			if strings.Contains(viewContent(router.View()), value) {
				t.Fatal("secret in initial frame")
			}
			_, err := loadDeployInventorySnapshot(context.Background(), filepath.Join(dir, "inventory.yml"))
			if err == nil || !strings.Contains(err.Error(), "forbidden secret storage") {
				t.Fatalf("deployment gate: %v", err)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatal("secret in deployment error")
			}
			blocking, _ := collectWorkspaceValidation(dir)
			if len(blocking) == 0 || strings.Contains(strings.Join(blocking, " "), value) {
				t.Fatal("unsafe/missing validation error")
			}
			_, err = applyEditScenario(dir, "test-130", editScenario{Version: 1, Steps: []editAction{{Action: "create_host", Host: "safe-host"}}}, editAgentSessionOptions{})
			if err == nil || strings.Contains(err.Error(), value) {
				t.Fatal("unsafe/missing apply error")
			}
		})
	}
}

func TestConfigSecretStorage_ExamplesRemainSafe(t *testing.T) {
	if err := validateInventorySecretStorage(repoRootForTest(t)); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSecretStorage_MCPPlanAndAuditNeverContainRejectedValue(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	const value = "ISSUE130_DUMMY_PASSWORD"
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "proposed", true: "existing"}[existing], func(t *testing.T) {
			dir, audit := t.TempDir(), t.TempDir()
			if existing {
				writeTestFile(t, filepath.Join(dir, "host_vars", "all", "nested.yml"), "ansible_password: "+value+"\n")
			}
			rev, err := computeWorkspaceRevision(dir)
			if err != nil {
				t.Fatal(err)
			}
			handler := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: audit})
			scenario := editScenario{Version: 1, Steps: []editAction{{Action: "set_group_var", File: "dashboard.yml", Key: "grafana_admin_password", Value: value}}}
			if existing {
				scenario.Steps = []editAction{{Action: "create_host", Host: "safe-host"}}
			}
			result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
			if err != nil || result == nil || !result.IsError {
				t.Fatalf("rejected result=%v err=%v", result, err)
			}
			data, _ := json.Marshal([]any{result, out})
			if strings.Contains(string(data), value) {
				t.Fatal("secret in MCP response")
			}
			if err := filepath.WalkDir(audit, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if strings.Contains(string(data), value) {
					t.Errorf("secret in audit %s", entry.Name())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigSecretStorage_PureReferenceActionsAllowed(t *testing.T) {
	for _, value := range []string{"", "{{ vault_grafana_admin_password }}"} {
		if err := validateSetGroupVar(editAction{File: "dashboard.yml", Key: "grafana_admin_password", Value: value}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConfigSecretStorage_DiffHidesExistingSecret(t *testing.T) {
	const value = "ISSUE130_DUMMY_PASSWORD"
	before := []managedFileEntry{{RelPath: "host_vars/example.yml", Content: []byte("ansible_password: " + value + "\n")}}
	after := []managedFileEntry{{RelPath: "host_vars/example.yml", Content: []byte("ansible_password: '{{ vault_ansible_password }}'\n")}}
	patch, _, redacted := diffEntries(before, after)
	if strings.Contains(patch, value) || !redacted {
		t.Fatal("migration diff disclosed the original credential")
	}
}
