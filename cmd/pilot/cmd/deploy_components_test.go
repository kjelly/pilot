package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/outbound"
)

// executeSelectedDeployCLI runs the registered Cobra command, including its real
// flag parser and non-TTY defaults driver, rather than calling a routing helper.
func executeSelectedDeployCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	oldComponents, oldDir, oldInv := deployComponentFlags, deployDirFlag, deployInventoryFlag
	oldForce, oldPreview, oldActions := deployForceFlag, deployPreviewOnlyFlag, deployActionsPath
	oldStage, oldHours, oldLimit := stageFlag, stagingAttestedHoursFlag, limitFlag
	oldTimeout, oldTTY := deployTimeoutFlag, deployStdinIsTerminal
	oldOut, oldErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		deployComponentFlags, deployDirFlag, deployInventoryFlag = oldComponents, oldDir, oldInv
		deployForceFlag, deployPreviewOnlyFlag, deployActionsPath = oldForce, oldPreview, oldActions
		stageFlag, stagingAttestedHoursFlag, limitFlag = oldStage, oldHours, oldLimit
		deployTimeoutFlag, deployStdinIsTerminal = oldTimeout, oldTTY
		rootCmd.SetOut(oldOut)
		rootCmd.SetErr(oldErr)
		rootCmd.SetArgs(nil)
	})
	deployComponentFlags, deployForceFlag, deployPreviewOnlyFlag, deployActionsPath = nil, false, false, ""
	stageFlag, stagingAttestedHoursFlag, limitFlag = "", "", ""
	deployDirFlag, deployInventoryFlag, deployTimeoutFlag = ".", "inventory.yml", "30s"
	deployStdinIsTerminal = func() bool { return false }
	var output bytes.Buffer
	rootCmd.SetOut(&output)
	rootCmd.SetErr(&output)
	rootCmd.SetArgs(append([]string{"deploy"}, args...))
	err := rootCmd.ExecuteContext(context.Background())
	return output.String(), err
}

func TestDeployComponentsCLI(t *testing.T) {
	for _, mode := range []string{"--preview-only", "--force"} {
		for _, repeated := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: "/repeated", false: "/single"}[repeated], func(t *testing.T) {
				env := newOutboundWorkflowEnv(t, map[string][]string{"consumer": {"host-a"}, "leaf": {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
				oldCatalog := deployCatalog
				deployCatalog = []deployPlaybook{
					{Key: "consumer", DefaultGroup: "consumer", StageVar: "stage"},
					{Key: "leaf", DefaultGroup: "leaf", StageVar: "stage"},
				}
				t.Cleanup(func() { deployCatalog = oldCatalog })
				argsLog := filepath.Join(t.TempDir(), "calls")
				bin := filepath.Join(t.TempDir(), "ansible-playbook")
				script, err := os.ReadFile(writeArgsFixture(t, argsLog))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(bin, script, 0o755); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
				args := []string{"--dir", env.workspace, "--component", "consumer", mode, "--stage", "sandbox", "--limit", "host-a"}
				if repeated {
					args = append(args, "--component", "leaf")
				}
				output, err := executeSelectedDeployCLI(t, args...)
				if err != nil {
					t.Fatalf("Cobra deploy: %v\n%s", err, output)
				}
				calls, err := os.ReadFile(argsLog)
				if err != nil {
					t.Fatal(err)
				}
				var actual []string
				for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					if strings.Contains(line, "preflight.yml") {
						continue
					}
					if !strings.Contains(line, "--limit host-a") || strings.Contains(line, "site.yml") {
						t.Fatalf("unscoped or site-wide execution: %s", line)
					}
					playbook := "consumer"
					if strings.Contains(line, "leaf-apply.yml") {
						playbook = "leaf"
					} else if !strings.Contains(line, "consumer-apply.yml") {
						t.Fatalf("unexpected playbook: %s", line)
					}
					kind := "apply"
					if strings.Contains(line, "--check --diff") {
						kind = "preview"
					}
					actual = append(actual, playbook+":"+kind)
				}
				want := []string{"leaf:preview", "consumer:preview"}
				if mode == "--force" {
					want = []string{"leaf:preview", "leaf:apply", "consumer:preview", "consumer:apply"}
				}
				if repeated {
					want = append(want, "leaf:preview")
					if mode == "--force" {
						want = append(want, "leaf:apply")
					}
				}
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("executed=%v want=%v\n%s", actual, want, output)
				}
				if mode == "--force" {
					var event struct {
						Operation struct {
							Type      string   `json:"type"`
							Requested []string `json:"requested_components"`
						} `json:"operation"`
					}
					if err := json.Unmarshal(env.capture.last(), &event); err != nil {
						t.Fatal(err)
					}
					requested := []string{"consumer"}
					if repeated {
						requested = append(requested, "leaf")
					}
					if env.capture.count() != 1 || event.Operation.Type != "deploy" || !reflect.DeepEqual(event.Operation.Requested, requested) {
						t.Fatalf("expected one selected deploy terminal event, got %d: %s", env.capture.count(), env.capture.last())
					}
				}
			})
		}
	}
}

func TestDeployComponentsRejectBeforeSideEffects(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	for _, invalid := range []string{"unknown-component", "freeipa-identity", "agent-controller", "core-infra-provider", ""} {
		t.Run(invalid, func(t *testing.T) {
			workspace := t.TempDir()
			// If validation reaches runtime or regeneration these paths either
			// change or return a different error, so early failure is observable.
			before := []byte("inventory sentinel\n")
			inv := filepath.Join(workspace, "inventory.yml")
			if err := os.WriteFile(inv, before, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"hosts.yml", "roster.yaml"} {
				if err := os.WriteFile(filepath.Join(workspace, name), before, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previousData := dataDir
			dataDir = filepath.Join(workspace, "runtime-must-not-exist")
			t.Cleanup(func() { dataDir = previousData })
			output, err := executeSelectedDeployCLI(t, "--dir", workspace, "--component", "host-monitoring", "--component", invalid, "--force")
			if err == nil || !strings.Contains(err.Error(), "not an available deploy component") {
				t.Fatalf("wrong rejection: %v\n%s", err, output)
			}
			if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
				t.Fatalf("runtime initialized before ID validation: %v", err)
			}
			for _, name := range []string{"inventory.yml", "hosts.yml", "roster.yaml"} {
				if after, err := os.ReadFile(filepath.Join(workspace, name)); err != nil || !bytes.Equal(after, before) {
					t.Fatalf("%s mutated before ID validation: %q %v", name, after, err)
				}
			}
		})
	}
	if _, err := executeSelectedDeployCLI(t, "--component", "host-monitoring", "--actions", "scenario.json"); err == nil || !strings.Contains(err.Error(), "--component 不能與 --actions") {
		t.Fatalf("actions conflict: %v", err)
	}
}

func TestDeployComponentsCatalogParity(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	catalog := loadOutboundWorkflowCatalog(t)
	for _, menuEntry := range workflowCatalogEntries(catalog, false) {
		for _, id := range entryComponentIDs(menuEntry) {
			selected, err := selectDeployComponents(catalog, []string{id, id}, "apply")
			if err != nil || len(selected) != 1 {
				t.Fatalf("%s: selected=%v err=%v", id, selected, err)
			}
			cliIDs := entryComponentIDs(selected[0])
			if !reflect.DeepEqual(cliIDs, []string{id}) {
				t.Fatalf("%s: resolved IDs=%v", id, cliIDs)
			}
			cliPlan, err := delivery.PlanComponents(catalog, cliIDs, deployShowExperimental)
			if err != nil {
				t.Fatal(err)
			}
			tuiPlan, err := delivery.PlanComponents(catalog, []string{id}, deployShowExperimental)
			if err != nil || !reflect.DeepEqual(cliPlan, tuiPlan) {
				t.Fatalf("%s: CLI/TUI plans differ: %v", id, err)
			}
			if len(menuEntry.InfraRoles) > 0 && !reflect.DeepEqual(selected[0].InfraRoles, []string{id}) {
				t.Fatalf("%s: aggregate role not narrowed: %v", id, selected[0])
			}
		}
	}
	// Membership is a workflow policy, not permission to expose every contract.
	for _, id := range []string{"freeipa-identity", "pilot-gateway-scope"} {
		if _, err := selectDeployComponents(catalog, []string{id}, "apply"); err == nil {
			t.Fatalf("reconcile-only component %s exposed under deploy", id)
		}
	}
}

func TestDeployComponentsPreviewFailureAndDeferred(t *testing.T) {
	for _, scenario := range []string{"later preview fails", "all deferred"} {
		t.Run(scenario, func(t *testing.T) {
			inv := writeReconcileBatchFixture(t, map[string]string{"host-a": "optional"})
			oldCatalog := deployCatalog
			deployCatalog = []deployPlaybook{{Key: "consumer", DefaultGroup: "consumer", StageVar: "stage"}}
			t.Cleanup(func() { deployCatalog = oldCatalog })
			oldProber := deployAvailabilityProber
			deployAvailabilityProber = fakeDownHostsProber(map[string]bool{"host-a": scenario == "all deferred"})
			t.Cleanup(func() { deployAvailabilityProber = oldProber })
			argsPath := filepath.Join(t.TempDir(), "calls")
			fixture, err := os.ReadFile(writeArgsFixture(t, argsPath))
			if err != nil {
				t.Fatal(err)
			}
			fixture = append(fixture, []byte("case \"$*\" in *consumer-apply.yml*) exit 2 ;; esac\n")...)
			bin := filepath.Join(t.TempDir(), "ansible-playbook")
			if err := os.WriteFile(bin, fixture, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := executeSelectedDeployCLI(t, "--inventory", inv, "--component", "consumer", "--preview-only")
			if err == nil || strings.Contains(out, "預覽都通過") {
				t.Fatalf("preview incorrectly passed: %v\n%s", err, out)
			}
			if scenario == "all deferred" {
				if !strings.Contains(err.Error(), "沒有預覽") {
					t.Fatalf("wrong failure: %v", err)
				}
				if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
					t.Fatalf("deferred run executed playbook: %v", err)
				}
			} else {
				if !strings.Contains(err.Error(), "預覽失敗") {
					t.Fatalf("wrong failure: %v", err)
				}
				calls, err := os.ReadFile(argsPath)
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					if !strings.Contains(line, "preflight.yml") && !strings.Contains(line, "--check --diff") {
						t.Fatalf("preview applied: %s", line)
					}
				}
			}
		})
	}
}

func TestDeployComponentsDifferentSelectionsPreviewAgain(t *testing.T) {
	inv := writeReconcileBatchFixture(t, map[string]string{"host-a": ""})
	stubDeploymentAvailabilityAllReachable(t)
	oldCatalog := deployCatalog
	deployCatalog = []deployPlaybook{
		{Key: "consumer", DefaultGroup: "consumer", StageVar: "stage"},
		{Key: "leaf", DefaultGroup: "leaf", StageVar: "stage"},
	}
	t.Cleanup(func() { deployCatalog = oldCatalog })
	argsPath := filepath.Join(t.TempDir(), "calls")
	fixture, err := os.ReadFile(writeArgsFixture(t, argsPath))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "ansible-playbook")
	if err := os.WriteFile(bin, fixture, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, component := range []string{"consumer", "leaf"} {
		out, err := executeSelectedDeployCLI(t, "--inventory", inv, "--component", component, "--preview-only")
		if err != nil {
			t.Fatalf("%s: %v\n%s", component, err, out)
		}
	}
	calls, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "--check --diff") != 3 || strings.Count(string(calls), "leaf-apply.yml") != 2 {
		t.Fatalf("a different selected set reused an old preview: %s", calls)
	}
}

func TestDeployComponentsAggregateRoleCLI(t *testing.T) {
	inv := writeReconcileBatchFixture(t, map[string]string{"host-a": ""})
	stubDeploymentAvailabilityAllReachable(t)
	oldCatalog := deployCatalog
	deployCatalog = []deployPlaybook{{Key: "aggregate", InfraRoles: []string{"consumer", "leaf"}, StageVar: "stage"}}
	t.Cleanup(func() { deployCatalog = oldCatalog })
	argsPath := filepath.Join(t.TempDir(), "calls")
	fixture, err := os.ReadFile(writeArgsFixture(t, argsPath))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "ansible-playbook")
	if err := os.WriteFile(bin, fixture, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := executeSelectedDeployCLI(t, "--inventory", inv, "--component", "leaf", "--preview-only")
	if err != nil {
		t.Fatalf("aggregate role CLI: %v\n%s", err, out)
	}
	calls, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "leaf-apply.yml") || !strings.Contains(string(calls), "infra_role=leaf") || strings.Contains(string(calls), "consumer-apply.yml") {
		t.Fatalf("selected aggregate contract ID did not bind its role: %s", calls)
	}
}

func TestDeployComponentsLifecyclePlanDoesNotApplyPrerequisites(t *testing.T) {
	inv := writeReconcileBatchFixture(t, map[string]string{"host-a": ""})
	stubDeploymentAvailabilityAllReachable(t)
	path := filepath.Join(os.Getenv("PILOT_ROOT"), "contracts", "consumer.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`apply: "consumer-apply.yml"`), []byte(`apply: "consumer-apply.yml", upgrade: "consumer-upgrade.yml"`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })
	argsPath := filepath.Join(t.TempDir(), "calls")
	runner := ansible.NewRunner()
	runner.Binary = writeArgsFixture(t, argsPath)
	var out bytes.Buffer
	request := catalogDeploymentRequest{playbook: "consumer-upgrade.yml", inv: inv, stage: "sandbox", extraVars: []string{"stage=sandbox"}, componentHints: []string{"consumer"}, workspaceDir: filepath.Dir(inv)}
	if err := executeCatalogBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request}, outbound.OperationDeploy); err != nil {
		t.Fatalf("upgrade preview: %v\n%s", err, out.String())
	}
	calls, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "--check --diff") != 1 || !strings.Contains(string(calls), "consumer-upgrade.yml") || strings.Contains(string(calls), "leaf-apply.yml") {
		t.Fatalf("non-apply lifecycle bootstrapped prerequisites: %s", calls)
	}
}

func TestDeployComponentsPreviewPersistsNothing(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(map[bool]string{false: "previewed", true: "deferred"}[deferred], func(t *testing.T) {
			inv := writeReconcileBatchFixture(t, map[string]string{"host-a": "optional"})
			workspace := filepath.Dir(inv)
			vars := filepath.Join(workspace, "group_vars", "all.yml")
			if err := os.MkdirAll(filepath.Dir(vars), 0o700); err != nil {
				t.Fatal(err)
			}
			original := []byte("# thanos_s3_target_host: 192.0.2.1\n")
			if err := os.WriteFile(vars, original, 0o600); err != nil {
				t.Fatal(err)
			}
			oldPrompt, oldProber := activePromptAutomation, deployAvailabilityProber
			activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
			deployAvailabilityProber = fakeDownHostsProber(map[string]bool{"host-a": deferred})
			t.Cleanup(func() { activePromptAutomation, deployAvailabilityProber = oldPrompt, oldProber })
			runner := ansible.NewRunner()
			runner.Binary = writeArgsFixture(t, filepath.Join(t.TempDir(), "calls"))
			request := catalogDeploymentRequest{
				playbook: "consumer-apply.yml", inv: inv, stage: "sandbox", extraVars: []string{"stage=sandbox"},
				componentHints: []string{"consumer"}, workspaceDir: workspace,
				acceptedAutoHostVars: []acceptedAutoHostVar{{Var: "thanos_s3_target_host", Value: "10.9.9.9"}},
			}
			var out bytes.Buffer
			err := executeCatalogBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request}, outbound.OperationDeploy)
			if (err != nil) != deferred {
				t.Fatalf("wrong preview outcome: %v\n%s", err, out.String())
			}
			if data, err := os.ReadFile(vars); err != nil || !bytes.Equal(data, original) {
				t.Fatalf("preview persisted inputs: %q %v", data, err)
			}
		})
	}
}

// Native Ansible resolves the inventory and host patterns. Only playbook
// mutation/fact transport is substituted; the target harness checks actual
// remote marker placement using these same committed fixture contracts/tasks.
func TestDeployComponentsTwoHopCLI(t *testing.T) {
	realAnsible, err := exec.LookPath("ansible")
	if err != nil {
		t.Skip("native ansible is required for host-pattern resolution")
	}
	if _, err := exec.LookPath("ansible-inventory"); err != nil {
		t.Skip("native ansible-inventory is required")
	}
	fixtureRoot := filepath.Join(repoRootForTest(t), "playbooks/test/fixtures/deploy-components")
	t.Chdir(fixtureRoot)
	t.Setenv("PILOT_ROOT", fixtureRoot)
	workspace := t.TempDir()
	inv := filepath.Join(workspace, "inventory.yml")
	raw := `all:
  hosts:
    host-a: {ansible_host: 127.0.0.1}
    host-b: {ansible_host: 127.0.0.1}
  children:
    fixture-consumer: {hosts: {host-a: {}}}
    fixture-provider: {hosts: {host-b: {}}}
    fixture-leaf: {hosts: {host-a: {}, host-b: {}}}
    fixture-support: {hosts: {host-a: {}}}
    fixture-unrelated: {hosts: {host-b: {}}}
`
	if err := os.WriteFile(inv, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	oldData := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldData })
	stubDeploymentAvailabilityAllReachable(t)
	binDir := t.TempDir()
	// List-hosts is a real Ansible operation; read-only fact probes get a
	// synthetic transport result to avoid making SSH connections in unit tests.
	shim := "#!/bin/sh\ncase \"$*\" in *--list-hosts*) exec " + realAnsible + " \"$@\" ;; esac\nprintf '%s\\n' '{\"plays\":[{\"tasks\":[{\"hosts\":{\"host-a\":{\"stdout\":\"unknown\",\"rc\":0},\"host-b\":{\"stdout\":\"unknown\",\"rc\":0}}}]}]}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(t.TempDir(), "calls")
	fake, err := os.ReadFile(writeArgsFixture(t, argsPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "ansible-playbook"), fake, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := executeSelectedDeployCLI(t, "--dir", workspace, "--component", "dns", "--limit", "host-a", "--force")
	if err != nil {
		t.Fatalf("two-hop CLI: %v\n%s", err, out)
	}
	calls, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	var previous string
	var sequence []string
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if strings.Contains(line, "preflight.yml") {
			continue
		}
		if strings.Contains(line, "site.yml") || strings.Contains(line, "support.yml") || strings.Contains(line, "unrelated.yml") {
			t.Fatalf("unselected lifecycle executed: %s", line)
		}
		for _, pb := range []string{"leaf", "provider", "consumer"} {
			if strings.Contains(line, "playbooks/"+pb+".yml") {
				sequence = append(sequence, pb)
				pattern := "fixture-" + pb
				var limit string
				args := strings.Fields(line)
				for i := 0; i+1 < len(args); i++ {
					if args[i] == "--limit" {
						limit = args[i+1]
					}
					if args[i] == "-e" && strings.HasPrefix(args[i+1], "target_group=") {
						pattern = strings.TrimPrefix(args[i+1], "target_group=")
					}
				}
				hosts, err := resolvePatternHosts(context.Background(), inv, pattern, limit)
				want := []string{"host-b"}
				if pb == "consumer" {
					want = []string{"host-a"}
				}
				if err != nil || !reflect.DeepEqual(hosts, want) {
					t.Fatalf("two-hop effective scope escaped its planned host: playbook=%s hosts=%v want=%v err=%v argv=%s", pb, hosts, want, err, line)
				}
			}
		}
		if strings.Contains(line, "--check --diff") {
			previous = strings.TrimPrefix(line, "--check --diff ")
		} else if line != previous {
			t.Fatalf("preview/apply scope differed:\npreview: %s\napply: %s", previous, line)
		}
	}
	if !reflect.DeepEqual(sequence, []string{"leaf", "leaf", "provider", "provider", "consumer", "consumer"}) {
		t.Fatalf("wrong scoped plan: %v\n%s", sequence, out)
	}
}
