package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/store"
	"go.yaml.in/yaml/v3"
)

func managedProviderCatalog(t *testing.T) contract.Catalog {
	t.Helper()
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "consumer", Role: "consumer", Dependencies: []contract.Dependency{
			{Component: "docker", Required: true, Relation: "sameHosts"},
			{Component: "provider", Required: true, Relation: "providerEndpoint", ApplyBeforeConsumer: true},
		}, Bindings: []contract.Binding{{Input: "provider_host", From: contract.BindingFrom{Component: "provider", Endpoint: "api"}}}},
		{ID: "provider", Role: "provider", Dependencies: []contract.Dependency{
			{Component: "docker", Required: true, Relation: "sameHosts"},
			{Component: "storage", Required: true, Relation: "providerEndpoint"},
		}, Bindings: []contract.Binding{{Input: "storage_host", From: contract.BindingFrom{Component: "storage", Endpoint: "api"}}}},
		{ID: "storage", Role: "storage", Dependencies: []contract.Dependency{{Component: "docker", Required: true, Relation: "sameHosts"}}},
		{ID: "docker", Role: "docker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestManagedProviderBothWorkflowMenus(t *testing.T) {
	for _, workflow := range []string{"deploy", "reconcile"} {
		ids := deployComponentIDs(workflow)
		for _, want := range []string{"dashboard", "thanos-query"} {
			found := false
			for _, id := range ids {
				if id == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s menu missing %s", workflow, want)
			}
		}
		if workflow == "deploy" {
			for _, id := range ids {
				if id == "pilot-gateway-scope" {
					t.Error("day-2-only gateway scope exposed under deploy")
				}
			}
		}
	}
}

func TestManagedProviderPlanOrderAndMutationScopes(t *testing.T) {
	catalog := managedProviderCatalog(t)
	chain, err := deploymentDependencyChain(catalog, []string{"consumer"})
	if err != nil {
		t.Fatal(err)
	}
	if got := contractIDs(chain); !reflect.DeepEqual(got, []string{"docker", "provider"}) {
		t.Fatalf("order=%v", got)
	}
	scope := delivery.Scope{HostsByRole: map[string][]string{
		"consumer": {"dashboard-a"}, "provider": {"query-b"}, "storage": {"s3-c"}, "docker": {"dashboard-a", "query-b", "s3-c", "unrelated-d"},
	}}
	limits, err := deploymentDependencyLimits(catalog, []string{"consumer"}, scope)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"docker": "dashboard-a,query-b", "provider": "query-b"}
	if !reflect.DeepEqual(limits, want) {
		t.Fatalf("limits=%v want=%v", limits, want)
	}
	for _, hosts := range [][]string{nil, {"query-b", "query-c"}} {
		scope.HostsByRole["provider"] = hosts
		if _, err := deploymentDependencyLimits(catalog, []string{"consumer"}, scope); err == nil {
			t.Fatalf("ambiguous/missing managed provider accepted: %v", hosts)
		}
	}
}

func TestManagedProviderBindingDefaultsAndOverrides(t *testing.T) {
	catalog := managedProviderCatalog(t)
	provider, _ := catalog.Component("provider")
	scope := delivery.Scope{HostsByRole: map[string][]string{"provider": {"query-b"}, "storage": {"s3-c"}}}
	hostVars := map[string]map[string]any{"query-b": {}, "s3-c": {"ansible_host": "s3.example.internal"}}
	vars, err := completeDependencyBindingVars(catalog, provider, scope, hostVars, []string{"stage=staging", "confirm_staging=true"})
	if err != nil || extraVarValue(vars, "storage_host") != "s3.example.internal" {
		t.Fatalf("vars=%v err=%v", vars, err)
	}
	hostVars["query-b"]["storage_host"] = "configured.example.internal"
	vars, err = completeDependencyBindingVars(catalog, provider, scope, hostVars, nil)
	if err != nil || len(vars) != 0 {
		t.Fatalf("inventory value overridden: %v %v", vars, err)
	}
	vars = dependencyTargetVars([]string{"target_group=dashboard-a", "stage=prod", "confirm_prod=true", "{\"target_group\":\"dashboard-a\"}"}, "provider")
	if extraVarValue(vars, "target_group") != "provider" || extraVarValue(vars, "stage") != "prod" || extraVarValue(vars, "confirm_prod") != "true" {
		t.Fatalf("target/stage lost: %v", vars)
	}
}

func TestManagedProviderActualDashboardPlan(t *testing.T) {
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	t.Setenv("ANSIBLE_CACHE_PLUGIN", "memory")
	root := repoRootForTest(t)
	t.Setenv("PILOT_ROOT", root)
	inv := filepath.Join(t.TempDir(), "inventory.yml")
	raw := `all:
  hosts:
    dashboard-a: {ansible_connection: local, ansible_host: dashboard.example.internal}
    query-b: {ansible_connection: local, ansible_host: query.example.internal}
    s3-c: {ansible_connection: local, ansible_host: s3.example.internal}
    unrelated-d: {ansible_connection: local}
  children:
    dashboard: {hosts: {dashboard-a: {}}}
    thanos-query: {hosts: {query-b: {}}}
    seaweedfs-s3: {hosts: {s3-c: {}}}
    docker: {hosts: {dashboard-a: {}, query-b: {}, s3-c: {}, unrelated-d: {}}}
`
	if err := os.WriteFile(inv, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	// Real Ansible inventory/list-hosts resolution, with no SSH or mutation.
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skip("ansible unavailable")
	}
	ctx := context.Background()
	plan, err := prepareReconcileExecutionPlan(ctx, "playbooks/apply/dashboard-apply.yml", inv, "dashboard-a", "C8", []string{"target_group=dashboard-a", "stage=sandbox"}, vaultInput{}, []string{"dashboard"})
	if err != nil {
		t.Fatal(err)
	}
	if got := contractIDs(plan.Chain); !reflect.DeepEqual(got, []string{"docker", "thanos-query"}) {
		t.Fatalf("chain=%v", got)
	}
	if plan.DependencyLimits["docker"] != "dashboard-a,query-b" || plan.DependencyLimits["thanos-query"] != "query-b" {
		t.Fatalf("limits=%v", plan.DependencyLimits)
	}
	if got := extraVarValue(plan.DependencyExtraVars["thanos-query"], "thanos_s3_target_host"); got != "s3.example.internal" {
		t.Fatalf("S3 binding=%q", got)
	}
	if got := extraVarValue(plan.ExtraVars, "thanos_query_target_host"); got != "query.example.internal" {
		t.Fatalf("Query binding=%q", got)
	}
	if got := extraVarValue(plan.DependencyExtraVars["thanos-query"], "target_group"); got != "thanos-query" {
		t.Fatalf("dependency retargeted=%q", got)
	}
	if strings.Contains(plan.DependencyLimits["docker"], "s3-c") || strings.Contains(plan.DependencyLimits["docker"], "unrelated-d") {
		t.Fatal("expanded mutation to support/unrelated hosts")
	}
}

// TestManagedProviderWorkflowExecutionAndFailures drives both entry points
// for dashboard with --limit on the consumer only: Docker on the consumer and
// the provider, then Thanos Query on the provider (two hops outside the
// limit), then dashboard. The operator's vars file sets target_group to the
// dashboard group, as in the PR #39 review; every dependency run must still
// end with its own target_group after that file. A provider run whose PLAY
// RECAP names no host fails the plan instead of being recorded as applied.
func TestManagedProviderWorkflowExecutionAndFailures(t *testing.T) {
	for _, workflow := range []string{"deploy", "reconcile"} {
		for _, mode := range []string{"success", "provider-fails", "provider-matches-no-host", "cancel"} {
			t.Run(workflow+"/"+mode, func(t *testing.T) {
				root := repoRootForTest(t)
				fixtureRoot := t.TempDir()
				if err := os.MkdirAll(filepath.Join(fixtureRoot, "contracts"), 0700); err != nil {
					t.Fatal(err)
				}
				// This test exercises runner order/authorization, not service
				// checks. The real CLI/VM test retains production auto-verify.
				for _, id := range []string{"docker", "dashboard", "thanos-query", "seaweedfs-s3"} {
					data, err := os.ReadFile(filepath.Join(root, "contracts", id+".yaml"))
					if err != nil {
						t.Fatal(err)
					}
					var c contract.Contract
					if err := yaml.Unmarshal(data, &c); err != nil {
						t.Fatal(err)
					}
					noVerify := false
					c.Verification.AutoDeploy = &noVerify
					data, err = yaml.Marshal(c)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(fixtureRoot, "contracts", id+".yaml"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PILOT_ROOT", fixtureRoot)
				t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
				t.Setenv("ANSIBLE_CACHE_PLUGIN", "memory")
				dataDir = t.TempDir()
				t.Cleanup(func() { dataDir = "" })
				realAnsible, err := exec.LookPath("ansible")
				if err != nil {
					t.Skip("ansible unavailable")
				}
				bin := t.TempDir()
				// List-hosts runs the real inventory resolver; SSH/facts are
				// replaced with a deterministic fixture for this runner test.
				script := fmt.Sprintf("#!/bin/sh\ncase \"$*\" in\n*--list-hosts*) exec %q \"$@\" ;;\n*) printf '{\"plays\":[{\"tasks\":[{\"hosts\":{\"consumer-a\":{\"stdout\":\"unknown\",\"rc\":0}}}]}]}\\n' ;;\nesac\n", realAnsible)
				if err := os.WriteFile(filepath.Join(bin, "ansible"), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				inv := filepath.Join(t.TempDir(), "inventory.yml")
				raw := `all:
  hosts:
    consumer-a: {ansible_host: dashboard.example.internal}
    provider-b: {ansible_host: query.example.internal}
    storage-c: {ansible_host: s3.example.internal}
    unrelated-d: {}
  children:
    dashboard: {hosts: {consumer-a: {}}}
    thanos-query: {hosts: {provider-b: {}}}
    seaweedfs-s3: {hosts: {storage-c: {}}}
    docker: {hosts: {consumer-a: {}, provider-b: {}, storage-c: {}, unrelated-d: {}}}
`
				if err := os.WriteFile(inv, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				argsFile := filepath.Join(t.TempDir(), "args")
				runner := ansible.NewRunner()
				runner.Timeout = 10 * time.Second
				runner.Binary = writeArgsFixture(t, argsFile)
				if mode == "provider-fails" {
					fixture, _ := os.ReadFile(runner.Binary)
					fixture = append(fixture, []byte("case \"$*\" in *thanos-query-apply.yml*) exit 7 ;; esac\n")...)
					if err := os.WriteFile(runner.Binary, fixture, 0755); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "provider-matches-no-host" {
					// ansible-playbook's output when the play's hosts and
					// --limit do not intersect: an empty recap, exit 0.
					fixture, _ := os.ReadFile(runner.Binary)
					noMatch := "case \"$*\" in *thanos-query-apply.yml*) printf 'PLAY RECAP ****\\n'; exit 0 ;; esac\n"
					fixture = []byte(strings.Replace(string(fixture), fakePlayRecapScript, noMatch+fakePlayRecapScript, 1))
					if err := os.WriteFile(runner.Binary, fixture, 0755); err != nil {
						t.Fatal(err)
					}
				}
				varsFile := filepath.Join(t.TempDir(), "vars.yml")
				if err := os.WriteFile(varsFile, []byte("target_group: dashboard\n"), 0600); err != nil {
					t.Fatal(err)
				}
				confirm := mode != "cancel"
				no := false
				old := activePromptAutomation
				activePromptAutomation = &promptAutomation{answers: []promptAnswer{
					{Prompt: "要先跑前置檢查(preflight)嗎？", Select: "跳過前置檢查"},
					{Prompt: "要先對此計畫中的所有 playbook 預覽", Confirm: &no},
					{Prompt: "確認：若所有前置檢查與預覽都成功", Confirm: &confirm},
				}}
				t.Cleanup(func() { activePromptAutomation = old })
				stubDeploymentAvailabilityAllReachable(t)
				request := catalogDeploymentRequest{playbook: "playbooks/apply/dashboard-apply.yml", inv: inv, limit: "consumer-a", tags: "C8", extraVars: []string{"target_group=consumer-a", "stage=sandbox"}, vault: vaultInput{ExtraVarsFile: varsFile}, stage: "sandbox", componentHints: []string{"dashboard"}}
				var out bytes.Buffer
				// Bound the whole workflow, including several real Ansible
				// inventory/list-hosts startups on slower CI hosts. This is a
				// hang watchdog, not a latency assertion.
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if workflow == "deploy" {
					err = executeRecordedDeployment(ctx, runner, &out, request.playbook, inv, request.limit, request.tags, request.extraVars, request.vault, request.stage, request.componentHints)
				} else {
					err = executeCatalogReconcileBatch(ctx, runner, &out, []catalogDeploymentRequest{request})
				}
				if mode == "success" && err != nil {
					t.Fatalf("%v\n%s", err, out.String())
				}
				if mode != "success" && err == nil {
					t.Fatal("failure/cancellation ignored")
				}
				if mode == "provider-matches-no-host" && !strings.Contains(err.Error(), "沒有比對到任何預定主機") {
					t.Fatalf("provider run that matched no host: err = %v", err)
				}
				if len(activePromptAutomation.answers) != 0 || activePromptAutomation.err != nil {
					t.Fatalf("unexpected prompts: %+v", activePromptAutomation)
				}
				args, readErr := os.ReadFile(argsFile)
				if mode == "cancel" {
					if !os.IsNotExist(readErr) {
						t.Fatalf("cancel ran apply: %s %v", args, readErr)
					}
					return
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				lines := strings.Split(strings.TrimSpace(string(args)), "\n")
				providerFails := mode == "provider-fails" || mode == "provider-matches-no-host"
				wantRuns := 3
				if providerFails {
					wantRuns = 2
				}
				if len(lines) != wantRuns {
					t.Fatalf("runs=%q want=%d", lines, wantRuns)
				}
				if !strings.Contains(lines[0], "docker-apply.yml") || !strings.Contains(lines[0], "--limit consumer-a,provider-b") {
					t.Fatalf("Docker scope=%s", lines[0])
				}
				if !strings.Contains(lines[1], "thanos-query-apply.yml") || !strings.Contains(lines[1], "--limit provider-b") || !strings.Contains(lines[1], "target_group=thanos-query") {
					t.Fatalf("Query scope=%s", lines[1])
				}
				for _, line := range lines[:2] {
					if strings.Contains(line, "--tags") || strings.Contains(line, "unrelated-d") || strings.Contains(line, "--limit storage-c") {
						t.Fatalf("dependency inherited unsafe scope/tags: %s", line)
					}
				}
				// Ansible gives the last -e precedence: each run's own
				// target_group must come after the operator's vars file.
				for i, group := range []string{"docker", "thanos-query", "consumer-a"} {
					if i >= len(lines) {
						break
					}
					varsAt := strings.Index(lines[i], "-e @"+varsFile)
					lastAt := strings.LastIndex(lines[i], "-e target_group=")
					if varsAt < 0 || lastAt < varsAt || strings.Fields(lines[i][lastAt:])[1] != "target_group="+group {
						t.Fatalf("run %d: the vars file can override target_group=%s: %s", i, group, lines[i])
					}
				}
				if mode == "success" && (!strings.Contains(lines[2], "dashboard-apply.yml") || !strings.Contains(lines[2], "--tags C8")) {
					t.Fatalf("consumer=%s", lines[2])
				}
				if providerFails {
					st, err := store.Open(filepath.Join(dataDir, "history.db"))
					if err != nil {
						t.Fatal(err)
					}
					defer st.Close()
					for id, want := range map[string]string{"docker": "success", "thanos-query": "failed"} {
						runs, err := st.ListRuns(store.RunFilter{Component: id})
						if err != nil || len(runs) != 1 || runs[0].Outcome != want {
							t.Fatalf("%s runs=%+v err=%v", id, runs, err)
						}
					}
					runs, err := st.ListRuns(store.RunFilter{Component: "dashboard"})
					if err != nil || len(runs) != 0 {
						t.Fatalf("consumer started after failure: %+v %v", runs, err)
					}
				}
			})
		}
	}
}

func TestAppliedBeforeConsumer(t *testing.T) {
	for _, tc := range []struct {
		dep              contract.Dependency
		managedProviders bool
		want             bool
	}{
		{contract.Dependency{Required: true, Relation: "sameHosts"}, false, true},
		{contract.Dependency{Required: true, Relation: "sameHosts"}, true, true},
		{contract.Dependency{Required: false, Relation: "sameHosts"}, true, false},
		{contract.Dependency{Required: true, Relation: "providerEndpoint", ApplyBeforeConsumer: true}, true, true},
		{contract.Dependency{Required: true, Relation: "providerEndpoint", ApplyBeforeConsumer: true}, false, false},
		{contract.Dependency{Required: true, Relation: "providerEndpoint"}, true, false},
		{contract.Dependency{Required: false, Relation: "providerEndpoint", ApplyBeforeConsumer: true}, true, false},
		{contract.Dependency{Required: true, Relation: "other", ApplyBeforeConsumer: true}, true, false},
	} {
		if got := appliedBeforeConsumer(tc.dep, tc.managedProviders); got != tc.want {
			t.Errorf("appliedBeforeConsumer(%+v, %v) = %v, want %v", tc.dep, tc.managedProviders, got, tc.want)
		}
	}
}
