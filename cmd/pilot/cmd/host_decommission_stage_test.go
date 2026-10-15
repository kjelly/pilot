package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

func TestHostDecommissionStageTargets(t *testing.T) {
	scope := decommission.NewStageScope([]inventory.Host{
		{Name: "c1", Env: "staging", Roles: []string{"freeipa-client", "wazuh-fim"}},
		{Name: "ipa", Env: "prod", Roles: []string{"freeipa-server"}},
		{Name: "wz", Roles: []string{"wazuh-manager"}},
	}, noStageAuthorization())
	plan := &decommission.Plan{
		Host: decommission.HostSnapshot{Name: "c1"},
		Components: []decommission.ComponentPlan{
			{ComponentID: "docker"},
			{ComponentID: providers.FreeIPAClientProviderID},
			{ComponentID: providers.WazuhAgentProviderID},
			{ComponentID: providers.InternalEndpointProviderID, Steps: []providers.Step{{Action: providers.ActionInternalEndpointApplyConverge}}},
		},
	}
	got := hostDecommissionStageTargets(plan, scope)
	want := [][]string{{"c1"}, {"ipa"}, {"wz"}, {"c1", "ipa", "wz"}}
	if len(got) != len(want) {
		t.Fatalf("got %d targets %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if !slices.Equal(got[i].Hosts, want[i]) {
			t.Errorf("target %d (%s) hosts = %v, want %v", i, got[i].Label, got[i].Hosts, want[i])
		}
	}

	// The login-probe target re-render runs on the login-probe hosts, so
	// their stage is what apply must have confirmation for.
	probeScope := decommission.NewStageScope([]inventory.Host{
		{Name: "c1", Roles: []string{"freeipa-client"}},
		{Name: "mon1", Env: "prod", Roles: []string{"freeipa-client", "host-monitoring", "login-probe"}},
	}, noStageAuthorization())
	probePlan := &decommission.Plan{
		Host:       decommission.HostSnapshot{Name: "c1"},
		Components: []decommission.ComponentPlan{{ComponentID: providers.LoginProbeTargetsProviderID}},
	}
	probeTargets := hostDecommissionStageTargets(probePlan, probeScope)
	if len(probeTargets) != 2 || !slices.Equal(probeTargets[1].Hosts, []string{"mon1"}) {
		t.Fatalf("login-probe targets: %+v, want the retired host then the login-probe hosts", probeTargets)
	}
	if _, err := probeScope.Args(probeTargets[1].Hosts); err == nil {
		t.Error("a prod login-probe host without --confirm-prod must refuse the re-render up front")
	}

	// Without an apply-converge step, internal-endpoint only queries, and
	// that read-only query carries no stage.
	plan.Components = []decommission.ComponentPlan{{ComponentID: providers.InternalEndpointProviderID, Steps: []providers.Step{{Action: providers.ActionInternalEndpointManifestAbsent}}}}
	if got := hostDecommissionStageTargets(plan, scope); len(got) != 1 {
		t.Errorf("internal-endpoint without apply-converge: targets = %+v, want only the retired host", got)
	}
}

// writeHostDecommissionStageFixture is writeHostDecommissionFixture with a
// docker contract that declares a decommission playbook, so plans are
// executable and apply runs the generic provider, and two hosts: web1 in
// prod and web2 with no env.
func writeHostDecommissionStageFixture(t *testing.T) (workspaceDir, ansibleLog string) {
	t.Helper()
	workspaceDir, ansibleLog, _ = writeHostDecommissionStageFixtureBin(t)
	return workspaceDir, ansibleLog
}

// writeHostDecommissionStageFixtureBin is writeHostDecommissionStageFixture
// that also returns the directory holding the fake ansible-playbook, for
// tests that replace it.
func writeHostDecommissionStageFixtureBin(t *testing.T) (workspaceDir, ansibleLog, bin string) {
	t.Helper()
	root, workspaceDir := writeHostDecommissionFixture(t)
	dockerComponent := `schemaVersion: 1
id: docker
role: docker
specs: [{path: "fake.md", rows: {all: true}}]
playbooks: {apply: "fake-apply.yml", decommission: "playbooks/decommission/docker-decommission.yml"}
dependencies: []
hostCardinality: one-or-more
resources: {minCPU: 1, minRAMMiB: 1, minDiskGiB: 1}
stagePolicy: {variable: stage, default: sandbox}
evidenceRequirement: {targetTest: vm, idempotency: required}
verification: {autoDeploy: false}
site: {include: false, order: 1, vars: {}, tags: [], optIn: true}
lifecycle:
  decommission: {class: stateless, scope: local, externalState: false, requiresReachableHost: true, retention: none}
`
	if err := os.WriteFile(filepath.Join(root, "contracts", "docker.yaml"), []byte(dockerComponent), 0o600); err != nil {
		t.Fatal(err)
	}
	hostsYAML := `hosts:
  web1:
    ansible_host: "10.0.0.5"
    env: prod
    roles: [docker]
  web2:
    ansible_host: "10.0.0.6"
    roles: [docker]
`
	if err := os.WriteFile(filepath.Join(workspaceDir, "hosts.yml"), []byte(hostsYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	// A fake ansible-playbook that records its arguments and reports the
	// component as already removed, so apply inspects, verifies and
	// finalizes without a real host.
	bin = t.TempDir()
	ansibleLog = filepath.Join(t.TempDir(), "ansible-playbook.log")
	script := "#!/bin/sh\necho \"$*\" >> '" + ansibleLog + "'\necho 'ok: [x] => {\"msg\": \"PILOT_COMPONENT_DECOMMISSIONED=true\"}'\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return workspaceDir, ansibleLog, bin
}

// runPilotForTest runs the root command with args after resetting the
// package-level flag variables the decommission commands bind, because a
// cobra flag not passed keeps the value of the previous Execute.
func runPilotForTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetHostDecommissionFlags()
	hostDecommissionApplyID, hostDecommissionApplyDir, hostDecommissionApplyConfirmHost = "", ".", ""
	hostDecommissionApplyJSON = false
	hostDecommissionApplyStage = hostDecommissionStageFlags{attestedHours: -1}
	hostDecommissionResumeStage = hostDecommissionStageFlags{attestedHours: -1}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), err
}

func planApproved(t *testing.T, planID string) bool {
	t.Helper()
	st, err := openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)
	plan, err := ds.LoadPlan(planID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ds.ApprovedForHash(plan.ID, plan.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestHostDecommissionApply_ProdHostNeedsStageConfirmation drives `pilot
// host decommission plan` and `apply` for a host in prod. Before the stage
// confirmation existed, every playbook run of such a host failed the
// playbook's environment-group cross-check (stage=sandbox against group
// prod), already at the read-only inspect step, and no flag could fix it.
func TestHostDecommissionApply_ProdHostNeedsStageConfirmation(t *testing.T) {
	ws, ansibleLog := writeHostDecommissionStageFixture(t)
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })

	out, err := runPilotForTest(t, "host", "decommission", "plan", "--dir", ws, "--host", "web1")
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	if !strings.Contains(out, "local cleanup on web1: prod — pass --confirm-prod --staging-attested-within-hours <0-168>") {
		t.Fatalf("plan output does not name the prod confirmation apply needs:\n%s", out)
	}
	planID := extractPlanID(t, out)

	out, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", planID, "--confirm-host", "web1")
	if err == nil || !strings.Contains(err.Error(), "was not started") || !strings.Contains(err.Error(), "--confirm-prod") {
		t.Fatalf("apply without --confirm-prod: err = %v, want a stage refusal naming --confirm-prod\n%s", err, out)
	}
	if _, statErr := os.Stat(ansibleLog); !os.IsNotExist(statErr) {
		t.Fatal("apply without stage confirmation ran ansible-playbook; it must refuse before any step")
	}
	if planApproved(t, planID) {
		t.Fatal("apply without stage confirmation recorded an approval")
	}

	_, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", planID, "--confirm-host", "web1", "--confirm-prod", "--staging-attested-within-hours", "200")
	if err == nil || !strings.Contains(err.Error(), "must be 0 to 168") {
		t.Fatalf("apply with a 200 h attestation: err = %v, want the 0-168 range error", err)
	}

	out, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", planID, "--confirm-host", "web1", "--confirm-prod", "--staging-attested-within-hours", "24")
	if err != nil {
		t.Fatalf("apply with prod confirmation: %v\n%s", err, out)
	}
	if !strings.Contains(out, "STATUS completed") {
		t.Fatalf("apply with prod confirmation did not complete:\n%s", out)
	}
	logged, err := os.ReadFile(ansibleLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		if !strings.Contains(line, "--limit web1") || !strings.Contains(line, "-e stage=prod -e confirm_prod=true -e staging_attested_within_hours=24") {
			t.Errorf("ansible-playbook run without the prod stage of web1: %s", line)
		}
	}
	hosts, err := os.ReadFile(filepath.Join(ws, "hosts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hosts), "web1") {
		t.Errorf("hosts.yml still lists web1 after a completed decommission:\n%s", hosts)
	}
}

// TestHostDecommissionApply_SandboxHostNeedsNoStageFlags keeps the
// sandbox path flag-free and checks it passes stage=sandbox explicitly.
func TestHostDecommissionApply_SandboxHostNeedsNoStageFlags(t *testing.T) {
	ws, ansibleLog := writeHostDecommissionStageFixture(t)
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })

	out, err := runPilotForTest(t, "host", "decommission", "plan", "--dir", ws, "--host", "web2")
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	if strings.Contains(out, "stage confirmation for apply/resume") {
		t.Errorf("plan for a sandbox host asks for stage confirmation:\n%s", out)
	}
	out, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", extractPlanID(t, out), "--confirm-host", "web2")
	if err != nil || !strings.Contains(out, "STATUS completed") {
		t.Fatalf("apply for a sandbox host: %v\n%s", err, out)
	}
	logged, err := os.ReadFile(ansibleLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "--limit web2") || !strings.Contains(string(logged), "-e stage=sandbox") {
		t.Errorf("sandbox run arguments = %q, want --limit web2 and -e stage=sandbox", logged)
	}
}

// TestHostDecommissionApply_LoginProbeReRenderGetsTheVault drives `pilot
// host decommission plan` and `apply` for a host that a login-probe host
// probes. The re-render of the probe host runs login-probe-apply.yml,
// whose always-tagged gate needs node_exporter_basic_auth_password from the
// vault; without the workspace vault that step failed on every real probe
// host (PR #80 review).
func TestHostDecommissionApply_LoginProbeReRenderGetsTheVault(t *testing.T) {
	ws, ansibleLog, bin := writeHostDecommissionStageFixtureBin(t)
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })
	hostsYAML := `hosts:
  web2:
    ansible_host: "10.0.0.6"
    roles: [docker]
  mon1:
    ansible_host: "10.0.0.7"
    roles: [docker, freeipa-client, host-monitoring, login-probe]
`
	if err := os.WriteFile(filepath.Join(ws, "hosts.yml"), []byte(hostsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(ws, ".vault", "main.yaml")
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, []byte("node_exporter_basic_auth_password: fixture-only-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The fake ansible-playbook reports web2 as a target on mon1 until the
	// re-render has run, so apply really executes the step.
	rendered := filepath.Join(t.TempDir(), "rendered")
	script := "#!/bin/sh\necho \"$*\" >> '" + ansibleLog + "'\n" +
		"case \"$*\" in *login-probe-apply.yml*) touch '" + rendered + "' ;; esac\n" +
		"if [ -f '" + rendered + "' ]; then p=false; else p=true; fi\n" +
		"echo \"ok: [mon1] => {\\\"msg\\\": \\\"LOGIN_PROBE_TARGET_PRESENT[mon1]=$p\\\"}\"\n" +
		"echo 'ok: [x] => {\"msg\": \"PILOT_COMPONENT_DECOMMISSIONED=true\"}'\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := runPilotForTest(t, "host", "decommission", "plan", "--dir", ws, "--host", "web2")
	if err != nil {
		t.Fatalf("plan: %v\n%s", err, out)
	}
	out, err = runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", extractPlanID(t, out), "--confirm-host", "web2")
	if err != nil || !strings.Contains(out, "STATUS completed") {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	logged, err := os.ReadFile(ansibleLog)
	if err != nil {
		t.Fatal(err)
	}
	var reRender string
	for _, line := range strings.Split(string(logged), "\n") {
		if strings.HasPrefix(line, "playbooks/apply/login-probe-apply.yml ") {
			reRender = line
		}
	}
	if reRender == "" {
		t.Fatalf("apply never re-rendered the login-probe host; ansible-playbook calls:\n%s", logged)
	}
	if !strings.Contains(reRender, "-e @"+vaultPath) {
		t.Errorf("login-probe re-render %q does not pass the workspace vault %s", reRender, vaultPath)
	}
	if strings.Contains(string(logged), "fixture-only-value") {
		t.Error("a vault value reached the ansible-playbook command line; only the file reference may")
	}
}
