package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The no-ssh precheck of the identity lock target (checkIdentityLockTarget;
// docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.2).
//
// The lock is the last thing a funnel does before its playbook, and refusing an
// inventory only there leaves a decommission with the client uninstalled and the
// roster entry tombstoned, a deploy after its freeipa-server dependency and
// `--check`, a drift repair after its probe. These tests run every funnel
// against an inventory whose freeipa-server host the lock cannot be taken
// through (ProxyCommand, a docker connection, a password, an option outside the
// allowlist, the ssh executable) with the production precheck, the real `ansible`
// and `ansible-inventory`, and recorders in place of `ansible-playbook` and
// `ssh`: each funnel must refuse, name the variable, and have run nothing. The
// same funnel on a supported inventory goes on (the other direction of each
// check, AGENTS.md §5.12).

// refusedByTheLock are the ways an inventory refuses the lock, with what the
// refusal must name. They are the same rows as
// TestProductionIdentityLockRefusesWhatItCannotReach: one rule, two moments.
var refusedByTheLock = []struct {
	name   string
	vars   string
	wantIn string
}{
	{"ProxyCommand", "          ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n", "ProxyCommand"},
	{"a docker connection", "          ansible_connection: docker\n", "ansible_connection 是 docker"},
	{"a connection password", "          ansible_ssh_pass: sentinel-not-a-credential\n", "設定了 ansible_ssh_pass"},
	{"an option outside the allowlist", "          ansible_ssh_common_args: \"-o ForwardAgent=yes\"\n", "ForwardAgent"},
	{"the ssh executable", "          ansible_ssh_executable: /usr/local/bin/other-ssh\n", "設定了 ansible_ssh_executable"},
}

const proxyCommandVars = "          ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n"

// funnelEnv is a real inventory whose freeipa-server host has serverVars, with
// recorders for everything that must not run on a refusal: an `ansible-playbook`
// and an `ssh` on PATH that only log their arguments, and the lock's dialer seam
// aimed at a fake ssh in a temporary directory.
type funnelEnv struct {
	t    *testing.T
	inv  string
	log  string
	seam *dialerSeam
}

func newFunnelEnv(t *testing.T, serverVars string) *funnelEnv {
	t.Helper()
	inv := writeLockInventory(t, serverVars)
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	for _, name := range []string{"ansible-playbook", "ssh"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + log + "'\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	oldData := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = oldData })
	return &funnelEnv{t: t, inv: inv, log: log, seam: useLocalLockDialer(t)}
}

// ran is what the recorders saw.
func (e *funnelEnv) ran() []string { return readEvents(e.t, e.log) }

// assertRefused: the run failed with the precheck's refusal, naming the
// variable, and nothing ran: no ansible-playbook, no ssh, no lock taken.
func (e *funnelEnv) assertRefused(err error, out string, wantIn string) {
	e.t.Helper()
	if err == nil {
		e.t.Fatalf("the funnel went on with an inventory the lock cannot be taken through\n%s", out)
	}
	for _, want := range []string{"取鎖前檢查沒有通過", "ipa-1", wantIn} {
		if !strings.Contains(err.Error(), want) {
			e.t.Fatalf("err = %v, want it to hold %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "sentinel-not-a-credential") {
		e.t.Fatalf("the refusal shows a password: %v", err)
	}
	if got := e.ran(); len(got) != 0 {
		e.t.Fatalf("the funnel ran %q before refusing", got)
	}
	if got := e.seam.started(); len(got) != 0 {
		e.t.Fatalf("an ssh for the lock was started before the refusal: %+v", got)
	}
}

// assertWentOn: the funnel did not stop at the precheck.
func (e *funnelEnv) assertWentOn(err error) {
	e.t.Helper()
	if err != nil && strings.Contains(err.Error(), "取鎖前檢查") {
		e.t.Fatalf("a supported inventory was refused by the precheck: %v", err)
	}
}

// funnelRun is one funnel, run the way an operator does, against env.
type funnelRun struct {
	name string
	run  func(t *testing.T, env *funnelEnv) (string, error)
}

func cliFunnelRuns() []funnelRun {
	return []funnelRun{
		{"pilot access reconcile --once", func(t *testing.T, env *funnelEnv) (string, error) {
			roster := writeAccessCLIFixture(t, accessCLIFixtureRoster)
			return runCLI(t, "access", "reconcile", roster, "--once", "--inventory", env.inv)
		}},
		{"pilot access breakglass activate", func(t *testing.T, env *funnelEnv) (string, error) {
			roster := writeAccessCLIFixture(t, accessBreakglassCLIFixtureRoster)
			return runCLI(t, "access", "breakglass", "activate", roster, "infra-emergency", "--duration", "30m", "--reason", "t", "--ticket", "T-1", "--inventory", env.inv)
		}},
		{"pilot access breakglass deactivate", func(t *testing.T, env *funnelEnv) (string, error) {
			roster := writeAccessCLIFixture(t, accessBreakglassCLIFixtureRoster)
			return runCLI(t, "access", "breakglass", "deactivate", roster, "infra-emergency", "--inventory", env.inv)
		}},
		{"pilot access drift --repair-managed", func(t *testing.T, env *funnelEnv) (string, error) {
			resetDriftCmdState(t)
			ws := newDriftWorkspace(t, "")
			return runDriftCmd(t, "access", "drift", ws.roster, "-i", env.inv, "--repair-managed")
		}},
		{"pilot identity drift --repair-managed", func(t *testing.T, env *funnelEnv) (string, error) {
			resetDriftCmdState(t)
			ws := newDriftWorkspace(t, "")
			return runDriftCmd(t, "identity", "drift", ws.roster, "-i", env.inv, "--repair-managed")
		}},
	}
}

// Every command line funnel refuses an inventory the lock cannot be taken
// through, for every kind of refusal, before it runs or connects to anything.
// The funnels that were refused only at the lock used to run their probe (the
// drift repairs) or their capability check (reconcile) first.
func TestEveryCLIFunnelRefusesAnUnlockableInventoryBeforeRunningAnything(t *testing.T) {
	for _, funnel := range cliFunnelRuns() {
		for _, refusal := range refusedByTheLock {
			t.Run(funnel.name+"/"+refusal.name, func(t *testing.T) {
				env := newFunnelEnv(t, refusal.vars)
				out, err := funnel.run(t, env)
				env.assertRefused(err, out, refusal.wantIn)
			})
		}
	}
}

// The other direction: the same funnels on an inventory the lock can be taken
// through are not stopped by the precheck. They run their playbook, and take the
// real lock (the production Acquirer, flock on a local path) around it. A drift
// repair that finds no drift has nothing to repair and takes no lock: what it
// shows is that it got as far as its probe.
func TestEveryCLIFunnelWithALockableInventoryGoesOn(t *testing.T) {
	for _, funnel := range cliFunnelRuns() {
		t.Run(funnel.name, func(t *testing.T) {
			env := newFunnelEnv(t, lockCommonArgs)
			out, err := funnel.run(t, env)
			env.assertWentOn(err)
			if got := env.ran(); len(got) == 0 {
				t.Fatalf("the funnel never ran its playbook (err = %v)\n%s", err, out)
			}
			if strings.Contains(funnel.name, "drift") {
				return
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if got := env.seam.started(); len(got) != 1 {
				t.Fatalf("the funnel started %d lock sessions, want 1: %+v", len(got), got)
			}
			if env.seam.held(t) {
				t.Fatal("the lock is still held after the funnel returned")
			}
		})
	}
}

// The pilot edit TUI's break-glass screens: the same refusal, shown in the
// screen's banner, and no lock built and no playbook run.
func TestTUIBreakglassIsRefusedBeforeAnythingRuns(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	oldData := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldData })
	calls := filepath.Join(t.TempDir(), "calls.log")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte("#!/bin/sh\necho \"ansible-playbook $*\" >> '"+calls+"'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	lock := useFakeIdentityLock(t)
	lock.PrecheckErr = errors.New("不能對 ipa-1 取 FreeIPA 的 /etc/ipa 鎖：ProxyCommand")

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "emergency-admin"},
		{Action: "create_hostgroup", Name: "prodweb"},
		{Action: "create_grant", Name: "infra-emergency", Kind: "breakglass", Users: []string{"emergency-admin"}, Hostgroups: []string{"prodweb"}, Services: []string{"sshd"}, MaxDuration: "1h"},
	}}); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() error{
		"activate":   func() error { return d.activateBreakglass(&r, "infra-emergency", "30m", "outage", "INC-1") },
		"deactivate": func() error { return d.deactivateBreakglass(&r, "infra-emergency") },
	} {
		if err := run(); err != nil {
			t.Fatalf("%s: navigation error %v", name, err)
		}
		if !strings.HasPrefix(r.banner, "❌") || !strings.Contains(r.banner, "取鎖前檢查沒有通過") || !strings.Contains(r.banner, "ProxyCommand") {
			t.Fatalf("%s: banner = %q, want the precheck's refusal", name, r.banner)
		}
	}
	if got := lock.Prechecks(); len(got) != 2 || got[0].Wait != 0 || got[0].Inventory != accessGovernanceInventoryPath(dir) {
		t.Fatalf("prechecks = %+v, want one per screen action, for the workspace's inventory, not waiting", got)
	}
	if reqs := lock.Requests(); len(reqs) != 0 || lock.Acquired() != 0 {
		t.Fatalf("a lock was built (%+v) or taken (%d) although the precheck refused", reqs, lock.Acquired())
	}
	if got := readEvents(t, calls); len(got) != 0 {
		t.Fatalf("a refused TUI action ran %q", got)
	}
}

// The TUI's Acquirer, on the real inventory: refused with the variable named
// and no lock session, accepted when the inventory is fine.
func TestTUIIdentityLockForOnARealInventory(t *testing.T) {
	for _, refusal := range refusedByTheLock {
		t.Run(refusal.name, func(t *testing.T) {
			env := newFunnelEnv(t, refusal.vars)
			_, err := tuiIdentityLockFor(context.Background(), env.inv)
			env.assertRefused(err, "", refusal.wantIn)
		})
	}
	env := newFunnelEnv(t, lockCommonArgs)
	acquire, err := tuiIdentityLockFor(context.Background(), env.inv)
	if err != nil {
		t.Fatal(err)
	}
	held, err := acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = held.Release()
}

// pilot deploy and pilot reconcile, ansible engine: the refusal comes before the
// plan is shown, the freeipa-server dependency is applied, the preflight pings
// anything or a preview runs, and --preview-only is refused exactly as --force
// is (a green preview predicts the real run).
func TestDeployAndReconcileRefuseAnUnlockableInventoryBeforeAnything(t *testing.T) {
	const playbook = "playbooks/apply/freeipa-identity-apply.yml"
	for _, refusal := range refusedByTheLock {
		for name, auth := range map[string]*deploymentAuthorization{
			"deploy":                   nil,
			"reconcile --force":        {Preview: false},
			"reconcile --preview-only": {Preview: true, PreviewOnly: true},
		} {
			t.Run(name+"/"+refusal.name, func(t *testing.T) {
				env := newFunnelEnv(t, refusal.vars)
				t.Setenv("PILOT_ROOT", repoRootForTest(t))
				oldPrompt := activePromptAutomation
				activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: true}
				t.Cleanup(func() { activePromptAutomation = oldPrompt })
				stubDeploymentAvailabilityAllReachable(t)
				var out bytes.Buffer
				_, err := executeRecordedDeploymentWithAuthorizationResult(context.Background(), ansible.NewRunner(), &out, playbook, env.inv, "", "", nil, vaultInput{}, "sandbox", []string{"freeipa-identity"}, auth, nil)
				env.assertRefused(err, out.String(), refusal.wantIn)
				if strings.Contains(out.String(), "Deployment execution plan") || strings.Contains(out.String(), "依賴串接") {
					t.Fatalf("the plan was shown or the dependency chain started before the refusal:\n%s", out.String())
				}
			})
		}
	}

	t.Run("a batch (several selected items, one authorization) is refused before its plan is shown or asked", func(t *testing.T) {
		env := newFunnelEnv(t, proxyCommandVars)
		t.Setenv("PILOT_ROOT", repoRootForTest(t))
		oldPrompt := activePromptAutomation
		activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
		t.Cleanup(func() { activePromptAutomation = oldPrompt })
		stubDeploymentAvailabilityAllReachable(t)
		var out bytes.Buffer
		err := executeCatalogReconcileBatch(context.Background(), ansible.NewRunner(), &out, []catalogDeploymentRequest{{
			playbook: playbook, inv: env.inv, stage: "sandbox", componentHints: []string{"freeipa-identity"}, workspaceDir: filepath.Dir(env.inv),
		}})
		env.assertRefused(err, out.String(), "ProxyCommand")
		if strings.Contains(out.String(), "batch execution plan") {
			t.Fatalf("the batch plan was shown before the refusal:\n%s", out.String())
		}
	})

	t.Run("another playbook is not asked", func(t *testing.T) {
		env := newFunnelEnv(t, proxyCommandVars)
		t.Setenv("PILOT_ROOT", repoRootForTest(t))
		catalog := loadRepoCatalogForPrecheck(t)
		if err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-dns"}, "playbooks/apply/freeipa-dns-apply.yml", env.inv, "", nil); err != nil {
			t.Fatalf("a component that is not the identity playbook was refused: %v", err)
		}
	})
}

func loadRepoCatalogForPrecheck(t *testing.T) contract.Catalog {
	t.Helper()
	loader, err := contract.NewLoader(repoRootForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// The other direction for the deploy runner: on a supported inventory the
// precheck passes, for the same candidates the lock is later taken for, and
// it follows --limit and target_group the way the run does.
func TestDeployPrecheckPassesALockableInventoryAndFollowsTheScope(t *testing.T) {
	const playbook = "playbooks/apply/freeipa-identity-apply.yml"
	env := newFunnelEnv(t, lockCommonArgs)
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	catalog := loadRepoCatalogForPrecheck(t)
	if err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, playbook, env.inv, "", nil); err != nil {
		t.Fatalf("a supported inventory was refused: %v", err)
	}

	// Two servers: the lock needs exactly one, and the contract does too.
	two := strings.Replace(lockInventory, "        ipa-1:", "        ipa-2:\n          ansible_host: 192.0.2.11\n        ipa-1:", 1)
	if err := os.WriteFile(env.inv, []byte(two), 0o600); err != nil {
		t.Fatal(err)
	}
	err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, playbook, env.inv, "", nil)
	if err == nil || !strings.Contains(err.Error(), "剛好一台 freeipa-server") {
		t.Fatalf("two servers: err = %v, want the exactly-one refusal", err)
	}
	// --limit narrows it to one, as it does for the run.
	if err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, playbook, env.inv, "ipa-1", nil); err != nil {
		t.Fatalf("--limit ipa-1: %v", err)
	}
	// A server the limit leaves out is not asked about: ipa-2 is the one with the
	// refusing variable here.
	bad := strings.Replace(two, "        ipa-2:\n          ansible_host: 192.0.2.11\n", "        ipa-2:\n          ansible_host: 192.0.2.11\n          ansible_connection: docker\n", 1)
	if err := os.WriteFile(env.inv, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, playbook, env.inv, "ipa-1", nil); err != nil {
		t.Fatalf("--limit ipa-1 with a refusing ipa-2 outside the limit: %v", err)
	}
	err = precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, playbook, env.inv, "ipa-2", nil)
	if err == nil || !strings.Contains(err.Error(), "ansible_connection 是 docker") {
		t.Fatalf("--limit ipa-2: err = %v, want the docker refusal", err)
	}
}

// The candidates the precheck asks about are the hosts of the scope before
// availability: the hosts the apply step locks (the included ones) are a subset.
func TestDeploymentCandidateHostsContainTheAppliedHosts(t *testing.T) {
	applied := []contract.Contract{{ID: "freeipa-identity", Role: "freeipa-server"}}
	scope := delivery.Scope{HostsByRole: map[string][]string{
		"freeipa-server": {"ipa-2", "ipa-1", "localhost"},
		"docker":         {"docker-1"},
	}}
	got := deploymentCandidateHosts(applied, scope)
	if strings.Join(got, ",") != "ipa-1,ipa-2" {
		t.Fatalf("candidates = %v, want the applied component's role hosts, sorted, without localhost", got)
	}
	for _, included := range [][]string{{"ipa-1", "ipa-2"}, {"ipa-2"}, {}} {
		applied := deploymentAppliedHosts(applied, scope, included)
		for _, host := range applied {
			found := false
			for _, c := range got {
				found = found || c == host
			}
			if !found {
				t.Fatalf("applied host %s is not a candidate %v", host, got)
			}
		}
	}
}

// pilot host decommission: the refusal comes in apply and resume before the
// first step, before the approval is recorded, so the client is not uninstalled
// and the roster entry is not tombstoned by a run that cannot reach its converge
// step. The inventory goes through the real hosts.yml -> inventory.yml
// generation and the real ansible-inventory.
func decommissionWorkspace(t *testing.T, serverVars string) (ws string, plan *decommission.Plan) {
	t.Helper()
	for _, tool := range []string{"ansible", "ansible-inventory", "flock"} {
		mustLookPath(t, tool)
	}
	t.Setenv("ANSIBLE_HOME", t.TempDir())
	t.Setenv("ANSIBLE_LOCAL_TEMP", t.TempDir())
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	ws = t.TempDir()
	hosts := `hosts:
  client1:
    ansible_host: "10.0.0.9"
    env: sandbox
    roles:
      - freeipa-client
    freeipa_roster_file: roster.yaml
  ipa-1:
    ansible_host: "192.0.2.10"
    ansible_user: root
    env: sandbox
    roles:
      - freeipa-server
    freeipa_roster_file: roster.yaml
` + serverVars
	for name, body := range map[string]string{
		"hosts.yml":   hosts,
		"roster.yaml": "schema_version: 2\nfreeipa: {server: ipa1.ipa.pilot.internal}\n",
	} {
		if err := os.WriteFile(filepath.Join(ws, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	plan = &decommission.Plan{
		ID: "hd-precheck-1", Status: decommission.PlanStatusExecutable,
		Host:        decommission.HostSnapshot{Name: "client1", AnsibleHost: "10.0.0.9", Env: "sandbox", Roles: []string{"freeipa-client"}},
		Environment: "sandbox", PlanHash: "hash-precheck-1",
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		Components: []decommission.ComponentPlan{{
			Role: "freeipa-client", ComponentID: providers.FreeIPAClientProviderID, ProviderRegistered: true,
			Steps: []providers.Step{
				{Provider: providers.FreeIPAClientProviderID, Phase: "local_cleanup", Action: providers.ActionFreeIPAClientUninstall, TargetIdentity: "client1",
					Params: map[string]string{"retirement_fqdn": "client1.ipa.pilot.internal", "inventory_alias": "client1", "retirement_stage": "sandbox"}},
				{Provider: providers.FreeIPAClientProviderID, Phase: "central_cleanup", Action: providers.ActionFreeIPARosterHostAbsent, TargetIdentity: "client1.ipa.pilot.internal",
					Params: map[string]string{"inventory_alias": "client1", "retirement_stage": "sandbox"}},
				{Provider: providers.FreeIPAClientProviderID, Phase: "central_cleanup", Action: providers.ActionFreeIPAIdentityApplyConverge, TargetIdentity: "client1.ipa.pilot.internal",
					Params: map[string]string{"inventory_alias": "client1", "retirement_stage": "sandbox"}},
			},
		}},
	}
	return ws, plan
}

func mustLookPath(t *testing.T, tool string) string {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Skipf("%s is not installed", tool)
	}
	return path
}

func savePrecheckPlan(t *testing.T, plan *decommission.Plan, approved bool) {
	t.Helper()
	st, err := openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)
	if err := ds.SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	if approved {
		if err := ds.RecordApproval(plan.ID, plan.PlanHash, "tester", "approve", "a prior apply attempt", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDecommissionApplyAndResumeRefuseAnUnlockableInventoryBeforeTheFirstStep(t *testing.T) {
	for _, refusal := range refusedByTheLock {
		t.Run(refusal.name, func(t *testing.T) {
			env := newFunnelEnv(t, "")
			ws, plan := decommissionWorkspace(t, "    ansible_ssh_extra_args: \"-o ProxyCommand=nc\"\n")
			// The refusals other than ProxyCommand are written the way hosts.yml
			// spells a host variable.
			switch refusal.name {
			case "a docker connection":
				ws, plan = decommissionWorkspace(t, "    ansible_connection: docker\n")
			case "a connection password":
				ws, plan = decommissionWorkspace(t, "    ansible_ssh_pass: sentinel-not-a-credential\n")
			case "an option outside the allowlist":
				ws, plan = decommissionWorkspace(t, "    ansible_ssh_common_args: \"-o ForwardAgent=yes\"\n")
			case "the ssh executable":
				ws, plan = decommissionWorkspace(t, "    ansible_ssh_executable: /usr/local/bin/other-ssh\n")
			}
			savePrecheckPlan(t, plan, false)
			t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })

			out, err := runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", plan.ID, "--confirm-host", "client1")
			env.assertRefused(err, out, refusal.wantIn)
			if planApproved(t, plan.ID) {
				t.Fatal("a refused apply recorded an approval")
			}

			// Resume, after an earlier attempt that did record its approval, is
			// refused the same way, before its first step.
			savePrecheckPlan(t, plan, true)
			out, err = runPilotForTest(t, "host", "decommission", "resume", "--dir", ws, "--id", plan.ID)
			env.assertRefused(err, out, refusal.wantIn)
		})
	}
}

// The other direction: on a supported inventory apply goes past the precheck.
// It records its approval and hands the plan to decommission.Apply, which here
// refuses the hand-built plan as stale (its hash is not one PlanHost derived):
// reaching that refusal is what shows the precheck let the run through.
func TestDecommissionApplyWithALockableInventoryGoesOn(t *testing.T) {
	env := newFunnelEnv(t, "")
	ws, plan := decommissionWorkspace(t, "")
	savePrecheckPlan(t, plan, false)
	t.Cleanup(func() { _, _ = runPilotForTest(t, "--help") })
	out, err := runPilotForTest(t, "host", "decommission", "apply", "--dir", ws, "--id", plan.ID, "--confirm-host", "client1")
	env.assertWentOn(err)
	if err == nil || !strings.Contains(err.Error(), "plan_stale") {
		t.Fatalf("err = %v, want decommission.Apply's own refusal of the hand-built plan\n%s", err, out)
	}
	if !planApproved(t, plan.ID) {
		t.Fatal("apply on a supported inventory did not record its approval")
	}
}

func TestDecommissionPrecheckAsksOnlyPlansThatRunTheConvergeStep(t *testing.T) {
	lock := useFakeIdentityLock(t)
	lock.PrecheckErr = errors.New("refused")
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	withConverge := &decommission.Plan{Components: []decommission.ComponentPlan{{Steps: []providers.Step{
		{Provider: providers.FreeIPAClientProviderID, Action: providers.ActionFreeIPAClientUninstall},
		{Provider: providers.FreeIPAClientProviderID, Action: providers.ActionFreeIPAIdentityApplyConverge},
	}}}}
	if err := precheckHostDecommissionIdentityLock(context.Background(), t.TempDir(), withConverge); err == nil {
		t.Fatal("a plan with the converge step was not refused by a refusing precheck")
	}
	for name, plan := range map[string]*decommission.Plan{
		"no components": {},
		"only the uninstall and the roster tombstone": {Components: []decommission.ComponentPlan{{Steps: []providers.Step{
			{Provider: providers.FreeIPAClientProviderID, Action: providers.ActionFreeIPAClientUninstall},
			{Provider: providers.FreeIPAClientProviderID, Action: providers.ActionFreeIPARosterHostAbsent},
		}}}},
		"another provider's converge-looking step": {Components: []decommission.ComponentPlan{{Steps: []providers.Step{
			{Provider: providers.InternalEndpointProviderID, Action: providers.ActionFreeIPAIdentityApplyConverge},
		}}}},
	} {
		if err := precheckHostDecommissionIdentityLock(context.Background(), t.TempDir(), plan); err != nil {
			t.Errorf("%s: asked about a lock the plan never takes: %v", name, err)
		}
	}
	if n := len(lock.Prechecks()); n != 1 {
		t.Fatalf("the precheck was asked %d times, want only for the plan with the converge step", n)
	}
}

// decommission plan: reports an unlockable inventory as a warning on stderr
// and not as a blocker (the plan is saved and exits 0), only for a plan that
// would run the converge step.
func TestDecommissionPlanWarnsAboutAnUnlockableInventory(t *testing.T) {
	env := newFunnelEnv(t, "")
	ws, plan := decommissionWorkspace(t, "    ansible_ssh_extra_args: \"-o ProxyCommand=nc\"\n")
	if _, err := buildHostDecommissionProviders(ws, "client1", loadRepoCatalogForPrecheck(t), &bytes.Buffer{}, noStageAuthorization()); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	warnIfDecommissionIsUnlockable(context.Background(), &stderr, ws, plan)
	for _, want := range []string{"⚠️", "apply／resume 會拒絕這份計畫", "取鎖前檢查沒有通過", "ProxyCommand"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("warning = %q, want it to hold %q", stderr.String(), want)
		}
	}
	if plan.Blocked() {
		t.Fatal("the warning turned the plan into a blocked one: it must stay a warning")
	}
	// Nothing to warn about: a blocked plan (apply is not possible anyway), a plan
	// without the converge step, or a supported inventory.
	stderr.Reset()
	blocked := *plan
	blocked.Blockers = []decommission.Blocker{{Code: decommission.ErrPlanStale, Detail: "some other blocker"}}
	warnIfDecommissionIsUnlockable(context.Background(), &stderr, ws, &blocked)
	plain := *plan
	plain.Components = nil
	warnIfDecommissionIsUnlockable(context.Background(), &stderr, ws, &plain)
	if stderr.Len() != 0 {
		t.Fatalf("a warning for a plan that needs none: %q", stderr.String())
	}
	good, goodPlan := decommissionWorkspace(t, "")
	if _, err := buildHostDecommissionProviders(good, "client1", loadRepoCatalogForPrecheck(t), &bytes.Buffer{}, noStageAuthorization()); err != nil {
		t.Fatal(err)
	}
	warnIfDecommissionIsUnlockable(context.Background(), &stderr, good, goodPlan)
	if stderr.Len() != 0 {
		t.Fatalf("a warning for a supported inventory: %q", stderr.String())
	}
	if got := env.ran(); len(got) != 0 {
		t.Fatalf("planning's check ran %q: it must start nothing", got)
	}
}

// The precheck and the lock are one decision: for every inventory the precheck
// refuses, taking the lock refuses with the same reason, and for every one it
// passes, the lock is taken. (AGENTS.md §5.7: a second copy of a rule drifts.)
func TestPrecheckAndLockMakeTheSameDecision(t *testing.T) {
	cases := append([]struct {
		name   string
		vars   string
		wantIn string
	}{{"a supported inventory", lockCommonArgs, ""}, {"the full name of the ssh plugin", "          ansible_connection: ansible.builtin.ssh\n", ""}}, refusedByTheLock...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newFunnelEnv(t, tc.vars)
			req := identityLockRequest{Inventory: env.inv}
			checkErr := checkIdentityLockTarget(context.Background(), req)
			held, lockErr := productionIdentityLock(req)(context.Background())
			if held != nil {
				defer func() { _ = held.Release() }()
			}
			if (checkErr == nil) != (lockErr == nil) {
				t.Fatalf("precheck: %v, lock: %v: they must agree", checkErr, lockErr)
			}
			if tc.wantIn == "" {
				if checkErr != nil {
					t.Fatalf("refused: %v", checkErr)
				}
				return
			}
			if !strings.Contains(checkErr.Error(), lockErr.Error()) {
				t.Fatalf("the precheck's reason differs from the lock's:\nprecheck: %v\nlock:     %v", checkErr, lockErr)
			}
			if !strings.Contains(checkErr.Error(), tc.wantIn) {
				t.Fatalf("err = %v, want %q", checkErr, tc.wantIn)
			}
		})
	}
}

// The seam is a test seam: the production precheck is what runs unless a test
// installs a fake, and a fake is restored.
func TestIdentityLockForRunsThePrecheckBeforeBuildingTheLock(t *testing.T) {
	var order []string
	prev, prevCheck := newIdentityLock, identityLockPrecheck
	t.Cleanup(func() { newIdentityLock, identityLockPrecheck = prev, prevCheck })
	identityLockPrecheck = func(context.Context, identityLockRequest) error {
		order = append(order, "precheck")
		return nil
	}
	newIdentityLock = func(identityLockRequest) identitylock.Acquirer {
		order = append(order, "lock")
		return func(context.Context) (*identitylock.Held, error) { return nil, nil }
	}
	if _, err := identityLockFor(context.Background(), identityLockRequest{Inventory: "i"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "precheck,lock" {
		t.Fatalf("order = %v, want the precheck first", order)
	}
	order = nil
	identityLockPrecheck = func(context.Context, identityLockRequest) error { return errors.New("refused") }
	acquirer, err := identityLockFor(context.Background(), identityLockRequest{Inventory: "i"})
	if err == nil || acquirer != nil || len(order) != 0 {
		t.Fatalf("a refusing precheck: acquirer %v, err %v, order %v: no lock may be built", acquirer, err, order)
	}
	var sshErr *sshdial.TunnelError
	if errors.As(err, &sshErr) {
		t.Fatalf("a precheck refusal is not an ssh error: %v", err)
	}
}
