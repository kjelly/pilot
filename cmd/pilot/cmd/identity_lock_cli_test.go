package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The wiring of the CLI funnels of the identity lock gate
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.2,
// §4.3): each command that runs freeipa-identity-apply.yml builds its lock
// request from the inventory it applies against, waits as long as its policy
// says (30 minutes by default and for the CLI commands, 0 in the TUI), and the
// lock is taken once, around the playbook, and given back after it.
// (identity_lock_funnel_test.go checks every literal of the options structs in
// cmd sets the lock; these run the commands.)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestAccessCommandsTakeTheIdentityLockAroundTheirPlaybook(t *testing.T) {
	for name, tc := range map[string]struct {
		roster string
		args   func(roster, inv string) []string
	}{
		"access reconcile --once": {accessCLIFixtureRoster, func(roster, inv string) []string {
			return []string{"access", "reconcile", roster, "--once", "--inventory", inv}
		}},
		"access breakglass activate": {accessBreakglassCLIFixtureRoster, func(roster, inv string) []string {
			return []string{"access", "breakglass", "activate", roster, "infra-emergency", "--duration", "30m", "--reason", "t", "--ticket", "T-1", "--inventory", inv}
		}},
		"access breakglass deactivate": {accessBreakglassCLIFixtureRoster, func(roster, inv string) []string {
			return []string{"access", "breakglass", "deactivate", roster, "infra-emergency", "--inventory", inv}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}}, "", 0)
			var events []string
			env.lock.Events = func(e string) { events = append(events, e) }
			roster := writeAccessCLIFixture(t, tc.roster)
			if out, err := runCLI(t, tc.args(roster, env.inv)...); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			req := onlyRequest(t, env.lock)
			if req.Inventory != env.inv || req.Hosts != nil || req.Wait != identityLockWaitDefault || req.Progress == nil {
				t.Fatalf("request = %+v: want the inventory of the command, the freeipa-server group, the 30 minute wait and a progress writer", req)
			}
			if want := []string{"lock ipa-1", "release ipa-1"}; strings.Join(events, ",") != strings.Join(want, ",") {
				t.Fatalf("lock events = %v, want %v: taken once, given back once", events, want)
			}
		})
	}
}

// A busy lock ends the command without running its playbook, and the workflow
// event says nothing was changed.
func TestAccessReconcileDoesNotRunWhenTheLockIsRefused(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}},
		reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "access.hbac"), 0)
	env.lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	ran := filepath.Join(t.TempDir(), "ran")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte("#!/bin/sh\ntouch '"+ran+"'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	roster := writeAccessCLIFixture(t, accessCLIFixtureRoster)
	_, err := runCLI(t, "access", "reconcile", roster, "--once", "--inventory", env.inv)
	if err == nil || !strings.Contains(err.Error(), "identity lock") {
		t.Fatalf("err = %v, want the lock refusal", err)
	}
	if _, statErr := os.Stat(ran); statErr == nil {
		t.Fatal("ansible-playbook ran although the lock was refused")
	}
}

// The TUI funnel: Activate and Deactivate through the screens' own helpers. It
// asks for no wait.
func TestTUIBreakglassFunnelsAskForNoWait(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}}, "", 0)
	roster := writeAccessCLIFixture(t, accessBreakglassCLIFixtureRoster)
	// The TUI calls the accessgrants API with these options: reproduce them with
	// the acquirer the TUI code builds.
	lock := tuiIdentityLock(env.inv)
	if _, err := accessgrants.Activate(context.Background(), accessgrants.ActivateOptions{
		RosterFile: roster, Inventory: env.inv, StateDir: t.TempDir(), Name: "infra-emergency",
		Duration: 30 * time.Minute, Reason: "t", Ticket: "T-1", Lock: lock,
	}); err != nil {
		t.Fatal(err)
	}
	req := onlyRequest(t, env.lock)
	if req.Wait != 0 || req.Progress != nil {
		t.Fatalf("request = %+v: the TUI funnel must fail at once and has no screen for progress", req)
	}
}

// The deploy runner, through executeRecordedDeploymentCore with the real
// catalog resolution: the lock request names the hosts the run was resolved to,
// the wait comes from the context (pilot reconcile --lock-wait), and the other
// component of the plan never locks.
func TestDeployCoreBuildsTheIdentityLockRequest(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-identity": {"host-a"}, "freeipa-dns": {"host-a"}},
		eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	catalog := loadOutboundWorkflowCatalog(t)
	runner := newRunnerWithExitCode(t, 0)

	run := func(t *testing.T, ctx context.Context, component, playbook string) {
		t.Helper()
		var requests []catalogDeploymentRequest
		entry := deployPlaybookEntry(component, playbook)
		if err := runCatalogPlaybookDeployEntry(ctx, runner, &bytes.Buffer{}, env.inv, "apply", catalog, entry, nil, deployInventorySnapshot{}, false, &requests); err != nil {
			t.Fatalf("runCatalogPlaybookDeployEntry: %v", err)
		}
	}
	t.Run("the identity component", func(t *testing.T) {
		ctx := withIdentityLockWait(context.Background(), 7*time.Minute)
		run(t, ctx, "freeipa-identity", "freeipa-identity-apply.yml")
		req := onlyRequest(t, env.lock)
		if req.Inventory != env.inv || len(req.Hosts) != 1 || req.Hosts[0] != "host-a" || req.Wait != 7*time.Minute || req.Progress == nil {
			t.Fatalf("request = %+v: want the resolved host, the context's wait and a progress writer", req)
		}
		if env.lock.Acquired() != 1 || env.lock.Released() != 1 {
			t.Fatalf("lock taken %d times, released %d", env.lock.Acquired(), env.lock.Released())
		}
	})
	t.Run("another component", func(t *testing.T) {
		before := env.lock.Acquired()
		run(t, context.Background(), "freeipa-dns", "freeipa-dns-apply.yml")
		if env.lock.Acquired() != before {
			t.Fatal("a component that is not the identity playbook took the lock")
		}
	})
}

// pilot host decommission: the provider registry it builds hands the
// central converge step the identity lock, for the inventory it generated
// and the Ansible runtime of the workspace.
func TestBuildHostDecommissionProvidersGivesTheConvergeStepTheIdentityLock(t *testing.T) {
	dir := t.TempDir()
	hostsYAML := "hosts:\n  client1:\n    ansible_host: \"10.0.0.9\"\n    env: sandbox\n    roles:\n      - freeipa-client\n    freeipa_roster_file: roster.yaml\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hostsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "roster.yaml"), []byte("schema_version: 2\nfreeipa: {server: ipa1.ipa.pilot.internal}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	events := filepath.Join(t.TempDir(), "events.log")
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"run $(basename \"$1\")\" >> '" + events + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	lock := useFakeIdentityLock(t)
	lock.Events = func(e string) { appendEvent(t, events, e) }

	provs, err := buildHostDecommissionProviders(dir, "client1", contract.Catalog{}, io.Discard, noStageAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := provs[providers.FreeIPAClientProviderID].(*providers.FreeIPAClientProvider)
	if !ok {
		t.Fatalf("providers = %v", provs)
	}
	step, err := provider.ExecutorForStep(providers.Step{Action: providers.ActionFreeIPAIdentityApplyConverge,
		TargetIdentity: "client1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "client1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := step.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	req := onlyRequest(t, lock)
	if req.Inventory != filepath.Join(dir, "inventory.yml") || req.Hosts != nil || req.Wait != identityLockWaitDefault || req.Runtime == nil || req.Runtime.TempDir == "" {
		t.Fatalf("request = %+v: want the generated inventory, the freeipa-server group, the default wait and the workspace's Ansible runtime", req)
	}
	if got, want := readEvents(t, events), []string{"lock ipa-1", "run freeipa-identity-apply.yml", "release ipa-1"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", got, want)
	}
}
