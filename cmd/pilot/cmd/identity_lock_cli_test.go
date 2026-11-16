package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessgrants"
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
	lock, err := tuiIdentityLockFor(context.Background(), env.inv)
	if err != nil {
		t.Fatal(err)
	}
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

// The deploy runner builds two lock requests for one run: the precheck's, before
// the plan is shown, and the lock's, taken around the apply step. Both read the
// inventory through the -e and vault arguments the apply step hands to
// ansible-playbook, because those decide the host and the ssh settings
// (issue #319); a request built from fewer arguments puts the lock back on the
// inventory alone with every derivation test still green. The oracle is the argv
// the fake ansible-playbook recorded for the apply run, not the helper that builds
// it. The lock-time request is built from the very arguments the apply step gets,
// so it is one contiguous run of that argv (the run adds arguments of its own
// around it). The precheck is built before the run's own additions (the values
// pilot fills in itself, the deferred hosts), so it is an in-order subsequence of
// the argv instead. Each carries the operator's extra var, the vault file and its
// password file: dropping any of them is what the test is for.
func TestDeployCoreHandsTheLockTheArgumentsThePlaybookGets(t *testing.T) {
	env := newOutboundWorkflowEnv(t, map[string][]string{"freeipa-identity": {"host-a"}, "freeipa-dns": {"host-a"}},
		eventsYAMLFor(outbound.OperationDeploy, outbound.ResultSuccess), 0)
	catalog := loadOutboundWorkflowCatalog(t)

	vaultDir := filepath.Join(env.workspace, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultFile := filepath.Join(vaultDir, "main.yaml")
	passwordFile := filepath.Join(vaultDir, "vault-password")
	for path, body := range map[string]string{vaultFile: "ipa_admin_password: sentinel-not-a-credential\n", passwordFile: "sentinel-not-a-credential\n"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	argvLog := filepath.Join(t.TempDir(), "argv.log")
	runner := newRunnerWithExitCode(t, 0)
	runner.Binary = writeScript(t, "ansible-playbook", "#!/bin/sh\n"+argvRecordingPrefix(argvLog)+fakePlayRecapScript+"exit 0\n")

	batch := &catalogBatchInputs{
		extraVars: []string{"lock_arg_marker=1"},
		vault:     vaultInput{ExtraVarsFile: vaultFile, VaultPasswordFile: passwordFile},
	}
	entry := deployPlaybookEntry("freeipa-identity", "freeipa-identity-apply.yml")
	if err := runCatalogPlaybookDeployEntry(context.Background(), runner, &bytes.Buffer{}, env.inv, "apply", catalog, entry, batch, deployInventorySnapshot{}, false, nil); err != nil {
		t.Fatalf("runCatalogPlaybookDeployEntry: %v", err)
	}

	// The apply run: the one that is not the --check preview.
	var apply []string
	for _, run := range readRecordedArgv(t, argvLog) {
		if len(run) > 0 && strings.HasSuffix(run[0], "freeipa-identity-apply.yml") && !slices.Contains(run, "--check") {
			if apply != nil {
				t.Fatalf("two apply runs recorded: %q and %q", apply, run)
			}
			apply = run
		}
	}
	if apply == nil {
		t.Fatalf("no apply run of freeipa-identity-apply.yml recorded: %q", readRecordedArgv(t, argvLog))
	}
	if !slices.Contains(apply, "@"+vaultFile) || !slices.Contains(apply, "lock_arg_marker=1") {
		t.Fatalf("the apply run %q was not handed the vault file and the extra var: the oracle shows nothing", apply)
	}

	prechecks := env.lock.Prechecks()
	if len(prechecks) != 1 {
		t.Fatalf("%d prechecks, want the one the run asks before its plan", len(prechecks))
	}
	for _, tc := range []struct {
		name     string
		got      []string
		followed func(argv, got []string) bool
		how      string
	}{
		{"the lock-time request", onlyRequest(t, env.lock).ExtraArgs, func(argv, got []string) bool { return indexOfRun(argv, got) >= 0 }, "one contiguous run of"},
		{"the precheck request", prechecks[0].ExtraArgs, isSubsequence, "an in-order subsequence of"},
	} {
		for _, want := range []string{"lock_arg_marker=1", "@" + vaultFile, passwordFile} {
			if !slices.Contains(tc.got, want) {
				t.Errorf("%s: ExtraArgs %q lack %q, which the playbook was handed", tc.name, tc.got, want)
			}
		}
		if !tc.followed(apply, tc.got) {
			t.Errorf("%s: ExtraArgs %q are not %s the apply argv %q", tc.name, tc.got, tc.how, apply)
		}
	}
}
