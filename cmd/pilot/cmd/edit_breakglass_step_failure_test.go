package cmd

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/sshdial"
)

// activate_breakglass and deactivate_breakglass in an automation step (AGENTS.md
// §5.8; docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4.4, E40).
//
// The screens report the outcome of the activation as a banner; the driver used
// to navigate, press Enter and return, so a step whose activation was refused
// (the precheck, a busy lock, a lost lock) or failed (the playbook) returned
// success: `pilot edit --actions` exited 0 with no output and an MCP apply said
// "applied", while nothing had run and no emergency access was in effect. These
// tests drive the real router through every front end that reuses the driver
// (the terminal router, --actions, an apply, the MCP apply) with the failures
// that happen in practice, and the same steps succeeding (the other direction,
// AGENTS.md §5.12): a failing step must fail with the cause, say so in the
// step's error, and leave nothing recorded as active.

const breakglassGrant = "infra-emergency"

// breakglassEnv is a workspace with a break-glass grant to create, its state
// directory, and recorders for what must not run on a refusal: an
// `ansible-playbook` on PATH that logs its arguments and exits with the status in
// a file, and either the fake identity lock (its precheck and its lock are what
// each case sets) or, for the precheck's own refusal, the production precheck on
// a real inventory.
type breakglassEnv struct {
	t        *testing.T
	dir      string
	stateDir string
	calls    string
	exitFile string
	lock     *fakeIdentityLock // nil when the production precheck is used
	funnel   *funnelEnv        // nil when the fake lock is used
}

func breakglassWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	return dir
}

// newBreakglassEnv is the workspace with the fake identity lock: the lock is
// taken in memory, the precheck passes unless a case sets PrecheckErr, and the
// playbook recorder exits 0 unless a case writes another status.
func newBreakglassEnv(t *testing.T) *breakglassEnv {
	t.Helper()
	state := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", state)
	oldData := dataDir
	dataDir = state
	t.Cleanup(func() { dataDir = oldData })
	e := &breakglassEnv{
		t:        t,
		dir:      breakglassWorkspace(t),
		stateDir: state,
		calls:    filepath.Join(t.TempDir(), "calls.log"),
		exitFile: filepath.Join(t.TempDir(), "exit"),
	}
	e.setPlaybookExit("0")
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"ansible-playbook $*\" >> '" + e.calls + "'\nexit $(cat '" + e.exitFile + "')\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	e.lock = useFakeIdentityLock(t)
	return e
}

// newBreakglassEnvOnInventory is the workspace whose inventory.yml (the one the
// screens read) is a real inventory with serverVars on its freeipa-server host,
// with the production precheck, the real ansible-inventory, and recorders for
// ansible-playbook and ssh.
func newBreakglassEnvOnInventory(t *testing.T, serverVars string) *breakglassEnv {
	t.Helper()
	funnel := newFunnelEnv(t, serverVars)
	e := &breakglassEnv{t: t, dir: breakglassWorkspace(t), stateDir: resolveStateDir(accessStateFiles...), calls: funnel.log, funnel: funnel}
	data, err := os.ReadFile(funnel.inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessGovernanceInventoryPath(e.dir), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *breakglassEnv) setPlaybookExit(status string) {
	e.t.Helper()
	if err := os.WriteFile(e.exitFile, []byte(status), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// ran is what the recorders saw: the ansible-playbook invocations.
func (e *breakglassEnv) ran() []string { return readEvents(e.t, e.calls) }

// active is how many activations of the grant are in effect in the local state.
func (e *breakglassEnv) active() int {
	e.t.Helper()
	activations, err := accessgrants.Status(e.stateDir, breakglassGrant)
	if err != nil {
		e.t.Fatal(err)
	}
	n := 0
	for _, a := range activations {
		if a.IsActive(time.Now()) {
			n++
		}
	}
	return n
}

func breakglassGrantSteps() []editAction {
	return []editAction{
		{Action: "create_user", User: "emergency-admin"},
		{Action: "create_hostgroup", Name: "prodweb"},
		{
			Action: "create_grant", Name: breakglassGrant, Kind: "breakglass",
			Users: []string{"emergency-admin"}, Hostgroups: []string{"prodweb"},
			Services: []string{"sshd"}, MaxDuration: "1h",
		},
	}
}

func activateStep() editAction {
	return editAction{Action: "activate_breakglass", Name: breakglassGrant, Duration: "30m", Reason: "outage", Ticket: "INC-1"}
}

func deactivateStep() editAction {
	return editAction{Action: "deactivate_breakglass", Name: breakglassGrant}
}

// breakglassFrontEnds are the ways a scenario reaches the driver: the terminal
// router's driver, `pilot edit --actions`, and an apply (the MCP apply runs
// the same function). Each returns the error the caller of the front end sees.
func breakglassFrontEnds() map[string]func(t *testing.T, dir string, steps []editAction) error {
	scenario := func(steps []editAction) editScenario { return editScenario{Version: 1, Steps: steps} }
	return map[string]func(t *testing.T, dir string, steps []editAction) error{
		"terminal router": func(t *testing.T, dir string, steps []editAction) error {
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			return d.run(&r, scenario(steps))
		},
		"--actions": func(t *testing.T, dir string, steps []editAction) error {
			cmd := &cobra.Command{}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			oldDir := editDir
			editDir = dir
			t.Cleanup(func() { editDir = oldDir })
			return runAutomatedEditWorkflow(cmd, scenario(steps), false, "")
		},
		"apply": func(t *testing.T, dir string, steps []editAction) error {
			result, err := applyEditScenario(dir, "breakglass-step", scenario(steps), editAgentSessionOptions{})
			if err != nil {
				return err
			}
			if result.RolledBack {
				return result.ScenarioErr
			}
			return nil
		},
	}
}

// assertStepFailed: the front end failed, the error is the step's (its number
// and action) and holds every want (the cause).
func assertStepFailed(t *testing.T, err error, step int, action string, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the step %q reported success; the screen showed a failure banner and nothing was done", action)
	}
	for _, w := range append([]string{"step " + strconv.Itoa(step) + " (" + action + ")"}, want...) {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("err = %v, want it to hold %q", err, w)
		}
	}
}

// Every failure of the activation fails the step, with the cause, on every
// front end, and nothing is in effect afterwards: the precheck's refusal of an
// inventory the lock cannot be taken through, a busy lock, a lock lost while the
// playbook ran, and the playbook failing.
func TestBreakglassActivationFailureFailsTheAutomationStep(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  func(t *testing.T) *breakglassEnv
		want []string
		// playbookRuns is how often the playbook recorder ran: a refusal runs
		// nothing; -1 for a case that does not pin it down (a lost lock
		// cancels the run that is starting).
		playbookRuns int
		lockTaken    int // -1 with the production precheck, which takes no fake lock
	}{
		{
			name: "the precheck refuses the inventory (ProxyCommand on the freeipa-server host)",
			env: func(t *testing.T) *breakglassEnv {
				return newBreakglassEnvOnInventory(t, proxyCommandVars)
			},
			want:         []string{"break-glass " + breakglassGrant + " was not activated", "取鎖前檢查沒有通過", "ProxyCommand"},
			playbookRuns: 0,
			lockTaken:    -1,
		},
		{
			name: "the lock is busy",
			env: func(t *testing.T) *breakglassEnv {
				e := newBreakglassEnv(t)
				e.lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
				return e
			},
			want:         []string{"break-glass " + breakglassGrant + " was not activated", "take the FreeIPA identity lock", "TUI 不等待"},
			playbookRuns: 0,
			lockTaken:    0,
		},
		{
			name: "the lock is lost while the playbook runs",
			env: func(t *testing.T) *breakglassEnv {
				e := newBreakglassEnv(t)
				e.lock.OnAcquire = func(context.Context) { e.lock.Lose() }
				return e
			},
			want:         []string{"break-glass " + breakglassGrant + " was not activated", "lock lost"},
			playbookRuns: -1,
			lockTaken:    1,
		},
		{
			name: "the playbook fails",
			env: func(t *testing.T) *breakglassEnv {
				e := newBreakglassEnv(t)
				e.setPlaybookExit("1")
				return e
			},
			want:         []string{"break-glass " + breakglassGrant + " was not activated", "exited 1"},
			playbookRuns: 1,
			lockTaken:    1,
		},
	} {
		for feName, run := range breakglassFrontEnds() {
			t.Run(tc.name+"/"+feName, func(t *testing.T) {
				e := tc.env(t)
				steps := append(breakglassGrantSteps(), activateStep())

				err := run(t, e.dir, steps)

				assertStepFailed(t, err, len(steps), "activate_breakglass", tc.want...)
				if got := e.active(); got != 0 {
					t.Fatalf("%d activations are recorded as in effect after a failed activation", got)
				}
				if got := e.ran(); tc.playbookRuns >= 0 && len(got) != tc.playbookRuns {
					t.Fatalf("ansible-playbook ran %d times (%q), want %d", len(got), got, tc.playbookRuns)
				}
				if e.funnel != nil {
					if got := e.funnel.seam.started(); len(got) != 0 {
						t.Fatalf("an ssh for the lock was started before the refusal: %+v", got)
					}
				}
				if e.lock != nil {
					if e.lock.Acquired() != tc.lockTaken || e.lock.Released() != tc.lockTaken {
						t.Fatalf("the lock was taken %d times and released %d, want %d each", e.lock.Acquired(), e.lock.Released(), tc.lockTaken)
					}
				}
			})
		}
	}
}

// The other direction: the same steps on a healthy target succeed, take the
// lock once and give it back, run the playbook once, and the activation is in
// effect until the deactivation, which ends it.
func TestBreakglassActivationAndDeactivationSucceedOnAHealthyTarget(t *testing.T) {
	for feName, run := range breakglassFrontEnds() {
		t.Run(feName, func(t *testing.T) {
			e := newBreakglassEnv(t)
			if err := run(t, e.dir, append(breakglassGrantSteps(), activateStep())); err != nil {
				t.Fatalf("activate_breakglass: %v", err)
			}
			if got := e.active(); got != 1 {
				t.Fatalf("%d activations in effect after a successful activation, want 1", got)
			}
			if got := e.ran(); len(got) != 1 || e.lock.Acquired() != 1 || e.lock.Released() != 1 {
				t.Fatalf("playbook runs %q, lock taken %d, released %d: want one of each", got, e.lock.Acquired(), e.lock.Released())
			}
			if err := run(t, e.dir, []editAction{deactivateStep()}); err != nil {
				t.Fatalf("deactivate_breakglass: %v", err)
			}
			if got := e.active(); got != 0 {
				t.Fatalf("%d activations in effect after the deactivation, want 0", got)
			}
			if got := e.ran(); len(got) != 2 || e.lock.Acquired() != 2 || e.lock.Released() != 2 {
				t.Fatalf("playbook runs %q, lock taken %d, released %d: want two of each", got, e.lock.Acquired(), e.lock.Released())
			}
		})
	}
}

// A deactivation that failed did not end the access: the step fails with the
// cause and the activation is still recorded as in effect (an operator told that
// it was deactivated would stop watching it).
func TestBreakglassDeactivationFailureFailsTheAutomationStep(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(e *breakglassEnv)
		want []string
	}{
		{"the precheck refuses the inventory", func(e *breakglassEnv) {
			e.lock.PrecheckErr = errors.New("不能對 ipa-1 取 FreeIPA 的 /etc/ipa 鎖：ProxyCommand")
		}, []string{"取鎖前檢查沒有通過", "ProxyCommand"}},
		{"the lock is busy", func(e *breakglassEnv) {
			e.lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
		}, []string{"take the FreeIPA identity lock", "TUI 不等待"}},
		{"the lock is lost while the playbook runs", func(e *breakglassEnv) {
			e.lock.OnAcquire = func(context.Context) { e.lock.Lose() }
		}, []string{"lock lost"}},
		{"the playbook fails", func(e *breakglassEnv) { e.setPlaybookExit("1") }, []string{"exited 1"}},
	} {
		for feName, run := range breakglassFrontEnds() {
			t.Run(tc.name+"/"+feName, func(t *testing.T) {
				e := newBreakglassEnv(t)
				if err := breakglassFrontEnds()["terminal router"](t, e.dir, append(breakglassGrantSteps(), activateStep())); err != nil {
					t.Fatalf("setting up the activation: %v", err)
				}
				if got := e.active(); got != 1 {
					t.Fatalf("setup: %d activations in effect, want 1", got)
				}
				tc.fail(e)

				err := run(t, e.dir, []editAction{deactivateStep()})

				assertStepFailed(t, err, 1, "deactivate_breakglass", append([]string{"break-glass " + breakglassGrant + " was not deactivated"}, tc.want...)...)
				if got := e.active(); got != 1 {
					t.Fatalf("%d activations in effect after a failed deactivation, want 1 (the access was not ended)", got)
				}
			})
		}
	}
}

// A plan does not run a screen action that acts on FreeIPA and local state, and
// it does not pretend to have previewed it: no precheck, no lock, no playbook,
// nothing recorded, and a warning saying the step was not taken. It is not a
// failure either: an apply needs the plan.
func TestBreakglassPlanSkipsTheStepAndSaysSo(t *testing.T) {
	for _, step := range []editAction{activateStep(), deactivateStep()} {
		t.Run(step.Action, func(t *testing.T) {
			e := newBreakglassEnv(t)
			result, err := planEditScenario(e.dir, editScenario{Version: 1, Steps: append(breakglassGrantSteps(), step)}, editAgentSessionOptions{})
			if err != nil {
				t.Fatalf("planEditScenario() error = %v: a plan that fails can never be applied", err)
			}
			want := "plan 沒有執行 " + step.Action + " " + breakglassGrant
			var found bool
			for _, w := range result.Warnings {
				found = found || strings.Contains(w, want)
			}
			if !found {
				t.Fatalf("plan warnings = %q, want one holding %q", result.Warnings, want)
			}
			if got := e.ran(); len(got) != 0 {
				t.Fatalf("a plan ran %q", got)
			}
			if got := e.lock.Prechecks(); len(got) != 0 || len(e.lock.Requests()) != 0 || e.lock.Acquired() != 0 {
				t.Fatalf("a plan asked the lock gate: prechecks %+v, requests %+v, taken %d", got, e.lock.Requests(), e.lock.Acquired())
			}
			if got := e.active(); got != 0 {
				t.Fatalf("a plan recorded %d activations", got)
			}
		})
	}
}

// Over MCP: the plan that skipped the activation is applied, the apply runs it,
// and a failing playbook is an apply_failed error that rolled back, never an
// "applied" result.
func TestBreakglassMCPApplyReportsTheActivationOutcome(t *testing.T) {
	steps := append(breakglassGrantSteps(), activateStep())
	apply := func(t *testing.T, e *breakglassEnv) (*mcp.CallToolResult, applyOutput) {
		t.Helper()
		auditDir := t.TempDir()
		rev, err := computeWorkspaceRevision(e.dir)
		if err != nil {
			t.Fatal(err)
		}
		_, planOut, err := planHandler(editMCPToolsOptions{Dir: e.dir, AuditDir: auditDir})(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: editScenario{Version: 1, Steps: steps}})
		if err != nil || planOut.PlanID == "" {
			t.Fatalf("planHandler() = %+v, %v", planOut, err)
		}
		result, out, err := applyHandler(editMCPToolsOptions{Dir: e.dir, AuditDir: auditDir, WriteEnabled: true})(context.Background(), &mcp.CallToolRequest{}, applyInput{PlanID: planOut.PlanID, ExpectedRevision: rev})
		if err != nil {
			t.Fatalf("applyHandler() error = %v", err)
		}
		return result, out
	}

	t.Run("a failing playbook is an error that rolled back", func(t *testing.T) {
		e := newBreakglassEnv(t)
		e.setPlaybookExit("1")
		result, out := apply(t, e)
		if result == nil || !result.IsError || out.Result == "applied" {
			t.Fatalf("a failed activation was reported as %+v / %+v; want an error result", result, out)
		}
		toolErr := decodeToolError(t, result)
		if toolErr.Code != mcpErrApplyFailed || !toolErr.RolledBack || !strings.Contains(toolErr.Message, "exited 1") || !strings.Contains(toolErr.Message, "step 4 (activate_breakglass)") {
			t.Fatalf("tool error = %+v, want apply_failed, rolled back, naming step 4 and the playbook's exit", toolErr)
		}
		if got := e.active(); got != 0 {
			t.Fatalf("%d activations recorded", got)
		}
		if got := e.ran(); len(got) != 1 {
			t.Fatalf("the apply ran the playbook %d times, want 1 (the plan runs nothing)", len(got))
		}
	})

	t.Run("a healthy target is applied", func(t *testing.T) {
		e := newBreakglassEnv(t)
		result, out := apply(t, e)
		if (result != nil && result.IsError) || out.Result != "applied" {
			t.Fatalf("apply = %+v / %+v, want applied", result, out)
		}
		if got := e.active(); got != 1 {
			t.Fatalf("%d activations in effect, want 1", got)
		}
	})
}

// The step's failure is read from what the screen recorded, not from the
// banner's text, and one step's failure is not left for the next step: a write
// refused as busy comes first, and both are cleared.
func TestTakeStepFailureReturnsAndClearsWhatTheScreensRecorded(t *testing.T) {
	r := newEditRouterModel(t.TempDir())
	if err := r.takeStepFailure(); err != nil {
		t.Fatalf("a fresh router has a step failure: %v", err)
	}
	banner := r.failedAction("doing x", errors.New("the cause"))
	if banner != "❌ the cause" {
		t.Fatalf("banner = %q: the operator sees the cause as it was", banner)
	}
	r.writeRefused = errors.New("roster was not written")
	if err := r.takeStepFailure(); err == nil || err.Error() != "roster was not written" {
		t.Fatalf("takeStepFailure() = %v, want the write refusal first", err)
	}
	if r.writeRefused != nil || r.actionFailed != nil {
		t.Fatal("takeStepFailure left a failure behind for the next step")
	}
	r.failedAction("doing y", errors.New("another cause"))
	if err := r.takeStepFailure(); err == nil || err.Error() != "doing y: another cause" {
		t.Fatalf("takeStepFailure() = %v, want what the action was doing and the cause", err)
	}
}

// failureBannerProblems finds the failure banners of the pilot edit screens
// (edit_*.go) that are not built by editRouterModel.failedAction: a string
// literal that starts with "❌" anywhere else. The banner is what the operator at
// the terminal reads; failedAction also records the failure for the automation
// driver, so a "❌" built another way is a screen action whose automation step
// reports success after it failed (the class of
// TestBreakglassActivationFailureFailsTheAutomationStep). Other banners ("⚠️",
// "✅") are not failures by their prefix: some are warnings, and the writes the
// screens refuse are recorded where they are refused (rosterBusyBanner).
func failureBannerProblems(t *testing.T, files map[string]string) []string {
	t.Helper()
	var problems []string
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "failedAction" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if value, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(value, "❌") {
					problems = append(problems, fset.Position(lit.Pos()).String()+": a ❌ banner built outside editRouterModel.failedAction in "+fn.Name.Name)
				}
				return true
			})
		}
	}
	return problems
}

func TestRegression_FailureBannersAreRecordedForTheDriver(t *testing.T) {
	files := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "edit_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	if len(files) < 20 || files["edit_tui_roster_breakglass.go"] == "" {
		t.Fatalf("read %d edit_*.go files: the lint is not looking at the screens", len(files))
	}
	if problems := failureBannerProblems(t, files); len(problems) > 0 {
		t.Fatalf("failure banners the automation driver cannot see (use r.failedAction):\n%s", strings.Join(problems, "\n"))
	}
}

// The lint fires on the spellings that left the hole, and passes the one that
// closes it (both directions, AGENTS.md §5.12).
func TestFailureBannerLintFiresOnTheHoleAndPassesTheHelper(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want int
	}{
		"a concatenated banner": {`package cmd
func pushX(r *editRouterModel, err error) { push(r, "❌ "+err.Error()) }`, 1},
		"a formatted banner": {`package cmd
func pushX(r *editRouterModel, err error) { push(r, fmt.Sprintf("❌ %v", err)) }`, 1},
		"a banner built in a closure": {`package cmd
func pushX(r *editRouterModel) { f := func(err error) string { return "❌ " + err.Error() }; _ = f }`, 1},
		"the helper": {`package cmd
func (r *editRouterModel) failedAction(doing string, err error) string { return "❌ " + err.Error() }`, 0},
		"a recorded failure": {`package cmd
func pushX(r *editRouterModel, err error) { push(r, r.failedAction("doing x", err)) }`, 0},
		"a warning": {`package cmd
func pushX(r *editRouterModel) { push(r, "⚠️  careful") }`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := failureBannerProblems(t, map[string]string{"edit_x.go": tc.src}); len(got) != tc.want {
				t.Fatalf("problems = %q, want %d", got, tc.want)
			}
		})
	}
}
