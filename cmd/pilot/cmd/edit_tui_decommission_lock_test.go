package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The TUI's decommission does not wait for the FreeIPA identity lock
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.3,
// §4.5). pushDecommissionExecute runs inside the Bubble Tea update loop: it is
// synchronous, nothing can cancel it and there is no screen to show a wait on, so
// the CLI's 30-minute wait would freeze the terminal while another run holds the
// lock. A busy lock fails at once, before any step, with the approval kept and the
// plan resumable; the CLI keeps its wait.

// tuiDecommissionRouter drives pushDecommissionExecute for the plan the lock env
// made, the way the confirmation screens do, and returns the router it left.
func (e *decommissionLockEnv) tuiExecute() editRouterModel {
	e.t.Helper()
	hostsPath := filepath.Join(e.ws, "hosts.yml")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		e.t.Fatal(err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		e.t.Fatal(err)
	}
	var r editRouterModel
	pushDecommissionExecute(&r, e.ws, hostsPath, hf, "client1", e.loadPlan(), decommission.StageAuthorization{})
	return r
}

func TestTUIDecommissionDoesNotWaitForTheLockAndTheSamePlanFinishesLater(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	hashBefore := env.loadPlan().PlanHash

	lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	r := env.tuiExecute()

	// What the lock was asked for: no wait, and nothing written to stderr, where
	// a progress line would land in the middle of the terminal UI.
	req := onlyRequest(t, lock)
	if req.Wait != 0 || req.Progress != io.Discard {
		t.Fatalf("request = %+v: the TUI must not wait for the lock (Wait 0) and must not print progress to stderr", req)
	}
	if lock.Acquired() != 0 {
		t.Fatalf("the lock was taken %d times; it was busy", lock.Acquired())
	}

	// What the operator sees: the run did not start, why, and how to go on.
	view := viewContent(r.View())
	for _, want := range []string{"尚未開始", env.planID, "不等待", "resume --id " + env.planID, "approval 已保留"} {
		if !strings.Contains(view, want) {
			t.Fatalf("the screen after a busy lock does not say %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "下架規劃失敗") {
		t.Fatalf("a busy lock is not a planning failure, but the screen says so:\n%s", view)
	}

	// What it left: nothing changed, the approval is kept, the plan is as planned.
	env.untouched()
	if !planApproved(t, env.planID) {
		t.Fatal("the approval was not kept: resume would refuse and the operator would have to re-plan")
	}
	if got := env.loadPlan(); got.PlanHash != hashBefore || got.Status != decommission.PlanStatusExecutable {
		t.Fatalf("the plan changed (hash %s -> %s, status %s)", hashBefore, got.PlanHash, got.Status)
	}

	// The same plan then finishes with the CLI, once the other run has let go.
	lock.Err = nil
	env.completed(env.resume())
}

// The CLI keeps its wait (the control for the test above: the difference is the
// path, not a changed default), and the TUI's no-wait does not leak into it: the
// same funnel asked afterwards by the CLI waits the default again.
func TestTUIDecommissionNoWaitDoesNotChangeTheCLIsWait(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	_ = env.tuiExecute()
	if _, err := env.apply(); err == nil {
		t.Fatal("apply with a busy lock succeeded")
	}
	reqs := lock.Requests()
	if len(reqs) != 2 || reqs[0].Wait != 0 || reqs[1].Wait != identityLockWaitDefault || reqs[1].Progress == nil || reqs[1].Progress == io.Discard {
		t.Fatalf("requests = %+v, want the TUI's with no wait and then the CLI's with the default wait (%s) and a progress writer", reqs, identityLockWaitDefault)
	}
}

// With the production acquirer over a real flock another run holds: the TUI call
// returns at once with the busy screen instead of waiting for the holder (the
// CLI would wait up to 30 minutes), and nothing was changed.
func TestTUIDecommissionReturnsAtOnceWhileAnotherRunHoldsTheRealLock(t *testing.T) {
	env := newDecommissionLockEnv(t)
	seam := useLocalLockDialer(t)
	env.plan()
	holder, err := productionIdentityLock(identityLockRequest{Inventory: filepath.Join(env.ws, "inventory.yml")})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Release() }()
	if !seam.held(t) {
		t.Fatal("the other run does not hold the lock")
	}

	started := time.Now()
	r := env.tuiExecute()
	if took := time.Since(started); took > 25*time.Second {
		t.Fatalf("the TUI call took %v with the lock held by another run: it waited", took)
	}
	if view := viewContent(r.View()); !strings.Contains(view, "尚未開始") {
		t.Fatalf("the screen does not say the run did not start:\n%s", view)
	}
	env.untouched()
	if !planApproved(t, env.planID) {
		t.Fatal("the approval was not kept")
	}
	if !seam.held(t) {
		t.Fatal("the other run's lock is gone")
	}

	if err := holder.Release(); err != nil {
		t.Fatal(err)
	}
	env.completed(env.resume())
}
