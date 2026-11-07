package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
	"github.com/kjelly/pilot/internal/inventory"
)

// A decommission whose identity lock is lost AFTER decommission.Apply has finished
// and recorded the receipt
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md R16, E41).
//
// The run still fails: it did not hold the lock to its end, which is what the lock
// is for (a concurrent identity run may have overlapped the part after the loss).
// What it says must be true of this run, though: the decommission is finished, its
// receipt is recorded and apply again replays it, so "FreeIPA may be partially
// reconciled; rerun" (the text of identitylock.ErrLockLost) is false here, and a
// run that did not finish keeps saying it. The loss itself cannot be provoked
// between Finalize's last write and the check that follows it, which are
// microseconds apart in one function, so the test hands decommissionRunEnd, the
// function that makes the decision, a lock the fake lost and the result the real
// run recorded: the real plan, the real receipt, and the real second apply.

// lostHeld takes a lock from the fake and ends its session without Release, as a
// dropped network does.
func lostHeld(t *testing.T) *identitylock.Held {
	t.Helper()
	fake := &identitylocktest.Fake{Host: "ipa-1"}
	held, err := fake.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fake.Lose()
	if err := held.Check(); !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("the held lock is not lost: Check = %v", err)
	}
	return held
}

func TestDecommissionRunEndAfterFinalizeReportsCompletionAndStillFails(t *testing.T) {
	env := newDecommissionLockEnv(t)
	lock := env.fakeLock()
	env.plan()
	env.completed(env.apply())
	plan := env.loadPlan()
	if plan.Status != decommission.PlanStatusCompleted || plan.Receipt == nil {
		t.Fatalf("the run did not leave a completed plan with a receipt: status %q, receipt %v", plan.Status, plan.Receipt)
	}
	finalized := &decommission.FinalizeResult{Status: "completed", Receipt: plan.Receipt, Plan: plan}

	result, err := decommissionRunEnd(lostHeld(t), plan.ID, finalized, nil)

	// Still a failure: the run did not hold the lock to its end.
	if err == nil || !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want a failure that wraps ErrLockLost", err)
	}
	// The result goes back with it: the host is gone from hosts.yml and a caller
	// that syncs its own copy needs to know.
	if result != finalized {
		t.Fatalf("result = %+v, want the completed result returned with the error", result)
	}
	// What it says is true of a finished run.
	for _, want := range []string{"host decommission " + plan.ID + " completed", "receipt is recorded", "apply` again replays it without running anything", "lock on ipa-1 was lost", "did not hold the lock to its end"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to say %q", err, want)
		}
	}
	for _, claim := range []string{"partially reconciled", "rerun"} {
		if strings.Contains(err.Error(), claim) {
			t.Fatalf("err = %q claims %q, which is false for a decommission that finished", err, claim)
		}
	}

	// And it is true: a second apply replays the receipt, takes no lock and runs
	// nothing.
	acquired, requests := lock.Acquired(), len(lock.Requests())
	timeline := env.timeline()
	out, applyErr := env.apply()
	if applyErr != nil || !strings.Contains(out, "STATUS already_completed") {
		t.Fatalf("apply again: %v\n%s", applyErr, out)
	}
	if lock.Acquired() != acquired || len(lock.Requests()) != requests || len(env.timeline()) != len(timeline) {
		t.Fatalf("apply again took the lock or ran a step: acquired %d->%d, requests %d->%d, timeline %v -> %v", acquired, lock.Acquired(), requests, len(lock.Requests()), timeline, env.timeline())
	}
}

// The other cases keep the text they had: a run Apply did not finish may be
// partial, a result that is not a completed one has nothing to replay, and a lock
// that was not lost changes nothing.
func TestDecommissionRunEndKeepsTheOtherOutcomes(t *testing.T) {
	completed := &decommission.FinalizeResult{Status: "completed", Receipt: &decommission.Receipt{}}
	blocked := &decommission.FinalizeResult{Status: "blocked", Blockers: []string{"x"}}
	applyErr := errors.New("freeipa_client_uninstall exited 1")

	t.Run("a run that failed before it finished may be partial", func(t *testing.T) {
		result, err := decommissionRunEnd(lostHeld(t), "hd-1", nil, applyErr)
		if result != nil || !errors.Is(err, identitylock.ErrLockLost) || !strings.Contains(err.Error(), "partially reconciled") || !strings.Contains(err.Error(), "freeipa_client_uninstall exited 1") {
			t.Fatalf("result %v, err %v: want the partial-reconcile text, ErrLockLost and the run's own error", result, err)
		}
	})
	t.Run("a completed result without a receipt has nothing to replay", func(t *testing.T) {
		result, err := decommissionRunEnd(lostHeld(t), "hd-1", &decommission.FinalizeResult{Status: "completed"}, nil)
		if result != nil || !errors.Is(err, identitylock.ErrLockLost) || strings.Contains(err.Error(), "completed") {
			t.Fatalf("result %v, err %v: must not claim a completion no receipt backs", result, err)
		}
	})
	t.Run("a blocked result is not a completion", func(t *testing.T) {
		result, err := decommissionRunEnd(lostHeld(t), "hd-1", blocked, nil)
		if result != nil || !errors.Is(err, identitylock.ErrLockLost) || strings.Contains(err.Error(), "receipt is recorded") {
			t.Fatalf("result %v, err %v", result, err)
		}
	})
	t.Run("a lock that is still held changes nothing", func(t *testing.T) {
		fake := &identitylocktest.Fake{Host: "ipa-1"}
		held, err := fake.Acquirer()(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = held.Release() }()
		if result, err := decommissionRunEnd(held, "hd-1", completed, nil); result != completed || err != nil {
			t.Fatalf("result %v, err %v: want the run's own outcome", result, err)
		}
		if result, err := decommissionRunEnd(held, "hd-1", nil, applyErr); result != nil || !errors.Is(err, applyErr) || errors.Is(err, identitylock.ErrLockLost) {
			t.Fatalf("result %v, err %v: want the run's own error", result, err)
		}
	})
	t.Run("a run that took no lock changes nothing", func(t *testing.T) {
		if result, err := decommissionRunEnd(nil, "hd-1", completed, nil); result != completed || err != nil {
			t.Fatalf("result %v, err %v", result, err)
		}
	})
}

// The TUI follows the receipt: the host is gone from hosts.yml, so the in-memory
// copy drops it too (a later save of that copy must not bring a decommissioned
// host back), and the screen says the run finished and the lock was lost. The
// error it is given is the one decommissionRunEnd makes for a real completed plan.
func TestTUIDecommissionAfterALostLockOnACompletedRunDropsTheHost(t *testing.T) {
	env := newDecommissionLockEnv(t)
	env.fakeLock()
	env.plan()
	env.completed(env.apply())
	plan := env.loadPlan()
	result, err := decommissionRunEnd(lostHeld(t), plan.ID, &decommission.FinalizeResult{Status: "completed", Receipt: plan.Receipt, Plan: plan}, nil)

	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "client1"}, {Name: "ipa-1"}}}
	var r editRouterModel
	pushDecommissionOutcome(&r, env.ws, filepath.Join(env.ws, "hosts.yml"), hf, "client1", plan, result, err)

	for _, h := range hf.Hosts {
		if h.Name == "client1" {
			t.Fatalf("the in-memory hosts still list the decommissioned host: %+v", hf.Hosts)
		}
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "ipa-1" {
		t.Fatalf("hosts = %+v, want only the host that was not decommissioned", hf.Hosts)
	}
	view := viewContent(r.View())
	for _, want := range []string{"已完成", plan.ID, "鎖遺失"} {
		if !strings.Contains(view, want) {
			t.Fatalf("the screen does not say %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "下架規劃失敗") {
		t.Fatalf("a completed decommission is not a planning failure:\n%s", view)
	}

	// A run that did not finish keeps the host and says it failed.
	hf = &inventory.HostsFile{Hosts: []inventory.Host{{Name: "client1"}}}
	r = editRouterModel{}
	_, notFinished := decommissionRunEnd(lostHeld(t), plan.ID, nil, errors.New("uninstall exited 1"))
	pushDecommissionOutcome(&r, env.ws, filepath.Join(env.ws, "hosts.yml"), hf, "client1", plan, nil, notFinished)
	if len(hf.Hosts) != 1 {
		t.Fatalf("a run that did not finish dropped the host: %+v", hf.Hosts)
	}
}
