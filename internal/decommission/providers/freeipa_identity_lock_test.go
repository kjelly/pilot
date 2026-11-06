package providers

import (
	"context"
	"errors"
	"path"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// The identity lock gate of the decommission funnel
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.5,
// E41): the central converge, (*freeipaIdentityConvergeStep).Execute, runs
// freeipa-identity-apply.yml, so it runs under the FreeIPA server's /etc/ipa
// lock, but the lock is not the step's. The decommission's first change is the
// client's uninstall, so the run's owner (runHostDecommissionApply) takes the
// lock before the first step, carries it in the context of decommission.Apply and
// gives it back after the last; the step reads it with identitylock.Require, never
// takes or releases one, and refuses without one. The read-only
// host_absent_inspect queries run the same playbook with a read-only tag and need
// no lock.

type lockEvents struct {
	mu sync.Mutex
	e  []string
}

func (l *lockEvents) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.e = append(l.e, s)
}

func (l *lockEvents) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.e)
}

// runOwnersLock is what the owner of a decommission run does before its first
// step: it takes the lock and puts it, bound, in the context the steps get. The
// lock is given back when the test ends, as the owner does when its run ends.
func runOwnersLock(t *testing.T, lock *identitylocktest.Fake) (context.Context, *identitylock.Held) {
	t.Helper()
	held, err := lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	ctx, cancel := held.Bind(context.Background())
	t.Cleanup(cancel)
	return ctx, held
}

// heldIdentityLock is a context that carries a lock the test holds, for the
// tests that run the converge step and are about something else.
func heldIdentityLock(t *testing.T) context.Context {
	t.Helper()
	ctx, _ := runOwnersLock(t, &identitylocktest.Fake{Host: "ipa-1"})
	return ctx
}

func convergeStep(t *testing.T, p *FreeIPAClientProvider) interface{ Execute(context.Context) error } {
	t.Helper()
	step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: "web1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "web1"}})
	if err != nil {
		t.Fatal(err)
	}
	return step
}

func convergeProvider(exec ansibleExecutor) *FreeIPAClientProvider {
	return NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		InventoryAlias: "web1", ServerInventory: "inventory.yml", IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		Executor: exec,
	})
}

// The step runs the playbook inside the lock the run holds, and does not take
// a second one or give that one back: the owner does, after the last step.
func TestIdentityConvergeRunsUnderTheRunsLockAndNeitherTakesNorReleasesIt(t *testing.T) {
	events := &lockEvents{}
	lock := &identitylocktest.Fake{Host: "ipa-1", Events: events.add}
	ctx, held := runOwnersLock(t, lock)
	p := convergeProvider(&fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		events.add("run " + path.Base(args[0]))
		return &ansible.Result{}, nil
	}})
	if err := convergeStep(t, p).Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := events.get(), []string{"lock ipa-1", "run freeipa-identity-apply.yml"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v: the step must not release the owner's lock", got, want)
	}
	if lock.Acquired() != 1 || lock.Released() != 0 || !held.Active() {
		t.Fatalf("acquired %d, released %d, active %v: the step took or gave back a lock", lock.Acquired(), lock.Released(), held.Active())
	}
}

// A playbook that fails leaves the lock where it is: the run is not over, and
// its owner releases it.
func TestIdentityConvergeLeavesTheLockToItsOwnerWhenThePlaybookFails(t *testing.T) {
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	ctx, held := runOwnersLock(t, lock)
	p := convergeProvider(&fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 2, Stderr: "boom"}, nil
	}})
	err := convergeStep(t, p).Execute(ctx)
	if err == nil || errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want the playbook's failure (not a lost lock)", err)
	}
	if lock.Released() != 0 || !held.Active() {
		t.Fatalf("released %d, active %v: the step gave back the owner's lock", lock.Released(), held.Active())
	}
}

// A context that carries no lock, a lock that is already lost or one already
// given back stops the step before the playbook, and the step does not take a
// lock of its own to make up for it.
func TestIdentityConvergeRefusesWithoutAUsableLockInItsContext(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx  func(t *testing.T) context.Context
		want error
	}{
		"no lock in the context": {func(t *testing.T) context.Context { return context.Background() }, identitylock.ErrNoLock},
		"the lock is already lost": {func(t *testing.T) context.Context {
			lock := &identitylocktest.Fake{Host: "ipa-1"}
			ctx, held := runOwnersLock(t, lock)
			lock.Lose()
			// Active looks at the session itself, so it is false from the moment it ends.
			if held.Active() {
				t.Fatal("the lock is still active after it was lost")
			}
			return ctx
		}, identitylock.ErrLockLost},
		"the lock was already released": {func(t *testing.T) context.Context {
			ctx, held := runOwnersLock(t, &identitylocktest.Fake{Host: "ipa-1"})
			if err := held.Release(); err != nil {
				t.Fatal(err)
			}
			return ctx
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			exec := &fakeAnsibleExecutor{}
			p := convergeProvider(exec)
			err := convergeStep(t, p).Execute(tc.ctx(t))
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.want)
			}
			if len(exec.calls) != 0 {
				t.Fatalf("the playbook ran without a usable lock: %v", exec.calls)
			}
		})
	}
}

// The lock is lost while the playbook runs, which then returns exit 0 anyway:
// the step still fails, and the playbook's context was cancelled with the cause.
func TestIdentityConvergeFailsWhenTheLockIsLost(t *testing.T) {
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	// A context that only Attached the lock: the step binds again itself, so the
	// playbook is killed on a loss even then.
	held, err := lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	ctx := held.Attach(context.Background())
	var sawCancel error
	p := convergeProvider(execFunc(func(ctx context.Context, args ...string) (*ansible.Result, error) {
		lock.Lose()
		select {
		case <-ctx.Done():
			sawCancel = context.Cause(ctx)
		case <-time.After(10 * time.Second):
		}
		return &ansible.Result{}, nil // exit 0, whatever happened to the lock
	}))
	err = convergeStep(t, p).Execute(ctx)
	if !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", err)
	}
	if !errors.Is(sawCancel, identitylock.ErrLockLost) {
		t.Fatalf("the playbook's context was not cancelled with ErrLockLost (cause %v)", sawCancel)
	}
}

type execFunc func(ctx context.Context, args ...string) (*ansible.Result, error)

func (f execFunc) Run(ctx context.Context, args ...string) (*ansible.Result, error) {
	return f(ctx, args...)
}

// The read-only side needs no lock: Inspect and the central queries run
// freeipa-identity-apply.yml with the read-only tag, which changes nothing, with
// a context that carries none.
func TestReadOnlyIdentityQueriesNeedNoLock(t *testing.T) {
	p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: hostShowClean}, nil
	})
	if _, err := p.query(context.Background(), "host_object", "web1.ipa.pilot.internal"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Inspect(context.Background(), InspectInput{HostName: "web1"}); err != nil {
		t.Fatal(err)
	}
}
