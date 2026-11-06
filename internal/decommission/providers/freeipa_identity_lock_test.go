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
	"github.com/kjelly/pilot/internal/sshdial"
)

// The identity lock gate of the decommission funnel,
// (*freeipaIdentityConvergeStep).Execute (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4.5): the central converge runs freeipa-identity-apply.yml, so it runs under
// the FreeIPA server's /etc/ipa lock, taken right before the playbook and given
// back when it has ended. The read-only host_absent_inspect queries run the same
// playbook with a read-only tag and never lock. A provider built without a lock
// cannot converge.

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

func convergeStep(t *testing.T, p *FreeIPAClientProvider) interface{ Execute(context.Context) error } {
	t.Helper()
	step, err := p.ExecutorForStep(Step{Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: "web1.ipa.pilot.internal", Params: map[string]string{"inventory_alias": "web1"}})
	if err != nil {
		t.Fatal(err)
	}
	return step
}

func TestIdentityConvergeRunsUnderTheLock(t *testing.T) {
	events := &lockEvents{}
	lock := &identitylocktest.Fake{Host: "ipa-1", Events: events.add}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		InventoryAlias: "web1", ServerInventory: "inventory.yml", IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		IdentityLock: lock.Acquirer(),
		Executor: &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
			events.add("run " + path.Base(args[0]))
			return &ansible.Result{}, nil
		}},
	})
	if err := convergeStep(t, p).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := events.get(), []string{"lock ipa-1", "run freeipa-identity-apply.yml", "release ipa-1"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestIdentityConvergeReleasesTheLockWhenThePlaybookFails(t *testing.T) {
	events := &lockEvents{}
	lock := &identitylocktest.Fake{Host: "ipa-1", Events: events.add}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		InventoryAlias: "web1", ServerInventory: "inventory.yml", IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		IdentityLock: lock.Acquirer(),
		Executor: &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
			events.add("run")
			return &ansible.Result{ExitCode: 2, Stderr: "boom"}, nil
		}},
	})
	err := convergeStep(t, p).Execute(context.Background())
	if err == nil || errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want the playbook's failure (not a lost lock)", err)
	}
	if got, want := events.get(), []string{"lock ipa-1", "run", "release ipa-1"}; !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestIdentityConvergeRefusesWithoutALockOrWhenItIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		lock identitylock.Acquirer
		want error
	}{
		"no lock configured": {nil, identitylock.ErrNoLock},
		"the lock is busy": {(&identitylocktest.Fake{Err: &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}}).Acquirer(),
			sshdial.ErrLockBusy},
	} {
		t.Run(name, func(t *testing.T) {
			exec := &fakeAnsibleExecutor{}
			p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
				InventoryAlias: "web1", ServerInventory: "inventory.yml", IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
				IdentityLock: tc.lock, Executor: exec,
			})
			err := convergeStep(t, p).Execute(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.want)
			}
			if len(exec.calls) != 0 {
				t.Fatalf("the playbook ran without the lock: %v", exec.calls)
			}
		})
	}
}

// The lock is lost while the playbook runs, which then returns exit 0 anyway:
// the step still fails.
func TestIdentityConvergeFailsWhenTheLockIsLost(t *testing.T) {
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	var sawCancel error
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		InventoryAlias: "web1", ServerInventory: "inventory.yml", IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
		IdentityLock: lock.Acquirer(),
		Executor: execFunc(func(ctx context.Context, args ...string) (*ansible.Result, error) {
			lock.Lose()
			select {
			case <-ctx.Done():
				sawCancel = context.Cause(ctx)
			case <-time.After(10 * time.Second):
			}
			return &ansible.Result{}, nil // exit 0, whatever happened to the lock
		}),
	})
	err := convergeStep(t, p).Execute(context.Background())
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

// The read-only side never locks: Inspect and the central queries run
// freeipa-identity-apply.yml with the read-only tag, which changes nothing.
func TestReadOnlyIdentityQueriesNeverTakeTheLock(t *testing.T) {
	lock := &identitylocktest.Fake{Host: "ipa-1"}
	p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: hostShowClean}, nil
	})
	p.cfg.IdentityLock = lock.Acquirer()
	if _, err := p.query(context.Background(), "host_object", "web1.ipa.pilot.internal"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Inspect(context.Background(), InspectInput{HostName: "web1"}); err != nil {
		t.Fatal(err)
	}
	if lock.Acquired() != 0 {
		t.Fatalf("the lock was taken %d times for read-only queries", lock.Acquired())
	}
}
