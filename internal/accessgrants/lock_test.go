package accessgrants

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

// The identity lock gate of accessgrants.applyPlan, the one funnel
// ReconcileOnce, RepairManaged, Activate and Deactivate share
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4.5): the lock is taken right before the playbook and given back when it
// has ended, whatever playbook --playbook names; a funnel handed no lock does
// not run; a lost lock cancels the playbook and the run fails even when the
// playbook exited 0.

// eventLog is what the fake lock and the fake runner both write to, so a test
// sees them in the order they happened.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// loggingRunner records the playbook it was asked to run and exits as told.
type loggingRunner struct {
	log      *eventLog
	exitCode int
	ran      int
}

func (r *loggingRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	r.ran++
	r.log.add("run " + path.Base(args[0]))
	return &ansible.Result{ExitCode: r.exitCode}, nil
}

// blockingRunner holds the playbook until the test lets it go. honorCtx says
// whether it notices its context being cancelled (a killed ansible-playbook
// does, a result that arrives anyway does not).
type blockingRunner struct {
	started  chan struct{}
	proceed  chan struct{}
	honorCtx bool
	exitCode int
	ctxErr   error
}

func newBlockingRunner(honorCtx bool) *blockingRunner {
	return &blockingRunner{started: make(chan struct{}), proceed: make(chan struct{}), honorCtx: honorCtx}
}

func (r *blockingRunner) Run(ctx context.Context, _ ...string) (*ansible.Result, error) {
	close(r.started)
	if r.honorCtx {
		select {
		case <-r.proceed:
		case <-ctx.Done():
			r.ctxErr = context.Cause(ctx)
			return &ansible.Result{ExitCode: -1}, ctx.Err()
		}
	} else {
		<-r.proceed
	}
	return &ansible.Result{ExitCode: r.exitCode}, nil
}

func newLockAndLog() (*identitylocktest.Fake, *eventLog) {
	log := &eventLog{}
	return &identitylocktest.Fake{Host: "ipa-1", Events: log.add}, log
}

func TestApplyPlanTakesTheLockAroundThePlaybook(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	for _, tc := range []struct {
		name     string
		playbook string
		exit     int
		wantErr  bool
	}{
		{name: "the default playbook", playbook: ""},
		// --playbook can name any playbook: the lock does not depend on the
		// answer to "is this the identity one".
		{name: "another playbook", playbook: "playbooks/apply/other.yml"},
		{name: "a failing playbook still releases", playbook: "", exit: 2, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock, log := newLockAndLog()
			runner := &loggingRunner{log: log, exitCode: tc.exit}
			_, _, err := ReconcileOnce(context.Background(), ReconcileOptions{
				RosterFile: rosterPath, Inventory: "inv.yml", Playbook: tc.playbook,
				Now: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), Runner: runner, Lock: lock.Acquirer(),
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && errors.Is(err, identitylock.ErrLockLost) {
				t.Fatalf("a playbook that exited %d is not a lost lock: %v", tc.exit, err)
			}
			want := path.Base(tc.playbook)
			if tc.playbook == "" {
				want = path.Base(DefaultPlaybook)
			}
			if got, wantEvents := log.get(), []string{"lock ipa-1", "run " + want, "release ipa-1"}; !slices.Equal(got, wantEvents) {
				t.Fatalf("events = %v, want %v", got, wantEvents)
			}
		})
	}
}

func TestEveryFunnelOfApplyPlanTakesTheLock(t *testing.T) {
	rosterPath := writeBreakglassTestRoster(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for name, run := range map[string]func(lock identitylock.Acquirer, runner playbookRunner) error{
		"activate": func(lock identitylock.Acquirer, runner playbookRunner) error {
			_, err := Activate(context.Background(), ActivateOptions{
				RosterFile: rosterPath, Inventory: "inv.yml", StateDir: t.TempDir(), Name: "infra-emergency",
				Duration: 30 * time.Minute, Reason: "x", Ticket: "y", Now: now, Runner: runner, Lock: lock,
			})
			return err
		},
		"deactivate": func(lock identitylock.Acquirer, runner playbookRunner) error {
			return Deactivate(context.Background(), DeactivateOptions{
				RosterFile: rosterPath, Inventory: "inv.yml", StateDir: t.TempDir(), Name: "infra-emergency",
				Now: now, Runner: runner, Lock: lock,
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			lock, log := newLockAndLog()
			if err := run(lock.Acquirer(), &loggingRunner{log: log}); err != nil {
				t.Fatal(err)
			}
			if got, want := log.get(), []string{"lock ipa-1", "run " + path.Base(DefaultPlaybook), "release ipa-1"}; !slices.Equal(got, want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			// Without a lock: refused before anything, the playbook never runs.
			log2 := &eventLog{}
			runner := &loggingRunner{log: log2}
			err := run(nil, runner)
			if !errors.Is(err, identitylock.ErrNoLock) || runner.ran != 0 {
				t.Fatalf("without a lock: err = %v, playbook runs = %d", err, runner.ran)
			}
		})
	}
}

// A funnel handed no lock refuses before it reads, probes or runs anything:
// the caller that forgot learns it at once, not after a probe.
func TestFunnelsRefuseWithoutALockBeforeDoingAnything(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	log := &eventLog{}
	runner := &loggingRunner{log: log}

	_, _, err := ReconcileOnce(context.Background(), ReconcileOptions{RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner})
	if !errors.Is(err, identitylock.ErrNoLock) {
		t.Fatalf("ReconcileOnce without a lock: %v", err)
	}
	_, _, _, err = RepairManaged(context.Background(),
		DriftProbeOptions{RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner},
		ReconcileOptions{RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner})
	if !errors.Is(err, identitylock.ErrNoLock) {
		t.Fatalf("RepairManaged without a lock: %v", err)
	}
	if runner.ran != 0 || len(log.get()) != 0 {
		t.Fatalf("something ran before the refusal: %d runs, %v", runner.ran, log.get())
	}
}

func TestApplyPlanDoesNotRunWhenTheLockIsRefused(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	busy := &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	lock, log := newLockAndLog()
	lock.Err = busy
	runner := &loggingRunner{log: log}
	_, result, err := reconcileOnceResult(t, rosterPath, runner, lock)
	if !errors.Is(err, sshdial.ErrLockBusy) {
		t.Fatalf("err = %v, want it to wrap ErrLockBusy", err)
	}
	if runner.ran != 0 || result != nil || lock.Acquired() != 0 {
		t.Fatalf("playbook runs = %d, result = %v: the playbook ran without the lock", runner.ran, result)
	}
}

func reconcileOnceResult(t *testing.T, rosterPath string, runner playbookRunner, lock *identitylocktest.Fake) (Plan, *ansible.Result, error) {
	t.Helper()
	return ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Now: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		Runner: runner, Lock: lock.Acquirer(),
	})
}

// A lock lost while the playbook runs: the run fails with ErrLockLost, and it
// does whether the playbook was cancelled or returned a clean exit 0 anyway
// (a concurrent run may have interleaved with it).
func TestApplyPlanFailsWhenTheLockIsLostWhileThePlaybookRuns(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	for _, tc := range []struct {
		name     string
		honorCtx bool
	}{
		{"the playbook is cancelled", true},
		{"the playbook exits 0 anyway", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock, log := newLockAndLog()
			runner := newBlockingRunner(tc.honorCtx)
			done := make(chan error, 1)
			go func() {
				_, result, err := reconcileOnceResult(t, rosterPath, runner, lock)
				if result == nil {
					err = errors.Join(err, errors.New("no result returned: the caller could not tell the playbook ran"))
				}
				done <- err
			}()
			select {
			case <-runner.started:
			case <-time.After(10 * time.Second):
				t.Fatal("the playbook never started")
			}
			lock.Lose()
			if !tc.honorCtx {
				// Give the watcher a moment so the loss is settled before the
				// playbook returns: either order must end in ErrLockLost, this
				// is the one that proves the check after the run.
				for i := 0; i < 100 && lock.Held().Active(); i++ {
					time.Sleep(10 * time.Millisecond)
				}
				close(runner.proceed)
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ReconcileOnce did not return after the lock was lost")
			}
			if !errors.Is(err, identitylock.ErrLockLost) {
				t.Fatalf("err = %v, want ErrLockLost", err)
			}
			if tc.honorCtx && !errors.Is(runner.ctxErr, identitylock.ErrLockLost) {
				t.Fatalf("the playbook's context was cancelled with %v, want the cause ErrLockLost", runner.ctxErr)
			}
			if events := log.get(); len(events) == 0 || events[len(events)-1] != "release ipa-1" {
				t.Fatalf("events = %v: the lost lock was not released at the end", events)
			}
		})
	}
}

// The playbook's context carries the token (HeldFrom), and it is the one that
// is bound to the lock: what a playbook runner is handed dies with the lock.
func TestApplyPlanHandsTheRunnerAContextBoundToTheLock(t *testing.T) {
	rosterPath := writeReconcileTestRoster(t)
	lock, _ := newLockAndLog()
	var sawHeld *identitylock.Held
	runner := &ctxProbeRunner{fn: func(ctx context.Context) { sawHeld = identitylock.HeldFrom(ctx) }}
	if _, _, err := reconcileOnceResult(t, rosterPath, runner, lock); err != nil {
		t.Fatal(err)
	}
	if sawHeld == nil || sawHeld != lock.Held() {
		t.Fatalf("the runner's context carries %v, want the lock the funnel took", sawHeld)
	}
}

type ctxProbeRunner struct{ fn func(ctx context.Context) }

func (r *ctxProbeRunner) Run(ctx context.Context, _ ...string) (*ansible.Result, error) {
	r.fn(ctx)
	return &ansible.Result{}, nil
}
