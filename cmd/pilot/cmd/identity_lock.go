package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The identity lock gate (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4): every pilot path that runs freeipa-identity-apply.yml holds the FreeIPA
// server's /etc/ipa lock for the length of the run, so that two runs cannot
// interleave their read-modify-write of the authorization cache journal. The
// packages that own a funnel (internal/accessgrants, internal/decommission)
// cannot resolve a server from an inventory (resolvePatternHosts and the
// snapshot helpers live here), so cmd builds the identitylock.Acquirer and
// injects it, and a funnel handed none refuses to run.

// identityLockWaitDefault is how long a funnel waits for another run to give
// the lock back: one full identity run takes about 26-27 minutes
// (docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md §1), so a
// funnel that waits this long outlasts one whole run in progress. The wait
// is the remote flock's own `--wait`, which ends by itself at that time.
const identityLockWaitDefault = 30 * time.Minute

// identityLockProgressEvery is how often a funnel that waits tells the
// operator it is still waiting. A variable so a test can shorten it.
var identityLockProgressEvery = 30 * time.Second

// identityLockRequest is what a funnel hands newIdentityLock.
type identityLockRequest struct {
	// Inventory is the inventory the funnel's playbook runs against.
	Inventory string
	// Hosts, when not nil, are the inventory hosts the run is going to change
	// (the deploy runner has resolved them already, honoring --limit,
	// target_group and availability). nil asks the acquirer to resolve the
	// `freeipa-server` group of Inventory, which is what the playbook's own
	// default `hosts:` is (accessgrants.applyPlan and the decommission
	// converge pass no limit and no target_group).
	Hosts []string
	// Wait is how long to wait for another holder; 0 fails at once.
	Wait time.Duration
	// Progress, when not nil, receives a line every identityLockProgressEvery
	// while waiting.
	Progress io.Writer
	// Runtime is the Ansible runtime of the caller, when its context does not
	// carry it already (the decommission runner has its own).
	Runtime *deployAnsibleRuntime
}

// newIdentityLock builds the Acquirer of a funnel. A variable so tests of the
// funnels, which have no FreeIPA server to take a lock on, can install a
// fake (internal/identitylock/identitylocktest); only test code assigns it
// (cmd/pilot/cmd/identity_lock_funnel_test.go checks that). The production
// value never returns nil.
var newIdentityLock = productionIdentityLock

// identityLockDialer is what the production acquirer needs from
// sshdial.Dialer; a variable below so a test can aim it at a fake ssh.
type identityLockDialer interface {
	AcquireLock(ctx context.Context, opts sshdial.LockOptions) (*sshdial.Lock, error)
	Close()
}

var newIdentityLockDialer = func(t sshdial.Target) identityLockDialer { return &sshdial.Dialer{Target: t} }

// productionIdentityLock resolves the one FreeIPA server, derives how to ssh
// to it from the inventory, and takes its /etc/ipa lock. It never runs the
// playbook without the lock: an inventory it cannot derive an ssh Target from
// (a docker or local connection, ProxyCommand, a password, an option outside
// the allowlist of sshdial.Target) is an error that names the variable.
func productionIdentityLock(req identityLockRequest) identitylock.Acquirer {
	return func(ctx context.Context) (*identitylock.Held, error) {
		if req.Runtime != nil {
			ctx = withDeployAnsibleRuntime(ctx, *req.Runtime)
		}
		hosts := req.Hosts
		if hosts == nil {
			var err error
			if hosts, err = resolvePatternHosts(ctx, req.Inventory, "freeipa-server", ""); err != nil {
				return nil, fmt.Errorf("resolve the FreeIPA server of %s to lock: %w", req.Inventory, err)
			}
		}
		if len(hosts) != 1 {
			return nil, fmt.Errorf("freeipa-identity 取鎖需要剛好一台 freeipa-server 主機(contract hostCardinality: exactly-one)，%s 有 %d 台：%v", req.Inventory, len(hosts), hosts)
		}
		host := hosts[0]
		snapshot, err := loadDeployInventorySnapshot(ctx, req.Inventory)
		if err != nil {
			return nil, err
		}
		target, err := sshdial.TargetFromHostVars(host, snapshot.HostVars[host])
		if err != nil {
			return nil, fmt.Errorf("不能對 %s 取 FreeIPA 的 %s 鎖，所以不執行 freeipa-identity-apply.yml(它一律先取鎖，不會無鎖執行)：%w", host, sshdial.DefaultLockPath, err)
		}
		dialer := newIdentityLockDialer(target)
		stopProgress := announceLockWait(req.Progress, host, req.Wait)
		lock, err := dialer.AcquireLock(ctx, sshdial.LockOptions{Wait: req.Wait})
		stopProgress()
		if err != nil {
			dialer.Close()
			if errors.Is(err, sshdial.ErrLockBusy) {
				return nil, fmt.Errorf("FreeIPA server %s 的 %s 鎖被另一輪 freeipa-identity 執行持有(等了 %s)：%w", host, sshdial.DefaultLockPath, req.Wait, err)
			}
			return nil, fmt.Errorf("取得 FreeIPA server %s 的 %s 鎖失敗：%w", host, sshdial.DefaultLockPath, err)
		}
		return identitylock.New(host, lock, dialer.Close), nil
	}
}

// announceLockWait prints a line to w every identityLockProgressEvery until
// the returned function is called. Waiting 0 (fail at once) prints nothing.
func announceLockWait(w io.Writer, host string, wait time.Duration) (stop func()) {
	if w == nil || wait <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(finished)
		ticker := time.NewTicker(identityLockProgressEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Fprintf(w, "等待 FreeIPA server %s 的 %s 鎖(另一輪 freeipa-identity 執行持有中)：已等 %s／上限 %s\n",
					host, sshdial.DefaultLockPath, time.Since(started).Round(time.Second), wait)
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

type identityLockWaitKey struct{}
type identityLockProgressKey struct{}

// withIdentityLockWait makes funnels reached from ctx wait this long for the
// lock instead of identityLockWaitDefault (pilot reconcile --lock-wait).
func withIdentityLockWait(ctx context.Context, wait time.Duration) context.Context {
	return context.WithValue(ctx, identityLockWaitKey{}, wait)
}

func identityLockWaitFrom(ctx context.Context) time.Duration {
	if wait, ok := ctx.Value(identityLockWaitKey{}).(time.Duration); ok {
		return wait
	}
	return identityLockWaitDefault
}

// withIdentityLockProgress sends the "still waiting" lines to w.
func withIdentityLockProgress(ctx context.Context, w io.Writer) context.Context {
	return context.WithValue(ctx, identityLockProgressKey{}, w)
}

// identityLockProgressFrom is where "still waiting" goes: stderr, which
// is not the deploy's own output stream.
func identityLockProgressFrom(ctx context.Context) io.Writer {
	if w, ok := ctx.Value(identityLockProgressKey{}).(io.Writer); ok {
		return w
	}
	return os.Stderr
}

// tuiIdentityLock is the Acquirer of the pilot edit TUI's break-glass
// activation: it does not wait. The TUI call is synchronous, with no context
// to cancel and no screen to show progress on, so a lock another run holds is
// refused at once and the message points at the command that does wait.
func tuiIdentityLock(inventory string) identitylock.Acquirer {
	acquire := newIdentityLock(identityLockRequest{Inventory: inventory, Wait: 0})
	return func(ctx context.Context) (*identitylock.Held, error) {
		held, err := acquire(ctx)
		if err != nil && errors.Is(err, sshdial.ErrLockBusy) {
			return nil, fmt.Errorf("%w；TUI 不等待。請改用會等待的 pilot access breakglass activate／deactivate(最多等 %s)", err, identityLockWaitDefault)
		}
		return held, err
	}
}
