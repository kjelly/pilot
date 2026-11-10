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

// identityLockHelp is the paragraph the help of every command that runs the
// identity apply playbook carries (see checkIdentityLockTarget for the rule and
// docs/runbooks/freeipa-identity.md §4.3 for the operator's side): one text, so
// the commands cannot say different things about the same refusals. It says
// what comes before the check as well as what the check comes before: a claim
// that nothing does is not true (a wizard asks its questions, deploy and
// reconcile regenerate inventory.yml and upgrade a roster's schema, decommission
// confirms the stage and regenerates inventory.yml first).
const identityLockHelp = `Before it runs any ansible-playbook, opens any ssh connection, records an approval
or starts a step of its own, it checks that this server's /etc/ipa lock can be
taken through the inventory, by the same rule the lock itself follows, and
refuses an inventory it cannot (a docker or local connection, ProxyCommand, a
password, an ssh option pilot's own ssh does not take), naming the variable.
Work that only prepares the workspace can come first: the questions of a wizard,
regenerating inventory.yml from hosts.yml, upgrading a roster file's schema (a
backup is kept) and, for decommission, the stage confirmation. It reads the
inventory through ansible-inventory without a vault password, so a workspace
whose group_vars hold a plaintext contract secret, or are encrypted as a whole
file, is refused too: keep secrets in .vault/main.yaml. Connection variables that
only reach the playbook through -e @file, ansible.cfg's ssh_args or
ANSIBLE_SSH_ARGS are not seen by that check.`

// identityLockDeployHelp is identityLockHelp for pilot deploy and pilot
// reconcile, whose help is in Chinese: the same rule and the same limits, one
// text for the two commands (TestLockHelpIsASingleSource).
const identityLockDeployHelp = `選到 freeipa-identity 時(deploy 與 reconcile 的 ansible engine，含 --preview-only)，
會在任何 ansible-playbook、ssh、依賴 apply 或預覽之前，先檢查 FreeIPA server 的
/etc/ipa 鎖能不能經 inventory 取得(與取鎖本身同一套規則)；取不到(docker 或
local connection、ProxyCommand、密碼、pilot 的 ssh 不接受的 -o)就拒絕並指出是
哪個 hostvar，--preview-only 與 --force 的結果一致。只整理 workspace 的事會在這個
檢查之前：精靈的問題、從 hosts.yml 重新產生 inventory.yml、roster 的 schema 升級
(會留備份)。這個檢查透過 ansible-inventory 讀 inventory(不帶 vault 密碼)，所以
group_vars 有 contract 的明文 secret、或整份 group_vars 被 vault 加密，會在取鎖前
被拒絕(secret 放在 .vault/main.yaml)；只靠 -e @file、ansible.cfg 的 ssh_args 或
ANSIBLE_SSH_ARGS 提供的連線設定，檢查看不到。--ask-vault-pass／--ask-become-pass
的密碼提示發生在取鎖之後(在 ansible-playbook 內)，輸入密碼的時間算在持鎖時間裡。`

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

// identityLockTarget is the one derivation of what the identity lock takes: the
// single FreeIPA server and how to ssh to it, from the inventory. The lock
// itself (productionIdentityLock) and the no-ssh precheck every funnel runs
// before it does anything (checkIdentityLockTarget) both call it, so a
// precheck that passes is the decision the lock will make, not a second copy
// of it that could drift (AGENTS.md §5.7). It starts no ssh and no
// ansible-playbook: it asks ansible and ansible-inventory what the inventory
// says.
//
// An inventory it cannot derive an ssh Target from (a docker or local
// connection, ProxyCommand, a password, an option outside the allowlist of
// sshdial.Target) is an error that names the variable: the playbook is not run
// without the lock.
func identityLockTarget(ctx context.Context, req identityLockRequest) (string, sshdial.Target, error) {
	if req.Runtime != nil {
		ctx = withDeployAnsibleRuntime(ctx, *req.Runtime)
	}
	hosts := req.Hosts
	if hosts == nil {
		var err error
		if hosts, err = resolvePatternHosts(ctx, req.Inventory, "freeipa-server", ""); err != nil {
			return "", sshdial.Target{}, fmt.Errorf("resolve the FreeIPA server of %s to lock: %w", req.Inventory, err)
		}
	}
	if len(hosts) != 1 {
		return "", sshdial.Target{}, fmt.Errorf("freeipa-identity 取鎖需要剛好一台 freeipa-server 主機(contract hostCardinality: exactly-one)，%s 有 %d 台：%v", req.Inventory, len(hosts), hosts)
	}
	host := hosts[0]
	snapshot, err := loadDeployInventorySnapshot(ctx, req.Inventory)
	if err != nil {
		return "", sshdial.Target{}, err
	}
	target, err := sshdial.TargetFromHostVars(host, snapshot.HostVars[host])
	if err != nil {
		return "", sshdial.Target{}, fmt.Errorf("不能對 %s 取 FreeIPA 的 %s 鎖，所以不執行 freeipa-identity-apply.yml(它一律先取鎖，不會無鎖執行)：%w", host, sshdial.DefaultLockPath, err)
	}
	return host, target, nil
}

// identityLockPrecheck is the seam of checkIdentityLockTarget: a variable so
// tests of the funnels, which have no inventory to derive a Target from, can
// install a fake (useFakeIdentityLock does); only test code assigns it
// (identity_lock_funnel_test.go checks that). The production value is
// identityLockTarget without the result.
var identityLockPrecheck = func(ctx context.Context, req identityLockRequest) error {
	_, _, err := identityLockTarget(ctx, req)
	return err
}

// checkIdentityLockTarget refuses, before anything runs, a run whose lock the
// inventory cannot give: the same derivation the lock makes
// (identityLockTarget), so the refusal does not wait until the lock is taken.
// Taking the lock is the last thing a funnel does before its playbook, and the
// funnels do other things first: a decommission uninstalls the client and
// tombstones the roster entry before its converge step runs, a deploy applies
// the freeipa-server dependency and the `--check` preview, and a drift repair
// probes the server. Refusing only then leaves the operator with a partial run
// that cannot finish; a `--preview-only` that passed would not have predicted
// the refusal of `--force`. This runs first, in every funnel, and the lock-time
// check stays as defence in depth.
//
// It starts no ssh and no ansible-playbook. What it cannot see is what the
// derivation cannot see (the known gaps of spec §4.2): the connection variables
// that only reach the playbook through `-e @file`, ansible.cfg's ssh_args and
// the ssh environment.
func checkIdentityLockTarget(ctx context.Context, req identityLockRequest) error {
	if err := identityLockPrecheck(ctx, req); err != nil {
		return fmt.Errorf("取鎖前檢查沒有通過，沒有執行任何 ansible-playbook 或 ssh：%w", err)
	}
	return nil
}

// identityLockFor is how a funnel whose lock request is known before it starts
// builds its Acquirer: the precheck first, then the lock. Every funnel goes
// through it or through checkIdentityLockTarget (the deploy runner, which
// learns its hosts in two steps), so none can take a lock it never checked
// (identity_lock_funnel_test.go).
func identityLockFor(ctx context.Context, req identityLockRequest) (identitylock.Acquirer, error) {
	err := checkIdentityLockTarget(ctx, req)
	if err != nil {
		return nil, err
	}
	return newIdentityLock(req), nil
}

// productionIdentityLock resolves the one FreeIPA server, derives how to ssh
// to it from the inventory (identityLockTarget), and takes its /etc/ipa lock.
// It never runs the playbook without the lock.
func productionIdentityLock(req identityLockRequest) identitylock.Acquirer {
	return func(ctx context.Context) (*identitylock.Held, error) {
		host, target, err := identityLockTarget(ctx, req)
		if err != nil {
			return nil, err
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
				fmt.Fprintf(w, "等待 FreeIPA server %s 的 %s 鎖(連線中，或另一輪 freeipa-identity 執行持有中)：已等 %s／上限 %s\n",
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

// tuiIdentityLockFor is the Acquirer of the pilot edit TUI's break-glass
// activation, after the precheck every funnel runs: it does not wait. The TUI
// call is synchronous, with no context to cancel and no screen to show progress
// on, so a lock another run holds is refused at once and the message points at
// the command that does wait.
func tuiIdentityLockFor(ctx context.Context, inventory string) (identitylock.Acquirer, error) {
	acquire, err := identityLockFor(ctx, identityLockRequest{Inventory: inventory, Wait: 0})
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (*identitylock.Held, error) {
		held, err := acquire(ctx)
		if err != nil && errors.Is(err, sshdial.ErrLockBusy) {
			return nil, fmt.Errorf("%w；TUI 不等待。請改用會等待的 pilot access breakglass activate／deactivate(最多等 %s)", err, identityLockWaitDefault)
		}
		return held, err
	}, nil
}
