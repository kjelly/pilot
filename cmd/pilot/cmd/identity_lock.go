package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
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
backup is kept) and, for decommission, the stage confirmation. The lock is taken
on the host the playbook is going to run on, with the connection it is going to
use: it reads the inventory through ansible-inventory with the -e and vault
arguments the playbook gets (deploy and reconcile: the --extra and vault file;
decommission: .vault/main.yaml), and the connection settings of ansible.cfg and
the ANSIBLE_* environment through ansible-config. A variable that only arrives
through -e @file, or a setting in ansible.cfg's ssh_args or ANSIBLE_SSH_ARGS, is
judged like one in the inventory, and a target_group that sends the playbook to a
host other than the one to lock is refused, naming the variable and where it
came from. An encrypted -e file needs its vault password where ansible-inventory
can read it too (--vault-password-file, or ANSIBLE_VAULT_PASSWORD_FILE). A
workspace whose group_vars hold a plaintext contract secret, or are encrypted as
a whole file, is refused as well: keep secrets in .vault/main.yaml.`

// identityLockDeployHelp is identityLockHelp for pilot deploy and pilot
// reconcile, whose help is in Chinese: the same rule and the same limits, one
// text for the two commands (TestLockHelpIsASingleSource).
const identityLockDeployHelp = `選到 freeipa-identity 時(deploy 與 reconcile 的 ansible engine，含 --preview-only)，
會在任何 ansible-playbook、ssh、依賴 apply 或預覽之前，先檢查 FreeIPA server 的
/etc/ipa 鎖能不能經 inventory 取得(與取鎖本身同一套規則)；取不到(docker 或
local connection、ProxyCommand、密碼、pilot 的 ssh 不接受的 -o)就拒絕並指出是
哪個 hostvar，--preview-only 與 --force 的結果一致。只整理 workspace 的事會在這個
檢查之前：精靈的問題、從 hosts.yml 重新產生 inventory.yml、roster 的 schema 升級
(會留備份)。鎖取在 playbook 實際會執行的那台主機，用 playbook 實際會用的連線：
透過 ansible-inventory 讀 inventory 時帶上 playbook 拿到的 -e 與 vault 參數(--extra
與 vault 檔)，ansible.cfg 與 ANSIBLE_* 環境變數裡的連線設定則透過 ansible-config
讀。只靠 -e @file 提供的變數、或 ansible.cfg 的 ssh_args／ANSIBLE_SSH_ARGS，與寫在
inventory 的同一個設定一樣被檢查；target_group 讓 playbook 去別台主機時拒絕，並指出
是哪個變數、來自哪裡。加密的 -e 檔要讓 ansible-inventory 也讀得到 vault 密碼
(--vault-password-file 或 ANSIBLE_VAULT_PASSWORD_FILE)。group_vars 有 contract 的明文
secret、或整份 group_vars 被 vault 加密，同樣會在取鎖前被拒絕(secret 放在
.vault/main.yaml)。--ask-vault-pass 會讓取鎖前檢查與取鎖時各多問一次密碼(沒有密碼
檔就無法在 ansible-playbook 之外讀 -e 檔)；--ask-vault-pass／--ask-become-pass 在
ansible-playbook 內的密碼提示發生在取鎖之後，輸入密碼的時間算在持鎖時間裡。`

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
	// ExtraArgs are the -e and vault arguments the playbook run is going to
	// get, as the funnel hands them to ansible-playbook (ansibleExtraVarArgs
	// for deploy, the workspace vault file for decommission). They decide
	// which host and which ssh settings the playbook uses, so the lock reads
	// the inventory through them: a funnel that passes none says the playbook's
	// only -e arguments are ones pilot made itself and set no connection
	// variable (accessgrants.applyPlan; TestExtraVarsCarryNoConnectionSetting).
	// Passing less than the playbook gets reopens issue #319.
	ExtraArgs []string
	// Hosts, when not nil, are the inventory hosts the run is going to change
	// (the deploy runner has resolved them already, honoring --limit,
	// target_group and availability). They must be among the hosts the
	// playbook's own `hosts:` resolves to under ExtraArgs, or the lock refuses.
	// nil asks the acquirer to resolve that pattern itself: target_group when
	// the effective variables set it, else `freeipa-server`
	// (accessgrants.applyPlan and the decommission converge pass no limit).
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
// The target is what ansible-playbook will use, not what the inventory alone
// says (issue #319; identity_lock_effective.go): the host variables come from
// ansible-inventory run with req.ExtraArgs, so `-e @file` and `-e key=value`
// layer over the inventory as they will for the playbook; the playbook's
// `hosts:` pattern is the effective target_group, and a host the run was handed
// that the pattern does not reach is refused; and the connection settings of
// ansible.cfg and the ANSIBLE_* environment (ansible-config) fill in what the
// host does not set. Whichever of these the lock cannot read or cannot honor is
// an error: the playbook is not run without the lock, and not with a lock on
// another machine.
//
// An inventory it cannot derive an ssh Target from (a docker or local
// connection, ProxyCommand, a password, an option outside the allowlist of
// sshdial.Target) is an error that names the variable, and where the variable
// came from when it was not the inventory.
func identityLockTarget(ctx context.Context, req identityLockRequest) (string, sshdial.Target, error) {
	if req.Runtime != nil {
		ctx = withDeployAnsibleRuntime(ctx, *req.Runtime)
	}
	snapshot, err := loadDeployInventorySnapshotWithArgs(ctx, req.Inventory, req.ExtraArgs)
	if err != nil {
		return "", sshdial.Target{}, fmt.Errorf("不能讀出 playbook 實際會用的 inventory 變數(ansible-inventory 帶著與 playbook 相同的 -e／vault 參數)，所以不能確定鎖要取在哪台：%w", err)
	}
	group, err := effectiveTargetGroup(snapshot.HostVars)
	if err != nil {
		return "", sshdial.Target{}, fmt.Errorf("不能對 %s 取 FreeIPA 的 %s 鎖：%w", req.Inventory, sshdial.DefaultLockPath, err)
	}
	hosts := req.Hosts
	// A run handed its hosts is only asked when target_group says the playbook
	// does not run on the default group: the hosts a funnel hands over are
	// freeipa-server members by construction, so the default needs no second
	// look and costs no second ansible run.
	if hosts == nil || group != identityDefaultTargetGroup {
		playbookHosts, err := resolvePatternHosts(ctx, req.Inventory, group, "")
		if err != nil {
			return "", sshdial.Target{}, fmt.Errorf("resolve the hosts freeipa-identity-apply.yml runs on (target_group %q) in %s to lock: %w", group, req.Inventory, err)
		}
		if hosts == nil {
			hosts = playbookHosts
		} else if outside := hostsOutside(hosts, playbookHosts); len(outside) > 0 {
			return "", sshdial.Target{}, fmt.Errorf("鎖與 playbook 的目標會不同台，所以不執行：這輪要鎖 %v，但 playbook 的 hosts 是 target_group=%q，只會對 %v 執行(target_group 來自 -e 或 inventory 變數；讓兩者一致，或移除 target_group)", outside, group, playbookHosts)
		}
	}
	if len(hosts) != 1 {
		return "", sshdial.Target{}, fmt.Errorf("freeipa-identity 取鎖需要剛好一台 freeipa-server 主機(contract hostCardinality: exactly-one)，%s 有 %d 台：%v", req.Inventory, len(hosts), hosts)
	}
	host := hosts[0]
	defaults, err := loadAnsibleConnectionConfig(ctx)
	if err != nil {
		return "", sshdial.Target{}, fmt.Errorf("不能讀出 Ansible 設定(ansible.cfg、ANSIBLE_* 環境變數)裡的連線設定，所以不能確定 playbook 會怎麼連 %s：%w", host, err)
	}
	if defaults.AskPass != "" {
		return "", sshdial.Target{}, fmt.Errorf("不能對 %s 取 FreeIPA 的 %s 鎖，所以不執行 freeipa-identity-apply.yml：%s 開啟了 ask_pass，playbook 會用 ssh 密碼連線，pilot 的 ssh 不支援", host, sshdial.DefaultLockPath, defaults.AskPass)
	}
	vars, applied := withConnectionDefaults(snapshot.HostVars[host], defaults)
	target, err := sshdial.TargetFromHostVars(host, vars)
	if err != nil {
		if len(applied) > 0 {
			err = fmt.Errorf("%w(%s 沒有自己設定的連線變數，採用了 Ansible 設定：%s)", err, host, strings.Join(applied, "；"))
		}
		return "", sshdial.Target{}, fmt.Errorf("不能對 %s 取 FreeIPA 的 %s 鎖，所以不執行 freeipa-identity-apply.yml(它一律先取鎖，不會無鎖執行)：%w", host, sshdial.DefaultLockPath, err)
	}
	return host, target, nil
}

// hostsOutside returns the hosts of want that are not in have.
func hostsOutside(want, have []string) []string {
	var outside []string
	for _, host := range want {
		if !slices.Contains(have, host) {
			outside = append(outside, host)
		}
	}
	return outside
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
