package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/store"
)

// pilot reconcile --engine golang --scope full (spec 2026-11-06 phase 2 §8.3, D28): the mixed
// run. The Go engine writes the users and groups of the roster, and the identity playbook, told
// with -e pilot_identity_users_groups_engine=go to skip those two sections, does everything
// else and acknowledges the authorization cache obligation the Go writes created.
//
// It is the Ansible engine's own reconcile path (the wizard's defaults driver, the dependency
// chain, availability, preview, stage, history, webhook, idempotency), with one change that only
// the command makes: a marker on the context, which executeRecordedDeploymentCore reads for the
// identity transaction and for nothing else. What the marker adds to that transaction:
//
//   - the preview: the Go engine's read-only plan first (a blocked plan fails the preview before
//     the playbook has been asked anything, and nothing is locked);
//   - the apply: under the lock the apply step took, PrepareApply is the Go writer (the entry, the
//     writes, the read after them). When it did not apply and verify its plan, the apply step
//     fails there and the playbook is never started (§7.6); when it committed anything, every
//     later failure is a partial application (§6.1);
//   - the runs of the playbook: each goes through AuthCacheOutput.Run, which makes the file the
//     playbook's observation task writes a new empty one first and reads it after, so a run reads
//     only what it wrote itself;
//   - the verification: after `pilot verify`, the apply's observation must say acked, or the run
//     is ErrUnsettled (exit code 4);
//   - the idempotency re-apply: the Go plan must have no operation after it.
//
// The roster's HBAC (spec 2026-11-19 phase 3a) is the Go engine's too, in a second Go stage after the
// playbook, because the hosts and hostgroups a rule refers to are created by it. The playbook is told
// -e pilot_identity_hbac_engine=go (its HBAC tasks do nothing for the roster) and its first apply run is
// told to defer the authorization cache settlement; the Go HBAC stage then writes, under the same lock,
// and a second playbook run, --tags client-cache, refreshes the clients' caches and acknowledges the
// obligation for what both Go stages wrote (applyMixedPlaybook):
//
//	Go(users/groups) -> playbook run 1 (settle deferred) -> Go(HBAC) -> playbook run 2 (client-cache)
//
// The preview adds the HBAC plan's read to the Go plan, and the idempotency check adds the HBAC plan to
// the Go plan that must be empty.

type mixedIdentityRunKey struct{}

func withMixedIdentityRun(ctx context.Context, run *mixedIdentityRun) context.Context {
	return context.WithValue(ctx, mixedIdentityRunKey{}, run)
}

func mixedIdentityRunFrom(ctx context.Context) *mixedIdentityRun {
	run, _ := ctx.Value(mixedIdentityRunKey{}).(*mixedIdentityRun)
	return run
}

// mixedIdentityRun is one `--scope full` command.
type mixedIdentityRun struct {
	cmd         *cobra.Command
	runtime     deployAnsibleRuntime
	timeout     time.Duration
	previewOnly bool
	planOut     *outputFile

	mu    sync.Mutex
	steps []*mixedStep
}

// begin makes the state of the identity transaction that is about to be set up.
func (r *mixedIdentityRun) begin(inv, limit, stage string) (*mixedStep, error) {
	out, err := identityreconcile.NewAuthCacheOutput()
	if err != nil {
		return nil, err
	}
	s := &mixedStep{run: r, inv: inv, limit: limit, stage: stage, out: out}
	r.mu.Lock()
	r.steps = append(r.steps, s)
	r.mu.Unlock()
	return s, nil
}

// last is the identity transaction the command ran (there is one: a second would be a second
// freeipa-identity request, which the exactly-one contract of the component does not allow).
func (r *mixedIdentityRun) last() *mixedStep {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.steps) == 0 {
		return nil
	}
	return r.steps[len(r.steps)-1]
}

// mixedStep is the identity transaction of a mixed run: what the Go phase did, what the playbook
// observed, and how the transaction ended.
type mixedStep struct {
	run               *mixedIdentityRun
	inv, limit, stage string
	out               *identityreconcile.AuthCacheOutput
	writer            *store.RunWriter

	// The Go phase.
	prep    *golangPrep
	session *golangSession // ended; its names and versions are what the summary shows
	host    string         // the inventory host the lock is on
	fqdn    string         // what the lock's own ssh reports for it
	res     *identityreconcile.Result
	execErr error
	stats   freeiparpc.Stats
	started time.Time

	// The playbook: whether its apply was started, and the observation of its last apply run, which
	// is its second one (the settlement, after the HBAC stage) when the run got that far.
	playbookRan bool
	obs         *identityreconcile.AuthCacheResult
	obsErr      error

	// The Go HBAC stage (after the playbook's first apply run).
	hbacRan     bool   // the stage connected and ran the writer
	hbacSkipped string // why it did not, when it did not
	hbacRes     *identityreconcile.HBACResult
	hbacErr     error
	hbacStats   freeiparpc.Stats
	secondRun   bool // the playbook's second apply run was started

	// The transaction.
	tx    delivery.Result
	runID string
}

// extraVars are the variables the playbook is told the Go engine owns the users, the groups and the
// roster's HBAC with. They go to every run of the playbook (the preview, both apply runs and the
// idempotency run); the playbook's gate refuses the HBAC one without the first. The observation file's
// path is not among them: AuthCacheOutput.Run hands it to each run, and neither is the settlement
// deferral, which only the first apply run is told (applyMixedPlaybook).
func (s *mixedStep) extraVars() []string {
	return []string{
		identityreconcile.UsersGroupsEngineVar + "=" + identityreconcile.UsersGroupsEngineGo,
		identityreconcile.HBACEngineVar + "=" + identityreconcile.HBACEngineGo,
	}
}

// addMetadata says in the run's metadata which engine and scope this was (the filter of
// `pilot runs last-success` reads scope, and a mixed run is one it counts: it ran the playbook).
func (s *mixedStep) addMetadata(metadata map[string]any) {
	metadata["engine"] = reconcileEngineGolang
	metadata["scope"] = reconcileScopeFull
	metadata["hbac_engine"] = identityreconcile.HBACEngineGo
	metadata["pilot_revision"] = pilotRevision()
}

func (s *mixedStep) bind(w *store.RunWriter) { s.writer = w }

func (s *mixedStep) close() { _ = s.out.Close() }

func (s *mixedStep) finished(tx delivery.Result, runID string) { s.tx, s.runID = tx, runID }

// committed reports whether a Go writer (the users and groups phase or the HBAC stage) changed FreeIPA, or may have: from then on a failure of
// any step is a partial application, and not an ordinary failure with nothing to say.
func (s *mixedStep) committed() bool {
	return (s.res != nil && s.res.Committed()) || (s.hbacRes != nil && s.hbacRes.Committed())
}

// partial shapes err for a step that fails after the Go writer committed.
func (s *mixedStep) partial(err error) error {
	if err != nil && s.committed() && !errors.Is(err, delivery.ErrPartiallyApplied) {
		return fmt.Errorf("%w: %w", delivery.ErrPartiallyApplied, err)
	}
	return err
}

// preflight is the Go phases' preflight for this transaction's inventory, limit and stage. The roster's hbac
// section is no longer left to the playbook in this run (the Go HBAC stage writes it), so it is not reported
// as outside the Go engine's scope.
func (s *mixedStep) preflight(ctx context.Context) (*golangPrep, error) {
	prep, err := golangPreflightFor(ctx, s.run.runtime, golangPreflightInput{Inventory: s.inv, Limit: s.limit, Stage: s.stage, Attested: stagingAttestedHoursFlag})
	if err != nil {
		return nil, err
	}
	prep.desired = prep.desired.WithoutNotInScope("hbac")
	return prep, nil
}

// mixedLink is a connection of the mixed run's Go writers to the FreeIPA server: the dialer, the write gate
// the client asks, and the logged-in session. The users and groups phase and the HBAC stage each make their own.
type mixedLink struct {
	dialer  golangDialer
	gate    *identityreconcile.Gate
	session *golangSession
}

// newMixedLink connects with a client whose writes the gate decides. On a failure nothing it started is left.
func newMixedLink(ctx context.Context, prep *golangPrep) (*mixedLink, error) {
	dialer := newGolangDialer(prep.target)
	gate := identityreconcile.NewGate()
	session, err := golangConnect(ctx, prep, dialer, freeiparpc.Config{WriteGate: gate.Check})
	if err != nil {
		dialer.Close()
		return nil, err
	}
	return &mixedLink{dialer: dialer, gate: gate, session: session}, nil
}

// close logs out and ends every ssh the dialer started, in that order.
func (l *mixedLink) close() {
	l.session.close()
	l.dialer.Close()
}

// newEntry is the authorization cache entry of a Go writer of this run: it records the obligation on the host
// the run holds the lock of, before the writer's first write.
func (s *mixedStep) newEntry(held *identitylock.Held, prep *golangPrep, fqdn string) (identityreconcile.Entry, error) {
	root, err := resolveContractRoot("")
	if err != nil {
		return nil, err
	}
	stageVars := golangStageVars(prep.stage, stagingAttestedHoursFlag)
	entry, err := identityreconcile.NewAuthCacheEntry(s.out, held, fqdn, func(c context.Context, extraVars string) (int, error) {
		return runGoAuthCacheEntry(c, held, root, prep, stageVars, extraVars, s.run.cmd.ErrOrStderr())
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// mixedApplyError is what the apply step reports of the Go phase. Anything but a plan that was
// applied and verified fails the step, and so the playbook is never started: an operation that
// failed or is unknown, a read after the writes that failed or shows something left on an object
// the run changed (D20), a blocked plan, a journal that could not be written. A run that
// committed something (or may have) is a partial application and is not rolled back, which is the
// point of the type; one that changed nothing is an ordinary failure, with a note when the entry
// had run, since the obligation is then recorded on the server for nothing.
func mixedApplyError(res *identityreconcile.Result, err error) error {
	switch {
	case err == nil:
		return nil
	case res != nil && res.Committed():
		return fmt.Errorf("%w: Go 階段沒有完成，identity playbook 沒有執行：%w", delivery.ErrPartiallyApplied, err)
	case res != nil && res.Entry.Ran:
		return fmt.Errorf("mixed run 的 Go 階段沒有完成，identity playbook 沒有執行：%w (入口已執行，授權快取義務已記錄；多一次刷新，無害)", err)
	}
	return fmt.Errorf("mixed run 的 Go 階段沒有完成，identity playbook 沒有執行：%w", err)
}

// PrepareApply is the Go writer's phase of the apply step: the transaction's lock is in ctx.
func (s *mixedStep) PrepareApply(ctx context.Context) error {
	held, err := identitylock.Require(ctx)
	if err != nil {
		return err
	}
	return runMixedGoPhase(ctx, held, s)
}

// runMixedGoPhase prepares the run the way the users-groups scope does (the same preflight, for the
// inventory, limit and stage of this transaction), connects to the FreeIPA server the lock is on
// and runs the Go writer: the entry, the writes, the read after them. It takes the lock the apply
// step holds, as every function that runs the entry or the writer must (the lint of
// identity_lock_funnel_test.go). The connection ends before it returns, and before the playbook
// starts.
func runMixedGoPhase(ctx context.Context, held *identitylock.Held, s *mixedStep) error {
	out := s.run.cmd.OutOrStdout()
	fmt.Fprintf(out, "▶ Go 階段（--scope %s）：Go engine 寫入 users 與 groups，成功並驗證之後才執行 identity playbook（它會略過這兩個區段）\n", reconcileScopeFull)
	runCtx, cancel := context.WithTimeout(ctx, s.run.timeout)
	defer cancel()
	prep, err := s.preflight(runCtx)
	if err != nil {
		return mixedApplyError(nil, err)
	}
	if prep.host != held.Host {
		return mixedApplyError(nil, fmt.Errorf("mixed run：Go engine 要寫的 FreeIPA server 是 %s，但這一輪的鎖在 %s：不寫入", prep.host, held.Host))
	}
	s.prep, s.host = prep, prep.host
	link, err := newMixedLink(runCtx, prep)
	if err != nil {
		return mixedApplyError(nil, err)
	}
	defer link.close()
	session, gate := link.session, link.gate
	s.session, s.fqdn = session, session.fqdn
	passwords, err := identityreconcile.NewRosterPasswords(prep.rosterData)
	if err != nil {
		return mixedApplyError(nil, fmt.Errorf("roster 的密碼：%w", err))
	}
	entry, err := s.newEntry(held, prep, session.fqdn)
	if err != nil {
		return mixedApplyError(nil, err)
	}
	s.started = time.Now()
	res, execErr := identityreconcile.Execute(runCtx, session.client, identityreconcile.Options{
		Desired: prep.desired, Passwords: passwords, Entry: entry, Gate: gate,
		Journal: storeJournal{w: s.writer},
	})
	s.res, s.execErr, s.stats = res, execErr, session.client.Stats()
	if execErr == nil {
		fmt.Fprintf(out, "✅ Go 階段完成：%d 個寫入已套用並驗證；接著執行 identity playbook\n", len(res.Ops))
	}
	return mixedApplyError(res, execErr)
}

// WrapStep implements mixedTransaction.
func (s *mixedStep) WrapStep(step string, inner delivery.StepFunc) delivery.StepFunc {
	switch step {
	case "preview":
		return func(ctx context.Context) error {
			// The Go plan before anything of the playbook, so a plan with blocked objects ends the
			// preview with no playbook task having run, and no lock taken (spec §8.3, A16).
			if err := s.previewGoPlan(ctx); err != nil {
				return err
			}
			return inner(ctx)
		}
	case "apply":
		return func(ctx context.Context) error { return s.partial(inner(ctx)) }
	case "verify":
		return func(ctx context.Context) error {
			if inner != nil {
				if err := inner(ctx); err != nil {
					return s.partial(err)
				}
			}
			return s.partial(s.settled())
		}
	case "idempotency":
		return func(ctx context.Context) error {
			if err := inner(ctx); err != nil {
				return s.partial(err)
			}
			return s.partial(s.goPlanIsEmpty(ctx))
		}
	}
	return inner
}

// previewGoPlan is the Go engine's read-only plan for the preview step: the preflight of this
// transaction's inventory, limit and stage, a read-only client, no lock. A blocked plan is the
// error, with the exit code 3 the Go preview gives it. It records the server's name, which the
// observation of the playbook's runs is checked against.
func (s *mixedStep) previewGoPlan(ctx context.Context) error {
	out := s.run.cmd.OutOrStdout()
	fmt.Fprintf(out, "▶ Go 階段的唯讀預覽（--scope %s）：先看 Go engine 對 users、groups 與 HBAC 的 plan（HBAC 是 playbook 之後的第二個 Go 階段，預覽時 roster 宣告而 FreeIPA 還沒有的 host、hostgroup、service 視為 playbook 會建立）\n", reconcileScopeFull)
	runCtx, cancel := context.WithTimeout(ctx, s.run.timeout)
	defer cancel()
	prep, err := s.preflight(runCtx)
	if err != nil {
		return err
	}
	var planOut *outputFile
	if s.run.previewOnly {
		planOut = s.run.planOut
	}
	doc, err := golangPreviewPlan(runCtx, out, prep, planOut, golangHBACPreview)
	if doc.Target.FQDN != "" {
		s.host, s.fqdn = prep.host, doc.Target.FQDN
	}
	return err
}

// goPlanIsEmpty is the idempotency check of the Go part: after the playbook's second run, the
// Go engine's read-only plan must have nothing to do. The playbook's own check is changed=0.
func (s *mixedStep) goPlanIsEmpty(ctx context.Context) error {
	out := s.run.cmd.OutOrStdout()
	runCtx, cancel := context.WithTimeout(ctx, s.run.timeout)
	defer cancel()
	prep, err := s.preflight(runCtx)
	if err != nil {
		return fmt.Errorf("冪等性檢查的 Go 唯讀 plan：%w", err)
	}
	doc, err := golangPreviewPlan(runCtx, out, prep, nil, golangHBACApplied)
	if err != nil {
		return fmt.Errorf("冪等性檢查的 Go 唯讀 plan：%w", err)
	}
	if n := len(doc.Operations); n != 0 {
		return fmt.Errorf("冪等性檢查失敗：第二次套用之後，users／groups 的 Go 唯讀 plan 仍有 %d 個操作", n)
	}
	if doc.HBAC == nil {
		return errors.New("冪等性檢查失敗：沒有 HBAC 的 Go 唯讀 plan，無法確認 HBAC 已收斂")
	}
	if n := len(doc.HBAC.Operations); n != 0 {
		return fmt.Errorf("冪等性檢查失敗：第二次套用之後，HBAC 的 Go 唯讀 plan 仍有 %d 個操作", n)
	}
	fmt.Fprintln(out, "✓ 冪等性檢查通過 (users／groups 與 HBAC 的 Go 唯讀 plan 都沒有操作)")
	return nil
}

// RunPlaybook implements mixedTransaction: every run of the playbook goes through the
// observation file's Run, which makes it a new empty file before the run and reads it after, so
// the run reads only what it wrote itself. The command's own result and error are returned as
// they were: whether the run failed is the apply step's to say, and what it observed is the
// verification's. The preview and the idempotency run are handed the file too (the playbook
// refuses the engine variables without it); a preview writes nothing, and the idempotency run's
// observation is for the record. The apply is two playbook runs with the Go HBAC stage between
// them (applyMixedPlaybook), and it is the last one's observation that settles the obligation (§5.4).
func (s *mixedStep) RunPlaybook(ctx context.Context, step string, run playbookRun) (*ansible.Result, error) {
	// A context that has ended (the first Ctrl-C, --timeout) starts nothing: the Go phase can end a run on a
	// converged unknown write that returns no error, and the playbook does not start after the signal that
	// cut it. The result file then says the playbook did not run, which is true.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("identity playbook (%s) 沒有啟動：%w", step, context.Cause(ctx))
	}
	if step == "apply" {
		s.playbookRan = true
		return applyMixedPlaybook(ctx, s, run)
	}
	o := s.playbookOnce(ctx, step, run, nil)
	if !o.started() {
		// The file could not be made: the playbook was not started.
		return nil, o.obsErr
	}
	return o.res, o.runErr
}

// playbookOutcome is one run of the playbook: what the command returned, and the observation the run wrote.
type playbookOutcome struct {
	res    *ansible.Result
	runErr error
	obs    *identityreconcile.AuthCacheResult // the accepted observation; nil when none was
	obsErr error
}

// started: the playbook was started. It was not when the observation file could not be made.
func (o playbookOutcome) started() bool { return o.res != nil || o.runErr != nil }

// succeeded: the playbook ran and exited 0.
func (o playbookOutcome) succeeded() bool {
	return o.runErr == nil && o.res != nil && o.res.ExitCode == 0
}

// failure is why the run did not succeed, in words for the step's error; nil for one that did.
func (o playbookOutcome) failure(what string) error {
	switch {
	case !o.started() && o.obsErr != nil:
		return fmt.Errorf("%s沒有啟動：%w", what, o.obsErr)
	case !o.started():
		return fmt.Errorf("%s沒有啟動", what)
	case o.runErr != nil:
		return fmt.Errorf("%s失敗：%w", what, o.runErr)
	case o.res.ExitCode != 0:
		return fmt.Errorf("%s失敗(結束碼 %d)", what, o.res.ExitCode)
	}
	return nil
}

// playbookOnce runs the playbook once through the observation file's Run, with the extra arguments after the
// transaction's own and the file's. label says which run it is in the line printed first.
func (s *mixedStep) playbookOnce(ctx context.Context, label string, run playbookRun, extra []string) playbookOutcome {
	// The command line printed before this run does not have the file the observation is written to: it is made
	// new for each run and handed to it here (AuthCacheOutput.Run).
	fmt.Fprintf(s.run.cmd.OutOrStdout(), "ℹ️  identity playbook（%s）另外帶入 -e {\"%s\": <暫存檔>}：它的觀察結果檔，每次執行前重建為空檔\n", label, identityreconcile.AuthCacheOutputVar)
	want := identityreconcile.AuthCacheWant{Action: identityreconcile.AuthCacheObserve, Host: s.host, FQDN: s.fqdn}
	var o playbookOutcome
	obs, obsErr := s.out.Run(ctx, want, func(c context.Context, vars string) (int, error) {
		o.res, o.runErr = run(c, append([]string{"-e", vars}, extra...))
		if o.runErr != nil {
			return 0, o.runErr
		}
		return o.res.ExitCode, nil
	})
	o.obsErr = obsErr
	if obsErr == nil {
		o.obs = &obs
	}
	return o
}

// recordObservation keeps what a run of the apply observed: it replaces what the run before it did, so a run
// that wrote nothing has no observation, not the earlier one's. The last run's is the one the obligation is
// settled by.
func (s *mixedStep) recordObservation(o playbookOutcome) { s.obs, s.obsErr = o.obs, o.obsErr }

// hbacSkip says why the HBAC stage did not run and returns err as the stage's error (mixedHBACError).
func (s *mixedStep) hbacSkip(reason string, err error) error {
	if s.hbacSkipped == "" {
		s.hbacSkipped = reason
	}
	return mixedHBACError(nil, err)
}

// applyMixedPlaybook is the apply step's playbook of a mixed run (spec 2026-11-19 phase 3a D1, D6, D7, §7.2):
//
//  1. the first run, told to defer the authorization cache settlement: the Go HBAC stage writes after it,
//     and a refresh of the clients' caches before that would settle nothing the stage did;
//  2. when it succeeded, the HBAC stage, under the lock the apply step holds;
//  3. whatever became of the stage, the second run (--tags client-cache), which refreshes the caches and
//     acknowledges the obligation for what the Go phases and the first run wrote (spec Q2: a stage that
//     failed part way still wrote something that needs the refresh).
//
// A first run that failed ends the step: neither the stage nor the second run starts, and the obligation
// stays owed. The step fails when the stage or the second run did, with both reasons; it returns the first
// run's result otherwise, for the transaction's recap check. The observation recorded is the last run's.
func applyMixedPlaybook(ctx context.Context, s *mixedStep, run playbookRun) (*ansible.Result, error) {
	first := s.playbookOnce(ctx, "apply，第 1 次：授權快取的刷新延後到 HBAC 階段之後", run,
		[]string{"-e", identityreconcile.CacheSettleVar + "=" + identityreconcile.CacheSettleDefer})
	s.recordObservation(first)
	if !first.started() {
		s.hbacSkipped = "identity playbook 的第 1 次執行沒有啟動"
		return nil, first.obsErr // gate: mixed-first-run-not-started
	}
	if !first.succeeded() {
		s.hbacSkipped = "identity playbook 的第 1 次執行失敗"
		return first.res, first.runErr // gate: mixed-first-run-failed
	}
	held, err := identitylock.Require(ctx)
	if err != nil {
		s.hbacSkipped = "這一輪沒有持有 FreeIPA server 的鎖"
		return first.res, fmt.Errorf("HBAC 階段與第二次 playbook 執行沒有啟動：%w", err) // gate: mixed-hbac-lock
	}
	if err := ctx.Err(); err != nil {
		s.hbacSkipped = "這一輪的 context 在 playbook 的第 1 次執行之後結束"
		return first.res, fmt.Errorf("HBAC 階段與第二次 playbook 執行沒有啟動：%w", context.Cause(ctx)) // gate: mixed-hbac-ctx
	}
	stageErr := mixedHBACStage(ctx, held, s)
	if err := ctx.Err(); err != nil {
		return first.res, errors.Join(stageErr, fmt.Errorf("第二次 playbook 執行沒有啟動（授權快取義務未結清）：%w", context.Cause(ctx))) // gate: mixed-second-run-ctx
	}
	second := s.playbookOnce(ctx, "apply，第 2 次：--tags "+identityreconcile.ClientCacheTag, run, []string{"--tags", identityreconcile.ClientCacheTag})
	s.secondRun = second.started()
	s.recordObservation(second)
	if stageErr != nil || !second.succeeded() {
		return first.res, errors.Join(stageErr, second.failure("identity playbook 的第 2 次執行(授權快取的刷新與確認)")) // gate: mixed-hbac-or-second-run-failed
	}
	return first.res, nil
}

// mixedHBACStage is the Go HBAC stage of the apply (spec 2026-11-19 phase 3a §5, §7.2): the writer of the
// roster's HBAC, on its own connection, under the lock the apply step holds, with its own authorization
// cache entry (the obligation is recorded before its first write, whatever the users and groups phase did)
// and the run's journal. It takes the lock as every function that runs the entry or the writer must (the lint
// of identity_lock_funnel_test.go). What it did is on the step; the error is the stage's, shaped by
// mixedHBACError.
func mixedHBACStage(ctx context.Context, held *identitylock.Held, s *mixedStep) error {
	prep := s.prep
	if prep == nil {
		return s.hbacSkip("Go 階段沒有準備好這一輪", errors.New("HBAC 階段：Go 階段沒有留下這一輪的 preflight，不寫入")) // gate: mixed-hbac-no-prep
	}
	if prep.host != held.Host {
		return s.hbacSkip("這一輪的鎖在另一台 FreeIPA server", fmt.Errorf("HBAC 階段：要寫的 FreeIPA server 是 %s，但這一輪的鎖在 %s：不寫入", prep.host, held.Host)) // gate: mixed-hbac-host
	}
	desired, err := identityreconcile.HBACFromRoster(prep.root)
	if err != nil {
		return s.hbacSkip("roster 的 HBAC 不能讀", fmt.Errorf("roster 的 HBAC：%w", err)) // gate: mixed-hbac-desired
	}
	out := s.run.cmd.OutOrStdout()
	fmt.Fprintf(out, "▶ HBAC 階段（--scope %s）：identity playbook 的第 1 次執行完成，Go engine 寫入 roster 的 HBAC，成功並驗證之後才執行第二次 playbook（--tags %s）\n", reconcileScopeFull, identityreconcile.ClientCacheTag)
	runCtx, cancel := context.WithTimeout(ctx, s.run.timeout)
	defer cancel()
	link, err := newMixedLink(runCtx, prep)
	if err != nil {
		return s.hbacSkip("連不上 FreeIPA", err) // gate: mixed-hbac-connect
	}
	defer link.close()
	entry, err := s.newEntry(held, prep, link.session.fqdn)
	if err != nil {
		return s.hbacSkip("授權快取的入口不能建立", err) // gate: mixed-hbac-entry
	}
	s.hbacRan = true
	res, execErr := identityreconcile.ExecuteHBAC(runCtx, link.session.client, identityreconcile.HBACOptions{
		Desired: desired, Entry: entry, Gate: link.gate, Journal: storeJournal{w: s.writer}, TestHost: link.session.fqdn,
	})
	s.hbacRes, s.hbacErr, s.hbacStats = res, execErr, link.session.client.Stats()
	if execErr == nil {
		fmt.Fprintf(out, "✅ HBAC 階段完成：%d 個寫入已套用並驗證；接著執行第二次 playbook（授權快取的刷新與確認）\n", len(res.Ops))
	}
	return mixedHBACError(res, execErr) // gate: mixed-hbac-result
}

// mixedHBACError is what the apply step reports of the HBAC stage; only a plan that was applied and verified
// is nil, as for the users and groups phase (mixedApplyError). A stage that committed something is a partial
// application, which is not rolled back. A plan with blocked objects wrote nothing, but it is not the exit
// code 3 a blocked users and groups plan is: that code says nothing at all was written, and the playbook's
// first run has run, so the cause is kept as text and the run exits 1.
func mixedHBACError(res *identityreconcile.HBACResult, err error) error {
	switch {
	case err == nil:
		return nil
	case res != nil && res.Committed():
		return fmt.Errorf("%w: HBAC 階段沒有完成，已寫入的不回滾：%w", delivery.ErrPartiallyApplied, err)
	case errors.Is(err, identityreconcile.ErrBlocked):
		return fmt.Errorf("HBAC 階段的 plan 有被阻擋的物件，HBAC 階段沒有寫入任何東西（identity playbook 的第 1 次執行已經完成）：%v", err)
	case res != nil && res.Entry.Ran:
		return fmt.Errorf("HBAC 階段沒有完成：%w (入口已執行，授權快取義務已記錄；多一次刷新，無害)", err)
	}
	return fmt.Errorf("HBAC 階段沒有完成：%w", err)
}

// unsettledMixed is the message of a mixed run whose playbook ran and did not acknowledge: what
// is still true, and what settles it.
const unsettledMixed = "授權快取義務未結清：identity playbook 已執行，但它的觀察結果沒有說已確認(acked)——可能是 ipa_identity_refresh_sssd_cache 為 false、有 optional client 被延後(pilot_deferred_hosts)、有 client 沒有完成刷新，或這次的 tag 沒有選到 settle；client 在 SSSD 快取過期前可能仍沿用舊授權；改正之後再執行一次 pilot reconcile --engine golang --scope full --force 或 Ansible engine 的完整 apply 會刷新所有 enrolled client"

// settled is the verification of the obligation (spec §8.3, §6.2): the apply run's observation
// must say the playbook acknowledged it. An observation that is missing, empty, of another host or
// that says no, is not settled: it is never read as "nothing was owed".
func (s *mixedStep) settled() error {
	switch {
	case !s.playbookRan:
		return fmt.Errorf("%w: 授權快取義務未結清：identity playbook 沒有執行過，沒有它的觀察結果", identityreconcile.ErrUnsettled)
	case s.obsErr != nil:
		return fmt.Errorf("%w: %s (沒有接受 identity playbook 的觀察結果：%v)", identityreconcile.ErrUnsettled, unsettledMixed, s.obsErr)
	case s.obs == nil || !s.obs.Acked:
		return fmt.Errorf("%w: %s", identityreconcile.ErrUnsettled, unsettledMixed)
	}
	return nil
}

// finish is what follows the whole command: the result file, with the Go phase's plans and
// outcomes and the playbook's observation, and the summary. The terminal publication was made by
// the batch the transaction ran in; this is the file and the lines on stdout, written on the way
// out of a run that may have been cancelled (a local write: T4 of spec §4.4).
func (r *mixedIdentityRun) finish(cmd *cobra.Command, err error, resultOut *outputFile) {
	s := r.last()
	if s == nil || s.res == nil || !s.res.Observed || s.prep == nil || s.session == nil {
		return // the Go phase never read FreeIPA: nothing to report, and no file (spec §8.6)
	}
	out := cmd.OutOrStdout()
	code := golangApplyExitCode(err)
	pb := &identityreconcile.PlaybookReport{Ran: s.playbookRan}
	if s.obs != nil {
		pb.Observation = &identityreconcile.ObservationDoc{Prepared: s.obs.Prepared, Dirty: s.obs.Dirty, Refreshed: s.obs.Refreshed, Acked: s.obs.Acked}
	} else if s.playbookRan && s.obsErr != nil {
		pb.ObservationError = s.obsErr.Error()
	}
	doc := identityreconcile.NewApplyDocument(identityreconcile.ApplyDocumentInput{
		Desired: s.prep.desired, Result: *s.res, Target: s.session.target(s.prep), Server: s.session.serverInfo(),
		Revision: pilotRevision(), Stage: s.stage, RunID: s.runID, Outcome: string(s.tx.Outcome),
		FailedStep: s.tx.FailedStep, ExitCode: code, Err: err,
		Stats: identityreconcile.Stats{HTTPRequests: s.stats.HTTPRequests, Reads: s.stats.Reads, Writes: s.stats.Writes, Relogins: s.stats.Relogins, ReadRetries: s.stats.ReadRetries},
		Scope: identityreconcile.ScopeFull, Playbook: pb, HBAC: s.hbacReport(),
	})
	printGolangApply(out, reconcileScopeFull, s.prep, &golangApplyRun{res: s.res, tx: s.tx, runID: s.runID, session: s.session, stats: s.stats, started: s.started}, doc, true)
	printMixedHBAC(out, s)
	printMixedPlaybook(out, s)
	if resultOut == nil {
		return
	}
	data, rerr := doc.Render()
	if rerr == nil {
		rerr = commitOutput(resultOut, data)
	}
	if rerr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "警告：沒有寫出 --result-out：%v\n", rerr)
		return
	}
	fmt.Fprintf(out, "result JSON：%s\n", resultOut.path)
}

// hbacReport is the HBAC stage's account for the result file: what it did, or why it did not run.
func (s *mixedStep) hbacReport() *identityreconcile.HBACReport {
	rep := &identityreconcile.HBACReport{Ran: s.hbacRan, Skipped: s.hbacSkipped, Result: s.hbacRes}
	if s.hbacRan {
		rep.Stats = identityreconcile.Stats{HTTPRequests: s.hbacStats.HTTPRequests, Reads: s.hbacStats.Reads, Writes: s.hbacStats.Writes, Relogins: s.hbacStats.Relogins, ReadRetries: s.hbacStats.ReadRetries}
	}
	if s.hbacErr != nil {
		rep.Error = s.hbacErr.Error()
	}
	if !s.hbacRan && rep.Skipped == "" {
		rep.Skipped = "這一輪在 HBAC 階段之前就停了"
	}
	return rep
}

// printMixedHBAC says what the HBAC stage did, in a few lines: the plan it applied, how each operation ended,
// the lockdown with the truth about its rollback, and why it did not run when it did not.
func printMixedHBAC(out io.Writer, s *mixedStep) {
	rep := s.hbacReport()
	if !rep.Ran {
		fmt.Fprintf(out, "HBAC 階段：沒有執行（%s）\n", rep.Skipped)
		return
	}
	res := rep.Result
	if res == nil || !res.Observed {
		fmt.Fprintf(out, "HBAC 階段：已連線，但沒有讀到 HBAC（%s）\n", rep.Error)
		return
	}
	counts := res.Counts()
	fmt.Fprintf(out, "HBAC 階段：%d 個操作（成功 %d、無變更 %d、衝突 %d、失敗 %d、未確定 %d、沒有送出 %d）；驗證：%s\n",
		len(res.Ops), counts[identityreconcile.OutcomeSuccess], counts[identityreconcile.OutcomeNoop], counts[identityreconcile.OutcomeConflictFailed],
		counts[identityreconcile.OutcomeFailed], counts[identityreconcile.OutcomeUnknown], counts[identityreconcile.OutcomeNotExecuted], hbacVerifyLine(res))
	if l := res.Lockdown; l != nil {
		fmt.Fprintf(out, "HBAC allow_all lockdown：%s\n", l.Detail)
	}
	if rep.Error != "" {
		fmt.Fprintf(out, "HBAC 階段的錯誤：%s\n", rep.Error)
	}
}

// hbacVerifyLine is the verification of the stage in a few words.
func hbacVerifyLine(res *identityreconcile.HBACResult) string {
	switch {
	case res.Verify.OK():
		return "讀回與 roster 一致"
	case res.Stop != nil:
		return "沒有做(" + res.Stop.Reason + ")"
	case !res.Verify.Done && len(res.Ops) == 0:
		// A plan with nothing to write ends the stage before the read-back: there is nothing to verify.
		return "計畫沒有操作，沒有寫入，不需要讀回"
	case !res.Verify.Done:
		return "沒有讀回，見 --result-out"
	}
	return "讀回與 roster 不一致，見 --result-out"
}

// printMixedPlaybook says what the playbook did, in one line.
func printMixedPlaybook(out io.Writer, s *mixedStep) {
	switch {
	case !s.playbookRan:
		fmt.Fprintln(out, "identity playbook：沒有執行（Go 階段沒有套用並驗證它的 plan，或這一輪在那之前就停了）")
	case s.obs != nil:
		dirty := "沒有執行 settle"
		if s.obs.Dirty != nil {
			dirty = fmt.Sprintf("dirty=%v", *s.obs.Dirty)
		}
		fmt.Fprintf(out, "identity playbook：已執行；觀察結果 prepared=%v %s refreshed=%v acked=%v\n", s.obs.Prepared, dirty, s.obs.Refreshed, s.obs.Acked)
	default:
		fmt.Fprintf(out, "identity playbook：已執行，但沒有接受的觀察結果：%v\n", s.obsErr)
	}
	if s.playbookRan && !s.secondRun {
		fmt.Fprintln(out, "identity playbook 的第 2 次執行（--tags client-cache，授權快取的刷新與確認）沒有啟動：上面的觀察結果是最後一次執行的")
	}
}

// runReconcileGolangMixed is golangMixed with the exit-code rule of the Go engine, the same one
// runReconcileGolangApply has: the playbook's own exit status is never pilot's (an error that wraps
// a child's *exec.ExitError is an ExitCoder too, so returned as it is it would end pilot with
// ansible's 3 or 4, which read as blocked and as an obligation owed). Only the two named results
// are 3 and 4: a blocked plan (the Go phase's, or the preview's), and a run whose every Go
// operation was applied and verified and only the authorization cache obligation is owed.
func runReconcileGolangMixed(cmd *cobra.Command) error {
	err := golangMixed(cmd)
	if err == nil {
		return nil
	}
	code := golangApplyExitCode(err)
	var coded *golangPreviewError
	if errors.As(err, &coded) && coded.code != 1 {
		code = coded.code
	}
	return &golangPreviewError{err: err, code: code} // gate: exit-code-mixed
}

// golangMixed runs the Ansible engine's reconcile path with the mixed marker on its context,
// which is the Go engine's signal context: SIGINT, SIGTERM and SIGHUP end the Go phase (no new
// write, the one in flight unknown, the read after the writes still attempted) or the playbook
// (killed), and the run's records are written on a context detached from it (spec §8.3).
func golangMixed(cmd *cobra.Command) error {
	planOut, err := reserveOutput("--plan-out", reconcilePlanOutFlag)
	if err != nil {
		return err // gate: mixed-plan-out
	}
	defer planOut.discard()
	resultOut, err := reserveOutput("--result-out", reconcileResultOutFlag)
	if err != nil {
		return err // gate: mixed-result-out
	}
	defer resultOut.discard()
	timeout, err := parseDeployTimeout(reconcileTimeoutFlag)
	if err != nil {
		return err // gate: mixed-timeout-parse
	}
	run := &mixedIdentityRun{cmd: cmd, timeout: timeout, previewOnly: reconcilePreviewOnlyFlag, planOut: planOut}
	err = runReconcileInteractiveIn(cmd, func(runtime deployAnsibleRuntime) (context.Context, context.CancelFunc) {
		run.runtime = runtime
		sigCtx, stop := golangSignalContext(cmd, runtime)
		return withMixedIdentityRun(sigCtx, run), stop
	})
	run.finish(cmd, err, resultOut)
	return err // gate: mixed-passthrough
}

// golangHBACMode says whether the read-only plan also reads and plans the roster's HBAC, and when in the run:
// the users-groups scope never does (its plan document is what it was), the mixed run's preview does before
// the playbook has run, and its idempotency check after it.
type golangHBACMode int

const (
	// golangHBACOff: no HBAC part.
	golangHBACOff golangHBACMode = iota
	// golangHBACPreview: the plan is made before the playbook phase, so the hosts, hostgroups and services the
	// roster declares and FreeIPA does not have yet are assumed to exist (spec D8).
	golangHBACPreview
	// golangHBACApplied: the plan is made after the playbook phase, as the apply's stage makes it.
	golangHBACApplied
)

// mixedHBACPlanDoc reads FreeIPA's HBAC with the (read-only) client of the preview and plans the roster's. It
// sends nothing but reads: ObserveHBAC is finds and env.
func mixedHBACPlanDoc(ctx context.Context, client *freeiparpc.Client, prep *golangPrep, preview bool) (*identityreconcile.HBACPlanDoc, error) {
	desired, err := identityreconcile.HBACFromRoster(prep.root)
	if err != nil {
		return nil, fmt.Errorf("roster 的 HBAC：%w", err) // gate: mixed-hbac-plan-desired
	}
	obs, err := identityreconcile.ObserveHBAC(ctx, client)
	if err != nil {
		return nil, err // gate: mixed-hbac-plan-observe
	}
	plan := identityreconcile.BuildHBAC(identityreconcile.HBACInput{Desired: desired, Obs: obs, Preview: preview})
	return identityreconcile.NewHBACPlanDoc(plan, obs, preview), nil
}

// printHBACPreview prints the HBAC plan the way the users and groups plan is: what it would write, what it
// blocks and what it leaves alone.
func printHBACPreview(out io.Writer, doc *identityreconcile.HBACPlanDoc) {
	fmt.Fprintln(out, "─── HBAC（Go engine 的第二階段：playbook 之後，唯讀預覽不寫入）───")
	fmt.Fprintf(out, "讀到 %d 條 HBAC rule、%d 個 HBAC service、%d 台 host、%d 個 hostgroup（domain %s）\n",
		doc.Observation.Rules, doc.Observation.Services, doc.Observation.Hosts, doc.Observation.Hostgroups, doc.Observation.Domain)
	counts := map[string]int{}
	for _, op := range doc.Operations {
		counts[op.Kind]++
	}
	if len(doc.Operations) == 0 {
		fmt.Fprintln(out, "HBAC 計畫：沒有任何寫入")
	} else {
		fmt.Fprintf(out, "HBAC 計畫：%d 個寫入\n", len(doc.Operations))
		for _, kind := range identityreconcile.HBACKinds {
			if counts[kind] > 0 {
				fmt.Fprintf(out, "  %-34s %d\n", kind, counts[kind])
			}
		}
		for _, op := range doc.Operations {
			if op.Destructive {
				fmt.Fprintf(out, "  ⚠️  %s %s（破壞性）\n", op.Kind, op.Object)
			}
		}
	}
	for _, b := range doc.Blocked {
		fmt.Fprintf(out, "🚫 阻擋 HBAC %s：%s — %s\n", b.Object, b.Reason, b.Detail)
	}
	if len(doc.Reports.UnmanagedRules) > 0 {
		fmt.Fprintf(out, "ℹ️  FreeIPA 有、roster 沒有提到的 HBAC rule（不會動，內建的 rule 不列）：%s\n", strings.Join(doc.Reports.UnmanagedRules, "、"))
	}
	if doc.Preview {
		fmt.Fprintln(out, "ℹ️  預覽的 HBAC plan 在 playbook 之前做：roster 宣告而 FreeIPA 還沒有的 host、hostgroup、service 視為 playbook 會建立；套用時 HBAC 階段在 playbook 之後重讀，仍不存在就阻擋")
	}
}
