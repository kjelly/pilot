package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
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

	// The playbook: its apply run, and the observation that run wrote.
	playbookRan bool
	obs         *identityreconcile.AuthCacheResult
	obsErr      error

	// The transaction.
	tx    delivery.Result
	runID string
}

// extraVars are the variables the playbook is told the Go engine owns the users and groups with.
// The observation file's path is not among them: AuthCacheOutput.Run hands it to each run.
func (s *mixedStep) extraVars() []string {
	return []string{identityreconcile.UsersGroupsEngineVar + "=" + identityreconcile.UsersGroupsEngineGo}
}

// addMetadata says in the run's metadata which engine and scope this was (the filter of
// `pilot runs last-success` reads scope, and a mixed run is one it counts: it ran the playbook).
func (s *mixedStep) addMetadata(metadata map[string]any) {
	metadata["engine"] = reconcileEngineGolang
	metadata["scope"] = reconcileScopeFull
	metadata["pilot_revision"] = pilotRevision()
}

func (s *mixedStep) bind(w *store.RunWriter) { s.writer = w }

func (s *mixedStep) close() { _ = s.out.Close() }

func (s *mixedStep) finished(tx delivery.Result, runID string) { s.tx, s.runID = tx, runID }

// committed reports whether the Go writer changed FreeIPA, or may have: from then on a failure of
// any step is a partial application, and not an ordinary failure with nothing to say.
func (s *mixedStep) committed() bool { return s.res != nil && s.res.Committed() }

// partial shapes err for a step that fails after the Go writer committed.
func (s *mixedStep) partial(err error) error {
	if err != nil && s.committed() && !errors.Is(err, delivery.ErrPartiallyApplied) {
		return fmt.Errorf("%w: %w", delivery.ErrPartiallyApplied, err)
	}
	return err
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
	prep, err := golangPreflightFor(runCtx, s.run.runtime, golangPreflightInput{Inventory: s.inv, Limit: s.limit, Stage: s.stage, Attested: stagingAttestedHoursFlag})
	if err != nil {
		return mixedApplyError(nil, err)
	}
	if prep.host != held.Host {
		return mixedApplyError(nil, fmt.Errorf("mixed run：Go engine 要寫的 FreeIPA server 是 %s，但這一輪的鎖在 %s：不寫入", prep.host, held.Host))
	}
	s.prep, s.host = prep, prep.host
	dialer := newGolangDialer(prep.target)
	defer dialer.Close()
	gate := identityreconcile.NewGate()
	session, err := golangConnect(runCtx, prep, dialer, freeiparpc.Config{WriteGate: gate.Check})
	if err != nil {
		return mixedApplyError(nil, err)
	}
	defer session.close()
	s.session, s.fqdn = session, session.fqdn
	passwords, err := identityreconcile.NewRosterPasswords(prep.rosterData)
	if err != nil {
		return mixedApplyError(nil, fmt.Errorf("roster 的密碼：%w", err))
	}
	root, err := resolveContractRoot("")
	if err != nil {
		return mixedApplyError(nil, err)
	}
	stageVars := golangStageVars(prep.stage, stagingAttestedHoursFlag)
	entry, err := identityreconcile.NewAuthCacheEntry(s.out, held, session.fqdn, func(c context.Context, extraVars string) (int, error) {
		return runGoAuthCacheEntry(c, held, root, prep, stageVars, extraVars, s.run.cmd.ErrOrStderr())
	})
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
	fmt.Fprintf(out, "▶ Go 階段的唯讀預覽（--scope %s）：先看 Go engine 對 users 與 groups 的 plan\n", reconcileScopeFull)
	runCtx, cancel := context.WithTimeout(ctx, s.run.timeout)
	defer cancel()
	prep, err := golangPreflightFor(runCtx, s.run.runtime, golangPreflightInput{Inventory: s.inv, Limit: s.limit, Stage: s.stage, Attested: stagingAttestedHoursFlag})
	if err != nil {
		return err
	}
	var planOut *outputFile
	if s.run.previewOnly {
		planOut = s.run.planOut
	}
	doc, err := golangPreviewPlan(runCtx, out, prep, planOut)
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
	prep, err := golangPreflightFor(runCtx, s.run.runtime, golangPreflightInput{Inventory: s.inv, Limit: s.limit, Stage: s.stage, Attested: stagingAttestedHoursFlag})
	if err != nil {
		return fmt.Errorf("冪等性檢查的 Go 唯讀 plan：%w", err)
	}
	doc, err := golangPreviewPlan(runCtx, out, prep, nil)
	if err != nil {
		return fmt.Errorf("冪等性檢查的 Go 唯讀 plan：%w", err)
	}
	if n := len(doc.Operations); n != 0 {
		return fmt.Errorf("冪等性檢查失敗：第二次套用之後，Go 的唯讀 plan 仍有 %d 個操作", n)
	}
	fmt.Fprintln(out, "✓ 冪等性檢查通過 (Go 的唯讀 plan 沒有操作)")
	return nil
}

// RunPlaybook implements mixedTransaction: every run of the playbook goes through the
// observation file's Run, which makes it a new empty file before the run and reads it after, so
// the run reads only what it wrote itself. The command's own result and error are returned as
// they were: whether the run failed is the apply step's to say, and what it observed is the
// verification's. The preview and the idempotency run are handed the file too (the playbook
// refuses the engine variable without it); a preview writes nothing, and the idempotency run's
// observation is for the record, the apply's is the one the obligation is settled by (§5.4).
func (s *mixedStep) RunPlaybook(ctx context.Context, step string, run playbookRun) (*ansible.Result, error) {
	// A context that has ended (the first Ctrl-C, --timeout) starts nothing: the Go phase can end a run on a
	// converged unknown write that returns no error, and the playbook does not start after the signal that
	// cut it. The result file then says the playbook did not run, which is true.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("identity playbook (%s) 沒有啟動：%w", step, context.Cause(ctx))
	}
	if step == "apply" {
		s.playbookRan = true
	}
	// The command line printed before this run does not have the file the observation is written to: it is made
	// new for each run and handed to it here (AuthCacheOutput.Run).
	fmt.Fprintf(s.run.cmd.OutOrStdout(), "ℹ️  identity playbook（%s）另外帶入 -e {\"%s\": <暫存檔>}：它的觀察結果檔，每次執行前重建為空檔\n", step, identityreconcile.AuthCacheOutputVar)
	want := identityreconcile.AuthCacheWant{Action: identityreconcile.AuthCacheObserve, Host: s.host, FQDN: s.fqdn}
	var res *ansible.Result
	var runErr error
	obs, obsErr := s.out.Run(ctx, want, func(c context.Context, vars string) (int, error) {
		res, runErr = run(c, []string{"-e", vars})
		if runErr != nil {
			return 0, runErr
		}
		return res.ExitCode, nil
	})
	if step == "apply" {
		// What this run observed replaces what an earlier apply run did: a run that wrote nothing
		// has no observation, not the last one's.
		s.obs, s.obsErr = nil, obsErr
		if obsErr == nil {
			s.obs = &obs
		}
	}
	if res == nil && runErr == nil {
		// The file could not be made: the playbook was not started.
		return nil, obsErr
	}
	return res, runErr
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
		Scope: identityreconcile.ScopeFull, Playbook: pb,
	})
	printGolangApply(out, reconcileScopeFull, s.prep, &golangApplyRun{res: s.res, tx: s.tx, runID: s.runID, session: s.session, stats: s.stats, started: s.started}, doc, true)
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
