package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/store"
)

// pilot reconcile --engine golang --force --scope users-groups (spec 2026-11-06 phase 2
// §8.2, D27): the Go writer for the users and groups of the roster, with no playbook but
// the authorization cache entry. The run holds the FreeIPA server's /etc/ipa lock from
// before it connects until its transaction is over (I1), writes only through the client's
// WriteGate (I2), and is its own delivery run, so history, the outbound webhook and the
// result file all say what happened, including after Ctrl-C, --timeout or a lost lock (the
// terminal-sink rule of §4.4).

// outputFile is a file a run owns from its start to its end: created exclusively before
// anything is read or written (a path that exists is refused then, not after the whole run),
// written once at the end, and removed when the run does not write it or the write fails,
// so a failed run leaves no truncated file for a later reader to take for a result (#274).
type outputFile struct {
	flag string
	path string
	f    *os.File
	done bool
}

// reserveOutput creates the file named by value (a flag's), 0600, exclusively. An empty
// value reserves nothing and returns nil, which every method accepts.
func reserveOutput(flag, value string) (*outputFile, error) {
	if value == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(expandHomeDir(value))
	if err != nil {
		return nil, err // gate: output-abs
	}
	if info, err := os.Stat(filepath.Dir(abs)); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s %s 的上層目錄 %s 不存在或不是目錄", flag, abs, filepath.Dir(abs)) // gate: output-dir
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%s %s 已存在；不覆寫", flag, abs) // gate: output-exists
		}
		return nil, fmt.Errorf("%s: %w", flag, err) // gate: output-create
	}
	return &outputFile{flag: flag, path: abs, f: f}, nil
}

// commitOutput writes data and closes the file; any failure removes it. A function, not a
// method, so that the gate ledger (which lists the refusals of functions) sees its gates.
func commitOutput(o *outputFile, data []byte) error {
	if o == nil || o.done {
		return nil
	}
	if _, err := o.f.Write(data); err != nil {
		o.discard()
		return fmt.Errorf("%s: %w", o.flag, err) // gate: output-write
	}
	if err := o.f.Close(); err != nil {
		o.f = nil
		o.discard()
		return fmt.Errorf("%s: %w", o.flag, err) // gate: output-close
	}
	o.done = true
	return nil
}

// discard removes the file unless commit made it the result. Safe to call on nil and twice.
func (o *outputFile) discard() {
	if o == nil || o.done {
		return
	}
	if o.f != nil {
		_ = o.f.Close()
		o.f = nil
	}
	_ = os.Remove(o.path)
}

// runReconcileGolangApply is golangApply with the exit-code rule of the Go engine: only
// the two named results are 3 and 4, and any other failure is 1, whatever process failed
// underneath (an error wrapping an *exec.ExitError is an ExitCoder too, so returned as it is
// it would end pilot with that child's status: a 3 from ansible would read as blocked).
func runReconcileGolangApply(cmd *cobra.Command) error {
	err := golangApply(cmd)
	var coded *golangPreviewError
	if err == nil || errors.As(err, &coded) {
		return err // gate: exit-code-passthrough-apply
	}
	return &golangPreviewError{err: err, code: 1} // gate: exit-code-1-apply
}

// golangApplyExitCode is the exit code of a finished run, decided from the error alone: the
// error says what ended it, and the Stop of a Result does not (a converged unknown outcome
// leaves one on a run that succeeded). Blocked is looked at first and wins over a journal
// failure that is reported beside it, since errors.Join keeps both: a plan with blocked objects
// wrote nothing, and a journal that also failed does not make it a failure of another kind.
func golangApplyExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, identityreconcile.ErrBlocked):
		return golangPreviewBlockedExitCode
	case errors.Is(err, identityreconcile.ErrUnsettled):
		return golangUnsettledExitCode
	}
	return 1
}

// golangApplyRun is what the transaction under the lock produced.
type golangApplyRun struct {
	res     *identityreconcile.Result // nil when Execute was never reached
	tx      delivery.Result
	txErr   error
	runID   string
	session *golangSession
	stats   freeiparpc.Stats
	started time.Time
}

func golangApply(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	resultOut, err := reserveOutput("--result-out", reconcileResultOutFlag)
	if err != nil {
		return err // gate: apply-result-out
	}
	defer resultOut.discard()
	timeout, err := parseDeployTimeout(reconcileTimeoutFlag)
	if err != nil {
		return err // gate: apply-timeout-parse
	}
	wait, err := parseReconcileLockWait(reconcileLockWaitFlag)
	if err != nil {
		return err // gate: apply-lock-wait
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return err // gate: apply-runtime-prepare
	}
	sigCtx, stop := golangSignalContext(cmd, runtime)
	defer stop()

	// The preflight has its own --timeout; the wait for the lock is --lock-wait's; what
	// follows the lock is timed again, so a 30 minute wait does not eat the run's budget.
	prepCtx, cancelPrep := context.WithTimeout(sigCtx, timeout)
	prep, err := golangPreflight(prepCtx, runtime)
	cancelPrep()
	if err != nil {
		return err // gate: apply-preflight
	}
	acquire, err := identityLockFor(sigCtx, identityLockRequest{
		Inventory: prep.inv, Hosts: []string{prep.host}, Wait: wait, Progress: cmd.ErrOrStderr(), Runtime: &runtime,
	})
	if err != nil {
		return err // gate: apply-lock-precheck
	}
	held, err := acquire(sigCtx)
	if err != nil {
		return fmt.Errorf("--engine %s --scope %s 沒有開始：沒有取得鎖，沒有任何寫入：%w", reconcileEngineGolang, reconcileScopeUsersGroups, err) // gate: apply-lock-acquire
	}
	defer func() { _ = held.Release() }()
	// Made only now: a run the lock refused has no tunnel to make or to end.
	dialer := newGolangDialer(prep.target)
	defer dialer.Close()

	run, runErr := runGolangApplyUnderLock(sigCtx, held, prep, dialer, cmd, runtime, timeout)
	// The lock is given back as soon as the transaction is over: the publication below
	// takes as long as a webhook receiver wants, and nothing in it needs the lock.
	if relErr := held.Release(); relErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "警告：放掉 FreeIPA server 的 /etc/ipa 鎖時出錯：%v\n", relErr)
	}
	if run == nil {
		// It never reached the first read: nothing was written, there is no run and no file.
		return runErr // gate: apply-before-first-read
	}
	return finishGolangApply(sigCtx, cmd, out, prep, run, resultOut) // gate: apply-finish
}

// golangStageVars is the extra variables of the entry playbook's stage gates: the Ansible
// engine's own function, so there is one place that says what staging and prod need
// (golangPreviewStage decides whether the host may have the stage, this says how the
// playbook is told; TestGolangStageRulesAgree keeps them consistent).
func golangStageVars(stage, attestedHours string) []string {
	d := stageDecisionFromFlag(io.Discard, "freeipa-identity", stage, attestedHours)
	return append([]string{"stage=" + d.Stage}, d.ConfirmVars...)
}

// runGolangApplyUnderLock is everything between the lock and its release: the connection,
// the delivery run, the entry, the Go writer and the transaction's verdict. It takes the
// lock the run holds, as every function that runs the entry or the writer must (the lint
// of identity_lock_funnel_test.go). It returns a nil run, with the error, when it failed
// before the first read of FreeIPA: nothing was written then and there is nothing to record.
func runGolangApplyUnderLock(ctx context.Context, held *identitylock.Held, prep *golangPrep, dialer golangDialer, cmd *cobra.Command, runtime deployAnsibleRuntime, timeout time.Duration) (*golangApplyRun, error) {
	// Attach, not Bind: this context carries the Go writer, the journal and the step
	// evidence, none of which may be cancelled because the lock was lost (their records
	// would fail and hide what happened); the writer asks the lock before every write, and
	// only the entry's playbook gets a context that ends with it (runGoAuthCacheEntry).
	runCtx, cancelRun := context.WithTimeout(held.Attach(ctx), timeout)
	defer cancelRun()

	gate := identityreconcile.NewGate()
	session, err := golangConnect(runCtx, prep, dialer, freeiparpc.Config{WriteGate: gate.Check})
	if err != nil {
		return nil, err // gate: apply-connect
	}
	defer session.close()
	passwords, err := identityreconcile.NewRosterPasswords(prep.rosterData)
	if err != nil {
		return nil, fmt.Errorf("roster 的密碼：%w", err) // gate: apply-passwords
	}
	root, err := resolveContractRoot("")
	if err != nil {
		return nil, err // gate: apply-root
	}
	authOut, err := identityreconcile.NewAuthCacheOutput()
	if err != nil {
		return nil, err // gate: apply-auth-output
	}
	defer func() { _ = authOut.Close() }()
	stageVars := golangStageVars(prep.stage, stagingAttestedHoursFlag)
	entry, err := identityreconcile.NewAuthCacheEntry(authOut, held, session.fqdn, func(c context.Context, extraVars string) (int, error) {
		return runGoAuthCacheEntry(c, held, root, prep, stageVars, extraVars, cmd.ErrOrStderr())
	})
	if err != nil {
		return nil, err // gate: apply-entry
	}

	st, err := openSpecStore()
	if err != nil {
		return nil, fmt.Errorf("open deployment evidence store: %w", err) // gate: apply-store
	}
	defer st.Close()
	started := time.Now()
	writer, err := store.StartRun(runCtx, st, store.RunStarted{
		Stage: prep.stage, Component: "freeipa-identity", Components: []string{"freeipa-identity"}, Playbook: "none",
		Inventory: prep.inv, Hosts: []string{prep.host},
		Metadata: map[string]any{
			"engine": reconcileEngineGolang, "scope": reconcileScopeUsersGroups, "lock_host": held.Host,
			"pilot_revision": pilotRevision(),
		},
		StartedAt: started,
	})
	if err != nil {
		return nil, fmt.Errorf("start deployment evidence run: %w", err) // gate: apply-start-run
	}
	writer.StartHeartbeat(runCtx, 10*time.Second)
	fmt.Fprintf(cmd.OutOrStdout(), "ℹ️  deployment run: %s\n", writer.RunID())

	run := &golangApplyRun{runID: writer.RunID(), session: session, started: started}
	var execRes *identityreconcile.Result
	var execErr error
	tx := delivery.Transaction{
		Writer: writer, Stage: prep.stage, IdempotencyPolicy: delivery.IdempotencyNever, RollbackPolicy: delivery.RollbackNone,
		Apply: func(c context.Context) error {
			execRes, execErr = identityreconcile.Execute(c, session.client, identityreconcile.Options{
				Desired: prep.desired, Passwords: passwords, Entry: entry, Gate: gate,
				Journal: storeJournal{w: writer}, ProbeWhenIdle: true,
			})
			return applyStepError(execRes, execErr)
		},
		Verify: func(context.Context) error { return verifyStepError(execRes, execErr) },
	}
	run.tx, run.txErr = tx.RunResult(runCtx)
	run.res = execRes
	run.stats = session.client.Stats()
	return run, nil
}

// applyStepError is what the Apply step reports of the Go writer: the writes' result. The
// verdict of the read after the writes is left for the Verify step (spec §7.6), except
// when the writes themselves failed too: a failure there ends the transaction at apply.
// A run that committed something (or may have) and failed is a partial application, so the
// transaction does not roll anything back (there is no rollback of a reconciler's effects)
// and ends partial_failed; one that changed nothing is an ordinary failure, with a note when
// the entry had run, since the obligation is then recorded on the server for nothing.
func applyStepError(res *identityreconcile.Result, err error) error {
	if err == nil || verifyOnly(err) {
		return nil
	}
	if res != nil && res.Committed() {
		return fmt.Errorf("%w: %w", delivery.ErrPartiallyApplied, err)
	}
	if res != nil && res.Entry.Ran {
		return fmt.Errorf("%w (入口已執行，授權快取義務已記錄；多一次刷新，無害)", err)
	}
	return err
}

// verifyOnly reports whether err is the failure of the read after the writes and nothing
// else: every planned operation was applied (no ErrWrites, no journal failure, nothing
// before the stages) and only the verification shows something left or could not read.
func verifyOnly(err error) bool {
	return errors.Is(err, identityreconcile.ErrVerify) &&
		!errors.Is(err, identityreconcile.ErrWrites) && !errors.Is(err, identityreconcile.ErrJournal) &&
		!errors.Is(err, identityreconcile.ErrBlocked) && !errors.Is(err, identityreconcile.ErrDestructiveDiff) &&
		!errors.Is(err, identityreconcile.ErrEntry)
}

// unsettledMessage is the message of a run that owes the authorization cache obligation
// (spec §6.2): the operator is told what is still true and what settles it.
const unsettledMessage = "授權快取義務未結清，client 在 SSSD 快取過期前可能仍沿用舊授權；下一次選到 identity 或 client-cache 的 apply 或完整 apply 會刷新所有 enrolled client(ipa_identity_refresh_sssd_cache 為 false 時則要先改回 true)"

// verifyStepError is the Verify step of the users-groups scope: it reads Plan₃'s verdict and
// the obligation. The Go writer's verification failure (a read that failed, or an operation or
// a blocked object left on what the run changed) fails it, partial when the run committed;
// a run that applied and verified everything but owes the obligation is ErrUnsettled, which
// is also a partial application for the transaction and exit code 4 for the command.
func verifyStepError(res *identityreconcile.Result, err error) error {
	if err != nil && verifyOnly(err) {
		if res != nil && res.Committed() {
			return fmt.Errorf("%w: %w", delivery.ErrPartiallyApplied, err)
		}
		return err
	}
	if res == nil {
		return nil
	}
	if ob := res.Obligation(); ob.Owed {
		if ob.Source == identityreconcile.ObligationThisRun {
			return fmt.Errorf("%w: 這一輪執行了入口(義務已記錄於 server 的 journal)：%s", identityreconcile.ErrUnsettled, unsettledMessage)
		}
		return fmt.Errorf("%w: 探測讀到先前的執行留下的義務：%s", identityreconcile.ErrUnsettled, unsettledMessage)
	}
	return nil
}

// boundedTail keeps the last bytes written to it: the end of ansible-playbook's output is
// what says why it failed.
type boundedTail struct {
	buf []byte
}

const boundedTailMax = 4096

func (b *boundedTail) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	if len(b.buf) > boundedTailMax {
		b.buf = b.buf[len(b.buf)-boundedTailMax:]
	}
	return len(p), nil
}

// runGoAuthCacheEntry runs the entry playbook (freeipa-identity-auth-cache.yml) once on the
// host whose lock the run holds, under a context that ends with that lock (Bind), and
// returns ansible-playbook's exit code. It starts nothing when the lock is already lost, and a
// playbook that exits 0 after the lock was lost did not run under it: that is an error, not a
// result. What the playbook prints is kept for the error and never goes to the journal.
func runGoAuthCacheEntry(ctx context.Context, held *identitylock.Held, root string, prep *golangPrep, stageVars []string, extraVars string, stderr io.Writer) (int, error) {
	inv, err := filepath.Abs(prep.inv)
	if err != nil {
		return 0, err
	}
	bound, cancel := held.Bind(ctx)
	defer cancel()
	args := []string{filepath.Join(root, identitylock.AuthCachePlaybook), "-i", inv, "--limit", prep.host}
	for _, v := range stageVars {
		args = append(args, "-e", v)
	}
	args = append(args, "-e", extraVars)
	command := deployAnsibleCommand(bound, "ansible-playbook", args...)
	command.Dir = root
	var tail boundedTail
	command.Stdout, command.Stderr = &tail, &tail
	// Every Ansible command holds the controller's Ansible log until it is done, so that the log's
	// maintenance (pilot mcp serve runs tools concurrently) does not rewrite or rotate it under the
	// playbook (TestAnsibleCommandsHoldTheLog). A hold that cannot be taken in time is a run that did
	// not start, and reads as one.
	var runErr error
	if release, holdErr := ansible.HoldCommandLog(bound, command); holdErr != nil {
		runErr = holdErr
	} else {
		runErr = command.Run()
		release()
	}
	if cause := context.Cause(bound); errors.Is(cause, identitylock.ErrLockLost) {
		return 0, fmt.Errorf("ansible-playbook was stopped: %w", cause)
	}
	if err := held.Check(); err != nil {
		return 0, fmt.Errorf("the entry playbook ended after the lock was lost: %w", err)
	}
	var exit *exec.ExitError
	switch {
	case runErr == nil:
		return 0, nil
	case errors.As(runErr, &exit) && exit.ExitCode() >= 0:
		fmt.Fprintf(stderr, "入口 playbook 的輸出(尾端)：\n%s\n", strings.TrimSpace(string(tail.buf)))
		return exit.ExitCode(), nil
	}
	return 0, fmt.Errorf("run ansible-playbook: %w", runErr)
}

// maxJournalEventBytes is the largest event the delivery store sink takes. The store itself
// limits none; the executor bounds the events it makes (chunked not_sent, bounded lists),
// and an event over this is a bug there that must fail the record, not fill the stream.
const maxJournalEventBytes = 1 << 20

// storeJournal is the run journal of the Go writer on the run's delivery event stream
// (spec §7.7, D21): the executor's events become delivery events of the run, with the type
// the executor gave them (identity.op, identity.verify, identity.auth_cache) and an
// operation id of the executor's id under a prefix, so none collides with the transaction's
// own (step-apply, run_started, …). Recording is idempotent for an identical event and
// refused for the same id with another payload (the store's rule), which the executor never
// produces.
type storeJournal struct {
	w *store.RunWriter
}

func (j storeJournal) Record(ctx context.Context, ev identityreconcile.Event) error {
	raw, err := json.Marshal(ev.Payload)
	if err != nil {
		return fmt.Errorf("journal event %s: %w", ev.ID, err)
	}
	if len(raw) > maxJournalEventBytes {
		return fmt.Errorf("journal event %s is %d bytes, over the %d the journal takes", ev.ID, len(raw), maxJournalEventBytes)
	}
	return j.w.AppendEvent(ctx, store.Event{OperationID: "identity:" + ev.ID, Type: ev.Kind, Step: "apply", Payload: json.RawMessage(raw)})
}

// finishGolangApply is what follows the transaction: the result file, the terminal
// publication, the summary and the exit code. It runs after the lock was given back, and
// on a context that may already be cancelled (the file and the publication do not depend on
// it: T4 to T7 of spec §4.4).
func finishGolangApply(ctx context.Context, cmd *cobra.Command, out io.Writer, prep *golangPrep, run *golangApplyRun, resultOut *outputFile) error {
	err := run.txErr
	code := golangApplyExitCode(err)
	var doc identityreconcile.ApplyDocument
	haveDoc := run.res != nil && run.res.Observed
	if haveDoc {
		doc = identityreconcile.NewApplyDocument(identityreconcile.ApplyDocumentInput{
			Desired: prep.desired, Result: *run.res, Target: run.session.target(prep), Server: run.session.serverInfo(),
			Revision: pilotRevision(), Stage: prep.stage, RunID: run.runID, Outcome: string(run.tx.Outcome),
			FailedStep: run.tx.FailedStep, ExitCode: code, Err: err,
			Stats: identityreconcile.Stats{HTTPRequests: run.stats.HTTPRequests, Reads: run.stats.Reads, Writes: run.stats.Writes, Relogins: run.stats.Relogins, ReadRetries: run.stats.ReadRetries},
		})
	}
	printGolangApply(out, reconcileScopeUsersGroups, prep, run, doc, haveDoc)
	if resultOut != nil {
		if haveDoc {
			data, rerr := doc.Render()
			if rerr == nil {
				rerr = commitOutput(resultOut, data)
			}
			if rerr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "警告：沒有寫出 --result-out：%v\n", rerr)
			} else {
				fmt.Fprintf(out, "result JSON：%s\n", resultOut.path)
			}
		}
		// A run that never reached the first read has no document: the reserved file is removed
		// by the deferred discard of golangApply.
	}
	publishGolangApply(ctx, out, prep, run)
	if err == nil {
		return nil
	}
	if code != 1 {
		return &golangPreviewError{err: err, code: code}
	}
	return err
}

// golangApplyEffects are the effects a users-groups run is routed on and confirms: the
// fixed subset it can speak for, not the whole freeipa-identity effect set (spec §8.2).
var golangApplyEffects = []string{"identity.groups", "identity.users"}

// publishGolangApply announces the run to the outbound webhooks, the one place that
// publishes the terminal state of a users-groups run.
func publishGolangApply(ctx context.Context, out io.Writer, prep *golangPrep, run *golangApplyRun) {
	results := []ComponentDeliveryResult{{ComponentIDs: []string{"freeipa-identity"}, RunID: run.runID, Outcome: run.tx.Outcome, FailedStep: run.tx.FailedStep}}
	agg := aggregateDeploymentResult(results)
	confirmed := agg.ConfirmedEffects
	if len(agg.CompletedComponents) > 0 {
		confirmed = golangApplyEffects
	}
	publishTerminalWorkflow(ctx, out, PublishTerminalWorkflowInput{
		WorkspaceDir: filepath.Dir(prep.inv), Inventory: prep.inv,
		Operation: outbound.OperationReconcile, WorkflowID: newWorkflowID(),
		RequestedComponents: []string{"freeipa-identity"}, ExecutedComponents: []string{"freeipa-identity"},
		CompletedComponents: agg.CompletedComponents, FailedComponent: agg.FailedComponent,
		Effects: golangApplyEffects, ConfirmedEffects: confirmed,
		Result: agg.Result, ApplicationConsistency: agg.ApplicationConsistency,
		DeliveryRuns: agg.DeliveryRuns, Failure: agg.Failure,
		StartedAt: run.started, FinishedAt: time.Now(),
	})
}

// printGolangApply is the run's summary on stdout: what was planned, what became of it, the
// verification and the obligation. It holds no secret (I6): operations are names and kinds.
func printGolangApply(out io.Writer, scope string, prep *golangPrep, run *golangApplyRun, doc identityreconcile.ApplyDocument, haveDoc bool) {
	fmt.Fprintf(out, "═══ pilot reconcile --engine %s --scope %s --force ═══\n", reconcileEngineGolang, scope)
	fmt.Fprintf(out, "stage：%s　目標：%s（%s）　FreeIPA %s／API %s\n", prep.stage, prep.host, run.session.fqdn, run.session.server.ServerVersion, run.session.server.APIVersion)
	if !haveDoc {
		fmt.Fprintf(out, "結果：%s（沒有進到第一次讀取，沒有寫入）\n", run.tx.Outcome)
		return
	}
	plan := doc.Plan1
	if doc.Plan2 != nil {
		plan = *doc.Plan2
	}
	kinds := map[string]int{}
	for _, op := range plan.Operations {
		kinds[op.Kind]++
	}
	fmt.Fprintf(out, "計畫：%d 個寫入", len(plan.Operations))
	if len(plan.Blocked) > 0 {
		fmt.Fprintf(out, "，%d 個物件被阻擋", len(plan.Blocked))
	}
	fmt.Fprintln(out)
	for _, kind := range identityreconcile.Kinds {
		if kinds[kind] > 0 {
			fmt.Fprintf(out, "  %-28s %d\n", kind, kinds[kind])
		}
	}
	for _, b := range plan.Blocked {
		fmt.Fprintf(out, "🚫 阻擋 %s：%s — %s\n", b.Object, b.Reason, b.Detail)
	}
	if len(doc.Ops) > 0 {
		counts := doc.Counts()
		var parts []string
		for _, o := range []identityreconcile.Outcome{identityreconcile.OutcomeSuccess, identityreconcile.OutcomeNoop, identityreconcile.OutcomeConflictFailed, identityreconcile.OutcomeFailed, identityreconcile.OutcomeUnknown, identityreconcile.OutcomeNotExecuted} {
			if counts[o] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", o, counts[o]))
			}
		}
		fmt.Fprintf(out, "結果：%s\n", strings.Join(parts, "、"))
		var failed []string
		for _, o := range doc.Ops {
			if f := o.Final(); f != identityreconcile.OutcomeSuccess && f != identityreconcile.OutcomeNoop {
				failed = append(failed, fmt.Sprintf("%s %s %s", o.Stage, o.Operation.ID, f))
			}
		}
		sort.Strings(failed)
		for _, line := range failed {
			fmt.Fprintf(out, "  ✗ %s\n", line)
		}
	}
	if doc.Stop != nil {
		fmt.Fprintf(out, "停在 %s：%s\n", doc.Stop.Stage, doc.Stop.Reason)
	}
	switch {
	case doc.Verify.Done && doc.Verify.OK():
		fmt.Fprintln(out, "驗證：重讀之後這一輪動過的物件沒有殘留操作")
	case doc.Verify.Done:
		fmt.Fprintf(out, "驗證失敗：%d 個殘留操作，%d 個被阻擋的物件%s\n", len(doc.Verify.Remaining), len(doc.Verify.Blocked), readErrorNote(doc.Verify.ReadError))
	}
	switch {
	case doc.Authorization.Owed:
		fmt.Fprintf(out, "授權快取義務：未結清(%s)。%s\n", doc.Authorization.Source, unsettledMessage)
	case doc.Authorization.ProbePending != nil:
		fmt.Fprintln(out, "授權快取義務：探測讀到沒有義務")
	}
	fmt.Fprintf(out, "run：%s　outcome：%s%s　verdict：%s\n", run.runID, run.tx.Outcome, stepNote(run.tx.FailedStep), doc.Verdict)
	fmt.Fprintf(out, "讀取：%d 個 HTTP 請求、%d 個讀取、%d 個寫入（鎖只約束 pilot 自己的程式碼路徑）\n", doc.Stats.HTTPRequests, doc.Stats.Reads, doc.Stats.Writes)
}

func readErrorNote(s string) string {
	if s == "" {
		return ""
	}
	return "；重讀失敗：" + s
}

func stepNote(step string) string {
	if step == "" {
		return ""
	}
	return "（" + step + "）"
}
