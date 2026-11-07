package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
	"github.com/kjelly/pilot/internal/sshdial"
	"github.com/kjelly/pilot/internal/store"
)

// The deploy funnel of the identity lock gate: executeDeploymentTransaction
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4.4, §4.5, §4.7). The identity playbook's apply step takes the lock after
// every confirmation and before anything that changes FreeIPA; the steps after
// it (verify, the idempotency re-apply, rollback) run under it and it is given
// back when the transaction has ended; a lost lock cancels the playbook and
// ends the run as `failed` with ErrLockLost, not `evidence_failed`.

const identityPlaybookForTest = "playbooks/apply/freeipa-identity-apply.yml"

// lockedDeployScript is a fake ansible-playbook: it logs what it was asked
// ("run check" for the --check preview, "run apply" otherwise) into $LOG and
// exits as told by env: CHECK_EXIT for the preview, APPLY_EXIT for the rest;
// BLOCK_AT=n makes the nth non-check run record its pid in $PIDFILE and wait.
const lockedDeployScript = `#!/bin/sh
kind=apply
for a in "$@"; do [ "$a" = --check ] && kind=check; done
echo "run $kind" >> "$LOG"
if [ "$kind" = check ]; then
  printf 'PLAY RECAP *********\nipa-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n'
  exit "${CHECK_EXIT:-0}"
fi
n=$(cat "$COUNT" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$COUNT"
if [ "$n" = "${BLOCK_AT:-0}" ]; then
  echo $$ > "$PIDFILE"
  exec sleep 120
fi
printf 'PLAY RECAP *********\nipa-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n'
exit "${APPLY_EXIT:-0}"
`

type recordingWriter struct {
	mu       sync.Mutex
	events   []store.Event
	finished []store.RunFinished
}

// AppendEvent fails on a cancelled context the way the SQLite writer does
// (db.Conn(ctx)): so a transaction whose context the lock's loss cancelled
// shows up as evidence_failed here, exactly as it would for real.
func (w *recordingWriter) AppendEvent(ctx context.Context, e store.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
	return nil
}

func (w *recordingWriter) Finish(ctx context.Context, f store.RunFinished) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finished = append(w.finished, f)
	return nil
}

func (w *recordingWriter) steps() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, e := range w.events {
		payload, _ := e.Payload.(map[string]any)
		status, _ := payload["status"].(string)
		out = append(out, e.Step+":"+status)
	}
	return out
}

type deployLockHarness struct {
	t      *testing.T
	log    string
	pid    string
	runner *ansible.Runner
	lock   *identitylocktest.Fake
	writer *recordingWriter
}

func newDeployLockHarness(t *testing.T) *deployLockHarness {
	t.Helper()
	dir := t.TempDir()
	h := &deployLockHarness{t: t, log: filepath.Join(dir, "events.log"), pid: filepath.Join(dir, "pid")}
	h.lock = &identitylocktest.Fake{Host: "ipa-1", Events: func(e string) { appendEvent(t, h.log, e) }}
	h.writer = &recordingWriter{}
	h.runner = ansible.NewRunner()
	h.runner.Binary = writeScript(t, "ansible-playbook", lockedDeployScript)
	h.runner.Timeout = 30 * time.Second
	t.Setenv("LOG", h.log)
	t.Setenv("PIDFILE", h.pid)
	t.Setenv("COUNT", filepath.Join(dir, "count"))
	prev := confirmDeployment
	t.Cleanup(func() { confirmDeployment = prev })
	confirmDeployment = func(id, _ string, _ bool) bool {
		appendEvent(t, h.log, "prompt "+id)
		return true
	}
	return h
}

func (h *deployLockHarness) run(playbook string, opts deploymentTransactionOptions) (delivery.Result, error) {
	h.t.Helper()
	var result delivery.Result
	opts.ResultOut = &result
	opts.Writer = h.writer
	if opts.IdentityLock == nil {
		opts.IdentityLock = h.lock.Acquirer()
	}
	err := executeDeploymentTransaction(context.Background(), h.runner, &bytes.Buffer{}, playbook, "inventory.yml", "", "", nil, vaultInput{}, opts)
	return result, err
}

func (h *deployLockHarness) events() []string { return readEvents(h.t, h.log) }

func (h *deployLockHarness) waitForPID() int {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(h.pid); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("the fake ansible-playbook never reached the step the test blocks it in")
	return 0
}

func processGone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// The order of a whole identity deploy: the lock comes after the last prompt
// (nobody holds it while a question waits for an answer) and before the
// playbook, it is still held for the idempotency re-apply, and it is given
// back last.
func TestIdentityDeployLockOrder(t *testing.T) {
	h := newDeployLockHarness(t)
	result, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != delivery.OutcomeSuccess {
		t.Fatalf("outcome = %s", result.Outcome)
	}
	want := []string{
		"prompt " + promptExecutionPreview,
		"prompt " + promptExecutionConfirmPreview,
		"run check",
		"prompt " + promptExecutionApplyAfterPreview,
		"prompt " + promptExecutionConfirmApply,
		"lock ipa-1",
		"run apply",
		"run apply", // the idempotency re-apply, under the same lock
		"release ipa-1",
	}
	if got := h.events(); !slices.Equal(got, want) {
		t.Fatalf("events:\n got %v\nwant %v", got, want)
	}
	if h.lock.Acquired() != 1 || h.lock.Released() != 1 {
		t.Fatalf("lock taken %d times, released %d: it must be once per run", h.lock.Acquired(), h.lock.Released())
	}
}

// What never takes the lock: a preview that fails, a preview-only run, a run
// the operator declines at the last prompt, and every playbook that is not the
// identity one (even when the caller handed the transaction a lock).
func TestIdentityDeployNeverLocksWhatItDoesNotApply(t *testing.T) {
	t.Run("a failing preview", func(t *testing.T) {
		h := newDeployLockHarness(t)
		t.Setenv("CHECK_EXIT", "2")
		if _, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{}); err == nil {
			t.Fatal("a failing preview did not fail the run")
		}
		if h.lock.Acquired() != 0 {
			t.Fatalf("the lock was taken for a run that never applied: %v", h.events())
		}
	})
	t.Run("--preview-only", func(t *testing.T) {
		h := newDeployLockHarness(t)
		_, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{Authorization: &deploymentAuthorization{Preview: true, PreviewOnly: true}})
		if !errors.Is(err, errPreviewOnlyStop) {
			t.Fatalf("err = %v, want errPreviewOnlyStop", err)
		}
		if got, want := h.events(), []string{"run check"}; !slices.Equal(got, want) {
			t.Fatalf("events = %v, want only the preview %v", got, want)
		}
		if h.lock.Acquired() != 0 {
			t.Fatal("--preview-only took the lock")
		}
	})
	t.Run("declined at the last prompt", func(t *testing.T) {
		h := newDeployLockHarness(t)
		confirmDeployment = func(id, _ string, _ bool) bool {
			appendEvent(t, h.log, "prompt "+id)
			return id != promptExecutionConfirmApply
		}
		_, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{})
		if !errors.Is(err, errDeployAborted) {
			t.Fatalf("err = %v, want errDeployAborted", err)
		}
		if h.lock.Acquired() != 0 {
			t.Fatalf("the lock was taken for a run the operator declined: %v", h.events())
		}
	})
	t.Run("another playbook, even with a lock in the options", func(t *testing.T) {
		h := newDeployLockHarness(t)
		result, err := h.run("playbooks/apply/docker-apply.yml", deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways})
		if err != nil || result.Outcome != delivery.OutcomeSuccess {
			t.Fatalf("outcome = %s, err = %v", result.Outcome, err)
		}
		if h.lock.Acquired() != 0 {
			t.Fatalf("a component that is not the identity playbook took the lock: %v", h.events())
		}
	})
}

// A busy server: the apply step fails, says why, and the playbook never ran.
func TestIdentityDeployBusyLockStopsBeforeThePlaybook(t *testing.T) {
	h := newDeployLockHarness(t)
	h.lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
	result, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{})
	if !errors.Is(err, sshdial.ErrLockBusy) {
		t.Fatalf("err = %v, want it to wrap ErrLockBusy", err)
	}
	if result.Outcome != delivery.OutcomeFailed || result.FailedStep != "apply" {
		t.Fatalf("result = %+v, want failed in apply", result)
	}
	for _, e := range h.events() {
		if e == "run apply" {
			t.Fatalf("the playbook ran without the lock: %v", h.events())
		}
	}
}

// The lock is lost while the playbook runs: it is killed, the run is `failed`
// in the step that was running with ErrLockLost, the evidence of the step was
// still written (the writer here fails on a cancelled context like SQLite
// does, so a transaction whose context the loss cancelled would be
// `evidence_failed`), and the lock is released at the end.
func TestIdentityDeployLostLockKillsTheApplyAndFailsTheRun(t *testing.T) {
	h := newDeployLockHarness(t)
	t.Setenv("BLOCK_AT", "1")
	type outcome struct {
		result delivery.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways})
		done <- outcome{result, err}
	}()
	pid := h.waitForPID()
	h.lock.Lose()
	var got outcome
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not end after the lock was lost")
	}
	if !errors.Is(got.err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", got.err)
	}
	if got.result.Outcome != delivery.OutcomeFailed || got.result.FailedStep != "apply" {
		t.Fatalf("result = %+v: a lost lock is `failed` in the step that was running, never `evidence_failed`", got.result)
	}
	if !processGone(pid) {
		t.Fatalf("the playbook (pid %d) outlived the lost lock", pid)
	}
	if steps := h.writer.steps(); !slices.Contains(steps, "apply:failed") {
		t.Fatalf("step evidence = %v: the failed step was not recorded", steps)
	}
	if len(h.writer.finished) != 1 || h.writer.finished[0].Outcome != string(delivery.OutcomeFailed) {
		t.Fatalf("run finished = %+v, want one `failed`", h.writer.finished)
	}
	events := h.events()
	if events[len(events)-1] != "release ipa-1" {
		t.Fatalf("events = %v: the lost lock was not released at the end", events)
	}
	// Nothing after the loss: no verify, no idempotency re-apply.
	if n := strings.Count(strings.Join(events, "\n"), "run apply"); n != 1 {
		t.Fatalf("the playbook ran %d times, want 1: %v", n, events)
	}
}

// The same for the idempotency re-apply, a second playbook run under the lock.
func TestIdentityDeployLostLockKillsTheIdempotencyRun(t *testing.T) {
	h := newDeployLockHarness(t)
	t.Setenv("BLOCK_AT", "2")
	done := make(chan struct {
		result delivery.Result
		err    error
	}, 1)
	go func() {
		result, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways})
		done <- struct {
			result delivery.Result
			err    error
		}{result, err}
	}()
	pid := h.waitForPID()
	h.lock.Lose()
	got := <-done
	if !errors.Is(got.err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", got.err)
	}
	if got.result.Outcome != delivery.OutcomeFailed || got.result.FailedStep != "idempotency" {
		t.Fatalf("result = %+v, want failed in idempotency", got.result)
	}
	if !processGone(pid) {
		t.Fatalf("the idempotency run (pid %d) outlived the lost lock", pid)
	}
}

// The verify step is read-only: the loss does not cancel it, but what it read
// was not read under the lock, so a verify that returns nil is still a
// failure.
func TestIdentityDeployLostLockVoidsAVerifyThatPassed(t *testing.T) {
	h := newDeployLockHarness(t)
	result, err := h.run(identityPlaybookForTest, deploymentTransactionOptions{
		Verify: func(ctx context.Context) error {
			if identitylock.HeldFrom(ctx) != nil && ctx.Err() != nil {
				return fmt.Errorf("the verify context was cancelled: %w", ctx.Err())
			}
			h.lock.Lose()
			return nil
		},
	})
	if !errors.Is(err, identitylock.ErrLockLost) {
		t.Fatalf("err = %v, want ErrLockLost", err)
	}
	if result.Outcome != delivery.OutcomeFailed || result.FailedStep != "verify" {
		t.Fatalf("result = %+v, want failed in verify", result)
	}
}

// The transaction refuses the identity playbook when it was handed no lock,
// before it runs anything, previews included; it does not change what a
// run of another playbook does with empty options.
func TestExecuteDeploymentRefusesTheIdentityPlaybookWithoutALock(t *testing.T) {
	runnerFor := func(t *testing.T) (*ansible.Runner, string) {
		log := filepath.Join(t.TempDir(), "calls.log")
		t.Setenv("LOG", log)
		t.Setenv("COUNT", filepath.Join(t.TempDir(), "count"))
		runner := ansible.NewRunner()
		runner.Binary = writeScript(t, "ansible-playbook", lockedDeployScript)
		runner.Timeout = 30 * time.Second
		return runner, log
	}
	stubConfirm := func(t *testing.T) {
		prev := confirmDeployment
		t.Cleanup(func() { confirmDeployment = prev })
		confirmDeployment = func(string, string, bool) bool { return true }
	}
	t.Run("the identity playbook, empty options", func(t *testing.T) {
		runner, log := runnerFor(t)
		stubConfirm(t)
		err := executeDeployment(context.Background(), runner, &bytes.Buffer{}, identityPlaybookForTest, "inventory.yml", "", "", nil, vaultInput{})
		if !errors.Is(err, identitylock.ErrNoLock) {
			t.Fatalf("err = %v, want ErrNoLock", err)
		}
		if got := readEvents(t, log); len(got) != 0 {
			t.Fatalf("ansible-playbook ran before the refusal: %v", got)
		}
	})
	t.Run("the identity playbook, a preview-only authorization", func(t *testing.T) {
		runner, log := runnerFor(t)
		err := executeDeploymentTransaction(context.Background(), runner, &bytes.Buffer{}, identityPlaybookForTest, "inventory.yml", "", "", nil, vaultInput{},
			deploymentTransactionOptions{Authorization: &deploymentAuthorization{Preview: true, PreviewOnly: true}})
		if !errors.Is(err, identitylock.ErrNoLock) {
			t.Fatalf("a preview must refuse too: err = %v", err)
		}
		if got := readEvents(t, log); len(got) != 0 {
			t.Fatalf("a preview ran before the refusal: %v", got)
		}
	})
	t.Run("a path to it that is not the repo-relative one", func(t *testing.T) {
		runner, log := runnerFor(t)
		stubConfirm(t)
		err := executeDeployment(context.Background(), runner, &bytes.Buffer{}, "/work/checkout/./playbooks/apply/freeipa-identity-apply.yml", "inventory.yml", "", "", nil, vaultInput{})
		if !errors.Is(err, identitylock.ErrNoLock) {
			t.Fatalf("err = %v, want ErrNoLock", err)
		}
		if got := readEvents(t, log); len(got) != 0 {
			t.Fatalf("ansible-playbook ran: %v", got)
		}
	})
	t.Run("another playbook is unaffected", func(t *testing.T) {
		runner, log := runnerFor(t)
		stubConfirm(t)
		if err := executeDeployment(context.Background(), runner, &bytes.Buffer{}, "playbooks/apply/docker-apply.yml", "inventory.yml", "", "", nil, vaultInput{}); err != nil {
			t.Fatalf("err = %v", err)
		}
		if got := readEvents(t, log); len(got) == 0 {
			t.Fatal("the playbook did not run")
		}
	})
}
