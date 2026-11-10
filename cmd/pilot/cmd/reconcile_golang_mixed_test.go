package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/store"
)

// The mixed run (`pilot reconcile --engine golang --scope full`, spec 2026-11-06 phase 2 §8.3): the Go
// engine writes the users and groups under the lock of the identity transaction, and the identity
// playbook, told to skip them, does the rest. Three layers of tests:
//
//   - executeDeploymentTransaction with a hook of its own, for the one rule that must not depend on the
//     Go phase being written right: the playbook is never started when the Go phase failed (§7.6, I7);
//   - the real mixedStep over the same fake FreeIPA the users-groups apply tests use: what the Go phase
//     does and returns, what each wrapped step does with an observation of the playbook;
//   - the command, through the real cobra tree (reconcile_golang_mixed_cli_test.go).

// ---- layer 1: the transaction and its hook ----

// mixedProbe is a mixedTransaction that records what the transaction asked of it, and a Go phase of
// the test's own.
type mixedProbe struct {
	t      *testing.T
	log    string
	extra  []string // handed to every run of the playbook
	phase  error    // what PrepareApply returns
	steps  []string
	ranFor []string
}

func (m *mixedProbe) PrepareApply(context.Context) error {
	appendEvent(m.t, m.log, "go phase")
	return m.phase
}

func (m *mixedProbe) WrapStep(step string, inner delivery.StepFunc) delivery.StepFunc {
	m.steps = append(m.steps, step)
	return func(ctx context.Context) error {
		appendEvent(m.t, m.log, "step "+step)
		if inner == nil {
			return nil
		}
		return inner(ctx)
	}
}

func (m *mixedProbe) RunPlaybook(ctx context.Context, step string, run playbookRun) (*ansible.Result, error) {
	m.ranFor = append(m.ranFor, step)
	return run(ctx, m.extra)
}

// mixedArgsScript is lockedDeployScript that also logs the arguments of every run, so that what the hook
// added to the command is seen as the command received it.
const mixedArgsScript = `#!/bin/sh
kind=apply
for a in "$@"; do [ "$a" = --check ] && kind=check; done
echo "run $kind" >> "$LOG"
printf 'args %s\n' "$*" >> "$LOG"
printf 'PLAY RECAP *********\nipa-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n'
exit "${APPLY_EXIT:-0}"
`

func newMixedTransactionHarness(t *testing.T) (*deployLockHarness, *mixedProbe) {
	t.Helper()
	h := newDeployLockHarness(t)
	h.runner.Binary = writeScript(t, "ansible-playbook-args", mixedArgsScript)
	return h, &mixedProbe{t: t, log: h.log, extra: []string{"-e", `{"pilot_identity_auth_cache_output": "/tmp/x"}`}}
}

func (h *deployLockHarness) runMixed(playbook string, m *mixedProbe, opts deploymentTransactionOptions) (delivery.Result, error) {
	h.t.Helper()
	opts.Mixed = m
	opts.PrepareApply = m.PrepareApply
	return h.run(playbook, opts)
}

func eventsWithout(events []string, prefixes ...string) []string {
	var out []string
	for _, e := range events {
		drop := false
		for _, p := range prefixes {
			drop = drop || strings.HasPrefix(e, p)
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}

// The order of a mixed transaction: the Go phase is after the lock and before the first run of the
// playbook that applies; every run of the playbook goes through the hook, which hands it what it asks;
// every step but the rollback-less ones is wrapped; the lock is given back last.
func TestMixedTransactionOrder(t *testing.T) {
	h, m := newMixedTransactionHarness(t)
	result, err := h.runMixed(identityPlaybookForTest, m, deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways, Verify: func(context.Context) error { appendEvent(t, h.log, "verify"); return nil }})
	if err != nil || result.Outcome != delivery.OutcomeSuccess {
		t.Fatalf("outcome %s, err %v", result.Outcome, err)
	}
	got := eventsWithout(h.events(), "prompt ", "args ")
	// The wrapper of a step is entered first, whatever the step does inside it: the apply wrapper before the lock is
	// taken; the Go phase is between the lock and the apply's playbook, and the idempotency re-apply is still under it.
	want := []string{"step preview", "run check", "step apply", "lock ipa-1", "go phase", "run apply", "step verify", "verify", "step idempotency", "run apply", "release ipa-1"}
	if !slices.Equal(got, want) {
		t.Fatalf("events:\n got %v\nwant %v", got, want)
	}
	if !slices.Equal(m.ranFor, []string{"preview", "apply", "idempotency"}) {
		t.Fatalf("the hook ran the playbook for %v, want preview, apply and idempotency", m.ranFor)
	}
	// What the hook added reached the command, in every run, after the transaction's own arguments.
	args := 0
	for _, e := range h.events() {
		if strings.HasPrefix(e, "args ") {
			args++
			if !strings.HasSuffix(e, `-e {"pilot_identity_auth_cache_output": "/tmp/x"}`) {
				t.Errorf("a run of the playbook did not receive what the hook added: %q", e)
			}
		}
	}
	if args != 3 {
		t.Fatalf("%d runs of the playbook, want 3", args)
	}
	if !slices.Equal(m.steps, []string{"preview", "apply", "verify", "idempotency"}) {
		t.Fatalf("wrapped steps %v", m.steps)
	}
}

// The playbook is never started when the Go phase did not apply and verify its plan: whatever the Go phase
// returns, the apply step ends there, the lock is given back, and no run of the playbook that applies follows
// (§7.6, I7: the same rule that a blocked Plan₂, an operation that failed or is unknown, and a read after the
// writes that shows something left all end the run before the playbook). A partial application is the
// outcome partial_failed and is not rolled back; any other error is a plain failure.
func TestMixedTransactionDoesNotRunThePlaybookWhenTheGoPhaseFails(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase       error
		wantOutcome delivery.Outcome
	}{
		{"the Go phase failed", errors.New("Go 階段沒有完成"), delivery.OutcomeFailed},
		{"the Go phase is blocked", fmt.Errorf("%w: uid_or_gid_change", identityreconcile.ErrBlocked), delivery.OutcomeFailed},
		{"the Go phase committed and then failed", fmt.Errorf("%w: %w", delivery.ErrPartiallyApplied, identityreconcile.ErrWrites), delivery.OutcomePartialFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, m := newMixedTransactionHarness(t)
			m.phase = tc.phase
			result, err := h.runMixed(identityPlaybookForTest, m, deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways})
			if err == nil || !errors.Is(err, tc.phase) {
				t.Fatalf("err = %v, want the Go phase's", err)
			}
			if result.Outcome != tc.wantOutcome || result.FailedStep != "apply" {
				t.Fatalf("outcome %s at %s, want %s at apply", result.Outcome, result.FailedStep, tc.wantOutcome)
			}
			applied := 0
			for _, e := range h.events() {
				if e == "run apply" {
					applied++
				}
			}
			if applied != 0 {
				t.Fatalf("the playbook was run %d time(s) after a Go phase that failed: %v", applied, h.events())
			}
			if !slices.Contains(h.events(), "run check") {
				t.Fatalf("the preview did not run: %v", h.events())
			}
			if h.lock.Acquired() != 1 || h.lock.Released() != 1 {
				t.Fatalf("lock taken %d, released %d", h.lock.Acquired(), h.lock.Released())
			}
			if slices.Contains(h.events(), "step verify") || slices.Contains(h.events(), "step idempotency") {
				t.Fatalf("a later step ran: %v", h.events())
			}
		})
	}
}

// A transaction that is not the identity playbook's never sees the hook, even handed one: the mixed marker
// is the identity transaction's, and the dependency chain's playbooks run as they did.
func TestMixedTransactionHookIsTheIdentityPlaybooksAlone(t *testing.T) {
	h, m := newMixedTransactionHarness(t)
	opts := deploymentTransactionOptions{Idempotency: delivery.IdempotencyAlways, Mixed: m, PrepareApply: nil}
	result, err := h.run("playbooks/apply/docker-apply.yml", opts)
	if err != nil || result.Outcome != delivery.OutcomeSuccess {
		t.Fatalf("outcome %s, err %v", result.Outcome, err)
	}
	if len(m.steps) != 0 || len(m.ranFor) != 0 {
		t.Fatalf("another playbook's transaction was wrapped (%v) or run through the hook (%v)", m.steps, m.ranFor)
	}
	if h.lock.Acquired() != 0 {
		t.Fatal("another playbook took the identity lock")
	}
}

// ---- layer 2: the real mixedStep ----

// mixedEnv is a mixed run's identity transaction without the playbook: the fake FreeIPA, the fake lock and
// the fake entry of the users-groups apply tests, a delivery run to journal in, and the step the command
// would have made.
type mixedEnv struct {
	*applyEnv
	run    *mixedIdentityRun
	step   *mixedStep
	out    *bytes.Buffer
	errOut *bytes.Buffer
	store  *store.Store
	writer *store.RunWriter
	inv    string
}

func newMixedEnv(t *testing.T, roster string) *mixedEnv {
	t.Helper()
	e := newApplyEnv(t, roster)
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &mixedEnv{applyEnv: e, out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, inv: filepath.Join(e.dir, "inventory.yml")}
	cmd := &cobra.Command{}
	cmd.SetOut(m.out)
	cmd.SetErr(m.errOut)
	m.run = &mixedIdentityRun{cmd: cmd, runtime: runtime, timeout: 2 * time.Minute}
	m.store, err = openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.store.Close() })
	m.writer, err = store.StartRun(context.Background(), m.store, store.RunStarted{Stage: "sandbox", Component: "freeipa-identity", Components: []string{"freeipa-identity"}, Playbook: identityPlaybookForTest, Inventory: m.inv, Hosts: []string{"ipa-1"}})
	if err != nil {
		t.Fatal(err)
	}
	m.step, err = m.run.begin(m.inv, "", "sandbox")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.step.close)
	m.step.bind(m.writer)
	return m
}

// goPhase takes the fake lock the apply step would have taken and runs PrepareApply under it.
func (m *mixedEnv) goPhase(t *testing.T) (*identitylock.Held, error) {
	t.Helper()
	held, err := m.lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Release() })
	return held, m.step.PrepareApply(held.Attach(context.Background()))
}

// The Go phase of a plan with something to write: the entry (prepare) runs, the write goes out, the read after it
// is clean, and PrepareApply returns nil, which is what lets the playbook start. The run is committed from then on.
func TestMixedGoPhaseAppliesAndVerifiesBeforeThePlaybook(t *testing.T) {
	m := newMixedEnv(t, rosterWithNewUser())
	_, err := m.goPhase(t)
	if err != nil {
		t.Fatalf("PrepareApply: %v\n%s", err, m.out.String())
	}
	if got := m.a.writeMethods(); !slices.Equal(got, []string{"user_add"}) {
		t.Fatalf("writes %v, want one user_add", got)
	}
	calls := m.playbookCalls()
	if len(calls) != 1 || !strings.Contains(strings.Join(calls[0], " "), identitylock.AuthCachePlaybook) || !strings.Contains(strings.Join(calls[0], " "), `"prepare"`) {
		t.Fatalf("the entry ran %v, want one prepare", calls)
	}
	if !m.step.committed() || m.step.res == nil || !m.step.res.Observed || !m.step.res.Entry.Ran {
		t.Fatalf("the step after the Go phase: committed %v, result %+v", m.step.committed(), m.step.res)
	}
	if m.step.host != "ipa-1" || m.step.fqdn == "" || m.step.prep == nil || m.step.session == nil {
		t.Fatalf("the step lost what the observation is checked against: host %q fqdn %q", m.step.host, m.step.fqdn)
	}
	// The journal is the delivery run's, with the executor's events.
	types := eventTypes(runEvents(t, m.writer.RunID()))
	for _, want := range []string{"identity.op", "identity.verify", "identity.auth_cache"} {
		if !slices.Contains(types, want) {
			t.Errorf("the run's events %v lack %s", types, want)
		}
	}
}

// A roster with no difference writes nothing and runs no entry: the Go phase is a read, and the playbook's own
// prepare, settle and acknowledgement are what the obligation of an earlier run waits for (H3).
func TestMixedGoPhaseWithNothingToWriteRunsNoEntry(t *testing.T) {
	m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
	_, err := m.goPhase(t)
	if err != nil {
		t.Fatalf("PrepareApply: %v\n%s", err, m.out.String())
	}
	if len(m.a.writeMethods()) != 0 || len(m.playbookCalls()) != 0 {
		t.Fatalf("a run with nothing to write wrote %v and ran the entry %v", m.a.writeMethods(), m.playbookCalls())
	}
	if m.step.committed() || m.step.res == nil || !m.step.res.Observed || m.step.res.Entry.Ran || m.step.res.Entry.Pending != nil {
		t.Fatalf("the step: committed %v, result %+v: no entry, and no probe (the playbook is what reads the obligation)", m.step.committed(), m.step.res)
	}
}

// The Go phase's failures, each with what the apply step is told: nothing but a plan that was applied and
// verified returns nil. Blocked is exit 3, an obligation that is only owed is never an error of the Go phase,
// and a phase that committed something is a partial application, which the transaction does not roll back.
func TestMixedGoPhaseFailuresAreNeverMistakenForAnAppliedPlan(t *testing.T) {
	t.Setenv("P26_ENTRY", "ok")
	for _, tc := range []struct {
		name      string
		roster    string
		setup     func(t *testing.T, m *mixedEnv)
		wantErr   error  // errors.Is
		wantText  string // in the message
		wantExit  int
		partial   bool
		wantWrite int
		wantEntry bool
	}{
		{name: "a plan with a blocked object (a uid change): blocked, nothing written, no entry",
			roster:  strings.Replace(captureRoster, "%s", "/bin/sh, uid: 1", 1),
			wantErr: identityreconcile.ErrBlocked, wantText: "identity playbook 沒有執行", wantExit: 3},
		{name: "the entry fails: nothing written",
			roster:  rosterWithNewUser(),
			setup:   func(t *testing.T, m *mixedEnv) { t.Setenv("P26_ENTRY", "fail") },
			wantErr: identityreconcile.ErrEntry, wantText: "identity playbook 沒有執行", wantExit: 1, wantEntry: true}, // started, and failed
		{name: "a write is refused and nothing was committed: an ordinary failure, with the entry noted",
			roster:  rosterWithNewUser(),
			setup:   func(t *testing.T, m *mixedEnv) { m.a.failItem["user_add:p26-new"] = "user-add-duplicate" },
			wantErr: identityreconcile.ErrWrites, wantText: "入口已執行", wantExit: 1, wantEntry: true},
		{name: "a write succeeds and another in the batch is refused: a partial application",
			roster:  rosterWithNewUser() + "  - {name: p26-two, first: P26, last: Two}\n",
			setup:   func(t *testing.T, m *mixedEnv) { m.a.failItem["user_add:p26-two"] = "user-add-duplicate" },
			wantErr: identityreconcile.ErrWrites, wantText: "identity playbook 沒有執行", wantExit: 1, partial: true, wantEntry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMixedEnv(t, tc.roster)
			if tc.setup != nil {
				tc.setup(t, m)
			}
			_, err := m.goPhase(t)
			if err == nil {
				t.Fatalf("PrepareApply returned nil for a plan that was not applied and verified:\n%s", m.out.String())
			}
			if !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err = %v, want %v and %q", err, tc.wantErr, tc.wantText)
			}
			if errors.Is(err, delivery.ErrPartiallyApplied) != tc.partial {
				t.Fatalf("partial application = %v, want %v: %v", errors.Is(err, delivery.ErrPartiallyApplied), tc.partial, err)
			}
			if got := golangApplyExitCode(err); got != tc.wantExit {
				t.Fatalf("exit code %d, want %d", got, tc.wantExit)
			}
			if tc.wantErr == identityreconcile.ErrBlocked && (len(m.a.writeMethods()) != 0 || len(m.playbookCalls()) != 0) {
				t.Fatalf("a blocked plan wrote %v or ran the entry %v", m.a.writeMethods(), m.playbookCalls())
			}
			if tc.wantEntry != (len(m.playbookCalls()) > 0) {
				t.Fatalf("entry ran = %v, want %v", len(m.playbookCalls()) > 0, tc.wantEntry)
			}
			if m.step.committed() != tc.partial {
				t.Fatalf("committed = %v, want %v", m.step.committed(), tc.partial)
			}
		})
	}
}

// The server the Go engine would write must be the one the lock is on: another host in the lock is refused
// before a connection is made.
func TestMixedGoPhaseRefusesAServerThatIsNotTheLockedOne(t *testing.T) {
	m := newMixedEnv(t, rosterWithNewUser())
	m.lock.Host = "ipa-2"
	_, err := m.goPhase(t)
	if err == nil || !strings.Contains(err.Error(), "鎖在 ipa-2") {
		t.Fatalf("err = %v, want the lock held on another host refused", err)
	}
	if len(m.a.writeMethods()) != 0 || len(m.playbookCalls()) != 0 {
		t.Fatalf("something ran: writes %v entry %v", m.a.writeMethods(), m.playbookCalls())
	}
	assertNoLogin(t, m.f)
}

// observeWrite is the run of a playbook that writes this observation to the path it was handed, and exits as told.
func observeWrite(t *testing.T, host, fqdn string, res *identityreconcile.AuthCacheResult, exit int) playbookRun {
	t.Helper()
	return func(_ context.Context, extra []string) (*ansible.Result, error) {
		if len(extra) != 2 || extra[0] != "-e" {
			t.Fatalf("the run was handed %v, want -e <the observation file's variable>", extra)
		}
		var vars map[string]string
		if err := json.Unmarshal([]byte(extra[1]), &vars); err != nil || vars[identityreconcile.AuthCacheOutputVar] == "" {
			t.Fatalf("the extra variable %q: %v", extra[1], err)
		}
		if _, has := vars[identityreconcile.AuthCacheActionVar]; has {
			t.Fatalf("the identity playbook was handed the entry's action variable: %v", vars)
		}
		if res != nil {
			r := *res
			r.Action, r.Host, r.FQDN = identityreconcile.AuthCacheObserve, host, fqdn
			data, err := identityreconcile.RenderAuthCacheResult(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(vars[identityreconcile.AuthCacheOutputVar], data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return &ansible.Result{ExitCode: exit}, nil
	}
}

// The verification of a mixed run consumes the playbook's observation of its apply: acknowledged is the
// only thing that settles the obligation, and anything else (no acknowledgement, no file, the file of
// another host, a playbook that never ran) is ErrUnsettled, exit code 4, and a partial application whether
// or not the Go phase committed (ErrUnsettled wraps it). A verify that failed is its own error, shaped
// as partial when the Go phase committed.
func TestMixedVerifyConsumesTheObservationOfTheApply(t *testing.T) {
	acked := &identityreconcile.AuthCacheResult{Prepared: true, Dirty: boolPtr(true), Refreshed: true, Acked: true}
	notAcked := &identityreconcile.AuthCacheResult{Prepared: true, Dirty: boolPtr(true)}
	for _, tc := range []struct {
		name      string
		obs       *identityreconcile.AuthCacheResult
		host      string
		exit      int
		skipRun   bool
		verifyErr error
		committed bool
		wantErr   error
		wantExit  int
		partial   bool
	}{
		{name: "acknowledged", obs: acked, host: "ipa-1"},
		{name: "acknowledged after a committed Go phase", obs: acked, host: "ipa-1", committed: true},
		{name: "not acknowledged (refresh off, a deferred client, a client that did not finish)", obs: notAcked, host: "ipa-1", wantErr: identityreconcile.ErrUnsettled, wantExit: 4, partial: true},
		{name: "not acknowledged, Go committed", obs: notAcked, host: "ipa-1", committed: true, wantErr: identityreconcile.ErrUnsettled, wantExit: 4, partial: true},
		{name: "the playbook wrote no file (no host matched, a skipped task)", obs: nil, host: "ipa-1", wantErr: identityreconcile.ErrUnsettled, wantExit: 4, partial: true},
		{name: "the file is another host's", obs: acked, host: "ipa-9", wantErr: identityreconcile.ErrUnsettled, wantExit: 4, partial: true},
		{name: "the playbook never ran", skipRun: true, wantErr: identityreconcile.ErrUnsettled, wantExit: 4, partial: true},
		{name: "pilot verify failed, Go committed", obs: acked, host: "ipa-1", verifyErr: errors.New("verify: 3 rows failed"), committed: true, wantErr: delivery.ErrPartiallyApplied, wantExit: 1, partial: true},
		{name: "pilot verify failed, nothing committed", obs: acked, host: "ipa-1", verifyErr: errors.New("verify: 3 rows failed"), wantExit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
			if _, err := m.goPhase(t); err != nil {
				t.Fatal(err)
			}
			if tc.committed {
				m.step.res.Ops = append(m.step.res.Ops, identityreconcile.OpResult{Outcome: identityreconcile.OutcomeSuccess})
			}
			if !tc.skipRun {
				if _, err := m.step.RunPlaybook(context.Background(), "apply", observeWrite(t, tc.host, m.step.fqdn, tc.obs, tc.exit)); err != nil {
					t.Fatal(err)
				}
			}
			verify := m.step.WrapStep("verify", func(context.Context) error { return tc.verifyErr })
			err := verify(context.Background())
			switch {
			case tc.wantErr == nil && tc.verifyErr == nil:
				if err != nil {
					t.Fatalf("verify = %v, want nil", err)
				}
				return
			case tc.verifyErr != nil && tc.wantErr == nil:
				if !errors.Is(err, tc.verifyErr) || errors.Is(err, delivery.ErrPartiallyApplied) {
					t.Fatalf("verify = %v, want the verify's own error and no partial application", err)
				}
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("verify = %v, want %v", err, tc.wantErr)
			}
			if got := errors.Is(err, delivery.ErrPartiallyApplied); got != tc.partial {
				t.Fatalf("partial application = %v, want %v: %v", got, tc.partial, err)
			}
			if got := golangApplyExitCode(err); got != tc.wantExit {
				t.Fatalf("exit code %d, want %d (%v)", got, tc.wantExit, err)
			}
			if tc.wantErr == identityreconcile.ErrUnsettled && !strings.Contains(err.Error(), "授權快取義務") {
				t.Fatalf("the message does not say the obligation is owed: %v", err)
			}
		})
	}
}

// The runs of the playbook through the hook: each is a new empty file before and is read after, so the
// apply's observation is never the one an earlier run left; the preview's and the idempotency run's are not the
// one the obligation is settled by; the command's own result comes back as it was, since whether it failed is
// the apply step's to say.
func TestMixedRunPlaybookObservesTheApplyAndLeavesTheCommandsResultAlone(t *testing.T) {
	acked := &identityreconcile.AuthCacheResult{Prepared: true, Acked: true}
	m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
	if _, err := m.goPhase(t); err != nil {
		t.Fatal(err)
	}
	// The preview writes nothing (the observation is skipped under --check): its file is empty, which is not an
	// observation, and not the apply's.
	if res, err := m.step.RunPlaybook(context.Background(), "preview", observeWrite(t, "ipa-1", m.step.fqdn, nil, 0)); err != nil || res == nil || res.ExitCode != 0 {
		t.Fatalf("preview: %+v, %v", res, err)
	}
	if m.step.obs != nil || m.step.obsErr != nil || m.step.playbookRan {
		t.Fatalf("the preview left an observation (%+v, %v) or counts as the playbook having run", m.step.obs, m.step.obsErr)
	}
	// The apply: acknowledged.
	if res, err := m.step.RunPlaybook(context.Background(), "apply", observeWrite(t, "ipa-1", m.step.fqdn, acked, 0)); err != nil || res.ExitCode != 0 {
		t.Fatalf("apply: %+v, %v", res, err)
	}
	if m.step.obs == nil || !m.step.obs.Acked || m.step.obsErr != nil || !m.step.playbookRan {
		t.Fatalf("the apply's observation: %+v, %v", m.step.obs, m.step.obsErr)
	}
	// The idempotency run writes nothing: its empty file does not take the apply's observation away.
	if _, err := m.step.RunPlaybook(context.Background(), "idempotency", observeWrite(t, "ipa-1", m.step.fqdn, nil, 0)); err != nil {
		t.Fatal(err)
	}
	if m.step.obs == nil || !m.step.obs.Acked {
		t.Fatalf("the idempotency run replaced the apply's observation: %+v", m.step.obs)
	}
	// A second apply that wrote nothing does not keep the first one's: the file was made empty first.
	if _, err := m.step.RunPlaybook(context.Background(), "apply", observeWrite(t, "ipa-1", m.step.fqdn, nil, 0)); err != nil {
		t.Fatal(err)
	}
	if m.step.obs != nil || m.step.obsErr == nil {
		t.Fatalf("a run that wrote nothing was read as the earlier run's result: %+v, %v", m.step.obs, m.step.obsErr)
	}
	// The playbook failed (exit 2): its result comes back as it was, and what it wrote before failing is not accepted.
	res, err := m.step.RunPlaybook(context.Background(), "apply", observeWrite(t, "ipa-1", m.step.fqdn, acked, 2))
	if err != nil || res == nil || res.ExitCode != 2 {
		t.Fatalf("a failed playbook's result was changed: %+v, %v", res, err)
	}
	if m.step.obs != nil || m.step.obsErr == nil {
		t.Fatalf("an observation of a failed run was accepted: %+v, %v", m.step.obs, m.step.obsErr)
	}
	// The command could not be started: its error comes back, and is not a parse rejection.
	boom := errors.New("no ansible-playbook")
	if _, err := m.step.RunPlaybook(context.Background(), "apply", func(context.Context, []string) (*ansible.Result, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("a run that did not start: %v", err)
	}
}

// What the apply step makes of a failure after the Go phase: a partial application when the Go writer
// committed, the error as it was otherwise, and the cases that are not failures of the run (a preview-only
// stop, an operator's cancellation) never turned into one.
func TestMixedApplyStepShapesFailuresByWhatTheGoPhaseCommitted(t *testing.T) {
	m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
	boom := errors.New("❌ 套用失敗(結束碼 2)")
	wrap := func(err error) error {
		return m.step.WrapStep("apply", func(context.Context) error { return err })(context.Background())
	}
	if got := wrap(boom); got != boom {
		t.Fatalf("a failure with nothing committed was changed: %v", got)
	}
	for _, passes := range []error{errPreviewOnlyStop, delivery.ErrCancelled, nil} {
		if got := wrap(passes); !errors.Is(got, passes) && got != nil {
			t.Fatalf("%v became %v", passes, got)
		}
	}
	m.step.res = &identityreconcile.Result{Observed: true, Ops: []identityreconcile.OpResult{{Outcome: identityreconcile.OutcomeUnknown}}}
	got := wrap(boom)
	if !errors.Is(got, delivery.ErrPartiallyApplied) || !errors.Is(got, boom) {
		t.Fatalf("a failure after an unknown write = %v, want a partial application that still says what failed", got)
	}
	if again := wrap(got); strings.Count(again.Error(), delivery.ErrPartiallyApplied.Error()) != 1 {
		t.Fatalf("a partial application was wrapped twice: %v", again)
	}
	if wrap(nil) != nil {
		t.Fatal("a successful apply became an error")
	}
}

// The preview step puts the Go engine's read-only plan first: a plan with a blocked object ends the preview
// with exit code 3 before the playbook's own preview has run at all, and without a lock (the step takes none);
// a clean plan lets the playbook's preview run. The plan is written to --plan-out when the command asked.
func TestMixedPreviewIsTheGoPlanThenThePlaybooksCheck(t *testing.T) {
	t.Run("a blocked plan stops before the playbook", func(t *testing.T) {
		m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh, uid: 1", 1))
		innerRan := false
		err := m.step.WrapStep("preview", func(context.Context) error { innerRan = true; return nil })(context.Background())
		var coded *golangPreviewError
		if err == nil || !errors.As(err, &coded) || coded.code != golangPreviewBlockedExitCode {
			t.Fatalf("err = %v, want the blocked plan, exit code 3", err)
		}
		if innerRan {
			t.Fatal("the playbook's preview ran after a blocked plan")
		}
		if m.lock.Acquired() != 0 || len(m.a.writeMethods()) != 0 {
			t.Fatalf("a preview took the lock (%d) or wrote %v", m.lock.Acquired(), m.a.writeMethods())
		}
		if !strings.Contains(m.out.String(), "阻擋") {
			t.Fatalf("the plan was not shown:\n%s", m.out.String())
		}
	})
	t.Run("a clean plan lets the playbook's preview run, and is the plan file", func(t *testing.T) {
		m := newMixedEnv(t, rosterWithNewUser())
		planPath := filepath.Join(t.TempDir(), "plan.json")
		planOut, err := reserveOutput("--plan-out", planPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(planOut.discard)
		m.run.previewOnly, m.run.planOut = true, planOut
		innerRan := false
		if err := m.step.WrapStep("preview", func(context.Context) error { innerRan = true; return nil })(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !innerRan {
			t.Fatal("the playbook's preview did not run after a clean plan")
		}
		data, err := os.ReadFile(planPath)
		if err != nil || !strings.Contains(string(data), "user.create") || !strings.Contains(string(data), identityreconcile.DocumentSchema) {
			t.Fatalf("the plan file: %v\n%s", err, data)
		}
		if m.step.fqdn == "" || m.step.host != "ipa-1" {
			t.Fatalf("the preview did not record the server's name: %q %q", m.step.host, m.step.fqdn)
		}
		if len(m.a.writeMethods()) != 0 {
			t.Fatalf("a preview wrote %v", m.a.writeMethods())
		}
	})
	t.Run("without --preview-only no plan file is written, whatever the flag held", func(t *testing.T) {
		m := newMixedEnv(t, rosterWithNewUser())
		planPath := filepath.Join(t.TempDir(), "plan.json")
		planOut, _ := reserveOutput("--plan-out", planPath)
		t.Cleanup(planOut.discard)
		m.run.planOut = planOut // previewOnly stays false: the preview of a --force run
		if err := m.step.WrapStep("preview", func(context.Context) error { return nil })(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(planPath); err != nil {
			// reserveOutput made the empty file; it must still be empty (not written)
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(planPath); len(data) != 0 {
			t.Fatalf("the preview of a --force run wrote the plan file: %s", data)
		}
	})
}

// The idempotency step: after the playbook's second run the Go engine's read-only plan must have nothing to
// do, or the step fails (as a partial application when the Go phase committed).
func TestMixedIdempotencyHoldsTheGoPlanToZeroOperations(t *testing.T) {
	t.Run("an empty plan passes", func(t *testing.T) {
		m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
		if err := m.step.WrapStep("idempotency", func(context.Context) error { return nil })(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(m.out.String(), "冪等性檢查通過") {
			t.Fatalf("not said:\n%s", m.out.String())
		}
	})
	t.Run("a plan that still has an operation fails", func(t *testing.T) {
		m := newMixedEnv(t, rosterWithNewUser())
		err := m.step.WrapStep("idempotency", func(context.Context) error { return nil })(context.Background())
		if err == nil || !strings.Contains(err.Error(), "仍有 1 個操作") {
			t.Fatalf("err = %v, want the operation left", err)
		}
		if errors.Is(err, delivery.ErrPartiallyApplied) {
			t.Fatal("nothing was committed, and the step says it was")
		}
		m.step.res = &identityreconcile.Result{Observed: true, Ops: []identityreconcile.OpResult{{Outcome: identityreconcile.OutcomeSuccess}}}
		if err := m.step.WrapStep("idempotency", func(context.Context) error { return nil })(context.Background()); !errors.Is(err, delivery.ErrPartiallyApplied) {
			t.Fatalf("err = %v, want a partial application after a committed Go phase", err)
		}
	})
	t.Run("the playbook's own check failing comes first and the plan is not read", func(t *testing.T) {
		m := newMixedEnv(t, rosterWithNewUser())
		boom := errors.New("冪等性檢查失敗：第二次套用仍有 3 個變更")
		if err := m.step.WrapStep("idempotency", func(context.Context) error { return boom })(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		assertNoLogin(t, m.f)
	})
}

// The result file of a mixed run (spec §8.6): the Go phase's plans and operations, the playbook's
// observation, the scope, and the obligation as the observation says it; it is not written for a run that never
// read FreeIPA.
func TestMixedFinishWritesTheResultFileAndTheSummary(t *testing.T) {
	m := newMixedEnv(t, rosterWithNewUser())
	if _, err := m.goPhase(t); err != nil {
		t.Fatal(err)
	}
	if _, err := m.step.RunPlaybook(context.Background(), "apply", observeWrite(t, "ipa-1", m.step.fqdn, &identityreconcile.AuthCacheResult{Prepared: true, Dirty: boolPtr(true), Refreshed: true, Acked: true}, 0)); err != nil {
		t.Fatal(err)
	}
	m.step.finished(delivery.Result{Outcome: delivery.OutcomeSuccess}, m.writer.RunID())
	path := filepath.Join(t.TempDir(), "result.json")
	resultOut, err := reserveOutput("--result-out", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resultOut.discard)
	m.run.finish(m.run.cmd, nil, resultOut)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := identityreconcile.ParseApplyDocument(data)
	if err != nil {
		t.Fatalf("the result file: %v\n%s", err, data)
	}
	if doc.Scope != reconcileScopeFull || doc.Verdict != identityreconcile.VerdictOK || doc.Outcome != "success" || doc.ExitCode != 0 ||
		doc.Playbook == nil || !doc.Playbook.Ran || doc.Playbook.Observation == nil || !doc.Playbook.Observation.Acked ||
		doc.Authorization.Owed || !doc.Authorization.ObservedAcked || !doc.Authorization.EntryRan || doc.RunID != m.writer.RunID() {
		t.Fatalf("the result file: scope %q verdict %q outcome %q exit %d playbook %+v authorization %+v", doc.Scope, doc.Verdict, doc.Outcome, doc.ExitCode, doc.Playbook, doc.Authorization)
	}
	for _, want := range []string{"--scope full", "identity playbook：已執行", "acked=true", "result JSON：" + path} {
		if !strings.Contains(m.out.String(), want) {
			t.Errorf("the summary lacks %q:\n%s", want, m.out.String())
		}
	}
	assertNoSecretAnywhere(t, nil, m.out.String()+string(data), "")
}

func TestMixedFinishWritesNothingForARunThatNeverReadFreeIPA(t *testing.T) {
	m := newMixedEnv(t, rosterWithNewUser())
	path := filepath.Join(t.TempDir(), "result.json")
	resultOut, err := reserveOutput("--result-out", path)
	if err != nil {
		t.Fatal(err)
	}
	m.run.finish(m.run.cmd, errors.New("preflight failed"), resultOut)
	resultOut.discard()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a result file exists for a run that never read FreeIPA")
	}
	if m.out.Len() != 0 {
		t.Fatalf("a summary was printed for a run that never read FreeIPA:\n%s", m.out.String())
	}
}

// The marker the command puts on the context is read by the identity transaction and by nothing else.
func TestMixedMarkerIsOnTheContextOnlyWhereTheCommandPutIt(t *testing.T) {
	if mixedIdentityRunFrom(context.Background()) != nil {
		t.Fatal("a context nobody marked carries a mixed run")
	}
	run := &mixedIdentityRun{}
	if mixedIdentityRunFrom(withMixedIdentityRun(context.Background(), run)) != run {
		t.Fatal("the marker does not come back")
	}
	if got := (&mixedStep{}).extraVars(); !slices.Equal(got, []string{"pilot_identity_users_groups_engine=go"}) {
		t.Fatalf("extra vars %v, want exactly the engine variable the playbook's gate accepts", got)
	}
}

// A context that has ended starts no playbook: after the first Ctrl-C, or --timeout, a Go phase that ended on a
// converged unknown write returns no error, and the run goes on to the playbook, which must not start (and the
// result file must not say it ran).
func TestMixedRunPlaybookStartsNothingOnAnEndedContext(t *testing.T) {
	m := newMixedEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := false
	res, err := m.step.RunPlaybook(ctx, "apply", func(context.Context, []string) (*ansible.Result, error) {
		started = true
		return &ansible.Result{}, nil
	})
	if started || res != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("started=%v res=%v err=%v: an ended context must not start the playbook", started, res, err)
	}
	if m.step.playbookRan {
		t.Fatal("the step says the playbook ran")
	}
}
