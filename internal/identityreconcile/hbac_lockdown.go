package identityreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The lockdown of allow_all (H8; spec §6). It is the playbook's "Transactional HBAC
// allow_all lockdown" block over JSON-RPC: prove with hbactest that admin may log in to the
// FreeIPA server, disable allow_all, prove it again, and put allow_all back if anything
// after the disable did not hold. It runs last, after every rule has converged, so that the
// break-glass rule the proofs rest on exists, and it does not run at all when an earlier
// stage stopped the run.

// LockdownReport is what the lockdown stage did: the proofs with hbactest, the disable and
// the rollback. It is the stage's own account, kept in the result and in the journal's
// result event of the stage.
type LockdownReport struct {
	// Before and After are what the hbactest proofs answered: "granted", "denied" or
	// "error: <why>"; "" when the proof was not run.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	// Disabled: hbacrule_disable allow_all was sent and answered success.
	Disabled bool `json:"disabled"`
	// Rollback is what became of the re-enabling of allow_all: "" when none was needed,
	// "re-enabled" when the rollback succeeded, "FAILED: <why>" when it did not. It never
	// says re-enabled unless the enable was answered.
	Rollback string `json:"rollback,omitempty"`
	// Detail says what happened, in words.
	Detail string `json:"detail,omitempty"`
}

// lockdownProofTimeout bounds the proof after the disable and lockdownRollbackTimeout each
// rollback. They are separate so that a proof that uses up its time cannot take the
// rollback's with it: the enable must always get a budget of its own. The worst case of
// the stage after the disable is therefore about twice VerifyTimeout. They are variables
// only so that tests can shorten them.
var (
	lockdownProofTimeout    = VerifyTimeout
	lockdownRollbackTimeout = VerifyTimeout
)

// detached returns a context that outlives the run's cancellation, bounded by timeout and
// built when it is called, not derived from any other bounded context.
func (r *hbacRunner) detached(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.ctx), timeout)
}

// lockdownService is the service the proofs ask about: what the break-glass rule is for.
const lockdownService = "sshd"

// parseHBACTest reads an hbactest answer by its value, a JSON boolean (captured:
// hbactest-granted, hbactest-denied-user; never by its summary text). An answer that has no
// value, or that carries an error, proves nothing.
func parseHBACTest(raw json.RawMessage) (granted bool, err error) {
	var r struct {
		Value *bool `json:"value"`
		Error any   `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return false, fmt.Errorf("decode the hbactest answer: %w", err)
	}
	if r.Error != nil {
		return false, fmt.Errorf("hbactest answered an error: %v", r.Error)
	}
	if r.Value == nil {
		return false, errors.New("the hbactest answer has no value")
	}
	return *r.Value, nil
}

// proof asks FreeIPA whether admin may log in to the lockdown's host over sshd.
func (r *hbacRunner) proof(ctx context.Context) (granted bool, text string) {
	raw, err := r.rpc.Call(ctx, freeiparpc.Command{Method: "hbactest", Args: []any{}, Options: map[string]any{
		"user": hbacAdminUser, "targethost": r.opts.TestHost, "service": lockdownService,
	}})
	if err == nil {
		granted, err = parseHBACTest(raw)
	}
	switch {
	case err != nil:
		return false, "error: " + err.Error()
	case granted:
		return true, "granted"
	}
	return false, "denied"
}

// allowAllEnabled reads whether allow_all is enabled now.
func (r *hbacRunner) allowAllEnabled() (bool, error) {
	raw, err := r.rpc.Call(r.ctx, freeiparpc.Command{Method: "hbacrule_show", Args: []any{hbacRuleNameAllowAll}, Options: map[string]any{"all": true}})
	if err != nil {
		return false, err
	}
	entry, err := showEntry(raw)
	if err != nil {
		return false, err
	}
	rule, err := parseHBACRule(entry)
	if err != nil {
		return false, err
	}
	return rule.Enabled, nil
}

// rollback puts allow_all back. It goes out on a context that is not cancelled with the
// run (the run may have been interrupted between the disable and the proof, which is when
// it matters most), still under the engine's gate and the lock, and says only what the
// answer says: "re-enabled" is a hbacrule_enable that answered true.
func (r *hbacRunner) rollback(ctx context.Context) string {
	if err := r.opts.Gate.Check(ctx, "hbacrule_enable"); err != nil {
		return "FAILED: the write gate refused: " + err.Error()
	}
	raw, err := r.rpc.Call(ctx, freeiparpc.Command{Method: "hbacrule_enable", Args: []any{hbacRuleNameAllowAll}})
	if err != nil {
		return "FAILED: " + err.Error()
	}
	var ans struct {
		Result any `json:"result"`
	}
	if json.Unmarshal(raw, &ans) != nil || ans.Result != true {
		return "FAILED: the answer does not say allow_all was enabled"
	}
	return "re-enabled"
}

// runLockdown is H8. Nothing is sent before the proof holds; once the disable has been
// sent, a failure of any kind that may have left allow_all disabled is followed by the
// rollback, and the operation ends as failed (never as an unknown outcome the read after the
// writes could resolve as converged: allow_all disabled with the proof failing is the one
// state a lockdown must not leave).
func (r *hbacRunner) runLockdown(idxs []int) {
	i := idxs[0]
	op := r.res.Ops[i].Operation
	rep := &LockdownReport{}
	r.res.Lockdown = rep
	stopWith := func(c classified) {
		rep.Detail = c.Detail
		r.settle(i, c)
		r.stopAt(H8, op.ID+": "+c.Detail)
	}

	var granted bool
	if granted, rep.Before = r.proof(r.ctx); !granted {
		stopWith(classified{Outcome: OutcomeConflictFailed, Error: "lockdown not attempted",
			Detail: fmt.Sprintf("hbactest before the lockdown: %s for %s on %s: allow_all was not touched", rep.Before, hbacAdminUser, r.opts.TestHost)})
		return
	}
	enabled, err := r.allowAllEnabled()
	switch {
	case err != nil:
		stopWith(classified{Outcome: OutcomeConflictFailed, Error: "lockdown not attempted", Detail: "allow_all could not be read: " + err.Error()})
		return
	case !enabled:
		r.settle(i, classified{Outcome: OutcomeNoop, Detail: "allow_all is already disabled"})
		rep.Detail = "allow_all is already disabled"
		return
	}

	cmd, err := hbacCommandFor(Operation{Kind: KindHBACRuleDisable, Object: hbacRuleNameAllowAll})
	if err != nil {
		stopWith(classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
		return
	}
	r.batches[H8]++
	n := r.batches[H8]
	id := fmt.Sprintf("hbac:%s-c%d", H8, n)
	items := []hbacPending{{idx: i, op: op, cmd: cmd}}
	if !r.beforeSending(H8, n, id, items) {
		rep.Detail = "the gate or the journal kept the disable from going out: allow_all was not touched"
		return
	}
	raw, err := r.rpc.Call(r.ctx, cmd)
	if err != nil && refusedBeforeSending(err) {
		rep.Detail = "the client refused to send the disable: allow_all was not touched"
		r.stopAt(H8, "the client refused to send: "+err.Error())
		r.afterSending(H8, n, id, items, rep)
		return
	}
	r.sent = true
	c := classifyHBAC(op, raw, err)
	// Everything after this point is on contexts that outlive the run's cancellation. The
	// proof and each rollback have a budget of their own, built when they run.
	rollback := func() string {
		rctx, cancel := r.detached(lockdownRollbackTimeout)
		defer cancel()
		return r.rollback(rctx)
	}

	var rpcErr *freeiparpc.RPCError
	switch {
	case c.Outcome == OutcomeSuccess:
		rep.Disabled = true
		pctx, cancel := r.detached(lockdownProofTimeout)
		granted, rep.After = r.proof(pctx)
		cancel()
		if granted {
			r.settle(i, c)
			rep.Detail = "allow_all is disabled and admin is still granted"
			r.afterSending(H8, n, id, items, rep)
			return
		}
		rep.Rollback = rollback()
		c = classified{Outcome: OutcomeFailed, Error: "lockdown failed", Detail: fmt.Sprintf("hbactest after the disable: %s for %s on %s; %s", rep.After, hbacAdminUser, r.opts.TestHost, rollbackSentence(rep.Rollback))}
	case errors.As(err, &rpcErr):
		// The server answered and refused: allow_all was not disabled, nothing to put back.
		c.Detail = "the server refused the disable: " + c.Detail + "; allow_all was not touched"
		rep.Rollback = ""
	default:
		// The disable may have left (an unknown outcome) or the answer says nothing: put
		// allow_all back, and say how that went.
		rep.Rollback = rollback()
		c = classified{Outcome: OutcomeFailed, Error: c.Error, Detail: fmt.Sprintf("the disable of allow_all did not end as success (%s %s); %s", c.Outcome, c.Detail, rollbackSentence(rep.Rollback))}
	}
	rep.Detail = c.Detail
	r.settle(i, c)
	r.afterSending(H8, n, id, items, rep)
}

// rollbackSentence says how the rollback went, in the words an operator needs: it says
// allow_all was re-enabled only when it was, and otherwise says to check the access.
func rollbackSentence(rollback string) string {
	if rollback == "re-enabled" {
		return "allow_all was re-enabled"
	}
	return "re-enabling allow_all " + rollback + "; check HBAC access now"
}
