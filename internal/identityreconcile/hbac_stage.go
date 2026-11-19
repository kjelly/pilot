package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// HBACStage is one step of the HBAC write order (spec §5.2): the operations of a stage
// are independent of each other, and a later stage depends on an earlier one. Removals
// come before the categories and the additions after them, because a category and members
// exclude each other (K3).
type HBACStage int

// The HBAC stages, in the order they run.
const (
	H1 HBACStage = iota + 1 // hbacsvc_add
	H2                      // hbacrule_add
	H3                      // hbacrule_remove_host, _remove_service, _remove_user
	H4                      // hbacrule_mod (the categories)
	H5                      // hbacrule_add_host, _add_service, _add_user
	H6                      // hbacrule_enable, hbacrule_disable
	H7                      // hbacrule_del
	H8                      // the lockdown of allow_all
)

// HBACStages is every HBAC stage in order.
var HBACStages = []HBACStage{H1, H2, H3, H4, H5, H6, H7, H8}

func (s HBACStage) String() string { return fmt.Sprintf("H%d", int(s)) }

// HBACStageOf is the stage an HBAC operation kind runs in; 0 for a kind the engine does
// not know, which no stage runs.
func HBACStageOf(kind string) HBACStage {
	switch kind {
	case KindHBACServiceCreate:
		return H1
	case KindHBACRuleCreate:
		return H2
	case KindHBACHostRemove, KindHBACHostgroupRemove, KindHBACServiceRemove, KindHBACUserRemove, KindHBACGroupRemove:
		return H3
	case KindHBACCategoryUpdate:
		return H4
	case KindHBACHostgroupAdd, KindHBACHostAdd, KindHBACServiceAdd, KindHBACUserAdd, KindHBACGroupAdd:
		return H5
	case KindHBACRuleEnable, KindHBACRuleDisable:
		return H6
	case KindHBACRuleDelete:
		return H7
	case KindHBACAllowAllDisable:
		return H8
	}
	return 0
}

// hbacMember is the command and option a member operation uses (captured: the member
// options are user, group, host, hostgroup and hbacsvc; hosts and hostgroups share a
// command, users and groups share one).
type hbacMember struct {
	remove, add string // methods
	option      string
}

var hbacMembers = map[string]struct {
	adding bool
	m      hbacMember
}{
	KindHBACHostRemove:      {false, hbacMember{remove: "hbacrule_remove_host", option: "host"}},
	KindHBACHostgroupRemove: {false, hbacMember{remove: "hbacrule_remove_host", option: "hostgroup"}},
	KindHBACServiceRemove:   {false, hbacMember{remove: "hbacrule_remove_service", option: "hbacsvc"}},
	KindHBACUserRemove:      {false, hbacMember{remove: "hbacrule_remove_user", option: "user"}},
	KindHBACGroupRemove:     {false, hbacMember{remove: "hbacrule_remove_user", option: "group"}},
	KindHBACHostgroupAdd:    {true, hbacMember{add: "hbacrule_add_host", option: "hostgroup"}},
	KindHBACHostAdd:         {true, hbacMember{add: "hbacrule_add_host", option: "host"}},
	KindHBACServiceAdd:      {true, hbacMember{add: "hbacrule_add_service", option: "hbacsvc"}},
	KindHBACUserAdd:         {true, hbacMember{add: "hbacrule_add_user", option: "user"}},
	KindHBACGroupAdd:        {true, hbacMember{add: "hbacrule_add_user", option: "group"}},
}

func isHBACMemberKind(kind string) (adding, ok bool) {
	m, ok := hbacMembers[kind]
	return m.adding, ok
}

// hbacFieldTo is the string a field of an operation is to be set to, and whether the
// operation has the field at all.
func hbacFieldTo(op Operation, key string) (string, bool, error) {
	c, ok := op.Fields[key]
	if !ok {
		return "", false, nil
	}
	if c.To == nil {
		return "", true, nil
	}
	s, ok := c.To.(string)
	if !ok {
		return "", true, fmt.Errorf("%s: the field %s is not a string", op.ID, key)
	}
	return s, true, nil
}

// hbacCommandFor is the FreeIPA command of an HBAC operation. The names are the captured
// ones; nothing is sent that the playbook does not send (a rule is created with its
// categories only, a service with its name only).
func hbacCommandFor(op Operation) (freeiparpc.Command, error) {
	obj := []any{op.Object}
	if mm, ok := hbacMembers[op.Kind]; ok {
		method := mm.m.add
		if !mm.adding {
			method = mm.m.remove
		}
		members := make([]any, 0, len(op.Members))
		for _, m := range op.Members {
			members = append(members, m)
		}
		return freeiparpc.Command{Method: method, Args: obj, Options: map[string]any{mm.m.option: members}}, nil
	}
	switch op.Kind {
	case KindHBACServiceCreate:
		name, _, err := hbacFieldTo(op, hbacFieldName)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		if name == "" {
			name = op.Object
		}
		return freeiparpc.Command{Method: "hbacsvc_add", Args: []any{name}}, nil
	case KindHBACRuleCreate:
		name, _, err := hbacFieldTo(op, hbacFieldName)
		if err != nil {
			return freeiparpc.Command{}, err
		}
		if name == "" {
			name = op.Object
		}
		opts := map[string]any{}
		if cat, present, err := hbacFieldTo(op, hbacFieldHostCategory); err != nil {
			return freeiparpc.Command{}, err
		} else if present && cat != "" {
			opts["hostcategory"] = cat
		}
		if len(opts) == 0 {
			opts = nil
		}
		return freeiparpc.Command{Method: "hbacrule_add", Args: []any{name}, Options: opts}, nil
	case KindHBACCategoryUpdate:
		// An explicit value for every category the operation changes; "" clears it (K3).
		opts := map[string]any{}
		for _, key := range []string{hbacFieldHostCategory, hbacFieldServiceCategory} {
			v, present, err := hbacFieldTo(op, key)
			if err != nil {
				return freeiparpc.Command{}, err
			}
			if present {
				opts[key] = v
			}
		}
		if len(opts) == 0 {
			return freeiparpc.Command{}, fmt.Errorf("%s: no category to change", op.ID)
		}
		return freeiparpc.Command{Method: "hbacrule_mod", Args: obj, Options: opts}, nil
	case KindHBACRuleEnable:
		return freeiparpc.Command{Method: "hbacrule_enable", Args: obj}, nil
	case KindHBACRuleDisable:
		return freeiparpc.Command{Method: "hbacrule_disable", Args: obj}, nil
	case KindHBACRuleDelete:
		return freeiparpc.Command{Method: "hbacrule_del", Args: obj}, nil
	}
	return freeiparpc.Command{}, fmt.Errorf("no command for the HBAC operation kind %q", op.Kind)
}

// classifyHBAC decides what became of op from the answer to its command: raw is the
// result object of a success, err what Call or the batch item returned. The rules are
// those of the captures (capture_p3a_facts_test.go): a member command is a success even
// when no member changed, and says so per member; enable and disable of what is already
// in that state also succeed, so their answer cannot say whether anything changed (the
// read after the writes does).
func classifyHBAC(op Operation, raw json.RawMessage, err error) classified {
	if err != nil {
		return classifyHBACError(op, err)
	}
	if adding, isMember := isHBACMemberKind(op.Kind); isMember {
		return classifyHBACMembers(op, adding, raw)
	}
	switch op.Kind {
	case KindHBACRuleEnable, KindHBACRuleDisable, KindHBACAllowAllDisable:
		var r struct {
			Result any `json:"result"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Result != true {
			return classified{Outcome: OutcomeUnknown, Detail: "the answer does not say the command succeeded"}
		}
	case KindHBACRuleDelete:
		// result: {failed: []}, a name in failed was not deleted.
		var r struct {
			Result struct {
				Failed []any `json:"failed"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &r) == nil && len(r.Result.Failed) > 0 {
			return classified{Outcome: OutcomeFailed, Detail: fmt.Sprintf("the answer lists %d failed deletion(s)", len(r.Result.Failed))}
		}
	}
	return classified{Outcome: OutcomeSuccess}
}

func classifyHBACError(op Operation, err error) classified {
	var unknown *freeiparpc.OutcomeUnknownError
	if errors.As(err, &unknown) {
		return classified{Outcome: OutcomeUnknown, Error: "outcome unknown", Detail: err.Error()}
	}
	var rpc *freeiparpc.RPCError
	if !errors.As(err, &rpc) {
		// Not an answer of the server and not a write that may have left: the command
		// did not reach it. It was not applied.
		return classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()}
	}
	out := classified{Error: fmt.Sprintf("%s (%d)", rpc.Name, rpc.Code), Detail: rpc.Message}
	_, isMember := isHBACMemberKind(op.Kind)
	switch {
	case rpc.Name == "EmptyModlist" && op.Kind == KindHBACCategoryUpdate:
		out.Outcome = OutcomeNoop
	case rpc.Name == "NotFound" && op.Kind == KindHBACRuleDelete:
		out.Outcome = OutcomeNoop
	case rpc.Name == "DuplicateEntry" && (op.Kind == KindHBACServiceCreate || op.Kind == KindHBACRuleCreate):
		// What the plan said was missing is there: another writer's, and the plan the
		// operator reviewed no longer describes the server. Like the users and groups,
		// not applied and not taken as done.
		out.Outcome = OutcomeConflictFailed
	case rpc.Name == "NotFound" && (isMember || op.Kind == KindHBACCategoryUpdate || op.Kind == KindHBACRuleEnable || op.Kind == KindHBACRuleDisable || op.Kind == KindHBACAllowAllDisable):
		out.Outcome = OutcomeConflictFailed
	default:
		// MutuallyExclusiveError among them (K3): the order of the stages should have
		// kept it from happening, so it is a failure, not a conflict.
		out.Outcome = OutcomeFailed
	}
	return out
}

// hbacMemberFailure is one member a member command did not change.
type hbacMemberFailure struct{ kind, name, reason string }

// decodeHBACMemberResult reads an hbacrule_add_* or hbacrule_remove_* answer: completed,
// and failed.<area>.<kind> lists of [name, reason] (captured: hbacrule-add-user-already,
// hbacrule-add-user-missing and the others). Every requested member must be accounted for
// by completed or failed: an answer that does not is unknown, the command may have
// changed some.
func decodeHBACMemberResult(raw json.RawMessage, requested int) (completed int, failed []hbacMemberFailure, err error) {
	var r struct {
		Completed *int                             `json:"completed"`
		Failed    map[string]map[string][][]string `json:"failed"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0, nil, fmt.Errorf("decode the member answer: %w", err)
	}
	if r.Completed == nil || r.Failed == nil {
		return 0, nil, errors.New("the member answer lacks completed or failed")
	}
	for _, area := range sortedKeys(r.Failed) {
		for _, kind := range sortedKeys(r.Failed[area]) {
			for _, f := range r.Failed[area][kind] {
				if len(f) != 2 {
					return 0, nil, fmt.Errorf("a failed member is %q, want [name, reason]", f)
				}
				failed = append(failed, hbacMemberFailure{kind: kind, name: f[0], reason: f[1]})
			}
		}
	}
	if *r.Completed+len(failed) != requested {
		return *r.Completed, failed, fmt.Errorf("%d members requested, %d completed and %d failed", requested, *r.Completed, len(failed))
	}
	return *r.Completed, failed, nil
}

// classifyHBACMembers reads a member answer for what each reason is: a member already in
// (adding) or already out (removing) needs nothing, a member FreeIPA does not know is a
// conflict, any other reason is a failure.
func classifyHBACMembers(op Operation, adding bool, raw json.RawMessage) classified {
	completed, failed, err := decodeHBACMemberResult(raw, len(op.Members))
	if err != nil {
		return classified{Outcome: OutcomeUnknown, Completed: completed, Detail: "the answer does not account for every member: " + err.Error()}
	}
	out := classified{Completed: completed}
	var problems []string
	hardFailed, conflicted := false, false
	for _, f := range failed {
		switch {
		case adding && f.reason == reasonAlreadyMember, !adding && f.reason == reasonNotMember:
			// nothing to do for this member
		case f.reason == reasonNoSuchEntry:
			conflicted = true
			problems = append(problems, fmt.Sprintf("%s %s: %s", f.kind, f.name, f.reason))
		default:
			hardFailed = true
			problems = append(problems, fmt.Sprintf("%s %s: %s", f.kind, f.name, f.reason))
		}
	}
	out.Detail = strings.Join(problems, "; ")
	switch {
	case hardFailed:
		out.Outcome = OutcomeFailed
	case conflicted:
		out.Outcome = OutcomeConflictFailed
	case completed > 0:
		out.Outcome = OutcomeSuccess
	default:
		out.Outcome = OutcomeNoop
	}
	return out
}

// ---- the stages --------------------------------------------------------------

func (r *hbacRunner) runStages() {
	for _, s := range HBACStages {
		if r.stopped {
			return
		}
		idxs := r.stageOps(s)
		if len(idxs) == 0 {
			continue
		}
		switch s {
		case H3:
			r.runRemovals(idxs)
		case H6:
			r.runEnableDisable(idxs)
		case H7:
			r.runDeletes(idxs)
		case H8:
			r.runLockdown(idxs)
		default:
			// H1, H2, H4, H5: the server's answer to each command is the check (an add of
			// what exists is DuplicateEntry, a mod of what is gone is NotFound): they are
			// idempotent or only widen, and Plan₂ was just made.
			r.sendBatches(s, r.plainItems(idxs))
		}
	}
}

func (r *hbacRunner) stageOps(s HBACStage) []int {
	var out []int
	for i, o := range r.res.Ops {
		if HBACStageOf(o.Operation.Kind) == s {
			out = append(out, i)
		}
	}
	return out
}

// hbacPending is a command ready to go with the operation it is for.
type hbacPending struct {
	idx int
	op  Operation // as sent: a member command's list may be shorter than planned
	cmd freeiparpc.Command
}

func (r *hbacRunner) plainItems(idxs []int) []hbacPending {
	var out []hbacPending
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		cmd, err := hbacCommandFor(op)
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
			r.stopAt(HBACStageOf(op.Kind), op.ID+": "+err.Error())
			return out
		}
		out = append(out, hbacPending{idx: i, op: op, cmd: cmd})
	}
	return out
}

// sendBatches sends items in batches of at most the batch limit, in order, and stops
// after the batch in which an operation failed, conflicted or was unknown.
func (r *hbacRunner) sendBatches(s HBACStage, items []hbacPending) {
	for len(items) > 0 && !r.stopped {
		n := min(r.opts.BatchLimit, len(items))
		r.sendBatch(s, items[:n])
		items = items[n:]
	}
}

// hbacResultEvent is the payload of the event after a batch or call is sent.
type hbacResultEvent struct {
	Phase    string          `json:"phase"`
	Stage    string          `json:"stage"`
	Batch    int             `json:"batch"`
	Results  []OpResult      `json:"results"`
	Stopped  *Stop           `json:"stopped,omitempty"`
	Lockdown *LockdownReport `json:"lockdown,omitempty"`
}

// beforeSending runs what must hold before a batch or a call leaves: the engine's own
// gate for each command (besides the one in the client), and then the record of it in the
// journal, without which nothing is sent (fail closed, AGENTS.md §5.8).
func (r *hbacRunner) beforeSending(s HBACStage, batch int, id string, items []hbacPending) bool {
	for _, it := range items {
		if err := r.opts.Gate.Check(r.ctx, it.cmd.Method); err != nil {
			r.stopAt(s, "the write gate refused: "+err.Error())
			return false
		}
	}
	ops := make([]Operation, len(items))
	for i, it := range items {
		ops[i] = it.op
	}
	if err := r.record(Event{Kind: EventOp, ID: id + ":sending", Payload: sendEvent{Phase: "sending", Stage: s.String(), Batch: batch, Operations: ops}}); err != nil {
		r.stopAt(s, "the journal refused the record of the batch, so it was not sent: "+err.Error())
		return false
	}
	return true
}

// afterSending records what became of the items and stops the scheduling when one of
// them ends it.
func (r *hbacRunner) afterSending(s HBACStage, batch int, id string, items []hbacPending, lockdown *LockdownReport) {
	results := make([]OpResult, len(items))
	for i, it := range items {
		results[i] = r.res.Ops[it.idx]
		r.covered[it.idx] = true
		if r.res.Ops[it.idx].Outcome.stops() && r.res.Stop == nil {
			r.stopAt(s, fmt.Sprintf("%s %s", it.op.ID, r.res.Ops[it.idx].Outcome))
		}
	}
	_ = r.record(Event{Kind: EventOp, ID: id + ":result", Payload: hbacResultEvent{Phase: "result", Stage: s.String(), Batch: batch, Results: results, Stopped: r.res.Stop, Lockdown: lockdown}})
}

func (r *hbacRunner) sendBatch(s HBACStage, items []hbacPending) {
	r.batches[s]++
	n := r.batches[s]
	id := fmt.Sprintf("hbac:%s-b%d", s, n)
	if !r.beforeSending(s, n, id, items) {
		return
	}
	cmds := make([]freeiparpc.Command, len(items))
	for i, it := range items {
		cmds[i] = it.cmd
	}
	got, err := r.rpc.Batch(r.ctx, cmds)
	switch {
	case err != nil && refusedBeforeSending(err):
		// The client's own gate or allowlist refused it: not sent, so not executed.
		r.stopAt(s, "the client refused to send: "+err.Error())
		r.afterSending(s, n, id, items, nil)
		return
	case err != nil:
		r.sent = true
		for _, it := range items {
			r.settle(it.idx, classifyHBACError(it.op, err))
		}
	default:
		r.sent = true
		for i, it := range items {
			var itemErr error
			if got[i].Err != nil {
				itemErr = got[i].Err
			}
			r.settle(it.idx, classifyHBAC(it.op, got[i].Result, itemErr))
		}
	}
	r.afterSending(s, n, id, items, nil)
}

// readRules is the check read of a destructive stage: the rules as they are now, by
// lower-case name.
func (r *hbacRunner) readRules() (map[string]LiveHBACRule, error) {
	raw, err := r.rpc.Find(r.ctx, "hbacrule_find", nil, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	rules, err := ParseHBACRules(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]LiveHBACRule, len(rules))
	for _, rule := range rules {
		out[lower(rule.Name)] = rule
	}
	return out, nil
}

// desiredRule is the roster's rule by lower-case name.
func (r *hbacRunner) desiredRule(name string) (DesiredHBACRule, bool) {
	for _, d := range r.opts.Desired.Rules {
		if lower(d.Name) == name {
			return d, true
		}
	}
	return DesiredHBACRule{}, false
}

// liveAndWant is the members of the rule's kind as the re-read shows them, and the ones
// the roster wants for it.
func (r *hbacRunner) liveAndWant(kind string, live LiveHBACRule, want DesiredHBACRule) (liveNames, wantNames []string) {
	completed := func(names []string) []string {
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = appendUnique(out, completeHost(n, r.obs2.Domain))
		}
		return out
	}
	switch kind {
	case KindHBACHostRemove:
		return live.Hosts, completed(want.Hosts)
	case KindHBACHostgroupRemove:
		return live.Hostgroups, want.Hostgroups
	case KindHBACServiceRemove:
		return live.Services, want.Services
	case KindHBACUserRemove:
		return live.Users, want.Users
	case KindHBACGroupRemove:
		return live.Groups, want.Groups
	}
	return nil, nil
}

// H3: a removal is checked against the rule as the re-read shows it. The members the
// roster would remove from it now must all be in the plan's list: another one means the
// rule changed since the plan, and the removal is not sent. A member the plan lists that
// has already left is not removed again. The other rules' removals are sent, and the
// stages after this one are not.
func (r *hbacRunner) runRemovals(idxs []int) {
	rules, readErr := r.readRules()
	var items []hbacPending
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		live, present := rules[lower(op.Object)]
		want, declared := r.desiredRule(lower(op.Object))
		switch {
		case readErr != nil:
			r.conflict(i, "the rules could not be read before members were removed: "+readErr.Error())
		case !present:
			r.conflict(i, "the rule is not there any more")
		case !declared:
			r.conflict(i, "the rule is no longer declared in the roster")
		default:
			liveNames, wantNames := r.liveAndWant(op.Kind, live, want)
			if extra := difference(difference(liveNames, wantNames), op.Members); len(extra) > 0 {
				r.conflict(i, "the rule has members the roster would remove that the plan did not list: "+strings.Join(extra, ", "))
				conflicted = true
				continue
			}
			still := intersect(op.Members, liveNames)
			if len(still) == 0 {
				r.settle(i, classified{Outcome: OutcomeNoop, Detail: "every member to remove has already left the rule"})
				continue
			}
			sent := op
			sent.Members = still
			cmd, err := hbacCommandFor(sent)
			if err != nil {
				r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
				r.stopAt(H3, op.ID+": "+err.Error())
				return
			}
			items = append(items, hbacPending{idx: i, op: sent, cmd: cmd})
			continue
		}
		conflicted = true
	}
	r.sendBatches(H3, items)
	if conflicted && !r.stopped {
		r.stopAt(H3, "a removal's precondition no longer holds")
	}
}

// sameRule says why the rule the re-read shows is not the one Plan₂ observed ("" when it
// is). A rule this run created has no earlier observation and need only exist.
func (r *hbacRunner) sameRule(name string, live LiveHBACRule) string {
	if r.created[name] {
		return ""
	}
	for _, o := range r.obs2.Rules {
		if lower(o.Name) != name {
			continue
		}
		if o.UniqueID != "" && live.UniqueID != "" && o.UniqueID != live.UniqueID {
			return "the rule is not the one the plan was made from (it was deleted and created again)"
		}
		return ""
	}
	return ""
}

// H6: enabling widens access and has no check of its own; disabling narrows it, so it is
// checked first: the rule must still be the one the plan observed, and one that is already
// disabled needs nothing and is not a conflict.
func (r *hbacRunner) runEnableDisable(idxs []int) {
	var rules map[string]LiveHBACRule
	var readErr error
	for _, i := range idxs {
		if r.res.Ops[i].Operation.Kind == KindHBACRuleDisable {
			rules, readErr = r.readRules()
			break
		}
	}
	var items []hbacPending
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		if op.Kind == KindHBACRuleDisable {
			live, present := rules[lower(op.Object)]
			switch {
			case readErr != nil:
				r.conflict(i, "the rules could not be read before a rule was disabled: "+readErr.Error())
				conflicted = true
				continue
			case !present:
				r.conflict(i, "the rule is not there any more")
				conflicted = true
				continue
			case !live.Enabled:
				r.settle(i, classified{Outcome: OutcomeNoop, Detail: "the rule is already disabled"})
				continue
			}
			if why := r.sameRule(lower(op.Object), live); why != "" {
				r.conflict(i, why)
				conflicted = true
				continue
			}
		}
		cmd, err := hbacCommandFor(op)
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
			r.stopAt(H6, op.ID+": "+err.Error())
			return
		}
		items = append(items, hbacPending{idx: i, op: op, cmd: cmd})
	}
	r.sendBatches(H6, items)
	if conflicted && !r.stopped {
		r.stopAt(H6, "a disable's precondition no longer holds")
	}
}

// H7: a delete is checked against the rule as the re-read shows it: one that is already
// gone is done, one that is not the rule the plan observed, or that the roster no longer
// marks absent, is not deleted, and allow_all is never deleted.
func (r *hbacRunner) runDeletes(idxs []int) {
	rules, readErr := r.readRules()
	absent := map[string]bool{}
	for _, n := range r.opts.Desired.AbsentRules {
		absent[lower(n)] = true
	}
	var items []hbacPending
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		key := lower(op.Object)
		live, present := rules[key]
		switch {
		case readErr != nil:
			r.conflict(i, "the rules could not be read before a rule was deleted: "+readErr.Error())
		case key == hbacRuleNameAllowAll:
			r.conflict(i, "allow_all is a FreeIPA built-in rule and is never deleted")
		case !absent[key]:
			r.conflict(i, "the rule is no longer marked absent in the roster")
		case !present:
			r.settle(i, classified{Outcome: OutcomeNoop, Detail: "the rule is already gone"})
			continue
		default:
			if why := r.sameRule(key, live); why != "" {
				r.conflict(i, why)
				break
			}
			cmd, err := hbacCommandFor(op)
			if err != nil {
				r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
				r.stopAt(H7, op.ID+": "+err.Error())
				return
			}
			items = append(items, hbacPending{idx: i, op: op, cmd: cmd})
			continue
		}
		conflicted = true
	}
	r.sendBatches(H7, items)
	if conflicted && !r.stopped {
		r.stopAt(H7, "a delete's precondition no longer holds")
	}
}
