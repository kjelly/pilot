package identityreconcile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The stages (spec §7.3): each runs its operations in batches of at most the batch
// limit, after the checks of its own that the spec asks for. A check reads the
// objects again just before the step it guards (a batch of user_show or
// group_show with all: true, captured, K19) and decides from what it reads, not
// from the observation the plan was made from: the entry's playbook ran between
// that read and this one, and so may anyone else.

func (r *runner) runStages() {
	r.indexDesired()
	for _, s := range Stages {
		if r.stopped {
			return
		}
		idxs := r.stageOps(s)
		if len(idxs) == 0 {
			continue
		}
		switch s {
		case S4:
			r.runPasswords(idxs)
		case S5:
			r.runRemovals(idxs)
		case S7:
			r.runEnableDisable(idxs)
		case S8:
			r.runDeletes(idxs)
		default:
			// S1, S2, S3, S6: the server's answer to each command is the check
			// (an add of what exists is DuplicateEntry, a mod of what is gone is
			// NotFound): they are idempotent or only widen, and the read of the
			// entry's aftermath was just made (spec §7.3, the deliberate relaxation).
			r.sendBatches(s, r.plainItems(idxs))
		}
	}
}

func (r *runner) stageOps(s Stage) []int {
	var out []int
	for i, o := range r.res.Ops {
		if StageOf(o.Operation.Kind) == s {
			out = append(out, i)
		}
	}
	return out
}

// desired objects by lower-case name, and the names a deleted group's marker is
// derived from as the roster wrote them (the marker hashes the name as written).
type desiredIndex struct {
	users   map[string]DesiredUser
	groups  map[string]DesiredGroup
	absentG map[string]string
}

func (r *runner) indexDesired() {
	r.dx = desiredIndex{users: map[string]DesiredUser{}, groups: map[string]DesiredGroup{}, absentG: map[string]string{}}
	for _, u := range r.des.Users {
		r.dx.users[strings.ToLower(u.Name)] = u
	}
	for _, g := range r.des.Groups {
		r.dx.groups[strings.ToLower(g.Name)] = g
	}
	for _, n := range r.des.AbsentGroups {
		r.dx.absentG[strings.ToLower(n)] = n
	}
}

// pending is a command ready to go with the operation it is for.
type pending struct {
	idx int
	op  Operation // as sent: a member command's list may be shorter than planned
	cmd freeiparpc.Command
}

func (r *runner) plainItems(idxs []int) []pending {
	var out []pending
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		cmd, err := commandFor(op, "")
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
			r.stopAt(StageOf(op.Kind), op.ID+": "+err.Error())
			return out
		}
		out = append(out, pending{idx: i, op: op, cmd: cmd})
	}
	return out
}

// sendBatches sends items in batches of at most the batch limit, in order, and
// stops after the batch in which an operation failed, conflicted or was unknown:
// the batch that was sent has its every answer recorded, what follows is not sent.
func (r *runner) sendBatches(s Stage, items []pending) {
	for len(items) > 0 && !r.stopped {
		n := min(r.opts.BatchLimit, len(items))
		r.sendBatch(s, items[:n])
		items = items[n:]
	}
}

// sendEvent is the payload of the event before a batch or call is sent.
type sendEvent struct {
	Phase      string      `json:"phase"`
	Stage      string      `json:"stage"`
	Batch      int         `json:"batch"`
	Operations []Operation `json:"operations"`
}

// resultEvent is the payload of the event after it.
type resultEvent struct {
	Phase   string     `json:"phase"`
	Stage   string     `json:"stage"`
	Batch   int        `json:"batch"`
	Results []OpResult `json:"results"`
	Stopped *Stop      `json:"stopped,omitempty"`
}

// refusedBeforeSending reports whether err says the command never left because the
// client or its gate refused it.
func refusedBeforeSending(err error) bool {
	var gate *freeiparpc.ErrWriteRefused
	var na *freeiparpc.ErrMethodNotAllowed
	return errors.As(err, &gate) || errors.As(err, &na)
}

// beforeSending runs what must hold before a batch or a call leaves: the record of
// it in the journal (without which nothing is sent: fail closed, AGENTS.md §5.8),
// and the engine's own gate for each command, besides the one in the client.
func (r *runner) beforeSending(s Stage, batch int, id string, items []pending) bool {
	ops := make([]Operation, len(items))
	for i, it := range items {
		ops[i] = it.op
	}
	if err := r.record(Event{Kind: EventOp, ID: id + ":sending", Payload: sendEvent{Phase: "sending", Stage: s.String(), Batch: batch, Operations: ops}}); err != nil {
		r.stopAt(s, "the journal refused the record of the batch, so it was not sent: "+err.Error())
		return false
	}
	for _, it := range items {
		if err := r.opts.Gate.Check(r.ctx, it.cmd.Method); err != nil {
			r.stopAt(s, "the write gate refused: "+err.Error())
			return false
		}
	}
	return true
}

// afterSending records what became of the items and stops the scheduling when one
// of them ends it.
func (r *runner) afterSending(s Stage, batch int, id string, items []pending) {
	results := make([]OpResult, len(items))
	for i, it := range items {
		results[i] = r.res.Ops[it.idx]
		if r.res.Ops[it.idx].Outcome.stops() && r.res.Stop == nil {
			r.stopAt(s, fmt.Sprintf("%s %s", it.op.ID, r.res.Ops[it.idx].Outcome))
		}
	}
	_ = r.record(Event{Kind: EventOp, ID: id + ":result", Payload: resultEvent{Phase: "result", Stage: s.String(), Batch: batch, Results: results, Stopped: r.res.Stop}})
}

func (r *runner) sendBatch(s Stage, items []pending) {
	r.batches[s]++
	n := r.batches[s]
	id := fmt.Sprintf("%s-b%d", s, n)
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
		r.stopAt(s, "the client refused to send: "+err.Error())
		return
	case err != nil:
		r.sent = true
		for _, it := range items {
			r.settle(it.idx, classifyError(it.op, err))
		}
	default:
		r.sent = true
		for i, it := range items {
			var itemErr error
			if got[i].Err != nil {
				itemErr = got[i].Err
			}
			r.settle(it.idx, classify(it.op, got[i].Result, itemErr))
		}
	}
	r.afterSending(s, n, id, items)
}

// sendOne sends one command on its own (a password: one user per call, never in a
// batch, never sent again, spec §7.3 S4).
func (r *runner) sendOne(s Stage, it pending) {
	r.batches[s]++
	n := r.batches[s]
	id := fmt.Sprintf("%s-c%d", s, n)
	items := []pending{it}
	if !r.beforeSending(s, n, id, items) {
		return
	}
	raw, err := r.rpc.Call(r.ctx, it.cmd)
	if err != nil && refusedBeforeSending(err) {
		r.stopAt(s, "the client refused to send: "+err.Error())
		return
	}
	r.sent = true
	r.settle(it.idx, classify(it.op, raw, err))
	r.afterSending(s, n, id, items)
}

// shown is what a re-read found of one object.
type shown struct {
	user    LiveUser
	group   LiveGroup
	present bool
	err     error
}

// showAll reads the named objects with show commands, in batches, as the entry's
// aftermath and the other writers leave them. A name the server does not know is
// not present; a read that failed is an error the check treats as a failed
// precondition.
func (r *runner) showAll(method string, names []string) map[string]shown {
	out := map[string]shown{}
	names = uniqueSorted(names)
	for len(names) > 0 {
		n := min(r.opts.BatchLimit, len(names))
		chunk := names[:n]
		names = names[n:]
		cmds := make([]freeiparpc.Command, len(chunk))
		for i, name := range chunk {
			cmds[i] = freeiparpc.Command{Method: method, Args: []any{name}, Options: map[string]any{"all": true}}
		}
		items, err := r.rpc.Batch(r.ctx, cmds)
		if err != nil {
			for _, name := range chunk {
				out[name] = shown{err: err}
			}
			continue
		}
		for i, name := range chunk {
			out[name] = readShown(method, items[i])
		}
	}
	return out
}

func readShown(method string, item freeiparpc.BatchItem) shown {
	if item.Err != nil {
		if item.Err.Name == "NotFound" {
			return shown{}
		}
		return shown{err: item.Err}
	}
	entry, err := showEntry(item.Result)
	if err != nil {
		return shown{err: err}
	}
	if method == "user_show" {
		u, err := parseUser(entry)
		return shown{user: u, present: err == nil, err: err}
	}
	g, err := parseGroup(entry)
	return shown{group: g, present: err == nil, err: err}
}

func (r *runner) showUsers(names []string) map[string]shown  { return r.showAll("user_show", names) }
func (r *runner) showGroups(names []string) map[string]shown { return r.showAll("group_show", names) }

func objectsOf(r *runner, idxs []int) []string {
	var out []string
	for _, i := range idxs {
		out = append(out, r.res.Ops[i].Operation.Object)
	}
	return out
}

// S4: a password is checked against the user as the re-read shows it, by the rule
// the plan uses (passwordAction: one rule for both), and each user is sent on its
// own. A user for whom the rule no longer chooses the planned action is not sent
// and stops the stages after this one; the users for whom it still does are sent.
func (r *runner) runPasswords(idxs []int) {
	show := r.showUsers(objectsOf(r, idxs))
	var todo []int
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		sh := show[op.Object]
		u, declared := r.dx.users[op.Object]
		switch {
		case sh.err != nil:
			r.conflict(i, "the user could not be read before its password was set: "+sh.err.Error())
		case !sh.present:
			r.conflict(i, "the user is not there any more")
		case !declared:
			r.conflict(i, "the user is no longer declared")
		case passwordAction(u, sh.user, true) != op.Kind:
			r.conflict(i, fmt.Sprintf("the user's state no longer calls for %s: someone set a password, or the user left the reset password, since the plan was made", op.Kind))
		default:
			todo = append(todo, i)
			continue
		}
		conflicted = true
	}
	for _, i := range todo {
		if r.stopped {
			break
		}
		op := r.res.Ops[i].Operation
		var pw string
		var err error
		if r.opts.Passwords == nil {
			err = errors.New("no password source")
		} else {
			pw, err = r.opts.Passwords.InitialPassword(op.Object)
		}
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "no password", Detail: err.Error()})
			r.stopAt(S4, op.ID+": the password cannot be read")
			break
		}
		cmd, err := commandFor(op, pw)
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
			r.stopAt(S4, op.ID+": "+err.Error())
			break
		}
		r.sendOne(S4, pending{idx: i, op: op, cmd: cmd})
	}
	if conflicted && !r.stopped {
		r.stopAt(S4, "a password's precondition no longer holds")
	}
}

// S5: a removal is checked against the group as the re-read shows it. The members
// the roster's declaration would have removed from it now must all be in the plan's
// list: another one means the group changed since the plan, and the removal is not
// sent. A member the plan lists that has already left is not removed again. The
// other groups' removals are sent, and the stages after this one are not.
func (r *runner) runRemovals(idxs []int) {
	show := r.showGroups(objectsOf(r, idxs))
	var items []pending
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		sh := show[op.Object]
		dg, declared := r.dx.groups[op.Object]
		users := op.Kind == KindMemberUserRemove
		switch {
		case sh.err != nil:
			r.conflict(i, "the group could not be read before its members were removed: "+sh.err.Error())
		case !sh.present:
			r.conflict(i, "the group is not there any more")
		case !declared || !dg.Authoritative:
			r.conflict(i, "the group is no longer declared with an authoritative membership")
		default:
			live, want := sh.group.MemberGroups, dg.Groups
			if users {
				live, want = sh.group.MemberUsers, dg.Users
			}
			if extra := difference(difference(live, want), op.Members); len(extra) > 0 {
				r.conflict(i, "the group has members the roster would remove that the plan did not list: "+strings.Join(extra, ", "))
				conflicted = true
				continue
			}
			still := intersect(op.Members, live)
			if len(still) == 0 {
				r.settle(i, classified{Outcome: OutcomeNoop, Detail: "every member to remove has already left the group"})
				continue
			}
			sent := op
			sent.Members = still
			cmd, err := commandFor(sent, "")
			if err != nil {
				r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
				r.stopAt(S5, op.ID+": "+err.Error())
				return
			}
			items = append(items, pending{idx: i, op: sent, cmd: cmd})
			continue
		}
		conflicted = true
	}
	r.sendBatches(S5, items)
	if conflicted && !r.stopped {
		r.stopAt(S5, "a removal's precondition no longer holds")
	}
}

// S7: enabling widens access and has no check of its own; disabling narrows it, so
// it is checked first (spec §7.3): the user must still be the one the plan
// observed (the same ipauniqueid; a user this run created has no earlier
// observation and need only exist) and not the login. A user who is already
// disabled needs nothing and is not a conflict.
func (r *runner) runEnableDisable(idxs []int) {
	var disable []int
	for _, i := range idxs {
		if r.res.Ops[i].Operation.Kind == KindUserDisable {
			disable = append(disable, i)
		}
	}
	var show map[string]shown
	if len(disable) > 0 {
		show = r.showUsers(objectsOf(r, disable))
	}
	var items []pending
	conflicted := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		if op.Kind == KindUserDisable {
			switch verdict, why := r.disableVerdict(op, show[op.Object]); verdict {
			case verdictConflict:
				r.conflict(i, why)
				conflicted = true
				continue
			case verdictNoop:
				r.settle(i, classified{Outcome: OutcomeNoop, Detail: why})
				continue
			}
		}
		cmd, err := commandFor(op, "")
		if err != nil {
			r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
			r.stopAt(S7, op.ID+": "+err.Error())
			return
		}
		items = append(items, pending{idx: i, op: op, cmd: cmd})
	}
	r.sendBatches(S7, items)
	if conflicted && !r.stopped {
		r.stopAt(S7, "a disable's precondition no longer holds")
	}
}

type verdict int

const (
	verdictOK verdict = iota
	verdictNoop
	verdictConflict
)

func (r *runner) disableVerdict(op Operation, sh shown) (verdict, string) {
	switch {
	case sh.err != nil:
		return verdictConflict, "the user could not be read before it was disabled: " + sh.err.Error()
	case !sh.present:
		return verdictConflict, "the user is not there any more"
	case op.Object == r.principal():
		return verdictConflict, "the user is the login the engine is using"
	}
	if !r.created[op.Object] {
		if why := r.sameUser(op.Object, sh.user); why != "" {
			return verdictConflict, why
		}
	}
	if sh.user.Locked {
		return verdictNoop, "the user is already disabled"
	}
	return verdictOK, ""
}

// sameUser is "" when the user the re-read shows is the one the plan observed (the
// same ipauniqueid, which a user deleted and added again does not keep), and why
// not otherwise. An observation without an ipauniqueid cannot show it, so it does
// not pass.
func (r *runner) sameUser(name string, now LiveUser) string {
	was, ok := r.users2[name]
	switch {
	case !ok:
		return "the user was not in the observation the plan was made from"
	case was.UniqueID == "" || now.UniqueID == "":
		return "the user has no ipauniqueid to tell it from one deleted and added again"
	case was.UniqueID != now.UniqueID:
		return "the user was deleted and added again since the plan was made (another ipauniqueid)"
	}
	return ""
}

// S8: users are deleted first, then groups, each after the read that checks them.
func (r *runner) runDeletes(idxs []int) {
	var users, groups []int
	for _, i := range idxs {
		if r.res.Ops[i].Operation.Kind == KindUserDelete {
			users = append(users, i)
		} else {
			groups = append(groups, i)
		}
	}
	if len(users) > 0 && !r.deleteUsers(users) {
		return
	}
	if len(groups) > 0 {
		r.deleteGroups(groups)
	}
}

// deleteUsers checks every user before any is deleted: the user must exist (one that
// does not is nothing to do), be the user the plan observed (ipauniqueid and
// uidnumber), not be preserved and not be the login. Any user that fails stops the
// whole stage: the others in the same batch are not deleted either, and no group is.
// It reports whether the deletes were sent.
func (r *runner) deleteUsers(idxs []int) bool {
	show := r.showUsers(objectsOf(r, idxs))
	var items []pending
	var noops []int
	failed := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		sh := show[op.Object]
		switch {
		case sh.err != nil:
			r.conflict(i, "the user could not be read before it was deleted: "+sh.err.Error())
			failed = true
		case !sh.present:
			noops = append(noops, i)
		case sh.user.Preserved:
			r.conflict(i, "the user is preserved")
			failed = true
		case op.Object == r.principal():
			r.conflict(i, "the user is the login the engine is using")
			failed = true
		default:
			if why := r.sameUser(op.Object, sh.user); why != "" {
				r.conflict(i, why)
				failed = true
			} else if was := r.users2[op.Object]; was.UIDNumber == "" || was.UIDNumber != sh.user.UIDNumber {
				r.conflict(i, "the user's uidnumber is not the one the plan observed")
				failed = true
			} else if cmd, err := commandFor(op, ""); err != nil {
				r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
				failed = true
			} else {
				items = append(items, pending{idx: i, op: op, cmd: cmd})
			}
		}
	}
	if failed {
		r.stopAt(S8, "a user's precondition no longer holds: no user and no group was deleted")
		return false
	}
	for _, i := range noops {
		r.settle(i, classified{Outcome: OutcomeNoop, Detail: "the user is not there"})
	}
	r.sendBatches(S8, items)
	return !r.stopped
}

// deleteGroups checks every group, and its history marker, before any is deleted:
// the group must exist (one that does not is nothing to do), be the group the plan
// observed (ipauniqueid and gidnumber), and its marker must exist with the
// description that proves the group was applied before. Any group that fails stops
// the deletes: none is sent.
func (r *runner) deleteGroups(idxs []int) {
	names := objectsOf(r, idxs)
	markerOf := map[string]string{}
	for _, name := range names {
		written := r.dx.absentG[name]
		if written == "" {
			written = name
		}
		markerOf[name] = HistoryMarkerName(written)
	}
	var markers []string
	for _, m := range markerOf {
		markers = append(markers, m)
	}
	show := r.showGroups(append(append([]string{}, names...), markers...))
	var items []pending
	var noops []int
	failed := false
	for _, i := range idxs {
		op := r.res.Ops[i].Operation
		sh := show[op.Object]
		mk := show[markerOf[op.Object]]
		written := r.dx.absentG[op.Object]
		if written == "" {
			written = op.Object
		}
		switch {
		case sh.err != nil:
			r.conflict(i, "the group could not be read before it was deleted: "+sh.err.Error())
			failed = true
		case !sh.present:
			noops = append(noops, i)
		case !r.sameGroup(op.Object, sh.group):
			r.conflict(i, "the group is not the one the plan observed (ipauniqueid or gidnumber differ, or the observation has none)")
			failed = true
		case mk.err != nil:
			r.conflict(i, "the group's history marker could not be read: "+mk.err.Error())
			failed = true
		case !mk.present || !containsString(mk.group.Description, HistoryMarkerDescription(written)):
			r.conflict(i, "the group's history marker is missing or does not carry the description that proves the group was applied")
			failed = true
		default:
			cmd, err := commandFor(op, "")
			if err != nil {
				r.settle(i, classified{Outcome: OutcomeFailed, Error: "not sent", Detail: err.Error()})
				failed = true
				continue
			}
			items = append(items, pending{idx: i, op: op, cmd: cmd})
		}
	}
	if failed {
		r.stopAt(S8, "a group's precondition no longer holds: no group was deleted")
		return
	}
	for _, i := range noops {
		r.settle(i, classified{Outcome: OutcomeNoop, Detail: "the group is not there"})
	}
	r.sendBatches(S8, items)
}

func (r *runner) sameGroup(name string, now LiveGroup) bool {
	was, ok := r.groups2[name]
	return ok && was.UniqueID != "" && was.UniqueID == now.UniqueID && was.GIDNumber == now.GIDNumber
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// intersect is the members of a that are in b, in a's order.
func intersect(a, b []string) []string {
	in := lowerSet(b)
	var out []string
	for _, v := range a {
		if in[v] {
			out = append(out, v)
		}
	}
	return out
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	for _, s := range in {
		seen[s] = true
	}
	return sortedKeys(seen)
}
