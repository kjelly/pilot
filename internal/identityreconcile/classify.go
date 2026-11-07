package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// What became of one operation (spec §7.4, D19).
type Outcome string

const (
	// OutcomeSuccess: applied.
	OutcomeSuccess Outcome = "success"
	// OutcomeNoop: nothing needed doing: the server said the state was already
	// what the operation asks for (EmptyModlist, AlreadyActive, AlreadyInactive, a
	// delete of what is not there, a member already in or already out).
	OutcomeNoop Outcome = "noop"
	// OutcomeConflictFailed: a precondition the plan rested on no longer holds
	// (an add of what exists, a mod, enable, disable or member command on what is
	// gone), or a re-read before a destructive step found it does not. Nothing was
	// applied.
	OutcomeConflictFailed Outcome = "conflict-failed"
	// OutcomeFailed: the server refused it. Nothing was applied.
	OutcomeFailed Outcome = "failed"
	// OutcomeUnknown: the command left and no answer says what it did; it may have
	// been applied. It is never sent again; the read after the writes classifies it.
	OutcomeUnknown Outcome = "unknown"
	// OutcomeNotExecuted: not sent, because an earlier operation failed, conflicted
	// or was unknown, or the write gate refused (§7.4: the plan's unexecuted items).
	OutcomeNotExecuted Outcome = "not_executed"
)

// classified is the outcome of one command and what it says.
type classified struct {
	Outcome   Outcome
	Completed int    // members a member command changed
	Error     string // FreeIPA's error name and code, "" when there was none
	Detail    string
}

// FreeIPA's reasons for a member it did not change (captured, K12, K13).
const (
	reasonAlreadyMember = "This entry is already a member"
	reasonNotMember     = "This entry is not a member"
	reasonNoSuchEntry   = "no such entry"
)

func isMemberKind(kind string) (adding, ok bool) {
	switch kind {
	case KindMemberUserAdd, KindMemberGroupAdd:
		return true, true
	case KindMemberUserRemove, KindMemberGroupRemove:
		return false, true
	}
	return false, false
}

func isPasswordKind(kind string) bool {
	return kind == KindPasswordInitialize || kind == KindPasswordReset
}

// classify decides what became of op from the answer to its command: raw is the
// result object of a success (Call's, or a batch item's), err what Call or the
// batch item returned. The rules are those of the table in spec §7.4, with the
// forms the P2-4 captures show: passwd for a user that is gone is EmptyResult, not
// NotFound; removing a member that is not there, or that does not exist, is "not a
// member"; a member command that changed nothing is still a success to FreeIPA.
func classify(op Operation, raw json.RawMessage, err error) classified {
	if err != nil {
		return classifyError(op, err)
	}
	if adding, isMember := isMemberKind(op.Kind); isMember {
		return classifyMembers(op, adding, raw)
	}
	switch op.Kind {
	case KindPasswordInitialize, KindPasswordReset, KindUserEnable, KindUserDisable:
		// result: true (captured, K6 and the enable and disable answers). Anything
		// else is an answer that does not say it happened.
		var r struct {
			Result any `json:"result"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Result != true {
			return classified{Outcome: OutcomeUnknown, Detail: "the answer does not say the command succeeded"}
		}
	case KindUserDelete, KindGroupDelete:
		// result: {failed: []} (captured, K7, K8): a name in failed was not deleted.
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

func classifyError(op Operation, err error) classified {
	var unknown *freeiparpc.OutcomeUnknownError
	if errors.As(err, &unknown) {
		return classified{Outcome: OutcomeUnknown, Error: "outcome unknown", Detail: errorText(op, err)}
	}
	var rpc *freeiparpc.RPCError
	if !errors.As(err, &rpc) {
		// Not an answer of the server and not a write that may have left: the
		// command did not reach it (the tunnel, the session, a refusal before it
		// was sent). It was not applied.
		return classified{Outcome: OutcomeFailed, Error: "not sent", Detail: errorText(op, err)}
	}
	out := classified{Error: fmt.Sprintf("%s (%d)", rpc.Name, rpc.Code), Detail: rpc.Message}
	if isPasswordKind(op.Kind) {
		out.Detail = "" // the name and code say what it was; nothing near a password is kept
	}
	switch {
	case rpc.Name == "EmptyModlist" && (op.Kind == KindUserUpdate || op.Kind == KindGroupUpdate):
		out.Outcome = OutcomeNoop
	case rpc.Name == "AlreadyActive" && op.Kind == KindUserEnable:
		out.Outcome = OutcomeNoop
	case rpc.Name == "AlreadyInactive" && op.Kind == KindUserDisable:
		out.Outcome = OutcomeNoop
	case rpc.Name == "NotFound" && (op.Kind == KindUserDelete || op.Kind == KindGroupDelete):
		out.Outcome = OutcomeNoop
	case rpc.Name == "DuplicateEntry" && (op.Kind == KindGroupCreate || op.Kind == KindMarkerCreate || op.Kind == KindUserCreate):
		out.Outcome = OutcomeConflictFailed
	case rpc.Name == "NotFound" && notFoundIsAConflict(op.Kind):
		out.Outcome = OutcomeConflictFailed
	case rpc.Name == "EmptyResult" && isPasswordKind(op.Kind):
		// passwd for a user that is gone (captured, K6): the same "the user is not
		// there any more" as NotFound is for the other commands.
		out.Outcome = OutcomeConflictFailed
	default:
		out.Outcome = OutcomeFailed
	}
	return out
}

// notFoundIsAConflict: a mod, enable, disable, password or member command whose
// target is gone is a precondition that no longer holds; for a delete the same
// answer is the delete's goal, and for an add it cannot be a NotFound at all.
func notFoundIsAConflict(kind string) bool {
	if _, isMember := isMemberKind(kind); isMember {
		return true
	}
	switch kind {
	case KindUserUpdate, KindGroupUpdate, KindUserEnable, KindUserDisable, KindPasswordInitialize, KindPasswordReset:
		return true
	}
	return false
}

// errorText is the text of a transport-level error, never holding what a password
// command was sent: those are reduced to their Go type.
func errorText(op Operation, err error) string {
	if isPasswordKind(op.Kind) {
		root := err
		for u := errors.Unwrap(root); u != nil; u = errors.Unwrap(root) {
			root = u
		}
		return fmt.Sprintf("%T", root)
	}
	return err.Error()
}

// classifyMembers reads a group_add_member or group_remove_member answer, which
// FreeIPA gives as a success even when no member changed: every requested member
// is in completed or in failed.member with its reason, and each reason is read for
// what it is. An answer that does not account for every member is unknown: the
// command may have changed some.
func classifyMembers(op Operation, adding bool, raw json.RawMessage) classified {
	mr, err := freeiparpc.DecodeMemberResult(raw, len(op.Members))
	if err != nil {
		return classified{Outcome: OutcomeUnknown, Detail: "the answer does not account for every member: " + err.Error()}
	}
	out := classified{Completed: mr.Completed}
	var problems []string
	failed, conflicted := false, false
	for _, f := range mr.Failed {
		switch {
		case adding && f.Reason == reasonAlreadyMember, !adding && f.Reason == reasonNotMember:
			// nothing to do for this member
		case f.Reason == reasonNoSuchEntry:
			conflicted = true
			problems = append(problems, fmt.Sprintf("%s %s: %s", f.Type, f.Name, f.Reason))
		default:
			failed = true
			problems = append(problems, fmt.Sprintf("%s %s: %s", f.Type, f.Name, f.Reason))
		}
	}
	out.Detail = strings.Join(problems, "; ")
	switch {
	case failed:
		out.Outcome = OutcomeFailed
	case conflicted:
		out.Outcome = OutcomeConflictFailed
	case mr.Completed > 0:
		out.Outcome = OutcomeSuccess
	default:
		out.Outcome = OutcomeNoop
	}
	return out
}

// stops reports whether an outcome ends the scheduling of what follows (spec §7.4).
func (o Outcome) stops() bool {
	return o == OutcomeConflictFailed || o == OutcomeFailed || o == OutcomeUnknown
}
