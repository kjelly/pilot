package identityreconcile

import "fmt"

// Stage is one step of the write order (spec §7.3): the operations of a stage are
// independent of each other, and a later stage depends on an earlier one. The
// planner's self-lockout check walks the plan stage by stage, and the executor
// sends it stage by stage, from this one table (AGENTS.md §5.7: two walks of the
// same order must not each keep their own copy of it).
type Stage int

// The stages, in the order they run.
const (
	S1 Stage = iota + 1 // group_add
	S2                  // group_mod, and the history markers' group_add
	S3                  // user_add, user_mod
	S4                  // passwd: one user, one call
	S5                  // group_remove_member
	S6                  // group_add_member
	S7                  // user_enable, user_disable
	S8                  // user_del, then group_del
)

// Stages is every stage in order.
var Stages = []Stage{S1, S2, S3, S4, S5, S6, S7, S8}

func (s Stage) String() string { return fmt.Sprintf("S%d", int(s)) }

// what is the FreeIPA commands of the stage, for a message that names a boundary.
func (s Stage) what() string {
	switch s {
	case S1:
		return "group_add"
	case S2:
		return "group_mod and the history markers' group_add"
	case S3:
		return "user_add and user_mod"
	case S4:
		return "passwd"
	case S5:
		return "group_remove_member"
	case S6:
		return "group_add_member"
	case S7:
		return "user_enable and user_disable"
	case S8:
		return "user_del and group_del"
	}
	return "?"
}

// StageOf is the stage an operation kind runs in; 0 for a kind the engine does
// not know, which no stage runs.
func StageOf(kind string) Stage {
	switch kind {
	case KindGroupCreate:
		return S1
	case KindGroupUpdate, KindMarkerCreate:
		return S2
	case KindUserCreate, KindUserUpdate:
		return S3
	case KindPasswordInitialize, KindPasswordReset:
		return S4
	case KindMemberUserRemove, KindMemberGroupRemove:
		return S5
	case KindMemberUserAdd, KindMemberGroupAdd:
		return S6
	case KindUserEnable, KindUserDisable:
		return S7
	case KindUserDelete, KindGroupDelete:
		return S8
	}
	return 0
}

// operationsOf are the operations of plan that run in stage s, in plan order.
func operationsOf(plan Plan, s Stage) []Operation {
	var out []Operation
	for _, op := range plan.Operations {
		if StageOf(op.Kind) == s {
			out = append(out, op)
		}
	}
	return out
}

// destructiveKind reports whether an operation of this kind is in the set the
// executor re-reads before and compares between Plan₁ and Plan₂ (spec §7.3): what
// the plan itself marks destructive (a password reset, a delete) and the narrowing
// kinds (a member removed, a user disabled), which are access revoked, not data
// lost, but equally something an operator reviewing a plan must have seen.
func destructiveKind(kind string) bool {
	switch kind {
	case KindPasswordReset, KindUserDelete, KindGroupDelete,
		KindMemberUserRemove, KindMemberGroupRemove, KindUserDisable:
		return true
	}
	return false
}
