package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// Every captured error answer read as every kind of operation, against a table written
// from the spec's §7.4 rules rather than from classify's own switch: a rule that is
// widened to a kind it does not name, or loses a kind it does, changes a cell.
func TestClassifyEveryCapturedErrorForEveryKind(t *testing.T) {
	mustReturn(returnDeadline, "classify", func() { classifyEveryCapturedErrorForEveryKind(t) })
}

func classifyEveryCapturedErrorForEveryKind(t *testing.T) {
	type cells struct {
		fixture string
		// outcomes of the kinds that are not the default
		special map[string]Outcome
		// the outcome of every other kind
		other Outcome
	}
	all := func(o Outcome, kinds ...string) map[string]Outcome {
		m := map[string]Outcome{}
		for _, k := range kinds {
			m[k] = o
		}
		return m
	}
	merge := func(ms ...map[string]Outcome) map[string]Outcome {
		out := map[string]Outcome{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	members := []string{KindMemberUserRemove, KindMemberGroupRemove, KindMemberUserAdd, KindMemberGroupAdd}
	passwords := []string{KindPasswordInitialize, KindPasswordReset}
	for _, c := range []cells{
		// NotFound: the goal of a delete, a precondition that no longer holds for what
		// mods, enables, disables, passwords and members touch, nothing an add can get.
		{"user-mod-not-found", merge(all(OutcomeNoop, KindUserDelete, KindGroupDelete),
			all(OutcomeConflictFailed, append(append([]string{KindUserUpdate, KindGroupUpdate, KindUserEnable, KindUserDisable}, passwords...), members...)...)), OutcomeFailed},
		// EmptyResult: a password for a user that is gone.
		{"passwd-not-found", all(OutcomeConflictFailed, passwords...), OutcomeFailed},
		{"user-enable-already-enabled", all(OutcomeNoop, KindUserEnable), OutcomeFailed},
		{"user-disable-already-disabled", all(OutcomeNoop, KindUserDisable), OutcomeFailed},
		{"user-mod-no-change", all(OutcomeNoop, KindUserUpdate, KindGroupUpdate), OutcomeFailed},
		{"group-add-duplicate", all(OutcomeConflictFailed, KindGroupCreate, KindMarkerCreate, KindUserCreate), OutcomeFailed},
		// An error that is nobody's rule is a failure for every kind, a delete included.
		{"user-mod-acierror", nil, OutcomeFailed},
	} {
		a := captured1(t, c.fixture)
		for _, kind := range Kinds {
			want := c.other
			if o, ok := c.special[kind]; ok {
				want = o
			}
			got := a.classify(op(kind, "x", "m"))
			if got.Outcome != want {
				t.Errorf("%s answered with %s: %s, want %s", kind, c.fixture, got.Outcome, want)
			}
			// What the server said is kept, except near a password.
			if isPasswordKind(kind) {
				if got.Detail != "" {
					t.Errorf("%s answered with %s keeps %q", kind, c.fixture, got.Detail)
				}
			} else if got.Detail == "" || got.Error == "" {
				t.Errorf("%s answered with %s: error %q detail %q, want both kept", kind, c.fixture, got.Error, got.Detail)
			}
		}
	}
}

// A success answer that does not say the command did its work is unknown, for each
// kind that has such an answer, and a delete that lists a failure is a failure for
// users and groups alike.
func TestClassifyASuccessThatDoesNotSayItSucceededForEachKind(t *testing.T) {
	for _, kind := range []string{KindPasswordInitialize, KindPasswordReset, KindUserEnable, KindUserDisable} {
		if got := classify(op(kind, "x"), json.RawMessage(`{"result":false}`), nil); got.Outcome != OutcomeUnknown {
			t.Errorf("%s with result false: %s", kind, got.Outcome)
		}
		if got := classify(op(kind, "x"), json.RawMessage(`not json`), nil); got.Outcome != OutcomeUnknown {
			t.Errorf("%s with an answer that is not JSON: %s", kind, got.Outcome)
		}
		if got := classify(op(kind, "x"), json.RawMessage(`{"result":true}`), nil); got.Outcome != OutcomeSuccess {
			t.Errorf("%s with result true: %s", kind, got.Outcome)
		}
	}
	for _, kind := range []string{KindUserDelete, KindGroupDelete} {
		if got := classify(op(kind, "x"), json.RawMessage(`{"result":{"failed":["x"]}}`), nil); got.Outcome != OutcomeFailed {
			t.Errorf("%s that lists a failure: %s", kind, got.Outcome)
		}
		if got := classify(op(kind, "x"), json.RawMessage(`{"result":{"failed":[]}}`), nil); got.Outcome != OutcomeSuccess {
			t.Errorf("%s that lists none: %s", kind, got.Outcome)
		}
	}
	// A kind that is not a member kind is not read as one, whatever its answer.
	if got := classify(op(KindUserCreate, "x"), json.RawMessage(`{"result":{}}`), nil); got.Outcome != OutcomeSuccess {
		t.Errorf("a user_add answer: %s", got.Outcome)
	}
	if adding, ok := isMemberKind(KindUserCreate); ok || adding && ok {
		t.Errorf("isMemberKind(user.create) = %v, %v", adding, ok)
	}
}

// Every stage says what its commands are in the messages that name a boundary.
func TestEveryStageNamesItsCommands(t *testing.T) {
	want := map[Stage]string{
		S1: "group_add", S2: "group_mod and the history markers' group_add", S3: "user_add and user_mod", S4: "passwd",
		S5: "group_remove_member", S6: "group_add_member", S7: "user_enable and user_disable", S8: "user_del and group_del",
	}
	if len(want) != len(Stages) {
		t.Fatalf("%d stages, %d descriptions", len(Stages), len(want))
	}
	for _, s := range Stages {
		if got := s.what(); got != want[s] {
			t.Errorf("%s.what() = %q, want %q", s, got, want[s])
		}
	}
	if Stage(0).what() != "?" {
		t.Errorf("a stage that is none: %q", Stage(0).what())
	}
}

// A reason that says a member is already in, or not in, a group is a noop only for the
// command it is the goal of: read as the other command's, it is a refusal. The answers
// are the captured ones, crossed.
func TestClassifyAMemberReasonByTheCommandItAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    string
		members []string
		fixture string
		want    Outcome
	}{
		{"an add that is already a member", KindMemberUserAdd, []string{"p0-alice"}, "group-add-member-already", OutcomeNoop},
		{"a remove that is not a member", KindMemberUserRemove, []string{"p0-bob"}, "group-remove-member-not-member", OutcomeNoop},
		{"a remove answered with 'already a member'", KindMemberUserRemove, []string{"p0-alice"}, "group-add-member-already", OutcomeFailed},
		{"an add answered with 'not a member'", KindMemberUserAdd, []string{"p0-bob"}, "group-remove-member-not-member", OutcomeFailed},
		{"a group remove answered with 'already a member'", KindMemberGroupRemove, []string{"p24cap-mg2"}, "group-add-member-group-already", OutcomeFailed},
		{"a group add answered with 'not a member'", KindMemberGroupAdd, []string{"p24cap-mg3"}, "group-remove-member-not-member", OutcomeFailed},
	} {
		got := captured1(t, tc.fixture).classify(op(tc.kind, "x", tc.members...))
		if got.Outcome != tc.want {
			t.Errorf("%s: %s (%q), want %s", tc.name, got.Outcome, got.Detail, tc.want)
		}
	}
}

// What an error that is not an answer of the server says of itself: its text, except
// for a password command, where it is reduced to the type of the innermost error.
func TestClassifyKeepsTheTextOfAnUnsentErrorExceptNearAPassword(t *testing.T) {
	mustReturn(returnDeadline, "classify", func() { classifyKeepsTheTextOfAnUnsentError(t) })
}

func classifyKeepsTheTextOfAnUnsentError(t *testing.T) {
	unsent := &freeiparpc.TransportError{Err: errors.New("dial tcp: no route"), Sent: false}
	if got := classify(op(KindUserCreate, "x"), nil, unsent); !strings.Contains(got.Detail, "no route") {
		t.Errorf("a user_add: %+v, want the text of the error", got)
	}
	unknown := &freeiparpc.OutcomeUnknownError{Method: "user_add", Err: errors.New("read: connection reset")}
	if got := classify(op(KindUserCreate, "x"), nil, unknown); !strings.Contains(got.Detail, "connection reset") {
		t.Errorf("an unknown user_add: %+v, want the text of the error", got)
	}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", errors.New(pwSecret)))
	got := classify(op(KindPasswordInitialize, "x"), nil, wrapped)
	if got.Detail != "*errors.errorString" || strings.Contains(got.Detail+got.Error, pwSecret) {
		t.Errorf("a password: detail %q, want the type of the innermost error", got.Detail)
	}
}
