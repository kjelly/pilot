package identityreconcile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// The classification of what a write became (spec §7.4) against the answers P2-4
// captured from FreeIPA 4.13.4 (internal/freeiparpc/testdata): an error is the
// error object of the capture, a success the result object of it, and member
// answers carry the captured reasons. Each operation kind has rows that must come
// out as success or noop and rows that must not (AGENTS.md §5.12): a classifier
// that read every answer as success would pass the first and fail the second.

func op(kind, object string, members ...string) Operation {
	return Operation{ID: kind + ":" + object, Kind: kind, Object: object, Members: members}
}

// answer is one captured answer of a command: its error, or its result.
type answer struct {
	err *freeiparpc.RPCError
	raw json.RawMessage
}

func captured1(t *testing.T, name string) answer {
	t.Helper()
	if e := capturedRPCError(t, name); e != nil {
		return answer{err: e}
	}
	return answer{raw: fixtureResult(t, name)}
}

func (a answer) classify(o Operation) classified {
	var err error
	if a.err != nil {
		err = a.err
	}
	return classify(o, a.raw, err)
}

func TestClassifyAgainstTheCapturedAnswers(t *testing.T) {
	type row struct {
		kind      string
		members   []string
		fixture   string
		want      Outcome
		completed int
	}
	rows := []row{
		// S1, S2: group_add
		{KindGroupCreate, nil, "group-add", OutcomeSuccess, 0},
		{KindGroupCreate, nil, "group-add-duplicate", OutcomeConflictFailed, 0},
		{KindGroupCreate, nil, "group-add-duplicate-case", OutcomeConflictFailed, 0},
		{KindGroupCreate, nil, "group-add-duplicate-private-group", OutcomeConflictFailed, 0},
		{KindMarkerCreate, nil, "group-add-marker", OutcomeSuccess, 0},
		{KindMarkerCreate, nil, "group-add-marker-duplicate", OutcomeConflictFailed, 0},
		// S2: group_mod
		{KindGroupUpdate, nil, "group-mod-description", OutcomeSuccess, 0},
		{KindGroupUpdate, nil, "group-mod-no-change", OutcomeNoop, 0},
		{KindGroupUpdate, nil, "group-mod-not-found", OutcomeConflictFailed, 0},
		// S3: user_add, user_mod
		{KindUserCreate, nil, "user-add", OutcomeSuccess, 0},
		{KindUserCreate, nil, "user-add-duplicate", OutcomeConflictFailed, 0},
		{KindUserCreate, nil, "user-add-duplicate-preserved", OutcomeConflictFailed, 0},
		{KindUserCreate, nil, "user-add-empty-givenname", OutcomeFailed, 0},
		{KindUserCreate, nil, "user-add-empty-homedirectory", OutcomeFailed, 0},
		{KindUserCreate, nil, "user-add-unknown-option-first", OutcomeFailed, 0},
		{KindUserUpdate, nil, "user-mod", OutcomeSuccess, 0},
		{KindUserUpdate, nil, "user-mod-empty-loginshell", OutcomeSuccess, 0},
		{KindUserUpdate, nil, "user-mod-no-change", OutcomeNoop, 0},
		{KindUserUpdate, nil, "user-mod-mail-same", OutcomeNoop, 0},
		{KindUserUpdate, nil, "user-mod-not-found", OutcomeConflictFailed, 0},
		{KindUserUpdate, nil, "user-mod-acierror", OutcomeFailed, 0},
		{KindUserUpdate, nil, "user-mod-empty-sn", OutcomeFailed, 0},
		// S4: passwd
		{KindPasswordInitialize, nil, "passwd-success", OutcomeSuccess, 0},
		{KindPasswordReset, nil, "passwd-success-again", OutcomeSuccess, 0},
		{KindPasswordReset, nil, "passwd-not-found", OutcomeConflictFailed, 0},
		{KindPasswordInitialize, nil, "passwd-not-found", OutcomeConflictFailed, 0},
		{KindPasswordReset, nil, "passwd-reuse-rejected", OutcomeFailed, 0},
		{KindPasswordInitialize, nil, "passwd-empty-password", OutcomeFailed, 0},
		// S5: group_remove_member
		{KindMemberUserRemove, []string{"p24cap-m1", "p24cap-m2"}, "group-remove-member-users", OutcomeSuccess, 2},
		{KindMemberGroupRemove, []string{"p24cap-mg2"}, "group-remove-member-group", OutcomeSuccess, 1},
		{KindMemberUserRemove, []string{"p0-bob"}, "group-remove-member-not-member", OutcomeNoop, 0},
		{KindMemberUserRemove, []string{"p24cap-nobody"}, "group-remove-member-no-such-entry", OutcomeNoop, 0},
		{KindMemberGroupRemove, []string{"p24cap-nogroup"}, "group-remove-member-group-no-such-entry", OutcomeNoop, 0},
		{KindMemberGroupRemove, []string{"p24cap-mg3", "p24cap-mg2"}, "group-remove-member-group-mixed", OutcomeSuccess, 1},
		{KindMemberUserRemove, []string{"p24cap-m1"}, "group-remove-member-from-missing-group", OutcomeConflictFailed, 0},
		// S6: group_add_member
		{KindMemberUserAdd, []string{"p0-alice"}, "group-add-member", OutcomeSuccess, 1},
		{KindMemberGroupAdd, []string{"p24cap-mg2"}, "group-add-member-group", OutcomeSuccess, 1},
		{KindMemberUserAdd, []string{"p0-alice"}, "group-add-member-already", OutcomeNoop, 0},
		{KindMemberGroupAdd, []string{"p24cap-mg2"}, "group-add-member-group-already", OutcomeNoop, 0},
		{KindMemberUserAdd, []string{"p0-nobody"}, "group-add-member-missing-user", OutcomeConflictFailed, 0},
		{KindMemberGroupAdd, []string{"p24cap-nogroup"}, "group-add-member-group-missing", OutcomeConflictFailed, 0},
		{KindMemberGroupAdd, []string{"p24cap-mg1"}, "group-add-member-group-itself", OutcomeFailed, 0},
		{KindMemberUserAdd, []string{"p24cap-m1"}, "group-add-member-to-missing-group", OutcomeConflictFailed, 0},
		// S7: user_enable, user_disable
		{KindUserEnable, nil, "user-enable", OutcomeSuccess, 0},
		{KindUserEnable, nil, "user-enable-already-enabled", OutcomeNoop, 0},
		{KindUserEnable, nil, "user-enable-not-found", OutcomeConflictFailed, 0},
		{KindUserDisable, nil, "user-disable", OutcomeSuccess, 0},
		{KindUserDisable, nil, "user-disable-already-disabled", OutcomeNoop, 0},
		{KindUserDisable, nil, "user-disable-not-found", OutcomeConflictFailed, 0},
		// S8: user_del, group_del
		{KindUserDelete, nil, "user-del", OutcomeSuccess, 0},
		{KindUserDelete, nil, "user-del-not-found", OutcomeNoop, 0},
		{KindGroupDelete, nil, "group-del", OutcomeSuccess, 0},
		{KindGroupDelete, nil, "group-del-not-found", OutcomeNoop, 0},
		{KindGroupDelete, nil, "group-del-with-members", OutcomeSuccess, 0},
	}
	for _, r := range rows {
		t.Run(r.kind+" "+r.fixture, func(t *testing.T) {
			got := captured1(t, r.fixture).classify(op(r.kind, "x", r.members...))
			if got.Outcome != r.want || got.Completed != r.completed {
				t.Fatalf("%s on %s: %+v, want %s (completed %d)", r.kind, r.fixture, got, r.want, r.completed)
			}
			if r.want != OutcomeSuccess && r.want != OutcomeNoop && got.Error == "" && got.Detail == "" {
				t.Fatal("a failure that says nothing")
			}
		})
	}
}

// A kind reads the same answer by its own rule: a NotFound for a delete is its goal,
// for a mod a conflict; EmptyResult is a conflict for a password and a failure for
// anything else.
func TestClassifyReadsTheSameErrorByTheKind(t *testing.T) {
	notFound := captured1(t, "user-mod-not-found")
	if got := notFound.classify(op(KindUserUpdate, "x")).Outcome; got != OutcomeConflictFailed {
		t.Fatalf("mod: %s", got)
	}
	if got := notFound.classify(op(KindUserDelete, "x")).Outcome; got != OutcomeNoop {
		t.Fatalf("delete: %s", got)
	}
	if got := notFound.classify(op(KindUserCreate, "x")).Outcome; got != OutcomeFailed {
		t.Fatalf("add (a NotFound cannot be the answer to an add): %s", got)
	}
	emptyResult := captured1(t, "passwd-not-found")
	if got := emptyResult.classify(op(KindPasswordInitialize, "x")).Outcome; got != OutcomeConflictFailed {
		t.Fatalf("passwd: %s", got)
	}
	if got := emptyResult.classify(op(KindUserEnable, "x")).Outcome; got != OutcomeFailed {
		t.Fatalf("EmptyResult for an enable: %s", got)
	}
	emptyModlist := captured1(t, "user-mod-no-change")
	if got := emptyModlist.classify(op(KindUserDisable, "x")).Outcome; got != OutcomeFailed {
		t.Fatalf("EmptyModlist for a disable: %s", got)
	}
	dup := captured1(t, "group-add-duplicate")
	if got := dup.classify(op(KindGroupUpdate, "x")).Outcome; got != OutcomeFailed {
		t.Fatalf("DuplicateEntry for a mod: %s", got)
	}
}

// What is not an answer of the server: an outcome the client could not confirm is
// unknown whatever the command; an error from before the command left is a failure.
func TestClassifyUnknownAndUnsentErrors(t *testing.T) {
	for _, k := range Kinds {
		unknown := classify(op(k, "x", "m"), nil, &freeiparpc.OutcomeUnknownError{Method: "x", Err: errors.New("EOF")})
		if unknown.Outcome != OutcomeUnknown {
			t.Errorf("%s: an outcome the client could not confirm is %s", k, unknown.Outcome)
		}
		unsent := classify(op(k, "x", "m"), nil, &freeiparpc.TransportError{Err: errors.New("dial"), Sent: false})
		if unsent.Outcome != OutcomeFailed || unsent.Error != "not sent" {
			t.Errorf("%s: an error from before the command left is %+v", k, unsent)
		}
	}
	// Answers that do not say the command did what it is for are unknown, not a
	// success: a passwd with result false, a member answer that misses a member.
	if got := classify(op(KindPasswordInitialize, "x"), json.RawMessage(`{"result":false,"value":"x","summary":"?"}`), nil); got.Outcome != OutcomeUnknown {
		t.Errorf("passwd with result false: %s", got.Outcome)
	}
	if got := classify(op(KindUserEnable, "x"), json.RawMessage(`{"result":"yes"}`), nil); got.Outcome != OutcomeUnknown {
		t.Errorf("enable with a result that is not true: %s", got.Outcome)
	}
	missing := captured1(t, "group-add-member")
	if got := missing.classify(op(KindMemberUserAdd, "x", "p0-alice", "p0-bob")); got.Outcome != OutcomeUnknown {
		t.Errorf("a member answer for one of two members: %s", got.Outcome)
	}
	if got := classify(op(KindUserDelete, "x"), json.RawMessage(`{"result":{"failed":["x"]},"value":["x"]}`), nil); got.Outcome != OutcomeFailed {
		t.Errorf("a delete that lists a failure: %s", got.Outcome)
	}
}

// No password-bearing error reaches a result: for a password command the message
// is dropped and a transport error is reduced to its type, whatever the error held.
func TestClassifyKeepsNothingNearAPasswordInAResult(t *testing.T) {
	adversary := &freeiparpc.RPCError{Code: 4203, Name: "DatabaseError", Message: "Constraint violation: " + pwSecret}
	got := classify(op(KindPasswordReset, "alice"), nil, adversary)
	if got.Outcome != OutcomeFailed || strings.Contains(got.Detail+got.Error, pwSecret) || got.Error != "DatabaseError (4203)" {
		t.Fatalf("an RPC error: %+v", got)
	}
	leaky := &freeiparpc.OutcomeUnknownError{Method: "passwd", Err: errors.New("write tcp: " + pwSecret)}
	got = classify(op(KindPasswordInitialize, "alice"), nil, leaky)
	if got.Outcome != OutcomeUnknown || strings.Contains(got.Detail+got.Error, pwSecret) {
		t.Fatalf("an unknown outcome: %+v", got)
	}
	got = classify(op(KindPasswordInitialize, "alice"), nil, errors.New("login: "+pwSecret))
	if strings.Contains(got.Detail+got.Error, pwSecret) {
		t.Fatalf("an error before sending: %+v", got)
	}
	// For other commands the message is kept: it names what failed.
	e := &freeiparpc.RPCError{Code: 4002, Name: "DuplicateEntry", Message: `group with name "g" already exists`}
	if got := classify(op(KindGroupCreate, "g"), nil, e); !strings.Contains(got.Detail, "already exists") {
		t.Fatalf("a group's error lost its message: %+v", got)
	}
}

// The batch fixtures, item by item: the way batch answers are read by the executor
// is the way single ones are, and the item after a failure was applied (K15).
func TestClassifyBatchItemsOfTheCapturedBatches(t *testing.T) {
	items := func(name string) []freeiparpc.BatchItem {
		data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Result struct {
				Results []json.RawMessage `json:"results"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatal(err)
		}
		var out []freeiparpc.BatchItem
		for _, raw := range env.Result.Results {
			var e struct {
				Error     *string `json:"error"`
				ErrorName string  `json:"error_name"`
				ErrorCode int     `json:"error_code"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			if e.Error != nil {
				out = append(out, freeiparpc.BatchItem{Err: &freeiparpc.RPCError{Code: e.ErrorCode, Name: e.ErrorName, Message: *e.Error}})
			} else {
				out = append(out, freeiparpc.BatchItem{Result: raw})
			}
		}
		return out
	}
	for _, tc := range []struct {
		fixture string
		kinds   []string
		want    []Outcome
	}{
		{"batch-group-add-duplicate", []string{KindGroupCreate, KindGroupCreate, KindGroupCreate}, []Outcome{OutcomeSuccess, OutcomeConflictFailed, OutcomeSuccess}},
		{"batch-user-mod-mixed", []string{KindUserUpdate, KindUserUpdate, KindUserUpdate, KindUserUpdate}, []Outcome{OutcomeSuccess, OutcomeConflictFailed, OutcomeNoop, OutcomeSuccess}},
		{"batch-delete-mixed", []string{KindUserDelete, KindUserDelete, KindGroupDelete, KindGroupDelete}, []Outcome{OutcomeSuccess, OutcomeNoop, OutcomeSuccess, OutcomeNoop}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			for i, it := range items(tc.fixture) {
				var err error
				if it.Err != nil {
					err = it.Err
				}
				if got := classify(op(tc.kinds[i], "x"), it.Result, err); got.Outcome != tc.want[i] {
					t.Errorf("item %d (%s): %s, want %s", i, tc.kinds[i], got.Outcome, tc.want[i])
				}
			}
		})
	}
	// batch-members-mixed holds four member commands: add (already a member), add,
	// add to a group that is gone, remove (one of three is not a member).
	got := items("batch-members-mixed")
	want := []struct {
		kind    string
		members []string
		out     Outcome
	}{
		{KindMemberUserAdd, []string{"a"}, OutcomeNoop},
		{KindMemberUserAdd, []string{"a"}, OutcomeSuccess},
		{KindMemberUserAdd, []string{"a"}, OutcomeConflictFailed},
		{KindMemberUserRemove, []string{"a", "b", "c"}, OutcomeSuccess},
	}
	for i, w := range want {
		var err error
		if got[i].Err != nil {
			err = got[i].Err
		}
		if c := classify(op(w.kind, "g", w.members...), got[i].Result, err); c.Outcome != w.out {
			t.Errorf("members item %d: %s, want %s", i, c.Outcome, w.out)
		}
	}
}

func TestEveryOperationKindHasAStageAndACommand(t *testing.T) {
	for _, k := range Kinds {
		if StageOf(k) == 0 {
			t.Errorf("%s has no stage", k)
		}
		o := Operation{ID: k + ":x", Kind: k, Object: "x", Members: []string{"m"}}
		if _, err := commandFor(o, "a password"); err != nil {
			t.Errorf("%s has no command: %v", k, err)
		}
	}
	if StageOf("something.else") != 0 {
		t.Error("an unknown kind has a stage")
	}
	if _, err := commandFor(Operation{Kind: "something.else", Object: "x"}, ""); err == nil {
		t.Error("an unknown kind has a command")
	}
	if _, err := commandFor(Operation{ID: "p", Kind: KindPasswordInitialize, Object: "x"}, ""); err == nil {
		t.Error("a password command without a password")
	}
	if _, err := commandFor(Operation{ID: "u", Kind: KindUserCreate, Object: "x", Fields: map[string]Change{"first": {To: "n"}}}, ""); err == nil {
		t.Error("a field that is not a FreeIPA option was sent (OptionError: first is the CLI's, not the API's)")
	}
}
