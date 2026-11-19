package identityreconcile

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// What each captured answer of an HBAC command means (capture_p3a_facts_test.go states the
// facts; these are the readings the writer makes of them). Every reading has a case that
// passes and one that fires: the same answer read for the wrong direction or the wrong
// kind of operation is not what it is for the right one.

func hbacOp(kind string, members ...string) Operation {
	return Operation{ID: kind + ":x", Kind: kind, Object: "x", Members: members}
}

func TestClassifyHBACReadsTheCapturedMemberAnswers(t *testing.T) {
	for _, c := range []struct {
		fixture string
		op      Operation
		want    Outcome
		done    int
		detail  string
	}{
		{"hbacrule-add-user", hbacOp(KindHBACUserAdd, "p3acap-u1"), OutcomeSuccess, 1, ""},
		{"hbacrule-add-user-already", hbacOp(KindHBACUserAdd, "p3acap-u1"), OutcomeNoop, 0, ""},
		{"hbacrule-add-group-already", hbacOp(KindHBACGroupAdd, "p3acap-g1"), OutcomeNoop, 0, ""},
		{"hbacrule-add-host-already", hbacOp(KindHBACHostAdd, "h"), OutcomeNoop, 0, ""},
		{"hbacrule-add-hostgroup-already", hbacOp(KindHBACHostgroupAdd, "hg"), OutcomeNoop, 0, ""},
		{"hbacrule-add-service-already", hbacOp(KindHBACServiceAdd, "s"), OutcomeNoop, 0, ""},
		{"hbacrule-add-two-users-one-already", hbacOp(KindHBACUserAdd, "p3acap-u1", "p3acap-u2"), OutcomeSuccess, 1, ""},
		{"hbacrule-add-user-missing", hbacOp(KindHBACUserAdd, "p3acap-nouser"), OutcomeConflictFailed, 0, "no such entry"},
		{"hbacrule-add-user-mixed-missing", hbacOp(KindHBACUserAdd, "p3acap-u2", "p3acap-nouser2"), OutcomeConflictFailed, 0, "p3acap-nouser2"},
		{"hbacrule-add-group-missing", hbacOp(KindHBACGroupAdd, "g"), OutcomeConflictFailed, 0, "group p3acap-nogroup"},
		{"hbacrule-add-host-missing", hbacOp(KindHBACHostAdd, "h"), OutcomeConflictFailed, 0, "host "},
		{"hbacrule-add-hostgroup-missing", hbacOp(KindHBACHostgroupAdd, "hg"), OutcomeConflictFailed, 0, "hostgroup "},
		{"hbacrule-add-service-missing", hbacOp(KindHBACServiceAdd, "s"), OutcomeConflictFailed, 0, "hbacsvc "},
		{"hbacrule-remove-user", hbacOp(KindHBACUserRemove, "p3acap-u2"), OutcomeSuccess, 1, ""},
		{"hbacrule-remove-user-not-member", hbacOp(KindHBACUserRemove, "p3acap-u2"), OutcomeNoop, 0, ""},
		{"hbacrule-remove-user-missing", hbacOp(KindHBACUserRemove, "p3acap-nouser"), OutcomeNoop, 0, ""},
		{"hbacrule-remove-group", hbacOp(KindHBACGroupRemove, "p3acap-g1"), OutcomeSuccess, 1, ""},
		{"hbacrule-remove-host", hbacOp(KindHBACHostRemove, "h"), OutcomeSuccess, 1, ""},
		{"hbacrule-remove-hostgroup", hbacOp(KindHBACHostgroupRemove, "hg"), OutcomeSuccess, 1, ""},
		{"hbacrule-remove-service", hbacOp(KindHBACServiceRemove, "s"), OutcomeSuccess, 1, ""},
		// The firing cases: a reason is a nothing-to-do only in its own direction.
		{"hbacrule-add-user-already", hbacOp(KindHBACUserRemove, "p3acap-u1"), OutcomeFailed, 0, "already a member"},
		{"hbacrule-remove-user-not-member", hbacOp(KindHBACUserAdd, "p3acap-u2"), OutcomeFailed, 0, "not a member"},
		// An answer that does not account for every member may have changed some.
		{"hbacrule-add-user", hbacOp(KindHBACUserAdd, "a", "b", "c"), OutcomeUnknown, 1, "does not account"},
	} {
		got := classifyHBAC(c.op, fixtureResult(t, c.fixture), nil)
		if got.Outcome != c.want || got.Completed != c.done || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s as %s: %+v, want %s completed %d detail %q", c.fixture, c.op.Kind, got, c.want, c.done, c.detail)
		}
	}
}

func TestClassifyHBACRefusesAMemberAnswerItCannotRead(t *testing.T) {
	good := fixtureResult(t, "hbacrule-add-user")
	var m map[string]any
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"no completed": func(m map[string]any) { delete(m, "completed") },
		"no failed":    func(m map[string]any) { delete(m, "failed") },
		"a failed entry that is not [name, reason]": func(m map[string]any) {
			m["failed"] = map[string]any{"memberuser": map[string]any{"user": []any{[]any{"only-a-name"}}}}
		},
		"another reason": func(m map[string]any) {
			m["completed"] = 0
			m["failed"] = map[string]any{"memberuser": map[string]any{"user": []any{[]any{"p3acap-u1", "Insufficient access"}}}}
		},
	}
	for name, mutate := range cases {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		mutate(c)
		raw, _ := json.Marshal(c)
		got := classifyHBAC(hbacOp(KindHBACUserAdd, "p3acap-u1"), raw, nil)
		want := OutcomeUnknown
		if name == "another reason" {
			want = OutcomeFailed
		}
		if got.Outcome != want {
			t.Errorf("%s: %+v, want %s", name, got, want)
		}
	}
	if got := classifyHBAC(hbacOp(KindHBACUserAdd, "p3acap-u1"), good, nil); got.Outcome != OutcomeSuccess {
		t.Errorf("the unmodified answer: %+v", got)
	}
}

func TestClassifyHBACReadsTheOtherCommands(t *testing.T) {
	for _, c := range []struct {
		fixture string
		kind    string
		want    Outcome
	}{
		{"hbacrule-enable", KindHBACRuleEnable, OutcomeSuccess},
		{"hbacrule-enable-already", KindHBACRuleEnable, OutcomeSuccess}, // the answer cannot tell (K2)
		{"hbacrule-disable", KindHBACRuleDisable, OutcomeSuccess},
		{"hbacrule-disable-already", KindHBACRuleDisable, OutcomeSuccess},
		{"hbacrule-disable-allow-all", KindHBACAllowAllDisable, OutcomeSuccess},
		{"hbacrule-del", KindHBACRuleDelete, OutcomeSuccess},
		{"hbacrule-add-bare", KindHBACRuleCreate, OutcomeSuccess},
		{"hbacrule-mod-hostcat-clear", KindHBACCategoryUpdate, OutcomeSuccess},
		// An answer that is not what the command answers with does not say it happened.
		{"hbacrule-del", KindHBACRuleDisable, OutcomeUnknown},
		{"hbacrule-enable", KindHBACRuleDelete, OutcomeSuccess}, // result true is not a failed list
	} {
		if got := classifyHBAC(hbacOp(c.kind), fixtureResult(t, c.fixture), nil); got.Outcome != c.want {
			t.Errorf("%s as %s: %+v, want %s", c.fixture, c.kind, got, c.want)
		}
	}
	// A delete whose answer lists a name it did not delete.
	failed := json.RawMessage(`{"result": {"failed": [["x", "no"]]}, "value": ["x"]}`)
	if got := classifyHBAC(hbacOp(KindHBACRuleDelete), failed, nil); got.Outcome != OutcomeFailed {
		t.Errorf("a delete with a failed name: %+v", got)
	}
	// An enable whose answer is not true.
	if got := classifyHBAC(hbacOp(KindHBACRuleEnable), json.RawMessage(`{"result": false}`), nil); got.Outcome != OutcomeUnknown {
		t.Errorf("an enable that says false: %+v", got)
	}
}

func TestClassifyHBACReadsTheCapturedErrors(t *testing.T) {
	for _, c := range []struct {
		fixture string
		kind    string
		want    Outcome
	}{
		{"hbacrule-add-duplicate", KindHBACRuleCreate, OutcomeConflictFailed},
		{"hbacsvc-add-duplicate", KindHBACServiceCreate, OutcomeConflictFailed},
		{"hbacrule-mod-no-change", KindHBACCategoryUpdate, OutcomeNoop},
		{"hbacrule-del-not-found", KindHBACRuleDelete, OutcomeNoop},
		{"hbacrule-add-user-rule-not-found", KindHBACUserAdd, OutcomeConflictFailed},
		{"hbacrule-add-user-rule-not-found", KindHBACHostRemove, OutcomeConflictFailed},
		{"hbacrule-mod-not-found", KindHBACCategoryUpdate, OutcomeConflictFailed},
		{"hbacrule-enable-not-found", KindHBACRuleEnable, OutcomeConflictFailed},
		{"hbacrule-disable-not-found", KindHBACRuleDisable, OutcomeConflictFailed},
		{"hbacrule-disable-not-found", KindHBACAllowAllDisable, OutcomeConflictFailed},
		{"hbacrule-add-host-while-hostcat-all", KindHBACHostAdd, OutcomeFailed},
		{"hbacrule-mod-hostcat-all-with-hosts", KindHBACCategoryUpdate, OutcomeFailed},
		// The firing cases: the same answer for another operation is not the same thing.
		{"hbacrule-mod-no-change", KindHBACRuleEnable, OutcomeFailed},
		{"hbacrule-del-not-found", KindHBACServiceCreate, OutcomeFailed}, // NotFound answers nothing a create asks
		{"hbacrule-add-duplicate", KindHBACUserAdd, OutcomeFailed},
		{"hbacrule-show-not-found", KindHBACServiceCreate, OutcomeFailed},
	} {
		err := fixtureError(t, c.fixture)
		got := classifyHBAC(hbacOp(c.kind), nil, err)
		if got.Outcome != c.want {
			t.Errorf("%s for %s: %+v, want %s", c.fixture, c.kind, got, c.want)
		}
		if !strings.HasPrefix(got.Error, err.Name+" (") {
			t.Errorf("%s: the error %q does not name %s", c.fixture, got.Error, err.Name)
		}
	}
	if got := classifyHBAC(hbacOp(KindHBACRuleDisable), nil, &freeiparpc.OutcomeUnknownError{Method: "hbacrule_disable", Err: errors.New("lost")}); got.Outcome != OutcomeUnknown {
		t.Errorf("an unknown outcome: %+v", got)
	}
	if got := classifyHBAC(hbacOp(KindHBACRuleDisable), nil, errors.New("tunnel closed")); got.Outcome != OutcomeFailed || got.Error != "not sent" {
		t.Errorf("a command that did not reach the server: %+v", got)
	}
	if got := classifyHBAC(hbacOp(KindHBACRuleDisable), nil, &freeiparpc.ErrWriteRefused{Method: "hbacrule_disable", Err: errors.New("gate")}); got.Outcome != OutcomeFailed {
		t.Errorf("a write the gate refused: %+v", got)
	}
}

func TestHBACCommandsAreTheCapturedOnes(t *testing.T) {
	members := func(names ...string) []any { return list(names...) }
	for _, c := range []struct {
		op     Operation
		method string
		args   []any
		opts   map[string]any
	}{
		{Operation{Kind: KindHBACServiceCreate, Object: "svc", Fields: map[string]Change{"name": {To: "Svc"}}}, "hbacsvc_add", []any{"Svc"}, nil},
		{Operation{Kind: KindHBACRuleCreate, Object: "r", Fields: map[string]Change{"name": {To: "R"}}}, "hbacrule_add", []any{"R"}, nil},
		{Operation{Kind: KindHBACRuleCreate, Object: "r", Fields: map[string]Change{"name": {To: "R"}, "hostcategory": {To: "all"}}}, "hbacrule_add", []any{"R"}, map[string]any{"hostcategory": "all"}},
		{Operation{Kind: KindHBACHostAdd, Object: "r", Members: []string{"h.d"}}, "hbacrule_add_host", []any{"r"}, map[string]any{"host": members("h.d")}},
		{Operation{Kind: KindHBACHostgroupAdd, Object: "r", Members: []string{"g"}}, "hbacrule_add_host", []any{"r"}, map[string]any{"hostgroup": members("g")}},
		{Operation{Kind: KindHBACServiceAdd, Object: "r", Members: []string{"sshd"}}, "hbacrule_add_service", []any{"r"}, map[string]any{"hbacsvc": members("sshd")}},
		{Operation{Kind: KindHBACUserAdd, Object: "r", Members: []string{"a", "b"}}, "hbacrule_add_user", []any{"r"}, map[string]any{"user": members("a", "b")}},
		{Operation{Kind: KindHBACGroupAdd, Object: "r", Members: []string{"t"}}, "hbacrule_add_user", []any{"r"}, map[string]any{"group": members("t")}},
		{Operation{Kind: KindHBACHostRemove, Object: "r", Members: []string{"h.d"}}, "hbacrule_remove_host", []any{"r"}, map[string]any{"host": members("h.d")}},
		{Operation{Kind: KindHBACHostgroupRemove, Object: "r", Members: []string{"g"}}, "hbacrule_remove_host", []any{"r"}, map[string]any{"hostgroup": members("g")}},
		{Operation{Kind: KindHBACServiceRemove, Object: "r", Members: []string{"sudo"}}, "hbacrule_remove_service", []any{"r"}, map[string]any{"hbacsvc": members("sudo")}},
		{Operation{Kind: KindHBACUserRemove, Object: "r", Members: []string{"a"}}, "hbacrule_remove_user", []any{"r"}, map[string]any{"user": members("a")}},
		{Operation{Kind: KindHBACGroupRemove, Object: "r", Members: []string{"t"}}, "hbacrule_remove_user", []any{"r"}, map[string]any{"group": members("t")}},
		{Operation{Kind: KindHBACCategoryUpdate, Object: "r", Fields: map[string]Change{"hostcategory": {From: "all", To: ""}}}, "hbacrule_mod", []any{"r"}, map[string]any{"hostcategory": ""}},
		{Operation{Kind: KindHBACCategoryUpdate, Object: "r", Fields: map[string]Change{"hostcategory": {To: "all"}, "servicecategory": {From: "all", To: ""}}}, "hbacrule_mod", []any{"r"}, map[string]any{"hostcategory": "all", "servicecategory": ""}},
		{Operation{Kind: KindHBACRuleEnable, Object: "r"}, "hbacrule_enable", []any{"r"}, nil},
		{Operation{Kind: KindHBACRuleDisable, Object: "r"}, "hbacrule_disable", []any{"r"}, nil},
		{Operation{Kind: KindHBACRuleDelete, Object: "r"}, "hbacrule_del", []any{"r"}, nil},
	} {
		cmd, err := hbacCommandFor(c.op)
		if err != nil {
			t.Errorf("%s: %v", c.op.Kind, err)
			continue
		}
		gotOpts, _ := json.Marshal(cmd.Options)
		wantOpts, _ := json.Marshal(c.opts)
		gotArgs, _ := json.Marshal(cmd.Args)
		wantArgs, _ := json.Marshal(c.args)
		if cmd.Method != c.method || string(gotArgs) != string(wantArgs) || (string(gotOpts) != string(wantOpts) && (len(cmd.Options) != 0 || len(c.opts) != 0)) {
			t.Errorf("%s: %s %s %s, want %s %s %s", c.op.Kind, cmd.Method, gotArgs, gotOpts, c.method, wantArgs, wantOpts)
		}
	}
	for _, op := range []Operation{
		{Kind: KindHBACCategoryUpdate, Object: "r"},
		{Kind: KindHBACCategoryUpdate, Object: "r", Fields: map[string]Change{"hostcategory": {To: 5}}},
		{Kind: KindUserCreate, Object: "u"},
		{Kind: KindHBACAllowAllDisable, Object: "allow_all"},
	} {
		if _, err := hbacCommandFor(op); err == nil {
			t.Errorf("%s with %v has a command", op.Kind, op.Fields)
		}
	}
}

func TestEveryHBACKindHasAStageAndTheStagesFollowThePlanOrder(t *testing.T) {
	last := HBACStage(0)
	for _, k := range HBACKinds {
		s := HBACStageOf(k)
		if s < H1 || s > H8 {
			t.Errorf("%s has stage %d", k, s)
		}
		if s < last {
			t.Errorf("%s (stage %s) comes after a later stage in the plan order", k, s)
		}
		last = s
	}
	if HBACStageOf("user.create") != 0 || HBACStageOf("") != 0 {
		t.Error("a kind that is not HBAC has a stage")
	}
	if !slices.IsSorted(HBACStages) || len(HBACStages) != 8 || HBACStages[0].String() != "H1" {
		t.Errorf("stages %v", HBACStages)
	}
}
