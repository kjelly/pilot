package identityreconcile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/identitylock"
)

// The executor against the model of FreeIPA (fakeipa_test.go): the flow of spec
// §7.2, the stages and batches of §7.3 and what the journal and the results hold.

const fullRoster = `schema_version: 3
users:
  - {name: alice, first: Alice, last: A, email: alice@example.test, password: {initial: "Pw-Alice-` + pwSecret + `"}}
  - {name: bob, state: disabled}
  - {name: carol, state: absent}
groups:
  - {name: team-a, category: team, membership: {users: [alice, bob]}}
  - {name: team-old, category: team, state: absent}
`

// a live state with the two objects the roster deletes.
func seedFullRoster(f *fakeIPA) {
	f.addUser("carol", "Carol", "C")
	f.groups["ipausers"].users["carol"] = true
	f.addGroup("team-old", "old", false)
}

func TestExecuteAppliesEveryStageInOrderAndVerifiesIt(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	seedFullRoster(e.f)
	e.entry.onPrepare = func() {
		if w := e.f.writes(); len(w) != 0 {
			t.Errorf("writes before the entry ran: %v", w)
		}
	}
	res := e.mustApply()

	markers := []string{"group_add " + HistoryMarkerName("team-a"), "group_add " + HistoryMarkerName("team-old")}
	slices.Sort(markers)                                     // the plan lists operations of a kind by object name
	want := append([]string{"group_add team-a"}, markers...) // S1, S2
	want = append(want,
		"user_add alice", "user_add bob", // S3
		"passwd alice",            // S4
		"group_add_member team-a", // S6
		"user_disable bob",        // S7
		"user_del carol",          // S8
		"group_del team-old",
	)
	equalStrings(t, e.f.writes(), want, "the writes, in the order of the stages")

	if e.entry.prepared != 1 || e.entry.probed != 0 {
		t.Fatalf("entry prepare/probe = %d/%d, want one prepare", e.entry.prepared, e.entry.probed)
	}
	if !res.Entry.Ran || res.Entry.Previous == nil || *res.Entry.Previous {
		t.Fatalf("entry = %+v", res.Entry)
	}
	if !res.Verify.OK() || res.Plan3 == nil || len(res.Plan3.Operations) != 0 {
		t.Fatalf("verify = %+v, plan3 = %+v", res.Verify, res.Plan3)
	}
	if c := res.Counts(); c[OutcomeSuccess] != len(res.Ops) {
		t.Fatalf("outcomes = %v for %d operations", c, len(res.Ops))
	}
	if !res.Committed() || res.Stop != nil {
		t.Fatalf("committed %v, stop %+v", res.Committed(), res.Stop)
	}
	// What the server now holds is what the roster says.
	if e.f.users["alice"] == nil || e.f.users["carol"] != nil || e.f.users["bob"] == nil || !e.f.users["bob"].locked {
		t.Fatalf("users = %v", sortedKeys(e.f.users))
	}
	if g := e.f.groups["team-a"]; g == nil || !g.users["alice"] || !g.users["bob"] || e.f.groups["team-old"] != nil {
		t.Fatalf("groups = %v", sortedKeys(e.f.groups))
	}
	if e.f.users["alice"].mail[0] != "alice@example.test" || !e.f.users["alice"].hasPwd {
		t.Fatalf("alice = %+v", e.f.users["alice"])
	}
	// The second run has nothing to do and sends nothing and runs no entry.
	before := len(e.f.writes())
	again, err := e.execute()
	if err != nil || len(again.Plan1.Operations) != 0 || len(e.f.writes()) != before || e.entry.prepared != 1 {
		t.Fatalf("second run: %v, plan %v, writes %d -> %d, prepares %d", err, kinds(again.Plan1), before, len(e.f.writes()), e.entry.prepared)
	}
	if len(e.journal.problem) != 0 {
		t.Fatalf("journal problems: %v", e.journal.problem)
	}
}

// Every command of a stage is one batch of the stage (up to the limit); a password
// is a call of its own.
func TestExecuteSendsBatchesOfAtMostTheLimitAndPasswordsOnTheirOwn(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("schema_version: 3\nusers:\n")
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&doc, "  - {name: u%d, password: {initial: \"Pw-%d-%s\"}}\n", i, i, pwSecret)
	}
	doc.WriteString("groups:\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&doc, "  - {name: team-g%02d, category: team}\n", i)
	}
	e := newRunEnv(t, doc.String())
	res := e.mustApply()
	if len(res.Ops) != 60+60+3+3 { // groups, markers, users, passwords
		t.Fatalf("%d operations", len(res.Ops))
	}
	// Group the commands the fake saw by the request they arrived in.
	var sizes []string
	last := 0
	for _, c := range e.f.calls {
		if !isWrite(c.method) {
			continue
		}
		switch {
		case !c.batch:
			sizes = append(sizes, c.method+"*1")
		case c.batchNo != last:
			last = c.batchNo
			sizes = append(sizes, c.method+"*1")
		default:
			var n int
			_, _ = fmt.Sscanf(sizes[len(sizes)-1][strings.Index(sizes[len(sizes)-1], "*")+1:], "%d", &n)
			sizes[len(sizes)-1] = fmt.Sprintf("%s*%d", c.method, n+1)
		}
	}
	// S1: 60 group_add as 25+25+10; S2: 60 marker group_add as 25+25+10; S3: 3 user_add; S4: three single passwd.
	equalStrings(t, sizes, []string{
		"group_add*25", "group_add*25", "group_add*10", "group_add*25", "group_add*25", "group_add*10",
		"user_add*3", "passwd*1", "passwd*1", "passwd*1",
	}, "batches by size")
}

func TestExecuteBatchLimitOption(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("schema_version: 3\ngroups:\n")
	for i := 0; i < 7; i++ {
		fmt.Fprintf(&doc, "  - {name: team-g%d, category: team}\n", i)
	}
	e := newRunEnv(t, doc.String())
	e.opts.BatchLimit = 3
	e.mustApply()
	counts := map[int]int{}
	for _, c := range e.f.calls {
		if c.method == "group_add" && c.batch {
			counts[c.batchNo]++
		}
	}
	var sizes []int
	for _, no := range sortedInts(counts) {
		sizes = append(sizes, counts[no])
	}
	// 7 groups and then 7 markers, at three a batch, each stage in its own batches.
	if !slices.Equal(sizes, []int{3, 3, 1, 3, 3, 1}) {
		t.Fatalf("batch sizes %v, want 3,3,1 for the groups and 3,3,1 for the markers", sizes)
	}
	for _, bad := range []int{-1, MaxBatch + 1} {
		e.opts.BatchLimit = bad
		if _, err := e.execute(); err == nil {
			t.Fatalf("a batch limit of %d was accepted", bad)
		}
	}
}

// Before the first write the entry has run and its result was observed; with
// nothing to write it does not run.
func TestExecuteRunsTheEntryOnlyForAPlanThatWrites(t *testing.T) {
	e := newRunEnv(t, "schema_version: 3\nusers: [{name: alice}]\n")
	e.f.addUser("alice", "alice", "alice")
	e.f.users["alice"].shell, e.f.users["alice"].home = "/bin/bash", "/home/alice"
	e.f.users["alice"].display, e.f.users["alice"].mail = "alice alice", nil
	res := e.mustApply()
	if len(res.Plan1.Operations) != 0 || e.entry.prepared != 0 || e.entry.probed != 0 || len(e.f.writes()) != 0 {
		t.Fatalf("an idle run: plan %v, prepares %d, probes %d, writes %v", kinds(res.Plan1), e.entry.prepared, e.entry.probed, e.f.writes())
	}
	if res.Entry.Ran || res.Verify.Done || e.f.finds != 1 {
		t.Fatalf("entry %+v, verify %+v, reads %d: an idle run reads once and does nothing else", res.Entry, res.Verify, e.f.finds)
	}

	// ProbeWhenIdle: the users-groups scope reads the obligation of a run that has
	// nothing to write.
	e.opts.ProbeWhenIdle = true
	e.entry.pending = true
	res = e.mustApply()
	if e.entry.probed != 1 || e.entry.prepared != 0 || res.Entry.Pending == nil || !*res.Entry.Pending || res.Entry.Ran {
		t.Fatalf("probe %d, prepare %d, entry %+v", e.entry.probed, e.entry.prepared, res.Entry)
	}
	if !strings.Contains(e.journal.all(), `"probe_pending":true`) {
		t.Fatalf("the probe is not in the journal:\n%s", e.journal.all())
	}
}

func TestExecuteRefusesWhatItCannotRunWithout(t *testing.T) {
	e := newRunEnv(t, fullRoster)
	for name, mod := range map[string]func(*Options){
		"no entry":   func(o *Options) { o.Entry = nil },
		"no gate":    func(o *Options) { o.Gate = nil },
		"no journal": func(o *Options) { o.Journal = nil },
	} {
		opts := e.opts
		mod(&opts)
		if _, err := executeWithin(e.ctx, e.f, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A context without the lock: no read, no write.
	if _, err := executeWithin(t.Context(), e.f, e.opts); !errors.Is(err, identitylock.ErrNoLock) {
		t.Fatalf("without the lock: %v", err)
	}
	if len(e.f.calls) != 0 {
		t.Fatalf("a run without a lock sent %v", e.f.methodsCalled())
	}
	// A lock that was released.
	_ = e.held.Release()
	if _, err := executeWithin(e.ctx, e.f, e.opts); err == nil || len(e.f.calls) != 0 {
		t.Fatalf("a released lock: %v, calls %v", err, e.f.methodsCalled())
	}
}

func sortedInts(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
