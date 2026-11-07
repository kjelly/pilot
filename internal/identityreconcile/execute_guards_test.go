package identityreconcile

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// Guards, refusals and stops of the executor that needed a row of their own: each
// test below is one a mutation of the guard (spec §5.12: a gate that is not shown to
// trigger is not shown to exist) found the package green without.

// showFails makes the read of one object fail with err: the show of method for name
// is answered with it, whatever else the fake does.
func (f *fakeIPA) showFails(method, name string, err error) {
	prev := f.intercept
	f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
		if c.method == method && len(c.args) > 0 && c.args[0] == name {
			return nil, err, true
		}
		if prev != nil {
			return prev(f, c)
		}
		return nil, nil, false
	}
}

var errACI = &freeiparpc.RPCError{Code: 4204, Name: "ACIError", Message: "Insufficient access"}

// A re-read that fails with an error that is not "not found" cannot prove its
// precondition, so the step it guards is not sent (conflict-failed), and the stages
// after it do not run. "Not found" is a different answer: the object is gone.
func TestAReReadThatFailsRefusesTheStepItGuards(t *testing.T) {
	t.Run("S4: the user's read fails, the password is not sent", func(t *testing.T) {
		e := newRunEnv(t, "schema_version: 3\nusers:\n  - {name: alice, "+pw("a")+"}\n")
		aliceLive(e.f)
		e.f.showFails("user_show", "alice", errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.password.initialize:alice") != OutcomeConflictFailed || slices.Contains(e.f.writes(), "passwd alice") {
			t.Fatalf("err %v writes %v:%s", err, e.f.writes(), describeOps(res))
		}
		mustContain(t, res.op("user.password.initialize:alice").Detail, "could not be read before its password was set", "the reason")
		journalAccounts(t, e, res, err)
	})
	roster := rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice]}}\n  - {name: team-c, category: team, membership: {users: [alice]}}\n  - {name: team-d, category: team, state: absent}\n")
	seedGroups := func(f *fakeIPA) {
		for _, n := range []string{"alice", "bob"} {
			f.addUser(n, n, n)
		}
		for _, n := range []string{"team-b", "team-c"} {
			g := f.addGroup(n, n, false)
			g.users["alice"], g.users["bob"] = true, true
		}
		f.addGroup("team-d", "d", false)
	}
	t.Run("S5: the group's read fails, its removal is not sent, the other group's is, and S8 does not run", func(t *testing.T) {
		e := newRunEnv(t, roster)
		seedGroups(e.f)
		e.f.showFails("group_show", "team-b", errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("group.member_user.remove:team-b") != OutcomeConflictFailed || res.outcomeOf("group.member_user.remove:team-c") != OutcomeSuccess {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("group.member_user.remove:team-b").Detail, "could not be read before its members were removed", "the reason")
		if e.f.sentMembers("group_remove_member", "team-b", "user") != nil || res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted || res.Stop == nil || res.Stop.Stage != "S5" {
			t.Fatalf("what followed:%s", describeOps(res))
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("S7: the user's read fails, the disable is not sent", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: carol, state: disabled}\n", ""))
		e.f.addUser("carol", "carol", "carol")
		e.f.showFails("user_show", "carol", errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.disable:carol") != OutcomeConflictFailed || slices.Contains(e.f.writes(), "user_disable carol") {
			t.Fatalf("err %v writes %v:%s", err, e.f.writes(), describeOps(res))
		}
		mustContain(t, res.op("user.disable:carol").Detail, "could not be read before it was disabled", "the reason")
		journalAccounts(t, e, res, err)
	})
	delRoster := rosterWith("  - {name: carol, state: absent}\n  - {name: dave, state: absent}\n", "  - {name: team-d, category: team, state: absent}\n")
	seedDel := func(f *fakeIPA) {
		f.addUser("carol", "carol", "carol")
		f.addUser("dave", "dave", "dave")
		f.addGroup("team-d", "d", false)
	}
	t.Run("S8 users: one user's read fails, neither user and no group is deleted", func(t *testing.T) {
		e := newRunEnv(t, delRoster)
		seedDel(e.f)
		e.f.showFails("user_show", "carol", errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.delete:carol") != OutcomeConflictFailed || res.outcomeOf("user.delete:dave") != OutcomeNotExecuted || res.outcomeOf("group.delete:team-d") != OutcomeNotExecuted {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("user.delete:carol").Detail, "could not be read before it was deleted", "the reason")
		for _, w := range e.f.writes() {
			if strings.HasPrefix(w, "user_del") || strings.HasPrefix(w, "group_del") {
				t.Fatalf("a delete was sent: %v", e.f.writes())
			}
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("S8 users: the whole read fails, every user conflicts", func(t *testing.T) {
		e := newRunEnv(t, delRoster)
		seedDel(e.f)
		e.f.intercept = func(f *fakeIPA, c call) (json.RawMessage, error, bool) {
			if c.method == "user_show" {
				return nil, errors.New("connection reset"), true
			}
			return nil, nil, false
		}
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("user.delete:carol") != OutcomeConflictFailed || res.outcomeOf("user.delete:dave") != OutcomeConflictFailed {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("user.delete:dave").Detail, "connection reset", "the reason")
	})
	t.Run("S8 groups: the group's read fails, the users were deleted and the group is not", func(t *testing.T) {
		e := newRunEnv(t, delRoster)
		seedDel(e.f)
		e.f.showFails("group_show", "team-d", errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("group.delete:team-d") != OutcomeConflictFailed || res.outcomeOf("user.delete:carol") != OutcomeSuccess {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("group.delete:team-d").Detail, "the group could not be read before it was deleted", "the reason")
		if slices.Contains(e.f.writes(), "group_del team-d") {
			t.Fatalf("the group was deleted: %v", e.f.writes())
		}
		journalAccounts(t, e, res, err)
	})
	t.Run("S8 groups: the marker's read fails, the group is not deleted", func(t *testing.T) {
		e := newRunEnv(t, delRoster)
		seedDel(e.f)
		e.f.showFails("group_show", HistoryMarkerName("team-d"), errACI)
		res, err := e.execute()
		if !errors.Is(err, ErrWrites) || res.outcomeOf("group.delete:team-d") != OutcomeConflictFailed {
			t.Fatalf("err %v:%s", err, describeOps(res))
		}
		mustContain(t, res.op("group.delete:team-d").Detail, "history marker could not be read", "the reason")
		if slices.Contains(e.f.writes(), "group_del team-d") {
			t.Fatalf("the group was deleted: %v", e.f.writes())
		}
	})
}

// The password of a user comes from the PasswordSource when the user is sent: a
// source that is missing, refuses, or gives an empty value stops S4 with the reason,
// sends nothing for that user and does not panic.
func TestAPasswordTheSourceCannotGiveStopsS4(t *testing.T) {
	roster := rosterWith("  - {name: ua, "+pw("a")+"}\n  - {name: ub, "+pw("b")+"}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n")
	for _, tc := range []struct {
		name   string
		source PasswordSource
		err    string // in the op's detail
		code   string // the op's error
	}{
		{"no source at all", nil, "no password source", "no password"},
		{"a source that refuses ua", stubPasswords{"ua": {err: errors.New("the password of ua is a template")}}, "the password of ua is a template", "no password"},
		{"a source that gives an empty value", stubPasswords{"ua": {value: ""}}, "no password to set", "not sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRunEnv(t, roster)
			e.opts.Passwords = tc.source
			res, err := e.execute() // a nil source must not panic
			if !errors.Is(err, ErrWrites) {
				t.Fatalf("err = %v", err)
			}
			first := res.op("user.password.initialize:ua")
			if first.Outcome != OutcomeFailed || first.Error != tc.code || !strings.Contains(first.Detail, tc.err) {
				t.Fatalf("ua: %+v", first)
			}
			if slices.ContainsFunc(e.f.writes(), func(w string) bool { return strings.HasPrefix(w, "passwd") }) {
				t.Fatalf("a password was sent: %v", e.f.writes())
			}
			if res.outcomeOf("user.password.initialize:ub") != OutcomeNotExecuted || res.outcomeOf("group.member_user.add:team-b") != OutcomeNotExecuted {
				t.Fatalf("what follows ua:%s", describeOps(res))
			}
			if res.Stop == nil || res.Stop.Stage != "S4" || !strings.Contains(res.Stop.Reason, "user.password.initialize:ua") {
				t.Fatalf("stop = %+v", res.Stop)
			}
			journalAccounts(t, e, res, err)
		})
	}
}

// stubPasswords is a PasswordSource with a value or an error per user.
type stubPasswords map[string]struct {
	value string
	err   error
}

func (s stubPasswords) InitialPassword(user string) (string, error) {
	if p, ok := s[user]; ok {
		return p.value, p.err
	}
	return "Pw-" + user + "-" + pwSecret, nil
}

// An idle run with ProbeWhenIdle reads the obligation with the entry's probe, and
// holds the entry to the same: a probe's answer for the locked host, nothing else.
func TestAnIdleRunProbesTheEntryAndRefusesWhatIsNotAProbeOfTheLockedHost(t *testing.T) {
	setup := func(t *testing.T) *runEnv {
		e := newRunEnv(t, "schema_version: 3\nusers: [{name: alice}]\n")
		aliceLive(e.f)
		e.opts.ProbeWhenIdle = true
		return e
	}
	for _, tc := range []struct {
		name string
		mod  func(e *fakeEntry)
		want string // "" when the run succeeds
	}{
		{"the probe fails", func(e *fakeEntry) { e.err = errors.New("ansible-playbook exited 2") }, "ansible-playbook exited 2"},
		{"the result is for another host", func(e *fakeEntry) {
			e.result = func(a AuthCacheAction) AuthCacheResult {
				return AuthCacheResult{Action: a, Host: "ipa-2", FQDN: testFQDN}
			}
		}, `for "ipa-2", not a probe result for the locked host "ipa-1"`},
		{"the result is a prepare's", func(e *fakeEntry) {
			e.result = func(AuthCacheAction) AuthCacheResult {
				return AuthCacheResult{Action: AuthCachePrepare, Host: "ipa-1", FQDN: testFQDN}
			}
		}, `a "prepare" result`},
		{"nothing is owed", func(e *fakeEntry) { e.pending = false }, ""},
		{"something is owed", func(e *fakeEntry) { e.pending = true }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			tc.mod(e.entry)
			res, err := e.execute()
			if e.entry.probed != 1 || e.entry.prepared != 0 || len(e.f.writes()) != 0 || res.Entry.Ran {
				t.Fatalf("probes %d, prepares %d, writes %v, entry %+v", e.entry.probed, e.entry.prepared, e.f.writes(), res.Entry)
			}
			if tc.want != "" {
				if !errors.Is(err, ErrEntry) || !strings.Contains(err.Error(), tc.want) || res.Entry.Pending != nil {
					t.Fatalf("err = %v, entry %+v, want ErrEntry holding %q and no answer", err, res.Entry, tc.want)
				}
				if strings.Contains(e.journal.all(), "auth_cache") {
					t.Fatalf("a probe that was refused is in the journal:\n%s", e.journal.all())
				}
				return
			}
			if err != nil || res.Entry.Pending == nil || *res.Entry.Pending != e.entry.pending {
				t.Fatalf("err = %v, entry %+v, want pending %v", err, res.Entry, e.entry.pending)
			}
			want := fmt.Sprintf(`"probe_pending":%v`, e.entry.pending)
			if !strings.Contains(e.journal.all(), want) || !strings.Contains(e.journal.all(), `"source":"previous_run"`) || !strings.Contains(e.journal.all(), `"entry_ran":false`) {
				t.Fatalf("the probe is not in the journal as %s:\n%s", want, e.journal.all())
			}
		})
	}
	t.Run("the journal cannot record the probe: the run fails with ErrJournal", func(t *testing.T) {
		e := setup(t)
		e.journal.failOn = func(ev Event) error { return errors.New("disk full") }
		res, err := e.execute()
		if !errors.Is(err, ErrJournal) || res.JournalError == "" {
			t.Fatalf("err = %v, journal error %q", err, res.JournalError)
		}
	})
	t.Run("without ProbeWhenIdle the entry is not asked at all", func(t *testing.T) {
		e := setup(t)
		e.opts.ProbeWhenIdle = false
		e.entry.err = errors.New("must not be called")
		if _, err := e.execute(); err != nil || e.entry.probed != 0 || e.entry.prepared != 0 {
			t.Fatalf("err %v, probes %d, prepares %d", err, e.entry.probed, e.entry.prepared)
		}
	})
}

// A re-read is made in batches of at most the batch limit, and an object that is in
// two operations of a stage is read once.
func TestReReadsAreBatchedAtTheLimitAndReadOnce(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("schema_version: 3\nusers:\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&doc, "  - {name: u%02d, %s}\n", i, pw("x"))
	}
	showSizes := func(f *fakeIPA, method string) []int {
		counts := map[int]int{}
		for _, c := range f.calls {
			if c.method == method && c.batch {
				counts[c.batchNo]++
			}
		}
		var out []int
		for _, no := range sortedInts(counts) {
			out = append(out, counts[no])
		}
		return out
	}
	for _, tc := range []struct {
		limit int
		want  []int
	}{
		{0, []int{25, 25, 10}},
		{7, []int{7, 7, 7, 7, 7, 7, 7, 7, 4}},
	} {
		t.Run(fmt.Sprintf("limit %d", tc.limit), func(t *testing.T) {
			e := newRunEnv(t, doc.String())
			e.opts.BatchLimit = tc.limit
			e.mustApply() // S3 creates the 60 users, S4 re-reads all of them before any password
			if got := showSizes(e.f, "user_show"); !slices.Equal(got, tc.want) {
				t.Fatalf("user_show batches %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("a group in two removals of one stage is read once", func(t *testing.T) {
		e := newRunEnv(t, rosterWith("  - {name: alice}\n", "  - {name: team-b, category: team, membership: {users: [alice], groups: []}}\n"))
		e.f.addUser("alice", "alice", "alice")
		e.f.addUser("bob", "bob", "bob")
		g := e.f.addGroup("team-b", "team-b", false)
		c := e.f.addGroup("team-c", "c", false)
		g.users["alice"], g.users["bob"], g.groups[c.name] = true, true, true
		res := e.mustApply()
		if res.outcomeOf("group.member_user.remove:team-b") != OutcomeSuccess || res.outcomeOf("group.member_group.remove:team-b") != OutcomeSuccess {
			t.Fatalf("outcomes:%s", describeOps(res))
		}
		n := 0
		for _, c := range e.f.calls {
			if c.method == "group_show" && len(c.args) > 0 && c.args[0] == "team-b" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("team-b was read %d times for the two removals of the stage, want once", n)
		}
	})
}
