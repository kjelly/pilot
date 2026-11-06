package identityreconcile

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/gateledger"
)

// Every read and every parse of Observe can fail the observation, and
// nothing after the failing step is read (spec §6.2, §10.1 observer): a
// preview built from a partial observation would plan deletes and membership
// revocations from what the reader merely did not see (AGENTS.md §5.12).
// The answers come from real captures (§5.6): a missing answer stands for a
// failed read, and a capture taken without `all: true` for an entry that
// cannot be parsed.
func TestObserveFailsOnEachRead(t *testing.T) {
	good := func() map[string][]map[string]any {
		return map[string][]map[string]any{
			"user_find":           captured(t, "user-find-all-k4"),
			"user_find/preserved": captured(t, "user-find-k1-preserved-all"),
			"group_find":          captured(t, "k3-records10-sizelimit0-groups"),
		}
	}
	for _, tc := range []struct {
		name      string
		principal string // "admin" unless set
		key       string // the answer to replace
		fixture   string // a capture to answer with; empty: no answer, a failed read
		gate      string
		want      string // in the error
		calls     int    // reads made, the failing one included
	}{
		{name: "users read fails", key: "user_find", gate: "observe-users-read", want: "read users", calls: 1},
		{name: "users unparseable", key: "user_find", fixture: "user-find-states-noall", gate: "observe-users-parse", want: "user_find entry", calls: 1},
		{name: "reader not among the users", principal: "nobody", gate: "observe-reader-absent", want: "not among the users FreeIPA returned", calls: 1},
		{name: "reader not in admins", principal: "pw-nokey", gate: "observe-reader-not-admin", want: "not a member of admins", calls: 1},
		{name: "preserved read fails", key: "user_find/preserved", gate: "observe-preserved-read", want: "read preserved users", calls: 2},
		{name: "preserved unparseable", key: "user_find/preserved", fixture: "user-find-states-noall", gate: "observe-preserved-parse", want: "user_find entry", calls: 2},
		{name: "groups read fails", key: "group_find", gate: "observe-groups-read", want: "read groups", calls: 3},
		{name: "groups unparseable", key: "group_find", fixture: "group-find-states-noall", gate: "observe-groups-parse", want: "group", calls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answers := good()
			if tc.key != "" {
				if tc.fixture == "" {
					delete(answers, tc.key)
				} else {
					answers[tc.key] = captured(t, tc.fixture)
				}
			}
			principal := tc.principal
			if principal == "" {
				principal = "admin"
			}
			f := &fakeFinder{answers: answers}
			_, err := Observe(context.Background(), f, principal)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if len(f.calls) != tc.calls {
				t.Fatalf("reads = %d, want %d: it must stop at the failure", len(f.calls), tc.calls)
			}
			if tc.key != "" && tc.fixture == "" && !strings.Contains(err.Error(), "no answer for "+tc.key) {
				t.Fatalf("err = %v does not wrap the finder's own failure", err)
			}
		})
	}
}

// The inverse, so the rows above are not trivially satisfied by an Observe
// that fails on everything: the same answers, all good, read in order.
func TestObserveReadsInOrderWhenEverythingAnswers(t *testing.T) {
	f := &fakeFinder{answers: map[string][]map[string]any{
		"user_find":           captured(t, "user-find-all-k4"),
		"user_find/preserved": captured(t, "user-find-k1-preserved-all"),
		"group_find":          captured(t, "k3-records10-sizelimit0-groups"),
	}}
	if _, err := Observe(context.Background(), f, "admin"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range f.calls {
		key := c["method"].(string)
		if c["opts"].(map[string]any)["preserved"] == true {
			key += "/preserved"
		}
		got = append(got, key)
	}
	if want := []string{"user_find", "user_find/preserved", "group_find"}; !slices.Equal(got, want) {
		t.Fatalf("reads = %v, want %v", got, want)
	}
}

// A read that fails with the finder's own sentinel keeps it reachable:
// callers tell a truncated read from a refusal by errors.Is.
func TestObserveKeepsTheReadsError(t *testing.T) {
	boom := errors.New("synthetic read failure")
	f := &errFinder{err: boom}
	if _, err := Observe(context.Background(), f, "admin"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
}

type errFinder struct{ err error }

func (f *errFinder) Find(context.Context, string, []any, map[string]any) ([]map[string]any, error) {
	return nil, f.err
}

// AGENTS.md §5.10/§5.12: every error return of Observe is named and has a
// row above that makes it fire, so deleting a gate fails a test and a new one
// cannot land without a row. The scanner itself is proven in
// internal/gateledger.
func TestObserveEveryGateHasARow(t *testing.T) {
	res, err := gateledger.Scan("observe.go", nil, "Observe")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := gateledger.RowGates("observe_gates_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Returns) < 8 {
		t.Fatalf("found %d gates in Observe, want at least the 8 it had", len(res.Returns))
	}
	for _, p := range gateledger.Check(res, rows, nil) {
		t.Error(p)
	}
}
