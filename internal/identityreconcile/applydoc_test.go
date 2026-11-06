package identityreconcile

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The result file of an apply (spec §8.6): a run's Result goes through NewApplyDocument, Render and
// ParseApplyDocument and comes back the same, so a field added to Result that the file drops, or
// one the parser refuses, fails here (AGENTS.md §5.15).
func TestApplyDocumentRoundTrips(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: ua, "+pw("a")+"}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n"))
	res, err := e.execute()
	if err != nil {
		t.Fatalf("Execute: %v%s", err, describeOps(res))
	}
	doc := NewApplyDocument(ApplyDocumentInput{
		Desired: e.opts.Desired, Result: *res, Stage: "sandbox", RunID: "run-1", Outcome: "partial_failed", FailedStep: "verify",
		ExitCode: 4, Err: fmt.Errorf("verify failed: %w: owed", ErrUnsettled), Revision: "abc",
		Target: Target{InventoryHost: "ipa-1", FQDN: testFQDN, Destination: "127.0.0.1:443"}, Server: Server{Version: "4.13.4", APIVersion: "2.257"},
		Stats: Stats{HTTPRequests: 9, Reads: 7, Writes: 4},
	})
	first, err := doc.Render()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseApplyDocument(first)
	if err != nil {
		t.Fatalf("the file does not parse: %v\n%s", err, first)
	}
	second, err := parsed.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("Parse then Render changed the file:\n%s\n---\n%s", first, second)
	}
	if parsed.Verdict != VerdictUnsettled || parsed.ExitCode != 4 || !parsed.Authorization.Owed || parsed.Authorization.Source != ObligationThisRun || !parsed.Observed {
		t.Fatalf("the parsed file: verdict %s exit %d authorization %+v observed %v", parsed.Verdict, parsed.ExitCode, parsed.Authorization, parsed.Observed)
	}
	if len(parsed.Ops) != len(res.Ops) || parsed.Plan2 == nil || parsed.Stats.Writes != 4 || parsed.Target.FQDN != testFQDN {
		t.Fatalf("the parsed file lost something: %d ops of %d, plan2 %v, stats %+v, target %+v", len(parsed.Ops), len(res.Ops), parsed.Plan2, parsed.Stats, parsed.Target)
	}
	if strings.Contains(string(first), pwSecret) {
		t.Fatal("a password is in the result file")
	}
}

func TestApplyDocumentParserIsStrict(t *testing.T) {
	e := newRunEnv(t, rosterWith("  - {name: ua}\n", ""))
	res, _ := e.execute()
	good, _ := NewApplyDocument(ApplyDocumentInput{Desired: e.opts.Desired, Result: *res, Outcome: "success"}).Render()
	for name, tc := range map[string]struct {
		data string
		want string
	}{
		"a field it does not know":  {strings.Replace(string(good), `"scope"`, `"extra": 1, "scope"`, 1), "unknown field"},
		"another schema":            {strings.Replace(string(good), ApplyDocumentSchema, "pilot.identity-apply/v2", 1), "schema"},
		"data after the document":   {string(good) + `{"schema": "x"}`, "after the document"},
		"not JSON":                  {"verdict: ok", "parse the apply result"},
		"the preview's plan schema": {strings.Replace(string(good), ApplyDocumentSchema, DocumentSchema, 1), "schema"},
	} {
		if _, err := ParseApplyDocument([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one holding %q", name, err, tc.want)
		}
	}
	if _, err := ParseApplyDocument(good); err != nil {
		t.Fatalf("the control does not parse: %v", err)
	}
}

// The verdict is the run's one word, from the error and the outcome: blocked wins over a journal
// failure reported beside it, an owed obligation is unsettled, a partial_failed outcome is partial.
func TestApplyDocumentVerdicts(t *testing.T) {
	yes := true
	owed := Result{Observed: true, Entry: EntryReport{Ran: true}}
	idleOK := Result{Observed: true, Entry: EntryReport{Pending: new(bool)}}
	idleOwing := Result{Observed: true, Entry: EntryReport{Pending: &yes}}
	for _, tc := range []struct {
		name    string
		res     Result
		err     error
		outcome string
		want    string
	}{
		{"nothing written, nothing owed", idleOK, nil, "success", VerdictOK},
		{"idle with an obligation owed", idleOwing, fmt.Errorf("x: %w", ErrUnsettled), "partial_failed", VerdictUnsettled},
		{"applied, the obligation owed", owed, fmt.Errorf("x: %w", ErrUnsettled), "partial_failed", VerdictUnsettled},
		{"blocked", Result{Observed: true}, fmt.Errorf("%w: x", ErrBlocked), "failed", VerdictBlocked},
		{"blocked and the journal failed", Result{Observed: true}, errors.Join(fmt.Errorf("%w: x", ErrBlocked), ErrJournal), "failed", VerdictBlocked},
		{"a partial application", owed, fmt.Errorf("%w: x", ErrWrites), "partial_failed", VerdictPartial},
		{"a failure that changed nothing", owed, fmt.Errorf("%w: x", ErrEntry), "failed", VerdictFailed},
	} {
		doc := NewApplyDocument(ApplyDocumentInput{Result: tc.res, Err: tc.err, Outcome: tc.outcome})
		if doc.Verdict != tc.want {
			t.Errorf("%s: verdict %s, want %s", tc.name, doc.Verdict, tc.want)
		}
	}
	long := NewApplyDocument(ApplyDocumentInput{Err: errors.New(strings.Repeat("x", 3*maxApplyErrorBytes))})
	if len(long.Error) > maxApplyErrorBytes+4 {
		t.Errorf("the error text is %d bytes, the bound is %d", len(long.Error), maxApplyErrorBytes)
	}
}
