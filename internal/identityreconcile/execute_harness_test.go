package identityreconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identitylock/identitylocktest"
)

// The harness of the executor's tests: a FreeIPA model (fakeipa_test.go), a lock
// that is held for the run, the entry, the journal and the gate, wired as the
// command layer will wire them.

// fakeEntry is the authorization cache entry. What it does besides answering is a
// test's way to be the entry playbook, which runs between the first read and the
// second.
type fakeEntry struct {
	mu        sync.Mutex
	host      string
	fqdn      string
	prepared  int
	probed    int
	previous  bool
	pending   bool
	err       error
	onPrepare func()
	// result, when set, replaces the answer (another host's, another action).
	result func(AuthCacheAction) AuthCacheResult
}

func (e *fakeEntry) answer(action AuthCacheAction) AuthCacheResult {
	if e.result != nil {
		return e.result(action)
	}
	return AuthCacheResult{Action: action, Host: e.host, FQDN: e.fqdn, Previous: e.previous, Pending: e.pending}
}

func (e *fakeEntry) Prepare(context.Context) (AuthCacheResult, error) {
	e.mu.Lock()
	e.prepared++
	hook := e.onPrepare
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	if e.err != nil {
		return AuthCacheResult{}, e.err
	}
	return e.answer(AuthCachePrepare), nil
}

func (e *fakeEntry) Probe(context.Context) (AuthCacheResult, error) {
	e.mu.Lock()
	e.probed++
	e.mu.Unlock()
	if e.err != nil {
		return AuthCacheResult{}, e.err
	}
	return e.answer(AuthCacheProbe), nil
}

// fakeJournal keeps the events and checks the context each is recorded on.
type fakeJournal struct {
	mu      sync.Mutex
	events  []Event
	failOn  func(Event) error
	problem []string
}

func (j *fakeJournal) Record(ctx context.Context, ev Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := ctx.Err(); err != nil {
		j.problem = append(j.problem, fmt.Sprintf("%s recorded on a cancelled context: %v", ev.ID, err))
	}
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > evidenceAppendTimeout {
		j.problem = append(j.problem, fmt.Sprintf("%s recorded without a bounded deadline", ev.ID))
	}
	if j.failOn != nil {
		if err := j.failOn(ev); err != nil {
			return err
		}
	}
	// Stored as JSON, as the delivery store keeps it: an event whose payload is not
	// encodable is not durable.
	if _, err := json.Marshal(ev.Payload); err != nil {
		return err
	}
	j.events = append(j.events, ev)
	return nil
}

func (j *fakeJournal) ids() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []string
	for _, e := range j.events {
		out = append(out, e.ID)
	}
	return out
}

// all is every event as the JSON a store would hold.
func (j *fakeJournal) all() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var b strings.Builder
	for _, e := range j.events {
		p, _ := json.Marshal(e.Payload)
		fmt.Fprintf(&b, "%s %s %s\n", e.Kind, e.ID, p)
	}
	return b.String()
}

// runEnv is one run's parts.
type runEnv struct {
	t       *testing.T
	f       *fakeIPA
	lock    *identitylocktest.Fake
	held    *identitylock.Held
	ctx     context.Context
	gate    *Gate
	entry   *fakeEntry
	journal *fakeJournal
	opts    Options
	roster  string
}

const testFQDN = "ipa-1.ipa.example.test"

// newRunEnv builds the desired state from the roster document, as the preview and
// the writer both do, takes the lock, and wires the fake's write gate to the Gate.
func newRunEnv(t *testing.T, roster string) *runEnv {
	t.Helper()
	e := &runEnv{t: t, f: newFakeIPA(t), roster: roster, gate: NewGate(), journal: &fakeJournal{}}
	e.lock = &identitylocktest.Fake{Host: "ipa-1"}
	held, err := e.lock.Acquirer()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.held = held
	t.Cleanup(func() { _ = held.Release() })
	e.ctx = held.Attach(context.Background())
	e.entry = &fakeEntry{host: "ipa-1", fqdn: testFQDN}
	e.f.writeGate = e.gate.Check
	pw, err := NewRosterPasswords([]byte(roster))
	if err != nil {
		t.Fatal(err)
	}
	e.opts = Options{Desired: desiredForPlan(t, roster), Passwords: pw, Entry: e.entry, Gate: e.gate, Journal: e.journal}
	return e
}

func (e *runEnv) execute() (*Result, error) {
	e.t.Helper()
	return executeWithin(e.ctx, e.f, e.opts)
}

// returnDeadline is how long a call under test may take before it is taken for a loop
// that does not end. Every call takes milliseconds; the deadline is a ceiling for a
// loaded machine, not a measure.
const returnDeadline = 30 * time.Second

// mustReturn runs fn and panics, naming what, if it has not returned within d. A loop
// that does not end (a batch that is never taken off its list, a batch limit of zero, a
// walk that visits a group twice) would otherwise hang the whole package until go test's
// own timeout and say nothing of where; the panic fails the run at once and names it.
// It reports whether fn returned, for the test of this helper.
func mustReturn(d time.Duration, what string, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		panic(fmt.Sprintf("%s did not return within %s: a loop that does not end", what, d))
	}
}

// executeWithin is Execute under mustReturn.
func executeWithin(ctx context.Context, rpc RPC, opts Options) (res *Result, err error) {
	mustReturn(returnDeadline, "Execute", func() { res, err = Execute(ctx, rpc, opts) })
	return res, err
}

// mustApply runs and fails the test unless the run ended as planned.
func (e *runEnv) mustApply() *Result {
	e.t.Helper()
	res, err := e.execute()
	if err != nil {
		e.t.Fatalf("Execute: %v\nops: %s", err, describeOps(res))
	}
	return res
}

func describeOps(res *Result) string {
	if res == nil {
		return "<no result>"
	}
	var b strings.Builder
	for _, o := range res.Ops {
		fmt.Fprintf(&b, "\n  %s %s %s %s", o.Stage, o.Operation.ID, o.Final(), strings.TrimSpace(o.Error+" "+o.Detail))
	}
	if res.Stop != nil {
		fmt.Fprintf(&b, "\n  stopped at %s: %s", res.Stop.Stage, res.Stop.Reason)
	}
	return b.String()
}

func (r *Result) outcomeOf(id string) Outcome {
	for _, o := range r.Ops {
		if o.Operation.ID == id {
			return o.Final()
		}
	}
	return ""
}

func (r *Result) op(id string) OpResult {
	for _, o := range r.Ops {
		if o.Operation.ID == id {
			return o
		}
	}
	return OpResult{}
}

func mustContain(t *testing.T, haystack, needle, what string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s: %q does not hold %q", what, haystack, needle)
	}
}

func equalStrings(t *testing.T, got, want []string, what string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s:\n got %v\nwant %v", what, got, want)
	}
}
