package freeiparpc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The WriteGate (spec docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §7.1): no write method, alone or in a batch, leaves the client while the gate
// refuses it; the server gets no request at all.

// writeMethods is every command the allowlist marks as a write, in name order:
// a method added to the allowlist later is covered without being listed here.
func writeMethods() []string {
	var out []string
	for m, k := range allowlist {
		if k == write {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func readMethods() []string {
	var out []string
	for m, k := range allowlist {
		if k == read && m != "ping" {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// gateRecorder is a gate that keeps what it was asked.
type gateRecorder struct {
	mu      sync.Mutex
	refuse  func(method string) error
	methods []string
	ctxSeen []context.Context
}

func (g *gateRecorder) gate(ctx context.Context, method string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.methods = append(g.methods, method)
	g.ctxSeen = append(g.ctxSeen, ctx)
	if g.refuse != nil {
		return g.refuse(method)
	}
	return nil
}

func (g *gateRecorder) asked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.methods)
}

var errGateClosed = errors.New("the lock is not held")

func closedGate(string) error { return errGateClosed }

// gatedClient is a logged-in client of a server that answers every command
// with a captured answer, with the gate g.
func gatedClient(t *testing.T, g func(context.Context, string) error, mod ...func(*Config)) (*fakeServer, *Client) {
	t.Helper()
	f := newFakeServer(t, testFQDN)
	// A batch is answered by a captured batch of the same size as the one the
	// tests send (3 for the writes, 4 for the reads).
	f.answer = func(method string, params []any) string {
		if method == "batch" {
			if items, _ := params[0].([]any); len(items) == 4 {
				return "batch-show-one-missing"
			}
			return "batch-group-add-duplicate"
		}
		return "user-show"
	}
	c := newTestClient(t, f, append([]func(*Config){func(c *Config) { c.WriteGate = g }}, mod...)...)
	if err := c.Login(context.Background(), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	return f, c
}

// zeroRequestProblems is the property of the gate: every write method called on
// its own and every batch that holds a write is answered by *ErrWriteRefused,
// the server saw no command, and the client counted no write. It returns what
// is wrong, so that a test can also run it against a gate that is open and
// require it to find something.
func zeroRequestProblems(t *testing.T, g func(context.Context, string) error) []string {
	t.Helper()
	var problems []string
	f, c := gatedClient(t, g)
	ctx := context.Background()
	for _, m := range writeMethods() {
		_, err := c.Call(ctx, Command{Method: m, Args: []any{"x"}})
		var refused *ErrWriteRefused
		if !errors.As(err, &refused) || refused.Method != m {
			problems = append(problems, fmt.Sprintf("Call %s: %v, want a refusal naming the method", m, err))
		}
		if errors.As(err, new(*OutcomeUnknownError)) {
			problems = append(problems, fmt.Sprintf("Call %s: a refusal read as an unknown outcome", m))
		}
		// A batch whose first command is a read and whose last is the write: the
		// read must not be sent either.
		_, err = c.Batch(ctx, []Command{{Method: "user_show", Args: []any{"x"}}, {Method: m, Args: []any{"x"}}})
		if !errors.As(err, &refused) || refused.Method != m {
			problems = append(problems, fmt.Sprintf("Batch with %s: %v, want a refusal naming the method", m, err))
		}
	}
	if got := f.methods(); len(got) != 0 {
		problems = append(problems, fmt.Sprintf("the server received %v, want no command at all", got))
	}
	if s := c.Stats(); s.Writes != 0 || s.Reads != 0 || s.Unknown != 0 {
		problems = append(problems, fmt.Sprintf("stats after the refusals: %+v, want no read, write or unknown outcome", s))
	}
	return problems
}

func TestWriteGateRefusesEveryWriteMethodAndBatchWithZeroRequests(t *testing.T) {
	if got := writeMethods(); len(got) != 11 {
		t.Fatalf("the allowlist has %d write methods %v; spec §7.1 names 11 (a new one needs this test and the spec read again)", len(got), got)
	}
	if problems := zeroRequestProblems(t, func(context.Context, string) error { return errGateClosed }); len(problems) != 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
}

// The zero-request property is not satisfied by accident: a gate that is always
// open, and a client that never asks its gate, both fail it.
func TestZeroRequestPropertyFailsForAnAlwaysOpenGate(t *testing.T) {
	problems := zeroRequestProblems(t, openGate)
	if len(problems) < len(writeMethods()) {
		t.Fatalf("an always-open gate passed the zero-request check: %d problems %v", len(problems), problems)
	}
}

func TestWriteGateIsAskedForEachWriteWithTheCallContextAndMethod(t *testing.T) {
	type ctxKey struct{}
	rec := &gateRecorder{}
	f, c := gatedClient(t, rec.gate)
	ctx := context.WithValue(context.Background(), ctxKey{}, "this run")
	if _, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Batch(ctx, []Command{{Method: "user_show", Args: []any{"x"}}, {Method: "group_add", Args: []any{"g"}}, {Method: "group_del", Args: []any{"g"}}}); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.asked(), []string{"user_mod", "group_add", "group_del"}; !slices.Equal(got, want) {
		t.Fatalf("the gate was asked about %v, want the writes in order: %v", got, want)
	}
	for i, got := range rec.ctxSeen {
		if got.Value(ctxKey{}) != "this run" {
			t.Fatalf("question %d: the gate did not get the call's context", i)
		}
	}
	if s := c.Stats(); s.Writes != 3 || s.Reads != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if got := f.methods(); !slices.Equal(got, []string{"user_mod", "batch"}) {
		t.Fatalf("the server received %v", got)
	}
}

// A batch is refused whole: one write the gate refuses keeps the writes the gate
// would have allowed from leaving with it.
func TestWriteGateRefusesTheWholeBatchForOneRefusedWrite(t *testing.T) {
	rec := &gateRecorder{refuse: func(m string) error {
		if m == "user_del" {
			return errGateClosed
		}
		return nil
	}}
	f, c := gatedClient(t, rec.gate)
	_, err := c.Batch(context.Background(), []Command{{Method: "group_add", Args: []any{"g"}}, {Method: "user_del", Args: []any{"u"}}, {Method: "group_del", Args: []any{"g"}}})
	var refused *ErrWriteRefused
	if !errors.As(err, &refused) || refused.Method != "user_del" || !errors.Is(err, errGateClosed) {
		t.Fatalf("err = %v, want a refusal of user_del that wraps the gate's reason", err)
	}
	if got := f.methods(); len(got) != 0 {
		t.Fatalf("the server received %v: the writes before and after the refused one must not leave", got)
	}
	if got := c.Stats().Writes; got != 0 {
		t.Fatalf("writes = %d", got)
	}
}

// Reads are not the gate's business, and a client that is ReadOnly never asks
// it: the refusal of a write on a read-only client is the old one.
func TestWriteGateDoesNotTouchReadsOrReadOnlyClients(t *testing.T) {
	rec := &gateRecorder{refuse: closedGate}
	f, c := gatedClient(t, rec.gate)
	for _, m := range readMethods() {
		if _, err := c.Call(context.Background(), Command{Method: m, Args: []any{"x"}}); err != nil {
			t.Fatalf("a closed gate refused the read %s: %v", m, err)
		}
	}
	if _, err := c.Batch(context.Background(), []Command{{Method: "user_show", Args: []any{"x"}}, {Method: "user_show", Args: []any{"y"}}, {Method: "group_show", Args: []any{"x"}}, {Method: "group_show", Args: []any{"y"}}}); err != nil {
		t.Fatalf("a closed gate refused a batch of reads: %v", err)
	}
	if got := rec.asked(); len(got) != 0 {
		t.Fatalf("the gate was asked about reads: %v", got)
	}
	if len(f.methods()) == 0 {
		t.Fatal("the reads did not reach the server")
	}

	roRec := &gateRecorder{}
	f2, ro := gatedClient(t, roRec.gate, func(c *Config) { c.ReadOnly = true })
	for _, m := range writeMethods() {
		_, err := ro.Call(context.Background(), Command{Method: m, Args: []any{"x"}})
		var na *ErrMethodNotAllowed
		if !errors.As(err, &na) || !na.ReadOnly {
			t.Fatalf("%s on a read-only client: %v", m, err)
		}
	}
	if len(roRec.asked()) != 0 || len(f2.methods()) != 0 {
		t.Fatalf("a read-only client asked the gate %v or sent %v", roRec.asked(), f2.methods())
	}
}

// New: a client that may write has a gate, or says it will not write.
func TestNewRefusesAWriterWithoutAGate(t *testing.T) {
	f := newFakeServer(t, testFQDN)
	base := Config{FQDN: testFQDN, CA: f.ca, DialContext: f.dial}
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "WriteGate") {
		t.Fatalf("New without a gate and not read-only = %v, want the WriteGate refusal", err)
	}
	ro := base
	ro.ReadOnly = true
	if _, err := New(ro); err != nil {
		t.Fatalf("a read-only client needs no gate: %v", err)
	}
	gated := base
	gated.WriteGate = openGate
	if _, err := New(gated); err != nil {
		t.Fatalf("a client with a gate: %v", err)
	}
}
