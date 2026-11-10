package freeiparpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The answers captured for Phase 2, P2-4 (spec §9: K6-K15, K19, K21), and
// the facts the Go identity writer will rely on, each read out of them.
//
// A fact is a function of the captured answers. It runs against the
// committed fixtures and has to hold; it runs again against a copy in which
// one thing the fact reads has been altered (a tamper probe) and has to
// fail, so that a fixture which is swapped, edited or re-captured into a
// different answer cannot go unnoticed. A fixture that no fact reads fails
// TestEveryWriteCaptureHasAFact. The facts that are about how the client
// takes an answer (a write that FreeIPA answered with an error is not an
// unknown outcome; a member command that changed nothing is still a
// success) go through the real Client against a server that serves the
// captured, or tampered, bytes.

// testingT is what a fact needs of the test it runs in.
type testingT = *testing.T

// capturedAnswer is one fixture.
type capturedAnswer struct {
	status int
	body   []byte
}

type captureSet struct {
	files map[string]*capturedAnswer
	read  map[string]bool
}

func loadCaptureSet(t *testing.T) *captureSet {
	t.Helper()
	s := &captureSet{files: map[string]*capturedAnswer{}, read: map[string]bool{}}
	for _, name := range p24Fixtures {
		fx := loadFixture(t, name)
		s.files[name] = &capturedAnswer{status: fx.status, body: fx.body}
	}
	return s
}

func (s *captureSet) clone() *captureSet {
	c := &captureSet{files: map[string]*capturedAnswer{}, read: map[string]bool{}}
	for n, a := range s.files {
		c.files[n] = &capturedAnswer{status: a.status, body: slices.Clone(a.body)}
	}
	return c
}

func (s *captureSet) answer(name string) *capturedAnswer {
	a, ok := s.files[name]
	if !ok {
		panic("no capture named " + name)
	}
	s.read[name] = true
	return a
}

// doc is the whole answer as a JSON document.
func (s *captureSet) doc(name string) map[string]any {
	var d map[string]any
	if err := json.Unmarshal(s.answer(name).body, &d); err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	return d
}

// result is the "result" object of a successful answer, as Call returns it.
func (s *captureSet) result(name string) (json.RawMessage, error) {
	a := s.answer(name)
	if a.status != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", name, a.status)
	}
	return decodeEnvelope(a.body)
}

// entry is result.result of a successful answer: the user or group.
func (s *captureSet) entry(name string) (map[string]any, error) {
	raw, err := s.result(name)
	if err != nil {
		return nil, err
	}
	var r struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.Result == nil {
		return nil, fmt.Errorf("%s: no entry in the result", name)
	}
	return r.Result, nil
}

// findEntryByName is the entry of a find answer (result.result is a list)
// whose attribute attrName holds name, nil when there is none.
func findEntryByName(s *captureSet, name, attrName, want string) map[string]any {
	res, _ := s.doc(name)["result"].(map[string]any)
	list, _ := res["result"].([]any)
	for _, item := range list {
		if e, ok := item.(map[string]any); ok && slices.Contains(attr(e, attrName), want) {
			return e
		}
	}
	return nil
}

// errorOf is the *RPCError of an answer that is one.
func (s *captureSet) errorOf(name string) (*RPCError, error) {
	_, err := s.result(name)
	var re *RPCError
	if !errors.As(err, &re) {
		return nil, fmt.Errorf("%s is not an RPC error: %v", name, err)
	}
	return re, nil
}

// errorData is error.data of an error answer (RPCError keeps no data).
func (s *captureSet) errorData(name string) map[string]any {
	e, _ := s.doc(name)["error"].(map[string]any)
	d, _ := e["data"].(map[string]any)
	return d
}

// serve starts a FreeIPA that answers every command with the captured bytes
// of name, and returns a client logged in to it.
func (s *captureSet) serve(t *testing.T, name string) *Client {
	t.Helper()
	a := s.answer(name)
	f := newFakeServer(t, testFQDN)
	f.hook = func(w http.ResponseWriter, _ string) bool {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(a.status)
		_, _ = w.Write(a.body)
		return true
	}
	c := newTestClient(t, f)
	if err := c.Login(context.Background(), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	return c
}

// call sends cmd to a server that answers with the capture name.
func (s *captureSet) call(t *testing.T, name string, cmd Command) (json.RawMessage, *Client, error) {
	t.Helper()
	c := s.serve(t, name)
	res, err := c.Call(context.Background(), cmd)
	return res, c, err
}

func (s *captureSet) batch(t *testing.T, name string, cmds ...Command) ([]BatchItem, *Client, error) {
	t.Helper()
	c := s.serve(t, name)
	items, err := c.Batch(context.Background(), cmds)
	return items, c, err
}

func (s *captureSet) find(t *testing.T, name, method string, opts map[string]any) ([]map[string]any, error) {
	t.Helper()
	return s.serve(t, name).Find(context.Background(), method, nil, opts)
}

// factCheck collects what a fact finds wrong.
type factCheck struct{ problems []string }

func (c *factCheck) that(ok bool, format string, args ...any) {
	if !ok {
		c.problems = append(c.problems, fmt.Sprintf(format, args...))
	}
}

func (c *factCheck) noError(err error) bool {
	if err != nil {
		c.problems = append(c.problems, err.Error())
		return false
	}
	return true
}

func (c *factCheck) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(c.problems, "; "))
}

// rpc checks that err is FreeIPA's answer named name with code, whose message
// holds message, and that it is an answered error, not an unknown outcome.
func (c *factCheck) rpc(what string, err error, name string, code int, message string) {
	var re *RPCError
	if !errors.As(err, &re) {
		c.problems = append(c.problems, fmt.Sprintf("%s: %v is not an RPC error", what, err))
		return
	}
	c.that(re.Name == name && re.Code == code, "%s: %s (%d), want %s (%d)", what, re.Name, re.Code, name, code)
	c.that(strings.Contains(re.Message, message), "%s: message %q lacks %q", what, re.Message, message)
	c.that(!errors.As(err, new(*OutcomeUnknownError)), "%s: an answered error is read as an unknown outcome", what)
}

// attr is the values of a user or group attribute, nil when it is absent.
func attr(e map[string]any, key string) []string {
	var out []string
	vals, _ := e[key].([]any)
	for _, v := range vals {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// stampOf is the timestamp of a datetime attribute, "" when it is absent.
func stampOf(e map[string]any, key string) (string, error) {
	vals, ok := e[key].([]any)
	if !ok {
		return "", nil
	}
	if len(vals) != 1 {
		return "", fmt.Errorf("%s = %v", key, vals)
	}
	m, ok := vals[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%s = %v is not a datetime", key, vals[0])
	}
	s, _ := m["__datetime__"].(string)
	if !stampFormat.MatchString(s) {
		return "", fmt.Errorf("%s = %q is not YYYYMMDDHHMMSSZ", key, s)
	}
	return s, nil
}

// A probe alters one capture in a copy of the set.
type probe struct {
	name string
	do   func(s *captureSet)
}

func jsonAt(doc any, path []any) (parent any, key any, ok bool) {
	cur := doc
	for i, step := range path {
		isLast := i == len(path)-1
		switch k := step.(type) {
		case string:
			m, isMap := cur.(map[string]any)
			if !isMap {
				return nil, nil, false
			}
			if isLast {
				return m, k, true
			}
			cur = m[k]
		case int:
			l, isList := cur.([]any)
			if !isList || k >= len(l) {
				return nil, nil, false
			}
			if isLast {
				return l, k, true
			}
			cur = l[k]
		}
	}
	return nil, nil, false
}

func (s *captureSet) edit(name string, path []any, change func(parent any, key any)) {
	a := s.files[name]
	var doc any
	if err := json.Unmarshal(a.body, &doc); err != nil {
		panic(err)
	}
	parent, key, ok := jsonAt(doc, path)
	if !ok {
		panic(fmt.Sprintf("tamper path %v is not in %s", path, name))
	}
	change(parent, key)
	body, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	a.body = body
}

// set puts value at path of the capture; the path must exist.
func set(label, name string, value any, path ...any) probe {
	return probe{label, func(s *captureSet) {
		s.edit(name, path, func(parent, key any) {
			switch p := parent.(type) {
			case map[string]any:
				if _, ok := p[key.(string)]; !ok {
					panic(fmt.Sprintf("tamper path %v is not in %s", path, name))
				}
				p[key.(string)] = value
			case []any:
				p[key.(int)] = value
			}
		})
	}}
}

// add puts value at key of the object at path (the key need not exist).
func add(label, name string, value any, path ...any) probe {
	key := path[len(path)-1]
	return probe{label, func(s *captureSet) {
		s.edit(name, path, func(parent, _ any) {
			if m, ok := parent.(map[string]any); ok {
				m[key.(string)] = value
			}
		})
	}}
}

// del removes the key at path.
func del(label, name string, path ...any) probe {
	return probe{label, func(s *captureSet) {
		s.edit(name, path, func(parent, key any) {
			m := parent.(map[string]any)
			if _, ok := m[key.(string)]; !ok {
				panic(fmt.Sprintf("tamper path %v is not in %s", path, name))
			}
			delete(m, key.(string))
		})
	}}
}

// copyValue puts the value at path of the capture from into the same place of
// the capture to: a value that differs from run to run is made the same.
func copyValue(label, from, to string, path ...any) probe {
	return probe{label, func(s *captureSet) {
		var src any
		if err := json.Unmarshal(s.files[from].body, &src); err != nil {
			panic(err)
		}
		parent, key, ok := jsonAt(src, path)
		if !ok {
			panic(fmt.Sprintf("tamper path %v is not in %s", path, from))
		}
		var value any
		switch p := parent.(type) {
		case map[string]any:
			value = p[key.(string)]
		case []any:
			value = p[key.(int)]
		}
		s.edit(to, path, func(parent, key any) {
			switch p := parent.(type) {
			case map[string]any:
				p[key.(string)] = value
			case []any:
				p[key.(int)] = value
			}
		})
	}}
}

// both applies several probes: one alteration made of consistent edits.
func both(label string, ps ...probe) probe {
	return probe{label, func(s *captureSet) {
		for _, p := range ps {
			p.do(s)
		}
	}}
}

// swap makes the capture name hold the answer of another.
func swap(label, name, other string) probe {
	return probe{label, func(s *captureSet) {
		a := s.files[other]
		s.files[name] = &capturedAnswer{status: a.status, body: slices.Clone(a.body)}
	}}
}

// asError turns a successful answer into an error answer.
func asError(label, name string) probe {
	return probe{label, func(s *captureSet) {
		s.files[name].body = []byte(`{"result":null,"error":{"code":4999,"message":"tampered","data":{},"name":"Tampered"},"id":0}`)
	}}
}

// asSuccess turns an error answer into one that succeeded.
func asSuccess(label, name string) probe {
	return probe{label, func(s *captureSet) {
		s.files[name].body = []byte(`{"result":{"result":{},"summary":"tampered","value":"x"},"error":null,"id":0}`)
	}}
}

type captureFact struct {
	id     string
	run    func(t *testing.T, s *captureSet) error
	probes []probe
}

// TestWriteCaptureFacts runs each fact against the committed fixtures, then
// against each tampered copy.
func TestWriteCaptureFacts(t *testing.T) {
	base := loadCaptureSet(t)
	for _, f := range p24Facts() {
		t.Run(f.id, func(t *testing.T) {
			if len(f.probes) == 0 {
				t.Fatal("a fact without a tamper probe")
			}
			if err := f.run(t, base.clone()); err != nil {
				t.Fatalf("the committed captures do not show it: %v", err)
			}
			for _, p := range f.probes {
				t.Run("tamper: "+p.name, func(t *testing.T) {
					s := base.clone()
					p.do(s)
					if err := f.run(t, s); err == nil {
						t.Fatalf("the fact still holds after: %s", p.name)
					}
				})
			}
		})
	}
}

// Every capture is read by a fact: nothing is committed that no assertion
// depends on.
func TestEveryWriteCaptureHasAFact(t *testing.T) {
	s := loadCaptureSet(t)
	for _, f := range p24Facts() {
		if err := f.run(t, s); err != nil {
			t.Fatalf("%s: %v", f.id, err)
		}
	}
	var unread []string
	for _, name := range p24Fixtures {
		if !s.read[name] {
			unread = append(unread, name)
		}
	}
	if len(unread) != 0 {
		t.Fatalf("no fact reads %v", unread)
	}
}

// The committed set is the harness's list, and nothing else of this kind is
// in the directory.
func TestWriteCaptureFilesAreTheHarnessList(t *testing.T) {
	names := captureNames(t, "testdata")
	for _, n := range p24Fixtures {
		if !slices.Contains(names, n) {
			t.Errorf("%s is in the harness list but has no fixture", n)
		}
	}
	if !slices.IsSorted(p24Fixtures) || len(slices.Compact(slices.Clone(p24Fixtures))) != len(p24Fixtures) {
		t.Error("p24Fixtures is not sorted and free of repeats")
	}
}

// headersConstant is the whole of every P2-4 .headers fixture: FreeIPA's
// JSON-RPC answer has one header the tests read, and the harness writes
// exactly this (capture_p24_live_test.go). A fixture with anything more in it
// (a Set-Cookie, a Location, a debugging header) was not written by the
// harness, and the secret scan would not necessarily see it.
const headersConstant = "Content-Type: application/json; charset=utf-8\n"

// headerProblems lists the .headers fixtures of names in dir that are not
// headersConstant.
func headerProblems(dir string, names []string) []string {
	var problems []string
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n+".headers"))
		switch {
		case err != nil:
			problems = append(problems, n+".headers: "+err.Error())
		case string(data) != headersConstant:
			problems = append(problems, fmt.Sprintf("%s.headers is %q, want %q", n, data, headersConstant))
		}
	}
	return problems
}

func TestEveryWriteCaptureHasTheConstantHeaders(t *testing.T) {
	if problems := headerProblems("testdata", p24Fixtures); len(problems) != 0 {
		t.Fatalf("%d fixtures differ:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

// The check fires: a copy of one fixture's headers with something added, with
// the line changed, with no final newline or missing is found, and a copy as
// committed is not.
func TestHeaderProblemsFire(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name+".headers"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ok", headersConstant)
	if got := headerProblems(dir, []string{"ok"}); len(got) != 0 {
		t.Fatalf("the constant line is refused: %v", got)
	}
	for name, content := range map[string]string{
		"extra-header":    headersConstant + "Set-Cookie: ipa_session=0123456789abcdef\n",
		"other-type":      "Content-Type: text/plain\n",
		"no-newline":      strings.TrimSuffix(headersConstant, "\n"),
		"two-lines":       headersConstant + headersConstant,
		"other-charset":   "Content-Type: application/json\n",
		"empty":           "",
		"carriage-return": strings.TrimSuffix(headersConstant, "\n") + "\r\n",
	} {
		write(name, content)
		if got := headerProblems(dir, []string{name}); len(got) != 1 {
			t.Errorf("%s: problems = %v, want one", name, got)
		}
	}
	if got := headerProblems(dir, []string{"missing"}); len(got) != 1 {
		t.Errorf("a missing file: problems = %v, want one", got)
	}
}
