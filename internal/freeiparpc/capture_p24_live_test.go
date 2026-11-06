package freeiparpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The capture harness of Phase 2, P2-4: it sends the writes the Go identity
// writer will rely on to a disposable FreeIPA server through the SSH tunnel
// and keeps what the server answered as fixtures (testdata/<name>.status,
// .headers and .json, the files every earlier capture here has).
// docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §9
// lists the captures (K6-K15, K19, K21) and what each decides.
//
// It is a live test: it runs only when PILOT_FREEIPA_LIVE_SSH,
// IPA_ADMIN_PASSWORD and PILOT_FREEIPA_CAPTURE_DIR are set. The variables of
// live_test.go name the server; the capture directory must exist and be
// empty. For example, from a clean clone of the candidate:
//
//	PILOT_FREEIPA_LIVE_SSH=root@<server> PILOT_FREEIPA_LIVE_SSH_KEY=<key> \
//	PILOT_FREEIPA_LIVE_SSH_OPTS=StrictHostKeyChecking=no,UserKnownHostsFile=/dev/null \
//	IPA_ADMIN_PASSWORD="$(cat <file>)" PILOT_FREEIPA_CAPTURE_DIR=<empty dir> \
//	go test ./internal/freeiparpc -run '^TestLiveCaptureP24$' -count=1 -v
//
// TestCaptureDirMatchesFixtures then compares the new directory with the
// committed fixtures.
//
// What it does to the server, and undoes: every object it creates is named
// p24cap-*, the password policies it needs are one per test group (the
// global policy is never changed), and a sweep at the end (and at the start,
// which refuses to run on leftovers) deletes everything with that prefix, the
// history markers it created and the policies; the sweep is checked.
//
// Secrets (AGENTS.md §5.6, the committed-secrets rule): the raw answers are
// never written. Each is passed through redactCapture first, which replaces
// the value of every secret-bearing attribute with the placeholder the
// fixture-secret test accepts. The one-time passwords the passwd captures
// send are random, carry the prefix p24CapPasswordPrefix, are never logged
// and never stored: no request is kept, and before a fixture is written the
// harness checks that none of the passwords it generated is in it.

// p24CapPasswordPrefix starts every password the harness sends, so that a
// scan of the fixture directory can find one without knowing its value
// (TestFixtureDirectoryHoldsNoPassword).
const p24CapPasswordPrefix = "P24Cap"

const p24CapPrefix = "p24cap-"

// captureAnswer is one answer of the server.
type captureAnswer struct {
	status  int
	errName string
	errCode int
	body    []byte // as the server sent it; never written or logged
}

func (a captureAnswer) ok() bool { return a.status == 200 && a.errName == "" }

type p24Capture struct {
	t       *testing.T
	c       *Client
	dir     string
	secrets []string // every password sent, which no fixture may hold
	names   map[string]bool
	order   []string
	made    []string // markers and policies to delete in the sweep
	redact  int
}

func (p *p24Capture) post(body []byte) (int, []byte) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for attempt := 0; ; attempt++ {
		resp, raw, err := p.c.post(ctx, "/ipa/session/json", "application/json", "application/json", body)
		if err != nil {
			p.t.Fatalf("post: %v", err)
		}
		if resp.StatusCode == 401 && attempt == 0 {
			p.c.mu.Lock()
			cr := p.c.creds
			p.c.mu.Unlock()
			if err := p.c.login(ctx, cr); err != nil {
				p.t.Fatalf("login again: %v", err)
			}
			continue
		}
		return resp.StatusCode, raw
	}
}

func decodeCaptureAnswer(status int, raw []byte) captureAnswer {
	a := captureAnswer{status: status, body: raw}
	var env struct {
		Error *struct {
			Name string `json:"name"`
			Code int    `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && env.Error != nil {
		a.errName, a.errCode = env.Error.Name, env.Error.Code
	}
	return a
}

// send posts one command (or a batch) and, when name is not empty, keeps the
// answer as the fixture name.
func (p *p24Capture) send(name string, req request) captureAnswer {
	p.t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		p.t.Fatal(err)
	}
	status, raw := p.post(body)
	a := decodeCaptureAnswer(status, raw)
	if name != "" {
		p.keep(name, a)
		got := "ok"
		if a.errName != "" {
			got = fmt.Sprintf("%s (%d)", a.errName, a.errCode)
		}
		p.t.Logf("%-46s %s HTTP %d %s", name, req.Method, a.status, got)
	}
	return a
}

func (p *p24Capture) rpc(name, method string, args []any, opts map[string]any) captureAnswer {
	p.t.Helper()
	cmd := Command{Method: method, Args: args, Options: opts}
	return p.send(name, request{Method: method, Params: cmd.params()})
}

func (p *p24Capture) batch(name string, cmds ...Command) captureAnswer {
	p.t.Helper()
	items := make([]map[string]any, 0, len(cmds))
	for _, c := range cmds {
		items = append(items, map[string]any{"method": c.Method, "params": c.params()})
	}
	return p.send(name, request{Method: "batch", Params: [2]any{items, map[string]any{"version": apiVersion}}})
}

// keep writes the three files of a fixture, after redaction.
func (p *p24Capture) keep(name string, a captureAnswer) {
	p.t.Helper()
	if p.names[name] {
		p.t.Fatalf("capture %s is written twice", name)
	}
	p.names[name] = true
	p.order = append(p.order, name)
	out, n, err := redactCapture(a.body)
	if err != nil {
		p.t.Fatalf("capture %s: %v", name, err)
	}
	p.redact += n
	for _, s := range p.secrets {
		if bytes.Contains(out, []byte(s)) {
			p.t.Fatalf("capture %s holds a password the harness sent; nothing is written for it", name)
		}
	}
	base := filepath.Join(p.dir, name)
	files := map[string][]byte{
		".status":  []byte(fmt.Sprintf("%d\n", a.status)),
		".headers": []byte("Content-Type: application/json; charset=utf-8\n"),
		".json":    out,
	}
	for ext, data := range files {
		if err := os.WriteFile(base+ext, data, 0o644); err != nil {
			p.t.Fatal(err)
		}
	}
}

// need fails the harness unless a setup call succeeded.
func (p *p24Capture) need(a captureAnswer, what string) captureAnswer {
	p.t.Helper()
	if !a.ok() {
		p.t.Fatalf("%s: HTTP %d, %s (%d)", what, a.status, a.errName, a.errCode)
	}
	return a
}

// wantErr fails the harness unless the answer is the error the fixture is
// named for: a capture must show what its name says.
func (p *p24Capture) wantErr(a captureAnswer, errName string, what string) captureAnswer {
	p.t.Helper()
	if a.status != 200 || a.errName != errName {
		p.t.Fatalf("%s: HTTP %d, %q (%d); the capture is named for %s", what, a.status, a.errName, a.errCode, errName)
	}
	return a
}

func (p *p24Capture) password() string {
	p.t.Helper()
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		p.t.Fatal(err)
	}
	s := p24CapPasswordPrefix + "-" + hex.EncodeToString(b)
	p.secrets = append(p.secrets, s)
	return s
}

// shortPassword is shorter than the global policy's minimum of 8.
func (p *p24Capture) shortPassword() string {
	p.t.Helper()
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		p.t.Fatal(err)
	}
	s := p24CapPasswordPrefix + hex.EncodeToString(b)[:1]
	p.secrets = append(p.secrets, s)
	return s
}

// lowerPassword is long enough and has three character classes (upper,
// lower, digit): too few for a policy that asks for four.
func (p *p24Capture) lowerPassword() string {
	p.t.Helper()
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		p.t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString(p24CapPasswordPrefix + "x")
	for _, c := range b {
		sb.WriteByte('a' + c%26)
	}
	s := sb.String()
	p.secrets = append(p.secrets, s)
	return s
}

func capUser(n string) string { return p24CapPrefix + n }

// markerOf is HistoryMarkerName; internal/identityreconcile cannot be
// imported here (the writer will import this package), so the formula is
// repeated and TestMarkerFixtureMatchesTheCode in identityreconcile holds the
// two together.
func markerOf(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "pilot-internal-history-g-" + hex.EncodeToString(sum[:])
}

func (p *p24Capture) addUser(name string, opts map[string]any) {
	p.t.Helper()
	o := map[string]any{"givenname": "P24", "sn": "Cap"}
	for k, v := range opts {
		o[k] = v
	}
	p.need(p.rpc("", "user_add", []any{name}, o), "setup user_add "+name)
}

func (p *p24Capture) addGroup(name string, opts map[string]any) {
	p.t.Helper()
	p.need(p.rpc("", "group_add", []any{name}, opts), "setup group_add "+name)
}

func (p *p24Capture) members(group, kind string, names ...string) {
	p.t.Helper()
	list := make([]any, len(names))
	for i, n := range names {
		list[i] = n
	}
	p.need(p.rpc("", "group_add_member", []any{group}, map[string]any{kind: list}), "setup group_add_member "+group)
}

func (p *p24Capture) showAll(name, method, object string) captureAnswer {
	p.t.Helper()
	return p.rpc(name, method, []any{object}, map[string]any{"all": true})
}

// found lists the names a find answers with under key (uid or cn).
func (p *p24Capture) found(method string, key string, opts map[string]any) []string {
	p.t.Helper()
	o := map[string]any{"sizelimit": 0, "timelimit": 0}
	for k, v := range opts {
		o[k] = v
	}
	a := p.rpc("", method, []any{p24CapPrefix}, o)
	p.need(a, method)
	var env struct {
		Result struct {
			Result []map[string]any `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(a.body, &env); err != nil {
		p.t.Fatal(err)
	}
	var names []string
	for _, e := range env.Result.Result {
		if l, ok := e[key].([]any); ok && len(l) == 1 {
			names = append(names, fmt.Sprint(l[0]))
		}
	}
	return names
}

// leftovers names what the harness may have left on the server.
func (p *p24Capture) leftovers() []string {
	p.t.Helper()
	var left []string
	for _, u := range p.found("user_find", "uid", nil) {
		left = append(left, "user "+u)
	}
	for _, u := range p.found("user_find", "uid", map[string]any{"preserved": true}) {
		left = append(left, "preserved user "+u)
	}
	for _, g := range p.found("group_find", "cn", nil) {
		left = append(left, "group "+g)
	}
	for _, m := range p.made {
		if a := p.rpc("", "group_show", []any{m}, nil); a.ok() {
			left = append(left, "marker "+m)
		}
	}
	for _, pol := range []string{"pg0", "pgc", "pgh"} {
		if a := p.rpc("", "pwpolicy_show", []any{capUser(pol)}, nil); a.ok() {
			left = append(left, "policy "+capUser(pol))
		}
	}
	sort.Strings(left)
	return left
}

// sweep deletes everything the harness may have created. Policies first (a
// policy belongs to a group), then users (their private groups go with them),
// then the groups and the markers.
func (p *p24Capture) sweep() {
	p.t.Helper()
	for _, pol := range []string{"pg0", "pgc", "pgh"} {
		_ = p.rpc("", "pwpolicy_del", []any{capUser(pol)}, nil)
	}
	for _, u := range p.found("user_find", "uid", map[string]any{"preserved": true}) {
		_ = p.rpc("", "user_del", []any{u}, nil)
	}
	for _, u := range p.found("user_find", "uid", nil) {
		_ = p.rpc("", "user_del", []any{u}, nil)
	}
	for _, g := range p.found("group_find", "cn", nil) {
		_ = p.rpc("", "group_del", []any{g}, nil)
	}
	for _, m := range p.made {
		_ = p.rpc("", "group_del", []any{m}, nil)
	}
}

func liveCaptureDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PILOT_FREEIPA_CAPTURE_DIR")
	if dir == "" {
		t.Skip("PILOT_FREEIPA_CAPTURE_DIR is not set")
	}
	return dir
}

func TestLiveCaptureP24(t *testing.T) {
	dir := liveCaptureDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s is not empty; give the capture a new directory", dir)
	}
	e := setupLive(t)
	p := &p24Capture{t: t, c: e.admin(t), dir: dir, names: map[string]bool{}}
	t.Cleanup(p.c.CloseIdleConnections)

	if left := p.leftovers(); len(left) != 0 {
		t.Fatalf("the server holds leftovers of an earlier run: %v", left)
	}
	t.Cleanup(func() {
		p.sweep()
		if left := p.leftovers(); len(left) != 0 {
			t.Errorf("the sweep left %v", left)
		}
	})

	p.captureUserFields()
	p.capturePasswd()
	p.captureUserLifecycle()
	p.captureGroups()
	p.captureMarkers()
	p.captureMembers()
	p.captureBatches()
	p.captureEmptyValues()

	t.Logf("%d fixtures written; %d secret-bearing values replaced by the placeholder", len(p.order), p.redact)
	// The one-time passwords must be in no file of the capture directory.
	if hits := scanDirForLiterals(t, dir, p.secrets); len(hits) != 0 {
		t.Fatalf("a password the harness sent is in %v", hits)
	}
}

// K14: the option names of user_add and user_mod, and how mail is replaced.
func (p *p24Capture) captureUserFields() {
	t := p.t
	u1, u2, u3 := capUser("u1"), capUser("u2"), capUser("u3")
	mail := func(n string) string { return capUser(n) + "@example.test" }

	p.need(p.rpc("user-add-all-options", "user_add", []any{u1}, map[string]any{
		"givenname": "P24", "sn": "One", "displayname": "P24 One Display", "mail": mail("u1"),
		"loginshell": "/bin/bash", "homedirectory": "/srv/home/" + u1,
	}), "user-add-all-options")
	p.need(p.showAll("user-show-all-options", "user_show", u1), "user-show-all-options")

	p.need(p.rpc("user-add-default-mail", "user_add", []any{u2}, map[string]any{"givenname": "P24", "sn": "Two"}), "user-add-default-mail")
	p.need(p.rpc("user-add-mail-two", "user_add", []any{u3}, map[string]any{
		"givenname": "P24", "sn": "Three", "mail": []any{mail("u3-a"), mail("u3-b")},
	}), "user-add-mail-two")

	// mail: one list replaces the whole set; the same set again is no change.
	p.need(p.rpc("user-mod-mail-replace", "user_mod", []any{u3}, map[string]any{"mail": []any{mail("u3-c")}}), "user-mod-mail-replace")
	p.need(p.showAll("user-show-after-mail-replace", "user_show", u3), "user-show-after-mail-replace")
	p.wantErr(p.rpc("user-mod-mail-same", "user_mod", []any{u3}, map[string]any{"mail": []any{mail("u3-c")}}), "EmptyModlist", "user-mod-mail-same")
	p.wantErr(p.rpc("user-mod-mail-same-string", "user_mod", []any{u3}, map[string]any{"mail": mail("u3-c")}), "EmptyModlist", "user-mod-mail-same-string")
	p.rpc("user-mod-mail-case", "user_mod", []any{u3}, map[string]any{"mail": []any{strings.ToUpper(mail("u3-c"))}})
	p.need(p.rpc("user-mod-mail-two", "user_mod", []any{u3}, map[string]any{"mail": []any{mail("u3-a"), mail("u3-b")}}), "user-mod-mail-two")
	// the order of the same two addresses
	p.rpc("user-mod-mail-two-reordered", "user_mod", []any{u3}, map[string]any{"mail": []any{mail("u3-b"), mail("u3-a")}})

	// the other options, one call for several, then one alone, then nothing
	p.need(p.rpc("user-mod-fields", "user_mod", []any{u1}, map[string]any{
		"givenname": "P24x", "sn": "Onex", "displayname": "P24 One Display 2", "loginshell": "/bin/zsh", "homedirectory": "/srv/home/" + u1 + "-2",
	}), "user-mod-fields")
	p.need(p.rpc("user-mod-loginshell-only", "user_mod", []any{u1}, map[string]any{"loginshell": "/bin/sh"}), "user-mod-loginshell-only")
	p.need(p.showAll("user-show-after-loginshell-only", "user_show", u1), "user-show-after-loginshell-only")
	p.wantErr(p.rpc("user-mod-no-change", "user_mod", []any{u1}, map[string]any{"loginshell": "/bin/sh"}), "EmptyModlist", "user-mod-no-change")
	p.wantErr(p.rpc("user-mod-not-found", "user_mod", []any{capUser("nobody")}, map[string]any{"loginshell": "/bin/sh"}), "NotFound", "user-mod-not-found")
	p.wantErr(p.rpc("user-enable-not-found", "user_enable", []any{capUser("nobody")}, nil), "NotFound", "user-enable-not-found")
	p.wantErr(p.rpc("user-disable-not-found", "user_disable", []any{capUser("nobody")}, nil), "NotFound", "user-disable-not-found")
	// neither the CLI's flag names nor the roster's key names are the API's
	// option names, and the server says so instead of ignoring them
	for name, key := range map[string]string{"user-add-unknown-option-first": "first", "user-add-unknown-option-display-name": "display_name"} {
		a := p.rpc(name, "user_add", []any{capUser("uopt")}, map[string]any{"givenname": "P24", "sn": "Opt", key: "x"})
		if a.ok() {
			t.Logf("user_add with the option %s was accepted; it is cleaned up in the sweep", key)
		}
	}
}

// K6: passwd, what the password policy does to it, and the timestamps
// user_show carries afterwards.
func (p *p24Capture) capturePasswd() {
	pw, pw0, pwc, pwh := capUser("pw"), capUser("pw0"), capUser("pwc"), capUser("pwh")

	p.need(p.rpc("pwpolicy-show-global-at-capture", "pwpolicy_show", nil, map[string]any{"all": true}), "global policy")
	p.addUser(pw, nil)
	p.need(p.showAll("user-show-no-password", "user_show", pw), "user-show-no-password")
	p.need(p.rpc("passwd-success", "passwd", []any{pw}, map[string]any{"password": p.password()}), "passwd-success")
	p.need(p.showAll("user-show-after-passwd", "user_show", pw), "user-show-after-passwd")
	p.need(p.rpc("passwd-success-again", "passwd", []any{pw}, map[string]any{"password": p.password()}), "passwd-success-again")
	p.need(p.showAll("user-show-after-passwd-again", "user_show", pw), "user-show-after-passwd-again")
	// shorter than the global policy's minimum
	p.rpc("passwd-short-password", "passwd", []any{pw}, map[string]any{"password": p.shortPassword()})
	p.wantErr(p.rpc("passwd-not-found", "passwd", []any{capUser("nobody")}, map[string]any{"password": p.password()}), "EmptyResult", "passwd-not-found")
	p.rpc("passwd-empty-password", "passwd", []any{pw}, map[string]any{"password": ""})

	// maxlife 0: a group policy that applies to one user, so that the global
	// policy stays as it is.
	g0 := capUser("pg0")
	p.addGroup(g0, nil)
	p.addUser(pw0, nil)
	p.members(g0, "user", pw0)
	p.need(p.rpc("", "pwpolicy_add", []any{g0}, map[string]any{"krbmaxpwdlife": 0, "cospriority": 1}), "pwpolicy_add "+g0)
	p.need(p.rpc("pwpolicy-show-maxlife0", "pwpolicy_show", []any{g0}, map[string]any{"all": true}), "pwpolicy-show-maxlife0")
	p.need(p.rpc("passwd-success-maxlife0", "passwd", []any{pw0}, map[string]any{"password": p.password()}), "passwd-success-maxlife0")
	p.need(p.showAll("user-show-after-passwd-maxlife0", "user_show", pw0), "user-show-after-passwd-maxlife0")

	// a policy that asks for four character classes
	gc := capUser("pgc")
	p.addGroup(gc, nil)
	p.addUser(pwc, nil)
	p.members(gc, "user", pwc)
	p.need(p.rpc("", "pwpolicy_add", []any{gc}, map[string]any{"krbpwdmindiffchars": 4, "cospriority": 2}), "pwpolicy_add "+gc)
	p.need(p.rpc("pwpolicy-show-classes4", "pwpolicy_show", []any{gc}, map[string]any{"all": true}), "pwpolicy-show-classes4")
	p.rpc("passwd-few-classes", "passwd", []any{pwc}, map[string]any{"password": p.lowerPassword()})

	// a policy that remembers three passwords: the same one twice
	gh := capUser("pgh")
	p.addGroup(gh, nil)
	p.addUser(pwh, nil)
	p.members(gh, "user", pwh)
	p.need(p.rpc("", "pwpolicy_add", []any{gh}, map[string]any{"krbpwdhistorylength": 3, "cospriority": 3}), "pwpolicy_add "+gh)
	p.need(p.rpc("pwpolicy-show-history3", "pwpolicy_show", []any{gh}, map[string]any{"all": true}), "pwpolicy-show-history3")
	same := p.password()
	p.need(p.rpc("", "passwd", []any{pwh}, map[string]any{"password": same}), "passwd "+pwh)
	p.need(p.showAll("user-show-before-rejected-passwd", "user_show", pwh), "user-show-before-rejected-passwd")
	p.wantErr(p.rpc("passwd-reuse-rejected", "passwd", []any{pwh}, map[string]any{"password": same}), "DatabaseError", "passwd-reuse-rejected")
	p.need(p.showAll("user-show-after-rejected-passwd", "user_show", pwh), "user-show-after-rejected-passwd")

	for _, pol := range []string{g0, gc, gh} {
		p.need(p.rpc("", "pwpolicy_del", []any{pol}, nil), "pwpolicy_del "+pol)
	}
}

// K7 and K19: deleting, preserving, disabling.
func (p *p24Capture) captureUserLifecycle() {
	ud, up, ux, gu := capUser("ud"), capUser("up"), capUser("ux"), capUser("gu")

	p.addGroup(gu, nil)
	p.addUser(ud, nil)
	p.addUser(up, nil)
	p.addUser(ux, nil)
	p.members(gu, "user", ud, up, ux)

	p.need(p.rpc("", "user_disable", []any{ud}, nil), "user_disable")
	p.need(p.showAll("user-show-disabled", "user_show", ud), "user-show-disabled")

	p.need(p.showAll("group-show-before-user-del", "group_show", gu), "group-show-before-user-del")
	p.need(p.rpc("user-del", "user_del", []any{ux}, nil), "user-del")
	p.wantErr(p.rpc("user-del-not-found", "user_del", []any{ux}, nil), "NotFound", "user-del-not-found")
	p.need(p.showAll("group-show-after-user-del", "group_show", gu), "group-show-after-user-del")
	p.wantErr(p.rpc("group-show-private-group-after-user-del", "group_show", []any{ux}, nil), "NotFound", "private group of a deleted user")

	p.need(p.rpc("user-del-preserve", "user_del", []any{up}, map[string]any{"preserve": true}), "user-del-preserve")
	p.rpc("user-show-preserved", "user_show", []any{up}, map[string]any{"all": true})
	p.need(p.showAll("group-show-after-preserve", "group_show", gu), "group-show-after-preserve")
	p.rpc("user-add-duplicate-preserved", "user_add", []any{up}, map[string]any{"givenname": "P24", "sn": "Again"})
	p.rpc("user-del-preserved", "user_del", []any{up}, nil)
	p.wantErr(p.rpc("user-show-after-permanent-delete", "user_show", []any{up}, nil), "NotFound", "a deleted preserved user")

	// deleted and added again under the same name: another account
	ur := capUser("ur")
	p.addUser(ur, nil)
	p.need(p.showAll("user-show-before-recreate", "user_show", ur), "user-show-before-recreate")
	p.need(p.rpc("", "user_del", []any{ur}, nil), "user_del "+ur)
	p.addUser(ur, nil)
	p.need(p.showAll("user-show-after-recreate", "user_show", ur), "user-show-after-recreate")
}

// K8, K9, K11: group_mod, group_del, group_add duplicates.
func (p *p24Capture) captureGroups() {
	g1, gd, gx := capUser("g1"), capUser("gd"), capUser("gx")

	p.addGroup(g1, map[string]any{"description": "P24 group one"})
	p.addUser(capUser("gdup"), nil)

	p.wantErr(p.rpc("group-add-duplicate", "group_add", []any{g1}, map[string]any{"description": "P24 again"}), "DuplicateEntry", "group-add-duplicate")
	p.rpc("group-add-duplicate-case", "group_add", []any{strings.ToUpper(g1)}, map[string]any{"description": "P24 case"})
	p.wantErr(p.rpc("group-add-duplicate-private-group", "group_add", []any{capUser("gdup")}, map[string]any{"description": "P24 like a user"}), "DuplicateEntry", "group-add-duplicate-private-group")

	p.need(p.rpc("group-mod-description", "group_mod", []any{g1}, map[string]any{"description": "P24 group one, changed"}), "group-mod-description")
	p.wantErr(p.rpc("group-mod-no-change", "group_mod", []any{g1}, map[string]any{"description": "P24 group one, changed"}), "EmptyModlist", "group-mod-no-change")
	p.wantErr(p.rpc("group-mod-not-found", "group_mod", []any{gx}, map[string]any{"description": "P24 nobody"}), "NotFound", "group-mod-not-found")

	p.addGroup(gd, map[string]any{"description": "P24 to delete"})
	p.need(p.rpc("group-del", "group_del", []any{gd}, nil), "group-del")
	p.wantErr(p.rpc("group-del-not-found", "group_del", []any{gd}, nil), "NotFound", "group-del-not-found")

	// deleted and added again under the same name: another group
	gr := capUser("gr")
	p.addGroup(gr, nil)
	p.need(p.showAll("group-show-before-recreate", "group_show", gr), "group-show-before-recreate")
	p.need(p.rpc("", "group_del", []any{gr}, nil), "group_del "+gr)
	p.addGroup(gr, nil)
	p.need(p.showAll("group-show-after-recreate", "group_show", gr), "group-show-after-recreate")
}

// K10: the history marker.
func (p *p24Capture) captureMarkers() {
	roster := capUser("gmk")
	marker := markerOf(roster)
	p.made = append(p.made, marker)
	desc := "pilot.group-history/v1 name=" + roster

	p.need(p.rpc("group-add-marker", "group_add", []any{marker}, map[string]any{"nonposix": true, "description": desc}), "group-add-marker")
	p.need(p.showAll("group-show-marker", "group_show", marker), "group-show-marker")
	p.need(p.rpc("group-find-marker", "group_find", nil, map[string]any{"cn": marker, "all": true, "sizelimit": 0, "timelimit": 0}), "group-find-marker")
	p.wantErr(p.rpc("group-add-marker-duplicate", "group_add", []any{marker}, map[string]any{"nonposix": true, "description": desc}), "DuplicateEntry", "group-add-marker-duplicate")
	// a marker whose description is not the expected one, as an operator's group of that name would have
	p.need(p.rpc("", "group_mod", []any{marker}, map[string]any{"description": "not the marker description"}), "group_mod marker")
	p.need(p.showAll("group-show-marker-changed", "group_show", marker), "group-show-marker-changed")
}

// K12, K13, K19: members.
func (p *p24Capture) captureMembers() {
	g1, g2, g3, m1, m2, m3 := capUser("mg1"), capUser("mg2"), capUser("mg3"), capUser("m1"), capUser("m2"), capUser("m3")
	for _, g := range []string{g1, g2, g3} {
		p.addGroup(g, nil)
	}
	for _, u := range []string{m1, m2, m3} {
		p.addUser(u, nil)
	}

	p.need(p.rpc("group-add-member-group", "group_add_member", []any{g1}, map[string]any{"group": []any{g2}}), "group-add-member-group")
	p.need(p.rpc("group-add-member-group-already", "group_add_member", []any{g1}, map[string]any{"group": []any{g2}}), "group-add-member-group-already")
	p.need(p.rpc("group-add-member-group-missing", "group_add_member", []any{g1}, map[string]any{"group": []any{capUser("nogroup")}}), "group-add-member-group-missing")
	p.rpc("group-add-member-group-itself", "group_add_member", []any{g1}, map[string]any{"group": []any{g1}})
	p.wantErr(p.rpc("group-add-member-to-missing-group", "group_add_member", []any{capUser("nogroup")}, map[string]any{"group": []any{g2}}), "NotFound", "group-add-member-to-missing-group")
	p.need(p.rpc("group-add-member-groups-two", "group_add_member", []any{g1}, map[string]any{"group": []any{g3}}), "group-add-member-groups-two")
	p.members(g1, "user", m1, m2)
	p.members(g2, "user", m3)

	p.need(p.showAll("group-show-members", "group_show", g1), "group-show-members")
	p.need(p.showAll("user-show-member", "user_show", m1), "user-show-member")

	p.need(p.rpc("group-remove-member-users", "group_remove_member", []any{g1}, map[string]any{"user": []any{m1, m2}}), "group-remove-member-users")
	p.need(p.rpc("group-remove-member-group", "group_remove_member", []any{g1}, map[string]any{"group": []any{g2}}), "group-remove-member-group")
	p.need(p.rpc("group-remove-member-group-mixed", "group_remove_member", []any{g1}, map[string]any{"group": []any{g3, g2}}), "group-remove-member-group-mixed")
	p.need(p.rpc("group-remove-member-no-such-entry", "group_remove_member", []any{g1}, map[string]any{"user": []any{capUser("nobody")}}), "group-remove-member-no-such-entry")
	p.need(p.rpc("group-remove-member-group-no-such-entry", "group_remove_member", []any{g1}, map[string]any{"group": []any{capUser("nogroup")}}), "group-remove-member-group-no-such-entry")
	p.wantErr(p.rpc("group-remove-member-from-missing-group", "group_remove_member", []any{capUser("nogroup")}, map[string]any{"user": []any{m1}}), "NotFound", "group-remove-member-from-missing-group")

	// a loop: the server answers it like any other addition
	c1, c2 := capUser("cg1"), capUser("cg2")
	p.addGroup(c1, nil)
	p.addGroup(c2, nil)
	p.members(c1, "group", c2)
	p.need(p.rpc("group-add-member-group-cycle", "group_add_member", []any{c2}, map[string]any{"group": []any{c1}}), "group-add-member-group-cycle")
	p.need(p.showAll("group-show-cycle", "group_show", c1), "group-show-cycle")

	// the member commands as the items of one batch
	p.addUser(capUser("bm1"), nil)
	p.addUser(capUser("bm2"), nil)
	p.members(capUser("mg3"), "user", capUser("bm1"))
	p.need(p.batch("batch-members-mixed",
		Command{Method: "group_add_member", Args: []any{g3}, Options: map[string]any{"user": []any{capUser("bm1")}}},
		Command{Method: "group_add_member", Args: []any{g3}, Options: map[string]any{"user": []any{capUser("bm2")}}},
		Command{Method: "group_add_member", Args: []any{capUser("nogroup")}, Options: map[string]any{"user": []any{capUser("bm2")}}},
		Command{Method: "group_remove_member", Args: []any{g3}, Options: map[string]any{"user": []any{capUser("bm1"), capUser("bm2"), capUser("nobody")}}},
	), "batch-members-mixed")

	// a group that has a member and is a member: what deleting it leaves behind
	p.addGroup(capUser("mdel"), nil)
	p.members(g1, "group", capUser("mdel"))
	p.members(capUser("mdel"), "user", m1)
	p.need(p.showAll("group-show-before-member-group-del", "group_show", g1), "group-show-before-member-group-del")
	p.need(p.showAll("user-show-before-member-group-del", "user_show", m1), "user-show-before-member-group-del")
	p.need(p.rpc("group-del-with-members", "group_del", []any{capUser("mdel")}, nil), "group-del-with-members")
	p.need(p.showAll("group-show-after-member-group-del", "group_show", g1), "group-show-after-member-group-del")
	p.need(p.showAll("user-show-after-member-group-del", "user_show", m1), "user-show-after-member-group-del")
}

// K15, K19: batches with one failing item.
func (p *p24Capture) captureBatches() {
	b1, b2, g1 := capUser("b1"), capUser("b2"), capUser("bg")
	p.addGroup(g1, map[string]any{"description": "P24 batch existing"})

	a := p.batch("batch-group-add-duplicate",
		Command{Method: "group_add", Args: []any{b1}, Options: map[string]any{"description": "P24 batch one"}},
		Command{Method: "group_add", Args: []any{g1}, Options: map[string]any{"description": "P24 batch dup"}},
		Command{Method: "group_add", Args: []any{b2}, Options: map[string]any{"description": "P24 batch two"}},
	)
	p.need(a, "batch-group-add-duplicate")
	p.need(p.rpc("group-find-after-batch", "group_find", []any{p24CapPrefix + "b"}, map[string]any{"all": true, "sizelimit": 0, "timelimit": 0}), "group-find-after-batch")

	u1, u2 := capUser("bu1"), capUser("bu2")
	p.addUser(u1, nil)
	p.addUser(u2, nil)
	p.need(p.batch("batch-user-mod-mixed",
		Command{Method: "user_mod", Args: []any{u1}, Options: map[string]any{"loginshell": "/bin/zsh"}},
		Command{Method: "user_mod", Args: []any{capUser("nobody")}, Options: map[string]any{"loginshell": "/bin/zsh"}},
		Command{Method: "user_mod", Args: []any{u1}, Options: map[string]any{"loginshell": "/bin/zsh"}},
		Command{Method: "user_mod", Args: []any{u2}, Options: map[string]any{"loginshell": "/bin/zsh"}},
	), "batch-user-mod-mixed")
	p.need(p.showAll("user-show-after-batch", "user_show", u2), "user-show-after-batch")

	gdel := capUser("bgd")
	p.addGroup(gdel, nil)
	p.need(p.batch("batch-delete-mixed",
		Command{Method: "user_del", Args: []any{u1}},
		Command{Method: "user_del", Args: []any{capUser("nobody")}},
		Command{Method: "group_del", Args: []any{gdel}},
		Command{Method: "group_del", Args: []any{capUser("nogroup")}},
	), "batch-delete-mixed")

	// K19: the pre-write re-read, one item missing
	p.need(p.batch("batch-show-one-missing",
		Command{Method: "user_show", Args: []any{u2}, Options: map[string]any{"all": true}},
		Command{Method: "user_show", Args: []any{capUser("nobody")}, Options: map[string]any{"all": true}},
		Command{Method: "group_show", Args: []any{g1}, Options: map[string]any{"all": true}},
		Command{Method: "group_show", Args: []any{capUser("nogroup")}, Options: map[string]any{"all": true}},
	), "batch-show-one-missing")
}

// K21: what FreeIPA says to an empty value.
func (p *p24Capture) captureEmptyValues() {
	fields := []string{"givenname", "sn", "loginshell", "homedirectory", "displayname", "mail"}
	for _, f := range fields {
		opts := map[string]any{"givenname": "P24", "sn": "Empty"}
		opts[f] = ""
		p.rpc("user-add-empty-"+f, "user_add", []any{capUser("ue-" + f)}, opts)
	}
	ue := capUser("ue")
	p.addUser(ue, map[string]any{"displayname": "P24 Empty", "mail": ue + "@example.test", "loginshell": "/bin/bash", "homedirectory": "/srv/home/" + ue})
	for _, f := range fields {
		p.rpc("user-mod-empty-"+f, "user_mod", []any{ue}, map[string]any{f: ""})
	}
	p.need(p.showAll("user-show-after-empty-mods", "user_show", ue), "user-show-after-empty-mods")

	ue2 := capUser("ue2")
	p.addUser(ue2, map[string]any{"mail": ue2 + "@example.test"})
	p.rpc("user-mod-empty-mail-list", "user_mod", []any{ue2}, map[string]any{"mail": []any{}})
	p.need(p.showAll("user-show-after-empty-mail-list", "user_show", ue2), "user-show-after-empty-mail-list")

	p.rpc("group-add-empty-description", "group_add", []any{capUser("ge")}, map[string]any{"description": ""})
	ge2 := capUser("ge2")
	p.addGroup(ge2, map[string]any{"description": "P24 has one"})
	p.rpc("group-mod-empty-description", "group_mod", []any{ge2}, map[string]any{"description": ""})
	p.need(p.showAll("group-show-after-empty-description", "group_show", ge2), "group-show-after-empty-description")
}

// scanDirForLiterals lists the files of dir that hold one of the literals.
func scanDirForLiterals(t *testing.T, dir string, literals []string) []string {
	t.Helper()
	var hits []string
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range literals {
			if l != "" && bytes.Contains(data, []byte(l)) {
				hits = append(hits, f.Name())
				break
			}
		}
	}
	return hits
}

// redactCapture re-indents a raw FreeIPA answer the way the fixtures are
// (two spaces, the server's key order) and replaces the value of every
// secret-bearing attribute with the placeholder, one placeholder per value,
// so that the field keeps its shape. It returns the number of attributes it
// replaced.
func redactCapture(raw []byte) ([]byte, int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out bytes.Buffer
	n := 0
	if err := copyRedacted(dec, &out, &n); err != nil {
		return nil, 0, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("data after the JSON document")
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, out.Bytes(), "", "  "); err != nil {
		return nil, 0, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), n, nil
}

func writeJSONString(out *bytes.Buffer, s string) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	out.Write(bytes.TrimRight(b.Bytes(), "\n"))
	return nil
}

func copyRedacted(dec *json.Decoder, out *bytes.Buffer, n *int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			out.WriteByte('{')
			first := true
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return errors.New("a non-string key")
				}
				if !first {
					out.WriteByte(',')
				}
				first = false
				if err := writeJSONString(out, key); err != nil {
					return err
				}
				out.WriteByte(':')
				if isSecretFixtureAttribute(key) {
					var v json.RawMessage
					if err := dec.Decode(&v); err != nil {
						return err
					}
					count := 1
					var list []json.RawMessage
					if json.Unmarshal(v, &list) == nil && len(list) > 0 {
						count = len(list)
					}
					out.WriteByte('[')
					for i := 0; i < count; i++ {
						if i > 0 {
							out.WriteByte(',')
						}
						out.WriteString(`{"__base64__":"` + fixtureSecretPlaceholder + `"}`)
					}
					out.WriteByte(']')
					*n++
					continue
				}
				if err := copyRedacted(dec, out, n); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					out.WriteByte(',')
				}
				first = false
				if err := copyRedacted(dec, out, n); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
			out.WriteByte(']')
		}
	case string:
		return writeJSONString(out, t)
	case json.Number:
		out.WriteString(t.String())
	case bool:
		fmt.Fprintf(out, "%t", t)
	case nil:
		out.WriteString("null")
	}
	return nil
}
