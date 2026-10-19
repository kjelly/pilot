package freeiparpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The fake server answers with responses captured from FreeIPA 4.13.4
// (testdata/<name>.{status,headers,json|body}).

const (
	testFQDN     = "ipa1.ipa.pilot.internal"
	testPassword = "Correct-Horse-Battery-Staple-9"
)

type fixture struct {
	status  int
	headers map[string]string
	body    []byte
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	base := filepath.Join("testdata", name)
	st, err := os.ReadFile(base + ".status")
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{headers: map[string]string{}}
	if f.status, err = strconv.Atoi(strings.TrimSpace(string(st))); err != nil {
		t.Fatal(err)
	}
	hdr, _ := os.ReadFile(base + ".headers")
	for _, line := range strings.Split(strings.TrimSpace(string(hdr)), "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok && k != "Set-Cookie" {
			f.headers[k] = v
		}
	}
	if f.body, err = os.ReadFile(base + ".json"); err != nil {
		if f.body, err = os.ReadFile(base + ".body"); err != nil {
			t.Fatalf("fixture %s has no body", name)
		}
	}
	return f
}

// received is one request the fake server got.
type received struct {
	path    string
	referer string
	form    map[string]string
	rpc     map[string]any
}

type fakeServer struct {
	t      *testing.T
	srv    *httptest.Server
	ca     *x509.CertPool
	mu     sync.Mutex
	got    []received
	valid  map[string]bool
	issued []string                                 // every session cookie handed out
	answer func(method string, params []any) string // fixture name
	// hook runs before answering a JSON-RPC call; returning true means it
	// handled the request.
	hook func(w http.ResponseWriter, method string) bool
	// logoutBody, when set, replaces the session_logout answer (fault
	// injection).
	logoutBody string
}

// newFakeServer starts a TLS server whose certificate names certName,
// signed by a CA of its own.
func newFakeServer(t *testing.T, certName string) *fakeServer {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test IPA CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: certName}, DNSNames: []string{certName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	f := &fakeServer{t: t, valid: map[string]bool{}, ca: x509.NewCertPool()}
	f.ca.AddCert(caCert)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) write(w http.ResponseWriter, name string) {
	fx := loadFixture(f.t, name)
	for k, v := range fx.headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(fx.status)
	_, _ = w.Write(fx.body)
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	rec := received{path: r.URL.Path, referer: r.Header.Get("Referer")}
	switch r.URL.Path {
	case "/ipa/session/login_password":
		_ = r.ParseForm()
		rec.form = map[string]string{"user": r.PostForm.Get("user"), "password": r.PostForm.Get("password")}
		f.record(rec)
		switch {
		case r.PostForm.Get("user") == "expired":
			f.write(w, "login-password-expired")
		case r.PostForm.Get("password") != testPassword:
			f.write(w, "login-invalid-password")
		default:
			token := fmt.Sprintf("session-%d", time.Now().UnixNano())
			f.mu.Lock()
			f.valid[token] = true
			f.issued = append(f.issued, token)
			f.mu.Unlock()
			// The attributes FreeIPA sets (testdata/login-ok.headers).
			http.SetCookie(w, &http.Cookie{Name: "ipa_session", Value: token, Path: "/ipa", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			f.write(w, "login-ok")
		}
	case "/ipa/session/json":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.rpc = body
		f.record(rec)
		ck, err := r.Cookie("ipa_session")
		f.mu.Lock()
		ok := err == nil && f.valid[ck.Value]
		f.mu.Unlock()
		if !ok {
			f.write(w, "json-without-session")
			return
		}
		method, _ := body["method"].(string)
		if method == "session_logout" {
			f.mu.Lock()
			delete(f.valid, ck.Value)
			f.mu.Unlock()
			if f.logoutBody != "" {
				_, _ = w.Write([]byte(f.logoutBody))
				return
			}
			f.write(w, "session-logout")
			return
		}
		if f.hook != nil && f.hook(w, method) {
			return
		}
		params, _ := body["params"].([]any)
		f.write(w, f.answer(method, params))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeServer) record(r received) {
	f.mu.Lock()
	f.got = append(f.got, r)
	f.mu.Unlock()
}

func (f *fakeServer) received() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

// expireSessions makes the server forget every session, as a timeout or a
// session_logout from elsewhere would.
func (f *fakeServer) expireSessions() {
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
}

func (f *fakeServer) methods() []string {
	var out []string
	for _, r := range f.received() {
		if r.rpc != nil {
			out = append(out, r.rpc["method"].(string))
		}
	}
	return out
}

// dial connects to the fake server whatever address the client asks for,
// as the SSH tunnel does.
func (f *fakeServer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.srv.Listener.Addr().String())
}

func newTestClient(t *testing.T, f *fakeServer, mod ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{FQDN: testFQDN, CA: f.ca, DialContext: f.dial, RequestTimeout: 5 * time.Second}
	for _, m := range mod {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// byMethod answers each method with one fixture.
func byMethod(m map[string]string) func(string, []any) string {
	return func(method string, _ []any) string {
		if name, ok := m[method]; ok {
			return name
		}
		return "unknown-command"
	}
}

func loggedIn(t *testing.T, answers map[string]string) (*fakeServer, *Client) {
	t.Helper()
	f := newFakeServer(t, testFQDN)
	f.answer = byMethod(answers)
	c := newTestClient(t, f)
	if err := c.Login(context.Background(), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestLoginSendsRefererAndKeepsTheSession(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"ping": "ping"})
	if _, err := c.Call(context.Background(), Command{Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	got := f.received()
	if len(got) != 2 || got[0].path != "/ipa/session/login_password" || got[0].form["user"] != "admin" {
		t.Fatalf("requests = %+v", got)
	}
	for _, r := range got {
		if r.referer != "https://"+testFQDN+"/ipa" {
			t.Fatalf("%s sent Referer %q", r.path, r.referer)
		}
	}
	if s := c.Stats(); s.Logins != 1 || s.Reads != 1 || s.Writes != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestLoginRejections(t *testing.T) {
	f := newFakeServer(t, testFQDN)
	c := newTestClient(t, f)
	for user, reason := range map[string]string{"admin": "invalid-password", "expired": "password-expired"} {
		err := c.Login(context.Background(), user, "Wrong-Password-1")
		var le *LoginError
		if !errors.As(err, &le) || le.Status != 401 || le.Reason != reason {
			t.Fatalf("login as %s = %v, want 401 %s", user, err, reason)
		}
		if strings.Contains(err.Error(), "Wrong-Password-1") {
			t.Fatalf("login error shows the password: %v", err)
		}
	}
}

func TestPingAndAPIVersionCheck(t *testing.T) {
	_, c := loggedIn(t, map[string]string{"ping": "ping"})
	info, err := c.CheckServer(context.Background())
	if err != nil || info != (ServerInfo{ServerVersion: "4.13.4", APIVersion: "2.257"}) {
		t.Fatalf("CheckServer = %+v, %v", info, err)
	}

	f := newFakeServer(t, testFQDN)
	f.answer = byMethod(map[string]string{"ping": "ping"})
	c = newTestClient(t, f, func(cfg *Config) { cfg.SupportedAPIVersions = []string{"2.300"} })
	if err := c.Login(context.Background(), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckServer(context.Background()); err == nil || !strings.Contains(err.Error(), "API version 2.257") {
		t.Fatalf("CheckServer with an unsupported API = %v", err)
	}
}

func TestEveryCommandCarriesTheAPIVersion(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"user_show": "user-show", "batch": "batch-mixed"})
	ctx := context.Background()
	if _, err := c.Call(ctx, Command{Method: "user_show", Args: []any{"p0-alice"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Batch(ctx, []Command{{Method: "user_show", Args: []any{"a"}}, {Method: "user_show", Args: []any{"b"}}, {Method: "user_mod", Args: []any{"c"}}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.received()[1:] {
		params := r.rpc["params"].([]any)
		if params[1].(map[string]any)["version"] != "2.257" {
			t.Fatalf("%v sent no version", r.rpc["method"])
		}
		if r.rpc["method"] == "batch" {
			for _, item := range params[0].([]any) {
				if item.(map[string]any)["params"].([]any)[1].(map[string]any)["version"] != "2.257" {
					t.Fatalf("batch item sent no version: %v", item)
				}
			}
		}
	}
}

func TestRPCErrorsAreTyped(t *testing.T) {
	_, c := loggedIn(t, map[string]string{
		"user_show": "user-show-not-found", "user_add": "user-add-duplicate", "user_mod": "user-mod-no-change",
		"user_enable": "user-enable-already-enabled", "user_disable": "user-disable-already-disabled",
		"group_add": "user-mod-acierror",
	})
	for method, want := range map[string]struct {
		name string
		code int
	}{
		"user_show": {"NotFound", 4001}, "user_add": {"DuplicateEntry", 4002}, "user_mod": {"EmptyModlist", 4202},
		"user_enable": {"AlreadyActive", 4009}, "user_disable": {"AlreadyInactive", 4010}, "group_add": {"ACIError", 2100},
	} {
		_, err := c.Call(context.Background(), Command{Method: method, Args: []any{"p0-alice"}})
		var re *RPCError
		if !errors.As(err, &re) || re.Name != want.name || re.Code != want.code || !IsRPC(err, want.name) {
			t.Fatalf("%s = %v, want %s %d", method, err, want.name, want.code)
		}
		var unknown *OutcomeUnknownError
		if errors.As(err, &unknown) {
			t.Fatalf("%s: an answered error is not an unknown outcome", method)
		}
	}
}

func TestCommandsOutsideTheAllowlistAreNeverSent(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"user_show": "user-show"})
	ctx := context.Background()
	for _, m := range []string{"hbacrule_del", "config_mod", "batch", "session_logout"} {
		if _, err := c.Call(ctx, Command{Method: m}); !errors.As(err, new(*ErrMethodNotAllowed)) {
			t.Fatalf("Call(%s) = %v", m, err)
		}
	}
	if _, err := c.Batch(ctx, []Command{{Method: "user_show"}, {Method: "host_del"}}); !errors.As(err, new(*ErrMethodNotAllowed)) {
		t.Fatalf("Batch with host_del = %v", err)
	}
	if got := f.methods(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
}

// A 401 comes before the command runs (captured: a write after
// session_logout got 401 and changed nothing), so it is re-sent once after
// a new login, write or not.
func TestRejectedSessionLogsInAgainOnce(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"user_mod": "user-mod"})
	f.expireSessions()
	if _, err := c.Call(context.Background(), Command{Method: "user_mod", Args: []any{"p0-alice"}, Options: map[string]any{"title": "x"}}); err != nil {
		t.Fatalf("write after the session expired: %v", err)
	}
	var paths []string
	for _, r := range f.received() {
		paths = append(paths, r.path)
	}
	want := []string{"/ipa/session/login_password", "/ipa/session/json", "/ipa/session/login_password", "/ipa/session/json"}
	if !slices.Equal(paths, want) {
		t.Fatalf("requests = %v, want %v", paths, want)
	}
	if s := c.Stats(); s.Relogins != 1 || s.Writes != 2 || s.Unknown != 0 {
		t.Fatalf("stats = %+v", s)
	}

	// A server that keeps rejecting the session gets one new login, not a loop.
	f.hook = func(w http.ResponseWriter, _ string) bool {
		f.expireSessions()
		f.write(w, "json-without-session")
		return true
	}
	if _, err := c.Call(context.Background(), Command{Method: "user_mod", Args: []any{"p0-alice"}}); !errors.Is(err, ErrSessionRejected) {
		t.Fatalf("second rejection = %v, want ErrSessionRejected", err)
	}
}

// dropOnce closes the connection without an answer the first time method
// is called.
func dropOnce(f *fakeServer, method string) {
	dropped := false
	f.hook = func(w http.ResponseWriter, m string) bool {
		if m != method || dropped {
			return false
		}
		dropped = true
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
		return true
	}
}

func TestLostAnswers(t *testing.T) {
	t.Run("a write is reported as unknown and not re-sent", func(t *testing.T) {
		f, c := loggedIn(t, map[string]string{"user_mod": "user-mod"})
		dropOnce(f, "user_mod")
		_, err := c.Call(context.Background(), Command{Method: "user_mod", Args: []any{"p0-alice"}})
		var unknown *OutcomeUnknownError
		if !errors.As(err, &unknown) || unknown.Method != "user_mod" {
			t.Fatalf("err = %v, want an unknown outcome", err)
		}
		if got := f.methods(); !slices.Equal(got, []string{"user_mod"}) {
			t.Fatalf("sent %v, want one user_mod", got)
		}
		if s := c.Stats(); s.Unknown != 1 {
			t.Fatalf("stats = %+v", s)
		}
	})
	t.Run("a read is re-sent once", func(t *testing.T) {
		f, c := loggedIn(t, map[string]string{"user_show": "user-show"})
		dropOnce(f, "user_show")
		if _, err := c.Call(context.Background(), Command{Method: "user_show", Args: []any{"p0-alice"}}); err != nil {
			t.Fatal(err)
		}
		if got := f.methods(); !slices.Equal(got, []string{"user_show", "user_show"}) {
			t.Fatalf("sent %v", got)
		}
	})
	t.Run("a write that times out is unknown", func(t *testing.T) {
		f := newFakeServer(t, testFQDN)
		f.answer = byMethod(map[string]string{"user_mod": "user-mod"})
		c := newTestClient(t, f, func(cfg *Config) { cfg.RequestTimeout = 300 * time.Millisecond })
		if err := c.Login(context.Background(), "admin", testPassword); err != nil {
			t.Fatal(err)
		}
		f.hook = func(http.ResponseWriter, string) bool { time.Sleep(time.Second); return false }
		if _, err := c.Call(context.Background(), Command{Method: "user_mod", Args: []any{"p0-alice"}}); !errors.As(err, new(*OutcomeUnknownError)) {
			t.Fatalf("err = %v, want an unknown outcome", err)
		}
	})
	t.Run("a write whose tunnel never opened was not sent", func(t *testing.T) {
		f := newFakeServer(t, testFQDN)
		var refuse atomic.Bool
		c := newTestClient(t, f, func(cfg *Config) {
			cfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if refuse.Load() {
					return nil, errors.New("sshd refused the TCP forwarding")
				}
				return f.dial(ctx, network, addr)
			}
		})
		if err := c.Login(context.Background(), "admin", testPassword); err != nil {
			t.Fatal(err)
		}
		c.http.CloseIdleConnections()
		refuse.Store(true)
		_, err := c.Call(context.Background(), Command{Method: "user_mod", Args: []any{"p0-alice"}})
		var te *TransportError
		if !errors.As(err, &te) || te.Sent || errors.As(err, new(*OutcomeUnknownError)) {
			t.Fatalf("err = %v, want a not-sent transport error", err)
		}
		if got := f.methods(); len(got) != 0 {
			t.Fatalf("sent %v", got)
		}
	})
}

// TLS fails before any request (and so the password) leaves.
func TestTLSRejectsTheWrongServer(t *testing.T) {
	t.Run("certificate for another name", func(t *testing.T) {
		f := newFakeServer(t, "other.ipa.pilot.internal")
		c := newTestClient(t, f)
		err := c.Login(context.Background(), "admin", testPassword)
		var te *TransportError
		if !errors.As(err, &te) || te.Sent {
			t.Fatalf("err = %v, want a not-sent TLS error", err)
		}
		if len(f.received()) != 0 {
			t.Fatal("the server received a request")
		}
	})
	t.Run("certificate from another CA", func(t *testing.T) {
		f := newFakeServer(t, testFQDN)
		other := newFakeServer(t, testFQDN)
		c := newTestClient(t, f, func(cfg *Config) { cfg.CA = other.ca })
		err := c.Login(context.Background(), "admin", testPassword)
		var te *TransportError
		if !errors.As(err, &te) || te.Sent || strings.Contains(err.Error(), testPassword) {
			t.Fatalf("err = %v, want a not-sent TLS error", err)
		}
		if len(f.received()) != 0 {
			t.Fatal("the server received a request")
		}
	})
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	_, c := loggedIn(t, map[string]string{"ping": "ping"})
	if _, err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping with a proxy in the environment: %v", err)
	}
}

func TestBatchReportsEachItem(t *testing.T) {
	_, c := loggedIn(t, map[string]string{"batch": "batch-mixed"})
	items, err := c.Batch(context.Background(), []Command{
		{Method: "user_show", Args: []any{"p0-alice"}},
		{Method: "user_show", Args: []any{"p0-missing"}},
		{Method: "user_mod", Args: []any{"p0-alice"}, Options: map[string]any{"title": "Phase 0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Err != nil || items[0].Result == nil {
		t.Fatalf("item 0 = %+v", items[0])
	}
	if items[1].Err == nil || items[1].Err.Name != "NotFound" || items[1].Err.Code != 4001 {
		t.Fatalf("item 1 = %+v", items[1].Err)
	}
	if items[2].Err == nil || items[2].Err.Name != "EmptyModlist" {
		t.Fatalf("item 2 = %+v", items[2].Err)
	}
	if s := c.Stats(); s.Writes != 1 || s.Reads != 2 {
		t.Fatalf("a batch counts each command by kind: %+v", s)
	}
	if _, err := c.Batch(context.Background(), []Command{{Method: "user_show"}}); err == nil {
		t.Fatal("a batch answered with the wrong number of results must fail")
	}
}

func TestFindFailsOnTruncation(t *testing.T) {
	_, c := loggedIn(t, map[string]string{"user_find": "user-find-truncated"})
	if _, err := c.Find(context.Background(), "user_find", nil, nil); !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
	f, c := loggedIn(t, map[string]string{"user_find": "user-find-p0"})
	entries, err := c.Find(context.Background(), "user_find", []any{"p0-"}, map[string]any{"all": true})
	if err != nil || len(entries) == 0 {
		t.Fatalf("Find = %d entries, %v", len(entries), err)
	}
	opts := f.received()[1].rpc["params"].([]any)[1].(map[string]any)
	if opts["sizelimit"] != float64(0) || opts["timelimit"] != float64(0) || opts["all"] != true {
		t.Fatalf("find options = %v", opts)
	}
}

func TestMemberResults(t *testing.T) {
	read := func(name string) json.RawMessage {
		var env struct{ Result json.RawMessage }
		if err := json.Unmarshal(loadFixture(t, name).body, &env); err != nil {
			t.Fatal(err)
		}
		return env.Result
	}
	for name, want := range map[string]MemberResult{
		"group-add-member":               {Completed: 1},
		"group-add-member-already":       {Failed: []MemberFailure{{Type: "user", Name: "p0-alice", Reason: "This entry is already a member"}}},
		"group-add-member-missing-user":  {Failed: []MemberFailure{{Type: "user", Name: "p0-nobody", Reason: "no such entry"}}},
		"group-remove-member-not-member": {Failed: []MemberFailure{{Type: "user", Name: "p0-bob", Reason: "This entry is not a member"}}},
	} {
		got, err := DecodeMemberResult(read(name), 1)
		if err != nil || got.Completed != want.Completed || !slices.Equal(got.Failed, want.Failed) {
			t.Fatalf("%s = %+v, %v; want %+v", name, got, err, want)
		}
	}
	if _, err := DecodeMemberResult(read("group-add-member"), 2); err == nil {
		t.Fatal("two members requested but one accounted for must fail")
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"ping": "ping"})
	if err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ping(context.Background()); !errors.Is(err, ErrSessionRejected) {
		t.Fatalf("ping after logout = %v, want ErrSessionRejected (no automatic login)", err)
	}
	if got := f.methods(); !slices.Equal(got, []string{"session_logout", "ping"}) {
		t.Fatalf("sent %v", got)
	}
}

// The password and the session cookie never appear in an error or in a
// printed Client.
func TestSecretsStayOutOfErrorsAndFormatting(t *testing.T) {
	f, c := loggedIn(t, map[string]string{"user_mod": "user-mod-acierror", "user_show": "user-show-not-found"})
	var texts []string
	ctx := context.Background()
	for _, m := range []string{"user_mod", "user_show"} {
		_, err := c.Call(ctx, Command{Method: m, Args: []any{"p0-alice"}})
		texts = append(texts, err.Error())
	}
	dropOnce(f, "user_mod")
	_, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{"p0-alice"}})
	texts = append(texts, err.Error())
	f.hook = func(w http.ResponseWriter, _ string) bool {
		f.expireSessions()
		f.write(w, "json-without-session")
		return true
	}
	_, err = c.Call(ctx, Command{Method: "user_show", Args: []any{"p0-alice"}})
	texts = append(texts, err.Error())
	texts = append(texts, fmt.Sprintf("%v %+v %#v", c, c, c))
	f.mu.Lock()
	secrets := append([]string{testPassword}, f.issued...)
	f.mu.Unlock()
	if len(secrets) < 3 {
		t.Fatalf("expected at least two sessions, got %v", secrets[1:])
	}
	for _, text := range texts {
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Fatalf("a secret leaked: %s", text)
			}
		}
	}
}

// injectBody makes the fake server answer every JSON-RPC call with body
// and HTTP 200. These bodies are fault injection, not captures: FreeIPA was
// never seen sending them. They stand for a broken or foreign server, whose
// answer must not be taken as success.
func injectBody(f *fakeServer, body string) {
	f.hook = func(w http.ResponseWriter, _ string) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
		return true
	}
}

func TestIncompleteAnswersAreNotSuccess(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"error":null}`,
		`{"error":null,"result":null}`,
		`{"error":null,"result":[]}`,
		`{"error":null,"result":{}}`,
		`{"error":null,"result":{"result":null,"value":"p0-alice","summary":"Modified user"}}`,
		`{"error":{},"result":null}`,
		`[]`,
		`not json`,
	} {
		t.Run(body, func(t *testing.T) {
			f, c := loggedIn(t, nil)
			injectBody(f, body)
			ctx := context.Background()

			_, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{"p0-alice"}, Options: map[string]any{"title": "x"}})
			if !errors.As(err, new(*OutcomeUnknownError)) || !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("write = %v, want an unknown outcome caused by an incomplete response", err)
			}
			if s := c.Stats(); s.Unknown != 1 || s.Writes != 1 {
				t.Fatalf("stats after the write = %+v, want 1 write, 1 unknown, no resend", s)
			}

			_, err = c.Call(ctx, Command{Method: "user_show", Args: []any{"p0-alice"}})
			if err == nil || errors.As(err, new(*OutcomeUnknownError)) || !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("read = %v, want an incomplete-response error", err)
			}
			if s := c.Stats(); s.Unknown != 1 || s.Reads != 1 {
				t.Fatalf("stats after the read = %+v", s)
			}
		})
	}
}

func TestFindRequiresACompleteAnswer(t *testing.T) {
	t.Run("a real empty answer is an empty set", func(t *testing.T) {
		_, c := loggedIn(t, map[string]string{"user_find": "user-find-no-match", "group_find": "group-find-no-match"})
		for _, m := range []string{"user_find", "group_find"} {
			entries, err := c.Find(context.Background(), m, []any{"p0-no-such"}, nil)
			if err != nil || entries == nil || len(entries) != 0 {
				t.Fatalf("%s = %v, %v; want an empty, non-nil set", m, entries, err)
			}
		}
	})
	for name, body := range map[string]string{
		"result object empty":       `{"error":null,"result":{}}`,
		"result null":               `{"error":null,"result":null}`,
		"entries without truncated": `{"error":null,"result":{"count":1,"result":[{"uid":["a"]}]}}`,
		"entries without count":     `{"error":null,"result":{"truncated":false,"result":[{"uid":["a"]}]}}`,
		"entry list null":           `{"error":null,"result":{"count":0,"truncated":false,"result":null}}`,
		"count of the wrong type":   `{"error":null,"result":{"count":"1","truncated":false,"result":[{"uid":["a"]}]}}`,
		"count not matching":        `{"error":null,"result":{"count":2,"truncated":false,"result":[{"uid":["a"]}]}}`,
		"entry that is null":        `{"error":null,"result":{"count":1,"truncated":false,"result":[null]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f, c := loggedIn(t, nil)
			injectBody(f, body)
			entries, err := c.Find(context.Background(), "user_find", nil, nil)
			if !errors.Is(err, ErrIncompleteResponse) || entries != nil {
				t.Fatalf("Find = %v, %v; want ErrIncompleteResponse", entries, err)
			}
		})
	}
}

func TestBatchAnswersThatCannotBeConfirmed(t *testing.T) {
	bodies := map[string]string{
		// The real answer to an empty batch, given to a batch of one.
		"no results for one command": "fixture:batch-empty",
		"result not an object":       `{"error":null,"result":[]}`,
		"results missing":            `{"error":null,"result":{"count":1}}`,
		"item not an object":         `{"error":null,"result":{"count":1,"results":[123]}}`,
		"item without a result":      `{"error":null,"result":{"count":1,"results":[{"error":null}]}}`,
		"failed item without a name": `{"error":null,"result":{"count":1,"results":[{"error":"boom"}]}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			setup := func() (*fakeServer, *Client) {
				if fx, ok := strings.CutPrefix(body, "fixture:"); ok {
					return loggedIn(t, map[string]string{"batch": fx})
				}
				f, c := loggedIn(t, nil)
				injectBody(f, body)
				return f, c
			}
			_, c := setup()
			_, err := c.Batch(context.Background(), []Command{{Method: "user_mod", Args: []any{"p0-alice"}, Options: map[string]any{"title": "x"}}})
			if !errors.As(err, new(*OutcomeUnknownError)) || !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("write batch = %v, want an unknown outcome", err)
			}
			if s := c.Stats(); s.Unknown != 1 {
				t.Fatalf("stats = %+v, want 1 unknown", s)
			}

			_, c = setup()
			_, err = c.Batch(context.Background(), []Command{{Method: "user_show", Args: []any{"p0-alice"}}})
			if err == nil || errors.As(err, new(*OutcomeUnknownError)) || !errors.Is(err, ErrIncompleteResponse) {
				t.Fatalf("read batch = %v, want a plain incomplete-response error", err)
			}
			if s := c.Stats(); s.Unknown != 0 {
				t.Fatalf("a read batch counted as unknown: %+v", s)
			}
		})
	}
}

// Fault injection: FreeIPA always sends completed and failed.member.
func TestMemberResultsMustAccountForEveryField(t *testing.T) {
	for _, raw := range []string{
		`{"completed":1}`,
		`{"completed":1,"failed":{}}`,
		`{"completed":0,"failed":{"member":{"user":null}}}`,
		`{"failed":{"member":{"user":[]}}}`,
	} {
		if _, err := DecodeMemberResult(json.RawMessage(raw), 1); !errors.Is(err, ErrIncompleteResponse) {
			t.Fatalf("DecodeMemberResult(%s) = %v, want ErrIncompleteResponse", raw, err)
		}
	}
}

// Fault injection: Logout reads only the envelope, so an answer without a
// result object must fail there.
func TestLogoutNeedsACompleteAnswer(t *testing.T) {
	for _, body := range []string{`{}`, `{"error":null,"result":null}`, `{"error":null,"result":[]}`} {
		f, c := loggedIn(t, nil)
		f.logoutBody = body
		if err := c.Logout(context.Background()); !errors.Is(err, ErrIncompleteResponse) {
			t.Fatalf("Logout answered %s = %v, want ErrIncompleteResponse", body, err)
		}
	}
}
