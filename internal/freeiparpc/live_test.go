package freeiparpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sshdial"
)

// Live tests against a disposable FreeIPA server through a real SSH tunnel.
// They run only when PILOT_FREEIPA_LIVE_SSH is set (see
// internal/sshdial/live_test.go for the variables) and IPA_ADMIN_PASSWORD
// holds the admin password. They create and delete p0-live* objects.
//
// docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md §5.

func liveTarget(t *testing.T) sshdial.Target {
	t.Helper()
	dest := os.Getenv("PILOT_FREEIPA_LIVE_SSH")
	if dest == "" {
		t.Skip("PILOT_FREEIPA_LIVE_SSH is not set")
	}
	tgt := sshdial.Target{Host: dest, IdentityFile: os.Getenv("PILOT_FREEIPA_LIVE_SSH_KEY"), Options: map[string]string{}}
	if user, host, ok := strings.Cut(dest, "@"); ok {
		tgt.User, tgt.Host = user, host
	}
	for _, kv := range strings.Split(os.Getenv("PILOT_FREEIPA_LIVE_SSH_OPTS"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			tgt.Options[k] = v
		}
	}
	return tgt
}

// dropper wraps a dialer so a test can make the next write on any
// connection kill that connection's ssh right after the bytes went in.
type dropper struct {
	dial  func(context.Context, string, string) (net.Conn, error)
	armed atomic.Bool
}

func (d *dropper) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &droppingConn{Conn: c, d: d}, nil
}

type droppingConn struct {
	net.Conn
	d *dropper
}

func (c *droppingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.d.armed.CompareAndSwap(true, false) {
		_ = c.Close()
	}
	return n, err
}

type liveEnv struct {
	dialer   *sshdial.Dialer
	drop     *dropper
	fqdn     string
	cfg      Config
	password string
}

func setupLive(t *testing.T) *liveEnv {
	t.Helper()
	tgt := liveTarget(t)
	password := os.Getenv("IPA_ADMIN_PASSWORD")
	if password == "" {
		t.Skip("IPA_ADMIN_PASSWORD is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := &sshdial.Dialer{Target: tgt}
	e := &liveEnv{dialer: d, drop: &dropper{dial: d.DialContext}, password: password}
	if os.Getenv("PILOT_FREEIPA_LIVE_EXPECT") == "forwarding-denied" {
		e.fqdn = os.Getenv("PILOT_FREEIPA_LIVE_FQDN")
		e.cfg = Config{FQDN: e.fqdn, CA: newFakeServer(t, "unused.example.test").ca, DialContext: e.drop.DialContext}
		return e
	}
	var err error
	if e.fqdn, err = d.FQDN(ctx); err != nil {
		t.Fatal(err)
	}
	ca, err := d.CA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = Config{FQDN: e.fqdn, CA: ca, DialContext: e.drop.DialContext}
	return e
}

func (e *liveEnv) admin(t *testing.T) *Client {
	t.Helper()
	c, err := New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.Login(context.Background(), "admin", e.password); err != nil {
		t.Fatal(err)
	}
	t.Logf("tunnel, TLS and login: %v", time.Since(start).Round(time.Millisecond))
	return c
}

func randomSecret() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "P0-" + hex.EncodeToString(b)
}

// ensureUser is the smallest reconcile there is: read the user, add it if
// missing, else modify only the attributes that differ. It returns the
// number of writes it sent.
func ensureUser(ctx context.Context, t *testing.T, c *Client, name string, want map[string]string) int {
	t.Helper()
	before := c.Stats().Writes
	raw, err := c.Call(ctx, Command{Method: "user_show", Args: []any{name}, Options: map[string]any{"all": true}})
	if IsRPC(err, "NotFound") {
		opts := map[string]any{}
		for k, v := range want {
			opts[k] = v
		}
		if _, err := c.Call(ctx, Command{Method: "user_add", Args: []any{name}, Options: opts}); err != nil {
			t.Fatal(err)
		}
		return c.Stats().Writes - before
	}
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &shown); err != nil {
		t.Fatal(err)
	}
	diff := map[string]any{}
	for k, v := range want {
		cur, _ := shown.Result[k].([]any)
		if len(cur) != 1 || cur[0] != v {
			diff[k] = v
		}
	}
	if len(diff) > 0 {
		if _, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{name}, Options: diff}); err != nil {
			t.Fatal(err)
		}
	}
	return c.Stats().Writes - before
}

func userTitle(ctx context.Context, t *testing.T, c *Client, name string) string {
	t.Helper()
	raw, err := c.Call(ctx, Command{Method: "user_show", Args: []any{name}})
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Result struct {
			Title []string `json:"title"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &shown); err != nil {
		t.Fatal(err)
	}
	return strings.Join(shown.Result.Title, ",")
}

func TestLiveFreeIPAThroughTheTunnel(t *testing.T) {
	e := setupLive(t)
	ctx := context.Background()

	if os.Getenv("PILOT_FREEIPA_LIVE_EXPECT") == "forwarding-denied" {
		c, err := New(e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		err = c.Login(ctx, "admin", e.password)
		var te *TransportError
		if !errors.As(err, &te) || te.Sent || !errors.Is(err, sshdial.ErrForwardingDenied) {
			t.Fatalf("login = %v; want a not-sent ErrForwardingDenied", err)
		}
		t.Logf("login refused before anything was sent: %v", err)
		return
	}

	c := e.admin(t)
	t.Cleanup(func() {
		cl := e.admin(t)
		for _, u := range []string{"p0-live", "p0-live-limited"} {
			if _, err := cl.Call(ctx, Command{Method: "user_del", Args: []any{u}}); err != nil && !IsRPC(err, "NotFound") {
				t.Errorf("cleanup %s: %v", u, err)
			}
		}
	})

	t.Run("server and API version are checked", func(t *testing.T) {
		info, err := c.CheckServer(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("FreeIPA %s, API %s", info.ServerVersion, info.APIVersion)
	})

	t.Run("one account: create, change one field, rerun without writes", func(t *testing.T) {
		want := map[string]string{"givenname": "Phase", "sn": "Zero", "mail": "p0-live@example.test", "title": "first"}
		if n := ensureUser(ctx, t, c, "p0-live", want); n != 1 {
			t.Fatalf("create sent %d writes, want 1", n)
		}
		start := time.Now()
		if n := ensureUser(ctx, t, c, "p0-live", want); n != 0 {
			t.Fatalf("rerun sent %d writes, want 0", n)
		}
		t.Logf("steady state check: %v", time.Since(start).Round(time.Millisecond))
		want["title"] = "second"
		if n := ensureUser(ctx, t, c, "p0-live", want); n != 1 {
			t.Fatalf("one changed field sent %d writes, want 1", n)
		}
		if got := userTitle(ctx, t, c, "p0-live"); got != "second" {
			t.Fatalf("title = %q", got)
		}
		if n := ensureUser(ctx, t, c, "p0-live", want); n != 0 {
			t.Fatalf("rerun sent %d writes, want 0", n)
		}
	})

	t.Run("batch reports each item", func(t *testing.T) {
		items, err := c.Batch(ctx, []Command{
			{Method: "user_show", Args: []any{"p0-live"}},
			{Method: "user_show", Args: []any{"p0-live-missing"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if items[0].Err != nil || items[1].Err == nil || items[1].Err.Name != "NotFound" {
			t.Fatalf("items = %+v %+v", items[0].Err, items[1].Err)
		}
	})

	t.Run("a session the server ended is renewed once and the write applied once", func(t *testing.T) {
		// End the session on the server without the client knowing.
		body := []byte(`{"method":"session_logout","params":[[],{"version":"2.257"}],"id":0}`)
		if _, _, err := c.post(ctx, "/ipa/session/json", "application/json", "application/json", body); err != nil {
			t.Fatal(err)
		}
		before := c.Stats()
		if _, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{"p0-live"}, Options: map[string]any{"title": "after logout"}}); err != nil {
			t.Fatal(err)
		}
		if s := c.Stats(); s.Relogins-before.Relogins != 1 {
			t.Fatalf("relogins = %d", s.Relogins-before.Relogins)
		}
		if got := userTitle(ctx, t, c, "p0-live"); got != "after logout" {
			t.Fatalf("title = %q", got)
		}
	})

	t.Run("an account without the rights gets ACIError", func(t *testing.T) {
		initial, own := randomSecret(), randomSecret()
		if _, err := c.Call(ctx, Command{Method: "user_add", Args: []any{"p0-live-limited"}, Options: map[string]any{"givenname": "P0", "sn": "Limited"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Call(ctx, Command{Method: "passwd", Args: []any{"p0-live-limited"}, Options: map[string]any{"password": initial}}); err != nil {
			t.Fatal(err)
		}
		u, err := New(e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		var le *LoginError
		if err := u.Login(ctx, "p0-live-limited", initial); !errors.As(err, &le) || le.Reason != "password-expired" {
			t.Fatalf("first login = %v, want password-expired", err)
		}
		form := url.Values{"user": {"p0-live-limited"}, "old_password": {initial}, "new_password": {own}}.Encode()
		if resp, _, err := u.post(ctx, "/ipa/session/change_password", "application/x-www-form-urlencoded", "text/plain", []byte(form)); err != nil || resp.StatusCode != 200 {
			t.Fatalf("change_password: %v", err)
		}
		if err := u.Login(ctx, "p0-live-limited", own); err != nil {
			t.Fatal(err)
		}
		_, err = u.Call(ctx, Command{Method: "user_mod", Args: []any{"p0-live"}, Options: map[string]any{"title": "denied"}})
		if !IsRPC(err, "ACIError") {
			t.Fatalf("user_mod as a plain user = %v, want ACIError", err)
		}
		if strings.Contains(err.Error(), own) || strings.Contains(err.Error(), initial) {
			t.Fatal("the error shows a password")
		}
	})

	t.Run("a dropped tunnel: reads are re-sent, writes are unknown", func(t *testing.T) {
		before := c.Stats()
		e.drop.armed.Store(true)
		if _, err := c.Call(ctx, Command{Method: "user_show", Args: []any{"p0-live"}}); err != nil {
			t.Fatalf("read after a drop: %v", err)
		}
		if s := c.Stats(); s.ReadRetries-before.ReadRetries != 1 {
			t.Fatalf("read retries = %d", s.ReadRetries-before.ReadRetries)
		}
		e.drop.armed.Store(true)
		_, err := c.Call(ctx, Command{Method: "user_mod", Args: []any{"p0-live"}, Options: map[string]any{"title": "dropped"}})
		if !errors.As(err, new(*OutcomeUnknownError)) {
			t.Fatalf("write after a drop = %v, want an unknown outcome", err)
		}
		t.Logf("dropped write: %v; title read back: %q", err, userTitle(ctx, t, c, "p0-live"))
	})

	t.Run("a write past its deadline is unknown", func(t *testing.T) {
		_ = userTitle(ctx, t, c, "p0-live") // a warm connection
		short, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
		defer cancel()
		_, err := c.Call(short, Command{Method: "user_mod", Args: []any{"p0-live"}, Options: map[string]any{"title": "deadline"}})
		if !errors.As(err, new(*OutcomeUnknownError)) {
			t.Fatalf("write past its deadline = %v, want an unknown outcome", err)
		}
		time.Sleep(time.Second)
		t.Logf("write past its deadline: %v; title read back: %q", err, userTitle(ctx, t, c, "p0-live"))
	})

	t.Run("the wrong server name or CA fails before anything is sent", func(t *testing.T) {
		wrongName := e.cfg
		wrongName.FQDN = "not-" + e.fqdn
		wrongCA := e.cfg
		wrongCA.CA = newFakeServer(t, e.fqdn).ca
		for name, cfg := range map[string]Config{"name": wrongName, "CA": wrongCA} {
			bad, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = bad.Login(ctx, "admin", e.password)
			var te *TransportError
			if !errors.As(err, &te) || te.Sent || strings.Contains(err.Error(), e.password) {
				t.Fatalf("wrong %s: %v; want a not-sent TLS error", name, err)
			}
			t.Logf("wrong %s: %v", name, err)
		}
	})

	t.Run("full reads", func(t *testing.T) {
		for _, m := range []string{"user_find", "group_find"} {
			start := time.Now()
			entries, err := c.Find(ctx, m, nil, map[string]any{"all": true})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s --all: %d entries in %v", m, len(entries), time.Since(start).Round(time.Millisecond))
		}
	})

	t.Logf("client counters: %+v", c.Stats())
}
