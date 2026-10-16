// Package freeiparpc is the FreeIPA JSON-RPC writer for the Go identity
// reconcile engine: a password-login session over a caller-supplied dialer
// (an SSH tunnel in practice, see internal/sshdial), TLS that trusts only the
// pinned IPA CA, a method allowlist, batch calls, and errors that say whether
// a write may have happened.
//
// It is separate from internal/freeipaaccess on purpose: that package is the
// gateway's read-only reader and must not gain write methods.
//
// The behaviour below follows responses captured from FreeIPA 4.13.4
// (testdata/, docs/superpowers/specs/2026-10-16-freeipa-go-reconcile-phase0-contract.md §2).
package freeiparpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// DefaultSupportedAPIVersions are the FreeIPA API versions this package was
// verified against. FreeIPA does not reject a client sending another version
// (captured), so the client checks.
var DefaultSupportedAPIVersions = []string{"2.257"}

// apiVersion is sent with every command.
const apiVersion = "2.257"

// sessionCookie is the cookie login_password sets.
const sessionCookie = "ipa_session"

// Config describes one FreeIPA server.
type Config struct {
	// FQDN is the server's name: the URL host, TLS server name and Referer.
	FQDN string
	// CA is the only certificate authority trusted for the server.
	CA *x509.CertPool
	// DialContext opens the connection to the server's HTTPS port.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RequestTimeout bounds each HTTP request; default 2 minutes.
	RequestTimeout time.Duration
	// SupportedAPIVersions; default DefaultSupportedAPIVersions.
	SupportedAPIVersions []string
}

var fqdnRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// credentials are kept behind a pointer so formatting a Client never
// prints them.
type credentials struct {
	user     string
	password string
}

// Stats counts what a Client sent.
type Stats struct {
	HTTPRequests int // every POST, logins included
	Logins       int
	Reads        int // read commands sent (batch items counted one by one)
	Writes       int // write commands sent (batch items counted one by one)
	ReadRetries  int // reads re-sent after a transport failure
	Relogins     int // logins after the server rejected the session
	Unknown      int // writes whose outcome is unknown
}

// Client is a FreeIPA JSON-RPC session. It is safe for concurrent use.
type Client struct {
	cfg  Config
	base string
	http *http.Client

	mu    sync.Mutex
	creds *credentials
	stats Stats
}

// New checks cfg and returns a Client with no session yet.
func New(cfg Config) (*Client, error) {
	if !fqdnRe.MatchString(cfg.FQDN) {
		return nil, fmt.Errorf("freeiparpc: invalid server FQDN %q", cfg.FQDN)
	}
	if cfg.CA == nil {
		return nil, errors.New("freeiparpc: no CA to trust")
	}
	if cfg.DialContext == nil {
		return nil, errors.New("freeiparpc: no dialer")
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 2 * time.Minute
	}
	if len(cfg.SupportedAPIVersions) == 0 {
		cfg.SupportedAPIVersions = DefaultSupportedAPIVersions
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	dial := cfg.DialContext
	tlsConfig := &tls.Config{RootCAs: cfg.CA, ServerName: cfg.FQDN, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{
		Proxy: nil, // never HTTP(S)_PROXY: the dialer decides the path
		// The handshake happens here, before any request is written, so a
		// failure to open the tunnel or to verify the server is marked as
		// not sent: a write that meets it did not happen.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, &notSentError{err}
			}
			hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			tc := tls.Client(raw, tlsConfig)
			if err := tc.HandshakeContext(hctx); err != nil {
				_ = raw.Close()
				return nil, &notSentError{fmt.Errorf("TLS handshake with %s: %w", cfg.FQDN, err)}
			}
			return tc, nil
		},
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		cfg:  cfg,
		base: "https://" + cfg.FQDN,
		http: &http.Client{Jar: jar, Transport: transport, Timeout: cfg.RequestTimeout},
	}, nil
}

// Stats returns the counters so far.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Client) count(f func(*Stats)) {
	c.mu.Lock()
	f(&c.stats)
	c.mu.Unlock()
}

// post sends one request. Every request carries the Referer FreeIPA
// requires for /ipa/session/*.
func (c *Client) post(ctx context.Context, path, contentType, accept string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Referer", c.base+"/ipa")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", accept)
	c.count(func(s *Stats) { s.HTTPRequests++ })
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, classifyTransport(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return resp, nil, &TransportError{Err: err, Sent: true}
	}
	return resp, raw, nil
}

// Login opens a session with login_password. The password stays in memory
// to log in again when the server rejects the session (see do).
func (c *Client) Login(ctx context.Context, user, password string) error {
	if err := c.login(ctx, &credentials{user: user, password: password}); err != nil {
		return err
	}
	c.mu.Lock()
	c.creds = &credentials{user: user, password: password}
	c.mu.Unlock()
	return nil
}

func (c *Client) login(ctx context.Context, cr *credentials) error {
	form := url.Values{"user": {cr.user}, "password": {cr.password}}.Encode()
	resp, _, err := c.post(ctx, "/ipa/session/login_password", "application/x-www-form-urlencoded", "text/plain", []byte(form))
	if err != nil {
		return fmt.Errorf("freeiparpc: login as %s: %w", cr.user, err)
	}
	c.count(func(s *Stats) { s.Logins++ })
	if resp.StatusCode != http.StatusOK {
		return &LoginError{User: cr.user, Status: resp.StatusCode, Reason: resp.Header.Get("X-IPA-Rejection-Reason")}
	}
	// FreeIPA scopes the cookie to /ipa (path=/ipa; httponly; secure;
	// SameSite=strict, captured).
	u, _ := url.Parse(c.base + "/ipa/session/json")
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			return nil
		}
	}
	return &LoginError{User: cr.user, Status: resp.StatusCode, Reason: "no session cookie"}
}

// Logout ends the session with the session_logout command
// (/ipa/session/logout does not exist on FreeIPA 4.13: it answers 404).
func (c *Client) Logout(ctx context.Context) error {
	body, _ := json.Marshal(request{Method: "session_logout", Params: [2]any{[]any{}, map[string]any{"version": apiVersion}}})
	resp, raw, err := c.post(ctx, "/ipa/session/json", "application/json", "application/json", body)
	c.mu.Lock()
	c.creds = nil
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil // no session to end
	}
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Status: resp.StatusCode}
	}
	_, err = decodeEnvelope(raw)
	return err
}

type request struct {
	Method string `json:"method"`
	Params [2]any `json:"params"`
	ID     int    `json:"id"`
}

// Command is one FreeIPA command: positional arguments and options, as in
// `ipa <command> <args> --<option>=<value>`, with underscores in names.
type Command struct {
	Method  string
	Args    []any
	Options map[string]any
}

func (cmd Command) params() [2]any {
	args := cmd.Args
	if args == nil {
		args = []any{}
	}
	opts := map[string]any{}
	for k, v := range cmd.Options {
		opts[k] = v
	}
	opts["version"] = apiVersion
	return [2]any{args, opts}
}

// Call sends one allowlisted command and returns its result object (the
// envelope's "result": result/value/summary, or count/truncated/result for
// a find). An application error comes back as *RPCError. A write whose
// answer does not carry a result is an *OutcomeUnknownError.
func (c *Client) Call(ctx context.Context, cmd Command) (json.RawMessage, error) {
	kind, ok := allowlist[cmd.Method]
	if !ok {
		return nil, &ErrMethodNotAllowed{Method: cmd.Method}
	}
	body, err := json.Marshal(request{Method: cmd.Method, Params: cmd.params()})
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, cmd.Method, kind == write, 1, body)
	if err != nil {
		return nil, err
	}
	// Every allowlisted command but ping answers with a non-null "result"
	// inside the result object (captured); ping has only a summary.
	if cmd.Method != "ping" {
		if err := requireField(res, "result"); err != nil {
			err = fmt.Errorf("freeiparpc: %s: %w", cmd.Method, err)
			if kind == write {
				return nil, c.unknown(cmd.Method, err)
			}
			return nil, err
		}
	}
	return res, nil
}

// unknown counts and returns a write whose outcome cannot be confirmed.
func (c *Client) unknown(method string, err error) error {
	c.count(func(s *Stats) { s.Unknown++ })
	return &OutcomeUnknownError{Method: method, Err: err}
}

// do sends a JSON-RPC body, logging in again once when the server rejects
// the session and re-sending a read once after a transport failure.
//
// A 401 from /ipa/session/json comes before the command runs (captured: a
// write sent after session_logout got 401 and changed nothing), so it is
// re-sent after the new login, write or not. Any other failure after a
// write may have reached the server is an *OutcomeUnknownError.
func (c *Client) do(ctx context.Context, method string, isWrite bool, items int, body []byte) (json.RawMessage, error) {
	relogged, retried := false, false
	for {
		c.count(func(s *Stats) {
			if isWrite {
				s.Writes += items
			} else {
				s.Reads += items
			}
		})
		resp, raw, err := c.post(ctx, "/ipa/session/json", "application/json", "application/json", body)
		if err != nil {
			var te *TransportError
			sent := !errors.As(err, &te) || te.Sent
			switch {
			case isWrite && sent:
				return nil, c.unknown(method, err)
			case !isWrite && !retried && ctx.Err() == nil:
				retried = true
				c.count(func(s *Stats) { s.ReadRetries++ })
				continue
			}
			return nil, fmt.Errorf("freeiparpc: %s: %w", method, err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			c.mu.Lock()
			cr := c.creds
			c.mu.Unlock()
			if relogged || cr == nil {
				return nil, fmt.Errorf("freeiparpc: %s: %w", method, ErrSessionRejected)
			}
			relogged = true
			c.count(func(s *Stats) { s.Relogins++ })
			if err := c.login(ctx, cr); err != nil {
				return nil, fmt.Errorf("freeiparpc: %s: session rejected, login again failed: %w", method, err)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			if isWrite {
				return nil, c.unknown(method, &HTTPError{Status: resp.StatusCode})
			}
			return nil, fmt.Errorf("freeiparpc: %s: %w", method, &HTTPError{Status: resp.StatusCode})
		}
		res, err := decodeEnvelope(raw)
		if err != nil {
			var rpcErr *RPCError
			if isWrite && !errors.As(err, &rpcErr) {
				return nil, c.unknown(method, err)
			}
			return nil, err
		}
		return res, nil
	}
}

// ErrIncompleteResponse is an answer without the fields that say what
// happened: it is never taken as success.
var ErrIncompleteResponse = errors.New("incomplete response")

// decodeEnvelope returns the result object of a JSON-RPC answer, or its
// *RPCError. Every FreeIPA answer has "error" (null on success) and, on
// success, a "result" object (captured); anything else is incomplete.
func decodeEnvelope(raw []byte) (json.RawMessage, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil || env == nil {
		return nil, fmt.Errorf("freeiparpc: decode response: %w", ErrIncompleteResponse)
	}
	if e, ok := env["error"]; ok && !isNull(e) {
		var rpcErr RPCError
		if err := json.Unmarshal(e, &rpcErr); err != nil || rpcErr.Name == "" {
			return nil, fmt.Errorf("freeiparpc: error object without a name: %w", ErrIncompleteResponse)
		}
		return nil, &rpcErr
	}
	res, ok := env["result"]
	if !ok || !isObject(res) {
		return nil, fmt.Errorf("freeiparpc: no result object: %w", ErrIncompleteResponse)
	}
	return res, nil
}

func isNull(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func isObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}

// requireField fails unless obj is a JSON object holding key with a
// non-null value.
func requireField(obj json.RawMessage, key string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(obj, &m); err != nil || m == nil {
		return fmt.Errorf("result is not an object: %w", ErrIncompleteResponse)
	}
	if v, ok := m[key]; !ok || isNull(v) {
		return fmt.Errorf("result has no %q: %w", key, ErrIncompleteResponse)
	}
	return nil
}
