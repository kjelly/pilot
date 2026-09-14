package freeipaaccess

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config configures the live Kerberos/JSON-RPC transport (spec.md
// §11.1/§12/§26). Adopted transport, per the Phase 0 spike (see
// docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md):
// direct Go SPNEGO via github.com/jcmturner/gokrb5/v8 — no kinit/curl
// fallback, no cgo.
type Config struct {
	// Servers are FreeIPA server FQDNs tried in order (spec.md §12
	// failover: a server that fails at the transport level is skipped in
	// favor of the next one; a definitive JSON-RPC answer from any server
	// is never retried against another as if it might change — spec.md
	// §12 "Authorization/RPC permission error不可 retry 成另一種判定").
	Servers []string
	// CAFile is the FreeIPA CA bundle path (spec.md §11: /etc/ipa/ca.crt).
	// There is deliberately no InsecureSkipVerify escape hatch.
	CAFile string
	// ServicePrincipal is this gateway's own principal: either
	// "pilot-access-gateway/gw01.example.com" (realm supplied separately
	// via Realm or krb5.conf's default_realm) or the full
	// "pilot-access-gateway/gw01.example.com@REALM" form spec.md §26's
	// example config uses — an embedded "@REALM" is split out automatically.
	ServicePrincipal string
	// Realm defaults to krb5.conf's default_realm when empty — spec.md
	// §26's example config has no explicit realm field, and a correctly
	// enrolled host's krb5.conf already names it authoritatively.
	Realm      string
	KeytabPath string
	// Krb5ConfPath defaults to /etc/krb5.conf when empty.
	Krb5ConfPath string
	// RequestTimeout bounds every HTTP call (spec.md §26 default 5s).
	RequestTimeout time.Duration
}

func (c Config) requestTimeout() time.Duration {
	if c.RequestTimeout > 0 {
		return c.RequestTimeout
	}
	return 5 * time.Second
}

func (c Config) krb5ConfPath() string {
	if c.Krb5ConfPath != "" {
		return c.Krb5ConfPath
	}
	return "/etc/krb5.conf"
}

// Client is the live FreeIPA JSON-RPC Provider.
type Client struct {
	cfg       Config
	krb5      *client.Client
	transport http.RoundTripper

	mu      sync.Mutex
	server  string
	session *spnego.Client // nil until a session is established
}

var _ Provider = (*Client)(nil)

// NewClient builds a Client. It loads the krb5 config, keytab, and CA
// bundle but does not contact FreeIPA yet — the session is established
// lazily, with failover across cfg.Servers, on the first call.
func NewClient(cfg Config) (*Client, error) {
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("freeipaaccess: at least one server is required")
	}
	krb5Conf, err := config.Load(cfg.krb5ConfPath())
	if err != nil {
		return nil, fmt.Errorf("load krb5 config: %w", err)
	}
	kt, err := keytab.Load(cfg.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("load keytab: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read FreeIPA CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse FreeIPA CA file %s: no certificates found", cfg.CAFile)
	}
	principal, embeddedRealm := splitPrincipalRealm(cfg.ServicePrincipal)
	realm := cfg.Realm
	if realm == "" {
		realm = embeddedRealm
	}
	if realm == "" {
		realm = krb5Conf.LibDefaults.DefaultRealm
	}
	if realm == "" {
		return nil, fmt.Errorf("freeipaaccess: no realm configured and %s has no default_realm", cfg.krb5ConfPath())
	}
	krb5Cl := client.NewWithKeytab(principal, realm, kt, krb5Conf, client.DisablePAFXFAST(true))
	return &Client{
		cfg:  cfg,
		krb5: krb5Cl,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// splitPrincipalRealm splits an optional "@REALM" suffix off a service
// principal (spec.md §26's example config embeds it, e.g.
// ".../pilot-gw-gpu-01.linker.internal@LINKER.INTERNAL", matching how
// ipa-getkeytab/klist print a full principal name). realm is "" when no
// "@" is present.
func splitPrincipalRealm(servicePrincipal string) (principal, realm string) {
	name, r, _ := strings.Cut(servicePrincipal, "@")
	return name, r
}

// errSessionExpired signals that the cached session cookie was rejected
// (HTTP 401) and a fresh login is needed — distinct from every other
// error, which is final for that call (spec.md §12).
var errSessionExpired = errors.New("freeipaaccess: session expired")

func (c *Client) httpClient() *http.Client {
	return &http.Client{Timeout: c.cfg.requestTimeout(), Transport: c.transport}
}

func (c *Client) loginTo(ctx context.Context, server string) (*spnego.Client, error) {
	httpCl := c.httpClient()
	spn := "HTTP/" + server
	sc := spnego.NewClient(c.krb5, httpCl, spn)
	loginURL := "https://" + server + "/ipa/session/login_kerberos"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return nil, err
	}
	// FreeIPA's httpd rejects ANY /ipa/session/* request without a Referer,
	// including this login request itself — Phase 0 spike finding.
	req.Header.Set("Referer", "https://"+server+"/ipa")
	if err := spnego.SetSPNEGOHeader(c.krb5, req, spn); err != nil {
		return nil, fmt.Errorf("spnego negotiate against %s: %w", server, err)
	}
	resp, err := sc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login_kerberos against %s: %w", server, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login_kerberos against %s: HTTP %d", server, resp.StatusCode)
	}
	return sc, nil
}

func (c *Client) ensureSession(ctx context.Context) (*spnego.Client, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, c.server, nil
	}
	var lastErr error
	for _, server := range c.cfg.Servers {
		sc, err := c.loginTo(ctx, server)
		if err != nil {
			lastErr = err
			continue
		}
		c.session = sc
		c.server = server
		return sc, server, nil
	}
	return nil, "", fmt.Errorf("freeipaaccess: could not establish a session against any configured server (%d tried): %w", len(c.cfg.Servers), lastErr)
}

func (c *Client) dropSession() {
	c.mu.Lock()
	c.session = nil
	c.mu.Unlock()
}

func (c *Client) doCall(ctx context.Context, sc *spnego.Client, server string, body []byte) (rpcEnvelope, error) {
	rpcURL := "https://" + server + "/ipa/session/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return rpcEnvelope{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://"+server+"/ipa")
	resp, err := sc.Do(req)
	if err != nil {
		return rpcEnvelope{}, fmt.Errorf("freeipa json-rpc call to %s: %w", server, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return rpcEnvelope{}, fmt.Errorf("read freeipa json-rpc response from %s: %w", server, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return rpcEnvelope{}, errSessionExpired
	}
	if resp.StatusCode != http.StatusOK {
		return rpcEnvelope{}, fmt.Errorf("freeipa json-rpc call to %s: HTTP %d: %s", server, resp.StatusCode, string(respBody))
	}
	return decodeEnvelope(respBody)
}

// call establishes (or reuses) a session, performs one JSON-RPC call, and
// retries exactly once — against the same server, after a fresh login —
// if the cached session was rejected. Any other error, including a
// well-formed RPCError, is returned as-is: it is a final answer, not
// something to retry against a different server (spec.md §12).
func (c *Client) call(ctx context.Context, method string, positional []any, named map[string]any) (rpcEnvelope, error) {
	body, err := newRPCRequest(method, positional, named)
	if err != nil {
		return rpcEnvelope{}, err
	}
	sc, server, err := c.ensureSession(ctx)
	if err != nil {
		return rpcEnvelope{}, err
	}
	env, err := c.doCall(ctx, sc, server, body)
	if errors.Is(err, errSessionExpired) {
		c.dropSession()
		sc, server, err = c.ensureSession(ctx)
		if err != nil {
			return rpcEnvelope{}, err
		}
		env, err = c.doCall(ctx, sc, server, body)
	}
	return env, err
}

func (c *Client) Ping(ctx context.Context) (PingResult, error) {
	env, err := c.call(ctx, "ping", nil, nil)
	if err != nil {
		return PingResult{}, err
	}
	return parsePing(env)
}

func (c *Client) UserShow(ctx context.Context, username string) (User, error) {
	env, err := c.call(ctx, "user_show", []any{username}, map[string]any{"all": true})
	if err != nil {
		return User{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return User{}, err
	}
	return parseUser(m), nil
}

func (c *Client) GroupShow(ctx context.Context, name string) (Group, error) {
	env, err := c.call(ctx, "group_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return Group{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return Group{}, err
	}
	return parseGroup(m), nil
}

func (c *Client) HostShow(ctx context.Context, fqdn string) (Host, error) {
	env, err := c.call(ctx, "host_show", []any{fqdn}, map[string]any{"all": true})
	if err != nil {
		return Host{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return Host{}, err
	}
	return parseHost(m), nil
}

func (c *Client) HostgroupShow(ctx context.Context, name string) (Hostgroup, error) {
	env, err := c.call(ctx, "hostgroup_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return Hostgroup{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return Hostgroup{}, err
	}
	return parseHostgroup(m), nil
}

func (c *Client) HBACRuleFind(ctx context.Context) ([]HBACRule, error) {
	env, err := c.call(ctx, "hbacrule_find", []any{[]any{}}, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	rows, err := decodeFind(env)
	if err != nil {
		return nil, err
	}
	rules := make([]HBACRule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, parseHBACRule(row))
	}
	return rules, nil
}

func (c *Client) HBACServiceGroupShow(ctx context.Context, name string) (HBACServiceGroup, error) {
	env, err := c.call(ctx, "hbacsvcgroup_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return HBACServiceGroup{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return HBACServiceGroup{}, err
	}
	return parseHBACServiceGroup(m), nil
}

func (c *Client) SudoRuleFind(ctx context.Context) ([]SudoRule, error) {
	env, err := c.call(ctx, "sudorule_find", []any{[]any{}}, map[string]any{"all": true})
	if err != nil {
		return nil, err
	}
	rows, err := decodeFind(env)
	if err != nil {
		return nil, err
	}
	rules := make([]SudoRule, 0, len(rows))
	for _, row := range rows {
		rule, err := parseSudoRule(row)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (c *Client) SudoCommandShow(ctx context.Context, name string) (SudoCommand, error) {
	env, err := c.call(ctx, "sudocmd_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return SudoCommand{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return SudoCommand{}, err
	}
	return parseSudoCommand(m), nil
}

func (c *Client) SudoCommandGroupShow(ctx context.Context, name string) (SudoCommandGroup, error) {
	env, err := c.call(ctx, "sudocmdgroup_show", []any{name}, map[string]any{"all": true})
	if err != nil {
		return SudoCommandGroup{}, err
	}
	m, err := decodeShow(env)
	if err != nil {
		return SudoCommandGroup{}, err
	}
	return parseSudoCommandGroup(m), nil
}

func (c *Client) HBACTest(ctx context.Context, req HBACTestRequest) (HBACTestResult, error) {
	named := map[string]any{
		"user":       req.User,
		"targethost": req.TargetHost,
		"service":    req.Service,
	}
	env, err := c.call(ctx, "hbactest", []any{}, named)
	if err != nil {
		return HBACTestResult{}, err
	}
	return parseHBACTest(env)
}
