package monitoring

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// TestOptions bounds a connectivity test (spec.md §30). Zero values are
// replaced by DefaultTestOptions' values by TestConnectivity.
type TestOptions struct {
	ConnectTimeout time.Duration
	RequestTimeout time.Duration
	MaxResponse    int64
}

// DefaultTestOptions matches spec.md §30's suggested defaults.
func DefaultTestOptions() TestOptions {
	return TestOptions{
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 10 * time.Second,
		MaxResponse:    8 << 20, // 8 MiB
	}
}

// TestStep is one stage of the pipeline spec.md §29 describes (DNS -> TCP ->
// TLS -> auth -> GET -> status -> payload).
type TestStep struct {
	Name   string
	Pass   bool
	Detail string
}

// TestReport is the full result of TestConnectivity — everything `pilot
// monitoring target test` needs to render spec.md §29's example output.
type TestReport struct {
	TargetName string
	Address    string
	Profile    string
	Steps      []TestStep
	Pass       bool
}

func (r *TestReport) step(name string, pass bool, detail string) {
	r.Steps = append(r.Steps, TestStep{Name: name, Pass: pass, Detail: detail})
	if !pass {
		r.Pass = false
	}
}

// metricLine is a deliberately loose heuristic for "this looks like
// Prometheus/OpenMetrics exposition text", not a full parser (spec.md §31
// explicitly allows this fallback when depending on the official Prometheus
// parser library "不合理" for a first version — this repo keeps its
// dependency tree minimal on purpose, see AGENTS.md/memory on the
// post-agent-surface-retirement go.mod). It only needs to distinguish real
// metrics text from an HTML login page or an empty body, not validate full
// exposition-format correctness.
var metricLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+\S+`)

// looksLikePrometheusText reports whether body has at least one line that
// looks like a metric sample and no line that looks like an HTML document
// (spec.md §31: "避免只檢查 HTTP 200 — 這可能只是 HTML login page").
func looksLikePrometheusText(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	if bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<!doctype")) || bytes.HasPrefix(trimmed, []byte("<")) {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if metricLine.MatchString(line) {
			return true
		}
	}
	return false
}

// TestConnectivity runs spec.md §29's pipeline against rt, authenticating
// with cred when rt.Profile.AuthRef is set (cred may be nil otherwise).
// Never logs cred's password/token (spec.md §30) — callers must apply the
// same discipline to anything they print from the returned TestReport,
// which itself never carries the credential.
func TestConnectivity(ctx context.Context, rt ResolvedTarget, cred *AuthCredential, opts TestOptions) TestReport {
	def := DefaultTestOptions()
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = def.ConnectTimeout
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = def.RequestTimeout
	}
	if opts.MaxResponse <= 0 {
		opts.MaxResponse = def.MaxResponse
	}

	report := TestReport{TargetName: rt.Target.Name, Address: rt.Target.Address, Profile: rt.Target.Profile, Pass: true}

	host, port, err := net.SplitHostPort(rt.Target.Address)
	if err != nil {
		report.step("resolve profile", false, fmt.Sprintf("invalid address %q: %v", rt.Target.Address, err))
		return report
	}
	report.step("profile exists", true, rt.Target.Profile)

	resolveCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	ips, err := net.DefaultResolver.LookupHost(resolveCtx, host)
	cancel()
	if err != nil {
		report.step("DNS resolution", false, fmt.Sprintf("%s: %v", host, err))
		return report
	}
	report.step("DNS resolution", true, fmt.Sprintf("%s -> %s", host, strings.Join(ips, ", ")))

	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	dialCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		report.step("TCP connection", false, fmt.Sprintf("%s: %v", rt.Target.Address, err))
		return report
	}
	report.step("TCP connection", true, rt.Target.Address)

	if rt.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: host}
		if rt.Profile.TLS != nil {
			if rt.Profile.TLS.ServerName != "" {
				tlsCfg.ServerName = rt.Profile.TLS.ServerName
			}
			tlsCfg.InsecureSkipVerify = rt.Profile.TLS.InsecureSkipVerify //nolint:gosec // operator opt-in, validated+warned at save time (spec.md §44)
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			report.step("TLS handshake", false, err.Error())
			return report
		}
		report.step("TLS certificate", true, tlsConn.ConnectionState().ServerName)
		conn = tlsConn
	}
	_ = conn.Close() // the probe above is enough to prove reachability; the real request below opens its own connection via http.Client.

	client := &http.Client{
		Timeout: opts.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Hostname() != host {
				return fmt.Errorf("refusing to follow redirect to a different host: %s", req.URL.Hostname())
			}
			return nil
		},
	}
	url := fmt.Sprintf("%s://%s%s", rt.Scheme, rt.Target.Address, rt.MetricsPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		report.step(fmt.Sprintf("GET %s", rt.MetricsPath), false, err.Error())
		return report
	}
	if cred != nil {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		report.step(fmt.Sprintf("GET %s", rt.MetricsPath), false, "request failed") // never include err.Error() verbatim: it can echo back the request URL with embedded creds on some transport errors
		return report
	}
	defer resp.Body.Close()
	report.step(fmt.Sprintf("GET %s", rt.MetricsPath), true, fmt.Sprintf("%d", resp.StatusCode))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		report.step("HTTP status validation", false, fmt.Sprintf("%d", resp.StatusCode))
		return report
	}
	report.step("HTTP status validation", true, fmt.Sprintf("%d", resp.StatusCode))

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxResponse))
	if err != nil {
		report.step("metrics payload", false, fmt.Sprintf("read body: %v", err))
		return report
	}
	if !looksLikePrometheusText(body) {
		report.step("metrics payload", false, "response does not look like Prometheus/OpenMetrics exposition text")
		return report
	}
	report.step("metrics payload", true, fmt.Sprintf("%d bytes", len(body)))

	return report
}
