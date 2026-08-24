package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func resolvedTargetFor(t *testing.T, srv *httptest.Server, profile Profile) ResolvedTarget {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return ResolvedTarget{
		Target:      Target{Name: "t", Address: u.Host, Profile: "p"},
		Profile:     profile,
		Scheme:      profile.EffectiveScheme(),
		MetricsPath: profile.EffectiveMetricsPath(),
	}
}

func TestTestConnectivity_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("go_goroutines 5\nprocess_cpu_seconds_total 1.2\n"))
	}))
	defer srv.Close()

	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), nil, DefaultTestOptions())
	if !report.Pass {
		t.Fatalf("expected PASS, got steps: %+v", report.Steps)
	}
}

func TestTestConnectivity_HTMLBodyFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<!doctype html><html><body>login</body></html>"))
	}))
	defer srv.Close()

	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), nil, DefaultTestOptions())
	if report.Pass {
		t.Fatalf("expected FAIL for an HTML body, got PASS")
	}
}

func TestTestConnectivity_NonOKStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), nil, DefaultTestOptions())
	if report.Pass {
		t.Fatalf("expected FAIL for a 404 status, got PASS")
	}
}

func TestTestConnectivity_UnreachableFails(t *testing.T) {
	rt := ResolvedTarget{
		Target:      Target{Name: "t", Address: "127.0.0.1:1", Profile: "p"}, // port 1 is reserved/never listens
		Profile:     Profile{JobName: "j"},
		Scheme:      "http",
		MetricsPath: "/metrics",
	}
	opts := DefaultTestOptions()
	report := TestConnectivity(context.Background(), rt, nil, opts)
	if report.Pass {
		t.Fatalf("expected FAIL for an unreachable target, got PASS")
	}
}

func TestTestConnectivity_BasicAuthSent(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		_, _ = w.Write([]byte("up 1\n"))
	}))
	defer srv.Close()

	cred := &AuthCredential{Type: "basic", Username: "demo", Password: "secret"}
	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), cred, DefaultTestOptions())
	if !report.Pass {
		t.Fatalf("expected PASS, got steps: %+v", report.Steps)
	}
	if !gotOK || gotUser != "demo" || gotPass != "secret" {
		t.Fatalf("basic auth not sent correctly: user=%q pass=%q ok=%v", gotUser, gotPass, gotOK)
	}
}

func TestLooksLikePrometheusText(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"html", "<html></html>", false},
		{"simple metric", "up 1\n", true},
		{"metric with labels", `up{job="x"} 1` + "\n", true},
		{"only comments", "# HELP x\n# TYPE x gauge\n", false},
	}
	for _, c := range cases {
		if got := looksLikePrometheusText([]byte(c.body)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTestConnectivity_RedirectToDifferentHostRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/metrics", http.StatusFound)
	}))
	defer srv.Close()
	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), nil, DefaultTestOptions())
	if report.Pass {
		t.Fatalf("expected FAIL when the target redirects to a different host, got PASS")
	}
}

// TestTestConnectivity_MaxResponseEnforced guards against a target that
// streams an unbounded body — spec.md §30's "限制 response body 大小".
func TestTestConnectivity_MaxResponseEnforced(t *testing.T) {
	const big = 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := "metric_name 1\n"
		w.Header().Set("Content-Length", strconv.Itoa(len(line)*big))
		for i := 0; i < big; i++ {
			_, _ = w.Write([]byte(line))
		}
	}))
	defer srv.Close()
	opts := DefaultTestOptions()
	opts.MaxResponse = 10 // far smaller than the real body
	report := TestConnectivity(context.Background(), resolvedTargetFor(t, srv, Profile{JobName: "j"}), nil, opts)
	// A truncated body (10 bytes of "metric_nam") does not match
	// metricLine, so this should fail closed rather than falsely pass.
	if report.Pass {
		t.Fatalf("expected the truncated body to fail the payload check, got PASS: %+v", report.Steps)
	}
	if strings.Contains(report.Steps[len(report.Steps)-1].Name, "TLS") {
		t.Fatalf("unexpected TLS step for an http:// target")
	}
}
