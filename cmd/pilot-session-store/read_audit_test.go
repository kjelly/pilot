package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sessionaudit"
	"github.com/kjelly/pilot/internal/sessionstore"
)

// auditSink collects audit JSON lines.
type auditSink struct {
	mu    sync.Mutex
	lines []string
}

func (a *auditSink) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, string(p))
	return len(p), nil
}

func (a *auditSink) events(t *testing.T) []sessionaudit.SessionAuditEvent {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []sessionaudit.SessionAuditEvent
	for _, l := range a.lines {
		var ev sessionaudit.SessionAuditEvent
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("decode audit %q: %v", l, err)
		}
		out = append(out, ev)
	}
	return out
}

func (a *auditSink) text() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.lines, "\n")
}

func readGet(t *testing.T, client *http.Client, path string) int {
	t.Helper()
	resp, err := client.Get("http://unix" + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestReadAPIAuditsReplayAndExport locks SS25 (per-host recording spec
// §21.5): every replay/export request, successful or not, emits a
// recording_replayed / recording_exported event naming the auditor and the
// recorded session, and never any terminal payload.
func TestReadAPIAuditsReplayAndExport(t *testing.T) {
	store := newTestStoreForReadAPI(t)
	ctx := context.Background()
	if err := store.StartSession(ctx, sessionstore.SessionStart{
		SessionID: "sess-audit", User: "alice", GatewayID: "gw01", Scope: "gpu", Target: "db.example.test",
		RecordingMode: "terminal_output", RecordingPolicySource: "host", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	const payload = "SECRET-PAYLOAD-7d1e"
	if _, err := store.IngestEvents(ctx, "sess-audit", []sessionstore.IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte(payload)}}); err != nil {
		t.Fatal(err)
	}

	audit := &auditSink{}
	metrics := newStoreMetrics()
	client := testReadServerWith(t, store, "", func(s *readServer) {
		s.emitter = sessionaudit.NewWriterEmitter("pilot-session-store", audit)
		s.metrics = metrics
	})
	for path, want := range map[string]int{
		"/v1/sessions/sess-audit/replay":                http.StatusOK,
		"/v1/sessions/sess-audit/replay?purpose=export": http.StatusOK,
		"/v1/sessions/missing/replay?purpose=export":    http.StatusNotFound,
		"/v1/sessions/sess-audit/replay?purpose=bogus":  http.StatusBadRequest,
	} {
		if got := readGet(t, client, path); got != want {
			t.Fatalf("GET %s = %d, want %d", path, got, want)
		}
	}

	type key struct{ kind, sid, result string }
	got := map[key]sessionaudit.SessionAuditEvent{}
	for _, ev := range audit.events(t) {
		got[key{ev.Kind, ev.SessionID, ev.Result}] = ev
	}
	me := currentUsername(t)
	for _, k := range []key{
		{sessionaudit.KindRecordingReplayed, "sess-audit", "ok"},
		{sessionaudit.KindRecordingExported, "sess-audit", "ok"},
		{sessionaudit.KindRecordingExported, "missing", "not_found"},
		{sessionaudit.KindRecordingReplayed, "sess-audit", "error"},
	} {
		ev, ok := got[k]
		if !ok {
			t.Fatalf("no audit event %+v; got %v", k, audit.text())
		}
		if ev.Auditor != me {
			t.Errorf("%+v: auditor = %q, want %q", k, ev.Auditor, me)
		}
		if k.sid == "sess-audit" && (ev.User != "alice" || ev.TargetFQDN != "db.example.test" || ev.GatewayID != "gw01" || ev.GatewayScope != "gpu" || ev.RecordingMode != "terminal_output") {
			t.Errorf("%+v: session identity missing: %+v", k, ev)
		}
		if k.sid == "missing" && ev.User != "" {
			t.Errorf("%+v: unknown session carries a user %q", k, ev.User)
		}
	}
	if text := audit.text(); strings.Contains(text, payload) || strings.Contains(text, base64.StdEncoding.EncodeToString([]byte(payload))) {
		t.Fatalf("audit events carry terminal payload: %s", text)
	}
	out := metrics.registry.Render()
	for _, line := range []string{
		`pilot_session_store_read_requests_total{action="replay",result="ok"} 1`,
		`pilot_session_store_read_requests_total{action="export",result="ok"} 1`,
		`pilot_session_store_read_requests_total{action="export",result="not_found"} 1`,
		`pilot_session_store_read_requests_total{action="replay",result="error"} 1`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("metrics lack %q:\n%s", line, out)
		}
	}

	// A caller outside the auditor group is denied, and that is audited too.
	denied := &auditSink{}
	client = testReadServerWith(t, store, "pilot-test-no-such-auditor-group", func(s *readServer) {
		s.emitter = sessionaudit.NewWriterEmitter("pilot-session-store", denied)
	})
	if got := readGet(t, client, "/v1/sessions/sess-audit/replay?purpose=export"); got != http.StatusUnauthorized {
		t.Fatalf("non-auditor replay = %d, want 401", got)
	}
	evs := denied.events(t)
	if len(evs) != 1 || evs[0].Kind != sessionaudit.KindRecordingExported || evs[0].Result != "denied" || evs[0].Auditor != me {
		t.Fatalf("denied audit = %+v", evs)
	}
}

// TestMetricsTextfileStoreCounters locks the store series of per-host
// recording spec §31 over the real ingest API.
func TestMetricsTextfileStoreCounters(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	if code, body := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
		t.Fatalf("start = %d %s", code, body)
	}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1, 3)); code != http.StatusOK {
		t.Fatalf("events = %d", code)
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	for range 2 { // the retry must not count a second finished session
		if code, body := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 4)); code != http.StatusOK {
			t.Fatalf("finish = %d %s", code, body)
		}
	}
	h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 5)) // after finish: 409
	h.post("not-a-token", "/v1/sessions/start", startBody(c))        // malformed: 401

	out := h.metrics.registry.Render()
	for _, line := range []string{
		`pilot_session_store_ingest_requests_total{endpoint="start",code="2xx"} 1`,
		`pilot_session_store_ingest_requests_total{endpoint="start",code="4xx"} 1`,
		`pilot_session_store_ingest_requests_total{endpoint="finish",code="2xx"} 2`,
		`pilot_session_store_ingest_requests_total{endpoint="events",code="4xx"} 1`,
		`pilot_session_store_ingest_auth_failures_total{reason="malformed"} 1`,
		`pilot_session_store_ingest_auth_failures_total{reason="session_finished"} 1`,
		`pilot_session_store_sessions_finished_total{mode="terminal_output",complete="false"} 1`,
		`pilot_session_store_gap_ranges_detected_total 2`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("metrics lack %q:\n%s", line, out)
		}
	}
	for _, leaked := range []string{sidA, "alice", "target01.example.test"} {
		if strings.Contains(out, leaked) {
			t.Errorf("metrics leak high-cardinality value %q", leaked)
		}
	}
}

// TestMetricsAlertedSeriesStartAtZero: the series the alert rules read
// exist at 0 before anything happens, so Prometheus's increase() sees the
// first 5xx or incomplete session after a restart.
func TestMetricsAlertedSeriesStartAtZero(t *testing.T) {
	out := newStoreMetrics().registry.Render()
	for _, want := range []string{
		`pilot_session_store_ingest_requests_total{endpoint="events",code="5xx"} 0`,
		`pilot_session_store_ingest_requests_total{endpoint="finish",code="5xx"} 0`,
		`pilot_session_store_sessions_finished_total{mode="terminal_output",complete="false"} 0`,
		`pilot_session_store_ingest_auth_failures_total{reason="bad_signature"} 0`,
		"pilot_session_store_gap_ranges_detected_total 0",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("fresh metrics lack %q:\n%s", want, out)
		}
	}
}

// TestAlertRulesMatchStoreSeries: every store series the shipped alert
// rules select is one this process renders from start.
func TestAlertRulesMatchStoreSeries(t *testing.T) {
	rules, err := os.ReadFile("../../playbooks/apply/files/pilot-alert-rules-seed.yml")
	if err != nil {
		t.Fatal(err)
	}
	out := newStoreMetrics().registry.Render()
	for expr, series := range map[string]string{
		`pilot_session_store_sessions_finished_total{complete="false"}`: `,complete="false"} 0`,
		`pilot_session_store_ingest_requests_total{code="5xx"}`:         `,code="5xx"} 0`,
		`pilot_session_store_metrics_last_write_timestamp_seconds`:      "# TYPE pilot_session_store_metrics_last_write_timestamp_seconds gauge",
	} {
		if !strings.Contains(string(rules), expr) {
			t.Errorf("alert rules no longer select %s", expr)
		}
		if !strings.Contains(out, series) {
			t.Errorf("store metrics do not render %q for rule selector %s", series, expr)
		}
	}
}
