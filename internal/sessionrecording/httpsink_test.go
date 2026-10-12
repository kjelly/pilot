package sessionrecording

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// realTestCAFile writes srv's own leaf certificate to a temp PEM file and
// returns its path — the same shape as a real /etc/ipa/ca.crit an
// operator would configure, so NewHTTPSink's CAFile-loading code path is
// exercised for real, not bypassed.
func realTestCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write test CA file: %v", err)
	}
	return path
}

// newTLSServerWithOwnCert starts an httptest server with a freshly
// generated, distinct self-signed certificate rather than httptest's
// built-in default (Go's httptest package deliberately reuses one fixed
// baked-in certificate/key across every httptest.NewTLSServer call, so
// two default servers are NOT a real trust mismatch — this helper is
// what makes TestHTTPSinkRejectsUntrustedServer a genuine test).
func newTLSServerWithOwnCert(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sessionrecording-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"127.0.0.1", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	return srv
}

type capturedRequest struct {
	Path string
	Auth string
	Body []byte
}

// TestHTTPSinkFullLifecycle proves NewHTTPSink/Write/Close drive the
// real ingest protocol (start -> events -> finish) against a real TLS
// server (httptest.NewTLSServer, real TCP + real TLS handshake, not a
// mocked http.RoundTripper), including the bearer token header and a
// real CA-file-based trust path.
func TestHTTPSinkFullLifecycle(t *testing.T) {
	var mu sync.Mutex
	var requests []capturedRequest

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, capturedRequest{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: body})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := context.Background()
	sink, err := NewHTTPSink(ctx, HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "test-token-123", CAFile: realTestCAFile(t, srv),
		SessionID: "sess-http-1", User: "alice", GatewayID: "gw01",
		Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
	})
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}

	if err := sink.WriteBatch(ctx, []TerminalEvent{{SchemaVersion: SchemaVersion1, SessionID: "sess-http-1", Seq: 1, Stream: StreamTTYOutput, DataBase64: "aGVsbG8="}}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sink.Finish(ctx, FinishInfo{Complete: true, LastSeq: 1}); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("got %d requests, want 3 (start, events, finish): %+v", len(requests), requests)
	}
	if requests[0].Path != "/v1/sessions/start" {
		t.Fatalf("request[0].Path = %q, want /v1/sessions/start", requests[0].Path)
	}
	if requests[1].Path != "/v1/sessions/sess-http-1/events" {
		t.Fatalf("request[1].Path = %q, want /v1/sessions/sess-http-1/events", requests[1].Path)
	}
	if requests[2].Path != "/v1/sessions/sess-http-1/finish" {
		t.Fatalf("request[2].Path = %q, want /v1/sessions/sess-http-1/finish", requests[2].Path)
	}
	for i, req := range requests {
		if req.Auth != "Bearer test-token-123" {
			t.Fatalf("request[%d].Auth = %q, want %q", i, req.Auth, "Bearer test-token-123")
		}
	}

	var eventsBody eventsRequest
	if err := json.Unmarshal(requests[1].Body, &eventsBody); err != nil {
		t.Fatalf("decode events request body: %v", err)
	}
	if len(eventsBody.Events) != 1 || eventsBody.Events[0].DataBase64 != "aGVsbG8=" {
		t.Fatalf("events request body = %+v, want one event with DataBase64=aGVsbG8=", eventsBody.Events)
	}
}

// TestHTTPSinkStartFailurePropagates proves a session-store outage (or
// auth rejection) at Connect time fails NewHTTPSink itself, rather than
// surfacing only on the first Write.
func TestHTTPSinkStartFailurePropagates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid ingest token"}`))
	}))
	defer srv.Close()

	_, err := NewHTTPSink(context.Background(), HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "wrong-token", CAFile: realTestCAFile(t, srv),
		SessionID: "sess-http-2",
	})
	if err == nil {
		t.Fatalf("NewHTTPSink succeeded against a 401 start response, want an error")
	}
}

// TestHTTPSinkWriteFailurePropagates proves a rejected event (e.g. a 409
// conflict from the store) surfaces as a Write error, which the Recorder
// (recorder.go) then handles per its own failure policy — this test only
// proves the Sink side reports it truthfully.
func TestHTTPSinkWriteFailurePropagates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sessions/start" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"sequence conflict"}`))
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(context.Background(), HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "t", CAFile: realTestCAFile(t, srv), SessionID: "sess-http-3",
	})
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	if err := sink.WriteBatch(context.Background(), []TerminalEvent{{Seq: 1, Stream: StreamTTYOutput}}); err == nil {
		t.Fatalf("Write against a 409 response succeeded, want an error")
	}
}

// TestHTTPSinkRejectsUntrustedServer proves a server presenting a
// certificate NOT signed by the configured CAFile is rejected — TLS
// trust is real, not a Config field that is parsed but never enforced.
func TestHTTPSinkRejectsUntrustedServer(t *testing.T) {
	srv := newTLSServerWithOwnCert(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	otherSrv := newTLSServerWithOwnCert(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer otherSrv.Close()

	// Trust otherSrv's CA, but connect to srv — a real mismatch.
	_, err := NewHTTPSink(context.Background(), HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "t", CAFile: realTestCAFile(t, otherSrv), SessionID: "sess-http-4",
	})
	if err == nil {
		t.Fatalf("NewHTTPSink succeeded despite a CA mismatch, want a TLS verification error")
	}
}

// scriptedServer answers each request path with the next status in its
// script (200 once the script runs out) and records every request.
type scriptedServer struct {
	mu       sync.Mutex
	script   map[string][]int
	requests []capturedRequest
}

func (s *scriptedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, capturedRequest{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Body: body})
	status := http.StatusOK
	if q := s.script[r.URL.Path]; len(q) > 0 {
		status, s.script[r.URL.Path] = q[0], q[1:]
	}
	s.mu.Unlock()
	w.WriteHeader(status)
}

func (s *scriptedServer) bodies(path string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.requests {
		if r.Path == path {
			out = append(out, string(r.Body))
		}
	}
	return out
}

func newScriptedSink(t *testing.T, script map[string][]int) (*HTTPSink, *scriptedServer) {
	t.Helper()
	ss := &scriptedServer{script: script}
	srv := httptest.NewTLSServer(ss)
	t.Cleanup(srv.Close)
	sink, err := NewHTTPSink(context.Background(), HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "pit1.x.y", CAFile: realTestCAFile(t, srv), SessionID: "sess-retry",
	})
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}
	sink.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return sink, ss
}

func TestHTTPSinkRetriesTransientSameBatch(t *testing.T) {
	sink, ss := newScriptedSink(t, map[string][]int{"/v1/sessions/sess-retry/events": {503, 429, 408}})
	ev := TerminalEvent{SchemaVersion: SchemaVersion1, SessionID: "sess-retry", Seq: 7, Stream: StreamTTYOutput, DataBase64: "YQ=="}
	if err := sink.WriteBatch(context.Background(), []TerminalEvent{ev}); err != nil {
		t.Fatalf("Write after transient failures: %v", err)
	}
	bodies := ss.bodies("/v1/sessions/sess-retry/events")
	if len(bodies) != 4 {
		t.Fatalf("events requests = %d, want 4 (3 transient + success)", len(bodies))
	}
	for i, b := range bodies {
		if b != bodies[0] {
			t.Fatalf("retry %d re-sent a different body: %s vs %s", i, b, bodies[0])
		}
	}
}

func TestHTTPSinkPermanentErrorNoRetry(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409} {
		sink, ss := newScriptedSink(t, map[string][]int{"/v1/sessions/sess-retry/events": {status}})
		err := sink.WriteBatch(context.Background(), []TerminalEvent{{Seq: 1, Stream: StreamTTYOutput}})
		if !errors.Is(err, ErrSinkPermanent) {
			t.Fatalf("status %d: err = %v, want ErrSinkPermanent", status, err)
		}
		if n := len(ss.bodies("/v1/sessions/sess-retry/events")); n != 1 {
			t.Fatalf("status %d retried %d times, want exactly one request", status, n)
		}
	}
}

func TestHTTPSinkWriteStopsWhenContextEnds(t *testing.T) {
	sink, _ := newScriptedSink(t, map[string][]int{"/v1/sessions/sess-retry/events": {503, 503, 503, 503, 503, 503}})
	ctx, cancel := context.WithCancel(context.Background())
	sink.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	err := sink.WriteBatch(ctx, []TerminalEvent{{Seq: 1, Stream: StreamTTYOutput}})
	if err == nil || errors.Is(err, ErrSinkPermanent) {
		t.Fatalf("Write under a cancelled context = %v, want a transient give-up error", err)
	}
}

func TestHTTPSinkFinishCarriesLastSeq(t *testing.T) {
	sink, ss := newScriptedSink(t, map[string][]int{"/v1/sessions/sess-retry/finish": {503}})
	if err := sink.Finish(context.Background(), FinishInfo{Complete: false, LastSeq: 42, Reason: "dropped"}); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	bodies := ss.bodies("/v1/sessions/sess-retry/finish")
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("finish bodies = %q, want the identical body re-sent once after a 503", bodies)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got["last_seq"] != float64(42) || got["complete"] != false || got["ended_at"] == "" {
		t.Fatalf("finish body = %v", got)
	}
	if _, leaked := got["reason"]; leaked {
		t.Fatalf("finish body leaks the client-side reason: %v", got)
	}
}

func TestHTTPSinkStartRetriesTransient(t *testing.T) {
	ss := &scriptedServer{script: map[string][]int{"/v1/sessions/start": {502}}}
	srv := httptest.NewTLSServer(ss)
	defer srv.Close()
	if _, err := NewHTTPSink(context.Background(), HTTPSinkConfig{
		BaseURL: srv.URL, IngestToken: "t", CAFile: realTestCAFile(t, srv), SessionID: "sess-start",
	}); err != nil {
		t.Fatalf("NewHTTPSink after one transient start failure: %v", err)
	}
	if n := len(ss.bodies("/v1/sessions/start")); n != 2 {
		t.Fatalf("start requests = %d, want 2", n)
	}
}

// batchesSent decodes every events request the scripted server received.
func batchesSent(t *testing.T, ss *scriptedServer, sessionID string) [][]TerminalEvent {
	t.Helper()
	var out [][]TerminalEvent
	for _, body := range ss.bodies("/v1/sessions/" + sessionID + "/events") {
		var req eventsRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("decode events body: %v", err)
		}
		out = append(out, req.Events)
	}
	return out
}

// runBatchingWriter drives a Recorder's writer (no PTY relay) against a
// real HTTPSink, feeding it through enqueue exactly as the relays do.
func runBatchingWriter(t *testing.T, flush time.Duration, feed func(rec *Recorder, events chan TerminalEvent, ss *scriptedServer)) *scriptedServer {
	t.Helper()
	sink, ss := newScriptedSink(t, nil)
	rec := New(Options{Mode: ModeTerminalOutput, SessionID: "sess-retry", FailurePolicy: FailurePolicyFailClosed, QueueEvents: 1024, FlushInterval: flush, FailureGrace: time.Minute}, sink, testEmitter(t))
	rec.writerCtx, rec.cancelWriter = context.WithCancel(context.Background())
	t.Cleanup(rec.cancelWriter)
	events := make(chan TerminalEvent, 1024)
	stop := make(chan struct{})
	go rec.runWriter(events, stop)
	feed(rec, events, ss)
	close(stop)
	select {
	case <-rec.writerStopped:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not stop")
	}
	return ss
}

// TestHTTPSinkBatchingThresholds locks per-host recording spec §19.4 end to
// end: batches reaching HTTPSink hold at most 128 events, stop growing once
// their encoded events reach 64 KiB, and a lone event is shipped after
// FlushInterval instead of waiting for a full batch. Seqs stay in order.
func TestHTTPSinkBatchingThresholds(t *testing.T) {
	t.Run("event count", func(t *testing.T) {
		ss := runBatchingWriter(t, 10*time.Second, func(rec *Recorder, events chan TerminalEvent, _ *scriptedServer) {
			for range 300 {
				rec.enqueue(events, TerminalEvent{Stream: StreamTTYOutput, DataBase64: "YQ=="})
			}
		})
		batches := batchesSent(t, ss, "sess-retry")
		var sizes []int
		next := uint64(1)
		for _, b := range batches {
			sizes = append(sizes, len(b))
			for _, ev := range b {
				if ev.Seq != next {
					t.Fatalf("seq %d shipped where %d was next", ev.Seq, next)
				}
				next++
			}
		}
		if len(sizes) != 3 || sizes[0] != maxBatchEvents || sizes[1] != maxBatchEvents || sizes[2] != 300-2*maxBatchEvents {
			t.Fatalf("batch sizes = %v, want [128 128 44]", sizes)
		}
	})

	t.Run("encoded bytes", func(t *testing.T) {
		payload := strings.Repeat("QUFB", 1000) // 4000 base64 characters
		ss := runBatchingWriter(t, 10*time.Second, func(rec *Recorder, events chan TerminalEvent, _ *scriptedServer) {
			for range 50 {
				rec.enqueue(events, TerminalEvent{Stream: StreamTTYOutput, DataBase64: payload})
			}
		})
		batches := batchesSent(t, ss, "sess-retry")
		if len(batches) < 3 {
			t.Fatalf("got %d batches for ~200 KiB of events, want the 64 KiB threshold to split them", len(batches))
		}
		for i, b := range batches {
			total := 0
			for _, ev := range b {
				total += encodedEventSize(ev)
			}
			last := encodedEventSize(b[len(b)-1])
			if total-last >= maxBatchBytes {
				t.Fatalf("batch %d kept growing past 64 KiB: %d bytes", i, total)
			}
			if i < len(batches)-1 && total < maxBatchBytes {
				t.Fatalf("batch %d shipped at %d bytes, before any threshold", i, total)
			}
		}
	})

	t.Run("flush interval", func(t *testing.T) {
		ss := runBatchingWriter(t, 50*time.Millisecond, func(rec *Recorder, events chan TerminalEvent, ss *scriptedServer) {
			start := time.Now()
			rec.enqueue(events, TerminalEvent{Stream: StreamTTYOutput, DataBase64: "YQ=="})
			deadline := time.Now().Add(3 * time.Second)
			for len(batchesSent(t, ss, "sess-retry")) == 0 {
				if time.Now().After(deadline) {
					t.Fatal("a lone event was never flushed")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
				t.Fatalf("lone event flushed after %v, want about FlushInterval", elapsed)
			}
		})
		if batches := batchesSent(t, ss, "sess-retry"); len(batches) != 1 || len(batches[0]) != 1 {
			t.Fatalf("batches = %v, want one single-event batch", batches)
		}
	})
}
