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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		SessionID: "sess-http-1", User: "alice", DirectoryID: "dir01", GatewayID: "gw01",
		Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
	})
	if err != nil {
		t.Fatalf("NewHTTPSink: %v", err)
	}

	if err := sink.Write(ctx, TerminalEvent{SchemaVersion: SchemaVersion1, SessionID: "sess-http-1", Seq: 1, Stream: StreamTTYOutput, DataBase64: "aGVsbG8="}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
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
	if err := sink.Write(context.Background(), TerminalEvent{Seq: 1, Stream: StreamTTYOutput}); err == nil {
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
