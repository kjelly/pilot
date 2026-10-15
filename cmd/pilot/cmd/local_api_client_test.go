package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serveLocalAPITest(t *testing.T, handler http.Handler) string {
	t.Helper()
	// Short directory name keeps even long test names below Unix path limits.
	dir, err := os.MkdirTemp("", "pilot-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return path
}

func TestPortalClientAccessBeyondOldDeadline(t *testing.T) {
	path := serveLocalAPITest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(11 * time.Second):
			_, _ = w.Write([]byte(`{"user":"alice","hosts":[]}`))
		case <-r.Context().Done():
		}
	}))
	client := newPortalClient(path)
	access, err := client.Access(context.Background())
	if err != nil {
		t.Fatalf("access taking more than the old 10s limit failed: %v", err)
	}
	if access.User != "alice" {
		t.Fatalf("access=%+v", access)
	}
}

func TestPortalClientAccessTimeoutIsNotUnreachable(t *testing.T) {
	path := serveLocalAPITest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	client := newPortalClient(path)
	client.httpClient.Timeout = 20 * time.Millisecond
	_, err := client.Access(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "GET /v1/access timed out") || strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("timeout=%v", err)
	}
}

type localAPIFailingTransport struct{ err error }

func (t localAPIFailingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func TestLocalAPIClientsDistinguishRequestFailures(t *testing.T) {
	for _, service := range []string{"gateway", "directory", "session-store"} {
		t.Run(service, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				err     error
				message string
			}{
				{"deadline", context.DeadlineExceeded, "timed out"},
				{"canceled", context.Canceled, "canceled"},
				{"dial", &net.OpError{Op: "dial", Net: "unix", Err: errors.New("missing socket")}, "socket connection failed"},
				{"dial timeout", &net.OpError{Op: "dial", Net: "unix", Err: context.DeadlineExceeded}, "socket connection timed out"},
				{"other", errors.New("read connection reset"), "failed"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					httpClient := &http.Client{Transport: localAPIFailingTransport{tc.err}}
					var err error
					switch service {
					case "gateway":
						c := newPortalClient("unused")
						c.httpClient = httpClient
						_, err = c.Access(context.Background())
					case "directory":
						c := newDirectoryClient("unused")
						c.httpClient = httpClient
						err = c.get(context.Background(), "/v1/access", nil)
					case "session-store":
						c := newSessionStoreClient("unused")
						c.httpClient = httpClient
						err = c.get(context.Background(), "/v1/sessions", nil)
					}
					if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), tc.message) || strings.Contains(err.Error(), "unreachable") {
						t.Fatalf("error=%v, want %q wrapping %v", err, tc.message, tc.err)
					}
				})
			}
		})
	}
}

func TestPortalClientCallerDeadlineStillWins(t *testing.T) {
	path := serveLocalAPITest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	client := newPortalClient(path)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Access(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline=%v", err)
	}
}
