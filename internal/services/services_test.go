package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls   []string
	code    int
	needDir bool
}

func (f *fakeRunner) Run(_ context.Context, dir, name string, args ...string) (CommandResult, error) {
	if f.needDir {
		if _, err := os.Stat(dir); err != nil {
			return CommandResult{}, err
		}
	}
	f.calls = append(f.calls, strings.Join(append([]string{dir, name}, args...), " "))
	return CommandResult{Stdout: "Docker Compose version v2.30\n", ExitCode: f.code}, nil
}

func TestManagerCreatesPersistentRootBeforeComposePreflight(t *testing.T) {
	dataDir := t.TempDir()
	root := DataRoot(dataDir)
	archive := harborTestArchive(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	defer server.Close()
	profile := BuiltInDevLite()
	profile.Harbor.InstallerURL = server.URL + "/harbor.tgz"
	runner := &fakeRunner{needDir: true}
	m, err := NewManager(dataDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	m.client = server.Client()
	m.seed = func(_ context.Context, _ Profile, _ string, _ net.IP, _ *http.Client) (ClientConfig, error) {
		return ClientConfig{Profile: profile.Name}, nil
	}
	if err := m.Up(context.Background(), profile, net.ParseIP("192.168.122.1")); err != nil {
		t.Fatalf("Up failed after creating root: %v", err)
	}
	if len(runner.calls) == 0 || !strings.Contains(runner.calls[0], root) {
		t.Fatalf("first runner call did not use persistent root: %v", runner.calls)
	}
}

func harborTestArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gz)
	compose := "services:\n  proxy:\n    container_name: nginx\n    ports:\n      - 8081:8080\n"
	for name, data := range map[string]string{"harbor/install.sh": "#!/bin/sh\n", "harbor/prepare": "#!/bin/sh\n", "harbor/docker-compose.yml": compose} {
		b := []byte(data)
		h := &tar.Header{Name: name, Mode: 0o700, Size: int64(len(b))}
		if err := tarWriter.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestManagerPurgeRequiresConfirmation(t *testing.T) {
	m, err := NewManager(t.TempDir(), &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Purge(context.Background(), false); err == nil {
		t.Fatal("purge without confirmation must fail")
	}
}

func TestManagerRequiresComposeV2(t *testing.T) {
	runner := &fakeRunner{code: 1}
	m, err := NewManager(t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Up(context.Background(), BuiltInDevLite(), net.ParseIP("192.168.122.1"))
	if err == nil || !strings.Contains(err.Error(), "Compose v2") {
		t.Fatalf("want Compose v2 error, got %v", err)
	}
}

func TestManagerSeedFailureDoesNotPersistRunningState(t *testing.T) {
	dataDir := t.TempDir()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(harborTestArchive(t))
	}))
	defer server.Close()
	profile := BuiltInDevLite()
	profile.Harbor.InstallerURL = server.URL + "/harbor.tgz"
	runner := &fakeRunner{}
	m, err := NewManager(dataDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	m.client = server.Client()
	m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
		return ClientConfig{}, errors.New("metadata sync failed")
	}
	if err := m.Up(context.Background(), profile, net.ParseIP("192.168.122.1")); err == nil || !strings.Contains(err.Error(), "seed cache resources") {
		t.Fatalf("want seed failure, got %v", err)
	}
	state, err := m.current()
	if err != nil {
		t.Fatal(err)
	}
	if state.Running || state.Fingerprint != "" {
		t.Fatalf("failed seed persisted running state: %+v", state)
	}
}

func TestClientConfigFailsClosedWhenServiceProbeFails(t *testing.T) {
	m, err := NewManager(t.TempDir(), &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		return []ServiceState{{
			Profile: "dev-lite", Fingerprint: "fp", BindIP: "192.168.122.1", Running: true,
			Client: ClientConfig{AptProxyURL: "http://cache.pilot.internal:3142", RPMBaseURL: "http://cache.pilot.internal:8080/pulp/content", RegistryMirrorURL: "http://cache.pilot.internal:8081"}, UpdatedAt: time.Now(),
		}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	m.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	if _, err := m.ClientConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected fail-closed probe error, got %v", err)
	}
}

func TestClientConfigProbesAllServices(t *testing.T) {
	m, err := NewManager(t.TempDir(), &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		return []ServiceState{{
			Profile: "dev-lite", Fingerprint: "fp", BindIP: "192.168.122.1", Running: true,
			Client: ClientConfig{AptProxyURL: "http://cache.pilot.internal:3142", RPMBaseURL: "http://cache.pilot.internal:8080/pulp/content", RegistryMirrorURL: "http://cache.pilot.internal:8081"}, UpdatedAt: time.Now(),
		}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var paths []string
	m.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
	})}
	if _, err := m.ClientConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/acng-report.html", "/pulp/api/v3/status/", "/api/v2.0/health"} {
		if !slices.Contains(paths, want) {
			t.Errorf("missing probe %s in %v", want, paths)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
