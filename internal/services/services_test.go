package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
	for name, data := range map[string]string{"harbor/install.sh": "#!/bin/sh\n", "harbor/docker-compose.yml": "services: {}\n"} {
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
