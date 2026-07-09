package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/config"
	"github.com/anomalyco/pilot/internal/sandbox"
	"github.com/anomalyco/pilot/internal/tools"
)

// TestNewRequiresCfg ensures that the cfg parameter is enforced.
func TestNewRequiresCfg(t *testing.T) {
	_, err := New(context.Background(), nil, Options{})
	if err == nil {
		t.Fatal("expected error for nil cfg")
	}
}

// TestNewSurvivesOllamaUnreachable documents that construction
// fails fast if Ollama is not reachable — the caller wants to
// surface a clear error to the user rather than getting stuck
// inside the loop.
func TestNewSurvivesOllamaUnreachable(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.OllamaURL = "http://127.0.0.1:1" // closed port
	_, err := New(context.Background(), cfg, Options{Banner: false})
	if err == nil {
		t.Fatal("expected error when Ollama is unreachable")
	}
}

// TestCloseIsIdempotent ensures double-close doesn't crash. This is
// the property the three command paths (run, chat, diagnose) all
// rely on because they defer res.Store.Close() independently.
func TestCloseIsIdempotent(t *testing.T) {
	a := &App{}
	a.Close()
	a.Close()
}

// TestDefaultRegistryConservativeDefaults sanity-checks that the
// conservative registry is built without panicking on a real cfg.
func TestDefaultRegistryConservativeDefaults(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "pilot-data")
	reg := defaultRegistry(cfg, nil, nil, nil, nil)
	if reg == nil {
		t.Fatal("defaultRegistry returned nil")
	}
	// Expect the 6 tools that don't require an Ollama client to be
	// present. generate_playbook is intentionally absent when oc==nil
	// because it needs an Ollama client for the in-loop generation
	// call; tests/cmd paths always pass a non-nil client.
	want := map[string]bool{
		"read_file": false, "run_command": false, "run_ansible": false,
		"ask_user": false, "run_inspec": false, "search_docs": false,
	}
	for _, n := range reg.List() {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("expected tool %q in default registry", name)
		}
	}
}

// fakeEnv lets us test SandboxImage without dragging in a real
// docker daemon. It satisfies the sandbox.Environment interface
// only for the Name() method, which is all SandboxImage touches.
type fakeEnv struct{ name string }

func (f *fakeEnv) Start(_ context.Context) error { return nil }
func (f *fakeEnv) Stop(_ context.Context) error  { return nil }
func (f *fakeEnv) Exec(_ context.Context, _ []string, _ sandbox.ExecOptions) (*sandbox.ExecResult, error) {
	return nil, nil
}
func (f *fakeEnv) ReadFile(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (f *fakeEnv) WriteFile(_ context.Context, _ string, _ []byte, _ os.FileMode) error {
	return nil
}
func (f *fakeEnv) ConnectionInfo() sandbox.AnsibleConnection { return sandbox.AnsibleConnection{} }
func (f *fakeEnv) IsAvailable(_ context.Context) error       { return nil }
func (f *fakeEnv) Name() string                              { return f.name }

func TestSandboxImage_HandlesAllShapes(t *testing.T) {
	cases := []struct {
		name string
		env  sandbox.Environment
		want string
	}{
		{"nil app", nil, ""},
		{"local env", &fakeEnv{name: "local"}, ""},
		{"docker ubuntu", &fakeEnv{name: "docker:ubuntu:22.04"}, "ubuntu:22.04"},
		{"docker rockylinux", &fakeEnv{name: "docker:rockylinux:9"}, "rockylinux:9"},
		{"docker unset (defensive)", &fakeEnv{name: "docker:<unset>"}, "<unset>"},
		{"future podman prefix", &fakeEnv{name: "podman:alpine:3.20"}, "podman:alpine:3.20"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &App{}
			if c.env != nil {
				a.Env = c.env
			}
			if got := a.SandboxImage(); got != c.want {
				t.Errorf("SandboxImage() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSandboxImage_NeverPanics(t *testing.T) {
	// Regression: a previous version did `name[len("docker:"):]`
	// which would panic on any name shorter than 7 chars.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SandboxImage panicked: %v", r)
		}
	}()
	a := &App{Env: &fakeEnv{name: ""}}
	if got := a.SandboxImage(); got != "" {
		t.Errorf("empty env name should return empty string, got %q", got)
	}
}

// buildTestApp constructs a minimal *App suitable for NewLoopWithDefaults tests
// without going through New() (which would require a live Ollama). Only the
// fields NewLoopWithDefaults actually touches are populated.
func buildTestApp(toolsRegistry *tools.Registry) *App {
	cfg := config.Default()
	cfg.DataDir = "" // no store/db needed for this test
	return &App{
		Cfg:    cfg,
		Tools:  toolsRegistry,
		Ollama: nil, // NewLoop doesn't call ollama during construction
		Store:  nil, // NewDedupTracker tolerates nil store
	}
}

// TestNewLoopWithDefaults_ReusesCachedRegistry is a regression test for the
// hang where each call to NewLoopWithDefaults rebuilt the tool registry, which
// in turn re-opened the 100 MB bleve index — a 30+ second stall per call
// that made `pilot run` feel hung between "Starting run" and the first
// proposal.
//
// We verify that calling NewLoopWithDefaults with empty defaults reuses the
// App's already-built registry (pointer equality) instead of rebuilding it.
func TestNewLoopWithDefaults_ReusesCachedRegistry(t *testing.T) {
	original := tools.NewRegistry()
	app := buildTestApp(original)

	loop := app.NewLoopWithDefaults("test-run-1", nil, "", "")
	if loop == nil {
		t.Fatal("NewLoopWithDefaults returned nil")
	}
	got := loop.Tools()
	if got != original {
		t.Errorf("NewLoopWithDefaults rebuilt the registry; expected to reuse the cached one (pointer %p vs %p)", original, got)
	}
}

// TestNewLoopWithDefaults_RebuildsWhenDefaultsProvided covers the chat-session
// path. When the caller passes a non-empty defaultInventory or defaultLimit
// (the `pilot chat --inventory ...` path), the registry must be rebuilt so
// run_ansible picks up the new defaults. This is the complement of the
// "reuse" test above and protects against an over-aggressive optimization.
func TestNewLoopWithDefaults_RebuildsWhenDefaultsProvided(t *testing.T) {
	original := tools.NewRegistry()
	app := buildTestApp(original)

	// Pass a non-empty defaultInventory to force a rebuild.
	loop := app.NewLoopWithDefaults("test-run-2", nil, "hosts.ini", "")
	if loop == nil {
		t.Fatal("NewLoopWithDefaults returned nil")
	}
	got := loop.Tools()
	if got == original {
		t.Errorf("NewLoopWithDefaults reused the registry when a non-empty defaultInventory was provided; expected a fresh build")
	}
	if got == nil {
		t.Error("NewLoopWithDefaults produced a nil registry for the chat-defaults path")
	}
}

// TestNewLoopWithDefaults_FastOnWarmCache is the timing-based complement of
// the pointer-equality test above. We measure how long NewLoopWithDefaults
// takes when the App already has a registry. The previous buggy version took
// 30+ seconds (bleve open). After the fix it must complete in well under
// a second — this catches any future regression that re-introduces a slow
// path into the cached call.
//
// We give a generous 2-second budget to avoid flakiness on slow CI while
// still catching the 30-second regression.
func TestNewLoopWithDefaults_FastOnWarmCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test under -short")
	}
	original := tools.NewRegistry()
	app := buildTestApp(original)

	start := time.Now()
	loop := app.NewLoopWithDefaults("test-run-3", nil, "", "")
	elapsed := time.Since(start)
	if loop == nil {
		t.Fatal("NewLoopWithDefaults returned nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("NewLoopWithDefaults took %s on a warm cache; expected < 2s (the 30s bleve-open regression is back)", elapsed)
	}
	t.Logf("NewLoopWithDefaults completed in %s", elapsed)
}
