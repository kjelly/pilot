package tools

import (
	"context"
	"os"
	"testing"

	"github.com/anomalyco/pilot/internal/sandbox"
)

// TestSelectExecutor_LocalEnvironment_UsesLocalExecutor is a regression
// test for the run_ansible hang that affected every user who did not
// pass --sandbox. The previous version of selectExecutor only checked
// `t.Env == nil` to decide between the local and docker code paths,
// but App.New always populates t.Env with a LocalEnvironment when no
// sandbox is requested — so the nil check was effectively dead code
// and every run_ansible call fell into the docker path, immediately
// failing with "sandbox requires a docker ConnectionInfo, got \"local\"".
//
// The fix is one extra condition: a LocalEnvironment (Name() == "local")
// must be treated the same as a nil env — i.e. use the local executor.
// This test pins that fix.
func TestSelectExecutor_LocalEnvironment_UsesLocalExecutor(t *testing.T) {
	tool := &RunPlaybookTool{
		Env: sandbox.NewLocalEnvironment(),
	}
	ex, err := tool.selectExecutor(sandbox.SandboxModeUnset)
	if err != nil {
		t.Fatalf("selectExecutor returned error for LocalEnvironment: %v", err)
	}
	if _, ok := ex.(localExecutor); !ok {
		t.Errorf("LocalEnvironment should select localExecutor, got %T", ex)
	}
}

// TestSelectExecutor_NilEnv_UsesLocalExecutor is the original behaviour:
// a nil Env (the pre-App.New fallback path, used in some tests) must
// also pick localExecutor. This test guards the nil branch of the
// selectExecutor condition.
func TestSelectExecutor_NilEnv_UsesLocalExecutor(t *testing.T) {
	tool := &RunPlaybookTool{Env: nil}
	ex, err := tool.selectExecutor(sandbox.SandboxModeUnset)
	if err != nil {
		t.Fatalf("selectExecutor returned error for nil env: %v", err)
	}
	if _, ok := ex.(localExecutor); !ok {
		t.Errorf("nil Env should select localExecutor, got %T", ex)
	}
}

// fakeNonLocalEnv is a minimal Environment whose only interesting
// property is that its Name() != "local". The dockerConnOrError path
// will fail because ConnectionType is not "docker", but the test only
// cares about the executor TYPE returned by selectExecutor (we expect
// it to ATTEMPT the docker path, not silently fall back to local).
type fakeNonLocalEnv struct{}

func (fakeNonLocalEnv) Name() string { return "docker-fake" }

func (fakeNonLocalEnv) Start(_ context.Context) error   { return nil }
func (fakeNonLocalEnv) Stop(_ context.Context) error    { return nil }
func (fakeNonLocalEnv) IsAvailable(_ context.Context) error { return nil }

func (fakeNonLocalEnv) Exec(_ context.Context, _ []string, _ sandbox.ExecOptions) (*sandbox.ExecResult, error) {
	return &sandbox.ExecResult{ExitCode: 0}, nil
}
func (fakeNonLocalEnv) ReadFile(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (fakeNonLocalEnv) WriteFile(_ context.Context, _ string, _ []byte, _ os.FileMode) error {
	return nil
}
func (fakeNonLocalEnv) ConnectionInfo() sandbox.AnsibleConnection {
	// Return ConnectionType = "docker" so the dockerConnOrError check
	// passes, but with an empty ContainerID. The subsequent
	// SandboxModeDockerExec branch will reject empty container ID;
	// for SandboxModeUnset we'll fall through to the dockerConnExecutor.
	// Either way, this proves the docker path was selected (not local).
	return sandbox.AnsibleConnection{
		Host:           "fake-container",
		ConnectionType: "docker",
		ContainerID:    "",
	}
}

// TestSelectExecutor_NonLocalEnv_DoesNotReturnLocal pins the negative
// side of the fix: when Env is something other than nil/Local (i.e.
// a real Docker environment), selectExecutor must NOT return a
// localExecutor. A non-local env that returns localExecutor would be
// the regression we are guarding against.
func TestSelectExecutor_NonLocalEnv_DoesNotReturnLocal(t *testing.T) {
	tool := &RunPlaybookTool{Env: fakeNonLocalEnv{}}
	ex, err := tool.selectExecutor(sandbox.SandboxModeUnset)
	if err != nil {
		// The docker path will likely fail at some point (fake
		// container ID, no real docker, etc.). For this test
		// we accept either an error OR a non-local executor;
		// what we MUST NOT see is a silent fall-through to
		// localExecutor.
		t.Logf("selectExecutor returned err=%v ex=%T (acceptable as long as it is not localExecutor)", err, ex)
		return
	}
	if _, ok := ex.(localExecutor); ok {
		t.Errorf("non-local env must NOT select localExecutor; got %T", ex)
	}
}
