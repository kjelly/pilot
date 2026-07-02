package tools

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/sandbox"
)

// TestDockerExecRunner_RealContainer is an integration test that
// brings up a real `geerlingguy/docker-ubuntu2204-ansible` container
// and runs ansible-playbook through dockerExecRunner. It is skipped
// when the docker CLI or that image is not present so it doesn't
// fail in environments without Docker (e.g. CI without daemon).
func TestDockerExecRunner_RealContainer(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not available; skipping integration test")
	}
	image := "geerlingguy/docker-ubuntu2204-ansible:latest"
	if out, err := exec.Command("docker", "images", "-q", image).Output(); err != nil {
		t.Skipf("docker images lookup failed: %v", err)
	} else if strings.TrimSpace(string(out)) == "" {
		t.Skipf("image %q not pulled locally; skipping", image)
	}

	// 1) Start container in background.
	containerName := "pilot-dexec-test-" + newNanoIDLite()
	startCmd := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName, image, "sleep", "120")
	out, err := startCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	// 2) Build a minimal playbook in a tempdir and stage it.
	dir := t.TempDir()
	pb := filepath.Join(dir, "probe.yml")
	inventory := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(pb, []byte(`---
- name: docker-exec runner probe
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.debug:
        msg: "ran-in-container"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventory, []byte(`all:
  hosts:
    localhost:
      ansible_connection: local
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3) Build ansible args (as BuildArgs would). Playbook is
	//    the first positional arg (index 0), per BuildArgs contract.
	allArgs := []string{
		pb,
		"-i", inventory,
		"--check", "--diff",
	}

	// 4) Invoke the runner.
	der := newDockerExecRunner(containerID)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := der.runInContainer(ctx, pb, inventory, "", allArgs, 60*time.Second)
	if err != nil {
		t.Fatalf("runInContainer error: %v\nstdout: %s\nstderr: %s", err, res.Stdout, res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code %d, want 0\nstdout: %s\nstderr: %s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "ran-in-container") {
		t.Errorf("expected output to contain 'ran-in-container', got: %s", res.Stdout)
	}
	if !strings.Contains(res.Cmd, "docker exec") {
		t.Errorf("expected Cmd to contain 'docker exec', got: %s", res.Cmd)
	}

	// 5) Verify cleanup: the staged /tmp/pilot-pb-*.yml should
	//    be gone (best-effort, but we removed it explicitly).
	listCmd := exec.Command("docker", "exec", containerID, "ls", "/tmp")
	listOut, lerr := listCmd.CombinedOutput()
	if lerr != nil {
		t.Logf("warning: could not list /tmp in container: %v\n%s", lerr, listOut)
	} else {
		if strings.Contains(string(listOut), "pilot-pb-") ||
			strings.Contains(string(listOut), "pilot-inv-") {
			t.Errorf("staged files not cleaned up: %s", listOut)
		}
	}
}

// newNanoIDLite returns a short unique suffix. We don't import the
// sandbox package's NewNanoID here to keep this test file
// independent of that package's surface.
func newNanoIDLite() string {
	return time.Now().Format("150405.000000000")
}

// TestDockerExecRunner_NonDockerEnvFails ensures the runner errors
// out gracefully when the ConnectionInfo isn't docker, so the
// tool-level dispatch in run_playbook.go can't accidentally
// route a non-docker sandbox through docker exec.
func TestDockerExecRunner_NonDockerEnvFails(t *testing.T) {
	// We exercise the dispatch path indirectly: the runInContainer
	// helper itself does not check ConnectionType — that's the
	// tool's job. So a focused test would be on RunPlaybookTool.
	// Here we just confirm the helper runs without panicking when
	// the docker binary is missing.
	if _, err := exec.LookPath("docker"); err == nil {
		t.Skip("docker present; this test only runs on hosts without docker")
	}
	der := newDockerExecRunner("deadbeef")
	_, err := der.runInContainer(context.Background(), "/nonexistent.yml", "", "",
		[]string{"/nonexistent.yml"}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error when docker CLI is missing")
	}
}

// TestRunPlaybookTool_DockerExecMode_RejectsNonDockerEnv asserts
// that the tool-level dispatch in run_playbook.go refuses to run
// in docker-exec mode when the active Environment isn't a docker
// connection (e.g. LocalEnvironment, SSH).
func TestRunPlaybookTool_DockerExecMode_RejectsNonDockerEnv(t *testing.T) {
	dir := t.TempDir()
	pb := filepath.Join(dir, "probe.yml")
	if err := os.WriteFile(pb, []byte(`---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &fakeSandboxEnv{connType: "local", containerID: "deadbeef"}
	tool := &RunPlaybookTool{
		Runner:               nil, // never reached
		AllowedPlaybookRoots: []string{dir},
		Env:                  env,
		SandboxMode:          sandbox.SandboxModeDockerExec,
	}
	args, _ := json.Marshal(map[string]any{"playbook": pb, "check": true})
	res, err := tool.Execute(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError=true rejection, got: %+v", res)
	}
	if !strings.Contains(res.Content, "sandbox requires a docker ConnectionInfo") {
		t.Errorf("expected rejection reason to mention sandbox ConnectionInfo, got: %s", res.Content)
	}
}

// fakeSandboxEnv is a minimal sandbox.Environment for tests. It
// reports a fixed ConnectionInfo and stubs out the rest. It does
// NOT exec anything — tests that touch docker go through
// dockerExecRunner directly (not this stub).
type fakeSandboxEnv struct {
	connType    string
	containerID string
}

func (f *fakeSandboxEnv) Start(ctx context.Context) error { return nil }
func (f *fakeSandboxEnv) Stop(ctx context.Context) error  { return nil }
func (f *fakeSandboxEnv) Exec(ctx context.Context, argv []string, opts sandbox.ExecOptions) (*sandbox.ExecResult, error) {
	return &sandbox.ExecResult{ExitCode: 0, Stdout: "", Stderr: ""}, nil
}
func (f *fakeSandboxEnv) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}
func (f *fakeSandboxEnv) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func (f *fakeSandboxEnv) ConnectionInfo() sandbox.AnsibleConnection {
	return sandbox.AnsibleConnection{ConnectionType: f.connType, ContainerID: f.containerID, Host: f.containerID}
}
func (f *fakeSandboxEnv) IsAvailable(ctx context.Context) error { return nil }
func (f *fakeSandboxEnv) Name() string {
	return f.connType + ":" + f.containerID
}
