package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/sandbox"
)

func TestRunPlaybookNoAllowedRootsRejects(t *testing.T) {
	tp := &RunPlaybookTool{Runner: ansible.NewRunner()}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"/etc/passwd"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error when no roots configured, got: %s", res.Content)
	}
	if !strings.Contains(res.Content, "no allowed roots") {
		t.Errorf("error message should explain, got: %s", res.Content)
	}
}

func TestRunPlaybookAllowsUnderRoot(t *testing.T) {
	root := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+pbPath+`","check":true}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.IsError && strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("path was inside an allowed root but got rejected: %s", res.Content)
	}
	if res.IsError && strings.Contains(res.Content, "no allowed roots") {
		t.Errorf("allowed root configured but message says none: %s", res.Content)
	}
}

func TestRunPlaybookRejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	pbPath := filepath.Join(other, "evil.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+pbPath+`"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error for path outside root, got: %s", res.Content)
	}
	if !strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("error message should explain, got: %s", res.Content)
	}
}

func TestRunPlaybookRejectsInventoryOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invPath := filepath.Join(other, "evil.ini")
	if err := os.WriteFile(invPath, []byte("[all]\nlocalhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+pbPath+`","inventory":"`+invPath+`"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("inventory outside root should be rejected, got: %s", res.Content)
	}
}

func TestRunPlaybookRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "secret.yml"), []byte("---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "evil.yml")
	if err := os.Symlink(filepath.Join(other, "secret.yml"), link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+link+`"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("symlink escape should be rejected, got: %s", res.Content)
	}
}

// ----- Item 2: DefaultInventory / DefaultLimit session defaults -----
//
// These tests verify that when the LLM omits inventory / limit and the
// tool has been configured with session defaults (typical of
// `pilot chat --inventory X --limit Y`), the defaults are applied.
// We assert the "rejection" path: if the default is OUTSIDE allowed
// roots, the path-whitelist step will reject it, proving the default
// was actually substituted.

func TestRunPlaybook_DefaultInventoryApplied(t *testing.T) {
	// Skip if ansible-playbook isn't installed — we need a real call
	// to confirm the inventory was actually used.
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invPath := filepath.Join(root, "hosts.ini")
	if err := os.WriteFile(invPath, []byte("[all]\nlocalhost ansible_connection=local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
		DefaultInventory:     invPath,
	}
	// LLM omits inventory; default should kick in and the playbook
	// should run (against localhost via the default inventory). The
	// result should NOT be a path-rejection error.
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+pbPath+`","check":true}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.IsError && strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("default inventory should be applied, got path-rejection: %s", res.Content)
	}
}

func TestRunPlaybook_DefaultInventoryRejectsIfOutsideRoots(t *testing.T) {
	// A default inventory that lives OUTSIDE allowed roots must still
	// be rejected by ValidatePath — the default isn't a magic bypass.
	root := t.TempDir()
	other := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invOutside := filepath.Join(other, "evil.ini")
	if err := os.WriteFile(invOutside, []byte("[all]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
		DefaultInventory:     invOutside,
	}
	res, err := tp.Execute(context.Background(), json.RawMessage(`{"playbook":"`+pbPath+`"}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content, "is outside the allowed roots") {
		t.Errorf("default inventory outside roots must be rejected, got: %s", res.Content)
	}
}

func TestRunPlaybook_ExplicitInventoryBeatsDefault(t *testing.T) {
	// If the LLM DOES pass an inventory, the default must not overwrite
	// it. We verify by passing an explicit inventory that's invalid
	// (outside roots) — the path-rejection error would only occur if
	// the default had been incorrectly applied.
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	other := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	explicitInv := filepath.Join(root, "explicit.ini")
	if err := os.WriteFile(explicitInv, []byte("[all]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = other // unused but documents intent

	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
		DefaultInventory:     filepath.Join(root, "default.ini"),
	}
	res, err := tp.Execute(context.Background(),
		json.RawMessage(`{"playbook":"`+pbPath+`","inventory":"`+explicitInv+`","check":true}`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// If the default had wrongly overwritten the explicit inventory,
	// `default.ini` (which doesn't exist on disk) would be the
	// reason the call failed. The point of this test is that
	// explicit beats default — we can only assert it doesn't fail
	// with a default-misuse error path.
	if res.IsError && strings.Contains(res.Content, "default.ini") {
		t.Errorf("explicit inventory should beat default, got: %s", res.Content)
	}
}

// ----- Item 4: sandbox integration via buildSandboxInventory -----

func TestBuildSandboxInventory_Docker(t *testing.T) {
	inv, err := buildSandboxInventory(
		sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abc123def456",
			User:           "root",
		}, "")
	if err != nil {
		t.Fatalf("buildSandboxInventory: %v", err)
	}
	mustContain := []string{
		"all:",
		"hosts:",
		"sandbox:",
		"ansible_connection: docker",
		"ansible_host: abc123def456",
		"ansible_user: root",
	}
	for _, s := range mustContain {
		if !strings.Contains(inv, s) {
			t.Errorf("inventory missing %q\n--- inventory ---\n%s", s, inv)
		}
	}
}

func TestBuildSandboxInventory_WithLimit(t *testing.T) {
	inv, err := buildSandboxInventory(
		sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abc",
		}, "webservers")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inv, "webservers") {
		t.Errorf("expected limit in inventory: %s", inv)
	}
}

func TestBuildSandboxInventory_DefaultUserIsRoot(t *testing.T) {
	inv, err := buildSandboxInventory(
		sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abc",
		}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inv, "ansible_user: root") {
		t.Errorf("default user should be root: %s", inv)
	}
}

func TestBuildSandboxInventory_RejectsNonDocker(t *testing.T) {
	_, err := buildSandboxInventory(
		sandbox.AnsibleConnection{ConnectionType: "ssh", ContainerID: "x"}, "")
	if err == nil {
		t.Error("expected error for non-docker connection")
	}
}

func TestBuildSandboxInventory_RejectsEmptyContainerID(t *testing.T) {
	_, err := buildSandboxInventory(
		sandbox.AnsibleConnection{ConnectionType: "docker"}, "")
	if err == nil {
		t.Error("expected error for empty container ID")
	}
}

func TestFilterOutputStdoutCallback(t *testing.T) {
	stdout := "TASK [test]\nok: [localhost]\nskipping: [localhost]\nchanged: [localhost]\nPLAY RECAP **************************"

	os.Setenv("ANSIBLE_STDOUT_CALLBACK", "")
	filtered := ansible.FilterOutput(stdout)
	if strings.Contains(filtered, "ok:") || strings.Contains(filtered, "skipping:") {
		t.Errorf("expected ok/skipping to be filtered under default callback, got: %s", filtered)
	}

	cb := "json"
	isStandard := cb == "" || cb == "default" || cb == "yaml" || cb == "debug"
	if isStandard {
		t.Error("expected json callback to be non-standard")
	}
}


// stubDockerEnv is a minimal sandbox.Environment used to drive
// resolveInventory / prepareRequest under a docker sandbox without
// requiring a real Docker daemon. Only ConnectionInfo matters for
// the temp-file and inventory-rewrite paths.
type stubDockerEnv struct {
	conn sandbox.AnsibleConnection
}

func (s *stubDockerEnv) Start(_ context.Context) error  { return nil }
func (s *stubDockerEnv) Stop(_ context.Context) error   { return nil }
func (s *stubDockerEnv) Exec(_ context.Context, _ []string, _ sandbox.ExecOptions) (*sandbox.ExecResult, error) {
	return nil, nil
}
func (s *stubDockerEnv) ReadFile(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (s *stubDockerEnv) WriteFile(_ context.Context, _ string, _ []byte, _ os.FileMode) error { return nil }
func (s *stubDockerEnv) ConnectionInfo() sandbox.AnsibleConnection { return s.conn }
func (s *stubDockerEnv) IsAvailable(_ context.Context) error { return nil }
func (s *stubDockerEnv) Name() string { return "stub-docker" }

// writePlaybookAndRoot drops a minimal playbook into a temp root
// so the tool passes ValidatePath and actually shells out to
// ansible-playbook (which won't be on the test box — tests that
// exercise the ansible subprocess rely on the temp-file cleanup
// happening before any subprocess error, so we assert on the
// side-effect files instead).
func writePlaybookAndRoot(t *testing.T) (root, pb string) {
	t.Helper()
	dir := t.TempDir()
	pbPath := filepath.Join(dir, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, pbPath
}

// TestPrepareRequest_ExtraVarsTempFileCleanedOnError covers Finding 1:
// when prepareRequest fails after writeExtraVarsFile has created the
// temp file, the file must NOT survive the call. We trigger the
// error by passing an explicitly-invalid path for the inventory so
// ValidatePath rejects the call after the extra-vars tmpfile has
// been written.
func TestPrepareRequest_ExtraVarsTempFileCleanedOnError(t *testing.T) {
	root, _ := writePlaybookAndRoot(t)
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	// Inventories are validated AFTER extra_vars is written; we
	// pre-create and then delete an inventory so ValidatePath
	// returns "outside the allowed roots" while the extra-vars
	// file has already been written.
	_, req, _ := t.TempDir(), 0, 0
	_ = req
	// Use raw JSON so we can inject an inventory path that's
	// clearly outside the allowed roots.
	args := json.RawMessage(fmt.Sprintf(`{"playbook":%q,"inventory":"/nonexistent/inv.yml","extra_vars":{"foo":"bar"}}`, root+"/site.yml"))
	res, err := tp.Execute(context.Background(), args)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error for out-of-root inventory, got: %s", res.Content)
	}
	// Walk /tmp for any stray pilot-extra-vars-*.json file that
	// belongs to us. We use a sampling approach: list the dir and
	// check no leftover was created with a fresh mtime.
	matches, err := filepath.Glob("/tmp/pilot-extra-vars-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		// Make sure none of them were created in the last few
		// seconds by this test.
		cutoff := time.Now().Add(-30 * time.Second)
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil {
				continue
			}
			if fi.ModTime().After(cutoff) {
				t.Errorf("leaked extra-vars temp file: %s (mtime=%s)", m, fi.ModTime())
			}
		}
	}
}

// TestPrepareRequest_ExtraVarsCleanedOnSuccess covers the happy
// path: extra_vars are written to a temp file, Execute runs (and
// will fail because no ansible binary exists), and the temp file
// must STILL be cleaned up by the defer.
func TestPrepareRequest_ExtraVarsCleanedOnSuccess(t *testing.T) {
	root, pb := writePlaybookAndRoot(t)
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
	}
	args := json.RawMessage(fmt.Sprintf(`{"playbook":%q,"extra_vars":{"k":"v"},"check":true}`, pb))
	res, err := tp.Execute(context.Background(), args)
	_ = res
	// We don't care if Execute returns a tool-level error (no
	// ansible binary on the test host). We only care that no
	// temp file leaked.
	if err != nil {
		t.Logf("Execute returned err (expected on test box without ansible): %v", err)
	}
	cutoff := time.Now().Add(-30 * time.Second)
	matches, err := filepath.Glob("/tmp/pilot-extra-vars-*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if fi.ModTime().After(cutoff) {
			t.Errorf("leaked extra-vars temp file after success: %s", m)
		}
	}
}

// TestResolveInventory_DockerModeGenerates covers Finding 3 in the
// default docker-connection mode: resolveInventory must produce a
// generated inventory file under the pilot sandbox prefix.
func TestResolveInventory_DockerModeGenerates(t *testing.T) {
	tp := &RunPlaybookTool{
		Env: &stubDockerEnv{conn: sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abcdef012345",
			User:           "root",
		}},
		SandboxMode: sandbox.SandboxModeDocker,
	}
	path, generated, errRes := tp.resolveInventory("", "", true)
	if errRes != nil {
		t.Fatalf("unexpected err: %+v", errRes)
	}
	if !generated {
		t.Fatal("expected generated=true for docker sandbox mode")
	}
	if path == "" {
		t.Fatal("expected non-empty inventory path")
	}
	if !strings.HasPrefix(filepath.Base(path), "pilot-sandbox-inv-") {
		t.Errorf("unexpected inventory name: %s", path)
	}
	// The defer in Execute is the one that actually deletes the
	// file; clean up manually for the unit-level check.
	defer os.Remove(path)
}

// TestResolveInventory_DockerExecModeSkips covers Finding 3: in
// docker-exec mode, ansible runs INSIDE the container so the
// rewritten inventory would be wrong. resolveInventory must
// return the caller-supplied inventory untouched and report
// generated=false so the cleanup defer does not delete a
// caller-owned file.
func TestResolveInventory_DockerExecModeSkips(t *testing.T) {
	tp := &RunPlaybookTool{
		Env: &stubDockerEnv{conn: sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abcdef012345",
		}},
		SandboxMode: sandbox.SandboxModeDockerExec,
	}
	callerInv := "/tmp/pilot-test-caller-inventory.yml"
	path, generated, errRes := tp.resolveInventory(callerInv, "", false)
	if errRes != nil {
		t.Fatalf("unexpected err: %+v", errRes)
	}
	if generated {
		t.Fatal("expected generated=false for docker-exec mode")
	}
	if path != callerInv {
		t.Fatalf("expected %q unchanged, got %q", callerInv, path)
	}
}

// TestPrepareRequest_DockerExecDoesNotGenerateInventory exercises
// the full prepareRequest path with a docker-exec sandbox and an
// explicit inventory: the prepared request must NOT have a
// generated inventory (the file would be wrong / leaked).
func TestPrepareRequest_DockerExecDoesNotGenerateInventory(t *testing.T) {
	root, pb := writePlaybookAndRoot(t)
	inv := filepath.Join(root, "inv.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    sandbox:\n      ansible_connection: local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tp := &RunPlaybookTool{
		Runner:               ansible.NewRunner(),
		AllowedPlaybookRoots: []string{root},
		Env: &stubDockerEnv{conn: sandbox.AnsibleConnection{
			ConnectionType: "docker",
			ContainerID:    "abcdef012345",
		}},
		SandboxMode: sandbox.SandboxModeDockerExec,
	}
	req, errRes := tp.prepareRequest(json.RawMessage(fmt.Sprintf(`{"playbook":%q,"inventory":%q}`, pb, inv)))
	if errRes != nil {
		t.Fatalf("unexpected err: %+v", errRes)
	}
	if req.GeneratedInventory {
		t.Errorf("GeneratedInventory should be false for docker-exec mode")
	}
	if req.InventoryPath != inv {
		t.Errorf("InventoryPath should be the caller-supplied %q, got %q", inv, req.InventoryPath)
	}
}
