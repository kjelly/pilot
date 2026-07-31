package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
)

func TestVaultInputBecomeArgs(t *testing.T) {
	if got := (vaultInput{}).becomeArgs(); got != nil {
		t.Fatalf("becomeArgs() = %#v, want nil when AskBecomePass is false", got)
	}
	got := (vaultInput{AskBecomePass: true}).becomeArgs()
	if want := []string{"--ask-become-pass"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("becomeArgs() = %#v, want %#v", got, want)
	}
}

// writeArgRecorderFixture writes an executable that appends its argv to
// recordPath (one line per invocation, space-joined) before exiting with
// exitCode — used to assert exactly what ansible-playbook / ansible-inventory
// argv pilot deploy actually constructs.
func writeArgRecorderFixture(t *testing.T, name, recordPath string, exitCode int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + strconv.Quote(recordPath) + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write %s fixture: %v", name, err)
	}
	return path
}

func TestExecuteDeployment_AskBecomePassAddsFlagAndWiresStdin(t *testing.T) {
	recordPath := filepath.Join(t.TempDir(), "record.log")
	runner := ansible.NewRunner()
	runner.Binary = writeArgRecorderFixture(t, "ansible-playbook", recordPath, 0)
	runner.Timeout = 5 * time.Second

	restore := stubDeploymentConfirm(t, true, true, true, true)
	defer restore()

	if err := executeDeployment(
		context.Background(), runner, &bytes.Buffer{},
		"playbooks/apply/docker-apply.yml", "inventory.yml", "", "", nil,
		vaultInput{AskBecomePass: true},
	); err != nil {
		t.Fatalf("executeDeployment() error = %v", err)
	}
	if runner.Stdin != os.Stdin {
		t.Fatalf("runner.Stdin = %v, want os.Stdin wired for --ask-become-pass", runner.Stdin)
	}
	recorded, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(recorded)), "\n")
	if len(lines) == 0 {
		t.Fatal("no ansible-playbook invocations recorded")
	}
	for _, line := range lines {
		if !strings.Contains(line, "--ask-become-pass") {
			t.Fatalf("ansible-playbook invocation missing --ask-become-pass: %q", line)
		}
	}
}

func TestExecuteDeployment_DefaultOmitsBecomeFlagAndStdin(t *testing.T) {
	recordPath := filepath.Join(t.TempDir(), "record.log")
	runner := ansible.NewRunner()
	runner.Binary = writeArgRecorderFixture(t, "ansible-playbook", recordPath, 0)
	runner.Timeout = 5 * time.Second

	restore := stubDeploymentConfirm(t, true, true, true, true)
	defer restore()

	if err := executeDeployment(
		context.Background(), runner, &bytes.Buffer{},
		"playbooks/apply/docker-apply.yml", "inventory.yml", "", "", nil,
		vaultInput{},
	); err != nil {
		t.Fatalf("executeDeployment() error = %v", err)
	}
	if runner.Stdin != nil {
		t.Fatalf("runner.Stdin = %v, want nil when neither vault nor become prompting is requested", runner.Stdin)
	}
	recorded, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if strings.Contains(string(recorded), "--ask-become-pass") {
		t.Fatalf("ansible-playbook invocation unexpectedly included --ask-become-pass:\n%s", recorded)
	}
}

// TestResolveInventoryVariables_NeverPassesBecomeFlagToAnsibleInventory locks
// in that becomeArgs() stays separate from args(): `ansible-inventory` (used
// by resolveInventoryVariables to resolve per-host group vars) does not
// support --ask-become-pass and errors out on it.
func TestResolveInventoryVariables_NeverPassesBecomeFlagToAnsibleInventory(t *testing.T) {
	binDir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "record.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + strconv.Quote(recordPath) + "\nprintf '%s\\n' '{\"_meta\": {\"hostvars\": {}}}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	inv := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveInventoryVariables(context.Background(), inv, nil, vaultInput{AskBecomePass: true}); err != nil {
		t.Fatalf("resolveInventoryVariables() error = %v", err)
	}
	recorded, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if strings.Contains(string(recorded), "--ask-become-pass") {
		t.Fatalf("ansible-inventory does not support --ask-become-pass but it was passed:\n%s", recorded)
	}
}

func TestDeploymentMetadata_RecordsBecomePasswordPrompted(t *testing.T) {
	root := repoRootForTest(t)
	metadata := deploymentMetadata(root, "playbooks/apply/docker-apply.yml", []string{"docker"}, nil, vaultInput{AskBecomePass: true}, "")
	if metadata["become_password_prompted"] != true {
		t.Fatalf("metadata = %+v, want become_password_prompted=true", metadata)
	}
	metadataOff := deploymentMetadata(root, "playbooks/apply/docker-apply.yml", []string{"docker"}, nil, vaultInput{}, "")
	if _, ok := metadataOff["become_password_prompted"]; ok {
		t.Fatalf("metadata = %+v, want no become_password_prompted key when not requested", metadataOff)
	}
}
