package cmd

import (
	"bytes"
	"context"
	"encoding/json"
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
	metadata := deploymentMetadata(root, "playbooks/apply/docker-apply.yml", []string{"docker"}, nil, vaultInput{AskBecomePass: true}, "", nil)
	if metadata["become_password_prompted"] != true {
		t.Fatalf("metadata = %+v, want become_password_prompted=true", metadata)
	}
	metadataOff := deploymentMetadata(root, "playbooks/apply/docker-apply.yml", []string{"docker"}, nil, vaultInput{}, "", nil)
	if _, ok := metadataOff["become_password_prompted"]; ok {
		t.Fatalf("metadata = %+v, want no become_password_prompted key when not requested", metadataOff)
	}
}

// The mixed run's extra variables (spec §8.3): the engine variable as `key=value`, and the observation file as
// a JSON object, whose path holds `=` and blanks. The metadata of the run records the names of the variables
// and never a value. The JSON object used to be cut at its first `=`: a piece of the path became a key (or,
// without an `=` in it, the argument was lost).
func TestDeploymentMetadataRecordsTheKeysOfJSONObjectExtraVars(t *testing.T) {
	root := t.TempDir()
	const path = "/tmp/pilot dir=with equals/pilot-auth-cache 1/result.json"
	object, err := json.Marshal(map[string]string{"pilot_identity_auth_cache_output": path})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		extra []string
		want  []string
	}{
		{"the mixed run's variables", []string{"stage=sandbox", "pilot_identity_users_groups_engine=go", string(object)}, []string{"pilot_identity_auth_cache_output", "pilot_identity_users_groups_engine", "stage"}},
		{"an object without an equals sign in it", []string{`{"a_key": "no equals here"}`}, []string{"a_key"}},
		{"two keys, nested values are not keys", []string{`{"outer": {"inner": 1}, "list": [1, 2]}`}, []string{"list", "outer"}},
		{"surrounding blanks", []string{"  " + string(object) + "  "}, []string{"pilot_identity_auth_cache_output"}},
		{"a { argument that is not an object names nothing", []string{`{"broken": `, `{not json=1}`}, []string{}},
		{"an array is not an object", []string{`[1, 2]`}, []string{}},
		{"key=value and @file as before", []string{"target_group=freeipa-server", "@vars.yml", "=novalue", "empty="}, []string{"empty", "target_group"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := deploymentMetadata(root, "playbooks/apply/freeipa-identity-apply.yml", []string{"freeipa-identity"}, tc.extra, vaultInput{}, "", nil)
			got, _ := metadata["extra_var_keys"].([]string)
			if len(got) != len(tc.want) {
				t.Fatalf("extra_var_keys = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("extra_var_keys = %q, want %q", got, tc.want)
				}
			}
			encoded, _ := json.Marshal(metadata)
			for _, leak := range []string{"pilot dir", "with equals", "pilot-auth-cache", "result.json", "no equals here"} {
				if strings.Contains(string(encoded), leak) {
					t.Fatalf("the metadata holds a piece of a value (%q): %s", leak, encoded)
				}
			}
		})
	}
}
