package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #113: ssh_keys is authoritative, but an empty list built a bare
// `ipa user-mod <user>`, which FreeIPA answers with "no modifications to be
// performed", so removing a user's last key never revoked it. The task now
// sends `--sshpubkey=` for an empty list. These tests run the playbook's own
// task on localhost with a fake `ipa` first on PATH that answers with output
// captured from FreeIPA 4.13.4 (testdata/freeipa-ssh-keys) and records each
// call; any other call fails.

const (
	sshKeysPlaybook = "../../playbooks/apply/freeipa-identity-apply.yml"
	sshKeysTaskName = "Set SSH public keys for users (declarative replace)"
	sshKeysFixtures = "testdata/freeipa-ssh-keys"
)

func sshKeysTask(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(sshKeysPlaybook)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	for _, r := range plays[0]["tasks"].([]any) {
		if task, ok := r.(map[string]any); ok && task["name"] == sshKeysTaskName {
			return task
		}
	}
	t.Fatalf("task %q not found", sshKeysTaskName)
	return nil
}

// sshKeysFakeIPA puts an `ipa` that answers each argument list (joined by
// spaces) with a fixture first on PATH and returns the calls made so far.
func sshKeysFakeIPA(t *testing.T, answers map[string]string) func() []string {
	t.Helper()
	dir := t.TempDir()
	var tsv strings.Builder
	for args, fixture := range answers {
		abs, err := filepath.Abs(filepath.Join(sshKeysFixtures, fixture))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&tsv, "%s\t%s\n", args, abs)
	}
	if err := os.WriteFile(filepath.Join(dir, "answers.tsv"), []byte(tsv.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
args="$*"
printf '%s\n' "$args" >> "` + dir + `/calls.log"
f=$(awk -F'\t' -v a="$args" '$1==a{print $2; exit}' "` + dir + `/answers.tsv")
if [ -z "$f" ]; then echo "fake ipa: unexpected call: $args" >&2; exit 99; fi
cat "$f.stdout"; cat "$f.stderr" >&2; exit "$(cat "$f.rc")"
`
	if err := os.WriteFile(filepath.Join(dir, "ipa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		raw, err := os.ReadFile(filepath.Join(dir, "calls.log"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
}

func TestRegression_IdentitySSHKeysEmptyListRevokesKeys(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTheTest pwb-u001@bench"
	users := []any{
		map[string]any{"name": "keeps-a-key", "ssh_keys": []any{key}},
		map[string]any{"name": "loses-last-key", "ssh_keys": []any{}},
		map[string]any{"name": "never-had-a-key", "ssh_keys": []any{}},
		map[string]any{"name": "keys-unmanaged"},
	}
	calls := sshKeysFakeIPA(t, map[string]string{
		"user-mod keeps-a-key --sshpubkey=" + key: "user-mod-modified",
		"user-mod loses-last-key --sshpubkey=":    "user-mod-modified",
		"user-mod never-had-a-key --sshpubkey=":   "user-mod-no-modifications",
	})
	res := runGatewayTasks(t, t.TempDir(), []any{sshKeysTask(t)}, map[string]any{"ipa_active_users": users}, nil)
	if res.rc != 0 || len(res.failures) != 0 {
		t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
	}
	want := []string{
		"user-mod keeps-a-key --sshpubkey=" + key,
		"user-mod loses-last-key --sshpubkey=",
		"user-mod never-had-a-key --sshpubkey=",
	}
	if got := calls(); !slices.Equal(got, want) {
		t.Fatalf("ipa calls = %q, want %q", got, want)
	}
	if !res.changed[sshKeysTaskName] {
		t.Fatalf("clearing a user's last key must report changed")
	}
}

// A user with no key and an empty list stays a no-op: FreeIPA answers the
// clear with "no modifications to be performed".
func TestRegression_IdentitySSHKeysEmptyListWithoutKeysIsANoOp(t *testing.T) {
	sshKeysFakeIPA(t, map[string]string{"user-mod never-had-a-key --sshpubkey=": "user-mod-no-modifications"})
	users := []any{map[string]any{"name": "never-had-a-key", "ssh_keys": []any{}}}
	res := runGatewayTasks(t, t.TempDir(), []any{sshKeysTask(t)}, map[string]any{"ipa_active_users": users}, nil)
	if res.rc != 0 || res.changed[sshKeysTaskName] {
		t.Fatalf("rc=%d changed=%v failures=%v", res.rc, res.changed[sshKeysTaskName], res.failures)
	}
}
