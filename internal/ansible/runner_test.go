package ansible

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyntaxCheckFailsForBadPlaybook(t *testing.T) {
	if _, err := lookPathOrSkip(t, "ansible-playbook"); err != nil {
		return
	}
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad.yml")
	if err := os.WriteFile(bad, []byte("- name: bad\n  shell: :\n  this is not valid yaml: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRunner()
	r.Env = []string{"ANSIBLE_LOCAL_TEMP=" + filepath.Join(tmp, "ansible-tmp")}
	res, err := r.SyntaxCheck(context.Background(), bad, "", "")
	if err != nil {
		t.Fatalf("SyntaxCheck returned error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code for bad syntax, got 0; stdout=%q", res.Stdout)
	}
	if res.Stderr == "" && res.Stdout == "" {
		t.Fatal("expected some error output")
	}
}

func TestSyntaxCheckPassesForGoodPlaybook(t *testing.T) {
	if _, err := lookPathOrSkip(t, "ansible-playbook"); err != nil {
		return
	}
	tmp := t.TempDir()
	good := filepath.Join(tmp, "good.yml")
	body := `- name: ok
  hosts: localhost
  gather_facts: false
  tasks:
    - name: ping
      ansible.builtin.ping:
`
	if err := os.WriteFile(good, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRunner()
	r.Env = []string{"ANSIBLE_LOCAL_TEMP=" + filepath.Join(tmp, "ansible-tmp")}
	res, err := r.SyntaxCheck(context.Background(), good, "", "")
	if err != nil {
		t.Fatalf("SyntaxCheck returned error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected 0 exit code, got %d\nstdout=%s\nstderr=%s", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestSyntaxCheckMissingFile(t *testing.T) {
	if _, err := lookPathOrSkip(t, "ansible-playbook"); err != nil {
		return
	}
	r := NewRunner()
	res, err := r.SyntaxCheck(context.Background(), "/nonexistent/playbook.yml", "", "")
	if err != nil {
		t.Fatalf("SyntaxCheck returned error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("expected non-zero exit code for missing file")
	}
	// ansible prints a useful error to stderr
	if !strings.Contains(strings.ToLower(res.Stderr+res.Stdout), "no such file") &&
		!strings.Contains(strings.ToLower(res.Stderr+res.Stdout), "could not find") {
		t.Logf("note: ansible did not print expected 'no such file' error; got: %s / %s", res.Stdout, res.Stderr)
	}
}

func TestRunnerAppliesEnvironmentOverrides(t *testing.T) {
	r := NewRunner()
	r.Binary = "sh"
	r.Env = []string{"PILOT_ANSIBLE_TEST_VALUE=isolated"}
	res, err := r.Run(context.Background(), "-c", "printf %s \"$PILOT_ANSIBLE_TEST_VALUE\"")
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Stdout; got != "isolated" {
		t.Fatalf("stdout = %q, want environment override", got)
	}
}

func lookPathOrSkip(t *testing.T, name string) (string, error) {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("ansible not installed; skipping test that needs %q", name)
	}
	return path, nil
}

// ----- Item 3: BuildArgs tests -----
//
// These cover the shared argv builder used by run_playbook.go,
// previewAnsibleRun, and the CLI syntax check.

func TestBuildArgs_BarePlaybook(t *testing.T) {
	got := BuildArgs(PlaybookArgs{Playbook: "site.yml"})
	want := []string{"site.yml"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs bare: got %v, want %v", got, want)
	}
}

func TestBuildArgs_HostTargeting(t *testing.T) {
	got := BuildArgs(PlaybookArgs{
		Playbook:  "site.yml",
		Inventory: "hosts.ini",
		Limit:     "webservers",
	})
	want := []string{"site.yml", "-i", "hosts.ini", "--limit", "webservers"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs host targeting: got %v, want %v", got, want)
	}
}

func TestBuildArgs_TagsAndSkipTags(t *testing.T) {
	got := BuildArgs(PlaybookArgs{
		Playbook: "site.yml",
		Tags:     []string{"web", "db"},
		SkipTags: []string{"never"},
	})
	want := []string{"site.yml", "--tags", "web,db", "--skip-tags", "never"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs tags: got %v, want %v", got, want)
	}
}

func TestBuildArgs_ExtraVarsFileBeatsRaw(t *testing.T) {
	// When both are set, file takes precedence (matches what
	// run_playbook.go enforces via mutual-exclusion check, but
	// BuildArgs itself is defensive).
	got := BuildArgs(PlaybookArgs{
		Playbook:      "site.yml",
		ExtraVarsFile: "/tmp/x.json",
		RawExtraVars:  "k=v",
	})
	want := []string{"site.yml", "-e", "@/tmp/x.json"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs extra-vars file precedence: got %v, want %v", got, want)
	}
}

func TestBuildArgs_RawExtraVars(t *testing.T) {
	got := BuildArgs(PlaybookArgs{
		Playbook:     "site.yml",
		RawExtraVars: "env=prod version=1.2",
	})
	want := []string{"site.yml", "-e", "env=prod version=1.2"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs raw extra-vars: got %v, want %v", got, want)
	}
}

func TestBuildArgs_BecomeVariants(t *testing.T) {
	yes := true
	no := false
	got := BuildArgs(PlaybookArgs{Playbook: "site.yml", Become: &yes})
	if !sliceEqual(got, []string{"site.yml", "--become"}) {
		t.Errorf("BuildArgs become=true: got %v", got)
	}
	got = BuildArgs(PlaybookArgs{Playbook: "site.yml", Become: &no})
	if !sliceEqual(got, []string{"site.yml", "--become=false"}) {
		t.Errorf("BuildArgs become=false: got %v", got)
	}
	got = BuildArgs(PlaybookArgs{Playbook: "site.yml"})
	if !sliceEqual(got, []string{"site.yml"}) {
		t.Errorf("BuildArgs become unset: got %v", got)
	}
}

func TestBuildArgs_ForksUserConnection(t *testing.T) {
	n := 10
	got := BuildArgs(PlaybookArgs{
		Playbook:   "site.yml",
		Forks:      &n,
		User:       "deploy",
		Connection: "local",
	})
	want := []string{
		"site.yml",
		"--forks", "10",
		"--user", "deploy",
		"--connection", "local",
	}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs forks/user/connection: got %v, want %v", got, want)
	}
}

func TestBuildArgs_VaultPasswordFile(t *testing.T) {
	got := BuildArgs(PlaybookArgs{
		Playbook:          "site.yml",
		VaultPasswordFile: "/etc/ansible/.vault_pass",
	})
	want := []string{"site.yml", "--vault-password-file", "/etc/ansible/.vault_pass"}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs vault: got %v, want %v", got, want)
	}
}

func TestBuildArgs_DiffAndFlushCache(t *testing.T) {
	yes := true
	no := false
	got := BuildArgs(PlaybookArgs{Playbook: "site.yml", Diff: &yes, FlushCache: &no})
	if !sliceEqual(got, []string{"site.yml", "--diff"}) {
		t.Errorf("BuildArgs diff+no flush: got %v", got)
	}
	got = BuildArgs(PlaybookArgs{Playbook: "site.yml", Diff: &no, FlushCache: &yes})
	if !sliceEqual(got, []string{"site.yml", "--flush-cache"}) {
		t.Errorf("BuildArgs no diff+flush: got %v", got)
	}
}

func TestBuildArgs_TimeoutIsNotArgv(t *testing.T) {
	// Timeout is applied via Runner.RunWithTimeout, not as an argv
	// flag, so BuildArgs must NOT emit --timeout. This is enforced
	// by contract and the test catches accidental regressions.
	n := 60
	got := BuildArgs(PlaybookArgs{Playbook: "site.yml", Timeout: &n})
	if !sliceEqual(got, []string{"site.yml"}) {
		t.Errorf("BuildArgs timeout should not appear in argv: got %v", got)
	}
}

func TestBuildArgs_AllFieldsTogether(t *testing.T) {
	// Smoke test: every field set, every flag appears.
	yes := true
	n := 5
	got := BuildArgs(PlaybookArgs{
		Playbook:          "site.yml",
		Inventory:         "hosts.ini",
		Limit:             "web*",
		Tags:              []string{"config"},
		SkipTags:          []string{"never"},
		RawExtraVars:      "k=v",
		Become:            &yes,
		Forks:             &n,
		User:              "root",
		Connection:        "ssh",
		VaultPasswordFile: "/tmp/.vp",
		Diff:              &yes,
		Timeout:           &n,
		FlushCache:        &yes,
	})
	want := []string{
		"site.yml",
		"-i", "hosts.ini",
		"--limit", "web*",
		"--tags", "config",
		"--skip-tags", "never",
		"-e", "k=v",
		"--become",
		"--forks", "5",
		"--user", "root",
		"--connection", "ssh",
		"--vault-password-file", "/tmp/.vp",
		"--diff",
		"--flush-cache",
	}
	if !sliceEqual(got, want) {
		t.Errorf("BuildArgs all fields:\n got %v\nwant %v", got, want)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
