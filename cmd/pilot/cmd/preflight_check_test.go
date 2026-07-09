package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/ansible"
)

func TestSyntaxCheckAndLint_ValidPlaybookPasses(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	pbPath := filepath.Join(root, "site.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := syntaxCheckAndLint(context.Background(), ansible.NewRunner(), pbPath, []string{pbPath}, false, true /* skipLint: keep this test independent of ansible-lint's opinions */)
	if err != nil {
		t.Fatalf("expected valid playbook to pass syntax check, got: %v", err)
	}
}

func TestSyntaxCheckAndLint_BadYAMLFails(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	pbPath := filepath.Join(root, "bad.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks: [this is not valid ansible\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := syntaxCheckAndLint(context.Background(), ansible.NewRunner(), pbPath, []string{pbPath}, false, true)
	if err == nil {
		t.Fatal("expected syntax check to fail on malformed playbook")
	}
	if !strings.Contains(err.Error(), "syntax check failed") {
		t.Errorf("expected a syntax-check-failed error, got: %v", err)
	}
}

func TestSyntaxCheckAndLint_SkipSyntaxSkipsCheckEntirely(t *testing.T) {
	// Nonexistent playbook path — if skipSyntax actually skips the
	// ansible-playbook call, this must return nil (no attempt to
	// syntax-check a file that isn't there).
	err := mustSkipSyntax(t)
	if err != nil {
		t.Fatalf("expected skipSyntax=true to bypass the check, got: %v", err)
	}
}

func mustSkipSyntax(t *testing.T) error {
	t.Helper()
	_, err := syntaxCheckAndLint(context.Background(), ansible.NewRunner(), "/nonexistent/playbook.yml", []string{"/nonexistent/playbook.yml"}, true, true)
	return err
}

func TestSyntaxCheckAndLint_LintIssuesAreNonFatal(t *testing.T) {
	if _, err := exec.LookPath("ansible-lint"); err != nil {
		t.Skipf("ansible-lint not installed: %v", err)
	}
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	root := t.TempDir()
	// A playbook that's syntactically valid but should trip up common
	// ansible-lint rules (no "name:" on the play/task).
	pbPath := filepath.Join(root, "unnamed.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: all\n  tasks:\n    - command: /bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	lintIssues, err := syntaxCheckAndLint(context.Background(), ansible.NewRunner(), pbPath, []string{pbPath}, false, false)
	if err != nil {
		t.Fatalf("lint issues must not be fatal, got err: %v", err)
	}
	if lintIssues == "" {
		t.Skip("ansible-lint did not flag anything on this ruleset/version; not a regression in our code")
	}
}
