package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitBlobOIDMatchesGit(t *testing.T) {
	// Known Git ids: the empty blob and "hello\n".
	if got := GitBlobOID(nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("empty blob = %s", got)
	}
	if got := GitBlobOID([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("hello blob = %s", got)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	content := []byte("- name: x\n  ansible.builtin.debug: {msg: \"é\"}\n")
	p := filepath.Join(t.TempDir(), "f.yml")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "hash-object", p).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSpace(string(out)); want != GitBlobOID(content) {
		t.Fatalf("git hash-object %s != %s", want, GitBlobOID(content))
	}
}
