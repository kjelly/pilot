package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestCIGoShardsCoverAllPackagesExactlyOnce(t *testing.T) {
	root := repoRootForTest(t)
	run := func(command string, args ...string) string {
		t.Helper()
		cmd := exec.Command(command, args...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", command, args, err, out)
		}
		return string(out)
	}
	all := strings.Fields(run("go", "list", "./..."))
	var got []string
	for _, shard := range []string{"spec", "cmd", "rest"} {
		packages := strings.Fields(run("bash", "scripts/ci-go-test-packages.sh", shard))
		if len(packages) == 0 {
			t.Fatalf("empty shard %s", shard)
		}
		if shard != "rest" && len(packages) != 1 {
			t.Fatalf("%s: %v", shard, packages)
		}
		got = append(got, packages...)
	}
	slices.Sort(got)
	slices.Sort(all)
	if !slices.Equal(got, all) {
		t.Fatalf("shards %v != all packages %v", got, all)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct{ Matrix struct{ Shard []string } }
			If       string
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(wf.Jobs["test"].Strategy.Matrix.Shard, []string{"spec", "cmd", "rest"}) {
		t.Fatal("CI must run all three package shards")
	}
	if wf.Jobs["test"].If != "needs.changes.outputs.evidence_only != 'true'" {
		t.Fatal("Go suite skip must depend only on evidence diff")
	}
}

func TestCIEvidenceOnlyDiff(t *testing.T) {
	root := repoRootForTest(t)
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Test", "GIT_COMMITTER_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.org", "GIT_COMMITTER_EMAIL=test@example.org")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("commit", "--allow-empty", "-qm", "base")
	base := git("rev-parse", "HEAD")
	check := func(base, head, want string) {
		t.Helper()
		cmd := exec.Command("bash", filepath.Join(root, "scripts/ci-evidence-only.sh"), base, head)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "evidence_only="+want {
			t.Fatalf("diff: %q %v, want %s", out, err, want)
		}
	}
	check("", "", "false")
	check(base, base, "false")
	commit := func(path string) {
		t.Helper()
		abs := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte("record"), 0644); err != nil {
			t.Fatal(err)
		}
		git("add", ".")
		git("commit", "-qm", "change")
	}
	commit("docs/evidence/feature/a space\nand newline.md")
	check(base, "HEAD", "true")
	git("rm", "-qr", "docs")
	git("commit", "-qm", "delete evidence")
	check("HEAD~1", "HEAD", "true")
	commit("docs/evidence/feature/record.md")
	commit("app.go")
	check(base, "HEAD", "false")
	git("mv", "app.go", "docs/evidence/runtime.md")
	git("commit", "-qm", "rename runtime into evidence")
	check("HEAD~1", "HEAD", "false")
}
