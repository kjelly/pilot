package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// tmp/go.mod keeps the gitignored scratch directory out of `./...`: agents
// keep checkouts of other PRs and loose test programs there, and before the
// sentinel `make test` compiled and failed them for reasons unrelated to the
// change under test (2026-10-31: `FAIL github.com/kjelly/pilot/tmp/pr-review-20261015`).
func TestTmpScratchIsNotPartOfTheModule(t *testing.T) {
	root := repoRootForTest(t)
	data, err := os.ReadFile(filepath.Join(root, "tmp", "go.mod"))
	if err != nil {
		t.Fatalf("tmp/go.mod must exist and be tracked: %v", err)
	}
	if !strings.Contains(string(data), "module github.com/kjelly/pilot/tmp") {
		t.Fatalf("tmp/go.mod does not declare the sentinel module:\n%s", data)
	}
	tracked := exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "tmp/go.mod")
	if out, err := tracked.CombinedOutput(); err != nil {
		t.Fatalf("tmp/go.mod is not tracked by git (tmp/* is ignored; .gitignore must except it): %v\n%s", err, out)
	}

	// A loose Go file under tmp/ must not appear in the module's package list.
	scratch := filepath.Join(root, "tmp", fmt.Sprintf("zz-scratch-%d", os.Getpid()))
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(scratch) })
	if err := os.WriteFile(filepath.Join(scratch, "main.go"), []byte("package main\n\nfunc main() { undefined() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list := exec.Command("go", "list", "./...")
	list.Dir = root
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list ./...: %v", err)
	}
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(pkg, "/tmp/") {
			t.Fatalf("go list ./... sees a scratch package: %s", pkg)
		}
	}
}
