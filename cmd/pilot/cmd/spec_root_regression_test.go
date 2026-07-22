package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/spec"
)

// TestPilotSpec_RootFlag is the regression test for the "spec and
// playbook dirs are hard-coded to this repo" limitation. Before this
// flag existed, every `pilot spec` invocation implicitly wrote
// playbooks/generated/<stem>.yml into the cwd, which only happened
// to be the tool repo when you ran from the tool repo. The fix
// introduces a single `--root` / $PILOT_ROOT / cwd fallback that
// anchors BOTH the spec source lookup and the generated playbook
// destination — so a clone of the spec.md living under any other
// repository layout works identically.
//
// The test pins the behavior by:
//
//  1. Creating a tmp project layout (docs/, playbooks/) entirely
//     outside this tool repo
//  2. Writing a copy of the canonical pam-oidc-sshd spec into it
//  3. Running `pilot spec --root /that/path --generate` and asserting
//     both the lint step and the generated file land in the tmp tree
//  4. Re-running `pilot verify --root /that/path --local` and
//     asserting the .verification report directory also lands in
//     the tmp tree, not in cwd.
//
// To prove the test isn't a tautology: delete the `if !filepath.IsAbs(...)
// && specRoot != ""` block from runSpec / runVerify and the assertion
// here fails because the generated playbook & NDJSON land somewhere
// they shouldn't.
func TestPilotSpec_RootFlag(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", filepath.Join(tmp, "pilot-data"))
	// Layout: <tmp>/docs/verification/spec.md
	if err := os.MkdirAll(filepath.Join(tmp, "docs", "verification"), 0o755); err != nil {
		t.Fatal(err)
	}
	specBody, err := os.ReadFile(filepath.Join("..", "..", "docs", "verification", "pam-oidc-sshd.md"))
	if err != nil {
		// fall back: build a minimal inline spec so the test still runs
		// in CI configurations that lack the docs tree on disk
		specBody = []byte("# Verification Spec — root-flag-test\n\n" +
			"> 版本：v1.0\n> 對齊規範：none\n> 維護者：sre\n\n" +
			"## 2. Checklist\n\n" +
			"| ID | Category | Check | Expected | Command |\n" +
			"|----|----------|-------|----------|---------|\n" +
			"| C1 | file | os | 0 | sh -c 'test -f /etc/os-release; echo $?' |\n")
	}
	specPath := filepath.Join(tmp, "docs", "verification", "spec.md")
	if err := os.WriteFile(specPath, specBody, 0o644); err != nil {
		t.Fatal(err)
	}

	// Save/restore the flag state across the sub-calls.
	savedRoot, savedGen, savedLint, savedLoc := specRoot, specGenerateOut, specLintOnly, verifyRoot
	defer func() {
		specRoot, specGenerateOut, specLintOnly, verifyRoot = savedRoot, savedGen, savedLint, savedLoc
	}()

	// --- Step 1: lint with --root tmp ---
	specRoot = tmp
	specLintOnly = true
	if err := runSpec(nil, []string{"docs/verification/spec.md"}); err != nil {
		t.Fatalf("lint: %v", err)
	}
	specLintOnly = false

	// --- Step 2: generate with --root tmp, relative out ---
	outRel := "playbooks/generated/spec.yml"
	specGenerateOut = outRel
	if err := runSpec(nil, []string{"docs/verification/spec.md"}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	wantPB := filepath.Join(tmp, outRel)
	if _, err := os.Stat(wantPB); err != nil {
		t.Fatalf("expected generated playbook at %s: %v", wantPB, err)
	}

	// --- Step 3: verify with --root tmp ---
	specGenerateOut = ""
	verifyRoot = tmp
	if err := runVerify(nil, []string{"docs/verification/spec.md"}); err != nil {
		// runVerify returns an error when verdict is FAIL; we don't
		// care about pass/fail, only that the report landed in tmp.
		t.Logf("verify returned (expected on FAIL): %v", err)
	}
	reports, _ := filepath.Glob(filepath.Join(tmp, ".verification", "*.md"))
	if len(reports) == 0 {
		t.Fatalf("no verification report under %s/.verification — --root not propagating into verify.go", tmp)
	}

	// Defense-in-depth: the tool repo's cwd must NOT have a
	// .verification/ or playbooks/generated/spec.yml appear. If
	// our --root logic is broken, fallback would write into cwd.
	for _, leak := range []string{
		filepath.Join(".", ".verification"),
		filepath.Join(".", "playbooks", "generated", "spec.yml"),
	} {
		if _, err := os.Stat(leak); err == nil {
			t.Errorf("--root appears not enforced: %s exists", leak)
		}
	}

	// Compile-time assurance the spec package's GenerateInventory is
	// still part of the public surface (any rename here gets caught).
	_ = spec.GenerateInventoryOptions{}
}
