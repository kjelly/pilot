package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/spec"
)

// TestPilotSpec_ToInventory_Wiring guards the "spec → inventory YAML"
// bridge. Before this command existed, every pilot invocation against
// a real host had to ship a hand-maintained `inventory.yaml` alongside
// the spec. The new flag eliminates that ceremony — and the test below
// pins the wiring so the path can't silently regress.
//
// Pre-fix, even though spec.GenerateInventory existed, `pilot spec`
// had no flag to call it, so users kept hand-rolling inventories. The
// fix wires --to-inventory into runSpec so the cycle is:
//
//   spec.md  --(pilot spec --to-inventory out.yaml)-->  inventory.yaml
//
// To prove the test isn't a tautology: delete the
// `emitSpecInventory(cmd, parsed, specToInv, specFromSSH)` call from
// the `case "to-inventory"` arm of the switch and the assertion
// below fails (`action` becomes "summary" because specToInv is now
// unused).
func TestPilotSpec_ToInventory_Wiring(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "wire.md")
	outPath := filepath.Join(tmp, "wire.yaml")
	body := `# Verification Spec — wire

> 版本：v1.0
> 對齊規範：none
> 維護者：sre

## 1. 目標系統

| Hostname | Group | Address | User |
|----------|-------|---------|------|
| host-a   | all   | 10.0.0.1 | ubuntu |
| host-b   | all   | 10.0.0.2 | deploy |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | os | 0 | sh -c 'test -f /etc/os-release; echo $?' |
`
	if err := os.WriteFile(specPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Save/restore stateful flags.
	savedTo, savedFrom, savedGen, savedApply, savedLint := specToInv, specFromSSH, specGenerateOut, specApply, specLintOnly
	defer func() {
		specToInv, specFromSSH, specGenerateOut, specApply, specLintOnly = savedTo, savedFrom, savedGen, savedApply, savedLint
	}()
	specToInv = outPath
	specFromSSH = false
	specGenerateOut = ""
	specApply = false
	specLintOnly = false

	if err := runSpec(nil, []string{specPath}); err != nil {
		t.Fatalf("runSpec: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v (the --to-inventory wiring did not produce the file)", outPath, err)
	}
	gstr := string(got)
	if !strings.Contains(gstr, "host-a") || !strings.Contains(gstr, "host-b") {
		t.Errorf("emitted inventory missing host-a/host-b; got:\n%s", gstr)
	}
	if !strings.Contains(gstr, "ansible_host: \"10.0.0.1\"") {
		t.Errorf("emitted inventory missing ansible_host for host-a; got:\n%s", gstr)
	}
	// Compile-time assurance: spec.GenerateInventory signature is
	// the contract; if it changes, we'll see the failure here.
	_ = spec.GenerateInventoryOptions{}
}
