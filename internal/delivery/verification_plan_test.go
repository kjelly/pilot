package delivery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func TestPlanVerificationResolvesSelectedV2Rows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "spec.md")
	data := `---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent: {summary: test, source: test, maintainer: sre}
targets: {roles: [role]}
inputs: []
traceability: {components: [component]}
defaults: {become: false, action: {mode: readOnly}}
---
# Verification Spec — test
## Checks
` + "```yaml" + `
- {id: C1, category: service, check: one, probe: 'true', expect: {exitCode: 0}}
- {id: C2, category: port, check: two, probe: 'true', expect: {exitCode: 0}}
` + "```" + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	auto := true
	catalog, err := contract.NewCatalog([]contract.Contract{{ID: "component", Role: "role", Verification: contract.Verification{AutoDeploy: &auto}, Specs: []contract.Spec{{Path: "spec.md", Rows: contract.RowSelector{Categories: []string{"service"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	plans, err := PlanVerification(root, catalog, []string{"component"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || len(plans[0].Rows) != 1 || plans[0].Rows[0].ID != "C1" {
		t.Fatalf("plans=%+v", plans)
	}
}

func TestPlanVerificationRejectsAutoDeployFallback(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{{ID: "component", Role: "role", Verification: contract.Verification{AutoDeploy: boolPtr(false)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanVerification(t.TempDir(), catalog, []string{"component"}); err == nil {
		t.Fatal("non-auto-deploy contract accepted")
	}
}
func boolPtr(v bool) *bool { return &v }
