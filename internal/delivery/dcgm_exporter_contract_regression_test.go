package delivery

import (
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// dcgm-exporter uses Docker Engine at runtime, but hosts can receive that
// engine from an existing platform installation.  It must therefore remain
// deployable without assigning the host the pilot docker role.
func TestDcgmExporterContract_AllowsExistingDockerWithoutDockerRole(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	dcgmExporter, ok := catalog.Component("dcgm-exporter")
	if !ok {
		t.Fatal("dcgm-exporter contract not found")
	}
	if len(dcgmExporter.Dependencies) != 0 {
		t.Fatalf("dcgm-exporter must not require the pilot docker role: dependencies=%#v", dcgmExporter.Dependencies)
	}
	plan, err := PlanComponents(catalog, []string{"dcgm-exporter"}, true)
	if err != nil {
		t.Fatalf("plan dcgm-exporter with an externally managed Docker Engine: %v", err)
	}
	if len(plan.Ordered) != 1 || plan.Ordered[0].ID != "dcgm-exporter" {
		t.Fatalf("dcgm-exporter plan must not include docker: %#v", plan.Ordered)
	}
}
