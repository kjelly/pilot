package delivery

import (
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/contract"
)

func TestPlanComponentsOrdersDependenciesAndRejectsExperimental(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{
		{ID: "client", Role: "client", Dependencies: []contract.Dependency{{Component: "provider", Required: true}}},
		{ID: "provider", Role: "provider", Dependencies: []contract.Dependency{{Component: "base", Required: true}}},
		{ID: "base", Role: "base"},
		{ID: "preview", Role: "preview", Experimental: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanComponents(catalog, []string{"client"}, false)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(plan.Ordered))
	for i, component := range plan.Ordered {
		got[i] = component.ID
	}
	if strings.Join(got, ",") != "base,provider,client" {
		t.Fatalf("order=%v", got)
	}
	if _, err := PlanComponents(catalog, []string{"preview"}, false); err == nil {
		t.Fatal("experimental component was not gated")
	}
	if _, err := PlanComponents(catalog, []string{"preview"}, true); err != nil {
		t.Fatal(err)
	}
}
