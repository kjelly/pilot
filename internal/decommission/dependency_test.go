package decommission

import (
	"context"
	"reflect"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// TestDependency_ReverseOrderTeardown proves HD8: component teardown
// follows reverse dependency order (consumers before providers), and a
// dependency cycle fails closed rather than guessing an order.
func TestDependency_ReverseOrderTeardown(t *testing.T) {
	t.Run("consumer before provider", func(t *testing.T) {
		catalog := newCatalog(t,
			contract.Contract{ID: "app", Role: "app", Dependencies: []contract.Dependency{
				{Component: "db", Required: true, Relation: "providerEndpoint"},
			}},
			contract.Contract{ID: "db", Role: "db"},
		)
		result := resolveTeardownOrder([]string{"app", "db"}, catalog)
		if result.Cycle {
			t.Fatalf("result = %+v, want no cycle", result)
		}
		if !reflect.DeepEqual(result.TeardownOrder, []string{"app", "db"}) {
			t.Fatalf("TeardownOrder = %v, want [app db] (consumer torn down before its provider)", result.TeardownOrder)
		}
	})

	t.Run("chain of three", func(t *testing.T) {
		catalog := newCatalog(t,
			contract.Contract{ID: "a", Role: "a", Dependencies: []contract.Dependency{{Component: "b", Required: true, Relation: "providerEndpoint"}}},
			contract.Contract{ID: "b", Role: "b", Dependencies: []contract.Dependency{{Component: "c", Required: true, Relation: "providerEndpoint"}}},
			contract.Contract{ID: "c", Role: "c"},
		)
		result := resolveTeardownOrder([]string{"a", "b", "c"}, catalog)
		if result.Cycle {
			t.Fatalf("result = %+v, want no cycle", result)
		}
		if !reflect.DeepEqual(result.TeardownOrder, []string{"a", "b", "c"}) {
			t.Fatalf("TeardownOrder = %v, want [a b c]", result.TeardownOrder)
		}
	})

	t.Run("cycle fails closed", func(t *testing.T) {
		catalog := newCatalog(t,
			contract.Contract{ID: "a", Role: "a", Dependencies: []contract.Dependency{{Component: "b", Required: true, Relation: "providerEndpoint"}}},
			contract.Contract{ID: "b", Role: "b", Dependencies: []contract.Dependency{{Component: "a", Required: true, Relation: "providerEndpoint"}}},
		)
		result := resolveTeardownOrder([]string{"a", "b"}, catalog)
		if !result.Cycle {
			t.Fatalf("result = %+v, want Cycle=true", result)
		}
		if len(result.TeardownOrder) != 0 {
			t.Fatalf("TeardownOrder = %v, want empty when a cycle is detected — never guess an order", result.TeardownOrder)
		}
		if result.CycleDetail == "" {
			t.Fatal("CycleDetail is empty, want a description of the cycle")
		}
	})

	t.Run("dependency on an unselected component is not an ordering edge", func(t *testing.T) {
		// "app" depends on "freeipa-server", but freeipa-server is not one
		// of THIS host's own components (it runs elsewhere) — it must not
		// participate in this host's local teardown ordering.
		catalog := newCatalog(t,
			contract.Contract{ID: "app", Role: "app", Dependencies: []contract.Dependency{
				{Component: "freeipa-server", Required: true, Relation: "providerEndpoint"},
			}},
		)
		result := resolveTeardownOrder([]string{"app"}, catalog)
		if result.Cycle {
			t.Fatalf("result = %+v, want no cycle", result)
		}
		if !reflect.DeepEqual(result.TeardownOrder, []string{"app"}) {
			t.Fatalf("TeardownOrder = %v, want [app]", result.TeardownOrder)
		}
	})

	t.Run("end to end through PlanHost", func(t *testing.T) {
		dir := t.TempDir()
		writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"app-role", "db-role"}, ""))
		catalog := newCatalog(t,
			contract.Contract{ID: "app", Role: "app-role", Dependencies: []contract.Dependency{
				{Component: "db", Required: true, Relation: "providerEndpoint"},
			}},
			contract.Contract{ID: "db", Role: "db-role"},
		)
		plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		if plan.DependencyCycle {
			t.Fatalf("plan.DependencyCycle = true, want false")
		}
		if !reflect.DeepEqual(plan.TeardownOrder, []string{"app", "db"}) {
			t.Fatalf("plan.TeardownOrder = %v, want [app db]", plan.TeardownOrder)
		}
	})

	t.Run("end to end cycle blocks planning", func(t *testing.T) {
		dir := t.TempDir()
		writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{"a-role", "b-role"}, ""))
		catalog := newCatalog(t,
			contract.Contract{ID: "a", Role: "a-role", Dependencies: []contract.Dependency{{Component: "b", Required: true, Relation: "providerEndpoint"}}},
			contract.Contract{ID: "b", Role: "b-role", Dependencies: []contract.Dependency{{Component: "a", Required: true, Relation: "providerEndpoint"}}},
		)
		plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}
		if !plan.DependencyCycle {
			t.Fatal("plan.DependencyCycle = false, want true")
		}
		if !plan.Blocked() {
			t.Fatal("plan.Blocked() = false, want true (a dependency cycle fails planning closed)")
		}
		found := false
		for _, b := range plan.Blockers {
			if b.Code == ErrDependencyCycle {
				found = true
			}
		}
		if !found {
			t.Fatalf("plan.Blockers = %+v, want one with Code=dependency_cycle", plan.Blockers)
		}
	})
}
