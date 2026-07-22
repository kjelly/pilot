package delivery

import (
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// The minimal PoC intentionally has no log-server host: Wazuh manager is its
// SIEM receiver. Audit forwarding must therefore remain deployable without a
// log-server contract provider or an explicit siem_forward_host input.
func TestAuditLogForwardingContract_AllowsMinimalPoCWithoutLogServer(t *testing.T) {
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
	auditForwarding, ok := catalog.Component("audit-log-forwarding")
	if !ok {
		t.Fatal("audit-log-forwarding contract not found")
	}
	if len(auditForwarding.Dependencies) != 0 || len(auditForwarding.Bindings) != 0 {
		t.Fatalf("audit-log-forwarding must not require log-server: dependencies=%#v bindings=%#v", auditForwarding.Dependencies, auditForwarding.Bindings)
	}
	if _, err := ValidateContractPreflight(PreflightRequest{
		Selected: []contract.Contract{auditForwarding},
		Scope: Scope{HostsByRole: map[string][]string{
			"audit-log-forwarding": {"client-vm", "freeipa-server", "nexus"},
			"log-server":           {},
			"wazuh-manager":        {"nexus"},
		}},
	}); err != nil {
		t.Fatalf("minimal PoC audit-log-forwarding preflight failed: %v", err)
	}
}
