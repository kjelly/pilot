package cmd

// TestEditRoleCatalogCoversAllContracts machine-enforces that every
// component in contracts/*.yaml is selectable in `pilot edit`'s per-host
// role checklist (internal/inventory.RoleContracts, backed by
// topLevelOrder + roleContracts).
//
// 2026-08-24: dcgm-exporter was wired into contracts/dcgm-exporter.yaml,
// playbooks/site.yml, and the deploy catalog, but NOT into
// internal/inventory — the actual data source behind that checklist. The
// component silently couldn't be assigned to any host at all; nothing
// errored, it was just absent from the list. This test closes that gap by
// making both drift directions fail CI:
//
//   - uncovered contract: a contracts/*.yaml component with no matching
//     internal/inventory.RoleContracts() entry and no exemption below
//     (new component, checklist registration forgotten);
//   - stale exemption: an exempted ID that has since gained a
//     RoleContracts entry (the exemption should be deleted so the table
//     tracks reality), or one that no longer exists as a contract at all.
//
// Exemptions are a ratchet, not an escape hatch — every exempt component
// legitimately reaches its hosts a different way (roster-driven, folded
// into another role's checklist entry, or its own dedicated TUI menu),
// not "someone forgot and nobody wrote a reason".

import (
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// editRoleCatalogExemptions lists contract IDs that are deliberately NOT
// selectable via the generic per-host role checklist, and why.
var editRoleCatalogExemptions = map[string]string{
	"freeipa-ca-trust":          "day-2/opt-in reconcile-only component, no per-host checklist entry (see AGENTS.md §4.3)",
	"freeipa-dns":               "day-2/opt-in reconcile-only component, no per-host checklist entry (see AGENTS.md §4.3)",
	"freeipa-identity":          "roster-driven (docs roster YAML), not a per-host role assignment",
	"freeipa-realm-replacement": "day-2/opt-in reconcile-only component, no per-host checklist entry (see AGENTS.md §4.3)",
	"internal-endpoint":         "has its own dedicated edit_tui_internal_endpoints.go menu, not the generic role checklist",
	"log-shipping":              "folded into the log-server role's checklist entry, not a separate checklist row",
	"os-patch-sla":              "day-2/opt-in, applied via patch_stage rather than the per-host role checklist",
	"pam-oidc-sshd":             "exposed under the \"linux-servers\" checklist entry, not its own contract-ID-named row",
}

func TestEditRoleCatalogCoversAllContracts(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}

	covered := map[string]bool{}
	for _, rc := range inventory.RoleContracts() {
		covered[rc.Name] = true
	}

	contractIDs := map[string]bool{}
	for _, c := range catalog.Components() {
		contractIDs[c.ID] = true
		if covered[c.ID] {
			continue
		}
		if _, exempt := editRoleCatalogExemptions[c.ID]; exempt {
			continue
		}
		t.Errorf("contract %q has no internal/inventory.RoleContracts() entry — "+
			"it cannot be assigned to any host via `pilot edit`'s role checklist. "+
			"Register it in internal/inventory/catalog.go's topLevelOrder and "+
			"contracts.go's roleContracts (AGENTS.md §4.3), or add a reasoned "+
			"exemption to editRoleCatalogExemptions here.", c.ID)
	}

	for id, reason := range editRoleCatalogExemptions {
		if !contractIDs[id] {
			t.Errorf("exemption %q no longer matches any contract in contracts/*.yaml (reason: %q) — remove the stale exemption", id, reason)
			continue
		}
		if covered[id] {
			t.Errorf("exemption %q is stale — it now HAS an internal/inventory.RoleContracts() entry, remove the exemption (reason was: %q)", id, reason)
		}
	}
}
