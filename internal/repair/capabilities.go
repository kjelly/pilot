// Package repair implements Agent Monitoring Phase 3's first live
// repair capability: R1-only, human-approved, single-host restart/
// reload of an explicitly opted-in component. It never accepts a
// caller-suppliable command, module, playbook, or shell string —
// every executable action is a fixed, contract-declared typed operation
// (internal/contract's Remediation schema). The Agent never receives
// this package's MCP transport; only the Agent Controller (or an
// operator) does, through a separate --enable-repair session.
package repair

import (
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// Capability is one contract-declared, inventory-applicable repair
// action — "declared" (in contracts/*.yaml) AND "applicable" (the
// component is actually assigned to a real inventory host right now).
// Only Risk R1 capabilities are ever returned — see ListCapabilities'
// own doc comment for why an R2-R4 action can exist in a contract
// without ever appearing here.
type Capability struct {
	Component    string
	Host         string
	ActionID     string
	Risk         string
	ExecutorKind string
}

// ListCapabilities returns every R1 repair action pilot_repair_
// capabilities may legitimately offer right now: a contract-declared
// remediation action whose component is assigned to a host that
// actually exists in the current inventory. A component with R2-R4
// actions declared (future phases) never appears here — Phase 3's
// planner and this listing both hard-restrict to R1, not merely by
// convention.
func ListCapabilities(catalog contract.Catalog, resolved networkcheck.ResolvedInventory) []Capability {
	var out []Capability
	for _, c := range catalog.Components() {
		if len(c.Remediation.Actions) == 0 {
			continue
		}
		hosts := resolved.GroupHosts[c.Role]
		for _, action := range c.Remediation.Actions {
			if action.Risk != "R1" {
				continue
			}
			for _, host := range hosts {
				out = append(out, Capability{
					Component: c.ID, Host: host, ActionID: action.ID,
					Risk: action.Risk, ExecutorKind: action.Executor.Kind,
				})
			}
		}
	}
	return out
}
