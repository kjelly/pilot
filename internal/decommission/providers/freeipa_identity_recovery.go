package providers

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// RetirementIdentity is supplied only after the lifecycle planner binds a
// previous plan to the current host snapshot, environment and inventory revision.
// It carries identity, never a server, runner, path or Ansible argument override.
type RetirementIdentity struct {
	InventoryAlias string
	Stage          string
	FQDN           string
}

var canonicalHostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// CanonicalFreeIPAFQDN follows the native lifecycle helper's identity boundary.
// A short alias, transport IP or malformed successful query cannot establish it.
func CanonicalFreeIPAFQDN(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
		return "", fmt.Errorf("an explicit canonical retirement FQDN is required")
	}
	for _, label := range strings.Split(name, ".") {
		if !canonicalHostLabel.MatchString(label) {
			return "", fmt.Errorf("an explicit canonical retirement FQDN is required")
		}
	}
	return name, nil
}

func (p *FreeIPAClientProvider) recoveryFQDN(in PlanInput) (string, error) {
	if in.RetirementIdentity == nil {
		return "", nil
	}
	bound := in.RetirementIdentity
	if bound.InventoryAlias != in.HostName ||
		(p.cfg.InventoryAlias != "" && p.cfg.InventoryAlias != bound.InventoryAlias) ||
		bound.Stage != p.retirementStage() {
		return "", fmt.Errorf("persisted retirement alias or stage changed; re-plan against the current inventory")
	}
	fqdn, err := CanonicalFreeIPAFQDN(bound.FQDN)
	if err != nil {
		return "", fmt.Errorf("persisted retirement identity: %w", err)
	}
	if p.cfg.InventoryFQDN != "" {
		current, err := CanonicalFreeIPAFQDN(p.cfg.InventoryFQDN)
		if err != nil || current != fqdn {
			return "", fmt.Errorf("persisted retirement FQDN differs from the explicit current inventory identity; re-plan")
		}
	}
	return fqdn, nil
}
