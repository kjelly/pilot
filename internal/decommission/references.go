package decommission

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// ScanReferences discovers and classifies every workspace reference to host
// before any mutation (spec.md §12, INV-6). It is best-effort for optional
// manifests: an absent roster/freeipa-dns.yaml/internal-endpoints.yaml is
// not an error, since spec.md §12 only requires inspecting them "if
// present". It never opens a connection to a live system — every input here
// is a workspace file already on disk (INV-2's "plan before mutation" and
// the read-only contract in planner.go's Plan depend on that).
//
// Path convention: freeipa-dns.yaml and internal-endpoints.yaml live at
// <workspaceDir>/freeipa-dns.yaml and <workspaceDir>/internal-endpoints.yaml
// — the fixed, non-configurable convention already used throughout
// cmd/pilot/cmd (edit_tui_dns.go, edit_tui_internal_endpoints.go,
// internal_endpoint_cli.go, deploy.go's autoFillWorkspaceManifestFile — see
// `grep -rn "freeipa-dns.yaml\|internal-endpoints.yaml" cmd/pilot/cmd/`).
// The canonical FreeIPA roster has no such fixed workspace-root path; it is
// a per-host inventory variable (host.Extra["freeipa_roster_file"], see
// internal/inventory/inventory.go's hostNeedsFreeIPARoster/Lint), resolved
// relative to workspaceDir when not absolute.
func ScanReferences(workspaceDir string, host inventory.Host) ([]Reference, []Warning) {
	var refs []Reference
	var warnings []Warning

	if hv := scanHostVars(workspaceDir, host.Name); hv != nil {
		refs = append(refs, *hv)
	}

	rosterRefs, rosterWarnings := scanFreeIPARoster(workspaceDir, host)
	refs = append(refs, rosterRefs...)
	warnings = append(warnings, rosterWarnings...)

	refs = append(refs, scanDNSManifest(workspaceDir, host.Name)...)
	refs = append(refs, scanInternalEndpoints(workspaceDir, host.Name)...)

	// Historical evidence (Pilot's own delivery/verify evidence store,
	// internal/store) is deliberately never scanned here: spec.md §5.4/§19
	// classify historical records as never-an-active-reference, so simply
	// not inspecting internal/store at all already satisfies "historical
	// evidence not treated as active reference" (spec.md §33) — there is
	// no code path here that could mistakenly surface one.

	return refs, warnings
}

func scanHostVars(workspaceDir, hostName string) *Reference {
	rel := filepath.Join("host_vars", hostName+".yml")
	path := filepath.Join(workspaceDir, rel)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return &Reference{
		Source:         "host_vars",
		Kind:           "host_vars_file",
		Identity:       rel,
		Classification: classifyOwnership(OwnershipCanonicalRosterExact, true),
		Detail:         "host-owned file, exclusively about this host — archived/removed at finalization",
	}
}

// rosterPathFor resolves the target host's canonical FreeIPA roster path
// from its own inventory variable, relative to workspaceDir when not
// absolute. Returns "" when the host declares none (most hosts don't need
// one — see inventory.hostNeedsFreeIPARoster).
// RosterPathFor is rosterPathFor's exported form — used by cmd/pilot/cmd
// to resolve the SAME roster path Plan/CheckFreshness derive internally,
// so CLI wiring that constructs a live provider (e.g.
// providers.NewFreeIPAClientProvider's ExtraArgs) can pass
// "-e freeipa_roster_file=<path>" pointing at exactly the file Plan's
// RosterPath/step Params referenced (spec.md §16.4) — never a
// independently-guessed path.
func RosterPathFor(workspaceDir string, host inventory.Host) string {
	return rosterPathFor(workspaceDir, host)
}

func rosterPathFor(workspaceDir string, host inventory.Host) string {
	p := strings.TrimSpace(host.Extra["freeipa_roster_file"])
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(workspaceDir, p)
}

func scanFreeIPARoster(workspaceDir string, host inventory.Host) ([]Reference, []Warning) {
	path := rosterPathFor(workspaceDir, host)
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil, nil // best-effort: absent roster is not an error
	}
	root, err := inventory.ReadRosterAsMapFile(path)
	if err != nil {
		if err == inventory.ErrRosterEncrypted {
			return nil, []Warning{{
				Code:   "roster_encrypted",
				Detail: "FreeIPA roster " + path + " is ansible-vault encrypted — cannot scan it for references without a vault password; treat as unresolved",
			}}
		}
		return nil, []Warning{{Code: "roster_unreadable", Detail: "could not scan FreeIPA roster " + path + " for references: " + err.Error()}}
	}

	var refs []Reference

	// Canonical top-level host declaration.
	for _, raw := range asAnyList(root["hosts"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if stringFieldGeneric(m, "name") == host.Name || stringFieldGeneric(m, "fqdn") == host.Name {
			refs = append(refs, Reference{
				Source: "freeipa-roster", Kind: "canonical_host_declaration",
				Identity:       path,
				Classification: classifyOwnership(OwnershipCanonicalRosterExact, true),
				Detail:         "canonical roster host entry — completes to state: absent",
			})
		}
	}

	refs = append(refs, scanRosterGroupList(root, "hostgroups", "hostgroup_membership", host.Name)...)
	refs = append(refs, scanRosterGroupList(root, "netgroups", "netgroup_membership", host.Name)...)
	refs = append(refs, scanRosterRuleList(root, "hbac", "hbac_rule", host.Name)...)
	refs = append(refs, scanRosterRuleList(root, "sudo", "sudo_rule", host.Name)...)

	return refs, nil
}

// scanRosterGroupList scans root[listKey][] entries (hostgroups/netgroups
// shape: {name, membership: {hosts: [...]}}) for exact membership of
// hostName -> AUTO_REMOVE. An entry whose name merely CONTAINS hostName as
// a substring, without exact membership, is surfaced as FOREIGN_UNKNOWN —
// never silently dropped, never auto-deleted (spec.md §5.6/HD28).
func scanRosterGroupList(root map[string]any, listKey, kind, hostName string) []Reference {
	var refs []Reference
	for _, raw := range asAnyList(root[listKey]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringFieldGeneric(m, "name")
		membership, _ := m["membership"].(map[string]any)
		exact := false
		for _, h := range asAnyList(membership["hosts"]) {
			if hs, ok := h.(string); ok && hs == hostName {
				exact = true
				break
			}
		}
		if exact {
			refs = append(refs, Reference{
				Source: "freeipa-roster", Kind: kind, Identity: name,
				Classification: classifyOwnership(OwnershipCanonicalRosterExact, true),
				Detail:         "exact roster membership match",
			})
			continue
		}
		if name != hostName && strings.Contains(name, hostName) {
			refs = append(refs, Reference{
				Source: "freeipa-roster", Kind: kind, Identity: name,
				Classification: classifyOwnership(OwnershipUnknown, false),
				Detail:         "name contains the host name as a substring only — not ownership evidence, left untouched",
			})
		}
	}
	return refs
}

// scanRosterRuleList scans root[sectionKey].rules[] (hbac/sudo shape:
// {name, targets: {hosts: [...]}}) for exact direct-host targets.
func scanRosterRuleList(root map[string]any, sectionKey, kind, hostName string) []Reference {
	section, _ := root[sectionKey].(map[string]any)
	var refs []Reference
	for _, raw := range asAnyList(section["rules"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name := stringFieldGeneric(m, "name")
		targets, _ := m["targets"].(map[string]any)
		for _, h := range asAnyList(targets["hosts"]) {
			if hs, ok := h.(string); ok && hs == hostName {
				refs = append(refs, Reference{
					Source: "freeipa-roster", Kind: kind, Identity: name,
					Classification: classifyOwnership(OwnershipCanonicalRosterExact, true),
					Detail:         "exact direct host target",
				})
				break
			}
		}
	}
	return refs
}

func scanDNSManifest(workspaceDir, hostName string) []Reference {
	path := filepath.Join(workspaceDir, "freeipa-dns.yaml")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	root, err := inventory.LoadDNSManifest(path)
	if err != nil {
		return nil
	}
	dns, _ := root["dns"].(map[string]any)
	var refs []Reference
	for _, rawZone := range asAnyList(dns["zones"]) {
		zone, ok := rawZone.(map[string]any)
		if !ok {
			continue
		}
		zoneName := stringFieldGeneric(zone, "name")
		for _, rawRecord := range asAnyList(zone["records"]) {
			record, ok := rawRecord.(map[string]any)
			if !ok {
				continue
			}
			target, _ := record["target"].(map[string]any)
			if stringFieldGeneric(target, "inventory_host") != hostName {
				continue
			}
			refs = append(refs, Reference{
				Source: "freeipa-dns.yaml", Kind: "dns_record",
				Identity:       zoneName + "/" + stringFieldGeneric(record, "name") + " " + stringFieldGeneric(record, "type"),
				Classification: classifyOwnership(OwnershipComponentManaged, true),
				Detail:         "record's target.inventory_host is the retiring host — Pilot-managed, surgical exact-value deletion only (INV-14)",
			})
		}
	}
	return refs
}

func scanInternalEndpoints(workspaceDir, hostName string) []Reference {
	path := filepath.Join(workspaceDir, "internal-endpoints.yaml")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	root, err := inventory.LoadInternalEndpointManifest(path)
	if err != nil {
		return nil
	}
	var refs []Reference
	for _, rawEndpoint := range asAnyList(root["endpoints"]) {
		endpoint, ok := rawEndpoint.(map[string]any)
		if !ok {
			continue
		}
		fqdn := stringFieldGeneric(endpoint, "fqdn")
		route, _ := endpoint["route"].(map[string]any)

		if target, ok := route["target"].(map[string]any); ok && stringFieldGeneric(target, "inventory_host") == hostName {
			refs = append(refs, Reference{
				Source: "internal-endpoints.yaml", Kind: "endpoint_target",
				Identity:       fqdn,
				Classification: RequiresReplacement,
				Detail:         "endpoint route.target.inventory_host is the retiring host — must be removed or repointed before decommission can proceed",
			})
		}
		if proxy, ok := route["proxy"].(map[string]any); ok && stringFieldGeneric(proxy, "inventory_host") == hostName {
			refs = append(refs, Reference{
				Source: "internal-endpoints.yaml", Kind: "endpoint_proxy",
				Identity:       fqdn,
				Classification: RequiresReplacement,
				Detail:         "endpoint route.proxy.inventory_host is the retiring host — must be removed or repointed before decommission can proceed",
			})
		}
	}
	return refs
}

func asAnyList(v any) []any {
	list, _ := v.([]any)
	return list
}

func stringFieldGeneric(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
