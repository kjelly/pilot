// roster_freeipa_client_autofill.go auto-fills the roster's hosts: list
// with hosts.yml hosts that carry the freeipa-client role but have no
// roster host entry at all — the exact gap that makes hostgroup/HBAC/
// sudo membership referencing them fail closed for the outbound webhook
// projection (internal/outbound/projection.go's namespaceHostRefs
// referential-integrity check) even though the host is genuinely
// enrolled. Mirrors AppendMissingNFSServerStub's "derive from inventory,
// append only if missing, never touch existing content" convention:
// purely additive and idempotent, so it needs no confirmation prompt —
// same reasoning as ensureRosterSchemaCurrentBanner
// (cmd/pilot/cmd/edit_tui_roster.go)'s auto-migration.
package inventory

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AutoFillFreeIPAClientRosterHosts appends a roster hosts: entry (FQDN +
// ansible_host as ip_address) for every hosts.yml host tagged
// freeipa-client that has no roster host entry yet, in ANY state — a
// host an operator already decommissioned via SetRosterHostAbsent is
// never resurrected, since its state: absent entry already counts as
// "has an entry." Returns the FQDNs it appended, sorted; nil, nil if
// there was nothing to do (no hosts.yml, no qualifying host, or every
// qualifying host already has an entry). dir is the workspace directory
// (hosts.yml, and group_vars/freeipa.yml as the domain fallback); path
// is the roster file.
func AutoFillFreeIPAClientRosterHosts(dir, path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}

	domain, _ := RosterDomain(path)
	if strings.TrimSpace(domain) == "" {
		domain, _ = FreeIPADomain(dir)
	}
	domain = strings.TrimSpace(domain)

	existing := map[string]bool{}
	for _, raw := range listField(root, "hosts") {
		if name := stringField(asMap(raw), "name"); name != "" {
			existing[name] = true
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	hf, err := Parse(data)
	if err != nil {
		return nil, err
	}

	var added []string
	for _, h := range hf.Hosts {
		if !hasRoleTag(h.Roles, "freeipa-client") {
			continue
		}
		fqdn := h.Name
		if !ValidRosterHostFQDN(fqdn) {
			if domain == "" {
				continue
			}
			fqdn = RosterHostFQDN(h.Name, domain)
		}
		if existing[fqdn] {
			continue
		}
		ip := strings.TrimSpace(h.AnsibleHost)
		if ip == "" {
			continue
		}
		if err := AppendRosterHost(path, fqdn, ip); err != nil {
			return added, err
		}
		existing[fqdn] = true
		added = append(added, fqdn)
	}
	sort.Strings(added)
	return added, nil
}

func hasRoleTag(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
