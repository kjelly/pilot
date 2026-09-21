package outbound

import (
	"sort"
	"strings"
)

// RosterSourceKind classifies how many distinct freeipa_roster_file
// values a workspace's effective FreeIPA targets resolve to (design spec
// §11.5).
type RosterSourceKind string

const (
	RosterSourceAbsent   RosterSourceKind = "absent"
	RosterSourceOne      RosterSourceKind = "one"
	RosterSourceMultiple RosterSourceKind = "multiple"
)

// RosterSource is ResolveRosterSource's typed result.
type RosterSource struct {
	Kind RosterSourceKind
	// Paths is empty for Absent, exactly one entry for One, and the
	// full sorted distinct set for Multiple.
	Paths []string
}

// ResolveRosterSource classifies the distinct freeipa_roster_file values
// across hostVars (already resolved by the caller — see this package's
// doc comment on why it never shells out to ansible-inventory itself).
// It does not read any file; a relative path is returned exactly as
// declared, joining against the workspace directory is the caller's job.
func ResolveRosterSource(hostVars map[string]map[string]any) RosterSource {
	seen := map[string]bool{}
	for _, vars := range hostVars {
		v, _ := vars["freeipa_roster_file"].(string)
		v = strings.TrimSpace(v)
		if v != "" {
			seen[v] = true
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	switch len(paths) {
	case 0:
		return RosterSource{Kind: RosterSourceAbsent}
	case 1:
		return RosterSource{Kind: RosterSourceOne, Paths: paths}
	default:
		return RosterSource{Kind: RosterSourceMultiple, Paths: paths}
	}
}

// rosterHostID returns the canonical lookup key for a roster host FQDN:
// lowercase without a trailing dot. It is used to resolve roster access
// references to the corresponding hosts.yml inventory ID.
func rosterHostID(fqdn string) string {
	return "freeipa:" + strings.ToLower(strings.TrimSuffix(fqdn, "."))
}

// inventoryHostID returns the stable namespaced ID for an inventory
// (hosts.yml) host.
func inventoryHostID(name string) string {
	return "inventory:" + name
}
