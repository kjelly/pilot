package sandbox

import (
	"fmt"
	"sort"
	"strings"
)

// HostSpec describes one logical host in a multi-container sandbox
// topology. Pilot starts one Docker container per HostSpec and
// generates an ansible inventory fragment that points each host at
// the right container.
//
// Loop engineering motivation: many real-world playbooks target
// multiple hosts (web tier behind a load balancer, db primary +
// replica). A single-container sandbox forces the LLM to hand-
// write the topology into the playbook; a multi-host sandbox lets
// the user describe the topology once and the playbook just works.
type HostSpec struct {
	// Name is the inventory hostname (e.g. "web01"). Required.
	Name string

	// Image overrides the default Image for this host. Empty means
	// use the Environment's default Image.
	Image string

	// Roles are the ansible groups this host belongs to (e.g.
	// "webservers", "dbservers"). Used to generate [groupname] sections
	// in the inventory.
	Roles []string

	// Vars are extra host_vars to inject into the inventory
	// (e.g. {"listen_port": "8080"}).
	Vars map[string]string
}

// Topology is an ordered set of HostSpecs. Order is preserved in
// the generated inventory so tests that snapshot the inventory
// output are stable.
type Topology struct {
	Hosts []HostSpec
}

// ParseTopology parses a CLI-style description into a Topology.
//
// Format (loose; comma+space separated):
//
//	web01,web02,web03:webservers  db01:dbservers,db=dbslave
//
// The `:groupname` suffix assigns the host to one group. Multiple
// groups are joined by `,` inside the suffix. A pure hostname with
// no suffix becomes a host with no group membership (still
// reachable via "all").
//
// The empty topology (zero hosts) means "single anonymous host" —
// callers can map this to a one-container sandbox with name
// "sandbox".
func ParseTopology(spec string) (Topology, error) {
	t := Topology{}
	if strings.TrimSpace(spec) == "" {
		return t, nil
	}
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host := HostSpec{}
		// Split on ":" once to extract optional group list.
		// Within a single host entry, groups are separated by "+".
		// Top-level hosts are separated by ",".
		if i := strings.Index(raw, ":"); i >= 0 {
			host.Name = strings.TrimSpace(raw[:i])
			groups := strings.TrimSpace(raw[i+1:])
			for _, g := range strings.Split(groups, "+") {
				g = strings.TrimSpace(g)
				if g != "" {
					host.Roles = append(host.Roles, g)
				}
			}
		} else {
			host.Name = raw
		}
		if host.Name == "" {
			return Topology{}, fmt.Errorf("topology: empty host name in %q", spec)
		}
		t.Hosts = append(t.Hosts, host)
	}
	// Stable order by name for snapshot tests.
	sort.SliceStable(t.Hosts, func(i, j int) bool {
		return t.Hosts[i].Name < t.Hosts[j].Name
	})
	return t, nil
}

// Groups returns the unique set of role names across all hosts,
// sorted alphabetically. Used by inventory generation.
func (t Topology) Groups() []string {
	seen := make(map[string]bool)
	for _, h := range t.Hosts {
		for _, r := range h.Roles {
			seen[r] = true
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// IsEmpty returns true when the topology has zero hosts.
func (t Topology) IsEmpty() bool { return len(t.Hosts) == 0 }
