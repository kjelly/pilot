// Package inventory expands a flat, low-ceremony "host → roles" source
// file into the nested Ansible inventory YAML that playbooks/*.yml
// actually target (all.hosts / all.children / group_vars-friendly
// group names).
//
// The nested group tree (which groups exist, how they nest, which
// apply playbook targets each) is a fixed catalog, not something the
// source file can invent — this is what lets the source file stay a
// simple per-host role list instead of a hand-maintained tree where a
// missed group membership silently breaks a deploy (see the
// spec-vs-inventory incident logged in AGENTS.md §0).
package inventory

// aggregateOrder is where each aggregator (parent group with no hosts
// of its own — membership flows in automatically from its children)
// sits relative to the leaf groups in the rendered `all.children` tree.
// freeipa wraps the three freeipa-* leaves; infra-provider wraps the
// five core-infra leaves so `-e target_group=infra-provider` can hit
// all of them at once (see inventory.example.yml's original comment).
var aggregates = []struct {
	Name     string
	Children []string
}{
	{"freeipa", []string{"freeipa-server", "freeipa-client", "freeipa-server-replica"}},
	{"infra-provider", []string{"dns", "ntp", "docker", "keycloak", "keycloak-db"}},
}

// topLevelOrder is the render order of `all.children` entries: either
// a leaf role name, or an aggregate name from aggregates above.
var topLevelOrder = []string{
	"freeipa",
	"dns", "ntp", "docker", "keycloak", "keycloak-db",
	"infra-provider",
	"linux-servers",
	"log-server",
	"audit-log-forwarding",
	"wazuh-manager",
	"wazuh-fim",
	"seaweedfs-s3",
	"restic-backup",
	"prometheus",
	"thanos-query",
	"alertmanager",
	"dashboard",
}

// envOrder is the environment-dimension groups — orthogonal to role,
// used for `-e target_group='dns:&prod'`-style intersections.
var envOrder = []string{"prod", "staging", "sandbox"}

func validRoleNames() map[string]bool {
	out := make(map[string]bool, len(roleContracts))
	for _, r := range roleContracts {
		out[r.Name] = true
	}
	return out
}

func validEnvNames() map[string]bool {
	out := make(map[string]bool, len(envOrder))
	for _, e := range envOrder {
		out[e] = true
	}
	return out
}

func aggregateChildren(name string) []string {
	for _, a := range aggregates {
		if a.Name == name {
			return a.Children
		}
	}
	return nil
}

// Roles returns the catalog of valid `roles:` entries, in render
// order, for callers that want to print it (e.g. `pilot inventory
// roles`) without reaching into package-private state.
func Roles() []struct{ Name, Description string } {
	out := make([]struct{ Name, Description string }, len(roleContracts))
	for i, r := range roleContracts {
		out[i] = struct{ Name, Description string }{r.Name, r.Description}
	}
	return out
}

// GroupVarsStems returns the deduped, sorted set of group_vars file
// stems (e.g. "dns", "freeipa") needed by the roles actually used
// across hf's hosts — not the full role catalog. Callers use this to
// backfill group_vars/<stem>.yml from group_vars/<stem>.example.yml
// only for roles someone actually assigned to a host. Roles with no
// group_vars contract contribute nothing.
func GroupVarsStems(hf *HostsFile) []string {
	return GroupVarsStemsForRoles(UsedRoles(hf))
}
