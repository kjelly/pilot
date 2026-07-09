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

import "sort"

// role is one leaf group a host can join via its `roles:` list.
// Description is one line, shown by `pilot inventory roles` and in
// lint errors — the full rationale (prerequisites, resource sizing,
// stage gates) stays in DELIVERY.md's "Playbook 對照表" and the
// docs/runbooks/*.md it links to, not duplicated here.
type role struct {
	Name        string
	Description string
}

// leafRoles is every group name valid in a host's `roles:` list, in
// the order they render in the generated inventory. This must stay in
// sync with the `all.children` tree in inventory.example.yml.
var leafRoles = []role{
	{"freeipa-server", "FreeIPA 身份伺服器 (freeipa-server-apply.yml)"},
	{"freeipa-client", "納入 FreeIPA 的機器 (freeipa-client-apply.yml)"},
	{"freeipa-server-replica", "FreeIPA multi-master replica，v0.1 草稿未實跑，見 docs/verification/freeipa-server-replica.md"},
	{"dns", "core-infra-provider-apply.yml -e infra_role=dns"},
	{"ntp", "core-infra-provider-apply.yml -e infra_role=ntp"},
	{"docker", "core-infra-provider-apply.yml -e infra_role=docker"},
	{"keycloak", "IdP (keycloak-apply.yml)"},
	{"keycloak-db", "Keycloak 的 PostgreSQL (keycloak-db-apply.yml)"},
	{"linux-servers", "SSH 走 OIDC 登入 (pam-oidc-sshd-apply.yml)"},
	{"log-server", "中央稽核日誌接收 (log-server-apply.yml)"},
	{"audit-log-forwarding", "主機稽核 + 轉送到 log-server (audit-log-forwarding-apply.yml)"},
	{"wazuh-manager", "Wazuh 中央伺服器，需先過 docker，資源需求見 docs/runbooks/wazuh-manager.md §5 (wazuh-manager-apply.yml)"},
	{"wazuh-fim", "Wazuh agent：FIM + auditd who-data (wazuh-fim-apply.yml)"},
	{"seaweedfs-s3", "S3 相容物件儲存，需先過 docker (seaweedfs-s3-apply.yml)"},
	{"restic-backup", "跨主機備份到 S3，見 docs/runbooks/restic-backup.md §5 (restic-backup-apply.yml)"},
	{"prometheus", "每站 Prometheus + Thanos Sidecar (prometheus-apply.yml)"},
	{"thanos-query", "中央 Thanos Query，只需一台 (thanos-query-apply.yml)"},
	{"alertmanager", "中央 Alertmanager，只需一台 (alertmanager-apply.yml)"},
	{"dashboard", "Grafana + Loki，只需一台 (dashboard-apply.yml)"},
}

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
	out := make(map[string]bool, len(leafRoles))
	for _, r := range leafRoles {
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
	out := make([]struct{ Name, Description string }, len(leafRoles))
	for i, r := range leafRoles {
		out[i] = struct{ Name, Description string }{r.Name, r.Description}
	}
	return out
}

// groupVarsStemOverrides maps a leaf role to a DIFFERENT group_vars
// file stem when several roles share one settings file. The three
// freeipa-* leaves all read realm coordinates from a single
// group_vars/freeipa.yml (see inventory.example.yml's `freeipa`
// aggregate and DELIVERY.md §1.5) — a role not listed here uses its
// own name as the stem.
var groupVarsStemOverrides = map[string]string{
	"freeipa-server":         "freeipa",
	"freeipa-client":         "freeipa",
	"freeipa-server-replica": "freeipa",
}

// GroupVarsStems returns the deduped, sorted set of group_vars file
// stems (e.g. "dns", "freeipa") needed by the roles actually used
// across hf's hosts — not the full role catalog. Callers use this to
// backfill group_vars/<stem>.yml from group_vars/<stem>.example.yml
// only for roles someone actually assigned to a host; a stem with no
// matching example file (e.g. "docker", which has no group_vars of its
// own) is still returned here — checking whether an example exists is
// the caller's job, not this package's, since it has no filesystem
// access.
func GroupVarsStems(hf *HostsFile) []string {
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		for _, r := range h.Roles {
			stem := r
			if o, ok := groupVarsStemOverrides[r]; ok {
				stem = o
			}
			seen[stem] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
