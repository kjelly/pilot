package cmd

// Topology graph: project the contract dependency DAG onto a concrete
// inventory and render it as an ASCII forest. The dependency edges,
// host role, host cardinality and resource sizing all come from the
// contract catalog (internal/contract) — the single machine-readable
// source of truth — so this view never invents a parallel dependency
// table. It is read-only: it mutates nothing and is safe to print
// before any deploy prompt.

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// expandIfSimplifiedHosts lets the topology graph accept pilot's simplified
// "host → roles" source file (the hosts.example.yml shape) directly: it
// detects that format and expands it in memory to a real Ansible inventory
// written to a temp file, so `ansible-inventory --list` can resolve the role
// groups. A file that is already a normal Ansible inventory is returned
// unchanged. cleanup removes any temp file created (always safe to call);
// notice is a non-empty one-liner when expansion happened, for the caller to
// print. This is read-only convenience for the graph — the real deploy still
// runs against the inventory path the operator passes.
func expandIfSimplifiedHosts(inv string) (path, notice string, cleanup func(), err error) {
	cleanup = func() {}
	data, readErr := os.ReadFile(inv)
	if readErr != nil {
		// Let the downstream ansible-inventory call surface the real error.
		return inv, "", cleanup, nil
	}
	hf, parseErr := inventory.Parse(data)
	if parseErr != nil || hf == nil {
		return inv, "", cleanup, nil
	}
	roled := false
	for _, h := range hf.Hosts {
		if len(h.Roles) > 0 {
			roled = true
			break
		}
	}
	if !roled {
		// Not the simplified format — a real Ansible inventory has no
		// top-level hosts: entries carrying a roles: list.
		return inv, "", cleanup, nil
	}
	rendered, genErr := inventory.Generate(hf)
	if genErr != nil {
		return inv, "", cleanup, fmt.Errorf(
			"%s 看起來是 pilot 的 hosts.yml 簡表，但展開失敗：\n%w\n先修好後用 `pilot inventory generate --in %s --out <inventory.yml>`",
			inv, genErr, inv)
	}
	tmp, tmpErr := os.CreateTemp("", "pilot-topology-*.yml")
	if tmpErr != nil {
		return inv, "", cleanup, tmpErr
	}
	if _, wErr := tmp.WriteString(rendered); wErr != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return inv, "", cleanup, wErr
	}
	tmp.Close()
	notice = fmt.Sprintf("（偵測到 %s 是 hosts.yml 簡表，已即時展開畫圖；實際部署請用展開後的 inventory.yml）", inv)
	return tmp.Name(), notice, func() { os.Remove(tmp.Name()) }, nil
}

// topoEdge is one outgoing dependency of a component ("this depends on To").
type topoEdge struct {
	To       string
	Required bool
	Relation string // sameHosts | providerEndpoint | ...
	Reason   string
}

// topoNode is one contract component projected onto the current inventory.
type topoNode struct {
	ID      string
	Role    string   // inventory group the component's hosts come from
	Hosts   []string // resolved hosts in this inventory (sorted); empty => not deployed
	Active  bool     // Role group has at least one host
	Card    string   // hostCardinality: exactly-one | one-or-more | ...
	MinCPU  int
	MinRAM  int // MiB
	MinDisk int // GiB
	Order   int // site.order, used only for stable sibling ordering
	InSite  bool
	Deps    []topoEdge
}

// spansAll reports whether an active node lands on every host in the
// inventory (the "overlay attaches everywhere" case rendered as [ALL]).
func (n *topoNode) spansAll(totalHosts int) bool {
	return n.Active && totalHosts > 1 && len(n.Hosts) == totalHosts
}

// overlay reports whether the node is an additive multi-host role that
// would be unsafe to run concurrently with another role on the same host
// (one-or-more cardinality spanning more than one host).
func (n *topoNode) overlay() bool {
	return n.Card == "one-or-more" && len(n.Hosts) > 1
}

type inventoryTopology struct {
	Nodes     map[string]*topoNode
	IDs       []string            // all catalog IDs, sorted by (Order, ID)
	Hosts     []string            // every host in the inventory, sorted
	HostRoles map[string][]string // host -> active component IDs it carries
}

// buildInventoryTopology projects the contract catalog onto a resolved
// group->hosts map (as returned by resolveInventoryGroups). It is pure:
// no I/O, so it is trivially unit-testable.
func buildInventoryTopology(catalog contract.Catalog, groupHosts map[string][]string) inventoryTopology {
	topo := inventoryTopology{
		Nodes:     map[string]*topoNode{},
		HostRoles: map[string][]string{},
	}
	allHosts := map[string]struct{}{}
	for _, c := range catalog.Components() {
		hosts := append([]string{}, groupHosts[c.Role]...)
		sort.Strings(hosts)
		n := &topoNode{
			ID:      c.ID,
			Role:    c.Role,
			Hosts:   hosts,
			Active:  len(hosts) > 0,
			Card:    c.HostCardinality,
			MinCPU:  c.Resources.MinCPU,
			MinRAM:  c.Resources.MinRAMMiB,
			MinDisk: c.Resources.MinDiskGiB,
			Order:   c.Site.Order,
			InSite:  c.Site.Include,
		}
		for _, d := range c.Dependencies {
			n.Deps = append(n.Deps, topoEdge{To: d.Component, Required: d.Required, Relation: d.Relation, Reason: d.Reason})
		}
		topo.Nodes[c.ID] = n
		topo.IDs = append(topo.IDs, c.ID)
		for _, h := range hosts {
			allHosts[h] = struct{}{}
			topo.HostRoles[h] = append(topo.HostRoles[h], c.ID)
		}
	}
	for h := range allHosts {
		topo.Hosts = append(topo.Hosts, h)
	}
	sort.Strings(topo.Hosts)
	for h := range topo.HostRoles {
		sort.Slice(topo.HostRoles[h], func(i, j int) bool {
			return topo.less(topo.HostRoles[h][i], topo.HostRoles[h][j])
		})
	}
	sort.Slice(topo.IDs, func(i, j int) bool { return topo.less(topo.IDs[i], topo.IDs[j]) })
	return topo
}

// less orders components by (site.order, id) for deterministic output.
func (t inventoryTopology) less(a, b string) bool {
	na, nb := t.Nodes[a], t.Nodes[b]
	if na != nil && nb != nil && na.Order != nb.Order {
		return na.Order < nb.Order
	}
	return a < b
}

// primaryParent returns the required+active dependency a node hangs under
// in the tree (smallest (order,id)), or "" if the node is a root.
func (t inventoryTopology) primaryParent(id string) string {
	n := t.Nodes[id]
	if n == nil || !n.Active {
		return ""
	}
	best := ""
	for _, d := range n.Deps {
		if !d.Required {
			continue
		}
		dep := t.Nodes[d.To]
		if dep == nil || !dep.Active {
			continue
		}
		if best == "" || t.less(d.To, best) {
			best = d.To
		}
	}
	return best
}

// renderInventoryTopology writes the ASCII topology graph to out. inventory
// is only used for the header line.
func renderInventoryTopology(out io.Writer, topo inventoryTopology, inventory string) {
	activeCount := 0
	for _, id := range topo.IDs {
		if topo.Nodes[id].Active {
			activeCount++
		}
	}
	fmt.Fprintf(out, "部署拓樸圖 — inventory: %s\n", inventory)
	fmt.Fprintf(out, "  %d 個已部署元件 / %d 台主機（依賴關係來自 contracts/）\n\n", activeCount, len(topo.Hosts))

	// Build the primary-parent forest over active nodes.
	children := map[string][]string{}
	var roots []string
	for _, id := range topo.IDs {
		n := topo.Nodes[id]
		if !n.Active {
			continue
		}
		if parent := topo.primaryParent(id); parent != "" {
			children[parent] = append(children[parent], id)
		} else {
			roots = append(roots, id)
		}
	}
	for p := range children {
		sort.Slice(children[p], func(i, j int) bool { return topo.less(children[p][i], children[p][j]) })
	}

	if len(roots) == 0 {
		fmt.Fprintln(out, "  （這份 inventory 沒有任何已部署的元件）")
	}
	for i, root := range roots {
		topo.renderNode(out, root, "", i == len(roots)-1, children)
	}

	// Components declared for site.yml but with no hosts in this inventory.
	var skipped []string
	for _, id := range topo.IDs {
		n := topo.Nodes[id]
		if !n.Active && n.InSite {
			skipped = append(skipped, id)
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintf(out, "\n未部署（inventory 無對應主機，site.yml 會自動跳過）：%s\n", strings.Join(skipped, ", "))
	}

	// Per-host load: surfaces the "one heavy host carries everything" reality,
	// with the summed minimum resources of every role stacked on that host —
	// the concrete reason a single busy host caps role-level parallelism.
	if len(topo.Hosts) > 0 {
		fmt.Fprintln(out, "\n各主機承載：")
		for _, h := range topo.Hosts {
			roles := topo.HostRoles[h]
			var cpu, ramMiB, diskGiB int
			for _, id := range roles {
				n := topo.Nodes[id]
				cpu += n.MinCPU
				ramMiB += n.MinRAM
				diskGiB += n.MinDisk
			}
			fmt.Fprintf(out, "  %s（%d 角色，≥ %d vCPU / %d GiB RAM / %d GiB 磁碟）← %s\n",
				h, len(roles), cpu, ramMiB/1024, diskGiB, strings.Join(roles, ", "))
		}
	}

	fmt.Fprintln(out, "\n圖例：──▶ 必要依賴（先於）  ┄▶ 選填連接  ⚠overlay 疊加型多主機角色  [ALL] 覆蓋全部主機")
}

// crossHostDep is one dependency that leaves the host it originates on:
// component Via (running on this host) needs component To, which lives on
// ToHosts (a different host). A nil ToHosts means a required dependency
// whose provider component has no host in this inventory (unmet).
type crossHostDep struct {
	Via      string
	To       string
	ToHosts  []string
	Required bool
	Relation string
}

// hostCrossDeps returns the outbound cross-host dependencies of everything
// running on host. sameHosts dependencies are co-located by contract and are
// never cross-host; a provider that only lives on this host is likewise
// internal and skipped. Optional dependencies whose provider is absent are
// dropped (that absence is by design); required-but-absent ones are surfaced.
func (t inventoryTopology) hostCrossDeps(host string) []crossHostDep {
	var out []crossHostDep
	for _, id := range t.HostRoles[host] {
		for _, d := range t.Nodes[id].Deps {
			if d.Relation == "sameHosts" {
				continue
			}
			dep := t.Nodes[d.To]
			if dep != nil && dep.Active {
				provider := make([]string, 0, len(dep.Hosts))
				for _, h := range dep.Hosts {
					if h != host {
						provider = append(provider, h)
					}
				}
				if len(provider) == 0 {
					continue // provider is co-located on this host
				}
				out = append(out, crossHostDep{Via: id, To: d.To, ToHosts: provider, Required: d.Required, Relation: d.Relation})
			} else if d.Required {
				out = append(out, crossHostDep{Via: id, To: d.To, ToHosts: nil, Required: true, Relation: d.Relation})
			}
		}
	}
	return out
}

// renderHostTopology writes a host-centric view: one block per host (heaviest
// first) listing the roles it carries, its summed minimum resources, and the
// cross-host service dependencies that leave it. inventory is used only for
// the header.
func renderHostTopology(out io.Writer, topo inventoryTopology, inventory string) {
	activeCount := 0
	for _, id := range topo.IDs {
		if topo.Nodes[id].Active {
			activeCount++
		}
	}
	fmt.Fprintf(out, "主機拓樸圖 — inventory: %s\n", inventory)
	fmt.Fprintf(out, "  %d 台主機 / %d 個已部署元件（跨主機依賴來自 contracts/）\n\n", len(topo.Hosts), activeCount)
	if len(topo.Hosts) == 0 {
		fmt.Fprintln(out, "  （這份 inventory 沒有任何已部署的元件）")
		return
	}

	// Order hosts by carried-role count (descending) so the busiest host —
	// the real cap on role-level parallelism — sits at the top.
	hosts := append([]string{}, topo.Hosts...)
	maxRoles := 0
	for _, h := range hosts {
		if n := len(topo.HostRoles[h]); n > maxRoles {
			maxRoles = n
		}
	}
	sort.Slice(hosts, func(i, j int) bool {
		ri, rj := len(topo.HostRoles[hosts[i]]), len(topo.HostRoles[hosts[j]])
		if ri != rj {
			return ri > rj
		}
		return hosts[i] < hosts[j]
	})

	for _, h := range hosts {
		roles := topo.HostRoles[h]
		var cpu, ramMiB, diskGiB int
		for _, id := range roles {
			n := topo.Nodes[id]
			cpu += n.MinCPU
			ramMiB += n.MinRAM
			diskGiB += n.MinDisk
		}
		heaviest := ""
		if len(hosts) > 1 && len(roles) == maxRoles {
			heaviest = "  ⚠ 承載最多"
		}
		fmt.Fprintf(out, "▪ %s — %d 角色，≥ %d vCPU / %d GiB RAM / %d GiB 磁碟%s\n",
			h, len(roles), cpu, ramMiB/1024, diskGiB, heaviest)
		fmt.Fprintf(out, "    承載：%s\n", strings.Join(roles, ", "))

		deps := topo.hostCrossDeps(h)
		if len(deps) == 0 {
			fmt.Fprintln(out, "    跨主機依賴：無（全部同機自足）")
		} else {
			fmt.Fprintln(out, "    跨主機依賴：")
			for i, d := range deps {
				connector := "├"
				if i == len(deps)-1 {
					connector = "└"
				}
				arrow := "──▶"
				if !d.Required {
					arrow = "┄▶"
				}
				target := d.To + "@未部署"
				extra := ""
				if len(d.ToHosts) > 0 {
					target = d.To + "@" + strings.Join(d.ToHosts, ",")
				} else {
					extra = "（⚠必要，未部署）"
				}
				if !d.Required && extra == "" {
					extra = "（選填）"
				}
				fmt.Fprintf(out, "      %s %s %s %s%s\n", connector, d.Via, arrow, target, extra)
			}
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "圖例：──▶ 必要跨主機依賴  ┄▶ 選填跨主機連接  @<host> 提供者所在主機")
}

func (t inventoryTopology) renderNode(out io.Writer, id, prefix string, last bool, children map[string][]string) {
	connector := "├──▶ "
	childPrefix := prefix + "│    "
	if last {
		connector = "└──▶ "
		childPrefix = prefix + "     "
	}
	if prefix == "" {
		connector = ""
		childPrefix = "  "
	}
	fmt.Fprintf(out, "%s%s%s%s\n", prefix, connector, id, t.nodeSuffix(id))

	kids := children[id]
	for i, kid := range kids {
		t.renderNode(out, kid, childPrefix, i == len(kids)-1, children)
	}
}

// nodeSuffix renders the "[hosts] ⚠overlay (另需 …) (選填 …)" tail.
func (t inventoryTopology) nodeSuffix(id string) string {
	n := t.Nodes[id]
	var b strings.Builder
	// Host placement.
	if n.spansAll(len(t.Hosts)) {
		b.WriteString(" [ALL]")
	} else {
		b.WriteString(" [" + strings.Join(n.Hosts, ", ") + "]")
	}
	if n.overlay() {
		b.WriteString(" ⚠overlay")
	}
	// Secondary dependencies not shown by the tree edge itself.
	primary := t.primaryParent(id)
	var alsoNeed, missing, optional []string
	for _, d := range n.Deps {
		if d.To == primary {
			continue
		}
		dep := t.Nodes[d.To]
		active := dep != nil && dep.Active
		switch {
		case d.Required && active:
			alsoNeed = append(alsoNeed, d.To)
		case d.Required && !active:
			missing = append(missing, d.To)
		case !d.Required && active:
			optional = append(optional, d.To)
		}
	}
	sort.Strings(alsoNeed)
	sort.Strings(missing)
	sort.Strings(optional)
	if len(alsoNeed) > 0 {
		b.WriteString("  ──▶另需 " + strings.Join(alsoNeed, ", "))
	}
	if len(optional) > 0 {
		b.WriteString("  ┄▶選填 " + strings.Join(optional, ", "))
	}
	if len(missing) > 0 {
		b.WriteString("  ⚠缺必要依賴 " + strings.Join(missing, ", ") + "（未部署）")
	}
	return b.String()
}
