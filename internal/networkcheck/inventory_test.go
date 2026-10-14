package networkcheck

import (
	"strings"
	"testing"
)

func TestParseInventoryList_ExpandsChildGroupsAndHostVars(t *testing.T) {
	raw := []byte(`{
		"all": {"children": ["freeipa-client", "freeipa-server", "ungrouped"]},
		"freeipa-client": {"hosts": ["dt-port6000"]},
		"freeipa-server": {"hosts": ["freeipa1"]},
		"ungrouped": {},
		"_meta": {"hostvars": {
			"dt-port6000": {"ansible_host": "192.168.110.35"},
			"freeipa1": {"ansible_host": "10.1.58.11", "restic_s3_target_host": ""}
		}}
	}`)

	inv, err := ParseInventoryList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.GroupHosts["all"]) != 2 {
		t.Fatalf("all group did not expand children: %v", inv.GroupHosts["all"])
	}
	if inv.HostAddr("dt-port6000") != "192.168.110.35" {
		t.Fatalf("HostAddr = %q", inv.HostAddr("dt-port6000"))
	}
	if inv.HostAddr("no-such-host") != "no-such-host" {
		t.Fatalf("HostAddr fallback broken: %q", inv.HostAddr("no-such-host"))
	}
	if _, ok := inv.HostVar("freeipa1", "restic_s3_target_host"); ok {
		t.Fatal("empty-string var must not resolve as set")
	}
	if _, ok := inv.HostVar("freeipa1", "does_not_exist"); ok {
		t.Fatal("unset var must not resolve as set")
	}
}

func TestParseInventoryList_RejectsGroupCycle(t *testing.T) {
	raw := []byte(`{
		"a": {"children": ["b"]},
		"b": {"children": ["a"]}
	}`)
	if _, err := ParseInventoryList(raw); err == nil {
		t.Fatal("group cycle accepted")
	}
}

func TestParseInventoryList_RejectsInvalidJSON(t *testing.T) {
	if _, err := ParseInventoryList([]byte("not json")); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

// GroupOrder keeps Ansible's groups[...] order (own hosts in inventory
// order, then child groups' hosts) while GroupHosts stays sorted, so a
// caller mirroring "the first N tier hosts" sees the order a playbook does.
// The JSON shape is ansible-inventory 2.19.2's --list output for a dns
// group listing zeta, alpha, mid and a child group with beta.
func TestParseInventoryList_GroupOrderFollowsAnsible(t *testing.T) {
	raw := []byte(`{
		"_meta": {"hostvars": {}},
		"all": {"children": ["ungrouped", "dns"]},
		"dns": {"children": ["dnsextra"], "hosts": ["zeta", "alpha", "mid"]},
		"dnsextra": {"hosts": ["beta", "alpha"]}
	}`)
	inv, err := ParseInventoryList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(inv.OrderedGroupHosts("dns"), ","); got != "zeta,alpha,mid,beta" {
		t.Fatalf("OrderedGroupHosts(dns) = %s, want zeta,alpha,mid,beta", got)
	}
	if got := strings.Join(inv.GroupHosts["dns"], ","); got != "alpha,beta,mid,zeta" {
		t.Fatalf("GroupHosts[dns] = %s, want the sorted list", got)
	}
	legacy := ResolvedInventory{GroupHosts: map[string][]string{"dns": {"a", "b"}}}
	if got := strings.Join(legacy.OrderedGroupHosts("dns"), ","); got != "a,b" {
		t.Fatalf("OrderedGroupHosts without GroupOrder = %s, want the GroupHosts fallback", got)
	}
}
