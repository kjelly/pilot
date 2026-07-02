package vmtarget

import (
	"strings"
	"testing"
)

// TestRenderInventory_AliasHostEntries is the regression guard
// for the user passing `--hosts dns,ntp,keycloak` at `up` time.
// We expect:
//  1. the primary is a top-level host entry (so `-l core` works)
//  2. every alias is also a top-level host entry (so `-l dns`
//     and `hosts: dns` both work — ansible matches the host
//     directly without needing a child group)
//  3. NO `all.children` block at all, because the alias host
//     entries already provide everything the user needs and a
//     same-name child group would trigger an ansible warning
//     (`Found both group and host with same name: <alias>`).
func TestRenderInventory_AliasHostEntries(t *testing.T) {
	tgt := &Target{
		Name:    "core",
		IP:      "192.168.123.232",
		SSHUser: "ubuntu",
		SSHPort: 22,
		KeyPath: "/var/lib/libvirt/images/pilot/core/id_ed25519",
		Hosts:   []string{"core", "dns", "ntp", "keycloak"},
	}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	// Every host entry must exist (primary + aliases).
	for _, host := range []string{"core", "dns", "ntp", "keycloak"} {
		marker := "    " + host + ":\n      ansible_connection: ssh"
		if !strings.Contains(inv, marker) {
			t.Errorf("host %q missing under all.hosts:\n%s", host, inv)
		}
	}
	// No children block: same-name collision would warn otherwise.
	if strings.Contains(inv, "  children:") {
		t.Errorf("children block should be omitted (avoids the 'Found both group and host with same name' ansible warning);\n%s", inv)
	}
}

// TestRenderInventory_OmitsChildrenBlock is the regression guard
// for the ansible `[WARNING]: Found both group and host with same
// name: <name>` warnings.
//
// Earlier versions of this function emitted alias-name child groups
// under all.children so `hosts: dns` could match by group. But
// the same alias is also a host entry under all.hosts, and ansible
// reports the same-name collision. The child groups are not needed:
// `hosts: <alias>` and `ansible -i inv <alias>` both match the
// host entry directly (host takes precedence over group in the
// inventory merge), so we emit no children block at all.
func TestRenderInventory_OmitsChildrenBlock(t *testing.T) {
	tgt := &Target{
		Name: "core", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22,
		KeyPath: "/k", Hosts: []string{"core", "dns", "ntp", "keycloak"},
	}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	// Every host entry must be present under all.hosts.
	for _, host := range []string{"core", "dns", "ntp", "keycloak"} {
		marker := "    " + host + ":\n      ansible_connection: ssh"
		if !strings.Contains(inv, marker) {
			t.Errorf("host %q missing under all.hosts:\n%s", host, inv)
		}
	}
	// No children block: ansible would warn about every name in it.
	if strings.Contains(inv, "  children:") {
		t.Errorf("children block should be omitted entirely; ansible would warn on every name that also appears under all.hosts.\n%s", inv)
	}
}
