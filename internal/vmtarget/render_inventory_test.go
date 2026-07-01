package vmtarget

import (
	"strings"
	"testing"
)

// TestRenderInventory_ChildrenGroupsForAliases is the regression
// guard: the user passes `--hosts dns,ntp,keycloak` at `up` time
// expecting that:
//   1) each alias is a top-level host entry (so `-l dns` works)
//   2) each alias is a child group with the primary as its sole
//      member (so `hosts: "{{ target_group }}"` apply playbooks
//      find a real group, and the user does NOT have to hand-write
//      an inventory file).
// Before this test, RenderInventory only emitted `all.hosts`, which
// forced every user to maintain their own grouped inventory by hand.
func TestRenderInventory_ChildrenGroupsForAliases(t *testing.T) {
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
	mustContain := []string{
		"    core:",        // primary host entry
		"    dns:",         // alias host entry
		"    ntp:",         // alias host entry
		"    keycloak:",    // alias host entry
		"  children:",      // children block exists
		"    dns:\n      hosts:\n        core:",
		"    ntp:\n      hosts:\n        core:",
		"    keycloak:\n      hosts:\n        core:",
	}
	for _, s := range mustContain {
		if !strings.Contains(inv, s) {
			t.Errorf("inventory missing %q\n--- full inventory ---\n%s", s, inv)
		}
	}
	// Each child group must contain `core` as its host.
	for _, child := range []string{"dns", "ntp", "keycloak"} {
		marker := "    " + child + ":\n      hosts:\n        core:"
		if !strings.Contains(inv, marker) {
			t.Errorf("child group %q missing or doesn't contain core as host\n%s", child, inv)
		}
	}
}

// TestRenderInventory_PrimarySelfGroup keeps the primary name as
// its own child group too, so playbooks that pin to the primary
// by name (`hosts: core`) also work after this refactor.
func TestRenderInventory_PrimarySelfGroup(t *testing.T) {
	tgt := &Target{
		Name: "core", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22,
		KeyPath: "/k", Hosts: []string{"core"},
	}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	if !strings.Contains(inv, "    core:\n      hosts:\n        core:") {
		t.Errorf("primary self-group missing:\n%s", inv)
	}
}

// TestRenderInventory_NoAliasesStillEmitsChildren guards the case
// where the user ran `up` without `--hosts`; we still emit the
// primary self-group so `hosts: core` keeps working.
func TestRenderInventory_NoAliasesStillEmitsChildren(t *testing.T) {
	tgt := &Target{
		Name: "solo", IP: "10.0.0.6", SSHUser: "u", SSHPort: 22,
		KeyPath: "/k",
	}
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	if !strings.Contains(inv, "  children:") {
		t.Errorf("children block should always be emitted, got:\n%s", inv)
	}
	if !strings.Contains(inv, "    solo:\n      hosts:\n        solo:") {
		t.Errorf("primary self-group missing when no aliases:\n%s", inv)
	}
}
