package networkcheck

import "testing"

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
