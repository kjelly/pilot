package accessgrants

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func objectSnapshot() IdentityObjects {
	return IdentityObjects{SchemaVersion: 1, DesiredUsers: []IdentityObject{}, DesiredGroups: []IdentityObject{}, LiveUsers: []IdentityObject{}, LiveGroups: []IdentityObject{}}
}

func TestIdentityObjectsCreateDeleteAndUnmanaged(t *testing.T) {
	s := objectSnapshot()
	s.DesiredUsers = []IdentityObject{{Name: "new", State: "present"}, {Name: "gone", State: "absent"}}
	s.LiveUsers = []IdentityObject{{Name: "gone"}, {Name: "other"}}
	items, err := ComputeIdentityObjectDrift(s)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range items {
		got[item.Category+":"+item.Name] = item.Action
	}
	for key, action := range map[string]string{"user_missing:new": "create", "user_should_be_absent:gone": "delete", "user_unexpected:other": "report"} {
		if got[key] != action {
			t.Fatalf("%s action=%q, want %q", key, got[key], action)
		}
	}
}

func TestIdentityObjectsDirectMembershipAuthority(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		s := objectSnapshot()
		s.DesiredGroups = []IdentityObject{{Name: "TEAM-parent", State: "present", Users: []string{"new"}, Groups: []string{"TEAM-child"}, Authoritative: authoritative}}
		s.LiveGroups = []IdentityObject{{Name: "team-parent", Users: []string{"extra"}, Groups: []string{"team-child", "old-child"}}}
		items, err := ComputeIdentityObjectDrift(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 3 {
			t.Fatalf("items=%+v", items)
		}
		for _, item := range items {
			if strings.Contains(item.Detail, "team-child") {
				t.Fatalf("case-only member drift: %+v", item)
			}
			if item.Action == "remove_member" && !authoritative {
				t.Fatalf("additive removal: %+v", item)
			}
		}
	}
}

func TestIdentityObjectsEnabledAttributesAndKeys(t *testing.T) {
	s := objectSnapshot()
	keys, clear := []string{"SHA256:test"}, []string{}
	s.DesiredUsers = []IdentityObject{{Name: "user", State: "disabled", Enabled: false, KeyHashes: &clear, Attributes: map[string][]string{"givenname": {"SENTINEL"}}}}
	s.LiveUsers = []IdentityObject{{Name: "user", Enabled: true, KeyHashes: &keys, Attributes: map[string][]string{"givenname": {"old"}}}}
	items, err := ComputeIdentityObjectDrift(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("items=%+v", items)
	}
	b, _ := json.Marshal(items)
	if strings.Contains(string(b), "SENTINEL") || strings.Contains(string(b), "SHA256:test") {
		t.Fatalf("values escaped: %s", b)
	}
	// Simulate the effective observed state after apply, including explicit key clear.
	s.LiveUsers = s.DesiredUsers
	items, err = ComputeIdentityObjectDrift(s)
	if err != nil || len(items) != 0 {
		t.Fatalf("converged items=%+v err=%v", items, err)
	}
}

func TestIdentityObjectObserverCapturedFixtures(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for the identity observer regression")
	}
	cmd := exec.Command(python, "../../playbooks/check/files/test_identity_object_observer.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("observer: %v\n%s", err, output)
	}
}
