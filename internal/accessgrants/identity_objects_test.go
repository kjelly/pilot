package accessgrants

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func objectSnapshot() IdentityObjects {
	return IdentityObjects{SchemaVersion: 1, DesiredUsers: []IdentityObject{}, DesiredGroups: []IdentityObject{}, LiveUsers: []IdentityObject{}, PreservedUsers: []string{}, LiveGroups: []IdentityObject{}}
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

func driftKeys(t *testing.T, s IdentityObjects) []string {
	t.Helper()
	items, err := ComputeIdentityObjectDrift(s)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, item := range items {
		keys = append(keys, item.Category+":"+item.Name+":"+item.Action)
	}
	return keys
}

// TestIdentityObjectsPreservedUsers: a preserved user (deleted with --preserve)
// is invisible to a plain user search but apply meets it, so drift must say what
// apply will do with it. Each case is from a live run: absent + preserved is
// deleted for good by apply; present + preserved makes apply fail at the group
// step ("no such entry") after user-add reported "already exists".
func TestIdentityObjectsPreservedUsers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		desired   []IdentityObject
		live      []IdentityObject
		preserved []string
		want      []string
	}{
		{"roster absent, user preserved: apply deletes it for good",
			[]IdentityObject{{Name: "gone", State: "absent"}}, nil, []string{"gone"}, []string{"user_should_be_absent:gone:delete"}},
		{"roster present, user preserved: apply cannot create it, an operator must act",
			[]IdentityObject{{Name: "Held", State: "present"}}, nil, []string{"held"}, []string{"user_preserved:held:manual"}},
		{"roster does not name the preserved user: report only",
			nil, nil, []string{"STRAY"}, []string{"user_unexpected:stray:report"}},
		{"present and active, nothing preserved: nothing",
			[]IdentityObject{{Name: "ok", State: "present", Enabled: true}}, []IdentityObject{{Name: "ok", Enabled: true}}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := objectSnapshot()
			if tc.desired != nil {
				s.DesiredUsers = tc.desired
			}
			if tc.live != nil {
				s.LiveUsers = tc.live
			}
			if tc.preserved != nil {
				s.PreservedUsers = tc.preserved
			}
			got := driftKeys(t, s)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("items = %v, want %v", got, tc.want)
			}
		})
	}
	// A snapshot without the preserved-user read is incomplete, never "no preserved users".
	s := objectSnapshot()
	s.PreservedUsers = nil
	if _, err := ComputeIdentityObjectDrift(s); err == nil {
		t.Fatal("a snapshot without the preserved-user read must be refused as incomplete")
	}
}

// TestIdentityObjectsIgnorePilotHistoryMarkers: apply keeps one empty marker
// group per group it ever applied (pilot-internal-history-g-<sha256>); they are
// Pilot's bookkeeping, not objects outside the roster. Look-alikes still count.
func TestIdentityObjectsIgnorePilotHistoryMarkers(t *testing.T) {
	marker := "pilot-internal-history-g-" + strings.Repeat("ab", 32)
	short := "pilot-internal-history-g-" + strings.Repeat("ab", 31)
	other := "pilot-internal-history-x-" + strings.Repeat("ab", 32)
	s := objectSnapshot()
	s.LiveGroups = []IdentityObject{{Name: marker}, {Name: short}, {Name: other}, {Name: "team-real"}}
	got := driftKeys(t, s)
	want := []string{"group_unexpected:" + short + ":report", "group_unexpected:" + other + ":report", "group_unexpected:team-real:report"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("items:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestHistoryMarkerNameMatchesTheApplyTask keeps historyMarkerRE equal to what
// apply names its markers (§5.7: one fact in two places needs a test).
func TestHistoryMarkerNameMatchesTheApplyTask(t *testing.T) {
	body, err := os.ReadFile("../../playbooks/apply/tasks/freeipa-group-history-marker.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`pilot_group_history_marker: "([^"{]*)\{\{ pilot_group_history_name \| hash\('sha256'\) \}\}"`).FindSubmatch(body)
	if m == nil {
		t.Fatal("the marker name expression in the apply task changed; update historyMarkerRE")
	}
	if want := "^" + regexp.QuoteMeta(string(m[1])) + "[0-9a-f]{64}$"; historyMarkerRE.String() != want {
		t.Fatalf("historyMarkerRE = %s, apply names markers %s", historyMarkerRE, want)
	}
}
