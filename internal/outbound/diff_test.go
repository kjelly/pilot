package outbound

import (
	"reflect"
	"testing"
)

func hostA() ProjectedHost {
	return ProjectedHost{ID: "inventory:web1", Name: "web1", Source: "inventory", Address: "10.0.0.1", Roles: []string{"docker"}}
}

func userA() ProjectedUser {
	return ProjectedUser{Name: "alice", Enabled: true, EffectiveGroups: []string{"team-x"}}
}

// TestOutboundDiff_D1: no cursor (base is the zero snapshot, bootstrap
// requested) produces bootstrap=true with every target entity as an
// upsert and no deletes.
func TestOutboundDiff_D1(t *testing.T) {
	target := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{hostA()}, Users: []ProjectedUser{userA()}}
	d := Diff(UserHostAccessSnapshotV1{}, target, true)
	if !d.Bootstrap {
		t.Fatal("expected Bootstrap=true")
	}
	if d.BaseSnapshotID != "" {
		t.Fatalf("BaseSnapshotID = %q, want empty for bootstrap", d.BaseSnapshotID)
	}
	if len(d.Hosts.Upsert) != 1 || len(d.Hosts.Delete) != 0 {
		t.Fatalf("Hosts diff = %+v, want one upsert and no deletes", d.Hosts)
	}
	if len(d.Users.Upsert) != 1 {
		t.Fatalf("Users diff = %+v, want one upsert", d.Users)
	}
}

// TestOutboundDiff_D2: adding a user produces an upsert.
func TestOutboundDiff_D2(t *testing.T) {
	base := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA()}}
	bob := ProjectedUser{Name: "bob", Enabled: true}
	target := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA(), bob}}
	d := Diff(base, target, false)
	if len(d.Users.Upsert) != 1 || d.Users.Upsert[0].Name != "bob" {
		t.Fatalf("Users diff = %+v, want exactly one upsert for bob", d.Users)
	}
	if len(d.Users.Delete) != 0 {
		t.Fatalf("Users.Delete = %v, want empty", d.Users.Delete)
	}
}

// TestOutboundDiff_D3: removing a user produces a delete keyed by name.
func TestOutboundDiff_D3(t *testing.T) {
	base := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA(), {Name: "bob", Enabled: true}}}
	target := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA()}}
	d := Diff(base, target, false)
	if !reflect.DeepEqual(d.Users.Delete, []string{"bob"}) {
		t.Fatalf("Users.Delete = %v, want [bob]", d.Users.Delete)
	}
	if len(d.Users.Upsert) != 0 {
		t.Fatalf("Users.Upsert = %+v, want empty", d.Users.Upsert)
	}
}

// TestOutboundDiff_D4: a role/annotation change on an otherwise
// unchanged host produces a host upsert (full entity, not a patch).
func TestOutboundDiff_D4(t *testing.T) {
	base := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{hostA()}}
	changed := hostA()
	changed.Roles = []string{"docker", "freeipa-client"}
	changed.Annotations = map[string]string{"owner": "team-a"}
	target := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{changed}}
	d := Diff(base, target, false)
	if len(d.Hosts.Upsert) != 1 {
		t.Fatalf("Hosts.Upsert = %+v, want exactly one entry", d.Hosts.Upsert)
	}
	if !reflect.DeepEqual(d.Hosts.Upsert[0].Roles, []string{"docker", "freeipa-client"}) {
		t.Fatalf("upserted host Roles = %v, want the new full role list", d.Hosts.Upsert[0].Roles)
	}
}

// TestOutboundDiff_D5: an HBAC/login-access change produces a login
// access upsert.
func TestOutboundDiff_D5(t *testing.T) {
	base := UserHostAccessSnapshotV1{}
	target := UserHostAccessSnapshotV1{
		Access: ProjectedAccess{Login: []ProjectedLoginAccess{
			{ID: "static_hbac:rule1", Source: "static_hbac", Rule: "rule1", Users: []string{"alice"}, AllHosts: true, Services: []string{"sshd"}},
		}},
	}
	d := Diff(base, target, false)
	if len(d.LoginAccess.Upsert) != 1 || d.LoginAccess.Upsert[0].ID != "static_hbac:rule1" {
		t.Fatalf("LoginAccess.Upsert = %+v, want one entry static_hbac:rule1", d.LoginAccess.Upsert)
	}
}

// TestOutboundDiff_D6: an identical base and target still produce a
// (potentially all-empty) diff object — dedupe is the caller's job
// (design spec §13.3), not Diff's; the diff computation itself must not
// error or panic on a no-op comparison.
func TestOutboundDiff_D6(t *testing.T) {
	snap := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA()}}
	d := Diff(snap, snap, false)
	if len(d.Users.Upsert) != 0 || len(d.Users.Delete) != 0 {
		t.Fatalf("identical snapshots must diff to empty Users, got %+v", d.Users)
	}
	if d.BaseSnapshotID != d.TargetSnapshotID {
		t.Fatalf("BaseSnapshotID=%q TargetSnapshotID=%q, want equal for an unchanged snapshot", d.BaseSnapshotID, d.TargetSnapshotID)
	}
}

// TestOutboundDiff_D7: SnapshotID depends only on semantic state — two
// UserHostAccessSnapshotV1 values built independently (no timestamp/
// event/workflow field exists on this type at all) with the same
// content hash identically. This also guards against a future field
// addition silently entering the hash undetected by keeping this
// assertion structural (content equality => hash equality), not a
// hardcoded golden hash string.
func TestOutboundDiff_D7(t *testing.T) {
	a := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{hostA()}, Users: []ProjectedUser{userA()}}
	b := UserHostAccessSnapshotV1{Users: []ProjectedUser{userA()}, Hosts: []ProjectedHost{hostA()}} // different field/slice construction order
	if SnapshotID(a) != SnapshotID(b) {
		t.Fatalf("SnapshotID must be independent of in-memory construction order: %q vs %q", SnapshotID(a), SnapshotID(b))
	}
}

// TestOutboundDiff_D15: the host diff key is the namespaced ID, not the
// display name — two hosts with the same Name but different ID (e.g. an
// inventory host and a freeipa-roster host that happen to share a short
// name) must be tracked as distinct diff entities.
func TestOutboundDiff_D15(t *testing.T) {
	invHost := ProjectedHost{ID: "inventory:web1", Name: "web1", Source: "inventory"}
	rosterHost := ProjectedHost{ID: "freeipa:web1.example.com", Name: "web1.example.com", Source: "freeipa_roster"}
	base := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{invHost}}
	target := UserHostAccessSnapshotV1{Hosts: []ProjectedHost{invHost, rosterHost}}
	d := Diff(base, target, false)
	if len(d.Hosts.Upsert) != 1 || d.Hosts.Upsert[0].ID != "freeipa:web1.example.com" {
		t.Fatalf("Hosts.Upsert = %+v, want exactly one new entry keyed by ID freeipa:web1.example.com", d.Hosts.Upsert)
	}
}
