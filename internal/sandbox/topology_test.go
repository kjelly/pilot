package sandbox

import (
	"reflect"
	"testing"
)

func TestParseTopology_Empty(t *testing.T) {
	t0, err := ParseTopology("")
	if err != nil {
		t.Fatal(err)
	}
	if !t0.IsEmpty() {
		t.Errorf("empty topology should be IsEmpty=true")
	}
}

func TestParseTopology_SingleHost(t *testing.T) {
	t0, err := ParseTopology("web01")
	if err != nil {
		t.Fatal(err)
	}
	if len(t0.Hosts) != 1 || t0.Hosts[0].Name != "web01" {
		t.Errorf("got %+v", t0.Hosts)
	}
	if len(t0.Hosts[0].Roles) != 0 {
		t.Errorf("expected no roles, got %v", t0.Hosts[0].Roles)
	}
}

func TestParseTopology_HostWithGroups(t *testing.T) {
	// Within a single host entry, groups are separated by '+'.
	// Top-level hosts are separated by ','.
	t0, err := ParseTopology("web01:webservers+frontend")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(t0.Hosts[0].Roles, []string{"webservers", "frontend"}) {
		t.Errorf("got roles %v", t0.Hosts[0].Roles)
	}
}

func TestParseTopology_MultipleHostsMultipleGroups(t *testing.T) {
	t0, err := ParseTopology("web01:webservers, web02:webservers, db01:dbservers")
	if err != nil {
		t.Fatal(err)
	}
	if len(t0.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(t0.Hosts))
	}
	groups := t0.Groups()
	want := []string{"dbservers", "webservers"}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("Groups = %v, want %v", groups, want)
	}
}

func TestParseTopology_RejectsEmptyName(t *testing.T) {
	if _, err := ParseTopology("web01,:webservers"); err == nil {
		t.Errorf("expected error for empty host name")
	}
}

func TestTopology_IsEmptyAndGroups(t *testing.T) {
	var t0 Topology
	if !t0.IsEmpty() {
		t.Error("zero-value topology should be empty")
	}
	t0 = Topology{Hosts: []HostSpec{
		{Name: "a", Roles: []string{"x"}},
		{Name: "b", Roles: []string{"y", "x"}},
		{Name: "c"},
	}}
	if t0.IsEmpty() {
		t.Error("populated topology should not be empty")
	}
	got := t0.Groups()
	if !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Errorf("Groups = %v, want [x y]", got)
	}
}
