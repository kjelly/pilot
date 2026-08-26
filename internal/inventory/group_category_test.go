package inventory

import (
	"strings"
	"testing"
)

func TestGroupCategoryPrefix(t *testing.T) {
	cases := []struct {
		category   string
		wantPrefix string
		wantOK     bool
	}{
		{"team", "team-", true},
		{"filesystem", "data-", true},
		{"role", "role-", true},
		{"access", "access-", true},
		{"bogus", "", false},
	}
	for _, c := range cases {
		prefix, ok := GroupCategoryPrefix(c.category)
		if prefix != c.wantPrefix || ok != c.wantOK {
			t.Errorf("GroupCategoryPrefix(%q) = (%q, %v), want (%q, %v)", c.category, prefix, ok, c.wantPrefix, c.wantOK)
		}
	}
}

func TestIsCreatableGroupCategory(t *testing.T) {
	cases := map[string]bool{
		"team": true, "filesystem": true, "role": true,
		"access": false, "bogus": false,
	}
	for category, want := range cases {
		if got := IsCreatableGroupCategory(category); got != want {
			t.Errorf("IsCreatableGroupCategory(%q) = %v, want %v", category, got, want)
		}
	}
}

func TestIsHBACSubjectGroupCategory(t *testing.T) {
	cases := map[string]bool{
		"team": true, "role": true, "access": true,
		"filesystem": false, "bogus": false,
	}
	for category, want := range cases {
		if got := IsHBACSubjectGroupCategory(category); got != want {
			t.Errorf("IsHBACSubjectGroupCategory(%q) = %v, want %v", category, got, want)
		}
	}
}

func TestIsSudoSubjectGroupCategory(t *testing.T) {
	cases := map[string]bool{
		"role": true,
		"team": false, "access": false, "filesystem": false, "bogus": false,
	}
	for category, want := range cases {
		if got := IsSudoSubjectGroupCategory(category); got != want {
			t.Errorf("IsSudoSubjectGroupCategory(%q) = %v, want %v", category, got, want)
		}
	}
}

func TestRosterDeprecationWarnings(t *testing.T) {
	root := mustParseRoster(t, `
groups:
  - {name: team-x, category: team}
  - {name: access-a, category: access}
  - {name: access-b, category: access}
`)
	warnings := RosterDeprecationWarnings(root)
	if len(warnings) != 2 {
		t.Fatalf("RosterDeprecationWarnings() = %v, want 2 entries", warnings)
	}
	if !strings.Contains(warnings[0].Detail, `"access-a"`) || !strings.Contains(warnings[1].Detail, `"access-b"`) {
		t.Fatalf("RosterDeprecationWarnings() = %+v, want access-a before access-b (file order)", warnings)
	}
}

func TestRosterDeprecationWarnings_NoneWithoutAccessGroups(t *testing.T) {
	root := mustParseRoster(t, `
groups:
  - {name: team-x, category: team}
  - {name: role-y, category: role}
`)
	if warnings := RosterDeprecationWarnings(root); len(warnings) != 0 {
		t.Fatalf("RosterDeprecationWarnings() = %v, want none", warnings)
	}
}

func TestIsDeprecatedGroupCategory(t *testing.T) {
	cases := map[string]bool{
		"access": true,
		"team":   false, "role": false, "filesystem": false, "bogus": false,
	}
	for category, want := range cases {
		if got := IsDeprecatedGroupCategory(category); got != want {
			t.Errorf("IsDeprecatedGroupCategory(%q) = %v, want %v", category, got, want)
		}
	}
}
