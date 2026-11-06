package identityreconcile

import (
	"strings"
	"testing"
)

// rosterEntries must refuse on its own what inventory.ValidateRoster happens
// to refuse first (a list element that is not a mapping, a name that is not
// a string): called without the validator, as these rows do, it may not skip
// the object or read it with an empty name.
func TestRosterEntriesRefusesWhatIsNotAnObjectWithAName(t *testing.T) {
	for _, tc := range []struct {
		name, doc, want string
	}{
		{"list of strings", "users: [bob]\n", "users[0] must be a mapping, not string"},
		{"list of lists", "groups:\n  - [team-a]\n", "groups[0] must be a mapping, not []interface {}"},
		{"null element", "users:\n  - {name: alice}\n  - ~\n", "users[1] must be a mapping, not <nil>"},
		{"no name", "users:\n  - {first: Bob}\n", "users[0]: name must be a string, not <nil>"},
		{"numeric name", "groups:\n  - {name: 5}\n", "groups[0]: name must be a string, not int"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "users"
			if strings.HasPrefix(tc.doc, "groups") {
				key = "groups"
			}
			_, err := rosterEntries(roster(t, tc.doc), key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRosterEntriesReadsNamesInOrder(t *testing.T) {
	got, err := rosterEntries(roster(t, "users:\n  - {name: bob, first: B}\n  - {name: alice}\n"), "users")
	if err != nil || len(got) != 2 || got[0].name != "bob" || got[1].name != "alice" || got[0].fields["first"] != "B" {
		t.Fatalf("entries = %+v, %v", got, err)
	}
	// Absent and an empty list are no entries; a null list is refused.
	for _, doc := range []string{"schema_version: 3\n", "users: []\n"} {
		if got, err := rosterEntries(roster(t, doc), "users"); err != nil || len(got) != 0 {
			t.Fatalf("%q: must be an empty list: %+v, %v", doc, got, err)
		}
	}
	if _, err := rosterEntries(roster(t, "users:\n"), "users"); err == nil || !strings.Contains(err.Error(), "users must be a list, not null") {
		t.Fatalf("a null users list: err = %v", err)
	}
}

// Through FromRoster the validator answers first for these: the roster is
// refused either way, and never read as an empty one.
func TestFromRosterRefusesNonMappingEntries(t *testing.T) {
	for _, doc := range []string{
		"schema_version: 3\nusers: [bob]\n",
		"schema_version: 3\ngroups: [team-a]\n",
		"schema_version: 3\nusers:\n  - {name: 5}\n",
	} {
		if _, err := FromRoster(roster(t, doc)); err == nil {
			t.Errorf("FromRoster accepted %q", doc)
		}
	}
}
