package identityreconcile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// captured reads result.result of a real FreeIPA answer captured for
// internal/freeiparpc (AGENTS.md §5.6: never a hand-written format).
func captured(t *testing.T, name string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result struct {
			Result []map[string]any `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Result.Result
}

// capturedOne reads result.result of a captured user_show or group_show: one
// entry, not a list.
func capturedOne(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result struct {
			Result map[string]any `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Result.Result == nil {
		t.Fatalf("%s: no entry in result.result (%v)", name, err)
	}
	return env.Result.Result
}

func liveUsers(t *testing.T, names ...string) []LiveUser {
	t.Helper()
	var out []LiveUser
	for _, n := range names {
		u, err := ParseUsers(captured(t, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out = append(out, u...)
	}
	return out
}

func liveGroups(t *testing.T, names ...string) []LiveGroup {
	t.Helper()
	var out []LiveGroup
	for _, n := range names {
		g, err := ParseGroups(captured(t, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out = append(out, g...)
	}
	return out
}

func roster(t *testing.T, doc string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func desired(t *testing.T, doc string) Desired {
	t.Helper()
	d, err := FromRoster(roster(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// desiredForPlan is desired with the password forms read from the roster's
// bytes, as the preview and the writer do it: what a plan needs.
func desiredForPlan(t *testing.T, doc string) Desired {
	t.Helper()
	d, err := desired(t, doc).WithPasswordForms([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// capturedDesired declares exactly what the 2026-10-27 capture holds
// (user-find-states, group-find-states, group-find-nested), so a plan
// against it plans nothing but the history markers the capture never had.
// The captured group names carry no category prefix, which the roster
// validator requires, so this is built as a Desired, not a roster.
func capturedDesired() Desired {
	user := func(name, last string) DesiredUser {
		dn := "P1 " + last
		return DesiredUser{Name: name, First: "P1", Last: last, DisplayName: &dn, Shell: "/bin/sh", Home: "/home/" + name, Enabled: true, PreserveExisting: true}
	}
	off := user("p1-off", "Off")
	off.Enabled = false
	return Desired{
		SchemaVersion: 3,
		Principal:     "admin",
		Users: []DesiredUser{
			user("p1-keys", "Keys"), user("p1-nokeys", "NoKeys"), user("p1-nopw", "NoPw"), off,
			user("p1-reset", "Reset"), user("p1-self", "Self"), user("p1-deep", "Deep"),
		},
		Groups: []DesiredGroup{
			{Name: "p1-team", Description: "P1 team", Type: TypePosix, Authoritative: true, Users: []string{"p1-keys", "p1-nopw", "p1-self"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "p1-nonposix", Description: "P1 non-posix", Type: TypeNonPosix, Authoritative: true, Users: []string{"p1-reset"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "p1-parent", Description: "P1 parent", Type: TypePosix, Authoritative: true, Users: []string{"p1-off"}, Groups: []string{"p1-team"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "p1-leaf", Description: "P1 leaf", Type: TypePosix, Authoritative: true, Users: []string{"p1-deep"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "p1-mid", Description: "P1 mid", Type: TypePosix, Authoritative: true, Groups: []string{"p1-leaf"}, UsersDeclared: true, GroupsDeclared: true},
			{Name: "p1-top", Description: "P1 top", Type: TypePosix, Authoritative: true, Groups: []string{"p1-mid"}, UsersDeclared: true, GroupsDeclared: true},
		},
	}
}

// capturedLive is the live state of that capture.
func capturedLive(t *testing.T) ([]LiveUser, []LiveGroup) {
	t.Helper()
	return liveUsers(t, "user-find-states", "user-find-nested"), liveGroups(t, "group-find-states", "group-find-nested")
}

// withMarkers adds a correct history marker for each group, as the
// playbook leaves after applying them.
func withMarkers(groups []LiveGroup, names ...string) []LiveGroup {
	for _, n := range names {
		groups = append(groups, LiveGroup{Name: HistoryMarkerName(n), Description: []string{HistoryMarkerDescription(n)}, Type: TypeNonPosix})
	}
	return groups
}
