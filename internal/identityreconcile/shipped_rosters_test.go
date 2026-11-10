package identityreconcile

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
)

// Rosters pilot itself hands to operators or writes must be accepted by the
// Go engine's adapter: a refusal of one of them is a regression, not a
// stricter roster (issue #273: refusing a null uid/gid broke both).

// The roster deploy_catalog.go tells operators to copy. It passes the
// validator and the adapter; if a later refusal rejects it, either the
// refusal or the example is wrong, and this fails.
func TestShippedExampleRosterIsAccepted(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "playbooks", "apply", "freeipa-identity.roster.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if v := inventory.ValidateRoster(root); len(v) != 0 {
		t.Fatalf("the validator refuses the shipped example: %s: %s", v[0].Rule, v[0].Detail)
	}
	d, err := FromRoster(root)
	if err != nil {
		t.Fatalf("the Go adapter refuses the shipped example: %v", err)
	}
	if len(d.Users) == 0 || len(d.Groups) == 0 {
		t.Fatalf("the example read as an empty roster: %d users, %d groups", len(d.Users), len(d.Groups))
	}
}

// A roster edited the way `pilot edit`'s roster wizard does it
// (cmd/pilot/cmd/edit_tui_roster.go): AppendRosterUser/AppendRosterGroup for
// the stub, then the entry read back, a blank integer field set to nil
// ("留空 = 未設定") and the entry written with SetRosterUser/SetRosterGroup.
func TestRosterWrittenByTheEditorIsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := inventory.AppendRosterUser(path, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := inventory.AppendRosterGroup(path, "team-a", "team"); err != nil {
		t.Fatal(err)
	}
	user, found, err := inventory.RosterUser(path, "alice")
	if err != nil || !found {
		t.Fatalf("user: %v %v", found, err)
	}
	user["uid"], user["gid"] = nil, nil
	if err := inventory.SetRosterUser(path, "alice", user); err != nil {
		t.Fatal(err)
	}
	group, found, err := inventory.RosterGroup(path, "team-a")
	if err != nil || !found {
		t.Fatalf("group: %v %v", found, err)
	}
	group["gid"] = nil
	if err := inventory.SetRosterGroup(path, "team-a", group); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	// The null really is in the file the editor wrote.
	if alice := root["users"].([]any)[0].(map[string]any); alice["uid"] != nil || alice["gid"] != nil {
		t.Fatalf("alice = %v", alice)
	} else if _, ok := alice["uid"]; !ok {
		t.Fatalf("the editor's file has no uid key, so this row would prove nothing:\n%s", data)
	}
	if v := inventory.ValidateRoster(root); len(v) != 0 {
		t.Fatalf("the validator refuses the editor's roster: %s: %s\n%s", v[0].Rule, v[0].Detail, data)
	}
	d, err := FromRoster(root)
	if err != nil {
		t.Fatalf("the Go adapter refuses the editor's roster: %v\n%s", err, data)
	}
	if len(d.Users) != 1 || d.Users[0].UID != nil || d.Users[0].GID != nil || len(d.Groups) != 1 || d.Groups[0].GID != nil {
		t.Fatalf("users = %+v groups = %+v, want ids not managed", d.Users, d.Groups)
	}
}
