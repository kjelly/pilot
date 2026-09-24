package identity

import (
	"os"
	"strings"
	"testing"
)

// capturedCases parses testdata/sssd-stale-group.txt (real SSSD output).
func capturedCases(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/sssd-stale-group.txt")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{}
	var cmd string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "=== "):
			cmd = strings.TrimPrefix(line, "=== ")
		case strings.HasPrefix(line, "stdout="):
			cases[cmd] = strings.TrimPrefix(line, "stdout=")
		}
	}
	return cases
}

// TestMembershipWithStaleSSSDGroupEntry replays the live case: SSSD's cached
// group entry does not list a user added after it was cached, but the
// user's own group list does. The user's list must win.
func TestMembershipWithStaleSSSDGroupEntry(t *testing.T) {
	c := capturedCases(t)
	groupLine := c["getent group role-pilot-portal-user"]
	if getentGroupListsMember(groupLine, "phruser3") {
		t.Fatal("fixture no longer shows the stale group entry")
	}
	if !idGroupsInclude(c["id -Gn -- phruser3"], "role-pilot-portal-user") {
		t.Fatal("the new user's own group list must show the membership")
	}
	if !getentGroupListsMember(groupLine, "phruser") || !idGroupsInclude(c["id -Gn -- phruser"], "role-pilot-session-auditor") {
		t.Fatal("an existing member must be recognised by either source")
	}
	if idGroupsInclude(c["id -Gn -- phruser"], "role-pilot") || getentGroupListsMember(groupLine, "phruser2x") {
		t.Fatal("membership must match whole names only")
	}
	if idGroupsInclude(c["id -Gn -- no-such-user-xyz"], "role-pilot-portal-user") {
		t.Fatal("an unknown user has no groups")
	}
}
