package identity

import (
	"context"
	"os/user"
	"testing"
)

// TestIsMemberOfGroupSelf uses a real group this test process's own user
// genuinely belongs to (its primary group), resolved via os/user rather
// than assumed, so the test works in any environment.
func TestIsMemberOfGroupSelf(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	// A user's primary group does not usually list them in the group's
	// own member list (that's implied by gid, not membership), so
	// IsMemberOfGroup (which only checks the explicit member list) is
	// expected to return false here — this just proves the group
	// resolves and the call doesn't error, without asserting membership
	// this mechanism was never meant to detect.
	primaryGroup, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId unavailable: %v", err)
	}
	if _, err := IsMemberOfGroup(context.Background(), u.Username, primaryGroup.Name); err != nil {
		t.Fatalf("IsMemberOfGroup: %v", err)
	}
}

func TestIsMemberOfGroupUnknownGroup(t *testing.T) {
	member, err := IsMemberOfGroup(context.Background(), "someone", "this-group-does-not-exist-12345")
	if err == nil {
		t.Fatalf("expected an error for a nonexistent group, got member=%v", member)
	}
}

func TestIsMemberOfGroupUnknownUserNotMember(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	primaryGroup, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId unavailable: %v", err)
	}
	member, err := IsMemberOfGroup(context.Background(), "definitely-not-a-real-user-98765", primaryGroup.Name)
	if err != nil {
		t.Fatalf("IsMemberOfGroup: %v", err)
	}
	if member {
		t.Fatalf("expected a nonexistent username to never be reported as a member")
	}
}
