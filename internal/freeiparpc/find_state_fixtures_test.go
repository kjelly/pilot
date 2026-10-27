package freeiparpc

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// The fixtures below were captured from a real FreeIPA 4.13.4 (API 2.257)
// server through the SSH tunnel: six p1-* users in the states the identity
// reconcile has to tell apart (no password, admin-reset, self-changed, with
// maxlife=0, disabled, with and without SSH keys) and three p1-* groups
// (posix, non-posix, nested). These tests pin what one *_find --all read
// does and does not carry, so the Phase 1 observer is built on observed
// facts. docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md.

func findFixture(t *testing.T, method, fixture string, args []any) []map[string]any {
	t.Helper()
	_, c := loggedIn(t, map[string]string{method: fixture})
	entries, err := c.Find(context.Background(), method, args, map[string]any{"all": true})
	if err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}
	return entries
}

func entryByName(t *testing.T, entries []map[string]any, key, name string) map[string]any {
	t.Helper()
	for _, e := range entries {
		if names, _ := e[key].([]any); len(names) == 1 && names[0] == name {
			return e
		}
	}
	t.Fatalf("no entry with %s = %s", key, name)
	return nil
}

// stamp returns the FreeIPA timestamp of a datetime attribute, or "" when absent.
func stamp(t *testing.T, e map[string]any, attr string) string {
	t.Helper()
	vals, ok := e[attr].([]any)
	if !ok {
		return ""
	}
	if len(vals) != 1 {
		t.Fatalf("%s = %v", attr, vals)
	}
	m, ok := vals[0].(map[string]any)
	if !ok {
		t.Fatalf("%s = %v is not a datetime", attr, vals[0])
	}
	return fmt.Sprint(m["__datetime__"])
}

func strs(e map[string]any, attr string) []string {
	var out []string
	vals, _ := e[attr].([]any)
	for _, v := range vals {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// The password decision of freeipa-identity-apply.yml reads only
// krbLastPwdChange and krbPasswordExpiration, and one user_find --all
// carries both. has_keytab and has_password exist only in user_show.
func TestUserFindCarriesThePasswordState(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states", []any{"p1-"})
	if len(users) != 6 {
		t.Fatalf("users = %d, want 6", len(users))
	}
	for _, u := range users {
		for _, computed := range []string{"has_keytab", "has_password", "memberofindirect_group"} {
			if _, ok := u[computed]; ok {
				t.Fatalf("user_find returned %s, which only user_show does: re-capture and revisit the observer", computed)
			}
		}
	}
	nopw := entryByName(t, users, "uid", "p1-nopw")
	if stamp(t, nopw, "krblastpwdchange") != "" || stamp(t, nopw, "krbpasswordexpiration") != "" {
		t.Fatalf("a user with no password must carry neither timestamp: %v", nopw)
	}
	reset := entryByName(t, users, "uid", "p1-reset")
	last, exp := stamp(t, reset, "krblastpwdchange"), stamp(t, reset, "krbpasswordexpiration")
	if last == "" || exp == "" || exp > last {
		t.Fatalf("admin-reset: last=%q expiration=%q, want expiration <= last change (still on the reset password)", last, exp)
	}
	self := entryByName(t, users, "uid", "p1-self")
	last, exp = stamp(t, self, "krblastpwdchange"), stamp(t, self, "krbpasswordexpiration")
	if last == "" || exp <= last {
		t.Fatalf("self-changed: last=%q expiration=%q, want expiration > last change", last, exp)
	}
}

// With maxlife=0 a self-changed password leaves no krbPasswordExpiration at
// all; the reset state is then recognised by the timestamp being present.
func TestUserFindWithUnlimitedPasswordLife(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-self0", []any{"p1-self0"})
	if len(users) != 1 {
		t.Fatalf("users = %d", len(users))
	}
	if stamp(t, users[0], "krblastpwdchange") == "" || stamp(t, users[0], "krbpasswordexpiration") != "" {
		t.Fatalf("maxlife=0 self-changed user: %v", users[0])
	}
}

func TestUserFindCarriesAccountAndKeyState(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states", []any{"p1-"})
	if off := entryByName(t, users, "uid", "p1-off"); off["nsaccountlock"] != true {
		t.Fatalf("disabled user nsaccountlock = %v", off["nsaccountlock"])
	}
	if on := entryByName(t, users, "uid", "p1-nopw"); on["nsaccountlock"] != false {
		t.Fatalf("enabled user nsaccountlock = %v", on["nsaccountlock"])
	}
	if got := len(strs(entryByName(t, users, "uid", "p1-keys"), "ipasshpubkey")); got != 2 {
		t.Fatalf("p1-keys carries %d keys, want 2", got)
	}
	// Clearing the last key removes the attribute; an empty list never comes back.
	if _, ok := entryByName(t, users, "uid", "p1-nokeys")["ipasshpubkey"]; ok {
		t.Fatal("a user whose keys were cleared must carry no ipasshpubkey")
	}
	if got := strs(entryByName(t, users, "uid", "p1-nopw"), "mail"); !slices.Equal(got, []string{"p1-nopw@example.test", "p1-nopw-2@example.test"}) {
		t.Fatalf("mail = %v", got)
	}
}

// Without all=true the entry has none of the password fields: the observer
// must always ask for all.
func TestUserFindWithoutAllHasNoPasswordState(t *testing.T) {
	_, c := loggedIn(t, map[string]string{"user_find": "user-find-states-noall"})
	users, err := c.Find(context.Background(), "user_find", []any{"p1-"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		for _, attr := range []string{"krblastpwdchange", "krbpasswordexpiration", "krbextradata", "memberof_group"} {
			if _, ok := u[attr]; ok {
				t.Fatalf("user_find without all returned %s", attr)
			}
		}
	}
}

// Indirect membership is not on the user (user_find has no
// memberofindirect_group); it is read from group_find's memberindirect_user.
func TestGroupFindSeparatesDirectAndIndirectMembers(t *testing.T) {
	groups := findFixture(t, "group_find", "group-find-states", []any{"p1-"})
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	parent := entryByName(t, groups, "cn", "p1-parent")
	if got := strs(parent, "member_user"); !slices.Equal(got, []string{"p1-off"}) {
		t.Fatalf("p1-parent direct users = %v", got)
	}
	if got := strs(parent, "member_group"); !slices.Equal(got, []string{"p1-team"}) {
		t.Fatalf("p1-parent direct groups = %v", got)
	}
	indirect := strs(parent, "memberindirect_user")
	slices.Sort(indirect)
	if !slices.Equal(indirect, []string{"p1-keys", "p1-nopw", "p1-self"}) {
		t.Fatalf("p1-parent indirect users = %v", indirect)
	}
	team := entryByName(t, groups, "cn", "p1-team")
	if got := strs(team, "memberof_group"); !slices.Equal(got, []string{"p1-parent"}) {
		t.Fatalf("p1-team memberof_group = %v", got)
	}
	if _, ok := team["memberindirect_user"]; ok {
		t.Fatal("p1-team has no nested group, so it carries no memberindirect_user")
	}
	if _, ok := entryByName(t, groups, "cn", "p1-nonposix")["gidnumber"]; ok {
		t.Fatal("a non-posix group carries no gidnumber")
	}
}

func TestGroupFindWithoutAllHasNoMembers(t *testing.T) {
	_, c := loggedIn(t, map[string]string{"group_find": "group-find-states-noall"})
	groups, err := c.Find(context.Background(), "group_find", []any{"p1-"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		for _, attr := range []string{"member_user", "member_group", "memberindirect_user"} {
			if _, ok := g[attr]; ok {
				t.Fatalf("group_find without all returned %s", attr)
			}
		}
	}
}
