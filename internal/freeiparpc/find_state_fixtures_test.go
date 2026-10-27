package freeiparpc

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

// The fixtures below were captured from a real FreeIPA 4.13.4 (API 2.257)
// server through the SSH tunnel, in two sessions on 2026-10-27:
//
//   - first session, seven p1-* users: six under the default policy (no
//     password, admin reset, self-changed, disabled, two SSH keys, keys
//     cleared) and p1-self0, self-changed under maxlife=0; groups posix,
//     non-posix and a two-level chain;
//   - second session: p1-nokeys before and after clearing its only key,
//     p1-deep in a three-level group chain, and p1-reset0, admin reset
//     under maxlife=0.
//
// These tests pin what one *_find --all read does and does not carry, so the
// Phase 1 observer is built on observed facts. The fake server answers by
// method only (byMethod), so they do not prove which options a caller sends;
// the observer's own tests must lock all=true.
// docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md.

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

// stamp returns the FreeIPA timestamp of a datetime attribute, or "" when
// absent. Non-raw finds wrap it as {"__datetime__": ...}; raw finds return
// the bare string.
func stamp(t *testing.T, e map[string]any, attr string) string {
	t.Helper()
	vals, ok := e[attr].([]any)
	if !ok {
		return ""
	}
	if len(vals) != 1 {
		t.Fatalf("%s = %v", attr, vals)
	}
	switch v := vals[0].(type) {
	case map[string]any:
		return fmt.Sprint(v["__datetime__"])
	case string:
		return v
	}
	t.Fatalf("%s = %v is not a timestamp", attr, vals[0])
	return ""
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
	if got := strs(self, "krbextradata"); len(got) != 1 {
		t.Fatalf("a user with a password carries krbextradata: %v", got)
	}
}

// The playbook reads `ipa user-show --all --raw`; the observer may read the
// non-raw find. Both carry the same timestamps for every user.
func TestRawAndNonRawFindsCarryTheSameTimestamps(t *testing.T) {
	for _, pair := range [][2]string{
		{"user-find-states", "user-find-states-raw"},
		{"user-find-self0", "user-find-self0-raw"},
		{"user-find-reset0", "user-find-reset0-raw"},
	} {
		plain := findFixture(t, "user_find", pair[0], []any{"p1-"})
		raw := findFixture(t, "user_find", pair[1], []any{"p1-"})
		if len(plain) != len(raw) || len(plain) == 0 {
			t.Fatalf("%s/%s: %d vs %d users", pair[0], pair[1], len(plain), len(raw))
		}
		for _, p := range plain {
			name := strs(p, "uid")[0]
			r := entryByName(t, raw, "uid", name)
			for attr, rawAttr := range map[string]string{
				"krblastpwdchange":      "krbLastPwdChange",
				"krbpasswordexpiration": "krbPasswordExpiration",
			} {
				if a, b := stamp(t, p, attr), stamp(t, r, rawAttr); a != b {
					t.Fatalf("%s %s: non-raw %q, raw %q", name, attr, a, b)
				}
			}
		}
	}
}

// With maxlife=0 a self-changed password leaves no krbPasswordExpiration at
// all, while an admin reset still sets it to the moment of the reset. So the
// playbook's "expiration <= last change" test still recognises a reset.
func TestUserFindWithUnlimitedPasswordLife(t *testing.T) {
	for _, policy := range []string{"pwpolicy-show-global-maxlife0", "pwpolicy-show-reset0-maxlife0"} {
		var env struct {
			Result struct {
				Result struct {
					Max []string `json:"krbmaxpwdlife"`
				} `json:"result"`
			} `json:"result"`
		}
		if err := json.Unmarshal(loadFixture(t, policy).body, &env); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(env.Result.Result.Max, []string{"0"}) {
			t.Fatalf("%s: krbmaxpwdlife = %v, the capture was not taken under maxlife=0", policy, env.Result.Result.Max)
		}
	}
	self := findFixture(t, "user_find", "user-find-self0", []any{"p1-self0"})
	if len(self) != 1 {
		t.Fatalf("users = %d", len(self))
	}
	if stamp(t, self[0], "krblastpwdchange") == "" || stamp(t, self[0], "krbpasswordexpiration") != "" {
		t.Fatalf("maxlife=0 self-changed user: %v", self[0])
	}
	reset := findFixture(t, "user_find", "user-find-reset0", []any{"p1-reset0"})
	if len(reset) != 1 {
		t.Fatalf("users = %d", len(reset))
	}
	last, exp := stamp(t, reset[0], "krblastpwdchange"), stamp(t, reset[0], "krbpasswordexpiration")
	if last == "" || exp == "" || exp > last {
		t.Fatalf("maxlife=0 admin reset: last=%q expiration=%q, want expiration <= last change", last, exp)
	}
}

// The default-policy captures were taken under maxlife=90.
func TestDefaultPolicyCaptureCondition(t *testing.T) {
	var env struct {
		Result struct {
			Result struct {
				Max []string `json:"krbmaxpwdlife"`
			} `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(loadFixture(t, "pwpolicy-show-global").body, &env); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(env.Result.Result.Max, []string{"90"}) {
		t.Fatalf("krbmaxpwdlife = %v", env.Result.Result.Max)
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
	keys := entryByName(t, users, "uid", "p1-keys")
	if got := len(strs(keys, "ipasshpubkey")); got != 2 {
		t.Fatalf("p1-keys carries %d keys, want 2", got)
	}
	if got := len(strs(keys, "sshpubkeyfp")); got != 2 {
		t.Fatalf("p1-keys carries %d fingerprints, want 2", got)
	}
	if got := strs(keys, "memberof_group"); len(got) == 0 {
		t.Fatal("user_find --all carries memberof_group")
	}
	if got := strs(entryByName(t, users, "uid", "p1-nopw"), "mail"); !slices.Equal(got, []string{"p1-nopw@example.test", "p1-nopw-2@example.test"}) {
		t.Fatalf("mail = %v", got)
	}
}

// The same account (same ipauniqueid) before and after its only key was
// cleared: the attribute disappears; an empty list never comes back.
func TestClearingTheLastKeyRemovesTheAttribute(t *testing.T) {
	before := findFixture(t, "user_find", "user-find-nokeys-before", []any{"p1-nokeys"})
	after := findFixture(t, "user_find", "user-find-nokeys-after", []any{"p1-nokeys"})
	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("users = %d, %d", len(before), len(after))
	}
	if b, a := strs(before[0], "ipauniqueid"), strs(after[0], "ipauniqueid"); len(b) != 1 || !slices.Equal(a, b) {
		t.Fatalf("ipauniqueid before %v, after %v: not the same account", b, a)
	}
	if got := len(strs(before[0], "ipasshpubkey")); got != 1 {
		t.Fatalf("before clearing: %d keys, want 1", got)
	}
	for _, attr := range []string{"ipasshpubkey", "sshpubkeyfp"} {
		if _, ok := after[0][attr]; ok {
			t.Fatalf("after clearing the last key the user still carries %s", attr)
		}
	}
}

// pkey_only does not restrict a user_find to the login name.
func TestUserFindPkeyOnlyStillCarriesKeys(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states-pkey", []any{"p1-"})
	keys := entryByName(t, users, "uid", "p1-keys")
	if got := len(strs(keys, "ipasshpubkey")); got != 2 {
		t.Fatalf("pkey_only user_find returned %d keys for p1-keys, want 2", got)
	}
}

// Without all=true the entries carry neither password nor member fields.
// These fixtures were captured without all; the fake server does not check
// the options a caller sends.
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

// user_find's memberof_group is the transitive closure: p1-keys is listed in
// p1-parent although p1-parent's direct users do not include it. Direct
// membership can only be read from group_find's member_user/member_group.
func TestUserFindMemberOfIsTransitive(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states", []any{"p1-"})
	groups := findFixture(t, "group_find", "group-find-states", []any{"p1-"})
	if !slices.Contains(strs(entryByName(t, users, "uid", "p1-keys"), "memberof_group"), "p1-parent") {
		t.Fatal("p1-keys' user_find memberof_group does not list p1-parent")
	}
	if slices.Contains(strs(entryByName(t, groups, "cn", "p1-parent"), "member_user"), "p1-keys") {
		t.Fatal("p1-keys is a direct member of p1-parent in this capture")
	}
}

// Three levels: p1-top > p1-mid > p1-leaf > user p1-deep. user_find lists
// every level in memberof_group; user_show splits direct (memberof_group)
// from indirect (memberofindirect_group); group_find splits members the same
// way on every level.
func TestNestedMembershipThreeLevels(t *testing.T) {
	deep := findFixture(t, "user_find", "user-find-nested", []any{"p1-deep"})
	if len(deep) != 1 {
		t.Fatalf("users = %d", len(deep))
	}
	got := strs(deep[0], "memberof_group")
	slices.Sort(got)
	if !slices.Equal(got, []string{"ipausers", "p1-leaf", "p1-mid", "p1-top"}) {
		t.Fatalf("user_find memberof_group = %v, want every level", got)
	}

	_, c := loggedIn(t, map[string]string{"user_show": "user-show-nested"})
	raw, err := c.Call(context.Background(), Command{Method: "user_show", Args: []any{"p1-deep"}, Options: map[string]any{"all": true}})
	if err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &shown); err != nil {
		t.Fatal(err)
	}
	direct, indirect := strs(shown.Result, "memberof_group"), strs(shown.Result, "memberofindirect_group")
	slices.Sort(direct)
	slices.Sort(indirect)
	if !slices.Equal(direct, []string{"ipausers", "p1-leaf"}) || !slices.Equal(indirect, []string{"p1-mid", "p1-top"}) {
		t.Fatalf("user_show memberof_group = %v, memberofindirect_group = %v", direct, indirect)
	}

	groups := findFixture(t, "group_find", "group-find-nested", []any{"p1-"})
	top := entryByName(t, groups, "cn", "p1-top")
	for attr, want := range map[string][]string{
		"member_group":         {"p1-mid"},
		"memberindirect_group": {"p1-leaf"},
		"memberindirect_user":  {"p1-deep"},
	} {
		if got := strs(top, attr); !slices.Equal(got, want) {
			t.Fatalf("p1-top %s = %v, want %v", attr, got, want)
		}
	}
	if _, ok := top["member_user"]; ok {
		t.Fatal("p1-top has no direct users")
	}
	leaf := entryByName(t, groups, "cn", "p1-leaf")
	if got := strs(leaf, "member_user"); !slices.Equal(got, []string{"p1-deep"}) {
		t.Fatalf("p1-leaf member_user = %v", got)
	}
}

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
