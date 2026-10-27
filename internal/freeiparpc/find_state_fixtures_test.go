package freeiparpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
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
// the observer's own tests must lock all=true. The plan's Phase 1 "find 讀取
// 契約" table lists each fact with the test that pins it, in
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

// stampFormat is the generalized-time form FreeIPA returns; string
// comparison orders it correctly, which the playbook's password decision
// relies on.
var stampFormat = regexp.MustCompile(`^[0-9]{14}Z$`)

// stamp returns the FreeIPA timestamp of a datetime attribute, or "" when
// absent. Non-raw finds wrap it as {"__datetime__": ...}; raw finds return
// the bare string. Either way it must be YYYYMMDDHHMMSSZ.
func stamp(t *testing.T, e map[string]any, attr string) string {
	t.Helper()
	vals, ok := e[attr].([]any)
	if !ok {
		return ""
	}
	if len(vals) != 1 {
		t.Fatalf("%s = %v", attr, vals)
	}
	var s string
	switch v := vals[0].(type) {
	case map[string]any:
		s = fmt.Sprint(v["__datetime__"])
	case string:
		s = v
	default:
		t.Fatalf("%s = %v is not a timestamp", attr, vals[0])
	}
	if !stampFormat.MatchString(s) {
		t.Fatalf("%s = %q is not YYYYMMDDHHMMSSZ", attr, s)
	}
	return s
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
// carries both.
func TestUserFindCarriesThePasswordState(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states", []any{"p1-"})
	if len(users) != 6 {
		t.Fatalf("users = %d, want 6", len(users))
	}
	nopw := entryByName(t, users, "uid", "p1-nopw")
	if stamp(t, nopw, "krblastpwdchange") != "" || stamp(t, nopw, "krbpasswordexpiration") != "" {
		t.Fatalf("a user with no password must carry neither timestamp: %v", nopw)
	}
	// An admin reset sets the expiration to the moment of the reset.
	reset := entryByName(t, users, "uid", "p1-reset")
	last, exp := stamp(t, reset, "krblastpwdchange"), stamp(t, reset, "krbpasswordexpiration")
	if last == "" || exp != last {
		t.Fatalf("admin-reset: last=%q expiration=%q, want both set and equal (still on the reset password)", last, exp)
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
	if last == "" || exp != last {
		t.Fatalf("maxlife=0 admin reset: last=%q expiration=%q, want both set and equal", last, exp)
	}
}

// has_keytab, has_password and memberofindirect_group are computed by
// user_show only; no user_find capture carries them, with or without all,
// raw or pkey_only.
func TestComputedUserFieldsComeOnlyFromUserShow(t *testing.T) {
	computed := []string{"has_keytab", "has_password", "memberofindirect_group"}
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
	for _, attr := range computed {
		if _, ok := shown.Result[attr]; !ok {
			t.Fatalf("user_show --all did not return %s", attr)
		}
	}
	for _, fixture := range []string{
		"user-find-states", "user-find-states-raw", "user-find-states-noall", "user-find-states-pkey",
		"user-find-self0", "user-find-self0-raw", "user-find-reset0", "user-find-reset0-raw",
		"user-find-nokeys-before", "user-find-nokeys-after", "user-find-nested",
	} {
		for _, u := range findFixture(t, "user_find", fixture, []any{"p1-"}) {
			for _, attr := range computed {
				if _, ok := u[attr]; ok {
					t.Fatalf("%s returned %s, which only user_show does: re-capture and revisit the observer", fixture, attr)
				}
			}
		}
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
	if got := len(strs(before[0], "sshpubkeyfp")); got != 1 {
		t.Fatalf("before clearing: %d fingerprints, want 1", got)
	}
	for _, attr := range []string{"ipasshpubkey", "sshpubkeyfp"} {
		if _, ok := after[0][attr]; ok {
			t.Fatalf("after clearing the last key the user still carries %s", attr)
		}
	}
}

// pkey_only does not restrict a user_find to the login name: it still
// returns the keys, encoded as {"__base64__": ...} of the same OpenSSH line
// that --all returns as a plain string.
func TestUserFindPkeyOnlyStillCarriesKeys(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-states-pkey", []any{"p1-"})
	vals, _ := entryByName(t, users, "uid", "p1-keys")["ipasshpubkey"].([]any)
	if len(vals) != 2 {
		t.Fatalf("pkey_only user_find returned %d keys for p1-keys, want 2", len(vals))
	}
	var decoded []string
	for _, v := range vals {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("pkey_only key = %v, want {\"__base64__\": ...}", v)
		}
		b, err := base64.StdEncoding.DecodeString(fmt.Sprint(m["__base64__"]))
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, string(b))
	}
	plain := strs(entryByName(t, findFixture(t, "user_find", "user-find-states", []any{"p1-"}), "uid", "p1-keys"), "ipasshpubkey")
	slices.Sort(decoded)
	slices.Sort(plain)
	if !slices.Equal(decoded, plain) {
		t.Fatalf("pkey_only keys decode to %v, --all keys are %v", decoded, plain)
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
	if len(users) == 0 {
		t.Fatal("no users")
	}
	for _, u := range users {
		for _, attr := range []string{"krblastpwdchange", "krbpasswordexpiration", "krbextradata", "memberof_group"} {
			if _, ok := u[attr]; ok {
				t.Fatalf("user_find without all returned %s", attr)
			}
		}
		// The principal names are still there: "no krb fields" would be wrong.
		for _, attr := range []string{"krbprincipalname", "krbcanonicalname"} {
			if _, ok := u[attr]; !ok {
				t.Fatalf("user_find without all did not return %s", attr)
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

	// group_find splits members and memberof into direct and indirect on
	// every level. An attribute missing here means the capture had none.
	groups := findFixture(t, "group_find", "group-find-nested", []any{"p1-"})
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	attrs := []string{"member_user", "member_group", "memberindirect_user", "memberindirect_group", "memberof_group", "memberofindirect_group"}
	for cn, want := range map[string]map[string][]string{
		"p1-top": {
			"member_group":         {"p1-mid"},
			"memberindirect_group": {"p1-leaf"},
			"memberindirect_user":  {"p1-deep"},
		},
		"p1-mid": {
			"member_group":        {"p1-leaf"},
			"memberindirect_user": {"p1-deep"},
			"memberof_group":      {"p1-top"},
		},
		"p1-leaf": {
			"member_user":            {"p1-deep"},
			"memberof_group":         {"p1-mid"},
			"memberofindirect_group": {"p1-top"},
		},
	} {
		g := entryByName(t, groups, "cn", cn)
		for _, attr := range attrs {
			got := strs(g, attr)
			if _, present := g[attr]; present != (want[attr] != nil) || !slices.Equal(got, want[attr]) {
				t.Fatalf("%s %s = %v (present %v), want %v", cn, attr, got, present, want[attr])
			}
		}
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
	if _, ok := parent["memberindirect_group"]; ok {
		t.Fatal("p1-team has no subgroup, so p1-parent carries no memberindirect_group")
	}
	team := entryByName(t, groups, "cn", "p1-team")
	if got := strs(team, "memberof_group"); !slices.Equal(got, []string{"p1-parent"}) {
		t.Fatalf("p1-team memberof_group = %v", got)
	}
	// No subgroup below p1-team or p1-nonposix: no indirect members at all.
	for _, cn := range []string{"p1-team", "p1-nonposix"} {
		for _, attr := range []string{"memberindirect_user", "memberindirect_group"} {
			if _, ok := entryByName(t, groups, "cn", cn)[attr]; ok {
				t.Fatalf("%s has no nested group, so it carries no %s", cn, attr)
			}
		}
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
	if len(groups) == 0 {
		t.Fatal("no groups")
	}
	for _, g := range groups {
		for _, attr := range []string{"member_user", "member_group", "memberindirect_user", "memberindirect_group", "memberof_group", "memberofindirect_group"} {
			if _, ok := g[attr]; ok {
				t.Fatalf("group_find without all returned %s", attr)
			}
		}
	}
}
