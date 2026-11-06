package freeiparpc

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// The fixtures below were captured from the same FreeIPA 4.13.4 (API 2.257)
// server on 2026-11-05 for the Phase 1 spec §9 (K1–K4), as admin through the
// SSH tunnel:
//
//   - K1: p1-pres deleted with preserve: true next to an active p1-live;
//     the server already held another preserved user, pwi-pres;
//   - K2: p1-ext, created with external: true;
//   - K3: with more users and groups than each limit, the read under
//     FreeIPA's ipasearchrecordslimit=10, then 389-ds nsslapd-sizelimit=3,
//     then nsslapd-lookthroughlimit=3, one at a time, each restored after;
//   - K4: the unfiltered user_find --all before any p1-* object existed.

func names(entries []map[string]any, key string) []string {
	var out []string
	for _, e := range entries {
		if v, _ := e[key].([]any); len(v) == 1 {
			out = append(out, v[0].(string))
		}
	}
	return out
}

// K1: a plain user_find never lists a preserved user, and preserved: true
// lists only preserved users, each with preserved: true. A reader therefore
// needs both reads to see every user (spec §6.2).
func TestPreservedUsersNeedTheirOwnRead(t *testing.T) {
	plain := findFixture(t, "user_find", "user-find-k1-default", []any{"p1-"})
	if got := names(plain, "uid"); !slices.Equal(got, []string{"p1-live"}) {
		t.Fatalf("plain read lists %v, want only the active p1-live", got)
	}
	for _, e := range plain {
		if e["preserved"] != false {
			t.Fatalf("%v: preserved = %v in a plain read", e["uid"], e["preserved"])
		}
	}
	for _, fixture := range []string{"user-find-k1-preserved", "user-find-k1-preserved-all"} {
		preserved := findFixture(t, "user_find", fixture, nil)
		got := names(preserved, "uid")
		if !slices.Contains(got, "p1-pres") || slices.Contains(got, "p1-live") || slices.Contains(got, "admin") {
			t.Fatalf("%s lists %v, want preserved users only", fixture, got)
		}
		for _, e := range preserved {
			if e["preserved"] != true {
				t.Fatalf("%s: %v has preserved = %v", fixture, e["uid"], e["preserved"])
			}
		}
	}
	p := entryByName(t, findFixture(t, "user_find", "user-find-k1-preserved", nil), "uid", "p1-pres")
	if lock, _ := p["nsaccountlock"].(bool); !lock {
		t.Fatalf("a preserved user is locked: nsaccountlock = %v", p["nsaccountlock"])
	}
	if _, ok := p["memberof_group"]; ok {
		t.Fatal("preserving a user removes its group memberships; memberof_group should be absent")
	}
}

// K2: an external group is the non-posix class set plus ipaexternalgroup
// and carries no member attributes.
func TestExternalGroupClasses(t *testing.T) {
	e := entryByName(t, findFixture(t, "group_find", "group-find-k2-external", nil), "cn", "p1-ext")
	var classes []string
	for _, c := range e["objectclass"].([]any) {
		classes = append(classes, c.(string))
	}
	slices.Sort(classes)
	want := []string{"groupofnames", "ipaexternalgroup", "ipaobject", "ipausergroup", "nestedgroup", "top"}
	if !slices.Equal(classes, want) {
		t.Fatalf("objectclass = %v, want %v", classes, want)
	}
	for _, attr := range []string{"gidnumber", "member_user", "member_group"} {
		if _, ok := e[attr]; ok {
			t.Fatalf("an empty external group has %s", attr)
		}
	}
}

// K3: sizelimit=0 overrides FreeIPA's own search limit, and the 389-ds
// limits never shorten a read silently: a user_find comes back truncated,
// a group_find fails. Find turns both into errors, so the observer never
// plans from a partial read.
func TestServerLimitsNeverShortenAReadSilently(t *testing.T) {
	// FreeIPA's ipasearchrecordslimit=10: without sizelimit the answer stops
	// at 10 and says so; with sizelimit=0 it is complete.
	_, c := loggedIn(t, map[string]string{"user_find": "k3-records10-nosizelimit-users"})
	if _, err := c.Find(context.Background(), "user_find", nil, map[string]any{"all": true}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("records limit without sizelimit: err = %v, want ErrTruncated", err)
	}
	groups := findFixture(t, "group_find", "k3-records10-sizelimit0-groups", nil)
	if len(groups) <= 10 {
		t.Fatalf("sizelimit=0 under ipasearchrecordslimit=10 returned %d groups", len(groups))
	}
	for _, tc := range []struct {
		fixture, method string
		want            func(error) bool
	}{
		{"k3-dssize3-sizelimit0-users", "user_find", func(err error) bool { return errors.Is(err, ErrTruncated) }},
		{"k3-dslook3-sizelimit0-users", "user_find", func(err error) bool { return errors.Is(err, ErrTruncated) }},
		{"k3-dssize3-sizelimit0-groups", "group_find", func(err error) bool { return IsRPC(err, "SizeLimitExceeded") }},
		{"k3-dslook3-sizelimit0-groups", "group_find", func(err error) bool { return IsRPC(err, "AdminLimitExceeded") }},
	} {
		_, c := loggedIn(t, map[string]string{tc.method: tc.fixture})
		entries, err := c.Find(context.Background(), tc.method, nil, map[string]any{"all": true})
		if !tc.want(err) || entries != nil {
			t.Errorf("%s: entries %d, err = %v", tc.fixture, len(entries), err)
		}
	}
}

// K4: the unfiltered read lists admin as a member of admins, which is how
// the observer checks its reader (D7).
func TestUnfilteredReadShowsTheAdminsMember(t *testing.T) {
	users := findFixture(t, "user_find", "user-find-all-k4", nil)
	if len(users) < 100 {
		t.Fatalf("the unfiltered read returned %d users", len(users))
	}
	admin := entryByName(t, users, "uid", "admin")
	groups, _ := admin["memberof_group"].([]any)
	if !slices.Contains(groups, any("admins")) {
		t.Fatalf("admin memberof_group = %v", admin["memberof_group"])
	}
	if _, ok := admin["givenname"]; ok {
		t.Fatal("the captured admin has no givenname; update the observer's expectations if FreeIPA now sets one")
	}
}
