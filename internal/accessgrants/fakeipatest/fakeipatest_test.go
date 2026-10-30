package fakeipatest

import (
	"encoding/json"
	"reflect"
	"testing"
)

// sameJSON compares what the fake would serve: the scenario file is JSON, so
// a Go int count and a decoded float64 count are the same reply.
func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	return string(x) == string(y)
}

// The replies the fake serves for config_show and the preserved-users search
// are captures of FreeIPA 4.13.4 taken on a live vm-target (2026-10-31). These
// tests pin the facts the observer relies on, so a re-capture that changes them
// is noticed here rather than in a live run.

func TestCapturedConfigShowIsWhatFreeIPAAnswers(t *testing.T) {
	reply := Capture(t, "config-show")
	if reply["value"] != nil || reply["summary"] != nil {
		t.Fatalf("config_show value/summary = %v / %v, FreeIPA answers null for both", reply["value"], reply["summary"])
	}
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("config_show result = %T", reply["result"])
	}
	// FreeIPA reads config["ipadefaultemaildomain"][0]: a one-element list.
	if got := result["ipadefaultemaildomain"]; !reflect.DeepEqual(got, []any{"ipa.pilot.internal"}) {
		t.Fatalf("ipadefaultemaildomain = %#v", got)
	}
	// The real reply carries the whole configuration, not only the domain; an
	// observer that read anything else from it would not notice a fixture that
	// holds only the domain, so the fixture must be the full reply.
	if len(result) < 20 {
		t.Fatalf("config_show result has %d attributes; the capture has 24", len(result))
	}
	if !sameJSON(t, Captured(t).ConfigShow, reply) {
		t.Fatal("the captured scenario does not serve the captured config_show reply")
	}
}

func TestPreservedUsersAreTheCapturedReplies(t *testing.T) {
	none := Capture(t, "user-find-no-match")
	if got := PreservedUsers(t); !sameJSON(t, got, none) {
		t.Fatalf("no preserved user: %#v, want the captured user-find-no-match reply", got)
	}
	if !sameJSON(t, Captured(t).PreservedFind, none) {
		t.Fatal("the captured scenario has no preserved users, as the live realm answered")
	}

	one := Capture(t, "user-find-preserved-one")
	if got := PreservedUsers(t, "pv-capture"); !sameJSON(t, got, one) {
		t.Fatalf("the captured login: %#v, want the captured reply %#v", got, one)
	}

	// Other logins: the captured entry with the login replaced, count following.
	got := PreservedUsers(t, "p1-a", "p1-b")
	entries, _ := got["result"].([]any)
	if len(entries) != 2 || got["count"] != 2 || got["truncated"] != false || got["summary"] != "2 users matched" {
		t.Fatalf("two logins: %#v", got)
	}
	for i, uid := range []string{"p1-a", "p1-b"} {
		want := map[string]any{"uid": []any{uid},
			"dn": "uid=" + uid + ",cn=deleted users,cn=accounts,cn=provisioning,dc=ipa,dc=pilot,dc=internal"}
		if !reflect.DeepEqual(entries[i], want) {
			t.Fatalf("entry %d = %#v, want %#v", i, entries[i], want)
		}
	}
	// A result is a fresh copy: changing it must not change the next one.
	got["truncated"] = true
	if PreservedUsers(t, "p1-a")["truncated"] != false {
		t.Fatal("PreservedUsers shares state between calls")
	}
}
