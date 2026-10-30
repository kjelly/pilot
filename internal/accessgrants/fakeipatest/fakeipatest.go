// Package fakeipatest is the test harness that lets the REAL drift probe
// playbook and the REAL users/groups observer run under real ansible-playbook
// without a FreeIPA server: a fake `ipalib` (and a model of FreeIPA's
// `ipapython.ssh`) on PYTHONPATH serve recorded FreeIPA replies, and fake
// `kinit`/`ipa` binaries stand in for the Kerberos tools. Only tests import it.
//
// What is real: ansible-playbook, the probe and shared normalization tasks,
// the observer program, Go's drift computation and the CLI. What is fake: the
// FreeIPA API, whose replies are the captured 4.13.4 fixtures in
// internal/freeiparpc/testdata (with each mutation spelled out by the test),
// and Kerberos (the fake client only checks that the private cache holds the
// word "ticket", which the fake kinit writes). Every reply it serves is a
// capture, none is constructed: user_find/group_find from the 2026-10-27
// sessions, config_show and the preserved-users search (user-find-no-match,
// user-find-preserved-one) from a live vm-target on 2026-10-31. See
// python/README.txt.
package fakeipatest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Failure makes one fake FreeIPA call raise an exception of class Error from
// the fake ipalib.errors with message Text. Where is "connect", "user_find",
// "preserved_find", "group_find" or "config_show".
type Failure struct {
	Where string `json:"where"`
	Error string `json:"error"`
	Text  string `json:"text"`
}

// Scenario is what the fake FreeIPA serves.
type Scenario struct {
	UserFind map[string]any `json:"user_find"`
	// PreservedFind answers the search for preserved users (user_find with
	// preserved=True, pkey_only=True).
	PreservedFind map[string]any `json:"preserved_find"`
	GroupFind     map[string]any `json:"group_find"`
	// ConfigShow answers config_show (the default e-mail domain).
	ConfigShow map[string]any `json:"config_show"`
	Fail       *Failure       `json:"fail,omitempty"`
}

// Env is an installed scenario.
type Env struct {
	// KinitStdin is the file the fake kinit wrote its stdin to (the password).
	KinitStdin string
	// ConnectLog has one line per attempt to connect to the fake FreeIPA.
	ConnectLog string
}

// Connects is how many times the observer reached for FreeIPA.
func (e Env) Connects(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile(e.ConnectLog)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(raw), "connect\n")
}

func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the fakeipatest package")
	}
	return filepath.Dir(file)
}

// Capture returns the `result` object of a captured FreeIPA JSON-RPC reply
// (internal/freeiparpc/testdata/<name>.json): what ipalib's Command returns.
func Capture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(packageDir(t), "..", "..", "freeiparpc", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Result == nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return doc.Result
}

// Install writes the scenario, puts the fake ipalib on PYTHONPATH and fake
// kinit/ipa first on PATH for the rest of the test.
func (s Scenario) Install(t *testing.T) Env {
	t.Helper()
	dir := t.TempDir()
	scenario := filepath.Join(dir, "scenario.json")
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scenario, body, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	e := Env{KinitStdin: filepath.Join(dir, "kinit-stdin"), ConnectLog: filepath.Join(dir, "connects")}
	// kinit: record the password and put a ticket in the cache KRB5CCNAME names.
	// A KRB5CCNAME that is not a writable FILE: path fails, as a real kinit
	// would without a private cache.
	kinit := "#!/bin/sh\ncat > \"" + e.KinitStdin + "\"\necho ticket > \"${KRB5CCNAME#FILE:}\"\n"
	for name, script := range map[string]string{"kinit": kinit, "ipa": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PYTHONPATH", filepath.Join(packageDir(t), "python"))
	t.Setenv("PILOT_FAKE_IPA_SCENARIO", scenario)
	t.Setenv("PILOT_FAKE_IPA_LOG", e.ConnectLog)
	return e
}

// RosterInitialSentinel is the initial password the fixture roster gives user
// p1-new; no report, error or output may carry it.
const RosterInitialSentinel = "Pr204RosterInitialSentinel-77"

// Roster is a canonical roster over the captured users and groups. p1KeysValues
// are the roster's ssh_keys for user p1-keys, spliced in as written. Users
// p1-nopw and p1-self and group team-p1-nonposix are deliberately not in it (the
// first two are members of captured group team-p1 that the roster does not
// list). The
// admin password here is a short placeholder: probes get the real one from a
// vault vars file. YAML-1.1 booleans are quoted ("Off" is a surname).
func Roster(t *testing.T, p1KeysValues []string) string {
	t.Helper()
	quoted := make([]string, len(p1KeysValues))
	for i, k := range p1KeysValues {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		quoted[i] = string(b)
	}
	return fmt.Sprintf(`
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: p1-keys
    first: P1
    last: Keys
    login_shell: /bin/sh
    ssh_keys: {authoritative: true, values: [%[1]s]}
  - name: p1-nokeys
    first: P1
    last: NoKeys
    login_shell: /bin/sh
    ssh_keys: {authoritative: true, values: []}
  - name: p1-off
    first: P1
    last: "Off"
    login_shell: /bin/sh
  - name: p1-reset
    state: absent
  - name: p1-new
    login_shell: /bin/sh
    password: {initial: %[2]s}
groups:
  - name: team-p1
    category: team
    description: P1 team
    membership: {authoritative: true, users: [p1-keys, p1-nokeys], groups: []}
  - name: team-p1-parent
    category: team
    description: P1 parent
    membership: {authoritative: true, users: [p1-off], groups: [team-p1]}
  - name: team-p1-new
    category: team
hosts: []
hostgroups: []
hbac:
  rules: []
sudo:
  rules: []
grants: []
`, strings.Join(quoted, ", "), RosterInitialSentinel)
}

// CapturedKeys returns the two SSH keys FreeIPA 4.13.4 stored for captured
// user p1-keys (the keys are public).
func CapturedKeys(t *testing.T) []string {
	t.Helper()
	result := Capture(t, "user-find-states")["result"].([]any)
	var keys []string
	for _, k := range result[0].(map[string]any)["ipasshpubkey"].([]any) {
		keys = append(keys, k.(string))
	}
	if len(keys) != 2 {
		t.Fatalf("fixture changed: %d keys", len(keys))
	}
	return keys
}

// Captured is the captured state: six users and three groups. The groups are
// renamed (p1-team to team-p1, p1-parent to team-p1-parent, p1-nonposix to
// team-p1-nonposix, in cn, member_group and memberof_group) because the roster
// validator requires the name prefix of a group's category; nothing else in the
// captured replies is changed.
func Captured(t *testing.T) Scenario {
	t.Helper()
	rename := map[string]string{"p1-team": "team-p1", "p1-parent": "team-p1-parent", "p1-nonposix": "team-p1-nonposix"}
	mapped := func(entry map[string]any, field string) {
		list, ok := entry[field].([]any)
		for i := range list {
			if to, found := rename[list[i].(string)]; ok && found {
				list[i] = to
			}
		}
	}
	s := Scenario{UserFind: Capture(t, "user-find-states"), GroupFind: Capture(t, "group-find-states"),
		PreservedFind: PreservedUsers(t), ConfigShow: Capture(t, "config-show")}
	for _, e := range s.UserFind["result"].([]any) {
		mapped(e.(map[string]any), "memberof_group")
	}
	for _, e := range s.GroupFind["result"].([]any) {
		for _, field := range []string{"cn", "member_group", "memberof_group"} {
			mapped(e.(map[string]any), field)
		}
	}
	return s
}

// LiveUser returns the mutable entry of a live user in s.
func LiveUser(t *testing.T, s Scenario, uid string) map[string]any {
	t.Helper()
	for _, e := range s.UserFind["result"].([]any) {
		if entry := e.(map[string]any); entry["uid"].([]any)[0] == uid {
			return entry
		}
	}
	t.Fatalf("no captured user %s", uid)
	return nil
}

// Converged is the state after an apply of Roster(t, [optioned key]): live
// equals the roster (including the option-prefixed key FreeIPA stores for
// p1-keys). keepUnexpected leaves the objects the roster does not name
// (users p1-nopw and p1-self, group team-p1-nonposix) in place, the one thing apply
// never removes. It returns the live scenario and the matching roster.
func Converged(t *testing.T, keepUnexpected bool) (Scenario, string) {
	t.Helper()
	keys := CapturedKeys(t)
	optioned := `from="10.0.0.0/8" ` + keys[0]
	s := Captured(t)
	LiveUser(t, s, "p1-keys")["ipasshpubkey"] = []any{optioned}
	LiveUser(t, s, "p1-off")["nsaccountlock"] = false
	var users []any
	for _, e := range s.UserFind["result"].([]any) {
		switch e.(map[string]any)["uid"].([]any)[0] {
		case "p1-reset":
			continue
		case "p1-nopw", "p1-self":
			if !keepUnexpected {
				continue
			}
		}
		users = append(users, e)
	}
	users = append(users, map[string]any{"uid": []any{"p1-new"}, "givenname": []any{"p1-new"}, "sn": []any{"p1-new"},
		"homedirectory": []any{"/home/p1-new"}, "loginshell": []any{"/bin/sh"}, "nsaccountlock": false})
	s.UserFind["result"], s.UserFind["count"] = users, len(users)
	var groups []any
	for _, e := range s.GroupFind["result"].([]any) {
		g := e.(map[string]any)
		switch g["cn"].([]any)[0] {
		case "team-p1-nonposix":
			if !keepUnexpected {
				continue
			}
		case "team-p1":
			g["member_user"] = []any{"p1-keys", "p1-nokeys"}
		}
		groups = append(groups, g)
	}
	groups = append(groups, map[string]any{"cn": []any{"team-p1-new"}, "description": []any{"team-p1-new"}})
	s.GroupFind["result"], s.GroupFind["count"] = groups, len(groups)

	roster := strings.Replace(Roster(t, []string{optioned}), "  - name: p1-reset\n    state: absent\n", "", 1)
	roster = strings.Replace(roster, "name: p1-new\n", "name: p1-new\n    first: p1-new\n    last: p1-new\n", 1)
	return s, roster
}

// PreservedUsers is the reply to the search for preserved users (user_find with
// preserved=True, pkey_only=True) for the given logins. Nothing in it is
// constructed. With no login it is the captured user-find-no-match reply, which
// is byte-identical to what FreeIPA 4.13.4 answered to this search on a realm
// with no preserved user (live capture, 2026-10-31). Otherwise it is the
// captured user-find-preserved-one reply (a real `user-del --preserve`d user,
// its DN under cn=deleted users,cn=accounts,cn=provisioning) with its login
// replaced by each of the given ones: the same entry shape, once per login, and
// count following. A single login keeps the captured summary ("1 user matched");
// another count uses the plural FreeIPA printed in the user-find-states and
// user-find-no-match captures ("N users matched").
func PreservedUsers(t *testing.T, uids ...string) map[string]any {
	t.Helper()
	if len(uids) == 0 {
		return Capture(t, "user-find-no-match")
	}
	reply := Capture(t, "user-find-preserved-one")
	captured, ok := reply["result"].([]any)
	if !ok || len(captured) != 1 {
		t.Fatalf("fixture user-find-preserved-one changed: %v", reply["result"])
	}
	template := captured[0].(map[string]any)
	const capturedLogin = "pv-capture"
	dn, _ := template["dn"].(string)
	if !strings.HasPrefix(dn, "uid="+capturedLogin+",cn=deleted users,cn=accounts,cn=provisioning,") {
		t.Fatalf("fixture user-find-preserved-one changed: dn %q", dn)
	}
	entries := make([]any, 0, len(uids))
	for _, uid := range uids {
		entry := map[string]any{}
		for field, value := range template {
			entry[field] = value
		}
		entry["uid"] = []any{uid}
		entry["dn"] = "uid=" + uid + strings.TrimPrefix(dn, "uid="+capturedLogin)
		entries = append(entries, entry)
	}
	reply["result"], reply["count"] = entries, len(entries)
	if len(uids) != 1 {
		reply["summary"] = fmt.Sprintf("%d users matched", len(uids))
	}
	return reply
}
