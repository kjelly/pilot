package accessgrants

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessgrants/fakeipatest"
	"go.yaml.in/yaml/v3"
)

// This file drives the production drift probe (playbooks/check/freeipa-access-
// drift-probe.yml) with pilot_drift_identity_objects=true under REAL
// ansible-playbook, the real users/groups observer program and the real shared
// normalization, against the fake FreeIPA client in fakeipatest (captured
// FreeIPA 4.13.4 replies; see that package for what is real and what is fake).
// `make identity-secret-test` runs it with PILOT_REQUIRE_CONTAINER_TESTS=1, so a
// missing ansible fails instead of skipping.

const (
	objectsVaultSentinel  = "Pr204VaultAdminSentinel-91"
	objectsRosterSentinel = fakeipatest.RosterInitialSentinel
	objectsLeakSentinel   = "Pr204ExceptionTextSentinel-55"
)

var (
	objectsRoster    = fakeipatest.Roster
	capturedKeys     = fakeipatest.CapturedKeys
	capturedScenario = fakeipatest.Captured
	liveUser         = fakeipatest.LiveUser
)

type objectsEnv struct {
	dir, inventory, roster, vault string
	ipa                           fakeipatest.Env
}

func newObjectsEnv(t *testing.T, roster string, scenario fakeipatest.Scenario, hosts ...string) objectsEnv {
	t.Helper()
	requireRealAnsible(t)
	if len(hosts) == 0 {
		hosts = []string{"ipa1"}
	}
	dir := t.TempDir()
	e := objectsEnv{dir: dir, inventory: filepath.Join(dir, "inventory.yml"), roster: filepath.Join(dir, "roster.yaml"),
		vault: filepath.Join(dir, "main.yaml"), ipa: scenario.Install(t)}
	inventory := "all:\n  children:\n    freeipa-server:\n      hosts:\n"
	for _, h := range hosts {
		inventory += "        " + h + ":\n          ansible_connection: local\n"
	}
	for path, body := range map[string]string{
		e.inventory: inventory, e.roster: roster, e.vault: "ipa_admin_password: " + objectsVaultSentinel + "\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e objectsEnv) opts(t *testing.T, objects bool) DriftProbeOptions {
	t.Helper()
	pb, err := filepath.Abs(realProbePlaybook)
	if err != nil {
		t.Fatal(err)
	}
	return DriftProbeOptions{
		IncludeIdentityObjects: objects, RosterFile: e.roster, Inventory: e.inventory, Playbook: pb,
		VarsFile: e.vault, Now: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
	}
}

// itemKeys renders a report as sorted "category:name:action[:detail]" lines.
func itemKeys(report DriftReport, withDetail bool) []string {
	var keys []string
	for _, item := range report.Items {
		key := item.Category + ":" + item.Name + ":" + item.Action
		if withDetail {
			key += ":" + item.Detail
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func assertNoSentinel(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{objectsVaultSentinel, objectsRosterSentinel, objectsLeakSentinel} {
		if strings.Contains(text, s) {
			t.Errorf("%s leaked %q:\n%s", what, s, text)
		}
	}
}

// TestRegression_IdentitySecretDriftProbeUsersGroupsFromCapturedFixtures is the
// end-to-end proof that the opt-in observer reports what apply would do, with a
// perturbed state built from captured FreeIPA replies, and that neither the
// roster's initial password nor the vault's admin password reaches a report.
func TestRegression_IdentitySecretDriftProbeUsersGroupsFromCapturedFixtures(t *testing.T) {
	keys := capturedKeys(t)
	env := newObjectsEnv(t, objectsRoster(t, keys[:1]), capturedScenario(t))

	report, err := DriftOnce(context.Background(), env.opts(t, true))
	if err != nil {
		t.Fatalf("drift failed: %v", err)
	}
	want := []string{
		"group_member_extra:team-p1:remove_member:user:p1-nopw",
		"group_member_extra:team-p1:remove_member:user:p1-self",
		"group_member_missing:team-p1:add_member:user:p1-nokeys",
		"group_missing:team-p1-new:create:managed object does not exist live",
		"group_unexpected:team-p1-nonposix:report:object outside the roster; apply will not delete it",
		"user_enabled:p1-off:update:account enabled state differs",
		"user_missing:p1-new:create:managed object does not exist live",
		"user_should_be_absent:p1-reset:delete:explicitly absent managed object exists live",
		"user_ssh_keys:p1-keys:update:SSH public key set differs (desired=1, live=2)",
		"user_unexpected:p1-nopw:report:object outside the roster; apply will not delete it",
		"user_unexpected:p1-self:report:object outside the roster; apply will not delete it",
	}
	if got := itemKeys(report, true); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("drift items:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rendered, _ := json.Marshal(report)
	assertNoSentinel(t, "the drift report", string(rendered))
	for _, material := range []string{"ssh-ed25519", "AAAAC3NzaC1", "SHA256:"} {
		if strings.Contains(string(rendered), material) {
			t.Errorf("the report carries key material %q: %s", material, rendered)
		}
	}
	if got, err := os.ReadFile(env.ipa.KinitStdin); err != nil || strings.TrimSpace(string(got)) != objectsVaultSentinel {
		t.Errorf("kinit stdin = %q (%v), want the vault admin password", got, err)
	}

	// Control: without the flag the observer does not run and nothing is reported
	// about users or groups (the staged scope is opt-in).
	plain, err := DriftOnce(context.Background(), env.opts(t, false))
	if err != nil {
		t.Fatalf("drift without the flag failed: %v", err)
	}
	if len(plain.Items) != 0 {
		t.Fatalf("users/groups reported without --include-users-groups: %v", itemKeys(plain, false))
	}
}

// TestRegression_IdentitySecretDriftProbeUsersGroupsConverged is the "after
// apply" state: live equals the roster, including an option-prefixed key,
// and the report is empty.
func TestRegression_IdentitySecretDriftProbeUsersGroupsConverged(t *testing.T) {
	scenario, roster := fakeipatest.Converged(t, false)
	env := newObjectsEnv(t, roster, scenario)
	report, err := DriftOnce(context.Background(), env.opts(t, true))
	if err != nil {
		t.Fatalf("drift failed: %v", err)
	}
	if len(report.Items) != 0 {
		t.Fatalf("drift after convergence: %v", itemKeys(report, true))
	}
}

// TestRegression_IdentitySecretDriftProbePreservedUsersMailAndMarkers covers
// what a live run found and apply does: preserved users (hidden from a plain
// user search), the default e-mail domain FreeIPA appends to an address without
// '@', and Pilot's own history-marker groups.
func TestRegression_IdentitySecretDriftProbePreservedUsersMailAndMarkers(t *testing.T) {
	keys := capturedKeys(t)
	scenario := capturedScenario(t)
	scenario.PreservedFind = fakeipatest.PreservedUsers(t, "p1-ghost", "p1-held", "p1-stray")
	marker := "pilot-internal-history-g-" + strings.Repeat("0f", 32)
	lookalike := "pilot-internal-history-g-" + strings.Repeat("0f", 31)
	for _, name := range []string{marker, lookalike} {
		scenario.GroupFind["result"] = append(scenario.GroupFind["result"].([]any), map[string]any{
			"cn": []any{name}, "description": []any{"pilot.group-history/v1 name=team-gone"}})
	}
	scenario.GroupFind["count"] = len(scenario.GroupFind["result"].([]any))

	roster := objectsRoster(t, keys[:1])
	// p1-keys: bare address, FreeIPA stores it with the domain (equal to live).
	// p1-off: the full address (equal to live). p1-nokeys: a different address.
	roster = strings.Replace(roster, "  - name: p1-keys\n", "  - name: p1-keys\n    email: p1-keys\n", 1)
	roster = strings.Replace(roster, "  - name: p1-off\n", "  - name: p1-off\n    email: p1-off@ipa.pilot.internal\n", 1)
	roster = strings.Replace(roster, "  - name: p1-nokeys\n", "  - name: p1-nokeys\n    email: other\n", 1)
	roster = strings.Replace(roster, "groups:\n", "  - name: p1-ghost\n    state: absent\n  - name: p1-held\n    login_shell: /bin/sh\ngroups:\n", 1)

	env := newObjectsEnv(t, roster, scenario)
	report, err := DriftOnce(context.Background(), env.opts(t, true))
	if err != nil {
		t.Fatalf("drift failed: %v", err)
	}
	got := map[string]string{}
	for _, item := range report.Items {
		got[item.Category+":"+item.Name] = item.Action + ":" + item.Detail
	}
	for key, want := range map[string]string{
		"user_should_be_absent:p1-ghost": "delete:explicitly absent managed user exists as a preserved user; apply deletes it permanently",
		"user_preserved:p1-held":         "manual:preserved user blocks apply; restore or delete it",
		"user_unexpected:p1-stray":       "report:preserved user outside the roster; apply will not delete it",
		"user_attribute:p1-nokeys":       "update:managed attribute differs: mail",
		"group_unexpected:" + lookalike:  "report:object outside the roster; apply will not delete it",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	for _, absent := range []string{"user_missing:p1-held", "user_missing:p1-ghost", "user_attribute:p1-keys", "user_attribute:p1-off", "group_unexpected:" + marker} {
		if _, found := got[absent]; found {
			t.Errorf("unexpected item %s", absent)
		}
	}
}

// TestRegression_IdentitySecretDriftProbeKeyIdentityFollowsApply: the observer
// reports an SSH key difference exactly when `ipa user-mod --sshpubkey` would
// modify the user, and never fails because of a key it has no business with.
// One probe run covers every case: each case is its own live user, a clone of
// captured user p1-keys whose stored keys are replaced (the replacement values
// are the spellings FreeIPA's normalizer produces, see the case names).
func TestRegression_IdentitySecretDriftProbeKeyIdentityFollowsApply(t *testing.T) {
	keys := capturedKeys(t)
	typeAndBlob := keys[0][:strings.LastIndex(keys[0], " ")]
	comment := keys[0][strings.LastIndex(keys[0], " ")+1:]
	optioned := func(options string) string { return options + " " + keys[0] }
	cases := []struct {
		name     string
		desired  []string // roster values
		live     []any    // what FreeIPA stores
		wantDiff bool
	}{
		{"identical", keys[:1], []any{keys[0]}, false},
		{"options-prefixed key, same in the roster", []string{optioned(`from="10.0.0.0/8"`)}, []any{optioned(`from="10.0.0.0/8"`)}, false},
		{"spelling FreeIPA normalizes away", []string{`  FROM="10.0.0.0/8"   ` + typeAndBlob + "  " + comment}, []any{optioned(`from="10.0.0.0/8"`)}, false},
		{"quoted options with spaces and commas", []string{optioned(`command="echo a, b",no-pty`)}, []any{optioned(`command="echo a, b",no-pty`)}, false},
		{"comment-only difference", keys[:1], []any{typeAndBlob + " renamed-comment"}, true},
		{"options-only difference", keys[:1], []any{optioned(`from="10.0.0.0/8"`)}, true},
		{"options changed", []string{optioned(`from="192.0.2.0/24"`)}, []any{optioned(`from="10.0.0.0/8"`)}, true},
		{"live key cleared by hand", keys[:1], []any{}, true},
		{"roster clears the keys", []string{}, []any{keys[0]}, true},
	}
	scenario := capturedScenario(t)
	template := liveUser(t, scenario, "p1-keys")
	add := func(uid string, stored []any) {
		clone := map[string]any{}
		for k, v := range template {
			clone[k] = v
		}
		clone["uid"], clone["homedirectory"], clone["ipasshpubkey"] = []any{uid}, []any{"/home/" + uid}, stored
		scenario.UserFind["result"] = append(scenario.UserFind["result"].([]any), clone)
		scenario.UserFind["count"] = len(scenario.UserFind["result"].([]any))
	}
	var rosterUsers []string
	for i, tc := range cases {
		uid := fmt.Sprintf("key-case-%d", i)
		add(uid, tc.live)
		quoted, _ := json.Marshal(tc.desired)
		rosterUsers = append(rosterUsers, fmt.Sprintf("  - name: %s\n    first: P1\n    last: Keys\n    login_shell: /bin/sh\n    ssh_keys: {authoritative: true, values: %s}\n", uid, quoted))
	}
	// A user the roster does not manage holds keys nothing may parse.
	add("key-unmanaged", []any{optioned(`from="10.0.0.0/8"`), "not a key at all"})
	text := strings.Replace(objectsRoster(t, keys[:1]), "groups:\n", strings.Join(rosterUsers, "")+"groups:\n", 1)
	env := newObjectsEnv(t, text, scenario)
	report, err := DriftOnce(context.Background(), env.opts(t, true))
	if err != nil {
		t.Fatalf("observation failed: %v", err)
	}
	drift := map[string]bool{}
	for _, item := range report.Items {
		if item.Category == "user_ssh_keys" {
			drift[item.Name] = true
		}
	}
	for i, tc := range cases {
		if got := drift[fmt.Sprintf("key-case-%d", i)]; got != tc.wantDiff {
			t.Errorf("%s: ssh_keys drift = %v, want %v", tc.name, got, tc.wantDiff)
		}
	}
	if drift["key-unmanaged"] || drift["p1-nopw"] {
		t.Errorf("a user the roster does not manage keys for is reported: %v", drift)
	}
	if !drift["p1-keys"] {
		t.Errorf("p1-keys (desired 1 key, live 2) must drift: %v", drift)
	}
	for _, item := range report.Items {
		if strings.HasPrefix(item.Name, "key-case-") && item.Category != "user_ssh_keys" {
			t.Errorf("unexpected non-key drift for a clone: %+v", item)
		}
	}
}

// TestRegression_IdentitySecretDriftProbeUsersGroupsRunOnTheTicketHost: the
// probe's kinit is run_once, so only the first host has a ticket in its private
// cache. With two hosts in the target group the observer must run once, on that
// host, and the decoded observation must reach the result the Go side reads.
func TestRegression_IdentitySecretDriftProbeUsersGroupsRunOnTheTicketHost(t *testing.T) {
	keys := capturedKeys(t)
	env := newObjectsEnv(t, objectsRoster(t, keys[:1]), capturedScenario(t), "ipa1", "ipa2")
	live, err := DriftProbe(context.Background(), env.opts(t, true))
	if err != nil {
		t.Fatalf("a two-host target group failed: %v", err)
	}
	if live.IdentityObjects == nil || len(live.IdentityObjects.LiveUsers) != 6 {
		t.Fatalf("observation = %+v", live.IdentityObjects)
	}
	// Once, on the host that has the ticket: a second attempt would be the
	// observer running on a host whose private cache is empty (its failure would
	// only be hidden by failed_when).
	if n := env.ipa.Connects(t); n != 1 {
		t.Errorf("the observer reached for FreeIPA %d times on 2 hosts, want exactly 1", n)
	}
}

var errClassRE = regexp.MustCompile(`PILOT_IDENTITY_OBSERVER_ERROR=`)

// TestRegression_IdentitySecretDriftProbeObserverFailuresAreFixedClasses: every
// way the observer can fail is named to the operator with one fixed message, and
// nothing from the exception, the reply or the roster is printed.
func TestRegression_IdentitySecretDriftProbeObserverFailuresAreFixedClasses(t *testing.T) {
	keys := capturedKeys(t)
	message := func(marker string) string {
		for _, k := range knownProbeMessages {
			if k.marker == marker {
				return k.text
			}
		}
		t.Fatalf("no known message with marker %q", marker)
		return ""
	}
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *fakeipatest.Scenario, *string)
		marker string
	}{
		{"no ticket for the observer", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.Fail = &fakeipatest.Failure{Where: "connect", Error: "KerberosError", Text: objectsLeakSentinel}
		}, "The users/groups observer had no usable Kerberos credentials"},
		{"an RPC fails", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.Fail = &fakeipatest.Failure{Where: "user_find", Error: "NetworkError", Text: objectsLeakSentinel}
		}, "The users/groups observer could not complete a FreeIPA API call"},
		{"the preserved-user search fails", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.Fail = &fakeipatest.Failure{Where: "preserved_find", Error: "NetworkError", Text: objectsLeakSentinel}
		}, "The users/groups observer could not complete a FreeIPA API call"},
		{"the preserved-user search is truncated", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.PreservedFind = fakeipatest.PreservedUsers(t, "p1-held")
			s.PreservedFind["truncated"] = true
		}, "FreeIPA returned a truncated or inconsistent user or group search result"},
		{"the default e-mail domain cannot be read", func(t *testing.T, s *fakeipatest.Scenario, roster *string) {
			*roster = strings.Replace(*roster, "  - name: p1-keys\n", "  - name: p1-keys\n    email: p1-keys\n", 1)
			s.Fail = &fakeipatest.Failure{Where: "config_show", Error: "ACIError", Text: objectsLeakSentinel}
		}, "The users/groups observer could not complete a FreeIPA API call"},
		{"truncated search", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.UserFind["truncated"] = true
		}, "FreeIPA returned a truncated or inconsistent user or group search result"},
		{"count does not match", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			s.GroupFind["count"] = 99
		}, "FreeIPA returned a truncated or inconsistent user or group search result"},
		{"missing nsaccountlock", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			delete(liveUser(t, *s, "p1-off"), "nsaccountlock")
		}, "FreeIPA did not report the account lock state"},
		{"record without a primary key", func(t *testing.T, s *fakeipatest.Scenario, _ *string) {
			delete(liveUser(t, *s, "p1-off"), "uid")
		}, "FreeIPA returned a user or group record in an unexpected shape"},
		{"invalid roster key", func(t *testing.T, s *fakeipatest.Scenario, roster *string) {
			*roster = strings.Replace(*roster, `"`+keys[0]+`"`, `"not-a-key `+objectsLeakSentinel+`"`, 1)
		}, "ssh_keys value is not a valid SSH public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario, roster := capturedScenario(t), objectsRoster(t, keys[:1])
			tc.mutate(t, &scenario, &roster)
			env := newObjectsEnv(t, roster, scenario)
			_, err := DriftOnce(context.Background(), env.opts(t, true))
			if err == nil {
				t.Fatal("the observation failed but the drift run succeeded")
			}
			text := err.Error()
			if !strings.Contains(text, message(tc.marker)) {
				t.Errorf("error does not carry the fixed message %q:\n%s", tc.marker, text)
			}
			if strings.Contains(text, withheldText) || errClassRE.MatchString(text) {
				t.Errorf("error shows the unclassified fallback or the raw class line:\n%s", text)
			}
			assertNoSentinel(t, "the error", text)
			// Only the failing class is named.
			others := 0
			for _, k := range knownProbeMessages {
				if strings.Contains(k.marker, "users/groups") || strings.Contains(k.marker, "FreeIPA returned") || strings.Contains(k.marker, "FreeIPA did not") ||
					strings.Contains(k.marker, "ssh_keys value") || strings.Contains(k.marker, "Python client") {
					if strings.Contains(text, k.text) {
						others++
					}
				}
			}
			if others != 1 {
				t.Errorf("%d observer messages in one error:\n%s", others, text)
			}
		})
	}

	t.Run("the FreeIPA Python client is missing", func(t *testing.T) {
		env := newObjectsEnv(t, objectsRoster(t, keys[:1]), capturedScenario(t))
		t.Setenv("PYTHONPATH", t.TempDir())
		_, err := DriftOnce(context.Background(), env.opts(t, true))
		if err == nil || !strings.Contains(err.Error(), message("The FreeIPA Python client (ipalib and ipapython) could not be imported")) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("an interpreter crash is the unclassified gate, not a hidden failure", func(t *testing.T) {
		env := newObjectsEnv(t, objectsRoster(t, keys[:1]), capturedScenario(t))
		// A fake ipalib that kills the interpreter without a class line.
		bad := t.TempDir()
		if err := os.MkdirAll(filepath.Join(bad, "ipalib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bad, "ipalib", "__init__.py"), []byte("import os\nos._exit(7)\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PYTHONPATH", bad)
		_, err := DriftOnce(context.Background(), env.opts(t, true))
		if err == nil || !strings.Contains(err.Error(), message("failed for a reason outside its fixed error classes")) {
			t.Fatalf("error = %v", err)
		}
	})
}

// TestObserverErrorClassesHaveAGateAndAMessage keeps the observer's error
// vocabulary, the probe's gates and the fixed messages Go prints equal: a class
// added to the observer without a gate would surface as "unclassified".
func TestObserverErrorClassesHaveAGateAndAMessage(t *testing.T) {
	observer, err := os.ReadFile("../../playbooks/check/files/freeipa-identity-object-observer.py")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)ERROR_CLASSES = \((.*?)\)`).FindSubmatch(observer)
	if block == nil {
		t.Fatal("ERROR_CLASSES not found in the observer")
	}
	var classes []string
	for _, m := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(block[1], -1) {
		classes = append(classes, string(m[1]))
	}
	sort.Strings(classes)

	body, err := os.ReadFile("../../playbooks/check/tasks/freeipa-identity-object-observe.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(body, &tasks); err != nil {
		t.Fatal(err)
	}
	gated := map[string]string{} // class -> collapsed fail_msg
	var known []string
	for _, task := range tasks {
		if vars, ok := task["vars"].(map[string]any); ok {
			if list, ok := vars["observer_known"].([]any); ok {
				for _, c := range list {
					known = append(known, c.(string))
				}
			}
		}
		assert, ok := task["ansible.builtin.assert"].(map[string]any)
		if !ok {
			continue
		}
		that := fmt.Sprint(assert["that"])
		if m := regexp.MustCompile(`pilot_identity_object_error != '([a-z_]+)'`).FindStringSubmatch(that); m != nil {
			gated[m[1]] = strings.Join(strings.Fields(assert["fail_msg"].(string)), " ")
		}
	}
	sort.Strings(known)
	if strings.Join(known, ",") != strings.Join(classes, ",") {
		t.Errorf("the classifier knows %v, the observer emits %v", known, classes)
	}
	messages := map[string]bool{}
	for _, k := range knownProbeMessages {
		messages[k.text] = true
	}
	for _, class := range classes {
		msg, ok := gated[class]
		if !ok {
			t.Errorf("class %s has no gate in the observe tasks", class)
			continue
		}
		if !messages[msg] {
			t.Errorf("the gate message of %s is not registered in knownProbeMessages: %q", class, msg)
		}
	}
	if len(gated) != len(classes) {
		t.Errorf("gates %v do not match classes %v", gated, classes)
	}
}

// TestObserverTasksFollowTheKinitsTagsAndRunOnce: the probe's kinit is tagged
// [identity, drift] and run_once, so the ticket exists only in the first host's
// private cache and only when those tags select it. The include of the observer
// must carry the same tags (it used to be `always`: it would run without a
// ticket), and every task inside that reads the ticket must be run_once; only
// the shared normalization include (always, per-host, no ticket) is exempt.
func TestObserverTasksFollowTheKinitsTagsAndRunOnce(t *testing.T) {
	load := func(path string) []map[string]any {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc []map[string]any
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	tagsOf := func(task map[string]any) string {
		var tags []string
		for _, tag := range task["tags"].([]any) {
			tags = append(tags, tag.(string))
		}
		sort.Strings(tags)
		return strings.Join(tags, ",")
	}
	var kinitTags, includeTags, applyTags string
	var walk func(tasks []any)
	walk = func(tasks []any) {
		for _, raw := range tasks {
			task := raw.(map[string]any)
			switch task["name"] {
			case "Kinit admin for read-only drift probe":
				kinitTags = tagsOf(task)
			case "Read the complete users/groups object model for identity drift":
				includeTags = tagsOf(task)
				include := task["ansible.builtin.include_tasks"].(map[string]any)
				var apply []string
				for _, tag := range include["apply"].(map[string]any)["tags"].([]any) {
					apply = append(apply, tag.(string))
				}
				sort.Strings(apply)
				applyTags = strings.Join(apply, ",")
			}
			if block, ok := task["block"].([]any); ok {
				walk(block)
			}
		}
	}
	for _, play := range load("../../playbooks/check/freeipa-access-drift-probe.yml") {
		walk(play["tasks"].([]any))
	}
	if kinitTags == "" || includeTags != kinitTags || applyTags != kinitTags {
		t.Errorf("kinit tags %q, observer include tags %q, its apply tags %q: they must be equal", kinitTags, includeTags, applyTags)
	}
	for _, task := range load("../../playbooks/check/tasks/freeipa-identity-object-observe.yml") {
		name := task["name"].(string)
		if _, includes := task["ansible.builtin.include_tasks"]; includes {
			if tagsOf(task) != "always" {
				t.Errorf("%q: the shared normalization include must stay always", name)
			}
			continue
		}
		if tagsOf(task) != kinitTags {
			t.Errorf("%q has tags %q, want the kinit's %q", name, tagsOf(task), kinitTags)
		}
		if task["run_once"] != true {
			t.Errorf("%q is not run_once: on a second host it would run without the ticket", name)
		}
	}
}
