package spec

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// freeipa-identity-apply.yml decides per user whether to run `ipa passwd`
// (freeipa-config.md §6.4): an account with no Kerberos key gets its
// declared password; an existing one is reset only when the roster asks
// (preserve_existing: false, or legacy force_password: true) and the user is
// no longer on the password the last reset gave them. Until 2026-10-15 the
// condition was `force_password or needs_reset`, which reset every
// force_change: true user on every run, including users who had changed
// their own password, and every user still pending their first change.
//
// These tests run the playbook's own password tasks, extracted by name, on
// localhost. The `ipa user-show --all --raw` lookup is replaced by `cat` of
// output captured from a real FreeIPA server (testdata/freeipa-user-show-*),
// and `ipa passwd` by a debug task printing "PASSWD <user>".

const identityApplyPath = "../../playbooks/apply/freeipa-identity-apply.yml"

const (
	identityPwLookupTask = "Look up password state for users with a declared password"
	identityPwSetTask    = "Set password for users that need one (first-time onboard, or requested reset)"
	identityUserGateTask = "Gate: canonical user objects are structurally valid"
)

var identityPasswordTaskNames = []string{
	identityPwLookupTask,
	"Start the password action accumulators",
	"Decide the password action for each user",
	"Gate: the password state of every declared password was read",
	identityPwSetTask,
}

// Real `ipa user-show <user> --all --raw` stdout, captured 2026-10-15 from a
// disposable FreeIPA 4.13.4 server on AlmaLinux 9.8: a user with no password
// yet, right after `ipa passwd`, and after the user changed it with kinit
// (under the default 90-day maxlife, and under maxlife 0, where
// krbPasswordExpiration is absent after the user's change).
const (
	userShowNoKey               = "testdata/freeipa-user-show-raw-no-key.txt"
	userShowResetPending        = "testdata/freeipa-user-show-raw-reset-pending.txt"
	userShowSelfChanged         = "testdata/freeipa-user-show-raw-self-changed.txt"
	userShowMaxlife0SelfChanged = "testdata/freeipa-user-show-raw-maxlife0-self-changed.txt"
)

// identityTasks returns the identity playbook's pre_tasks and tasks named in
// names, in playbook order, without no_log so the test can read their
// results.
func identityTasks(t *testing.T, names []string) []any {
	t.Helper()
	raw, err := os.ReadFile(identityApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var out []any
	found := map[string]bool{}
	pre, _ := plays[0]["pre_tasks"].([]any)
	for _, r := range flattenTasks(append(slices.Clone(pre), plays[0]["tasks"].([]any)...)) {
		task := r.(map[string]any)
		name, _ := task["name"].(string)
		if !slices.Contains(names, name) {
			continue
		}
		found[name] = true
		c := map[string]any{}
		for k, v := range task {
			if k != "no_log" {
				c[k] = v
			}
		}
		switch name {
		case identityPwLookupTask:
			c["ansible.builtin.command"] = map[string]any{"argv": []any{"cat", "{{ pw_fixture_dir }}/{{ item.name }}.txt"}}
		case identityPwSetTask:
			for _, k := range []string{"ansible.builtin.shell", "register", "changed_when", "failed_when"} {
				delete(c, k)
			}
			c["ansible.builtin.debug"] = map[string]any{"msg": "PASSWD {{ item.name }}"}
		}
		out = append(out, c)
	}
	for _, n := range names {
		if !found[n] {
			t.Fatalf("task %q not found in %s", n, identityApplyPath)
		}
	}
	return out
}

// flattenTasks lists the tasks in playbook order, descending into blocks:
// most reconcile tasks sit inside the private Kerberos cache block (issue
// #69), so a top-level scan would not find them.
func flattenTasks(tasks []any) []any {
	var out []any
	for _, r := range tasks {
		task, ok := r.(map[string]any)
		if !ok {
			continue
		}
		sections := []string{"block", "rescue", "always"}
		if _, isBlock := task["block"]; !isBlock {
			out = append(out, task)
			continue
		}
		for _, section := range sections {
			if inner, ok := task[section].([]any); ok {
				out = append(out, flattenTasks(inner)...)
			}
		}
	}
	return out
}

// pwUser is one ipa_active_users entry plus the captured user-show output
// its lookup returns ("" = the lookup fails).
type pwUser struct {
	entry   map[string]any
	fixture string
}

// canonicalUser is a user as the playbook normalizes a canonical roster
// entry: preserve_existing always present, force_password from force_change.
func canonicalUser(name string, preserve, forceChange bool) map[string]any {
	return map[string]any{"name": name, "password": "Roster-Initial-1", "preserve_existing": preserve, "force_password": forceChange}
}

// legacyUser is a legacy ipa_users entry: no preserve_existing.
func legacyUser(name string, forcePassword bool) map[string]any {
	return map[string]any{"name": name, "password": "Roster-Initial-1", "force_password": forcePassword}
}

// runIdentityPassword runs the password tasks for users and returns the
// run and the sorted names `ipa passwd` would have been run for.
func runIdentityPassword(t *testing.T, users []pwUser, args ...string) (ag82Run, []string) {
	t.Helper()
	dir := t.TempDir()
	var active []any
	for _, u := range users {
		active = append(active, u.entry)
		if u.fixture == "" {
			continue
		}
		body, err := os.ReadFile(u.fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, u.entry["name"].(string)+".txt"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := runGatewayTasks(t, dir, identityTasks(t, identityPasswordTaskNames),
		map[string]any{"ipa_active_users": active, "pw_fixture_dir": dir}, nil, args...)
	var passwd []string
	prefix := identityPwSetTask + `: "PASSWD `
	for _, m := range res.messages {
		if strings.HasPrefix(m, prefix) {
			passwd = append(passwd, strings.TrimSuffix(strings.TrimPrefix(m, prefix), `"`))
		}
	}
	sort.Strings(passwd)
	return res, passwd
}

func TestRegression_IdentityPasswordResetFollowsRosterSchema(t *testing.T) {
	users := []pwUser{
		// No Kerberos key yet: initialized whatever the flags say.
		{canonicalUser("new-preserve", true, false), userShowNoKey},
		{canonicalUser("new-forced", true, true), userShowNoKey},
		// preserve_existing: true never touches an existing password —
		// force_change: true used to reset these on every run.
		{canonicalUser("pending-forced", true, true), userShowResetPending},
		{canonicalUser("changed-forced", true, true), userShowSelfChanged},
		{canonicalUser("changed-plain", true, false), userShowSelfChanged},
		// preserve_existing: false resets, but not again while the user is
		// still on the last reset's password.
		{canonicalUser("reset-requested", false, true), userShowSelfChanged},
		{canonicalUser("reset-done", false, true), userShowResetPending},
		{canonicalUser("reset-done-plain", false, false), userShowResetPending},
		// maxlife 0: no krbPasswordExpiration after the user's change. The
		// old condition read the missing attribute as "still on the reset
		// password" and reset these users on every run.
		{canonicalUser("nomax-changed", true, false), userShowMaxlife0SelfChanged},
		{canonicalUser("nomax-reset", false, true), userShowMaxlife0SelfChanged},
		// Legacy ipa_users: force_password: true asks for the reset.
		{legacyUser("legacy-new", false), userShowNoKey},
		{legacyUser("legacy-reset", true), userShowSelfChanged},
		{legacyUser("legacy-reset-done", true), userShowResetPending},
		{legacyUser("legacy-changed", false), userShowSelfChanged},
		{legacyUser("legacy-pending", false), userShowResetPending},
	}
	res, got := runIdentityPassword(t, users)
	if res.rc != 0 || len(res.failures) != 0 {
		t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
	}
	want := []string{"legacy-new", "legacy-reset", "new-forced", "new-preserve", "nomax-reset", "reset-requested"}
	if !slices.Equal(got, want) {
		t.Fatalf("ipa passwd would run for %v, want %v", got, want)
	}
}

// A failed lookup says nothing about the account. Reading it as "no
// Kerberos key" would reset an existing password; the run must stop
// before setting any password instead.
func TestRegression_IdentityPasswordLookupFailureSetsNothing(t *testing.T) {
	res, got := runIdentityPassword(t, []pwUser{
		{canonicalUser("new-user", true, false), userShowNoKey},
		{canonicalUser("unreadable", true, false), ""},
	})
	if res.rc == 0 {
		t.Fatalf("expected the run to fail\n%s", res.raw)
	}
	if len(got) != 0 {
		t.Fatalf("ipa passwd would run for %v after a failed lookup", got)
	}
	if !slices.ContainsFunc(res.failures, func(f string) bool { return strings.Contains(f, "unreadable") }) {
		t.Fatalf("failure does not name the unreadable user: %v", res.failures)
	}
}

// In check mode the lookup is skipped; nothing is decided and nothing fails.
func TestRegression_IdentityPasswordCheckModeSetsNothing(t *testing.T) {
	res, got := runIdentityPassword(t, []pwUser{
		{canonicalUser("new-user", true, false), userShowNoKey},
		{canonicalUser("reset-requested", false, true), userShowSelfChanged},
	}, "--check")
	if res.rc != 0 || len(res.failures) != 0 {
		t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
	}
	if len(got) != 0 {
		t.Fatalf("ipa passwd would run for %v in check mode", got)
	}
}

// The canonical user gate rejects a password flag that is not a boolean, so
// a null or "no" preserve_existing is never read as false (a reset).
func TestRegression_IdentityPasswordFlagsMustBeBooleans(t *testing.T) {
	gate := identityTasks(t, []string{identityUserGateTask})
	run := func(password map[string]any) ag82Run {
		roster := map[string]any{"schema_version": 3, "users": []any{map[string]any{
			"name": "alice", "password": password,
			"ssh_keys": map[string]any{"authoritative": true, "values": []any{}},
		}}}
		return runGatewayTasks(t, t.TempDir(), gate, map[string]any{"freeipa_roster": roster}, nil)
	}
	if res := run(map[string]any{"initial": "x", "force_change": true, "preserve_existing": false}); res.rc != 0 {
		t.Fatalf("booleans rejected: %v\n%s", res.failures, res.raw)
	}
	for _, pw := range []map[string]any{
		{"initial": "x", "preserve_existing": nil},
		{"initial": "x", "preserve_existing": "no"},
		{"initial": "x", "force_change": "true"},
	} {
		if res := run(pw); res.rc == 0 {
			t.Fatalf("password %v accepted", pw)
		}
	}
}
