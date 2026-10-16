package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #102: freeipa-identity-apply.yml ignored `ipa` failures in places
// where a failure changes what the run does. `ipa passwd` failing was
// reported as ok, a failed membership lookup read as "no members" (so stale
// access was never removed), an existence check could not tell "not found"
// from any other error, and the HBAC lockdown rollback always claimed it had
// re-enabled allow_all.
//
// These tests run the playbook's own tasks, extracted by name, on localhost
// with a fake `ipa` first on PATH. The fake answers each expected argument
// list with output captured from FreeIPA 4.13.4 (testdata/freeipa-ipa-cli;
// the object names inside the captured error text are the capture's, the
// tasks match only the error kind) and fails any other call.

const ipaCLIFixtures = "testdata/freeipa-ipa-cli"

// fakeIPA puts an `ipa` that answers args (joined by spaces) with a fixture
// first on PATH, and returns a function listing the calls made so far.
func fakeIPA(t *testing.T, answers map[string]string) (calls func() []string) {
	t.Helper()
	dir := t.TempDir()
	var tsv strings.Builder
	for args, fixture := range answers {
		base := fixture
		if !filepath.IsAbs(base) {
			abs, err := filepath.Abs(filepath.Join(ipaCLIFixtures, fixture))
			if err != nil {
				t.Fatal(err)
			}
			base = abs
		}
		if _, err := os.Stat(base + ".rc"); err != nil {
			t.Fatalf("fixture %s: %v", fixture, err)
		}
		fmt.Fprintf(&tsv, "%s\t%s\n", args, base)
	}
	if err := os.WriteFile(filepath.Join(dir, "answers.tsv"), []byte(tsv.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
args="$*"
printf '%s\n' "$args" >> "` + dir + `/calls.log"
[ "$1" = passwd ] && cat >/dev/null
f=$(awk -F'\t' -v a="$args" '$1==a{print $2; exit}' "` + dir + `/answers.tsv")
if [ -z "$f" ]; then echo "fake ipa: unexpected call: $args" >&2; exit 99; fi
cat "$f.stdout"; cat "$f.stderr" >&2; exit "$(cat "$f.rc")"
`
	if err := os.WriteFile(filepath.Join(dir, "ipa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		raw, err := os.ReadFile(filepath.Join(dir, "calls.log"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
}

// stdoutFixture turns a captured stdout file into a fixture base (exit 0, no
// stderr) under a temp dir.
func stdoutFixture(t *testing.T, stdoutPath string) string {
	t.Helper()
	body, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "fixture")
	for ext, content := range map[string][]byte{".stdout": body, ".stderr": nil, ".rc": []byte("0\n")} {
		if err := os.WriteFile(base+ext, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

func runIdentityTasks(t *testing.T, names []string, vars map[string]any, args ...string) ag82Run {
	t.Helper()
	var tasks []any
	for _, task := range identityPlaybookTasks(t, names) {
		tasks = append(tasks, task)
	}
	return runGatewayTasks(t, t.TempDir(), tasks, vars, nil, args...)
}

func failureOf(res ag82Run, task string) string {
	for _, f := range res.failures {
		if strings.HasPrefix(f, task+": ") {
			return f
		}
	}
	return ""
}

const identityPasswdGateTask = "Gate: every password this run set was accepted"

func TestRegression_IdentityPasswdFailureFailsTheRun(t *testing.T) {
	noKey := stdoutFixture(t, userShowNoKey)
	names := append(slices.Clone(identityPasswordTaskNames), identityPasswdGateTask)
	users := []any{canonicalUser("ok-user", true, false), canonicalUser("gone-user", true, false)}
	answers := map[string]string{
		"user-show ok-user --all --raw":   noKey,
		"user-show gone-user --all --raw": noKey,
		"passwd ok-user":                  "passwd-ok",
		"passwd gone-user":                "passwd-no-matching-entry",
	}

	t.Run("a failed passwd stops the run and names the user", func(t *testing.T) {
		calls := fakeIPA(t, answers)
		res := runIdentityTasks(t, names, map[string]any{"ipa_active_users": users})
		if res.rc == 0 {
			t.Fatalf("expected the run to fail\n%s", res.raw)
		}
		msg := failureOf(res, identityPasswdGateTask)
		if !strings.Contains(msg, "gone-user (rc=2: ipa: ERROR: no matching entry found)") {
			t.Fatalf("gate failure does not name the user and ipa's error: %q\nfailures: %v", msg, res.failures)
		}
		if strings.Contains(msg, "ok-user") || strings.Contains(msg, "Roster-Initial-1") {
			t.Fatalf("gate failure names a user that succeeded or shows the password: %q", msg)
		}
		if got := calls(); !slices.Contains(got, "passwd ok-user") || !slices.Contains(got, "passwd gone-user") {
			t.Fatalf("every password must still be attempted, calls: %v", got)
		}
	})

	t.Run("all passwords accepted", func(t *testing.T) {
		ok := maps(answers, "passwd gone-user", "passwd-ok")
		fakeIPA(t, ok)
		if res := runIdentityTasks(t, names, map[string]any{"ipa_active_users": users}); res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
	})
}

// maps returns a copy of m with key set to value.
func maps(m map[string]string, key, value string) map[string]string {
	c := map[string]string{}
	for k, v := range m {
		c[k] = v
	}
	c[key] = value
	return c
}

func TestRegression_IdentityMembershipLookupFailureFailsTheRun(t *testing.T) {
	const lookup = "Look up canonical group direct membership"
	names := []string{lookup, "Compute stale canonical group membership", "Remove stale canonical direct users", "Remove stale canonical direct nested groups"}
	vars := map[string]any{
		"freeipa_roster":    map[string]any{"schema_version": 3},
		"ipa_active_groups": []any{map[string]any{"name": "pwc-team", "membership": map[string]any{"authoritative": true, "users": []any{"pwe-keep"}, "groups": []any{}}}},
	}

	t.Run("lookup works", func(t *testing.T) {
		fakeIPA(t, map[string]string{"group-show pwc-team --all": "group-show-members"})
		if res := runIdentityTasks(t, names, vars); res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
	})

	// Read as "no members", this used to compute no removals and pass.
	t.Run("lookup fails", func(t *testing.T) {
		fakeIPA(t, map[string]string{"group-show pwc-team --all": "no-kerberos-ticket"})
		res := runIdentityTasks(t, names, vars)
		if res.rc == 0 || failureOf(res, lookup) == "" {
			t.Fatalf("expected the run to fail at %q, rc=%d failures=%v", lookup, res.rc, res.failures)
		}
	})
}

func TestRegression_IdentityGroupDeleteLookupStopsOnErrors(t *testing.T) {
	const lookup = "Look up actual FreeIPA group before deleting"
	names := []string{lookup, "Delete canonical groups explicitly marked absent"}
	vars := map[string]any{
		"freeipa_roster": map[string]any{"schema_version": 3},
		"ipa_groups":     []any{map[string]any{"name": "old-team", "state": "absent"}},
	}

	t.Run("group already gone", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{"group-show old-team": "group-show-not-found", "group-del old-team": "group-del-not-found"})
		if res := runIdentityTasks(t, names, vars); res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if !slices.Contains(calls(), "group-del old-team") {
			t.Fatalf("group-del not run: %v", calls())
		}
	})

	// The history marker is written only for a group the lookup proved to
	// exist; any other lookup failure used to let group-del run without it.
	t.Run("lookup fails", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{"group-show old-team": "no-kerberos-ticket", "group-del old-team": "group-del-not-found"})
		res := runIdentityTasks(t, names, vars)
		if res.rc == 0 || failureOf(res, lookup) == "" {
			t.Fatalf("expected the run to fail at %q, rc=%d failures=%v", lookup, res.rc, res.failures)
		}
		if slices.Contains(calls(), "group-del old-team") {
			t.Fatalf("group-del ran after a failed lookup: %v", calls())
		}
	})
}

func TestRegression_IdentityHostLookupDistinguishesNotFound(t *testing.T) {
	const lookup = "Look up canonical FreeIPA host objects"
	const add = "host-add pwc-host.ipa.pilot.internal --ip-address=192.168.122.251 --desc=pwc-host"
	names := []string{lookup, "Ensure canonical FreeIPA host objects exist"}
	vars := map[string]any{"freeipa_roster": map[string]any{"schema_version": 3, "hosts": []any{
		map[string]any{"name": "pwc-host.ipa.pilot.internal", "ip_address": "192.168.122.251", "description": "pwc-host"},
	}}}
	for _, tc := range []struct {
		name, show string
		wantAdd    bool
		wantFail   bool
	}{
		{"not found adds the host", "host-show-not-found", true, false},
		{"existing host is left alone", "host-show-existing", false, false},
		{"lookup error stops the run", "no-kerberos-ticket", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeIPA(t, map[string]string{"host-show pwc-host.ipa.pilot.internal": tc.show, add: "host-add-new"})
			res := runIdentityTasks(t, names, vars)
			if failed := res.rc != 0; failed != tc.wantFail || (tc.wantFail && failureOf(res, lookup) == "") {
				t.Fatalf("rc=%d failures=%v, want failure at the lookup: %v", res.rc, res.failures, tc.wantFail)
			}
			if got := slices.Contains(calls(), add); got != tc.wantAdd {
				t.Fatalf("host-add ran: %v, want %v; calls %v", got, tc.wantAdd, calls())
			}
		})
	}
}

func TestRegression_IdentityPasswordPolicyLookupDistinguishesNotFound(t *testing.T) {
	const lookup = "Check existence of each desired password_policy's group policy"
	names := []string{lookup, "Create group password policies that don't exist yet", "Modify group password policies that already exist"}
	vars := map[string]any{"pilot_compiled_password_policies": []any{map[string]any{"group": "pwc-pol", "state": "present", "priority": 7}}}

	t.Run("not found creates the policy", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{"pwpolicy-show pwc-pol": "pwpolicy-show-not-found", "pwpolicy-add pwc-pol --priority=7": "pwpolicy-add-new"})
		if res := runIdentityTasks(t, names, vars); res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if !slices.Contains(calls(), "pwpolicy-add pwc-pol --priority=7") {
			t.Fatalf("pwpolicy-add not run: %v", calls())
		}
	})

	t.Run("lookup error stops the run", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{"pwpolicy-show pwc-pol": "no-kerberos-ticket", "pwpolicy-add pwc-pol --priority=7": "pwpolicy-add-new"})
		res := runIdentityTasks(t, names, vars)
		if res.rc == 0 || failureOf(res, lookup) == "" {
			t.Fatalf("expected the run to fail at %q, rc=%d failures=%v", lookup, res.rc, res.failures)
		}
		if got := calls(); len(got) != 1 {
			t.Fatalf("expected only the lookup, calls %v", got)
		}
	})
}

// The lockdown block's rescue re-enables allow_all; its failure message must
// say whether that worked.
func TestRegression_IdentityHBACRollbackReportsItsResult(t *testing.T) {
	const block = "Transactional HBAC allow_all lockdown"
	const failTask = "Fail after HBAC lockdown rollback"
	vars := map[string]any{
		"ipa_hbac_disable_allow_all": true,
		"ipa_hbac_rules":             []any{}, // no break-glass rule: the block's first gate fails
		"ipa_hbac_allow_all_show":    map[string]any{"stdout": ""},
		"identity_hbac_test_host":    "ipa1.ipa.pilot.internal",
	}
	for _, tc := range []struct{ name, enable, want string }{
		{"rollback works", "hbacrule-enable-allow-all", "allow_all was re-enabled."},
		{"rollback fails", "no-kerberos-ticket", "re-enabling allow_all FAILED (rc=1: ipa: ERROR: did not receive Kerberos credentials); check HBAC access now."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeIPA(t, map[string]string{"hbacrule-enable allow_all": tc.enable})
			res := runIdentityTasks(t, []string{block}, vars)
			if msg := failureOf(res, failTask); !strings.Contains(msg, tc.want) {
				t.Fatalf("rollback message %q, want %q; failures %v", msg, tc.want, res.failures)
			}
		})
	}
}

// identityFailedWhenFalse lists, for every task in the identity playbook
// (blocks, rescue and always included) whose failed_when is literally false,
// why ignoring the result is safe. A new task with failed_when: false must
// be added here with its reason, or fail on its own errors.
var identityFailedWhenFalse = map[string]string{
	"Look up password state for users with a declared password":                     `"Gate: the password state of every declared password was read" fails the run`,
	"Set password for users that need one (first-time onboard, or requested reset)": `"Gate: every password this run set was accepted" fails the run; no_log would hide the user here`,
	"Rollback HBAC lockdown by re-enabling allow_all":                               `rescue; the next task always fails and reports whether the rollback worked`,
	// Known gaps with their own issues:
	"Look up the current live DNS A record for the query target host (read-only, decommission verify)": "issue #105: the error text of a FreeIPA without integrated DNS is not captured yet, so errors cannot be told apart",
	"Check the current DNS A record value for each absent host's owner (surgical delete step 1)":       "issue #105: same as the verify DNS query",
}

func TestRegression_IdentityFailedWhenFalseIsAllowlisted(t *testing.T) {
	raw, err := os.ReadFile(identityApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var found []string
	var walk func(tasks []any)
	walk = func(tasks []any) {
		for _, r := range tasks {
			task, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if v, ok := task["failed_when"].(bool); ok && !v {
				name, _ := task["name"].(string)
				found = append(found, name)
			}
			for _, k := range []string{"block", "rescue", "always"} {
				if sub, ok := task[k].([]any); ok {
					walk(sub)
				}
			}
		}
	}
	for _, play := range plays {
		for _, k := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			if tasks, ok := play[k].([]any); ok {
				walk(tasks)
			}
		}
	}
	for _, name := range found {
		if _, ok := identityFailedWhenFalse[name]; !ok {
			t.Errorf("task %q ignores its own failures (failed_when: false); make it fail on errors, or list it in identityFailedWhenFalse with the reason that is safe", name)
		}
	}
	for name := range identityFailedWhenFalse {
		if !slices.Contains(found, name) {
			t.Errorf("identityFailedWhenFalse lists %q, which no longer has failed_when: false; remove it", name)
		}
	}
}

// Removing a roster host: the gates before host-del run only for a lookup
// that worked, and host-del does not wait for them. A failed service-find
// (exit 1, like "no match") used to skip the unknown-service gate and
// delete the host anyway.
func TestRegression_IdentityAbsentHostLookupsStopBeforeHostDel(t *testing.T) {
	const svcLookup = "Look up services managed by each absent host (spec.md §16.6) — separate from host-show, which never lists them"
	const hostDel = "host-del pwc-host.ipa.pilot.internal"
	names := []string{
		"Look up the current live host object for each absent roster host (spec.md §16.6/§16.7)",
		svcLookup,
		"Gate: no unknown/unproven service principal remains before deleting an absent host",
		"Delete the FreeIPA host object for each roster host marked absent (spec.md §16.3 step 5)",
	}
	vars := map[string]any{"freeipa_absent_hosts": []any{
		map[string]any{"name": "pwc-host.ipa.pilot.internal", "state": "absent", "ip_address": "192.168.122.251"},
	}}
	for _, tc := range []struct {
		name, show, services, del string
		wantDel, wantFail         bool
	}{
		{"no services: deleted", "host-show-existing", "service-find-no-match", "host-del", true, false},
		{"already gone", "host-show-not-found", "service-find-no-match", "host-del-not-found", true, false},
		{"service lookup error stops the run", "host-show-existing", "no-kerberos-ticket", "host-del", false, true},
		{"host lookup error stops the run", "no-kerberos-ticket", "service-find-no-match", "host-del", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeIPA(t, map[string]string{
				"host-show pwc-host.ipa.pilot.internal":                   tc.show,
				"service-find --man-by-hosts=pwc-host.ipa.pilot.internal": tc.services,
				hostDel: tc.del,
			})
			res := runIdentityTasks(t, names, vars)
			if failed := res.rc != 0; failed != tc.wantFail {
				t.Fatalf("rc=%d failures=%v, want failure: %v", res.rc, res.failures, tc.wantFail)
			}
			if got := slices.Contains(calls(), hostDel); got != tc.wantDel {
				t.Fatalf("host-del ran: %v, want %v; calls %v", got, tc.wantDel, calls())
			}
		})
	}
}

// Issue #104: the decommission reference queries list every rule. `find`
// exits 1 when there is no rule at all and 0, with a stderr warning, when
// the listing is truncated; a truncated or failed listing must stop the
// run rather than read as "no rule names the host".
func TestRegression_IdentityRuleReferenceQueriesStopOnErrors(t *testing.T) {
	for _, q := range []struct{ kind, task, find string }{
		{"hbac_references", "Look up direct HBAC rules referencing the query target host (read-only, decommission verify)", "hbacrule-find --all --sizelimit=0"},
		{"sudo_references", "Look up direct sudo rules referencing the query target host (read-only, decommission verify)", "sudorule-find --all --sizelimit=0"},
	} {
		vars := map[string]any{"pilot_decommission_query": q.kind, "pilot_decommission_target_fqdn": "pwr-host3.ipa.pilot.internal"}
		for _, tc := range []struct {
			name, answer string
			wantFail     bool
		}{
			{"rules listed", "sudorule-find-some", false},
			{"no rule at all", "sudorule-find-no-rules", false},
			{"truncated listing", "hbacrule-find-truncated", true},
			{"lookup error", "no-kerberos-ticket", true},
		} {
			t.Run(q.kind+"/"+tc.name, func(t *testing.T) {
				fakeIPA(t, map[string]string{q.find: tc.answer})
				res := runIdentityTasks(t, []string{q.task}, vars)
				if failed := res.rc != 0; failed != tc.wantFail || (tc.wantFail && failureOf(res, q.task) == "") {
					t.Fatalf("rc=%d failures=%v, want failure at the query: %v", res.rc, res.failures, tc.wantFail)
				}
			})
		}
	}
}
