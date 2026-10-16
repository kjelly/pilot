package spec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// PR #119 review: membership removals compared names case-sensitively. A
// roster may spell a group team-Child; FreeIPA stores and lists it as
// team-child (checked on 4.13.4: group, hostgroup, host and netgroup names
// come back in lower case; sudo commands keep their case and are found only
// by it). The canonical group task then removed team-child on every run,
// and once the adds skipped members the lookup had listed, it was never
// added back. Every removal now compares lower case on both sides, as the
// HBAC task already did; sudo commands stay case-sensitive.
//
// The outputs replayed here are real (testdata/freeipa-ipa-cli/case-*,
// group-remove-member-*, group-add-member-*), captured from objects created
// with mixed-case names.

var identityCanonicalMembershipTasks = []string{
	"Look up canonical group direct membership",
	"Compute stale canonical group membership",
	"Start the canonical group member index",
	"Index canonical group direct members",
	"Remove stale canonical direct users",
	"Remove stale canonical direct nested groups",
	"Ensure canonical direct user membership",
	"Ensure canonical direct nested-group membership",
}

func caseParent(users, groups []any) []any {
	return []any{map[string]any{"name": "P0Case-Parent", "membership": map[string]any{
		"authoritative": true, "users": users, "groups": groups}}}
}

func TestRegression_IdentityGroupMembershipIgnoresCase(t *testing.T) {
	roster := map[string]any{"schema_version": 2}
	show := map[string]string{"group-show P0Case-Parent --all": "case-group-show-parent"}

	// The roster gate already rejects upper-case logins; the user here
	// checks the comparison itself.
	t.Run("members spelled in another case are neither removed nor added", func(t *testing.T) {
		calls := fakeIPA(t, show)
		res := runIdentityTasks(t, identityCanonicalMembershipTasks, map[string]any{
			"freeipa_roster": roster, "ipa_active_groups": caseParent([]any{"P0CASE-USER"}, []any{"P0Case-Child"})})
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if got := calls(); !slices.Equal(got, []string{"group-show P0Case-Parent --all"}) {
			t.Fatalf("ipa calls = %q, want only the lookup", got)
		}
	})

	t.Run("a member the roster dropped is still removed", func(t *testing.T) {
		calls := fakeIPA(t, maps(show, "group-remove-member P0Case-Parent --groups=p0case-child", "group-remove-member-group"))
		res := runIdentityTasks(t, identityCanonicalMembershipTasks, map[string]any{
			"freeipa_roster": roster, "ipa_active_groups": caseParent([]any{"p0case-user"}, []any{})})
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		want := []string{"group-show P0Case-Parent --all", "group-remove-member P0Case-Parent --groups=p0case-child"}
		if got := calls(); !slices.Equal(got, want) {
			t.Fatalf("ipa calls = %q, want %q", got, want)
		}
	})
}

// statefulGroupIPA is an `ipa` that keeps P0Case-Parent's direct members in
// files and applies group-add-member/group-remove-member to them, so two
// runs in a row see each other's effects. group-show prints the fields of
// the case-group-show-parent capture; the add and remove answers are the
// captured ones. It returns the calls of the run so far and the members.
func statefulGroupIPA(t *testing.T, users, groups []string) (calls func() []string, members func() ([]string, []string), reset func()) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, v []string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(v, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("users", users)
	write("groups", groups)
	fx, err := filepath.Abs(ipaCLIFixtures)
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/bash
D="` + dir + `"
printf '%s\n' "$*" >> "$D/calls.log"
list() { grep -v '^$' "$D/$1" | paste -sd, - | sed 's/,/, /g'; }
case "$1" in
group-show)
  printf '  Group name: p0case-parent\n  Description: x\n  GID: 1927600214\n'
  u=$(list users); g=$(list groups)
  [ -n "$u" ] && printf '  Member users: %s\n' "$u"
  [ -n "$g" ] && printf '  Member groups: %s\n' "$g"
  exit 0 ;;
group-remove-member|group-add-member)
  kind=${3%%=*}; kind=${kind#--}; name=$(printf '%s' "${3#*=}" | tr A-Z a-z)
  f="$D/$kind"
  grep -vx "$name" "$f" > "$f.new"; mv "$f.new" "$f"
  if [ "$1" = group-add-member ]; then echo "$name" >> "$f"; base=group-add-member-${kind%s}
  else base=group-remove-member-${kind%s}; fi
  cat "` + fx + `/$base.stdout"; exit 0 ;;
esac
echo "fake ipa: unexpected call: $*" >&2; exit 99
`
	if err := os.WriteFile(filepath.Join(dir, "ipa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	read := func(name string) []string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			t.Fatal(err)
		}
		var out []string
		for _, l := range strings.Split(string(raw), "\n") {
			if l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	return func() []string { return read("calls.log") },
		func() ([]string, []string) { return read("users"), read("groups") },
		func() { _ = os.Remove(filepath.Join(dir, "calls.log")) }
}

// The review's scenario end to end: the roster spells the nested group in
// another case. Before the fix the first run removed it and skipped adding
// it back; now both runs leave it alone.
func TestRegression_IdentityMixedCaseMemberSurvivesTwoRuns(t *testing.T) {
	calls, members, reset := statefulGroupIPA(t, []string{"p0case-user"}, []string{"p0case-child"})
	vars := map[string]any{
		"freeipa_roster":    map[string]any{"schema_version": 2},
		"ipa_active_groups": caseParent([]any{"p0case-user"}, []any{"P0Case-Child"}),
	}
	for run := 1; run <= 2; run++ {
		reset()
		res := runIdentityTasks(t, identityCanonicalMembershipTasks, vars)
		if res.rc != 0 {
			t.Fatalf("run %d: rc=%d failures=%v\n%s", run, res.rc, res.failures, res.raw)
		}
		if got := calls(); !slices.Equal(got, []string{"group-show P0Case-Parent --all"}) {
			t.Fatalf("run %d: ipa calls = %q, want only the lookup", run, got)
		}
		users, groups := members()
		if !slices.Equal(users, []string{"p0case-user"}) || !slices.Equal(groups, []string{"p0case-child"}) {
			t.Fatalf("run %d: members = %v %v, want p0case-user and p0case-child", run, users, groups)
		}
	}
}

// computeOnly runs one "Compute stale …" task against a registered lookup
// result and returns the fact it builds, read back through a debug task.
func computeOnly(t *testing.T, task, fact string, vars map[string]any) []map[string]any {
	t.Helper()
	tasks := []any{}
	for _, tk := range identityPlaybookTasks(t, []string{task}) {
		tasks = append(tasks, tk)
	}
	tasks = append(tasks, map[string]any{"name": "dump", "ansible.builtin.debug": map[string]any{"msg": "{{ " + fact + " | default([]) | to_json }}"}})
	// The vars go in as JSON extra vars: the play's YAML would drop the
	// two-space indent the captured output starts each line with.
	dir := t.TempDir()
	varsFile := filepath.Join(dir, "vars.json")
	raw, err := json.Marshal(vars)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(varsFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	res := runGatewayTasks(t, dir, tasks, nil, nil, "-e", "@"+varsFile)
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
	}
	for _, m := range res.messages {
		if msg, ok := strings.CutPrefix(m, "dump: "); ok {
			var s string
			var out []map[string]any
			if err := json.Unmarshal([]byte(msg), &s); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
	}
	t.Fatalf("no dump message in %v", res.messages)
	return nil
}

func lookupResult(t *testing.T, item map[string]any, fixture string) map[string]any {
	t.Helper()
	out, err := os.ReadFile(filepath.Join(ipaCLIFixtures, fixture+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"results": []any{map[string]any{"item": item, "stdout": string(out), "rc": 0}}}
}

func stale(t *testing.T, removals []map[string]any, key string) []string {
	t.Helper()
	if len(removals) != 1 {
		t.Fatalf("removals = %v, want one entry", removals)
	}
	var out []string
	for _, v := range removals[0][key].([]any) {
		out = append(out, v.(string))
	}
	return out
}

const caseHost = "P0Case-Host.ipa.pilot.internal"

// The same comparison in the legacy, hostgroup, netgroup and sudo tasks:
// mixed-case roster names are not stale, a dropped member still is, and sudo
// commands keep their case.
func TestRegression_IdentityRemovalsIgnoreCaseEverywhere(t *testing.T) {
	t.Run("legacy group membership", func(t *testing.T) {
		vars := func(groups []any) map[string]any {
			return map[string]any{
				"freeipa_roster":    map[string]any{},
				"ipa_active_groups": []any{map[string]any{"name": "P0Case-Parent"}},
				"ipa_user_show":     lookupResult(t, map[string]any{"name": "p0case-user", "groups": groups}, "case-user-show"),
			}
		}
		const task, fact = "Compute stale group memberships to remove", "ipa_group_membership_removals"
		if got := stale(t, computeOnly(t, task, fact, vars([]any{"P0Case-Parent"})), "groups"); len(got) != 0 {
			t.Fatalf("stale = %v, want none", got)
		}
		if got := stale(t, computeOnly(t, task, fact, vars([]any{})), "groups"); !slices.Equal(got, []string{"p0case-parent"}) {
			t.Fatalf("stale = %v, want p0case-parent", got)
		}
	})

	t.Run("hostgroup membership", func(t *testing.T) {
		vars := func(hosts, hostgroups []any) map[string]any {
			return map[string]any{"ipa_hostgroup_show": lookupResult(t,
				map[string]any{"name": "P0Case-HG", "hosts": hosts, "hostgroups": hostgroups}, "case-hostgroup-show")}
		}
		const task, fact = "Compute stale hostgroup memberships to remove", "ipa_hostgroup_membership_removals"
		r := computeOnly(t, task, fact, vars([]any{caseHost}, []any{"P0Case-HG2"}))
		if len(stale(t, r, "hosts")) != 0 || len(stale(t, r, "hostgroups")) != 0 {
			t.Fatalf("removals = %v, want none", r)
		}
		r = computeOnly(t, task, fact, vars([]any{}, []any{}))
		if !slices.Equal(stale(t, r, "hosts"), []string{"p0case-host"}) || !slices.Equal(stale(t, r, "hostgroups"), []string{"p0case-hg2"}) {
			t.Fatalf("removals = %v, want the host and the nested hostgroup", r)
		}
	})

	t.Run("netgroup membership", func(t *testing.T) {
		vars := func(m map[string]any) map[string]any {
			m["authoritative"] = true
			return map[string]any{"ipa_netgroup_show": lookupResult(t, map[string]any{"name": "P0Case-NG", "membership": m}, "case-netgroup-show")}
		}
		const task, fact = "Compute stale netgroup memberships to remove", "ipa_netgroup_membership_removals"
		r := computeOnly(t, task, fact, vars(map[string]any{
			"users": []any{"p0case-user"}, "groups": []any{"P0Case-Child"}, "hosts": []any{caseHost},
			"hostgroups": []any{"P0Case-HG"}, "netgroups": []any{"P0Case-NG2"}}))
		for _, k := range []string{"users", "groups", "hosts", "hostgroups", "netgroups"} {
			if got := stale(t, r, k); len(got) != 0 {
				t.Fatalf("stale %s = %v, want none", k, got)
			}
		}
		r = computeOnly(t, task, fact, vars(map[string]any{
			"users": []any{"p0case-user"}, "groups": []any{}, "hosts": []any{caseHost}, "hostgroups": []any{"P0Case-HG"}, "netgroups": []any{}}))
		if !slices.Equal(stale(t, r, "groups"), []string{"p0case-child"}) || !slices.Equal(stale(t, r, "netgroups"), []string{"p0case-ng2"}) {
			t.Fatalf("removals = %v, want the group and the nested netgroup", r)
		}
	})

	t.Run("sudo rule attachments", func(t *testing.T) {
		vars := func(cmds []any, groups []any) map[string]any {
			return map[string]any{"ipa_sudorule_show": lookupResult(t, map[string]any{
				"name": "P0Case-Sudo", "hosts": []any{caseHost}, "hostgroups": []any{"P0Case-HG"},
				"users": []any{"p0case-user"}, "groups": groups, "allow_commands": cmds}, "case-sudorule-show")}
		}
		const task, fact = "Compute sudo rule attachments to remove", "ipa_sudo_removals"
		r := computeOnly(t, task, fact, vars([]any{"/usr/bin/P0CaseCmd"}, []any{"P0Case-Child"}))
		for _, k := range []string{"hosts", "hostgroups", "users", "groups", "allow_commands"} {
			if got := stale(t, r, k); len(got) != 0 {
				t.Fatalf("stale %s = %v, want none", k, got)
			}
		}
		// FreeIPA finds a sudo command only by its exact case, so a command
		// spelled differently is a different command.
		r = computeOnly(t, task, fact, vars([]any{"/usr/bin/p0casecmd"}, []any{}))
		if !slices.Equal(stale(t, r, "allow_commands"), []string{"/usr/bin/P0CaseCmd"}) || !slices.Equal(stale(t, r, "groups"), []string{"p0case-child"}) {
			t.Fatalf("removals = %v, want the command and the group", r)
		}
	})
}
