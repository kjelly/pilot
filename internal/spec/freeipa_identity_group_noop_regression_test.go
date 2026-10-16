package spec

import (
	"slices"
	"strings"
	"testing"
)

// Plan docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md, Phase
// −1, the group follow-up to the user listings: an `ipa group-find
// --pkey-only` listing lets a rerun skip `group-add` for groups that exist,
// and the direct members the membership lookup already reads let it skip
// `group-add-member` for users and groups that are members. Before, every
// rerun made each of those calls.
//
// The tests run the playbook's own tasks on localhost with the fake `ipa`
// from freeipa_identity_ipa_failures_regression_test.go, answering with
// output captured from FreeIPA 4.13.4 (testdata/freeipa-ipa-cli/group-*):
// team-pwb-01 has direct member users pwb-u001…pwb-u111, and access-pwb-01
// has the member group team-pwb-01, so those users are its indirect members.

var identityGroupListingTasks = []string{
	"List existing IPA groups",
	"Index the existing IPA groups",
	"Gate: the group listing was parsed completely",
	"Ensure IPA groups exist",
}

var identityGroupMemberTasks = []string{
	"Look up canonical group direct membership",
	"Start the canonical group member index",
	"Index canonical group direct members",
	"Ensure canonical direct user membership",
	"Ensure canonical direct nested-group membership",
}

const groupFindAll = "group-find --pkey-only --sizelimit=0 --timelimit=0"

func TestRegression_IdentityGroupListingSkipsExistingGroups(t *testing.T) {
	// A roster name in another case is the same FreeIPA group.
	groups := []any{
		map[string]any{"name": "Team-PWB-01", "desc": "Bench team 1"},
		map[string]any{"name": "gf-new", "desc": "Listing"},
	}
	answers := map[string]string{groupFindAll: "group-find-pkey-all", "group-add gf-new --desc=Listing": "group-add-new"}

	t.Run("only a group missing from the listing is added", func(t *testing.T) {
		calls := fakeIPA(t, answers)
		res := runIdentityTasks(t, identityGroupListingTasks, map[string]any{"ipa_active_groups": groups})
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if got, want := calls(), []string{groupFindAll, "group-add gf-new --desc=Listing"}; !slices.Equal(got, want) {
			t.Fatalf("ipa calls = %q, want %q", got, want)
		}
		if !res.changed["Ensure IPA groups exist"] {
			t.Fatalf("adding a group must report changed")
		}
	})

	t.Run("check mode reads the listing and adds nothing", func(t *testing.T) {
		calls := fakeIPA(t, answers)
		res := runIdentityTasks(t, identityGroupListingTasks, map[string]any{"ipa_active_groups": groups}, "--check")
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if got := calls(); !slices.Equal(got, []string{groupFindAll}) {
			t.Fatalf("ipa calls = %q, want only the listing", got)
		}
	})

	for _, tc := range []struct{ name, fixture, task, want string }{
		{"no Kerberos ticket", "no-kerberos-ticket", "List existing IPA groups", ""},
		{"truncated listing", "group-find-pkey-truncated", "List existing IPA groups", ""},
		{"a listing in another language", "group-find-pkey-de", "Gate: the group listing was parsed completely", "cannot parse"},
	} {
		t.Run(tc.name+" stops the run before any group-add", func(t *testing.T) {
			calls := fakeIPA(t, maps(answers, groupFindAll, tc.fixture))
			res := runIdentityTasks(t, identityGroupListingTasks, map[string]any{"ipa_active_groups": groups})
			if res.rc == 0 {
				t.Fatalf("expected the run to fail\n%s", res.raw)
			}
			if msg := failureOf(res, tc.task); msg == "" || !strings.Contains(msg, tc.want) {
				t.Fatalf("want a failure in %q containing %q, got failures %v", tc.task, tc.want, res.failures)
			}
			if got := calls(); !slices.Equal(got, []string{groupFindAll}) {
				t.Fatalf("ipa calls = %q, want only the listing", got)
			}
		})
	}
}

func TestRegression_IdentityGroupMembershipSkipsCurrentMembers(t *testing.T) {
	groups := []any{
		map[string]any{"name": "team-pwb-01", "membership": map[string]any{
			"users": []any{"pwb-u001", "PWB-U011", "uf-enabled"}, "groups": []any{}}},
		// pwb-u001 is only an indirect member here, so it is still added
		// directly.
		map[string]any{"name": "access-pwb-01", "membership": map[string]any{
			"users": []any{"pwb-u001"}, "groups": []any{"team-pwb-01", "team-pwb-02"}}},
	}
	vars := map[string]any{"ipa_active_groups": groups, "freeipa_roster": map[string]any{"schema_version": 2}}
	answers := map[string]string{
		"group-show team-pwb-01 --all":                        "group-show-team",
		"group-show access-pwb-01 --all":                      "group-show-nested",
		"group-add-member team-pwb-01 --users=uf-enabled":     "group-add-member-user",
		"group-add-member access-pwb-01 --users=pwb-u001":     "group-add-member-user",
		"group-add-member access-pwb-01 --groups=team-pwb-02": "group-add-member-group",
	}

	t.Run("only members missing from the lookup are added", func(t *testing.T) {
		calls := fakeIPA(t, answers)
		res := runIdentityTasks(t, identityGroupMemberTasks, vars)
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		want := []string{
			"group-show team-pwb-01 --all", "group-show access-pwb-01 --all",
			"group-add-member team-pwb-01 --users=uf-enabled",
			"group-add-member access-pwb-01 --users=pwb-u001",
			"group-add-member access-pwb-01 --groups=team-pwb-02",
		}
		if got := calls(); !slices.Equal(got, want) {
			t.Fatalf("ipa calls = %q, want %q", got, want)
		}
		for _, task := range []string{"Ensure canonical direct user membership", "Ensure canonical direct nested-group membership"} {
			if !res.changed[task] {
				t.Fatalf("%s must report changed", task)
			}
		}
	})

	// The lookups are skipped in check mode; the index must stay usable.
	t.Run("check mode runs without the lookups", func(t *testing.T) {
		calls := fakeIPA(t, answers)
		res := runIdentityTasks(t, identityGroupMemberTasks, vars, "--check")
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if got := calls(); len(got) != 0 {
			t.Fatalf("check mode made ipa calls: %q", got)
		}
	})
}
