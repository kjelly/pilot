package spec

import (
	"slices"
	"strings"
	"testing"
)

// Plan docs/superpowers/plans/2026-10-15-freeipa-go-ssh-reconcile.md, Phase
// −1: two `ipa user-find --pkey-only` listings let a rerun skip `user-add`
// for users that exist and `user-enable`/`-disable` for users already in the
// declared state. Before, every rerun made both calls for every user.
//
// The tests run the playbook's own tasks on localhost with the fake `ipa`
// from freeipa_identity_ipa_failures_regression_test.go, which answers with
// output captured from FreeIPA 4.13.4 (testdata/freeipa-ipa-cli/user-*). In
// the captured state the server has admin, uf-enabled (enabled) and
// uf-disabled (disabled).

var identityUserListingTasks = []string{
	"List existing IPA users",
	"List disabled IPA users",
	"Index the existing and the disabled IPA users",
	"Gate: the user listings were parsed completely",
	"Ensure IPA users exist",
	"Reconcile canonical account enabled state",
}

const (
	userFindAll      = "user-find --pkey-only --sizelimit=0 --timelimit=0"
	userFindDisabled = "user-find --disabled=True --pkey-only --sizelimit=0 --timelimit=0"
)

func listingUser(name string, enabled bool) map[string]any {
	return map[string]any{"name": name, "first": "User", "last": "Listing", "enabled": enabled}
}

func runUserListing(t *testing.T, answers map[string]string, users []any, args ...string) (ag82Run, []string) {
	t.Helper()
	calls := fakeIPA(t, answers)
	res := runIdentityTasks(t, identityUserListingTasks, map[string]any{
		"ipa_active_users": users,
		"freeipa_roster":   map[string]any{"schema_version": 2},
	}, args...)
	return res, calls()
}

func TestRegression_IdentityUserListingSkipsNoOpCalls(t *testing.T) {
	listings := map[string]string{userFindAll: "user-find-pkey-all", userFindDisabled: "user-find-pkey-disabled"}

	t.Run("users already in the declared state get no calls", func(t *testing.T) {
		// A roster name in another case is the same FreeIPA login.
		users := []any{listingUser("UF-Enabled", true), listingUser("uf-disabled", false)}
		res, calls := runUserListing(t, listings, users)
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if want := []string{userFindAll, userFindDisabled}; !slices.Equal(calls, want) {
			t.Fatalf("ipa calls = %q, want only the two listings", calls)
		}
	})

	t.Run("new users and state changes still get their calls", func(t *testing.T) {
		answers := maps(maps(maps(maps(listings,
			"user-add uf-new --first=User --last=Listing", "user-add-new"),
			"user-enable uf-new", "user-enable-already-enabled"),
			"user-disable uf-enabled", "user-disable"),
			"user-enable uf-disabled", "user-enable")
		users := []any{listingUser("uf-new", true), listingUser("uf-enabled", false), listingUser("uf-disabled", true)}
		res, calls := runUserListing(t, answers, users)
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		want := []string{
			userFindAll, userFindDisabled,
			"user-add uf-new --first=User --last=Listing",
			"user-enable uf-new", "user-disable uf-enabled", "user-enable uf-disabled",
		}
		if !slices.Equal(calls, want) {
			t.Fatalf("ipa calls = %q, want %q", calls, want)
		}
		for _, task := range []string{"Ensure IPA users exist", "Reconcile canonical account enabled state"} {
			if !res.changed[task] {
				t.Fatalf("%s must report changed", task)
			}
		}
	})

	t.Run("no disabled users is an answer, not an error", func(t *testing.T) {
		answers := maps(maps(listings, userFindDisabled, "user-find-pkey-disabled-none"),
			"user-disable uf-enabled", "user-disable")
		users := []any{listingUser("uf-enabled", false)}
		res, calls := runUserListing(t, answers, users)
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if want := []string{userFindAll, userFindDisabled, "user-disable uf-enabled"}; !slices.Equal(calls, want) {
			t.Fatalf("ipa calls = %q, want %q", calls, want)
		}
	})

	// The listings are reads, so --check runs them and the gate; the writes
	// stay skipped as before.
	t.Run("check mode reads the listings and writes nothing", func(t *testing.T) {
		users := []any{listingUser("uf-new", true), listingUser("uf-enabled", false)}
		res, calls := runUserListing(t, listings, users, "--check")
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if want := []string{userFindAll, userFindDisabled}; !slices.Equal(calls, want) {
			t.Fatalf("ipa calls = %q, want only the two listings", calls)
		}
	})
}

// Each way a listing can be incomplete stops the run before any user call.
func TestRegression_IdentityUserListingFailsClosed(t *testing.T) {
	users := []any{listingUser("uf-enabled", true)}
	for _, tc := range []struct {
		name, args, fixture, task, want string
	}{
		{"no Kerberos ticket", userFindAll, "no-kerberos-ticket", "List existing IPA users", ""},
		{"truncated listing", userFindAll, "user-find-pkey-truncated", "List existing IPA users", ""},
		{"truncated disabled listing", userFindDisabled, "user-find-pkey-truncated", "List disabled IPA users", ""},
		// The CLI prints the server's system language (/etc/locale.conf
		// sets LANG for ssh sessions) when it is installed there.
		{"a listing in another language", userFindAll, "user-find-pkey-de", "Gate: the user listings were parsed completely", "cannot parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answers := maps(map[string]string{userFindAll: "user-find-pkey-all", userFindDisabled: "user-find-pkey-disabled"}, tc.args, tc.fixture)
			res, calls := runUserListing(t, answers, users)
			if res.rc == 0 {
				t.Fatalf("expected the run to fail\n%s", res.raw)
			}
			msg := failureOf(res, tc.task)
			if msg == "" || !strings.Contains(msg, tc.want) {
				t.Fatalf("want a failure in %q containing %q, got failures %v", tc.task, tc.want, res.failures)
			}
			for _, c := range calls {
				if !strings.HasPrefix(c, "user-find ") {
					t.Fatalf("a user call ran after an incomplete listing: %q", calls)
				}
			}
		})
	}
}
