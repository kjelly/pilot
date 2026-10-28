package spec

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Issue #155: freeipa-identity-apply.yml registers an A record for every
// present roster host with `ipa dnsrecord-add`. A FreeIPA server installed
// with freeipa_setup_dns: false answers every DNS command with rc 2 and
// stderr `ipa: ERROR: DNS is not configured`, and the task failed the whole
// apply on it. Its `changed_when` also looked for an "Added record" line that
// the real command never prints, so a record that was added reported ok.
//
// The fake `ipa` replays output captured from FreeIPA 4.13.4
// (testdata/freeipa-ipa-cli/dnsrecord-add-*): on a server with integrated
// DNS for the added / already-present / zone-not-found / no-ticket /
// API-unreachable outcomes, and on one installed with freeipa_setup_dns: false
// for "DNS is not configured".

func TestRegression_IdentityHostDNSRecords(t *testing.T) {
	const (
		task   = "Ensure canonical host DNS A records exist"
		report = "Report roster hosts whose DNS A record was skipped (FreeIPA DNS not configured)"
		web1   = "dnsrecord-add ipa.pilot.internal i155-web01 --a-rec=192.168.122.201"
		web2   = "dnsrecord-add ipa.pilot.internal i155-web02 --a-rec=192.168.122.202"
	)
	vars := map[string]any{
		"ipa_domain": "ipa.pilot.internal",
		"freeipa_roster": map[string]any{"schema_version": 2, "hosts": []any{
			map[string]any{"name": "i155-web01.ipa.pilot.internal", "state": "present", "ip_address": "192.168.122.201"},
			map[string]any{"name": "i155-web02.ipa.pilot.internal", "state": "present", "ip_address": "192.168.122.202"},
			map[string]any{"name": "i155-gone.ipa.pilot.internal", "state": "absent", "ip_address": "192.168.122.203"},
		}},
	}
	reportMessage := func(res ag82Run) string {
		for _, m := range res.messages {
			if strings.HasPrefix(m, report+": ") {
				return m
			}
		}
		return ""
	}

	for _, tc := range []struct {
		name     string
		fixture  string
		wantFail bool
		// wantChanged is whether the task reports a change; wantSkipMsg is
		// whether the visible "DNS is not configured" report is printed.
		wantChanged, wantSkipMsg bool
	}{
		// should pass
		{"record added is a change", "dnsrecord-add-new", false, true, false},
		{"record already present is ok, not a change", "dnsrecord-add-duplicate", false, false, false},
		{"DNS not configured is skipped and reported", "dnsrecord-add-dns-not-configured", false, false, true},
		// should trigger
		{"zone not found fails the run", "dnsrecord-add-zone-not-found", true, false, false},
		{"no Kerberos ticket fails the run", "dnsrecord-add-no-kerberos-ticket", true, false, false},
		{"API unreachable fails the run", "dnsrecord-add-api-unreachable", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeIPA(t, map[string]string{web1: tc.fixture, web2: tc.fixture})
			res := runIdentityTasks(t, []string{task, report}, vars)
			if failed := res.rc != 0; failed != tc.wantFail || (tc.wantFail && failureOf(res, task) == "") {
				t.Fatalf("rc=%d failures=%v, want a failure at %q: %v\n%s", res.rc, res.failures, task, tc.wantFail, res.raw)
			}
			if tc.wantFail {
				// The skip report must not hide a real failure behind a
				// "skipped" message.
				if reportMessage(res) != "" {
					t.Fatalf("report printed for a failing run: %v", res.messages)
				}
				return
			}
			if res.changed[task] != tc.wantChanged {
				t.Fatalf("task changed=%v, want %v\n%s", res.changed[task], tc.wantChanged, res.raw)
			}
			if got := reportMessage(res) != ""; got != tc.wantSkipMsg {
				t.Fatalf("skip report printed=%v, want %v; messages %v", got, tc.wantSkipMsg, res.messages)
			}
			// A host marked absent never gets a record.
			for _, c := range calls() {
				if strings.Contains(c, "i155-gone") {
					t.Fatalf("absent host got a DNS call: %v", calls())
				}
			}
			if tc.wantSkipMsg {
				msg := reportMessage(res)
				for _, want := range []string{"2 roster host(s)", "i155-web01.ipa.pilot.internal", "i155-web02.ipa.pilot.internal", "DNS is not configured"} {
					if !strings.Contains(msg, want) {
						t.Fatalf("skip report %q lacks %q", msg, want)
					}
				}
				if strings.Contains(msg, "i155-gone") {
					t.Fatalf("skip report names an absent host: %q", msg)
				}
			}
		})
	}

	// Same stderr text with the wrong exit code is not the captured
	// "DNS is not configured" outcome; it must not be waved through.
	t.Run("the message alone, with another exit code, fails", func(t *testing.T) {
		fx := fixtureWithRC(t, "dnsrecord-add-dns-not-configured", "1\n")
		fakeIPA(t, map[string]string{web1: fx, web2: fx})
		res := runIdentityTasks(t, []string{task, report}, vars)
		if res.rc == 0 || failureOf(res, task) == "" {
			t.Fatalf("expected failure at %q, rc=%d failures=%v", task, res.rc, res.failures)
		}
	})

	// A different line mentioning DNS is not the captured message either.
	t.Run("another DNS error on the same exit code fails", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{web1: "dnsrecord-add-zone-not-found", web2: "dnsrecord-add-dns-not-configured"})
		res := runIdentityTasks(t, []string{task, report}, vars)
		if res.rc == 0 || failureOf(res, task) == "" {
			t.Fatalf("expected failure at %q, rc=%d failures=%v", task, res.rc, res.failures)
		}
		if !slices.Contains(calls(), web1) {
			t.Fatalf("first host not attempted: %v", calls())
		}
	})

	// check mode skips the command; the report must not fail on results that
	// have no rc or stderr.
	t.Run("check mode runs nothing and does not fail", func(t *testing.T) {
		calls := fakeIPA(t, map[string]string{web1: "dnsrecord-add-dns-not-configured", web2: "dnsrecord-add-dns-not-configured"})
		res := runIdentityTasks(t, []string{task, report}, vars, "--check")
		if res.rc != 0 {
			t.Fatalf("check mode failed: rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
		}
		if got := calls(); len(got) != 0 {
			t.Fatalf("check mode ran ipa: %v", got)
		}
		if reportMessage(res) != "" {
			t.Fatalf("report printed in check mode: %v", res.messages)
		}
	})

	// No hosts in the roster: nothing to register, nothing to report.
	t.Run("roster without hosts", func(t *testing.T) {
		fakeIPA(t, map[string]string{})
		res := runIdentityTasks(t, []string{task, report}, map[string]any{
			"ipa_domain":     "ipa.pilot.internal",
			"freeipa_roster": map[string]any{"schema_version": 2},
		})
		if res.rc != 0 || reportMessage(res) != "" {
			t.Fatalf("rc=%d messages=%v failures=%v", res.rc, res.messages, res.failures)
		}
	})
}

// fixtureWithRC copies a captured fixture into a temp dir with its exit code
// replaced; the stdout and stderr stay the captured bytes.
func fixtureWithRC(t *testing.T, fixture, rc string) string {
	t.Helper()
	base := filepath.Join(t.TempDir(), "fixture")
	for _, ext := range []string{".stdout", ".stderr"} {
		body, err := os.ReadFile(filepath.Join(ipaCLIFixtures, fixture+ext))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(base+ext, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(base+".rc", []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}
