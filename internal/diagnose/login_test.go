package diagnose

import (
	"strings"
	"testing"
)

func TestLoginSteps_HostAndPerUserSteps(t *testing.T) {
	steps := LoginSteps("web1", []string{"alice", "bob"})
	byID := map[string]Step{}
	for _, s := range steps {
		if _, dup := byID[s.ID]; dup {
			t.Fatalf("duplicate step ID %q", s.ID)
		}
		byID[s.ID] = s
	}

	for _, id := range []string{"sssd-active", "kerberos-keytab", "sssd-domain-status", "resolv-nameserver", "nss-resolve"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing host-level step %q", id)
		}
	}
	for _, user := range []string{"alice", "bob"} {
		g, ok := byID["getent-passwd:"+user]
		if !ok {
			t.Fatalf("missing getent-passwd step for %s", user)
		}
		if g.Command != "getent passwd "+user {
			t.Fatalf("getent-passwd:%s command = %q, want %q", user, g.Command, "getent passwd "+user)
		}
		if g.Module != "command" {
			t.Fatalf("getent-passwd:%s module = %q, want \"command\"", user, g.Module)
		}
		s, ok := byID["sudo-l:"+user]
		if !ok {
			t.Fatalf("missing sudo-l step for %s", user)
		}
		if s.Command != "sudo -l -U "+user {
			t.Fatalf("sudo-l:%s command = %q, want %q", user, s.Command, "sudo -l -U "+user)
		}
	}
	// nss-resolve/direct-resolve are the DNS name-resolution pair, keyed
	// against host — confirms LoginSteps threads host into DNSSteps rather
	// than only running the always-on facts.
	if byID["nss-resolve"].Command != "getent hosts web1" {
		t.Fatalf("nss-resolve command = %q, want to target host web1", byID["nss-resolve"].Command)
	}
}

func TestBuildLoginHostOutput_VerdictBranches(t *testing.T) {
	allGood := []StepResult{
		stepResult("sssd-active", 0, "active"),
		stepResult("kerberos-keytab", 0, "host/web1@REALM"),
		stepResult("sssd-domain-status", 0, "Domain: example.test\nOnline status: Online"),
		stepResult("resolv-nameserver", 0, "10.0.0.1"),
		stepResult("resolved-active", 0, "active"),
		stepResult("daemon-listening", 0, ""),
		stepResult("daemon-installed", 0, "0"),
		stepResult("nss-resolve", 0, "10.0.0.5 web1"),
		stepResult("direct-resolve", 0, "10.0.0.5"),
	}

	cases := []struct {
		name       string
		mutate     func([]StepResult) []StepResult
		checkField func(LoginHostOutput) bool
	}{
		{
			name:       "sssd down",
			mutate:     func(rs []StepResult) []StepResult { rs[0] = stepResult("sssd-active", 3, "inactive"); return rs },
			checkField: func(o LoginHostOutput) bool { return !o.SssdActive },
		},
		{
			name:       "no kerberos identity",
			mutate:     func(rs []StepResult) []StepResult { rs[1] = stepResult("kerberos-keytab", 1, ""); return rs },
			checkField: func(o LoginHostOutput) bool { return o.SssdActive && !o.HasKerberosMachineIdentity },
		},
		{
			name: "domain backend offline",
			mutate: func(rs []StepResult) []StepResult {
				rs[2] = stepResult("sssd-domain-status", 0, "Domain: example.test\nOnline status: Offline")
				return rs
			},
			checkField: func(o LoginHostOutput) bool {
				return o.SssdDomainStatusChecked && !o.SssdDomainOnline
			},
		},
		{
			name: "self-DNS does not resolve",
			mutate: func(rs []StepResult) []StepResult {
				rs[7] = stepResult("nss-resolve", 2, "")
				rs[8] = stepResult("direct-resolve", 0, "")
				return rs
			},
			checkField: func(o LoginHostOutput) bool {
				return !o.DNS.ResolvesViaNSS && !o.DNS.ResolvesViaDirectQuery
			},
		},
		{
			name:   "everything works",
			mutate: func(rs []StepResult) []StepResult { return rs },
			checkField: func(o LoginHostOutput) bool {
				return o.SssdActive && o.HasKerberosMachineIdentity && o.SssdDomainOnline
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := append([]StepResult(nil), allGood...)
			results = tc.mutate(results)
			out := BuildLoginHostOutput("web1", results)
			if !tc.checkField(out) {
				t.Fatalf("%s: BuildLoginHostOutput() = %+v, want condition to hold", tc.name, out)
			}
			if out.Verdict == "" {
				t.Fatalf("%s: Verdict is empty", tc.name)
			}
		})
	}
}

func TestBuildLoginUserOutput_VerdictBranches(t *testing.T) {
	goodHost := LoginHostOutput{SssdActive: true, HasKerberosMachineIdentity: true}
	goodSteps := []StepResult{
		stepResult("getent-passwd:alice", 0, "alice:x:1000:1000::/home/alice:/bin/bash"),
		stepResult("sudo-l:alice", 0, "(root) NOPASSWD: ALL"),
	}

	t.Run("host-level failure takes precedence", func(t *testing.T) {
		badHost := LoginHostOutput{SssdActive: false}
		out := BuildLoginUserOutput("alice", "web1", badHost, goodSteps, true, []string{"allow-sudo"}, []string{"allow-sudo"})
		if !strings.Contains(out.Verdict, "host-level failure") {
			t.Fatalf("Verdict = %q, want it to defer to the host-level failure", out.Verdict)
		}
	})

	t.Run("account does not resolve", func(t *testing.T) {
		steps := []StepResult{stepResult("getent-passwd:alice", 2, ""), stepResult("sudo-l:alice", 1, "")}
		out := BuildLoginUserOutput("alice", "web1", goodHost, steps, true, nil, nil)
		if out.AccountResolvesViaSSSD {
			t.Fatal("AccountResolvesViaSSSD = true, want false")
		}
		if !strings.Contains(out.Verdict, "cannot resolve") {
			t.Fatalf("Verdict = %q, want it to name the resolution failure", out.Verdict)
		}
	})

	t.Run("roster declares sudo but live host has none — drift", func(t *testing.T) {
		steps := []StepResult{stepResult("getent-passwd:alice", 0, "alice:x:1000:1000::/home/alice:/bin/bash"), stepResult("sudo-l:alice", 1, "not allowed")}
		out := BuildLoginUserOutput("alice", "web1", goodHost, steps, true, nil, []string{"allow-sudo"})
		if !strings.Contains(out.Verdict, "hasn't reconciled") {
			t.Fatalf("Verdict = %q, want it to flag config-declared-but-not-live drift", out.Verdict)
		}
	})

	t.Run("live sudo rule but roster does not declare it — drift", func(t *testing.T) {
		out := BuildLoginUserOutput("alice", "web1", goodHost, goodSteps, true, nil, nil)
		if !strings.Contains(out.Verdict, "roster does not declare") {
			t.Fatalf("Verdict = %q, want it to flag live-but-not-roster-declared drift", out.Verdict)
		}
	})

	t.Run("no HBAC rule authorizes this user", func(t *testing.T) {
		out := BuildLoginUserOutput("alice", "web1", goodHost, goodSteps, true, nil, []string{"allow-sudo"})
		if out.RosterHBACAuthorized {
			t.Fatal("RosterHBACAuthorized = true, want false")
		}
		if !strings.Contains(out.Verdict, "no roster HBAC rule") {
			t.Fatalf("Verdict = %q, want it to flag the missing HBAC rule", out.Verdict)
		}
	})

	t.Run("everything consistent", func(t *testing.T) {
		out := BuildLoginUserOutput("alice", "web1", goodHost, goodSteps, true, []string{"allow-login"}, []string{"allow-sudo"})
		if !out.AccountResolvesViaSSSD || !out.CentralSudoRuleGrantsAccess || !out.RosterHBACAuthorized || !out.RosterSudoAuthorized {
			t.Fatalf("out = %+v, want every fact true", out)
		}
		if !strings.Contains(out.Verdict, "no config/live drift") {
			t.Fatalf("Verdict = %q, want it to say no drift was found", out.Verdict)
		}
	})

	t.Run("roster unavailable never asserts a roster fact", func(t *testing.T) {
		out := BuildLoginUserOutput("alice", "web1", goodHost, goodSteps, false, []string{"would-be-ignored"}, nil)
		if out.RosterHBACAuthorized || out.RosterSudoAuthorized || out.RosterHBACRules != nil {
			t.Fatalf("out = %+v, want every roster field zero-valued when roster is unavailable", out)
		}
		if strings.Contains(out.Verdict, "declares") || strings.Contains(out.Verdict, "no roster HBAC rule authorizes") || strings.Contains(out.Verdict, "does not declare") {
			t.Fatalf("Verdict = %q, must not assert a roster authorization fact when roster was unavailable", out.Verdict)
		}
		if !strings.Contains(out.Verdict, "unavailable") {
			t.Fatalf("Verdict = %q, want it to explain the roster comparison was skipped", out.Verdict)
		}
	})
}

func TestLoginSecurityLogsQuery(t *testing.T) {
	got := LoginSecurityLogsQuery("web1", []string{"alice", "bob"})
	want := `{job="pilot-siem"} |= "web1" |~ "alice|bob"`
	if got != want {
		t.Fatalf("LoginSecurityLogsQuery() = %q, want %q", got, want)
	}

	if got := LoginSecurityLogsQuery("web1", nil); got != `{job="pilot-siem"} |= "web1"` {
		t.Fatalf("LoginSecurityLogsQuery() with no users = %q, want plain SecurityLogsQuery output", got)
	}

	// A username containing a regex metacharacter (only '.' is possible
	// given inventory.ValidRosterUserName's charset) must not change the
	// alternation's meaning.
	got = LoginSecurityLogsQuery("", []string{"svc.robot"})
	if !strings.Contains(got, `svc\.robot`) {
		t.Fatalf("LoginSecurityLogsQuery() = %q, want the '.' escaped", got)
	}
}
