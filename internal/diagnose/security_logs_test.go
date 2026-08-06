package diagnose

import "testing"

func TestSecurityLogsQuery_BareCallScopesToJobSelectorOnly(t *testing.T) {
	got := SecurityLogsQuery("", "")
	want := `{job="pilot-siem"}`
	if got != want {
		t.Fatalf("SecurityLogsQuery(\"\", \"\") = %q, want %q", got, want)
	}
}

func TestSecurityLogsQuery_HostAddsOneLineFilter(t *testing.T) {
	got := SecurityLogsQuery("web1", "")
	want := `{job="pilot-siem"} |= "web1"`
	if got != want {
		t.Fatalf("SecurityLogsQuery(%q, \"\") = %q, want %q", "web1", got, want)
	}
}

func TestSecurityLogsQuery_SearchAddsOneLineFilter(t *testing.T) {
	got := SecurityLogsQuery("", "Failed password")
	want := `{job="pilot-siem"} |= "Failed password"`
	if got != want {
		t.Fatalf("SecurityLogsQuery(\"\", %q) = %q, want %q", "Failed password", got, want)
	}
}

func TestSecurityLogsQuery_HostAndSearchChainInOrder(t *testing.T) {
	got := SecurityLogsQuery("web1", "sudo")
	want := `{job="pilot-siem"} |= "web1" |= "sudo"`
	if got != want {
		t.Fatalf("SecurityLogsQuery(%q, %q) = %q, want %q", "web1", "sudo", got, want)
	}
}

func TestSecurityLogsQuery_EmbeddedDoubleQuoteRoundTrips(t *testing.T) {
	got := SecurityLogsQuery(`agent"name`, "")
	want := `{job="pilot-siem"} |= "agent\"name"`
	if got != want {
		t.Fatalf("SecurityLogsQuery with an embedded double quote = %q, want %q", got, want)
	}
}

func TestSecurityLogsSteps_CurlQueryMatchesSecurityLogsQuery(t *testing.T) {
	steps := SecurityLogsSteps("web1", "Failed password", "1h", "now", "50", "forward")
	if len(steps) != 1 {
		t.Fatalf("SecurityLogsSteps() returned %d steps, want 1", len(steps))
	}
	got := testShlexSplit(steps[0].Command)
	wantQuery := "query=" + SecurityLogsQuery("web1", "Failed password")
	found := false
	for _, tok := range got {
		if tok == wantQuery {
			found = true
		}
	}
	if !found {
		t.Fatalf("SecurityLogsSteps() command tokens = %#v, missing %q", got, wantQuery)
	}
}
