package diagnose

import "testing"

func TestDNSSteps_OmitsNameStepsWhenNameEmpty(t *testing.T) {
	steps := DNSSteps("")
	for _, s := range steps {
		if s.ID == "nss-resolve" || s.ID == "direct-resolve" {
			t.Fatalf("DNSSteps(\"\") included step %s, want name-based steps omitted when name is empty", s.ID)
		}
	}
}

func TestDNSSteps_IncludesNameStepsWhenNameSet(t *testing.T) {
	steps := DNSSteps("keycloak.infra.internal")
	byID := map[string]Step{}
	for _, s := range steps {
		byID[s.ID] = s
	}
	if byID["nss-resolve"].Command != "getent hosts keycloak.infra.internal" {
		t.Fatalf("nss-resolve command = %q", byID["nss-resolve"].Command)
	}
	if byID["direct-resolve"].Command != "dig +short keycloak.infra.internal @127.0.0.1" {
		t.Fatalf("direct-resolve command = %q", byID["direct-resolve"].Command)
	}
}

func TestBuildDNSOutput_NoNameIsFactsOnly(t *testing.T) {
	results := []StepResult{
		stepResult("resolv-nameserver", 0, "127.0.0.1"),
		stepResult("resolved-active", 0, ""),
		stepResult("daemon-listening", 0, ""),
		stepResult("daemon-installed", 0, "0"),
	}
	out := BuildDNSOutput("", results)
	if out.NameQueried {
		t.Fatal("NameQueried = true, want false when no name supplied")
	}
	if out.Nameserver != "127.0.0.1" {
		t.Fatalf("Nameserver = %q, want 127.0.0.1", out.Nameserver)
	}
	if out.Verdict == "" {
		t.Fatal("Verdict is empty")
	}
}

func TestBuildDNSOutput_NSSAndDirectAgreeResolves(t *testing.T) {
	results := []StepResult{
		stepResult("resolv-nameserver", 0, "127.0.0.1"),
		stepResult("resolved-active", 0, ""),
		stepResult("daemon-listening", 0, "udp   UNCONN 0 0 10.0.0.5:53"),
		stepResult("daemon-installed", 0, "1"),
		stepResult("nss-resolve", 0, "10.0.0.5 keycloak.infra.internal"),
		stepResult("direct-resolve", 0, "10.0.0.5"),
	}
	out := BuildDNSOutput("keycloak.infra.internal", results)
	if !out.ResolvesViaNSS || !out.ResolvesViaDirectQuery {
		t.Fatalf("BuildDNSOutput() = %+v, want both NSS and direct resolution to succeed", out)
	}
}

func TestBuildDNSOutput_NSSFailsButDirectSucceeds(t *testing.T) {
	results := []StepResult{
		stepResult("resolv-nameserver", 0, "127.0.0.1"),
		stepResult("resolved-active", 0, ""),
		stepResult("daemon-listening", 0, "udp   UNCONN 0 0 10.0.0.5:53"),
		stepResult("daemon-installed", 0, "1"),
		stepResult("nss-resolve", 2, ""),
		stepResult("direct-resolve", 0, "10.0.0.5"),
	}
	out := BuildDNSOutput("keycloak.infra.internal", results)
	if out.ResolvesViaNSS || !out.ResolvesViaDirectQuery {
		t.Fatalf("BuildDNSOutput() = %+v, want NSS to fail and direct to succeed", out)
	}
}

func TestBuildDNSOutput_NeitherResolvesNoLocalResolver(t *testing.T) {
	results := []StepResult{
		stepResult("resolv-nameserver", 0, "8.8.8.8"),
		stepResult("resolved-active", 3, ""),
		stepResult("daemon-listening", 0, ""),
		stepResult("daemon-installed", 0, "0"),
		stepResult("nss-resolve", 2, ""),
		stepResult("direct-resolve", 0, ""),
	}
	out := BuildDNSOutput("keycloak.infra.internal", results)
	if out.ResolvesViaNSS || out.ResolvesViaDirectQuery {
		t.Fatalf("BuildDNSOutput() = %+v, want neither to resolve", out)
	}
	if out.Verdict == "" {
		t.Fatal("Verdict is empty")
	}
}
