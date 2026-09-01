package diagnose

import (
	"errors"
	"testing"
)

var errBoom = errors.New("boom")

func TestNetworkPathSteps_HTTPNoTLSLayer(t *testing.T) {
	steps := NetworkPathSteps("10.0.0.5", 9093, "http", "/-/ready")
	byID := map[string]Step{}
	for _, s := range steps {
		byID[s.ID] = s
	}
	if _, ok := byID["tls"]; ok {
		t.Fatal("http scheme must not produce a tls step")
	}
	if _, ok := byID["application_readiness"]; !ok {
		t.Fatal("missing application_readiness step when readinessPath is set")
	}
}

func TestNetworkPathSteps_HTTPSAddsTLSLayer(t *testing.T) {
	steps := NetworkPathSteps("10.0.0.5", 443, "https", "")
	found := false
	for _, s := range steps {
		if s.ID == "tls" {
			found = true
		}
		if s.ID == "application_readiness" {
			t.Fatal("empty readinessPath must not produce an application_readiness step")
		}
	}
	if !found {
		t.Fatal("https scheme must produce a tls step")
	}
}

func TestBuildNetworkPathOutput_Reachable(t *testing.T) {
	results := []StepResult{
		stepResult("name_resolution", 0, "10.0.0.5  alertmanager-backend"),
		stepResult("routing", 0, "10.0.0.5 via 10.0.0.1 dev eth0"),
		stepResult("transport", 0, "open"),
		stepResult("application_readiness", 0, "OK\nHTTP_STATUS:200"),
	}
	out := BuildNetworkPathOutput("10.0.0.5", 9093, "http", false, true, true, results)
	if out.Verdict != "reachable" {
		t.Fatalf("verdict = %q, want reachable; out=%+v", out.Verdict, out)
	}
}

func TestBuildNetworkPathOutput_BlockedAtTransport(t *testing.T) {
	results := []StepResult{
		stepResult("name_resolution", 0, "10.0.0.5  alertmanager-backend"),
		stepResult("routing", 0, "10.0.0.5 via 10.0.0.1 dev eth0"),
		stepResult("transport", 0, "closed"),
	}
	out := BuildNetworkPathOutput("10.0.0.5", 9093, "http", false, false, true, results)
	if out.Verdict != "blocked_at_transport" {
		t.Fatalf("verdict = %q, want blocked_at_transport", out.Verdict)
	}
}

func TestBuildNetworkPathOutput_InsufficientEvidenceOnRunError(t *testing.T) {
	results := []StepResult{
		stepResult("name_resolution", 0, "10.0.0.5"),
		stepResult("routing", 0, "10.0.0.5 via 10.0.0.1 dev eth0"),
		{Step: Step{ID: "transport"}, Result: AdHocResult{RunErr: errBoom}},
	}
	out := BuildNetworkPathOutput("10.0.0.5", 9093, "http", false, false, true, results)
	if out.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence (transport step errored, not confirmed closed)", out.Verdict)
	}
}

func TestBuildNetworkPathOutput_Unreachable(t *testing.T) {
	out := BuildNetworkPathOutput("10.0.0.5", 9093, "http", false, false, false, nil)
	if out.Verdict != "unreachable" {
		t.Fatalf("verdict = %q, want unreachable", out.Verdict)
	}
}
