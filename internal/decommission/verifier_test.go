package decommission

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/decommission/providers"
)

// fakeResidueProvider is an in-package test-only providers.Provider whose
// Verify() call reports whatever status is currently set — used to prove
// the verifier's input is a real independently-produced Provider result,
// never a re-parse of hosts.yml standing in for "did cleanup work"
// (INV-10).
type fakeResidueProvider struct {
	id     string
	status string
}

func (p *fakeResidueProvider) ID() string { return p.id }

func (p *fakeResidueProvider) Inspect(ctx context.Context, in providers.InspectInput) (providers.Inspection, error) {
	return providers.Inspection{Provider: p.id, Found: p.status == "active_residue"}, nil
}

func (p *fakeResidueProvider) Plan(ctx context.Context, in providers.PlanInput) ([]providers.Step, error) {
	return nil, nil
}

func (p *fakeResidueProvider) Verify(ctx context.Context, in providers.VerifyInput) ([]providers.Verification, error) {
	return []providers.Verification{{
		Provider: p.id, Kind: "fake_residue_check", Identity: in.HostName,
		Status: p.status, Active: p.status == "active_residue",
		Detail: "fake provider independently reports " + p.status,
	}}, nil
}

var _ providers.Provider = (*fakeResidueProvider)(nil)

// TestVerifier_IndependentZeroResidueGatesFinalization proves HD19/INV-10:
// registering a fake Provider whose Verify() call reports active_residue
// makes the finalizer refuse to finalize — no host removed, no receipt —
// and flipping that SAME provider to report pass lets finalization
// proceed. The verifier's input here is genuinely the fake provider's own
// Verify() return value, not a re-read of hosts.yml.
func TestVerifier_IndependentZeroResidueGatesFinalization(t *testing.T) {
	hostName := "hd19-host"
	dir := newZeroRoleHostWorkspace(t, hostName)
	hostsPath := filepath.Join(dir, "hosts.yml")

	st := openTestStore(t)
	ds := NewStore(st)
	plan := planZeroRoleHost(t, dir, hostName, ds)

	fake := &fakeResidueProvider{id: "fake-endpoint", status: "active_residue"}
	residueResults, err := fake.Verify(context.Background(), providers.VerifyInput{HostName: hostName})
	if err != nil {
		t.Fatalf("fake.Verify: %v", err)
	}

	blocked, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, residueResults, "hd19", ds))
	if err != nil {
		t.Fatalf("Finalize (active_residue) returned error, want blocked result: %v", err)
	}
	if blocked.Status != "blocked" {
		t.Fatalf("Status = %q, want blocked", blocked.Status)
	}
	if blocked.Receipt != nil {
		t.Fatal("expected no receipt while the fake provider reports active_residue")
	}
	if data, err := os.ReadFile(hostsPath); err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	} else if !strings.Contains(string(data), hostName) {
		t.Fatalf("host removed from hosts.yml despite active_residue from the independent provider")
	}

	fake.status = "pass"
	passResults, err := fake.Verify(context.Background(), providers.VerifyInput{HostName: hostName})
	if err != nil {
		t.Fatalf("fake.Verify (pass): %v", err)
	}

	completed, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, passResults, "hd19", ds))
	if err != nil {
		t.Fatalf("Finalize (pass) error: %v", err)
	}
	if completed.Status != "completed" {
		t.Fatalf("Status = %q, want completed", completed.Status)
	}
	if completed.Receipt == nil {
		t.Fatal("expected a receipt once the independent provider reports pass")
	}
	if data, err := os.ReadFile(hostsPath); err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	} else if strings.Contains(string(data), hostName) {
		t.Fatalf("host still present in hosts.yml after the independent provider reported pass")
	}
}

func TestEvaluateVerifications_Formula(t *testing.T) {
	cases := []struct {
		name    string
		results []providers.Verification
		want    bool
	}{
		{"empty is vacuously passed", nil, true},
		{"all pass", []providers.Verification{{Status: "pass"}, {Status: "not_applicable"}, {Status: "historical_only"}}, true},
		{"one active residue blocks", []providers.Verification{{Status: "pass"}, {Status: "active_residue"}}, false},
		{"one unknown ownership blocks", []providers.Verification{{Status: "unknown_ownership"}}, false},
		{"unreachable_unverified fails closed", []providers.Verification{{Status: "unreachable_unverified"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateVerifications(c.results)
			if got.Passed != c.want {
				t.Fatalf("Passed = %v, want %v (outcome=%+v)", got.Passed, c.want, got)
			}
		})
	}
}
