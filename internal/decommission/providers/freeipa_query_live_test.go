package providers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// TestFreeIPAQuery_Live exercises production provider queries against a
// dedicated disposable FreeIPA server. The external lab supplies inventory,
// secret-file references and seeded host names; ordinary go test never
// mutates or contacts infrastructure.
func TestFreeIPAQuery_Live(t *testing.T) {
	path := os.Getenv("PILOT_FREEIPA_QUERY_LIVE")
	if path == "" {
		t.Skip("dedicated FreeIPA query lab is not configured")
	}
	var cfg struct {
		Inventory, Playbook, Vars, Transcript, Present, Deleted, Absent string
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{cfg.Inventory, cfg.Playbook, cfg.Vars, cfg.Transcript, cfg.Present, cfg.Deleted, cfg.Absent} {
		if v == "" {
			t.Fatal("live lab configuration is incomplete")
		}
	}
	transcript, err := os.OpenFile(cfg.Transcript, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer transcript.Close()
	runner := ansible.NewRunner()
	runner.StdoutWriter, runner.StderrWriter = transcript, transcript
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		Executor: runner, ServerInventory: cfg.Inventory,
		IdentityApplyPlaybook: cfg.Playbook, ExtraArgs: []string{"-e", "@" + cfg.Vars, "-e", "target_group=all"},
	})
	ctx := context.Background()
	for _, tc := range []struct {
		name, fqdn string
		statuses   map[string]string
		blocked    bool
		converged  bool
	}{
		{"present", cfg.Present, map[string]string{"host_object": "active_residue", "service_principal": "unknown_ownership", "hbac_direct": "active_residue", "sudo_direct": "active_residue"}, true, false},
		{"deleted with DNS and external sudo residue", cfg.Deleted, map[string]string{"host_object": "pass", "host_dns": "active_residue", "sudo_direct": "active_residue"}, false, true},
		{"absent tombstone", cfg.Absent, map[string]string{"host_object": "pass", "host_dns": "pass", "hbac_direct": "pass", "sudo_direct": "pass"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs, err := p.Verify(ctx, VerifyInput{FQDN: tc.fqdn})
			if err != nil {
				t.Fatal(err)
			}
			for kind, want := range tc.statuses {
				if got := findVerification(t, vs, kind).Status; got != want {
					t.Errorf("%s=%s want %s", kind, got, want)
				}
			}
			steps, err := p.Plan(ctx, PlanInput{HostName: tc.fqdn, FQDN: tc.fqdn})
			if tc.blocked {
				if !errors.Is(err, ErrUnknownServicePrincipal) {
					t.Fatalf("Plan=%v want unknown-service blocker", err)
				}
			} else if err != nil || len(steps) != 3 {
				t.Fatalf("Plan=%v/%v want 3 steps", steps, err)
			}
			e := &freeipaIdentityConvergeStep{provider: p, fqdn: tc.fqdn}
			if got, err := e.Inspect(ctx); err != nil || got != tc.converged {
				t.Fatalf("Inspect=%v/%v want %v", got, err, tc.converged)
			}
		})
	}
	// The vm-target inventory has only `all`; without the intentional
	// target_group override the actual identity playbook matches no server.
	// Exercise that exact production playbook / runner failure boundary.
	noServer := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		Executor: runner, ServerInventory: cfg.Inventory,
		IdentityApplyPlaybook: cfg.Playbook, ExtraArgs: []string{"-e", "@" + cfg.Vars},
	})
	if _, err := noServer.Plan(ctx, PlanInput{FQDN: cfg.Present}); err == nil {
		t.Fatal("production playbook with no matching server did not block Plan")
	}
	if _, err := noServer.Verify(ctx, VerifyInput{FQDN: cfg.Present}); err == nil {
		t.Fatal("production playbook with no matching server did not block Verify")
	}
}
