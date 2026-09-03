package providers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// fakeAnsibleExecutor is the in-package fake ansibleExecutor every test in
// this file substitutes for *internal/ansible.Runner — no real
// ansible-playbook binary or live host is ever touched (Phase 3a is
// fixture-only). fn inspects the exact args this provider built and
// returns canned stdout/exit codes, keyed on whatever substring the test
// cares about (the query kind passed via "pilot_decommission_query=...",
// or a playbook path) rather than a strict call-order queue, so tests stay
// readable as the provider's exact call sequence evolves.
type fakeAnsibleExecutor struct {
	fn    func(args []string) (*ansible.Result, error)
	calls [][]string
}

func (f *fakeAnsibleExecutor) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if f.fn == nil {
		return &ansible.Result{}, nil
	}
	return f.fn(args)
}

func argsContain(args []string, substr string) bool {
	for _, a := range args {
		if strings.Contains(a, substr) {
			return true
		}
	}
	return false
}

func queryKind(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "pilot_decommission_query=") {
			return strings.TrimPrefix(a, "pilot_decommission_query=")
		}
	}
	return ""
}

// These fixtures mirror the REAL combined HOST_INSPECT text
// freeipa-identity-apply.yml's "Print live host inspection" task now
// prints (Phase 3b live-target testing bug fix): plain (non-raw) `ipa
// host-show` output — which always carries its OWN "Principal name:
// host/<fqdn>@REALM" line — concatenated with a separate `ipa
// service-find --man-by-hosts=<fqdn>` result. There is no
// "managedby_service:"/"memberof_hostgroup:"/"memberof_netgroup:"
// attribute in real output at all; those never matched anything before
// this fix (see freeipa_client.go's package/pattern doc comments).
const hostShowClean = `
  Host name: web1.ipa.pilot.internal
  Principal name: host/web1.ipa.pilot.internal@IPA.PILOT.INTERNAL
----------------------
0 services matched
----------------------
`

const hostShowUnknownService = `
  Host name: web1.ipa.pilot.internal
  Principal name: host/web1.ipa.pilot.internal@IPA.PILOT.INTERNAL
-----------------
1 service matched
-----------------
  Principal name: HTTP/web1.ipa.pilot.internal@IPA.PILOT.INTERNAL
`

const hostShowNotFound = `ipa: ERROR: web1.ipa.pilot.internal: host not found`

const hostShowWithMembership = `
  Host name: web1.ipa.pilot.internal
  Principal name: host/web1.ipa.pilot.internal@IPA.PILOT.INTERNAL
  Member of host-groups: web-servers
  Member of netgroups: ng-web
----------------------
0 services matched
----------------------
`

func testProvider(t *testing.T, fn func(args []string) (*ansible.Result, error)) (*FreeIPAClientProvider, *fakeAnsibleExecutor) {
	t.Helper()
	exec := &fakeAnsibleExecutor{fn: fn}
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{
		Executor:              exec,
		ClientInventory:       "inventory.yml",
		ServerInventory:       "inventory.yml",
		DecommissionPlaybook:  "playbooks/decommission/freeipa-client-decommission.yml",
		IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
	})
	return p, exec
}

// ---- HD9: TestFreeIPAProvider_ClientEnrollmentRemoved ---------------------

func TestFreeIPAProvider_ClientEnrollmentRemoved(t *testing.T) {
	p, exec := testProvider(t, func(args []string) (*ansible.Result, error) {
		if argsContain(args, "freeipa-client-decommission.yml") {
			if !argsContain(args, "inspect") {
				t.Fatalf("Inspect() must restrict to a read-only tag, got args=%v", args)
			}
			return &ansible.Result{Stdout: "IPA_CLIENT_ENROLLED=true", ExitCode: 0}, nil
		}
		// Plan()'s service-principal discovery: no unknown principal.
		return &ansible.Result{Stdout: hostShowClean, ExitCode: 0}, nil
	})

	insp, err := p.Inspect(context.Background(), InspectInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !insp.Found {
		t.Fatalf("Inspect() = %+v, want Found=true (host reported as currently enrolled)", insp)
	}

	steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(steps) == 0 {
		t.Fatal("Plan() returned no steps")
	}
	first := steps[0]
	if first.Phase != "local_cleanup" || first.Action != ActionFreeIPAClientUninstall || first.TargetIdentity != "web1" {
		t.Fatalf("Plan() first step = %+v, want the established uninstall mechanism scheduled as local_cleanup", first)
	}

	// The decommission playbook must have been invoked for the local
	// uninstall mechanism at least once (via Inspect above); confirm it
	// was never invoked WITHOUT the read-only "inspect" tag restriction
	// in this test (Inspect must never trigger the real uninstall task).
	sawDecommissionPlaybook := false
	for _, call := range exec.calls {
		if argsContain(call, "freeipa-client-decommission.yml") {
			sawDecommissionPlaybook = true
			if !argsContain(call, "inspect") {
				t.Fatalf("a call to the decommission playbook was not tag-restricted to inspect: %v", call)
			}
		}
	}
	if !sawDecommissionPlaybook {
		t.Fatal("expected at least one call to the decommission playbook (via Inspect)")
	}
}

// ---- HD10: TestFreeIPAProvider_HostObjectAndDNSAbsent ---------------------

func TestFreeIPAProvider_HostObjectAndDNSAbsent(t *testing.T) {
	cases := []struct {
		name           string
		hostStdout     string
		dnsStdout      string
		wantHostStatus string
		wantDNSStatus  string
	}{
		{
			name:           "clean after cleanup",
			hostStdout:     hostShowNotFound,
			dnsStdout:      "ipa: ERROR: web1: DNS record not found",
			wantHostStatus: "pass",
			wantDNSStatus:  "pass",
		},
		{
			name:           "host object still present blocks",
			hostStdout:     hostShowClean,
			dnsStdout:      "ipa: ERROR: web1: DNS record not found",
			wantHostStatus: "active_residue",
			wantDNSStatus:  "pass",
		},
		{
			name:           "DNS A record still present blocks (never a broad cascade — presence alone is residue)",
			hostStdout:     hostShowNotFound,
			dnsStdout:      "  arecord: 10.0.0.5",
			wantHostStatus: "pass",
			wantDNSStatus:  "active_residue",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
				switch queryKind(args) {
				case "host_dns":
					return &ansible.Result{Stdout: tc.dnsStdout}, nil
				default:
					return &ansible.Result{Stdout: tc.hostStdout}, nil
				}
			})
			results, err := p.Verify(context.Background(), VerifyInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			gotHost := findVerification(t, results, "host_object")
			if gotHost.Status != tc.wantHostStatus {
				t.Fatalf("host_object status = %q, want %q (%+v)", gotHost.Status, tc.wantHostStatus, gotHost)
			}
			gotDNS := findVerification(t, results, "host_dns")
			if gotDNS.Status != tc.wantDNSStatus {
				t.Fatalf("host_dns status = %q, want %q (%+v)", gotDNS.Status, tc.wantDNSStatus, gotDNS)
			}
		})
	}
}

// ---- HD11: TestFreeIPAProvider_DirectReferencesAbsent ---------------------

func TestFreeIPAProvider_DirectReferencesAbsent(t *testing.T) {
	cases := []struct {
		name          string
		hostStdout    string
		hbacStdout    string
		sudoStdout    string
		wantHostgroup string
		wantNetgroup  string
		wantHBAC      string
		wantSudo      string
	}{
		{
			name:          "all direct references pruned",
			hostStdout:    hostShowNotFound,
			hbacStdout:    "",
			sudoStdout:    "",
			wantHostgroup: "pass", wantNetgroup: "pass", wantHBAC: "pass", wantSudo: "pass",
		},
		{
			name:          "residual hostgroup/netgroup membership blocks",
			hostStdout:    hostShowWithMembership,
			hbacStdout:    "",
			sudoStdout:    "",
			wantHostgroup: "active_residue", wantNetgroup: "active_residue", wantHBAC: "pass", wantSudo: "pass",
		},
		{
			name:          "residual HBAC/sudo direct reference blocks",
			hostStdout:    hostShowNotFound,
			hbacStdout:    "  Rule name: web-login\n",
			sudoStdout:    "  Rule name: web-sudo\n",
			wantHostgroup: "pass", wantNetgroup: "pass", wantHBAC: "active_residue", wantSudo: "active_residue",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
				switch queryKind(args) {
				case "hbac_references":
					return &ansible.Result{Stdout: tc.hbacStdout}, nil
				case "sudo_references":
					return &ansible.Result{Stdout: tc.sudoStdout}, nil
				case "host_dns":
					return &ansible.Result{Stdout: "ipa: ERROR: not found"}, nil
				default:
					return &ansible.Result{Stdout: tc.hostStdout}, nil
				}
			})
			results, err := p.Verify(context.Background(), VerifyInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got := findVerification(t, results, "hostgroup_membership").Status; got != tc.wantHostgroup {
				t.Fatalf("hostgroup_membership = %q, want %q", got, tc.wantHostgroup)
			}
			if got := findVerification(t, results, "netgroup_membership").Status; got != tc.wantNetgroup {
				t.Fatalf("netgroup_membership = %q, want %q", got, tc.wantNetgroup)
			}
			if got := findVerification(t, results, "hbac_direct").Status; got != tc.wantHBAC {
				t.Fatalf("hbac_direct = %q, want %q", got, tc.wantHBAC)
			}
			if got := findVerification(t, results, "sudo_direct").Status; got != tc.wantSudo {
				t.Fatalf("sudo_direct = %q, want %q", got, tc.wantSudo)
			}
		})
	}
}

// ---- HD12: TestFreeIPAProvider_UnknownServicePrincipalBlocks --------------

func TestFreeIPAProvider_UnknownServicePrincipalBlocks(t *testing.T) {
	t.Run("unknown service principal hard-blocks", func(t *testing.T) {
		p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
			return &ansible.Result{Stdout: hostShowUnknownService}, nil
		})
		steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
		if err == nil {
			t.Fatalf("Plan() = %+v, want an error (unknown service principal must hard-block, HD12)", steps)
		}
		if !errors.Is(err, ErrUnknownServicePrincipal) {
			t.Fatalf("Plan() error = %v, want it to wrap ErrUnknownServicePrincipal", err)
		}
		if steps != nil {
			t.Fatalf("Plan() steps = %+v, want nil — the central-cleanup steps must not be scheduled at all", steps)
		}
	})

	t.Run("only the host's own principal is present -- not blocked", func(t *testing.T) {
		p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
			return &ansible.Result{Stdout: hostShowClean}, nil
		})
		steps, err := p.Plan(context.Background(), PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
		if err != nil {
			t.Fatalf("Plan() error = %v, want success (host/<fqdn> alone is never unknown)", err)
		}
		if len(steps) != 3 {
			t.Fatalf("Plan() steps = %+v, want all 3 steps scheduled", steps)
		}
	})

	// Verify() must independently surface the same finding as
	// unknown_ownership (never simply "active_residue", so a caller can
	// tell "needs investigation" from "definitely mine, still there").
	t.Run("Verify reports unknown_ownership for the same finding", func(t *testing.T) {
		p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
			switch queryKind(args) {
			case "host_dns":
				return &ansible.Result{Stdout: "ipa: ERROR: not found"}, nil
			case "hbac_references", "sudo_references":
				return &ansible.Result{Stdout: ""}, nil
			default:
				return &ansible.Result{Stdout: hostShowUnknownService}, nil
			}
		})
		results, err := p.Verify(context.Background(), VerifyInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		got := findVerification(t, results, "service_principal")
		if got.Status != "unknown_ownership" {
			t.Fatalf("service_principal status = %q, want unknown_ownership (%+v)", got.Status, got)
		}
		if !got.Active {
			t.Fatal("expected Active=true for an unresolved service principal finding")
		}
	})
}

// ---- Extra coverage: executor plumbing ------------------------------------

func TestFreeIPAProvider_ExecutorErrorPropagates(t *testing.T) {
	wantErr := errors.New("boom")
	p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
		return nil, wantErr
	})
	if _, err := p.Inspect(context.Background(), InspectInput{HostName: "web1"}); !errors.Is(err, wantErr) {
		t.Fatalf("Inspect() error = %v, want it to wrap the executor error", err)
	}
	if _, err := p.Plan(context.Background(), PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"}); !errors.Is(err, wantErr) {
		t.Fatalf("Plan() error = %v, want it to wrap the executor error", err)
	}
	if _, err := p.Verify(context.Background(), VerifyInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"}); !errors.Is(err, wantErr) {
		t.Fatalf("Verify() error = %v, want it to wrap the executor error", err)
	}
}

func TestFreeIPAClientProvider_NoExecutorConfiguredErrors(t *testing.T) {
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{})
	if _, err := p.Inspect(context.Background(), InspectInput{HostName: "web1"}); err == nil {
		t.Fatal("expected an error with no executor configured")
	}
}

func TestFreeIPAClientProvider_ID(t *testing.T) {
	p := NewFreeIPAClientProvider(FreeIPAClientProviderConfig{})
	if p.ID() != "freeipa-client" {
		t.Fatalf("ID() = %q, want freeipa-client", p.ID())
	}
}

func findVerification(t *testing.T, results []Verification, kind string) Verification {
	t.Helper()
	for _, r := range results {
		if r.Kind == kind {
			return r
		}
	}
	t.Fatalf("no verification result with Kind=%q in %+v", kind, results)
	return Verification{}
}
