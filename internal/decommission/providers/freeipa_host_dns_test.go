package providers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// hostDNSFixture returns ansible-playbook stdout captured on 2026-10-27 from
// real host_dns queries (`--tags freeipa_host_absent_inspect -e
// pilot_decommission_query=host_dns`) against two disposable FreeIPA 4.13.4
// servers, one with integrated DNS and one installed with
// freeipa_setup_dns: false. The local checkout path in the "included:" lines
// is shortened to the repo-relative path.
//   - own-tombstone-record: i105-resid.ipa.pilot.internal is `state: absent`
//     in the roster and its host object is gone ("host not found" in its
//     own tombstone block), but its A record 192.168.122.252 remains.
//   - record-not-found: i105-missing.ipa.pilot.internal has no record.
//   - zone-not-found: foo.example.invalid, run with -e
//     ipa_domain=example.invalid, a zone the server does not hold.
//   - dns-not-configured: i105-nd.ipa.pilot.internal on the server without
//     integrated DNS.
//   - api-unreachable-before-fix: i105-host.ipa.pilot.internal with httpd
//     stopped, run with the playbook before issue #105's fix: it printed the
//     error and exited 0. The fixed playbook fails at the lookup instead.
func hostDNSFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "host-dns", name+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Issue #105: Verify read every dnsrecord-show failure as "no record", and
// any "not found" in the target's blocks as absence, so the target's own
// roster tombstone ("host not found") hid a record that was still there.
// Only a shown record without an A value, the captured "record/zone not
// found" errors and "DNS is not configured" may pass; anything else is an
// error. The name starts with TestFreeIPAProvider_HostObjectAndDNSAbsent so
// HD10's probe (`-run TestFreeIPAProvider_HostObjectAndDNSAbsent`) runs it.
func TestFreeIPAProvider_HostObjectAndDNSAbsent_OnlyProvenAbsencePasses(t *testing.T) {
	for _, tc := range []struct {
		name, fqdn, stdout string
		wantStatus         string // "" means Verify must return an error
		wantDetail         string
	}{
		{"record left behind by the target's own tombstone", "i105-resid.ipa.pilot.internal", hostDNSFixture(t, "own-tombstone-record"), "active_residue", "192.168.122.252"},
		{"record shown", "web1.ipa.pilot.internal", dnsShowRecord, "active_residue", "192.168.122.251"},
		{"record not found", "i105-missing.ipa.pilot.internal", hostDNSFixture(t, "record-not-found"), "pass", "no DNS record"},
		{"zone not found", "foo.example.invalid", hostDNSFixture(t, "zone-not-found"), "pass", "no DNS record"},
		{"DNS not configured", "i105-nd.ipa.pilot.internal", hostDNSFixture(t, "dns-not-configured"), "pass", "FreeIPA DNS is not configured"},
		{"API unreachable, printed by the playbook before the fix", "i105-host.ipa.pilot.internal", hostDNSFixture(t, "api-unreachable-before-fix"), "", ""},
		{"no Kerberos ticket", "i105-host.ipa.pilot.internal", " ipa: ERROR: did not receive Kerberos credentials", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testProvider(t, func(args []string) (*ansible.Result, error) {
				switch queryKind(args) {
				case "host_dns":
					return &ansible.Result{Stdout: tc.stdout}, nil
				case "hbac_references", "sudo_references":
					return &ansible.Result{Stdout: ""}, nil
				default:
					return &ansible.Result{Stdout: hostShowNotFound}, nil
				}
			})
			results, err := p.Verify(context.Background(), VerifyInput{FQDN: tc.fqdn})
			if tc.wantStatus == "" {
				if err == nil {
					t.Fatalf("Verify() = %+v, want an error for an unrecognized DNS query result", findVerification(t, results, "host_dns"))
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			got := findVerification(t, results, "host_dns")
			if got.Status != tc.wantStatus || got.Active != (tc.wantStatus != "pass") || !strings.Contains(got.Detail, tc.wantDetail) {
				t.Fatalf("host_dns = %+v, want status %s with detail containing %q", got, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}
