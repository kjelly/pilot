package decommission

import (
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// TestReferences_DiscoveredAndClassifiedBeforeMutation proves HD6: reverse
// references across the FreeIPA roster, freeipa-dns.yaml, and
// internal-endpoints.yaml are discovered and correctly classified —
// including that a merely-similar name (a hostgroup whose name contains
// the target host's name as a substring, without exact membership) is
// FOREIGN_UNKNOWN, never AUTO_REMOVE (spec.md §5.6).
func TestReferences_DiscoveredAndClassifiedBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	rosterPath := writeWorkspaceFile(t, dir, "roster.yaml", `schema_version: 2
freeipa:
  server: ipa1.example.internal
hosts:
  - name: web1
    state: present
hostgroups:
  - name: web-servers
    state: present
    membership: {authoritative: true, hosts: [web1]}
  - name: web1-decoy-group
    state: present
    membership: {authoritative: true, hosts: []}
netgroups:
  - name: ng-web
    state: present
    membership: {authoritative: true, users: [], groups: [], hosts: [web1], hostgroups: [], netgroups: []}
hbac:
  rules:
    - name: web-login
      targets: {hosts: [web1], hostgroups: []}
sudo:
  rules:
    - name: web-sudo
      targets: {hosts: [web1], hostgroups: []}
`)

	dnsPath := filepath.Join(dir, "freeipa-dns.yaml")
	if err := inventory.CreateMinimalDNSManifest(dnsPath, "svc.pilot.internal", "SVC.PILOT.INTERNAL", "ipa1.svc.pilot.internal"); err != nil {
		t.Fatalf("CreateMinimalDNSManifest() error = %v", err)
	}
	if err := inventory.AppendDNSZone(dnsPath, map[string]any{"name": "svc.pilot.internal.", "state": "present"}); err != nil {
		t.Fatalf("AppendDNSZone() error = %v", err)
	}
	if err := inventory.AppendDNSRecord(dnsPath, "svc.pilot.internal.", map[string]any{
		"name": "web1", "type": "A", "target": map[string]any{"inventory_host": "web1"},
	}); err != nil {
		t.Fatalf("AppendDNSRecord() error = %v", err)
	}

	iepPath := filepath.Join(dir, "internal-endpoints.yaml")
	if err := inventory.CreateMinimalInternalEndpointManifest(iepPath); err != nil {
		t.Fatalf("CreateMinimalInternalEndpointManifest() error = %v", err)
	}
	if err := inventory.AppendInternalEndpoint(iepPath, map[string]any{
		"fqdn":  "direct.svc.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "svc.pilot.internal."},
		"route": map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": "web1"}},
		"tls":   map[string]any{"mode": "disabled"},
	}); err != nil {
		t.Fatalf("AppendInternalEndpoint() error = %v", err)
	}

	host := inventory.Host{
		Name:        "web1",
		AnsibleHost: "10.0.0.5",
		Roles:       []string{"freeipa-client"},
		Extra:       map[string]string{"freeipa_roster_file": "roster.yaml"},
	}
	writeWorkspaceFile(t, dir, "host_vars/web1.yml", "some_var: 1\n")

	refs, warnings := ScanReferences(dir, []inventory.Host{host}, host)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none for a fully-readable set of manifests", warnings)
	}

	byKey := map[string]Reference{}
	for _, r := range refs {
		byKey[r.Source+"/"+r.Kind+"/"+r.Identity] = r
	}

	wantAutoRemove := []string{
		"host_vars/host_vars_file/host_vars/web1.yml",
		"freeipa-roster/canonical_host_declaration/" + rosterPath,
		"freeipa-roster/hostgroup_membership/web-servers",
		"freeipa-roster/netgroup_membership/ng-web",
		"freeipa-roster/hbac_rule/web-login",
		"freeipa-roster/sudo_rule/web-sudo",
	}
	for _, k := range wantAutoRemove {
		r, ok := byKey[k]
		if !ok {
			t.Fatalf("missing expected reference %q; got refs=%+v", k, refs)
		}
		if r.Classification != AutoRemove {
			t.Fatalf("reference %q classification = %s, want AUTO_REMOVE", k, r.Classification)
		}
	}

	decoy, ok := byKey["freeipa-roster/hostgroup_membership/web1-decoy-group"]
	if !ok {
		t.Fatalf("expected the substring-only decoy hostgroup to be surfaced as a reference, not silently dropped; got refs=%+v", refs)
	}
	if decoy.Classification != ForeignUnknown {
		t.Fatalf("decoy hostgroup (name contains host name as a substring only, no exact membership) classification = %s, want FOREIGN_UNKNOWN — a name/hostname substring is never ownership evidence (spec.md §5.6)", decoy.Classification)
	}

	dnsRef, ok := byKey["freeipa-dns.yaml/dns_record/svc.pilot.internal./web1 A"]
	if !ok {
		t.Fatalf("missing expected DNS record reference; got refs=%+v", refs)
	}
	if dnsRef.Classification != AutoRemove {
		t.Fatalf("DNS record reference classification = %s, want AUTO_REMOVE (Pilot-managed, surgical exact-value deletion)", dnsRef.Classification)
	}

	iepRef, ok := byKey["internal-endpoints.yaml/endpoint_target/direct.svc.pilot.internal"]
	if !ok {
		t.Fatalf("missing expected internal-endpoint reference; got refs=%+v", refs)
	}
	if iepRef.Classification != RequiresReplacement {
		t.Fatalf("internal-endpoint target reference classification = %s, want REQUIRES_REPLACEMENT", iepRef.Classification)
	}
}

// TestReferences_AbsentOptionalManifestsAreNotErrors covers spec.md §12's
// "if present" — a host with no roster/DNS/endpoint manifests at all must
// scan cleanly with zero references and zero warnings, not fail.
func TestReferences_AbsentOptionalManifestsAreNotErrors(t *testing.T) {
	dir := t.TempDir()
	host := inventory.Host{Name: "bare1", AnsibleHost: "10.0.0.9"}
	refs, warnings := ScanReferences(dir, []inventory.Host{host}, host)
	if len(refs) != 0 {
		t.Fatalf("refs = %+v, want none", refs)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
}

// TestReferences_RosterPathFallsBackToAnotherHostInWorkspace is a
// regression test for a real bug found via a live vm-target `pilot host
// decommission apply` run (2026-09-11): the overwhelmingly common case is
// a freeipa-CLIENT host with no freeipa_roster_file of its own (only the
// FreeIPA server, or an nfs-server/nfs-client host, conventionally
// declares one — see checkRosterCompleteness/discoverRosterFilePath in
// cmd/pilot/cmd). Scanning references (and, via RosterPathFor, wiring the
// roster-absent/identity-apply-converge steps) using ONLY the target
// host's own inventory var silently found nothing for such a host — the
// plan looked clean, but the central roster-absent step was a no-op and
// the FreeIPA host object was never actually deleted, so `apply` deadlocked
// forever at "active_residue". Confirms the fallback: when the DECOMMISSION
// TARGET declares no roster path, scanning still finds the one declared by
// a DIFFERENT host in the same workspace.
func TestReferences_RosterPathFallsBackToAnotherHostInWorkspace(t *testing.T) {
	dir := t.TempDir()
	rosterPath := writeWorkspaceFile(t, dir, "roster.yaml", `schema_version: 2
freeipa:
  server: ipa1.example.internal
hosts:
  - name: client1
    state: present
hostgroups:
  - name: client-hosts
    state: present
    membership: {authoritative: true, hosts: [client1]}
`)

	server := inventory.Host{Name: "ipa1", AnsibleHost: "10.0.0.1", Extra: map[string]string{"freeipa_roster_file": "roster.yaml"}}
	target := inventory.Host{Name: "client1", AnsibleHost: "10.0.0.5"} // no freeipa_roster_file of its own

	if got := RosterPathFor(dir, []inventory.Host{server, target}, target); got != rosterPath {
		t.Fatalf("RosterPathFor = %q, want %q (fallback to the server host's declared roster)", got, rosterPath)
	}

	refs, warnings := ScanReferences(dir, []inventory.Host{server, target}, target)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	byKey := map[string]Reference{}
	for _, r := range refs {
		byKey[r.Source+"/"+r.Kind+"/"+r.Identity] = r
	}
	want := "freeipa-roster/canonical_host_declaration/" + rosterPath
	r, ok := byKey[want]
	if !ok {
		t.Fatalf("missing expected reference %q via fallback roster path; got refs=%+v", want, refs)
	}
	if r.Classification != AutoRemove {
		t.Fatalf("reference %q classification = %s, want AUTO_REMOVE", want, r.Classification)
	}
	hg := "freeipa-roster/hostgroup_membership/client-hosts"
	if _, ok := byKey[hg]; !ok {
		t.Fatalf("missing expected hostgroup reference %q via fallback roster path; got refs=%+v", hg, refs)
	}
}
