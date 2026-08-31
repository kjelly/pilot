package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegression_FreeIPANFSSpecs(t *testing.T) {
	tests := []struct {
		path string
		rows int
	}{
		{"../../docs/verification/freeipa-nfs-server.md", 8},
		{"../../docs/verification/freeipa-nfs-client.md", 6},
	}
	for _, tt := range tests {
		s, err := Parse(tt.path)
		if err != nil {
			t.Fatalf("parse %s: %v", tt.path, err)
		}
		if len(s.Rows) != tt.rows {
			t.Errorf("%s rows=%d want=%d", tt.path, len(s.Rows), tt.rows)
		}
		if findings := Lint(s); HasErrors(findings) {
			t.Errorf("%s lint errors:\n%s", tt.path, fsToString(findings))
		}
		for i, row := range s.Rows {
			if row.ID != "C"+string(rune('1'+i)) {
				t.Errorf("%s row %d ID=%s", tt.path, i, row.ID)
			}
		}
	}
}

func TestRegression_FreeIPANFSSafetyContracts(t *testing.T) {
	serverDoc, err := os.ReadFile("../../docs/verification/freeipa-nfs-server.md")
	if err != nil {
		t.Fatal(err)
	}
	server, _ := Parse("../../docs/verification/freeipa-nfs-server.md")
	all := ""
	for _, row := range server.Rows {
		all += row.Command + " " + row.Expected
	}
	for _, required := range []string{"root_squash", "sec=krb5i", "default:group", "/etc/krb5.keytab"} {
		if !strings.Contains(all, required) {
			t.Errorf("NFS server spec must lock %q", required)
		}
	}
	for _, required := range []string{"AlmaLinux 9、Ubuntu 24.04", "command -v rpm", "dpkg-query", "nfs-kernel-server"} {
		if !strings.Contains(string(serverDoc), required) {
			t.Errorf("NFS server spec must support portable package check %q", required)
		}
	}
	client, _ := Parse("../../docs/verification/freeipa-nfs-client.md")
	all = ""
	for _, row := range client.Rows {
		all += row.Command + " " + row.Expected
	}
	if !strings.Contains(all, "/etc/fstab") || !strings.Contains(all, "autofs") {
		t.Error("NFS client spec must lock automount and forbid fstab mutation")
	}
}

func TestRegression_FreeIPANFSServerSupportsEnrolledUbuntuHosts(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-server-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	for _, required := range []string{
		"Debian: [nfs-kernel-server, acl]",
		"path: /etc/ipa/default.conf",
		"systemctl is-active sssd\n      check_mode: false",
		"hostname --fqdn",
		"PILOT FQDN CANONICAL HOSTNAME",
		"insertbefore: '^127\\.0\\.1\\.1\\s'",
		"ipa_admin_password == freeipa_roster.freeipa.admin.password",
		"path: \"{{ nfs_exports_fragment | dirname }}\"",
		"name: \"{{ nfs_server_service }}\"",
		"when: not ansible_check_mode",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("Ubuntu NFS server contract missing %q", required)
		}
	}
	for _, forbidden := range []string{"name: gssproxy", "nfs_exports_fragment is file", "nfs_selected_server.packages", "nfs_selected_server.services"} {
		if strings.Contains(playbook, forbidden) {
			t.Errorf("Ubuntu NFS server contract must not contain %q", forbidden)
		}
	}
}

func TestRegression_FreeIPANFSClientFreshPreviewIsCheckSafe(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-client-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	if !strings.Contains(playbook, "name: autofs\n        enabled: true\n        state: started\n      #") ||
		!strings.Contains(playbook, "when: not ansible_check_mode") {
		t.Fatal("fresh NFS client preview must not inspect the autofs unit before package installation")
	}
}

func TestRegression_FreeIPAClientPreservesConfiguredAutofsResponder(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-client-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	for _, required := range []string{
		"FreeIPA client — inspect the current SSSD services line",
		"ipa_sssd_services_current.stdout",
		"'autofs' in",
		"split(',') | map('trim') | list",
		"FreeIPA client — disable socket activation for explicit SSSD responders",
		"sssd-pam-priv.socket",
		"argv: [systemctl, reset-failed]",
		"name: sssd-sudo.socket",
	} {
		if !strings.Contains(playbook, required) {
			t.Fatalf("base FreeIPA client must preserve an autofs responder configured by the NFS overlay; missing %q", required)
		}
	}

	nfsPlaybookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-client-apply.yml")
	nfsData, err := os.ReadFile(nfsPlaybookPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Ensure SSSD keeps the autofs responder enabled",
		"services = nss, pam, ssh, autofs",
		"Restart SSSD after enabling automount",
	} {
		if !strings.Contains(string(nfsData), required) {
			t.Fatalf("NFS client overlay must self-heal the autofs responder; missing %q", required)
		}
	}
}

func TestRegression_FreeIPANFSServerSnapshotIsCreateOnce(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-server-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	start := strings.Index(playbook, "- name: \"Snapshot managed exports fragment\"")
	if start < 0 {
		t.Fatal("managed exports snapshot task is missing")
	}
	rest := playbook[start:]
	end := strings.Index(rest[1:], "\n        - name:")
	if end < 0 {
		t.Fatal("could not isolate managed exports snapshot task")
	}
	task := rest[:end+1]
	if !strings.Contains(task, "force: false") {
		t.Fatal("managed exports .pre-freeipa-nfs.bak must be created once so a no-op run does not rewrite it")
	}
	for _, required := range []string{
		"pre-freeipa-nfs.absent",
		"Record that the managed exports fragment was initially absent",
		"Remove a managed exports fragment that did not exist before this role",
		"nfs_exports_initially_absent.stat.exists",
	} {
		if !strings.Contains(playbook, required) {
			t.Fatalf("managed exports rollback must preserve an initially-absent state; missing %q", required)
		}
	}
}

// TestRegression_FreeIPANFSClientConsumesRosterNFSClients locks the
// 2026-08-14 fix: nfs_clients[] used to be accepted by the roster schema
// (schema validation, migration fingerprinting) but never actually read by
// any playbook — freeipa-nfs-client-apply.yml drove purely off static
// inventory group membership. This test ensures the roster is genuinely the
// targeting authority (a host not covered by any present nfs_clients entry
// must fail closed) and that the verification_mounts steps (freeipa-config.md
// §14.3 steps 7-8) exist as real, tagged tasks.
func TestRegression_FreeIPANFSClientConsumesRosterNFSClients(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-client-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	for _, required := range []string{
		"Load canonical roster under a namespace",
		"file: \"{{ freeipa_roster_file }}\"",
		"Discover this NFS client's operating-system FQDN",
		"Resolve which present nfs_clients entries (if any) cover this host",
		"Gate: this host must be declared as a present nfs_clients entry in the roster",
		"nfs_client_entry.automount.location | default(nfs_automount_location)",
		"nfs_client_entry.automount.enable_service | default(true) | bool",
		"Trigger autofs mount for each roster-declared verification path",
		"tags: [nfs-client-verify-mount-trigger]",
		"Verify each triggered path is a genuinely mounted, Kerberized NFSv4 filesystem",
		"tags: [nfs-client-verify-mount-check]",
		"'nfs4' not in nfs_client_verify_mount.stdout",
		"'sec=krb5' not in nfs_client_verify_mount.stdout",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("freeipa-nfs-client-apply.yml must be roster-driven; missing %q", required)
		}
	}
	// The gate must be a hard fail-closed assert, not a soft warn-and-skip —
	// static inventory group membership alone must no longer be sufficient.
	if !strings.Contains(playbook, "(nfs_client_matches | default([])) | length > 0") {
		t.Error("freeipa-nfs-client-apply.yml must hard-fail when no nfs_clients entry covers this host")
	}
	// The mount-check task itself must NOT hard-fail the host: its
	// prerequisites (the IPA automount map/key, created only by the separate
	// freeipa-identity day-2 reconcile; and the NFS server FQDN actually
	// resolving, which needs the separate freeipa-dns-client day-2 role)
	// are never guaranteed to exist on a plain site.yml pass, since both run
	// after site.yml in this project's established rebuild order. Confirmed
	// live 2026-08-15 (round 25): without ignore_errors, a hard failure here
	// silently excludes this host from every later site.yml play.
	checkStart := strings.Index(playbook, "- name: \"Verify each triggered path is a genuinely mounted, Kerberized NFSv4 filesystem\"")
	if checkStart < 0 {
		t.Fatal("mount-check task is missing")
	}
	checkEnd := strings.Index(playbook[checkStart:], "\n  handlers:")
	if checkEnd < 0 {
		t.Fatal("could not isolate mount-check task")
	}
	if !strings.Contains(playbook[checkStart:checkStart+checkEnd], "ignore_errors: true") {
		t.Error("freeipa-nfs-client-apply.yml's mount-check task must not cascade-fail the rest of site.yml for this host (ignore_errors: true)")
	}
}

// TestRegression_FreeIPANFSClientHostgroupAllWildcard locks the 2026-08-18
// fix that lets a roster declare "every managed host may become an NFS
// client" once, instead of requiring every new host to be individually
// appended to a hostgroup's membership.hosts list as it's onboarded. A
// hostgroup with `membership.all: true` referenced by a present nfs_clients
// entry must satisfy the targeting gate for ANY host, regardless of whether
// that host also appears in membership.hosts/nested hostgroups.
func TestRegression_FreeIPANFSClientHostgroupAllWildcard(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-client-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	start := strings.Index(playbook, "- name: \"Resolve which present nfs_clients entries (if any) cover this host\"")
	if start < 0 {
		t.Fatal("nfs_clients resolution task is missing")
	}
	rest := playbook[start:]
	end := strings.Index(rest[1:], "\n    - name:")
	if end < 0 {
		t.Fatal("could not isolate nfs_clients resolution task")
	}
	task := rest[:end+1]
	for _, required := range []string{
		"nfs_client_hg.membership.all | default(false) | bool",
		"when: nfs_client_hg_all or (nfs_client_fqdn in nfs_client_resolved_hosts)",
	} {
		if !strings.Contains(task, required) {
			t.Errorf("nfs_clients resolution task must support a membership.all wildcard; missing %q", required)
		}
	}
	if !strings.Contains(playbook, "membership.all: true") {
		t.Error("Gate fail_msg should point authors at the membership.all wildcard as an alternative to per-host hostgroup membership")
	}
}

func TestRegression_FreeIPAClientFreshPreviewDoesNotReadMissingSSSDConfig(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-client-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	start := strings.Index(playbook, "- name: \"FreeIPA client — inspect the current SSSD services line\"")
	if start < 0 {
		t.Fatal("SSSD services inspection task is missing")
	}
	rest := playbook[start:]
	end := strings.Index(rest[1:], "\n    - name:")
	if end < 0 {
		t.Fatal("could not isolate SSSD services inspection task")
	}
	task := rest[:end+1]
	if !strings.Contains(task, "when: not ansible_check_mode") {
		t.Fatal("fresh FreeIPA client preview must not read /etc/sssd/sssd.conf before enrollment creates it")
	}
}

// TestRegression_FreeIPANFSServerAcceptsCurrentRosterSchema locks the
// 2026-08-31 fix: this gate's accepted schema_version list must stay in
// sync with freeipa-identity-apply.yml's sibling gate, which loads the same
// roster. It hardcoded `== 1` through the v2 rollout (round 21, 2026-08-11)
// and then missed the v3 rollout the same way — v3 is the current default
// `pilot edit`'s NFS-server bootstrap itself writes into a brand-new
// roster, so a stale list here rejects every freshly-created roster
// (round 30, 2026-08-31).
func TestRegression_FreeIPANFSServerAcceptsCurrentRosterSchema(t *testing.T) {
	playbookPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-nfs-server-apply.yml")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	if !strings.Contains(playbook, "freeipa_roster.schema_version | int in [1, 2, 3]") {
		t.Error("freeipa-nfs-server-apply.yml's roster schema gate must accept [1, 2, 3], matching freeipa-identity-apply.yml's sibling gate")
	}

	identityPath := filepath.Join("..", "..", "playbooks", "apply", "freeipa-identity-apply.yml")
	identityData, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := string(identityData)
	nfsIdx := strings.Index(playbook, "schema_version | int in [")
	identityIdx := strings.Index(identity, "schema_version | int in [")
	if nfsIdx < 0 || identityIdx < 0 {
		t.Fatal("could not locate schema_version acceptance gate in one or both playbooks")
	}
	nfsList := playbook[nfsIdx : nfsIdx+strings.Index(playbook[nfsIdx:], "]")+1]
	identityList := identity[identityIdx : identityIdx+strings.Index(identity[identityIdx:], "]")+1]
	if nfsList != identityList {
		t.Errorf("freeipa-nfs-server-apply.yml's schema gate (%s) must match freeipa-identity-apply.yml's (%s)", nfsList, identityList)
	}
}
