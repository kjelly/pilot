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
		"nfs_server_fqdn == ansible_fqdn",
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
