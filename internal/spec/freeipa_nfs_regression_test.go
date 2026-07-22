package spec

import (
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
	client, _ := Parse("../../docs/verification/freeipa-nfs-client.md")
	all = ""
	for _, row := range client.Rows {
		all += row.Command + " " + row.Expected
	}
	if !strings.Contains(all, "/etc/fstab") || !strings.Contains(all, "autofs") {
		t.Error("NFS client spec must lock automount and forbid fstab mutation")
	}
}
