package spec

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_LdapiExternalRowsRunAsRoot locks that every verification
// row reading LDAP over the ldapi socket with SASL EXTERNAL runs as root.
// Only root autobinds as Directory Manager; as the SSH user the bind is that
// uid or anonymous, sees less, and the row's verdict depends on who
// connected. Before this rule, pilot-gateway-scope.md C1-C3 and every
// freeipa-identity.md row ran without become and passed only because the
// vm-target SSH user is root (PR #89 review).
func TestRegression_LdapiExternalRowsRunAsRoot(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{`ldapsearch -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-X.socket -b cn=x cn`, true},
		{`ldapsearch -H ldapi://%2Frun%2Fslapd-X.socket -x -b cn=x`, true},
		{`ldapsearch -Y external -H ldap://ipa1 -b cn=x`, true},
		{`ldapsearch -x -H ldap://ipa1 -b cn=x cn`, false},
		{`getent passwd alice`, false},
	} {
		if got := NeedsBecome(Row{Command: c.cmd}); got != c.want {
			t.Errorf("NeedsBecome(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}

	files, err := filepath.Glob(filepath.Join("..", "..", "docs", "verification", "*.md"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no specs found: %v", err)
	}
	seen := 0
	for _, f := range files {
		s, err := Parse(f)
		if err != nil {
			continue
		}
		for _, r := range s.Rows {
			c := strings.ToLower(r.Command)
			if !strings.Contains(c, "ldapi://") && !strings.Contains(c, "-y external") {
				continue
			}
			seen++
			if !NeedsBecome(r) {
				t.Errorf("%s %s reads LDAP over ldapi/EXTERNAL but does not run as root", filepath.Base(f), r.ID)
			}
		}
	}
	// pilot-gateway-scope.md C1-C3 and freeipa-identity.md alone have 27.
	if seen < 27 {
		t.Fatalf("found only %d ldapi/EXTERNAL rows; the scan is not reading the specs", seen)
	}
}
