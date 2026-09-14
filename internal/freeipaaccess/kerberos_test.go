package freeipaaccess

import "testing"

func TestSplitPrincipalRealm(t *testing.T) {
	cases := []struct {
		in            string
		wantPrincipal string
		wantRealm     string
	}{
		{"pilot-access-gateway/gw01.example.com", "pilot-access-gateway/gw01.example.com", ""},
		{"pilot-access-gateway/gw01.example.com@LINKER.INTERNAL", "pilot-access-gateway/gw01.example.com", "LINKER.INTERNAL"},
	}
	for _, c := range cases {
		principal, realm := splitPrincipalRealm(c.in)
		if principal != c.wantPrincipal || realm != c.wantRealm {
			t.Errorf("splitPrincipalRealm(%q) = (%q, %q), want (%q, %q)", c.in, principal, realm, c.wantPrincipal, c.wantRealm)
		}
	}
}
