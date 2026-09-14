package freeipaaccess

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// TestNewClientDoesNotEagerlyLoadCredentials pins the Phase 8 fix
// (docs/evidence/pilot-access-gateway/2026-09-14-phase8-multi-gateway-e2e.md):
// NewClient must succeed even when the keytab/CA/krb5.conf files do not
// exist yet — a missing keytab must never crash the process at startup,
// only degrade a later call.
func TestNewClientDoesNotEagerlyLoadCredentials(t *testing.T) {
	cl, err := NewClient(Config{
		Servers:    []string{"ipa1.example.com"},
		KeytabPath: filepath.Join(t.TempDir(), "does-not-exist.keytab"),
		CAFile:     filepath.Join(t.TempDir(), "does-not-exist-ca.crt"),
	})
	if err != nil {
		t.Fatalf("NewClient with a missing keytab/CA returned an error, want lazy success: %v", err)
	}
	if cl == nil {
		t.Fatal("NewClient returned a nil Client with a nil error")
	}
}

// TestClientRetriesCredentialLoadOnEveryCall proves a bad keytab degrades
// gracefully and keeps retrying on every call — never caching the first
// failure forever, and never panicking — so that fixing the file on disk
// is picked up by the very next request without a process restart.
func TestClientRetriesCredentialLoadOnEveryCall(t *testing.T) {
	dir := t.TempDir()
	krb5ConfPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(krb5ConfPath, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(dir, "gateway.keytab")
	caPath := filepath.Join(dir, "ca.crt")

	cl, err := NewClient(Config{
		Servers:          []string{"ipa1.example.com"},
		ServicePrincipal: "pilot-access-gateway/gw01.example.com",
		Krb5ConfPath:     krb5ConfPath,
		KeytabPath:       keytabPath,
		CAFile:           caPath,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// First call: keytab file does not exist at all.
	_, _, err = cl.ensureSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "load keytab") {
		t.Fatalf("ensureSession (missing keytab) = %v, want a \"load keytab\" error", err)
	}

	// Second call, same missing file: must fail the SAME way, not panic
	// or return a stale/cached success — proves buildCredentialsLocked
	// actually retries rather than caching the first attempt forever.
	_, _, err = cl.ensureSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "load keytab") {
		t.Fatalf("ensureSession (still missing) = %v, want the same \"load keytab\" error again", err)
	}

	// Now the file exists but is not a valid keytab — the error message
	// must change, proving the load was retried against the new file
	// content rather than returning a memoized failure.
	if err := os.WriteFile(keytabPath, []byte("not a keytab"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = cl.ensureSession(context.Background())
	if err == nil || strings.Contains(err.Error(), "no such file") {
		t.Fatalf("ensureSession (garbage keytab) = %v, want a parse error, not a stale \"no such file\"", err)
	}
}
