package services

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests also run unchanged against the Issue's base tree as negative
// controls: they must fail on the credential invariant, never on compilation.
func TestCredentialCounterexampleWhitespaceMustNotRegenerate(t *testing.T) {
	root := t.TempDir()
	if _, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "harbor/secrets/admin-password")
	if err := os.WriteFile(target, []byte(" \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("credential invariant: an established blank credential was silently replaced")
	}
}

func TestCredentialCounterexampleAnonymousHealthCannotAuthorizeAttach(t *testing.T) {
	m, profile, runner := healthyLifecycleFixture(t)
	m.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v2.0/users/current" {
			return jsonResponse(401, nil), nil
		}
		return jsonResponse(200, nil), nil
	})}
	err := m.Up(context.Background(), profile, net.ParseIP("127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("credential invariant: anonymous health authorized an invalid admin association: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("failed authentication mutated services")
	}
}
