package identity

import (
	"context"
	"os"
	"os/user"
	"testing"
)

// TestLookupUsernameSelf resolves this test process's own EUID via getent
// and checks it matches os/user's view of the current user — a sanity
// check that the subprocess/parsing plumbing works. It does not exercise
// the SSSD/FreeIPA case (no cgo-free os/user fallback to compare against
// there by definition) — that was verified live on the Phase 0/1/2
// vm-target and is recorded in docs/evidence/pilot-access-gateway/.
func TestLookupUsernameSelf(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable in this sandbox: %v", err)
	}
	got, err := LookupUsername(context.Background(), uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("LookupUsername: %v", err)
	}
	if got != me.Username {
		t.Fatalf("LookupUsername = %q, want %q", got, me.Username)
	}
}

func TestLookupUsernameUnknownUID(t *testing.T) {
	if _, err := LookupUsername(context.Background(), 4294960000); err == nil {
		t.Fatalf("expected an error for a UID with no NSS entry")
	}
}
