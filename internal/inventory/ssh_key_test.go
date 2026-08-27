package inventory

import "testing"

// Real ssh-keygen output (ssh-keygen -t ed25519 / -t ecdsa -b 256), not
// hand-crafted, so the wire-format self-consistency check
// (sshBlobDeclaredAlgorithm) exercises genuine SSH key bytes.
const (
	testSSHKeyEd25519          = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE+W2fUehVce+VbyNG5lfFmw3Mbfo3VDY4jJgIOynSoH test@example.com"
	testSSHKeyEd25519NoComment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE+W2fUehVce+VbyNG5lfFmw3Mbfo3VDY4jJgIOynSoH"
	testSSHKeyECDSA            = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHHMeDC4+UlmQUDXBQ+sgx5z9fViIcoM97Cug+ME5OWEpKX1MiZf4UrLJ13SE8UGSqfnAU3pBtkz0EgemXXGkW0= ecdsa@example.com"
)

func TestParseSSHAuthorizedKeyLine_ValidEd25519(t *testing.T) {
	k := ParseSSHAuthorizedKeyLine(testSSHKeyEd25519)
	if k.Issue != "" {
		t.Fatalf("expected a real ssh-keygen ed25519 key to parse cleanly, got issue %q", k.Issue)
	}
	if k.Algorithm != "ssh-ed25519" {
		t.Errorf("Algorithm = %q, want ssh-ed25519", k.Algorithm)
	}
	if k.Comment != "test@example.com" {
		t.Errorf("Comment = %q, want test@example.com", k.Comment)
	}
	if k.NormalizedMaterial == "" {
		t.Error("expected non-empty NormalizedMaterial for a cleanly-parsed key")
	}
}

func TestParseSSHAuthorizedKeyLine_ValidECDSA(t *testing.T) {
	k := ParseSSHAuthorizedKeyLine(testSSHKeyECDSA)
	if k.Issue != "" {
		t.Fatalf("expected a real ssh-keygen ecdsa key to parse cleanly, got issue %q", k.Issue)
	}
	if k.Algorithm != "ecdsa-sha2-nistp256" {
		t.Errorf("Algorithm = %q, want ecdsa-sha2-nistp256", k.Algorithm)
	}
}

func TestParseSSHAuthorizedKeyLine_NoCommentIsFine(t *testing.T) {
	k := ParseSSHAuthorizedKeyLine(testSSHKeyEd25519NoComment)
	if k.Issue != "" {
		t.Fatalf("expected a key with no comment to still parse cleanly, got issue %q", k.Issue)
	}
	if k.Comment != "" {
		t.Errorf("Comment = %q, want empty", k.Comment)
	}
}

func TestParseSSHAuthorizedKeyLine_BlankRejected(t *testing.T) {
	for _, line := range []string{"", "   ", "\t"} {
		if k := ParseSSHAuthorizedKeyLine(line); k.Issue != SSHKeyIssueBlank {
			t.Errorf("ParseSSHAuthorizedKeyLine(%q).Issue = %q, want blank", line, k.Issue)
		}
	}
}

func TestParseSSHAuthorizedKeyLine_SingleFieldRejected(t *testing.T) {
	k := ParseSSHAuthorizedKeyLine("ssh-ed25519")
	if k.Issue != SSHKeyIssueMalformed {
		t.Fatalf("expected a single-field line to be malformed, got issue %q", k.Issue)
	}
}

func TestParseSSHAuthorizedKeyLine_InvalidBase64Rejected(t *testing.T) {
	k := ParseSSHAuthorizedKeyLine("ssh-ed25519 not-valid-base64!!! comment")
	if k.Issue != SSHKeyIssueMalformed {
		t.Fatalf("expected invalid base64 to be malformed, got issue %q", k.Issue)
	}
}

func TestParseSSHAuthorizedKeyLine_TruncatedKeyRejected(t *testing.T) {
	// Chop the real ed25519 key's base64 data field down to something
	// short — still valid base64, but far too short to hold a real
	// length-prefixed algorithm name matching "ssh-ed25519" (11 chars).
	k := ParseSSHAuthorizedKeyLine("ssh-ed25519 QUFBQQ== comment")
	if k.Issue != SSHKeyIssueMalformed {
		t.Fatalf("expected a truncated key blob to be malformed, got issue %q", k.Issue)
	}
}

func TestParseSSHAuthorizedKeyLine_AlgorithmMismatchRejected(t *testing.T) {
	// The blob's real algorithm is ssh-ed25519; claiming it's an RSA key
	// must fail the self-consistency check.
	k := ParseSSHAuthorizedKeyLine("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIE+W2fUehVce+VbyNG5lfFmw3Mbfo3VDY4jJgIOynSoH comment")
	if k.Issue != SSHKeyIssueMalformed {
		t.Fatalf("expected an algorithm-field/blob mismatch to be malformed, got issue %q", k.Issue)
	}
}

func TestParseSSHAuthorizedKeyLine_DuplicateDetectionIgnoresComment(t *testing.T) {
	a := ParseSSHAuthorizedKeyLine(testSSHKeyEd25519)
	b := ParseSSHAuthorizedKeyLine(testSSHKeyEd25519NoComment)
	if a.NormalizedMaterial != b.NormalizedMaterial {
		t.Fatal("expected the same key with/without a comment to normalize to identical material")
	}
	c := ParseSSHAuthorizedKeyLine(testSSHKeyECDSA)
	if a.NormalizedMaterial == c.NormalizedMaterial {
		t.Fatal("expected different keys to normalize to different material")
	}
}
