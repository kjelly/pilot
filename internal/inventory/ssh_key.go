// ssh_key.go parses OpenSSH authorized_keys-format lines (users[].
// ssh_keys.values) structurally — never cryptographically. This package
// deliberately has no crypto dependency (this repo trimmed go.mod hard
// during the 2026-07-17 agent-surface retirement — see docs/superpowers/
// memory), and spec.md §10 only asks for "safely detectable"
// malformed/truncated rejection, blank rejection, algorithm extraction,
// and normalized-material duplicate detection — none of which need a
// real signature/curve implementation.
//
// The malformed check below is the standard "does this blob's own
// embedded algorithm name match the textual algorithm field" technique:
// an OpenSSH public key's base64 data is SSH wire format (RFC 4251 §5),
// whose very first field is a length-prefixed copy of the algorithm
// name. A genuinely truncated or corrupted key overwhelmingly fails this
// self-consistency check; it is not a substitute for verifying the key
// is cryptographically well-formed, only for catching the truncated/
// garbled cases spec.md §10 calls out.
package inventory

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// SSHKeyIssue classifies why ParseSSHAuthorizedKeyLine could not extract
// a usable key. Empty means the line parsed cleanly.
type SSHKeyIssue string

const (
	SSHKeyIssueBlank     SSHKeyIssue = "blank"
	SSHKeyIssueMalformed SSHKeyIssue = "malformed"
)

// ParsedSSHKey is one authorized_keys-format line, parsed structurally.
type ParsedSSHKey struct {
	// Raw is the original line, for error messages.
	Raw string
	// Algorithm is the line's textual algorithm field (e.g.
	// "ssh-ed25519"). Empty when Issue == SSHKeyIssueBlank.
	Algorithm string
	// Comment is everything after the base64 data field, joined with a
	// single space. Empty when absent (comments are optional).
	Comment string
	// NormalizedMaterial is the base64 field's decoded raw bytes, used
	// as a duplicate-detection key — spec.md §10: "compare normalized
	// public-key material, not comments". Empty when Issue is set.
	NormalizedMaterial string
	// Issue is "" when the key parsed cleanly.
	Issue SSHKeyIssue
}

// ParseSSHAuthorizedKeyLine parses one authorized_keys-format line.
func ParseSSHAuthorizedKeyLine(line string) ParsedSSHKey {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ParsedSSHKey{Raw: line, Issue: SSHKeyIssueBlank}
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return ParsedSSHKey{Raw: line, Issue: SSHKeyIssueMalformed}
	}
	algorithm := fields[0]
	comment := strings.Join(fields[2:], " ")

	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ParsedSSHKey{Raw: line, Algorithm: algorithm, Comment: comment, Issue: SSHKeyIssueMalformed}
	}
	declared, ok := sshBlobDeclaredAlgorithm(raw)
	if !ok || declared != algorithm {
		return ParsedSSHKey{Raw: line, Algorithm: algorithm, Comment: comment, Issue: SSHKeyIssueMalformed}
	}
	return ParsedSSHKey{Raw: line, Algorithm: algorithm, Comment: comment, NormalizedMaterial: string(raw)}
}

// sshBlobDeclaredAlgorithm reads an SSH wire-format blob's first field
// (a length-prefixed string, RFC 4251 §5) and returns it as the
// algorithm name the blob itself claims to be. ok is false when data is
// too short to even hold the length prefix, or the declared length
// exceeds the remaining bytes — both are exactly the truncation shape
// spec.md §10 calls out.
func sshBlobDeclaredAlgorithm(data []byte) (name string, ok bool) {
	if len(data) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(data[:4])
	if uint64(n) > uint64(len(data)-4) {
		return "", false
	}
	return string(data[4 : 4+n]), true
}
