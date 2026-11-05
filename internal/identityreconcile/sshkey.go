package identityreconcile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

var errInvalidSSHKey = errors.New("invalid SSH public key")

// NormalizeSSHKey reduces an OpenSSH public key line to "type base64",
// dropping the comment, as the #138 helper's keyset does
// (playbooks/apply/files/freeipa-ssh-key-cache.py): the type must start
// with ssh-, ecdsa- or sk-, the body must be strict base64, and the wire
// format must begin with the same algorithm name.
func NormalizeSSHKey(line string) (string, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", errInvalidSSHKey
	}
	typ := parts[0]
	if !strings.HasPrefix(typ, "ssh-") && !strings.HasPrefix(typ, "ecdsa-") && !strings.HasPrefix(typ, "sk-") {
		return "", errInvalidSSHKey
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(raw) < 4 {
		return "", errInvalidSSHKey
	}
	size := binary.BigEndian.Uint32(raw[:4])
	if uint64(len(raw)) < 4+uint64(size) || string(raw[4:4+size]) != typ {
		return "", errInvalidSSHKey
	}
	return typ + " " + parts[1], nil
}

// sshKeyID names a normalized key in a plan without its body.
func sshKeyID(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	typ, _, _ := strings.Cut(normalized, " ")
	return typ + " sha256:" + hex.EncodeToString(sum[:8])
}
