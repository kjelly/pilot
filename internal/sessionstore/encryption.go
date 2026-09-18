package sessionstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Encryptor seals/opens one recording's event payloads with AES-256-GCM
// (spec.md §28.4): a unique nonce per event/chunk and an AAD binding
// session_id/seq/stream, so a ciphertext can never be replayed into a
// different event's slot even by someone who can write to the database
// directly.
type Encryptor struct {
	keyID string
	aead  cipher.AEAD
}

// KeyID identifies which master key sealed a session's events (spec.md
// §28.3's index.key_id column) — never the key material itself.
func (e *Encryptor) KeyID() string { return e.keyID }

// NewEncryptor builds an Encryptor from a 32-byte AES-256 key and an
// operator-assigned key ID (spec.md: "config 只 reference key file / key
// ID" — the ID is metadata, not derived from the key bytes, so rotating
// the key file's contents without renaming key_id is caught by
// Store.Replay decrypt failures rather than silently mis-tagging old
// events with a new ID).
func NewEncryptor(keyID string, key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("sessionstore: master key must be 32 bytes for AES-256, got %d", len(key))
	}
	if keyID == "" {
		return nil, fmt.Errorf("sessionstore: key ID must not be empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build AES-GCM: %w", err)
	}
	return &Encryptor{keyID: keyID, aead: gcm}, nil
}

// LoadMasterKeyFile reads the master key from a vault-provided file
// (spec.md §28.4: "vault 提供, file mode 0600, 不寫 log"). The file's
// content is a 64-character hex string (32 raw bytes hex-encoded, the
// same convention `openssl rand -hex 32` produces) with optional
// surrounding whitespace/trailing newline. The key bytes are never
// logged or returned in any error message.
func LoadMasterKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat master key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s must not be group/world accessible (mode %04o)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master key file: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode master key file: not valid hex")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key file must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

// aad builds the Additional Authenticated Data spec.md §28.4 requires:
// session_id, seq, and stream, joined so that no combination of shorter
// field values can collide into the same bytes (e.g. session "a"+seq
// 1+stream "bc" must not authenticate identically to session "ab"+seq
// 1+stream "c").
func aad(sessionID string, seq uint64, stream string) []byte {
	return []byte(fmt.Sprintf("%d:%s|%d|%d:%s", len(sessionID), sessionID, seq, len(stream), stream))
}

// seal encrypts plaintext for one event, returning a freshly generated
// nonce and the ciphertext (with GCM's authentication tag appended, as
// cipher.AEAD.Seal always does).
func (e *Encryptor) seal(sessionID string, seq uint64, stream string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext = e.aead.Seal(nil, nonce, plaintext, aad(sessionID, seq, stream))
	return nonce, ciphertext, nil
}

// open decrypts and authenticates one event. A tampered ciphertext, a
// nonce/AAD mismatch (e.g. the row was somehow associated with the wrong
// session/seq/stream), or the wrong key all fail here with the same
// generic error — cipher.AEAD deliberately gives no signal to distinguish
// them.
func (e *Encryptor) open(sessionID string, seq uint64, stream string, nonce, ciphertext []byte) ([]byte, error) {
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, aad(sessionID, seq, stream))
	if err != nil {
		return nil, fmt.Errorf("decrypt/authenticate event (session=%s seq=%d stream=%s): %w", sessionID, seq, stream, err)
	}
	return plaintext, nil
}
