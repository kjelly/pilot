// Package ingesttoken mints and verifies Pilot Ingest Tokens (PIT1): short
// lived, per-session bearer tokens pilot-access-gateway hands to one
// recorded session and pilot-session-store verifies on every ingest call
// (per-host recording spec §16, decision D-B).
//
// A token is an HMAC-SHA256 over its claims with a key shared by the
// gateway and the store. It binds one session id plus the session's
// identity (user, gateway, scope, target, mode, policy source) and a random
// jti, so a token obtained for one session cannot write into, start, or
// finish any other session. The token and key never appear in errors.
package ingesttoken

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// Version is the token prefix and the MAC domain separator.
	Version = "pit1"
	// KeySize is the signing key length in bytes (64 hex characters).
	KeySize = 32
	// StartWindow bounds how long after issue the session may be started;
	// it covers the user typing a Kerberos password after authorize.
	StartWindow = 900 * time.Second
	// MaxLifetime caps exp - iat.
	MaxLifetime = 168 * time.Hour
	// ClockSkew is the tolerated clock difference between gateway and store.
	ClockSkew = 60 * time.Second
)

// Fixed failure reasons. They are safe to log and to count in metrics.
const (
	ReasonMalformed         = "malformed"
	ReasonUnknownKey        = "unknown_key"
	ReasonBadSignature      = "bad_signature"
	ReasonNotYetValid       = "not_yet_valid"
	ReasonExpired           = "expired"
	ReasonStartWindowClosed = "start_window_closed"
	ReasonInvalidClaims     = "invalid_claims"
)

// Recording modes and policy sources a token may carry. metadata sessions
// never receive a token.
var (
	validModes   = map[string]bool{"terminal_output": true, "terminal_io": true}
	validSources = map[string]bool{"host": true, "gateway_default": true}
	jtiPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Error is a token rejection. Its message carries only the fixed Reason.
type Error struct {
	Reason string
}

func (e *Error) Error() string { return "ingest token rejected: " + e.Reason }

func reject(reason string) error { return &Error{Reason: reason} }

// Claims is the signed PIT1 payload.
type Claims struct {
	SessionID string `json:"sid"`
	User      string `json:"usr"`
	Gateway   string `json:"gw"`
	Scope     string `json:"scp"`
	Target    string `json:"tgt"`
	Mode      string `json:"mode"`
	Source    string `json:"src"`
	IssuedAt  int64  `json:"iat"`
	StartBy   int64  `json:"sby"`
	Expires   int64  `json:"exp"`
	JTI       string `json:"jti"`
	KeyID     string `json:"kid"`
}

// KeyID derives the non-secret key identifier carried in every token, so a
// gateway/store key mismatch is diagnosable without revealing the key.
func KeyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("pilot-ingest-kid-v1"), key...))
	return hex.EncodeToString(sum[:])[:16]
}

// ParseKeyHex decodes a 64-hex-character signing key.
func ParseKeyHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 2*KeySize {
		return nil, fmt.Errorf("ingest signing key must be %d hex characters, got %d", 2*KeySize, len(s))
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ingest signing key is not valid hex")
	}
	return key, nil
}

// LoadKeyFile reads a signing key file that must not be group- or
// world-accessible.
func LoadKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat ingest signing key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ingest signing key file %s must not be group/world accessible (mode %04o)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ingest signing key file: %w", err)
	}
	key, err := ParseKeyHex(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

func mac(key []byte, signingInput string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(signingInput))
	return m.Sum(nil)
}

var b64 = base64.RawURLEncoding

// Signer mints tokens (pilot-access-gateway side).
type Signer struct {
	key  []byte
	kid  string
	now  func() time.Time
	rand io.Reader
}

// NewSigner returns a Signer for key. now defaults to time.Now.
func NewSigner(key []byte, now func() time.Time) (*Signer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("ingest signing key must be %d bytes", KeySize)
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{key: append([]byte(nil), key...), kid: KeyID(key), now: now, rand: rand.Reader}, nil
}

// Mint signs c after filling IssuedAt, StartBy, Expires (IssuedAt +
// lifetime), JTI and KeyID. The session identity fields of c must already
// be set and are validated with the same rules Verify applies.
func (s *Signer) Mint(c Claims, lifetime time.Duration) (string, error) {
	var jti [16]byte
	if _, err := io.ReadFull(s.rand, jti[:]); err != nil {
		return "", fmt.Errorf("generate ingest token jti: %w", err)
	}
	now := s.now().Unix()
	c.IssuedAt = now
	c.StartBy = now + int64(StartWindow/time.Second)
	c.Expires = now + int64(lifetime/time.Second)
	c.JTI = hex.EncodeToString(jti[:])
	c.KeyID = s.kid
	if err := validateClaims(c); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := Version + "." + b64.EncodeToString(payload)
	return signingInput + "." + b64.EncodeToString(mac(s.key, signingInput)), nil
}

// Verifier checks tokens (pilot-session-store side).
type Verifier struct {
	key []byte
	kid string
	now func() time.Time
}

// NewVerifier returns a Verifier for key. now defaults to time.Now.
func NewVerifier(key []byte, now func() time.Time) (*Verifier, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("ingest signing key must be %d bytes", KeySize)
	}
	if now == nil {
		now = time.Now
	}
	return &Verifier{key: append([]byte(nil), key...), kid: KeyID(key), now: now}, nil
}

// KeyID returns the verifier's key identifier (for diagnostics).
func (v *Verifier) KeyID() string { return v.kid }

// Verify checks format, key id, signature, claims, iat and exp. It does NOT
// check the start window: events and finish for a long session arrive well
// after it closes (use CheckStartWindow in the start handler only).
func (v *Verifier) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != Version || parts[1] == "" || parts[2] == "" {
		return Claims{}, reject(ReasonMalformed)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, reject(ReasonMalformed)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return Claims{}, reject(ReasonMalformed)
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Claims{}, reject(ReasonMalformed)
	}
	if c.KeyID != v.kid {
		return Claims{}, reject(ReasonUnknownKey)
	}
	if !hmac.Equal(sig, mac(v.key, parts[0]+"."+parts[1])) {
		return Claims{}, reject(ReasonBadSignature)
	}
	if err := validateClaims(c); err != nil {
		return Claims{}, err
	}
	now := v.now()
	if now.Add(ClockSkew).Before(time.Unix(c.IssuedAt, 0)) {
		return Claims{}, reject(ReasonNotYetValid)
	}
	if now.Add(-ClockSkew).After(time.Unix(c.Expires, 0)) {
		return Claims{}, reject(ReasonExpired)
	}
	return c, nil
}

// CheckStartWindow rejects c once its start window (plus clock skew) has
// passed. Only the session start handler calls it.
func (v *Verifier) CheckStartWindow(c Claims) error {
	if v.now().Add(-ClockSkew).After(time.Unix(c.StartBy, 0)) {
		return reject(ReasonStartWindowClosed)
	}
	return nil
}

func validateClaims(c Claims) error {
	if _, err := uuid.Parse(c.SessionID); err != nil || len(c.SessionID) != 36 {
		return reject(ReasonInvalidClaims)
	}
	if c.User == "" || c.Gateway == "" || c.Scope == "" || c.Target == "" {
		return reject(ReasonInvalidClaims)
	}
	if !validModes[c.Mode] || !validSources[c.Source] || !jtiPattern.MatchString(c.JTI) || c.KeyID == "" {
		return reject(ReasonInvalidClaims)
	}
	if c.Expires <= c.IssuedAt || time.Duration(c.Expires-c.IssuedAt)*time.Second > MaxLifetime {
		return reject(ReasonInvalidClaims)
	}
	if c.StartBy <= c.IssuedAt || c.StartBy > c.Expires {
		return reject(ReasonInvalidClaims)
	}
	return nil
}
