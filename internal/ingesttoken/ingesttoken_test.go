package ingesttoken

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	otherKey = []byte("fedcba9876543210fedcba9876543210")
	t0       = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
)

func baseClaims() Claims {
	return Claims{
		SessionID: "0b6f2c1e-8d3a-4f5b-9c7e-1a2b3c4d5e6f",
		User:      "alice", Gateway: "gpu-01", Scope: "gpu",
		Target: "db-prod-01.ipa.pilot.internal", Mode: "terminal_output", Source: "host",
	}
}

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

func mint(t *testing.T, key []byte, c Claims, lifetime time.Duration) string {
	t.Helper()
	s, err := NewSigner(key, clock(t0))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Mint(c, lifetime)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return tok
}

func verifier(t *testing.T, key []byte, at time.Time) *Verifier {
	t.Helper()
	v, err := NewVerifier(key, clock(at))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Reason != reason {
		t.Fatalf("err = %v, want reason %q", err, reason)
	}
}

func TestMintVerifyRoundTrip(t *testing.T) {
	tok := mint(t, testKey, baseClaims(), 24*time.Hour)
	if !strings.HasPrefix(tok, "pit1.") || strings.Count(tok, ".") != 2 {
		t.Fatalf("token shape = %q", tok)
	}
	c, err := verifier(t, testKey, t0.Add(time.Minute)).Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := baseClaims()
	if c.SessionID != want.SessionID || c.User != want.User || c.Gateway != want.Gateway || c.Scope != want.Scope || c.Target != want.Target || c.Mode != want.Mode || c.Source != want.Source {
		t.Fatalf("claims = %+v", c)
	}
	if c.IssuedAt != t0.Unix() || c.StartBy != t0.Add(StartWindow).Unix() || c.Expires != t0.Add(24*time.Hour).Unix() || c.KeyID != KeyID(testKey) || !jtiPattern.MatchString(c.JTI) {
		t.Fatalf("derived claims = %+v", c)
	}
}

func TestMint_UniqueJTI(t *testing.T) {
	s, err := NewSigner(testKey, clock(t0))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Mint(baseClaims(), time.Hour)
	b, _ := s.Mint(baseClaims(), time.Hour)
	ca, _ := verifier(t, testKey, t0).Verify(a)
	cb, _ := verifier(t, testKey, t0).Verify(b)
	if ca.JTI == "" || ca.JTI == cb.JTI {
		t.Fatalf("two mints share jti %q", ca.JTI)
	}
}

func TestVerify_Malformed(t *testing.T) {
	v := verifier(t, testKey, t0)
	tok := mint(t, testKey, baseClaims(), time.Hour)
	parts := strings.Split(tok, ".")
	for _, bad := range []string{"", "pit1", "pit2." + parts[1] + "." + parts[2], "pit1.%%%." + parts[2], "pit1." + parts[1] + ".%%%", tok + ".x"} {
		_, err := v.Verify(bad)
		wantReason(t, err, ReasonMalformed)
	}
}

func TestVerify_UnknownKey(t *testing.T) {
	tok := mint(t, otherKey, baseClaims(), time.Hour)
	_, err := verifier(t, testKey, t0).Verify(tok)
	wantReason(t, err, ReasonUnknownKey)
}

func TestVerify_BadSignature(t *testing.T) {
	tok := mint(t, testKey, baseClaims(), time.Hour)
	parts := strings.Split(tok, ".")
	// Tamper with the claims but keep the kid: the MAC no longer matches.
	payload, _ := b64.DecodeString(parts[1])
	var c Claims
	_ = json.Unmarshal(payload, &c)
	c.User = "mallory"
	forged, _ := json.Marshal(c)
	_, err := verifier(t, testKey, t0).Verify(parts[0] + "." + b64.EncodeToString(forged) + "." + parts[2])
	wantReason(t, err, ReasonBadSignature)
}

func TestVerify_NotYetValidAndExpired(t *testing.T) {
	tok := mint(t, testKey, baseClaims(), time.Hour)
	_, err := verifier(t, testKey, t0.Add(-2*ClockSkew)).Verify(tok)
	wantReason(t, err, ReasonNotYetValid)
	if _, err := verifier(t, testKey, t0.Add(-ClockSkew/2)).Verify(tok); err != nil {
		t.Fatalf("within skew before iat: %v", err)
	}
	_, err = verifier(t, testKey, t0.Add(time.Hour+2*ClockSkew)).Verify(tok)
	wantReason(t, err, ReasonExpired)
	if _, err := verifier(t, testKey, t0.Add(time.Hour+ClockSkew/2)).Verify(tok); err != nil {
		t.Fatalf("within skew after exp: %v", err)
	}
}

// TestVerify_DoesNotCheckStartWindow guards the recorded session's long
// tail: events and finish arrive long after the start window closes.
func TestVerify_DoesNotCheckStartWindow(t *testing.T) {
	tok := mint(t, testKey, baseClaims(), 24*time.Hour)
	c, err := verifier(t, testKey, t0.Add(1000*time.Second)).Verify(tok)
	if err != nil {
		t.Fatalf("Verify at iat+1000s: %v", err)
	}
	v := verifier(t, testKey, t0.Add(StartWindow+ClockSkew+time.Second))
	wantReason(t, v.CheckStartWindow(c), ReasonStartWindowClosed)
	if err := verifier(t, testKey, t0.Add(StartWindow+ClockSkew-time.Second)).CheckStartWindow(c); err != nil {
		t.Fatalf("start window at sby+59s: %v", err)
	}
}

func TestMint_RejectsInvalidClaims(t *testing.T) {
	cases := map[string]func(*Claims){
		"bad sid":         func(c *Claims) { c.SessionID = "not-a-uuid" },
		"empty user":      func(c *Claims) { c.User = "" },
		"metadata mode":   func(c *Claims) { c.Mode = "metadata" },
		"built-in source": func(c *Claims) { c.Source = "built_in_default" },
	}
	s, _ := NewSigner(testKey, clock(t0))
	for name, mutate := range cases {
		c := baseClaims()
		mutate(&c)
		_, err := s.Mint(c, time.Hour)
		if err == nil {
			t.Errorf("%s: Mint accepted invalid claims", name)
			continue
		}
		wantReason(t, err, ReasonInvalidClaims)
	}
	if _, err := s.Mint(baseClaims(), MaxLifetime+time.Hour); err == nil {
		t.Error("Mint accepted a lifetime above MaxLifetime")
	}
}

func TestVerify_RejectsUnknownClaimField(t *testing.T) {
	c := baseClaims()
	c.IssuedAt, c.StartBy, c.Expires = t0.Unix(), t0.Add(StartWindow).Unix(), t0.Add(time.Hour).Unix()
	c.JTI, c.KeyID = strings.Repeat("a", 32), KeyID(testKey)
	raw, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["admin"] = true
	payload, _ := json.Marshal(m)
	input := Version + "." + b64.EncodeToString(payload)
	tok := input + "." + b64.EncodeToString(mac(testKey, input))
	_, err := verifier(t, testKey, t0).Verify(tok)
	wantReason(t, err, ReasonMalformed)
}

func TestVerify_RejectsBadJTI(t *testing.T) {
	c := baseClaims()
	c.IssuedAt, c.StartBy, c.Expires = t0.Unix(), t0.Add(StartWindow).Unix(), t0.Add(time.Hour).Unix()
	c.KeyID = KeyID(testKey)
	for _, jti := range []string{"", "short", strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		c.JTI = jti
		payload, _ := json.Marshal(c)
		input := Version + "." + b64.EncodeToString(payload)
		tok := input + "." + b64.EncodeToString(mac(testKey, input))
		_, err := verifier(t, testKey, t0).Verify(tok)
		wantReason(t, err, ReasonInvalidClaims)
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	tok := mint(t, testKey, baseClaims(), time.Hour)
	for _, v := range []*Verifier{verifier(t, otherKey, t0), verifier(t, testKey, t0.Add(48*time.Hour))} {
		_, err := v.Verify(tok)
		if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), strings.Split(tok, ".")[2]) {
			t.Fatalf("error %v leaks token material", err)
		}
	}
}

func TestLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "k")
	if err := os.WriteFile(good, []byte(strings.Repeat("ab", KeySize)+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKeyFile(good)
	if err != nil || len(key) != KeySize {
		t.Fatalf("LoadKeyFile = %d bytes, %v", len(key), err)
	}
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte(strings.Repeat("ab", KeySize)), 0o640)
	if _, err := LoadKeyFile(loose); err == nil {
		t.Fatal("group-readable key file accepted")
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("abcd"), 0o600)
	if _, err := LoadKeyFile(short); err == nil {
		t.Fatal("short key accepted")
	}
}
