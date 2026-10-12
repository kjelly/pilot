package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/sessionstore"
)

var ingestTestKey = []byte("0123456789abcdef0123456789abcdef")

func newTestStoreForIngestAPI(t *testing.T) *sessionstore.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	enc, err := sessionstore.NewEncryptor("test-key", key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	store, err := sessionstore.Open(filepath.Join(t.TempDir(), "index.db"), enc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// ingestHarness is a real httptest server over a real store, a signer and
// a verifier sharing one key, and a movable clock.
type ingestHarness struct {
	t       *testing.T
	store   *sessionstore.Store
	srv     *httptest.Server
	metrics *storeMetrics
	mu      sync.Mutex
	now     time.Time
}

func newIngestHarness(t *testing.T) *ingestHarness {
	t.Helper()
	h := &ingestHarness{t: t, store: newTestStoreForIngestAPI(t), now: time.Now().UTC()}
	v, err := ingesttoken.NewVerifier(ingestTestKey, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	ingest := newIngestServer(h.store, v, nil)
	h.metrics = newStoreMetrics()
	ingest.metrics = h.metrics
	h.srv = httptest.NewServer(ingest.routes())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *ingestHarness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *ingestHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func testClaims(sid, user string) ingesttoken.Claims {
	return ingesttoken.Claims{
		SessionID: sid, User: user, Gateway: "gw01", Scope: "gpu",
		Target: "target01.example.test", Mode: "terminal_output", Source: "host",
	}
}

func (h *ingestHarness) mint(c ingesttoken.Claims) string {
	h.t.Helper()
	s, err := ingesttoken.NewSigner(ingestTestKey, h.clock)
	if err != nil {
		h.t.Fatal(err)
	}
	tok, err := s.Mint(c, 24*time.Hour)
	if err != nil {
		h.t.Fatalf("Mint: %v", err)
	}
	return tok
}

func (h *ingestHarness) post(token, path string, body any) (int, string) {
	h.t.Helper()
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader(payload))
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func startBody(c ingesttoken.Claims) sessionStartRequest {
	return sessionStartRequest{
		SessionID: c.SessionID, User: c.User, GatewayID: c.Gateway, Scope: c.Scope,
		Target: c.Target, RecordingMode: c.Mode, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func eventsBody(sid string, seqs ...uint64) eventsRequest {
	var evs []wireEvent
	for _, seq := range seqs {
		evs = append(evs, wireEvent{
			SchemaVersion: 1, SessionID: sid, Seq: seq, Stream: "tty_output",
			DataBase64: base64.StdEncoding.EncodeToString([]byte("chunk")),
		})
	}
	return eventsRequest{Events: evs}
}

func finishBody(endedAt string, complete bool, lastSeq uint64) map[string]any {
	return map[string]any{"ended_at": endedAt, "complete": complete, "last_seq": lastSeq}
}

const (
	sidA = "0b6f2c1e-8d3a-4f5b-9c7e-1a2b3c4d5e6f"
	sidB = "7d1e9a33-2c4b-4e8f-a1b2-c3d4e5f60718"
)

// TestIngestAPIFullLifecycle drives start -> events -> finish over real
// HTTP against a real SQLite store with a real PIT1 token.
func TestIngestAPIFullLifecycle(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)

	if code, body := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
		t.Fatalf("start = %d %s", code, body)
	}
	if code, body := h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1, 2)); code != http.StatusOK {
		t.Fatalf("events = %d %s", code, body)
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	if code, body := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 2)); code != http.StatusOK {
		t.Fatalf("finish = %d %s", code, body)
	}
	sum, err := h.store.GetSession(t.Context(), sidA)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Complete || sum.EventCount != 2 || sum.LastSeq != 2 || sum.RecordingPolicySource != "host" || sum.User != "alice" {
		t.Fatalf("stored session = %+v", sum)
	}
}

// TestIngestAPIRejectsInvalidSessionToken locks SS03.
func TestIngestAPIRejectsInvalidSessionToken(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	good := h.mint(c)

	otherSigner, _ := ingesttoken.NewSigner([]byte("fedcba9876543210fedcba9876543210"), h.clock)
	foreignKey, _ := otherSigner.Mint(c, time.Hour)
	parts := strings.Split(good, ".")
	badSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

	for name, tok := range map[string]string{
		"missing":     "",
		"garbage":     "not-a-token",
		"foreign key": foreignKey,
		"bad sig":     badSig,
		"old bearer":  "correct-token",
	} {
		code, body := h.post(tok, "/v1/sessions/start", startBody(c))
		if code != http.StatusUnauthorized || !strings.Contains(body, "unauthorized") {
			t.Errorf("%s: start = %d %s, want 401 unauthorized", name, code, body)
		}
		if strings.Contains(body, good) {
			t.Errorf("%s: response echoes token material", name)
		}
	}

	// Expired: well past exp.
	h.advance(25*time.Hour + 2*ingesttoken.ClockSkew)
	if code, _ := h.post(good, "/v1/sessions/start", startBody(c)); code != http.StatusUnauthorized {
		t.Errorf("expired token start = %d, want 401", code)
	}
}

// TestIngestAPIStartMustMatchClaims locks SS19.
func TestIngestAPIStartMustMatchClaims(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)

	for name, mutate := range map[string]func(*sessionStartRequest){
		"user":    func(b *sessionStartRequest) { b.User = "bob" },
		"target":  func(b *sessionStartRequest) { b.Target = "other.example.test" },
		"mode":    func(b *sessionStartRequest) { b.RecordingMode = "terminal_io" },
		"gateway": func(b *sessionStartRequest) { b.GatewayID = "gw02" },
		"scope":   func(b *sessionStartRequest) { b.Scope = "dmz" },
		"sid":     func(b *sessionStartRequest) { b.SessionID = sidB },
	} {
		b := startBody(c)
		mutate(&b)
		if code, body := h.post(tok, "/v1/sessions/start", b); code != http.StatusForbidden || !strings.Contains(body, "claims_mismatch") {
			t.Errorf("%s mismatch: start = %d %s, want 403 claims_mismatch", name, code, body)
		}
	}
	b := startBody(c)
	b.DirectoryID = "dir01"
	if code, body := h.post(tok, "/v1/sessions/start", b); code != http.StatusBadRequest || !strings.Contains(body, "unbound_field") {
		t.Errorf("directory_id: start = %d %s, want 400 unbound_field", code, body)
	}
	// Identical retry of a valid start is idempotent.
	for i := 0; i < 2; i++ {
		if code, body := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
			t.Fatalf("start attempt %d = %d %s", i, code, body)
		}
	}
}

// TestIngestAPISessionIDBinding locks SS20 (path/body binding).
func TestIngestAPISessionIDBinding(t *testing.T) {
	h := newIngestHarness(t)
	a := testClaims(sidA, "alice")
	tokA := h.mint(a)
	if code, _ := h.post(tokA, "/v1/sessions/start", startBody(a)); code != http.StatusOK {
		t.Fatal("start A")
	}
	b := testClaims(sidB, "alice")
	tokB := h.mint(b)
	if code, _ := h.post(tokB, "/v1/sessions/start", startBody(b)); code != http.StatusOK {
		t.Fatal("start B")
	}
	// A's token against B's path.
	if code, body := h.post(tokA, "/v1/sessions/"+sidB+"/events", eventsBody(sidB, 1)); code != http.StatusForbidden || !strings.Contains(body, "session_id_mismatch") {
		t.Errorf("A token on B path = %d %s, want 403 session_id_mismatch", code, body)
	}
	// A's own path but an event claiming B.
	if code, body := h.post(tokA, "/v1/sessions/"+sidA+"/events", eventsBody(sidB, 1)); code != http.StatusBadRequest {
		t.Errorf("event session_id mismatch = %d %s, want 400", code, body)
	}
}

// TestIngestAPIRejectsOtherUsersTokenForSameSID locks SS20's cross-user
// case: the sid is user-controllable and not secret, so mallory can get a
// token for alice's sid — it must not let her touch alice's recording.
func TestIngestAPIRejectsOtherUsersTokenForSameSID(t *testing.T) {
	h := newIngestHarness(t)
	alice := testClaims(sidA, "alice")
	tokAlice := h.mint(alice)
	if code, _ := h.post(tokAlice, "/v1/sessions/start", startBody(alice)); code != http.StatusOK {
		t.Fatal("start alice")
	}
	mallory := testClaims(sidA, "mallory")
	tokMallory := h.mint(mallory)
	if code, _ := h.post(tokMallory, "/v1/sessions/start", startBody(mallory)); code != http.StatusConflict {
		t.Errorf("mallory start on alice's sid = %d, want 409", code)
	}
	if code, body := h.post(tokMallory, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1)); code != http.StatusForbidden || !strings.Contains(body, "claims_mismatch") {
		t.Errorf("mallory events on alice's sid = %d %s, want 403 claims_mismatch", code, body)
	}
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	if code, _ := h.post(tokMallory, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 0)); code != http.StatusForbidden {
		t.Errorf("mallory finish on alice's sid = %d, want 403", code)
	}
	if sum, _ := h.store.GetSession(t.Context(), sidA); sum.EndedAt != nil || sum.EventCount != 0 {
		t.Fatalf("alice's session was modified: %+v", sum)
	}
}

// TestIngestAPIRejectsSecondTokenForSameSID: even the same user cannot take
// over a running session with a second token (a different jti).
func TestIngestAPIRejectsSecondTokenForSameSID(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	first := h.mint(c)
	if code, _ := h.post(first, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
		t.Fatal("start")
	}
	second := h.mint(c)
	if code, _ := h.post(second, "/v1/sessions/start", startBody(c)); code != http.StatusConflict {
		t.Errorf("second token start = %d, want 409", code)
	}
	if code, body := h.post(second, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1)); code != http.StatusForbidden {
		t.Errorf("second token events = %d %s, want 403", code, body)
	}
}

// TestIngestAPIRejectsEventsAfterFinish locks SS21.
func TestIngestAPIRejectsEventsAfterFinish(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 0)); code != http.StatusOK {
		t.Fatal("finish")
	}
	if code, body := h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1)); code != http.StatusConflict || !strings.Contains(body, "session_finished") {
		t.Errorf("events after finish = %d %s, want 409 session_finished", code, body)
	}
	if code, _ := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusConflict {
		t.Errorf("start after finish = %d, want 409", code)
	}
}

func TestIngestAPIFinishIdempotentRetry(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1))
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 2; i++ {
		if code, body := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 1)); code != http.StatusOK {
			t.Fatalf("finish attempt %d = %d %s", i, code, body)
		}
	}
}

func TestIngestAPIFinishDifferentBodyConflict(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1))
	ended := time.Now().UTC()
	h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended.Format(time.RFC3339Nano), true, 1))
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended.Add(time.Second).Format(time.RFC3339Nano), true, 1)); code != http.StatusConflict {
		t.Errorf("finish with a different ended_at = %d, want 409", code)
	}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended.Format(time.RFC3339Nano), true, 3)); code != http.StatusConflict {
		t.Errorf("finish with a different last_seq = %d, want 409", code)
	}
}

// TestIngestAPIFinishOnlyCompleteDiffers: the stored complete is the
// store's own recomputation, so a retry that only differs in the client's
// complete flag is still the same finish.
func TestIngestAPIFinishOnlyCompleteDiffers(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 0))
	if code, body := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, false, 0)); code != http.StatusOK {
		t.Errorf("finish retry differing only in complete = %d %s, want 200", code, body)
	}
}

func TestIngestAPIFinishRequiresEndedAt(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	for name, body := range map[string]map[string]any{
		"no ended_at":  {"complete": true, "last_seq": 0},
		"bad ended_at": {"ended_at": "yesterday", "complete": true, "last_seq": 0},
	} {
		if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", body); code != http.StatusBadRequest {
			t.Errorf("%s: finish = %d, want 400", name, code)
		}
	}
}

func TestIngestAPIFinishRequiresLastSeq(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 3))
	ended := time.Now().UTC().Format(time.RFC3339Nano)
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", map[string]any{"ended_at": ended, "complete": true}); code != http.StatusBadRequest {
		t.Errorf("finish without last_seq = %d, want 400", code)
	}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(ended, true, 2)); code != http.StatusBadRequest {
		t.Errorf("finish with last_seq below a stored seq = %d, want 400", code)
	}
}

// TestIngestAPIStartOnFinishedSessionConflict: a finished session can never
// be reopened, even by its own token.
func TestIngestAPIStartOnFinishedSessionConflict(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	h.post(tok, "/v1/sessions/"+sidA+"/finish", finishBody(time.Now().UTC().Format(time.RFC3339Nano), true, 0))
	if code, body := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusConflict || !strings.Contains(body, "session_finished") {
		t.Errorf("start on finished session = %d %s, want 409 session_finished", code, body)
	}
}

// TestIngestAPIEventsAcceptedAfterStartWindow: the start window only gates
// start; a long session keeps writing.
func TestIngestAPIEventsAcceptedAfterStartWindow(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	if code, _ := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
		t.Fatal("start")
	}
	h.advance(1000 * time.Second)
	if code, body := h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1)); code != http.StatusOK {
		t.Fatalf("events at iat+1000s = %d %s, want 200", code, body)
	}
	late := testClaims(sidB, "alice")
	lateTok := h.mint(late) // minted at the advanced clock
	h.advance(ingesttoken.StartWindow + ingesttoken.ClockSkew + time.Second)
	if code, body := h.post(lateTok, "/v1/sessions/start", startBody(late)); code != http.StatusUnauthorized || !strings.Contains(body, "start_window_closed") {
		t.Fatalf("start after the window = %d %s, want 401 start_window_closed", code, body)
	}
}

func TestIngestAPIEventConflictReturns409(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	h.post(tok, "/v1/sessions/start", startBody(c))
	first := eventsBody(sidA, 1)
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/events", first); code != http.StatusOK {
		t.Fatal("events")
	}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/events", first); code != http.StatusOK {
		t.Fatal("identical retry must be a no-op")
	}
	conflict := first
	conflict.Events = []wireEvent{{SchemaVersion: 1, SessionID: sidA, Seq: 1, Stream: "tty_output", DataBase64: base64.StdEncoding.EncodeToString([]byte("different"))}}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/events", conflict); code != http.StatusConflict {
		t.Fatalf("divergent payload for an existing seq = %d, want 409", code)
	}
}

// TestIngestAPILogsInternalErrors: a store failure (found live as SQLite
// "database or disk is full", per-host recording spec L18) answers 500 and
// logs the cause, since the recorder only sees a retryable error.
func TestIngestAPILogsInternalErrors(t *testing.T) {
	h := newIngestHarness(t)
	c := testClaims(sidA, "alice")
	tok := h.mint(c)
	if code, body := h.post(tok, "/v1/sessions/start", startBody(c)); code != http.StatusOK {
		t.Fatalf("start = %d %s", code, body)
	}
	var logs bytes.Buffer
	v, err := ingesttoken.NewVerifier(ingestTestKey, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newIngestServer(h.store, v, slog.New(slog.NewTextHandler(&logs, nil))).routes())
	t.Cleanup(srv.Close)
	h.srv = srv
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.post(tok, "/v1/sessions/"+sidA+"/events", eventsBody(sidA, 1)); code != http.StatusInternalServerError {
		t.Fatalf("events on a failing store = %d, want 500", code)
	}
	if !strings.Contains(logs.String(), "ingest request failed") || strings.Contains(logs.String(), tok) {
		t.Fatalf("log = %q, want the failure logged without the token", logs.String())
	}
}
