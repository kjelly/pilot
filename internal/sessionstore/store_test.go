package sessionstore

import (
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	enc, err := NewEncryptor("test-key-1", key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return enc
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "index.db")
	store, err := Open(dbPath, newTestEncryptor(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func startTestSession(t *testing.T, store *Store, sessionID string) {
	t.Helper()
	ctx := context.Background()
	if err := store.StartSession(ctx, SessionStart{
		SessionID: sessionID, User: "alice", DirectoryID: "dir01", GatewayID: "gw01",
		Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
}

// TestStoreRealSQLiteAESRoundTrip proves the full ingest -> replay path
// against a REAL on-disk SQLite file and REAL AES-256-GCM, not a mock: a
// plaintext event survives seal (openDB's schema, Store.IngestEvents)
// and open (Store.Replay) byte-for-byte.
func TestStoreRealSQLiteAESRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-roundtrip")

	want := []byte("echo VERIFY_ROUNDTRIP_XYZ\r\n")
	out, err := store.IngestEvents(ctx, "sess-roundtrip", []IngestEvent{
		{Seq: 1, Stream: "tty_output", OffsetNanos: 100, Data: want},
	})
	if err != nil {
		t.Fatalf("IngestEvents: %v", err)
	}
	if out.Accepted != 1 || out.Duplicate != 0 {
		t.Fatalf("IngestEvents outcome = %+v, want Accepted=1 Duplicate=0", out)
	}

	if err := store.FinishSession(ctx, "sess-roundtrip", time.Now().UTC(), true); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}

	result, err := store.Replay(ctx, "sess-roundtrip")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("Replay events = %d, want 1", len(result.Events))
	}
	if string(result.Events[0].Data) != string(want) {
		t.Fatalf("Replay decrypted data = %q, want %q", result.Events[0].Data, want)
	}
	if len(result.Gaps) != 0 {
		t.Fatalf("Replay gaps = %+v, want none", result.Gaps)
	}
	if !result.Complete {
		t.Fatalf("Replay Complete = false, want true (no gap, session finished complete)")
	}

	// Verify the on-disk ciphertext is not the plaintext (encryption at
	// rest actually happened, not a no-op passthrough).
	var ciphertext []byte
	row := store.db.QueryRowContext(ctx, `SELECT ciphertext FROM session_events WHERE session_id=? AND seq=1`, "sess-roundtrip")
	if err := row.Scan(&ciphertext); err != nil {
		t.Fatalf("read raw ciphertext: %v", err)
	}
	if string(ciphertext) == string(want) {
		t.Fatalf("ciphertext on disk equals plaintext — encryption did not happen")
	}
}

// TestStoreIngestIdempotentRetry proves spec.md §28.1's retry-idempotency
// contract: resending the exact same (seq, payload) is a silent no-op,
// not a duplicate row or an error.
func TestStoreIngestIdempotentRetry(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-idempotent")

	ev := IngestEvent{Seq: 1, Stream: "tty_output", OffsetNanos: 50, Data: []byte("hello")}

	out1, err := store.IngestEvents(ctx, "sess-idempotent", []IngestEvent{ev})
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if out1.Accepted != 1 {
		t.Fatalf("first ingest Accepted = %d, want 1", out1.Accepted)
	}

	out2, err := store.IngestEvents(ctx, "sess-idempotent", []IngestEvent{ev})
	if err != nil {
		t.Fatalf("retried ingest (identical payload) returned error, want no-op success: %v", err)
	}
	if out2.Accepted != 0 || out2.Duplicate != 1 {
		t.Fatalf("retried ingest outcome = %+v, want Accepted=0 Duplicate=1", out2)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM session_events WHERE session_id=? AND seq=1`, "sess-idempotent").Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("session_events row count for seq=1 = %d, want exactly 1 (no duplicate row written)", count)
	}
}

// TestStoreIngestConflictingRetryFails proves the other half of spec.md
// §28.1: the SAME sequence number arriving with a DIFFERENT payload is a
// conflict, never silently accepted (which would let a client overwrite
// or race a previously-durable event).
func TestStoreIngestConflictingRetryFails(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-conflict")

	if _, err := store.IngestEvents(ctx, "sess-conflict", []IngestEvent{
		{Seq: 1, Stream: "tty_output", OffsetNanos: 50, Data: []byte("original")},
	}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	_, err := store.IngestEvents(ctx, "sess-conflict", []IngestEvent{
		{Seq: 1, Stream: "tty_output", OffsetNanos: 50, Data: []byte("different-payload")},
	})
	if err == nil {
		t.Fatalf("conflicting retry succeeded, want ErrEventConflict")
	}
	if !errors.Is(err, ErrEventConflict) {
		t.Fatalf("conflicting retry error = %v, want ErrEventConflict", err)
	}

	// The original payload must survive untouched.
	result, err := store.Replay(ctx, "sess-conflict")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(result.Events) != 1 || string(result.Events[0].Data) != "original" {
		t.Fatalf("Replay after rejected conflict = %+v, want the original payload preserved", result.Events)
	}
}

// TestStoreReplayDetectsGap proves spec.md §29's gap detection: a missing
// sequence number must surface as a GapRange and force Complete=false,
// even when FinishSession was told complete=true (the caller's own claim
// of completeness must never override what is actually on disk).
func TestStoreReplayDetectsGap(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-gap")

	if _, err := store.IngestEvents(ctx, "sess-gap", []IngestEvent{
		{Seq: 1, Stream: "tty_output", Data: []byte("a")},
		{Seq: 2, Stream: "tty_output", Data: []byte("b")},
		{Seq: 5, Stream: "tty_output", Data: []byte("e")},
	}); err != nil {
		t.Fatalf("IngestEvents: %v", err)
	}
	if err := store.FinishSession(ctx, "sess-gap", time.Now().UTC(), true); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}

	result, err := store.Replay(ctx, "sess-gap")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(result.Events) != 3 {
		t.Fatalf("Replay events = %d, want 3", len(result.Events))
	}
	if len(result.Gaps) != 1 || result.Gaps[0] != (GapRange{FromSeq: 3, ToSeq: 4}) {
		t.Fatalf("Replay gaps = %+v, want [{3 4}]", result.Gaps)
	}
	if result.Complete {
		t.Fatalf("Replay Complete = true despite a real gap, want false (RECORDING INCOMPLETE must not be hidden)")
	}
}

// TestStoreReplayTamperedCiphertextFails proves a corrupted/tampered
// on-disk payload is DETECTED, not silently returned as garbage
// plaintext — GCM's authentication tag is what makes this possible, and
// this test flips one byte directly in the database to prove it, not
// just unit-test the cipher in isolation.
func TestStoreReplayTamperedCiphertextFails(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-tamper")

	if _, err := store.IngestEvents(ctx, "sess-tamper", []IngestEvent{
		{Seq: 1, Stream: "tty_output", Data: []byte("untampered")},
	}); err != nil {
		t.Fatalf("IngestEvents: %v", err)
	}

	// Flip one bit directly in the stored ciphertext, simulating disk
	// corruption or a tampered payload file.
	var ciphertext []byte
	if err := store.db.QueryRowContext(ctx, `SELECT ciphertext FROM session_events WHERE session_id=? AND seq=1`, "sess-tamper").Scan(&ciphertext); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xFF
	if _, err := store.db.ExecContext(ctx, `UPDATE session_events SET ciphertext=? WHERE session_id=? AND seq=1`, tampered, "sess-tamper"); err != nil {
		t.Fatalf("write tampered ciphertext: %v", err)
	}

	if _, err := store.Replay(ctx, "sess-tamper"); err == nil {
		t.Fatalf("Replay of tampered ciphertext succeeded, want a decrypt/authentication failure")
	}
}

// TestStoreUnknownSessionFailsClosed proves every entry point rejects an
// unstarted session_id rather than silently creating implicit state.
func TestStoreUnknownSessionFailsClosed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.IngestEvents(ctx, "never-started", []IngestEvent{{Seq: 1, Data: []byte("x")}}); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("IngestEvents on unknown session = %v, want ErrUnknownSession", err)
	}
	if err := store.FinishSession(ctx, "never-started", time.Now(), true); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("FinishSession on unknown session = %v, want ErrUnknownSession", err)
	}
	if _, err := store.Replay(ctx, "never-started"); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("Replay on unknown session = %v, want ErrUnknownSession", err)
	}
}

// TestStoreStartSessionConflict proves a session_id re-started with
// different metadata (a different user, e.g.) fails closed rather than
// silently overwriting who the session belongs to.
func TestStoreStartSessionConflict(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-restart")

	err := store.StartSession(ctx, SessionStart{
		SessionID: "sess-restart", User: "mallory", Target: "target01.example.test",
		StartedAt: time.Now().UTC(),
	})
	if !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("StartSession with mismatched user = %v, want ErrSessionConflict", err)
	}
}

// TestStoreDeleteSessionPayloadRetentionOrder proves
// DeleteSessionPayload's three-step order (index updated, payload
// deleted, audit record written) all lands durably, and that a purged
// session's replay comes back empty rather than erroring — the index
// row itself is retained for audit history.
func TestStoreDeleteSessionPayloadRetentionOrder(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-retain")
	if _, err := store.IngestEvents(ctx, "sess-retain", []IngestEvent{
		{Seq: 1, Stream: "tty_output", Data: []byte("payload")},
	}); err != nil {
		t.Fatalf("IngestEvents: %v", err)
	}

	if err := store.DeleteSessionPayload(ctx, "sess-retain", "retention: 30 day policy"); err != nil {
		t.Fatalf("DeleteSessionPayload: %v", err)
	}

	summary, err := store.GetSession(ctx, "sess-retain")
	if err != nil {
		t.Fatalf("GetSession after purge: %v", err)
	}
	if summary.Bytes != 0 || summary.EventCount != 0 {
		t.Fatalf("index after purge = %+v, want bytes=0 event_count=0", summary)
	}

	result, err := store.Replay(ctx, "sess-retain")
	if err != nil {
		t.Fatalf("Replay after purge: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("Replay after purge returned %d events, want 0", len(result.Events))
	}

	var auditCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM retention_events WHERE session_id=? AND action='retention_delete'`, "sess-retain").Scan(&auditCount); err != nil {
		t.Fatalf("count retention_events: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("retention_events audit rows = %d, want 1", auditCount)
	}

	ids, err := store.SessionsOlderThan(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SessionsOlderThan: %v", err)
	}
	for _, id := range ids {
		if id == "sess-retain" {
			t.Fatalf("SessionsOlderThan still returned an already-purged session")
		}
	}
}

// TestStoreSessionsOlderThanRespectsCutoff proves the retention sweep
// query only selects sessions strictly older than cutoff.
func TestStoreSessionsOlderThanRespectsCutoff(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)
	if err := store.StartSession(ctx, SessionStart{SessionID: "sess-old", User: "alice", Target: "t", StartedAt: old}); err != nil {
		t.Fatalf("StartSession(old): %v", err)
	}
	if err := store.StartSession(ctx, SessionStart{SessionID: "sess-recent", User: "alice", Target: "t", StartedAt: recent}); err != nil {
		t.Fatalf("StartSession(recent): %v", err)
	}

	ids, err := store.SessionsOlderThan(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("SessionsOlderThan: %v", err)
	}
	if len(ids) != 1 || ids[0] != "sess-old" {
		t.Fatalf("SessionsOlderThan(24h cutoff) = %v, want [sess-old]", ids)
	}
}

// TestEncryptorRejectsWrongKeySize proves NewEncryptor fails closed on a
// key that cannot be AES-256.
func TestEncryptorRejectsWrongKeySize(t *testing.T) {
	if _, err := NewEncryptor("k1", make([]byte, 16)); err == nil {
		t.Fatalf("NewEncryptor accepted a 16-byte key, want an error (AES-256 requires 32 bytes)")
	}
}
