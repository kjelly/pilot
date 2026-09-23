package sessionstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// schemaV1 is the sessions table exactly as SchemaVersion 1 shipped, used to
// build a real v1 database for the migration tests.
const schemaV1 = `
CREATE TABLE sessions (
    session_id      TEXT PRIMARY KEY,
    user            TEXT NOT NULL,
    directory_id    TEXT NOT NULL DEFAULT '',
    gateway_id      TEXT NOT NULL DEFAULT '',
    scope           TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    recording_mode  TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    ended_at        TEXT NOT NULL DEFAULT '',
    complete        INTEGER NOT NULL DEFAULT 0,
    bytes           INTEGER NOT NULL DEFAULT 0,
    event_count     INTEGER NOT NULL DEFAULT 0,
    key_id          TEXT NOT NULL DEFAULT ''
);
INSERT INTO sessions (session_id, user, gateway_id, scope, target, recording_mode, started_at, ended_at, complete, key_id)
VALUES ('legacy-1', 'bob', 'gw01', 'gpu', 't1.example.test', 'terminal_output', '2026-09-01T00:00:00Z', '2026-09-01T00:10:00Z', 1, 'test-key-1');
PRAGMA user_version = 1;
`

func writeV1Database(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "index.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schemaV1); err != nil {
		t.Fatalf("build v1 database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func userVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestStoreMigratesV1ToV2(t *testing.T) {
	path := writeV1Database(t)
	store, err := Open(path, newTestEncryptor(t))
	if err != nil {
		t.Fatalf("Open v1 database: %v", err)
	}
	defer func() { _ = store.Close() }()

	got, err := store.GetSession(context.Background(), "legacy-1")
	if err != nil {
		t.Fatalf("legacy session lost in migration: %v", err)
	}
	if got.User != "bob" || !got.Complete || got.RecordingPolicySource != "" || got.LastSeq != 0 || got.IngestJTI != "" {
		t.Fatalf("migrated row = %+v", got)
	}
	if v := userVersion(t, path); v != SchemaVersion {
		t.Fatalf("user_version after migration = %d, want %d", v, SchemaVersion)
	}
	// The migrated database accepts the new columns.
	if err := store.StartSession(context.Background(), SessionStart{
		SessionID: "new-1", User: "alice", GatewayID: "gw01", Scope: "gpu", Target: "t2.example.test",
		RecordingMode: "terminal_output", RecordingPolicySource: "host", IngestJTI: strings.Repeat("a", 32),
	}); err != nil {
		t.Fatalf("StartSession on migrated database: %v", err)
	}
}

func TestStoreMigrationBacksUpBeforeAlter(t *testing.T) {
	path := writeV1Database(t)
	store, err := Open(path, newTestEncryptor(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = store.Close()

	backup := backupPath(path, 1)
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("pre-migration backup missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %04o, want 0600", info.Mode().Perm())
	}
	// The backup is the untouched v1 database.
	if v := userVersion(t, backup); v != 1 {
		t.Fatalf("backup user_version = %d, want 1 (taken before migration)", v)
	}
}

func TestStoreMigrationRefusesWithoutSpace(t *testing.T) {
	path := writeV1Database(t)
	orig := freeBytesFunc
	freeBytesFunc = func(string) (uint64, error) { return 1, nil }
	t.Cleanup(func() { freeBytesFunc = orig })

	if _, err := Open(path, newTestEncryptor(t)); err == nil || !strings.Contains(err.Error(), "need at least") {
		t.Fatalf("Open with no free space = %v, want refusal", err)
	}
	if v := userVersion(t, path); v != 1 {
		t.Fatalf("user_version = %d after refused migration, want untouched 1", v)
	}
	if _, err := os.Stat(backupPath(path, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused migration left a backup behind: %v", err)
	}
}

func TestStoreMigrationRefusesExistingBackup(t *testing.T) {
	path := writeV1Database(t)
	if err := os.WriteFile(backupPath(path, 1), []byte("previous backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, newTestEncryptor(t)); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Open with an existing backup = %v, want refusal", err)
	}
	if v := userVersion(t, path); v != 1 {
		t.Fatalf("user_version = %d, want untouched 1", v)
	}
	if b, _ := os.ReadFile(backupPath(path, 1)); string(b) != "previous backup" {
		t.Fatal("the previous backup was overwritten")
	}
}

func TestStoreFreshDatabaseIsV2WithoutBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.db")
	store, err := Open(path, newTestEncryptor(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if v := userVersion(t, path); v != SchemaVersion {
		t.Fatalf("fresh user_version = %d, want %d", v, SchemaVersion)
	}
	matches, _ := filepath.Glob(path + ".pre-v*.bak")
	if len(matches) != 0 {
		t.Fatalf("fresh database produced backups %v", matches)
	}
}

func TestStoreFinishDetectsTrailingGap(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-tail")
	if _, err := store.IngestEvents(ctx, "sess-tail", []IngestEvent{
		{Seq: 1, Stream: "tty_output", Data: []byte("a")},
		{Seq: 2, Stream: "tty_output", Data: []byte("b")},
	}); err != nil {
		t.Fatal(err)
	}
	// The recorder assigned seq 3 and 4 but they never arrived.
	if err := store.FinishSession(ctx, "sess-tail", time.Now().UTC(), true, 4); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}
	sum, _ := store.GetSession(ctx, "sess-tail")
	if sum.Complete || sum.LastSeq != 4 {
		t.Fatalf("summary = %+v, want complete=false last_seq=4", sum)
	}
	result, err := store.Replay(ctx, "sess-tail")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Gaps) != 1 || result.Gaps[0] != (GapRange{FromSeq: 3, ToSeq: 4}) {
		t.Fatalf("replay complete=%v gaps=%+v, want incomplete with trailing gap [3,4]", result.Complete, result.Gaps)
	}
}

func TestStoreFinishCompleteWhenNothingLost(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-clean")
	if _, err := store.IngestEvents(ctx, "sess-clean", []IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte("a")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishSession(ctx, "sess-clean", time.Now().UTC(), true, 1); err != nil {
		t.Fatal(err)
	}
	if sum, _ := store.GetSession(ctx, "sess-clean"); !sum.Complete {
		t.Fatalf("clean session stored incomplete: %+v", sum)
	}
	// A client that itself knows of a loss is believed.
	startTestSession(t, store, "sess-client-incomplete")
	if err := store.FinishSession(ctx, "sess-client-incomplete", time.Now().UTC(), false, 0); err != nil {
		t.Fatal(err)
	}
	if sum, _ := store.GetSession(ctx, "sess-client-incomplete"); sum.Complete {
		t.Fatal("complete=false from the client was overridden")
	}
}

func TestStoreFinishRejectsLastSeqBelowStored(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-low")
	if _, err := store.IngestEvents(ctx, "sess-low", []IngestEvent{{Seq: 3, Stream: "tty_output", Data: []byte("c")}}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishSession(ctx, "sess-low", time.Now().UTC(), true, 2); !errors.Is(err, ErrLastSeqTooLow) {
		t.Fatalf("FinishSession(last_seq below stored) = %v, want ErrLastSeqTooLow", err)
	}
}

func TestStoreFinishIdempotentAndFinishedSessionRejectsWrites(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	startTestSession(t, store, "sess-done")
	ended := time.Date(2026, 9, 23, 12, 0, 0, 123456789, time.UTC)
	if err := store.FinishSession(ctx, "sess-done", ended, true, 0); err != nil {
		t.Fatal(err)
	}
	// Retry after a client-side timeout: same instant (any zone) and last_seq.
	if err := store.FinishSession(ctx, "sess-done", ended.In(time.FixedZone("x", 3600)), false, 0); err != nil {
		t.Fatalf("identical finish retry = %v, want no-op", err)
	}
	if err := store.FinishSession(ctx, "sess-done", ended.Add(time.Second), true, 0); !errors.Is(err, ErrSessionFinished) {
		t.Fatalf("different finish = %v, want ErrSessionFinished", err)
	}
	if _, err := store.IngestEvents(ctx, "sess-done", []IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte("late")}}); !errors.Is(err, ErrSessionFinished) {
		t.Fatalf("events after finish = %v, want ErrSessionFinished", err)
	}
	err := store.StartSession(ctx, SessionStart{
		SessionID: "sess-done", User: "alice", DirectoryID: "dir01", GatewayID: "gw01",
		Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
	})
	if !errors.Is(err, ErrSessionFinished) {
		t.Fatalf("start on a finished session = %v, want ErrSessionFinished", err)
	}
}

func TestStoreStartBindsJTI(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	in := SessionStart{
		SessionID: "sess-jti", User: "alice", GatewayID: "gw01", Scope: "gpu", Target: "t.example.test",
		RecordingMode: "terminal_output", RecordingPolicySource: "host", IngestJTI: strings.Repeat("a", 32),
	}
	if err := store.StartSession(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := store.StartSession(ctx, in); err != nil {
		t.Fatalf("identical start retry = %v, want no-op", err)
	}
	second := in
	second.IngestJTI = strings.Repeat("b", 32)
	if err := store.StartSession(ctx, second); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("start with a second token's jti = %v, want ErrSessionConflict", err)
	}
	if sum, _ := store.GetSession(ctx, "sess-jti"); sum.IngestJTI != in.IngestJTI || sum.RecordingPolicySource != "host" {
		t.Fatalf("stored jti/source = %q/%q", sum.IngestJTI, sum.RecordingPolicySource)
	}
}

func TestStoreFinishSessionResultReportsGapsAndRetries(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.StartSession(ctx, SessionStart{SessionID: "sess-fr", User: "alice", GatewayID: "gw", Scope: "gpu", Target: "t", RecordingMode: "terminal_output", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestEvents(ctx, "sess-fr", []IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte("a")}, {Seq: 3, Stream: "tty_output", Data: []byte("c")}}); err != nil {
		t.Fatal(err)
	}
	ended := time.Now().UTC()
	res, err := store.FinishSessionResult(ctx, "sess-fr", ended, true, 5)
	if err != nil {
		t.Fatal(err)
	}
	if res.Repeated || res.Complete || res.GapRanges != 2 {
		t.Fatalf("first finish = %+v, want a new incomplete finish with gaps 2 and 4-5", res)
	}
	res, err = store.FinishSessionResult(ctx, "sess-fr", ended, true, 5)
	if err != nil || !res.Repeated || res.Complete {
		t.Fatalf("identical retry = %+v, %v; want Repeated with the stored completeness", res, err)
	}
}
