package sessionaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// TestEmitWritesSchemaShapedJSONLine proves Emit fills SchemaVersion/
// EventID/Seq/Timestamp itself and writes exactly one JSON line matching
// spec.md §21.2's field shape.
func TestEmitWritesSchemaShapedJSONLine(t *testing.T) {
	var buf bytes.Buffer
	e := newEmitterWithWriter("pilot-access-directory", &buf)

	e.Emit(SessionAuditEvent{
		SessionID:  "0d33c638-83fa-4d77-9811-a97a7a7af1d5",
		Kind:       KindDirectoryConnectRequested,
		User:       "alice",
		TargetFQDN: "gpu-a.example.com",
	})

	var got SessionAuditEvent
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal emitted line: %v (line=%q)", err, buf.String())
	}
	if got.SchemaVersion != SchemaVersion1 {
		t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion1)
	}
	if got.EventID == "" {
		t.Fatalf("EventID must be set")
	}
	if got.Seq != 1 {
		t.Fatalf("Seq = %d, want 1", got.Seq)
	}
	if got.Timestamp.IsZero() {
		t.Fatalf("Timestamp must be set")
	}
	if got.SessionID != "0d33c638-83fa-4d77-9811-a97a7a7af1d5" || got.Kind != KindDirectoryConnectRequested || got.User != "alice" || got.TargetFQDN != "gpu-a.example.com" {
		t.Fatalf("event = %+v, caller-supplied fields not preserved", got)
	}
}

// TestEmitSeqIncrementsAndEventIDDiffers proves each Emit call on the same
// Emitter gets a strictly increasing Seq and a fresh EventID, so a central
// log consumer can order and de-duplicate records from one component's
// stream.
func TestEmitSeqIncrementsAndEventIDDiffers(t *testing.T) {
	var buf bytes.Buffer
	e := newEmitterWithWriter("pilot-access-gateway", &buf)

	var lines []SessionAuditEvent
	for i := 0; i < 3; i++ {
		buf.Reset()
		e.Emit(SessionAuditEvent{SessionID: "s1", Kind: KindTargetConnectStarted, User: "alice"})
		var ev SessionAuditEvent
		if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		lines = append(lines, ev)
	}
	for i, ev := range lines {
		if ev.Seq != uint64(i+1) {
			t.Fatalf("lines[%d].Seq = %d, want %d", i, ev.Seq, i+1)
		}
	}
	if lines[0].EventID == lines[1].EventID || lines[1].EventID == lines[2].EventID {
		t.Fatalf("EventID must differ per Emit call: %+v", lines)
	}
}

// failingWriter always errors, simulating an unreachable/broken syslog
// sink after construction (e.g. the daemon restarted mid-process).
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// TestEmitNeverPanicsOnBrokenWriter proves a broken underlying sink is
// swallowed, not propagated — Emit has no error return by design (see its
// doc comment): a broken audit sink must never be able to affect, block,
// or crash the real connect/authorize flow it is merely describing.
func TestEmitNeverPanicsOnBrokenWriter(t *testing.T) {
	e := newEmitterWithWriter("pilot-access-directory", failingWriter{})
	e.Emit(SessionAuditEvent{SessionID: "s1", Kind: KindSessionStarted, User: "alice"})
}

// TestNewEmitterFallsBackWhenSyslogUnavailable proves NewEmitter itself
// never fails a caller's startup just because local syslog can't be
// reached — Emit must still be safely callable afterward.
func TestNewEmitterFallsBackWhenSyslogUnavailable(t *testing.T) {
	// A real environment's syslog daemon may or may not be reachable in
	// this test sandbox; either way NewEmitter must succeed and Emit must
	// not panic.
	e, err := NewEmitter("pilot-access-directory-test")
	if err != nil {
		t.Fatalf("NewEmitter: %v, want no error even if local syslog is unreachable", err)
	}
	e.Emit(SessionAuditEvent{SessionID: "s1", Kind: KindSessionEnded, User: "alice"})
}
