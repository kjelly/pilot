package sessionrecording

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recording.ndjson")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	want := []TerminalEvent{
		{SchemaVersion: 1, SessionID: "s1", Seq: 1, Stream: StreamTTYOutput, DataBase64: "aGVsbG8="},
		{SchemaVersion: 1, SessionID: "s1", Seq: 2, Stream: StreamTTYInput, RedactedBytes: 8},
		{SchemaVersion: 1, SessionID: "s1", Seq: 3, Stream: StreamResize, Rows: 40, Cols: 120},
	}
	for _, ev := range want {
		if err := sink.Write(context.Background(), ev); err != nil {
			t.Fatalf("Write(%+v): %v", ev, err)
		}
	}
	if err := sink.Finish(context.Background(), FinishInfo{Complete: true}); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open recording file: %v", err)
	}
	defer f.Close()

	var got []TerminalEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev TerminalEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal line %q: %v", scanner.Text(), err)
		}
		got = append(got, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestNullSinkNeverFails(t *testing.T) {
	var s NullSink
	if err := s.Write(context.Background(), TerminalEvent{}); err != nil {
		t.Fatalf("NullSink.Write: %v", err)
	}
	if err := s.Finish(context.Background(), FinishInfo{}); err != nil {
		t.Fatalf("NullSink.Finish: %v", err)
	}
}
