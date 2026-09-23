package sessionrecording

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// asciicastLines splits an export into its header and event lines.
func asciicastLines(t *testing.T, out string) (map[string]any, [][]any) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	var header map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header %q: %v", lines[0], err)
	}
	var events [][]any
	for _, l := range lines[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("event %q: %v", l, err)
		}
		events = append(events, ev)
	}
	return header, events
}

func export(t *testing.T, s ExportSession) (map[string]any, [][]any) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteAsciicastV2(&buf, s); err != nil {
		t.Fatalf("WriteAsciicastV2: %v", err)
	}
	return asciicastLines(t, buf.String())
}

func TestAsciicastExportHeader(t *testing.T) {
	started := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	h, _ := export(t, ExportSession{SessionID: "sid-1", StartedAt: started, Complete: true, Events: []ExportEvent{
		{Seq: 1, Stream: StreamResize, Rows: 40, Cols: 132},
		{Seq: 2, Stream: StreamResize, Rows: 50, Cols: 200},
	}})
	if h["version"] != float64(2) || h["width"] != float64(132) || h["height"] != float64(40) ||
		h["timestamp"] != float64(started.Unix()) || h["title"] != "pilot session sid-1" {
		t.Fatalf("header = %v", h)
	}
	h, _ = export(t, ExportSession{SessionID: "old", Complete: true})
	if h["width"] != float64(80) || h["height"] != float64(24) {
		t.Fatalf("header without a resize = %v, want 80x24", h)
	}
}

func TestAsciicastExportStreams(t *testing.T) {
	_, evs := export(t, ExportSession{SessionID: "s", Complete: true, Events: []ExportEvent{
		{Seq: 1, Stream: StreamResize, Rows: 24, Cols: 80},
		{Seq: 2, Stream: StreamTTYOutput, OffsetNanos: 1_500_000_000, Data: []byte("$ ")},
		{Seq: 3, Stream: StreamTTYInput, OffsetNanos: 2_000_000_000, Data: []byte("ls\r")},
		{Seq: 4, Stream: StreamResize, OffsetNanos: 3_250_000_000, Rows: 30, Cols: 100},
	}})
	want := [][]any{
		{0.0, "r", "80x24"},
		{1.5, "o", "$ "},
		{2.0, "i", "ls\r"},
		{3.25, "r", "100x30"},
	}
	if len(evs) != len(want) {
		t.Fatalf("events = %v, want %v", evs, want)
	}
	for i := range want {
		if evs[i][0] != want[i][0] || evs[i][1] != want[i][1] || evs[i][2] != want[i][2] {
			t.Fatalf("event %d = %v, want %v", i, evs[i], want[i])
		}
	}
}

func TestAsciicastExportMarkers(t *testing.T) {
	_, evs := export(t, ExportSession{SessionID: "s", Complete: false, Gaps: []ExportGap{{2, 3}, {6, 7}}, Events: []ExportEvent{
		{Seq: 1, Stream: StreamTTYOutput, OffsetNanos: 1e9, Data: []byte("a")},
		{Seq: 4, Stream: StreamTTYInput, OffsetNanos: 2e9, RedactedBytes: 9},
		{Seq: 5, Stream: StreamTTYOutput, OffsetNanos: 3e9, Data: []byte("b")},
	}})
	got := make([]string, 0, len(evs))
	for _, ev := range evs {
		got = append(got, ev[1].(string)+":"+ev[2].(string))
	}
	want := []string{
		"m:pilot: RECORDING INCOMPLETE",
		"o:a",
		"m:pilot: gap seq 2-3",
		"m:pilot: input redacted (9 bytes)",
		"o:b",
		"m:pilot: gap seq 6-7",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("events = %q, want %q", got, want)
	}
	if evs[0][0] != 0.0 {
		t.Fatalf("incomplete marker at t=%v, want 0", evs[0][0])
	}
	for _, ev := range evs {
		if ev[1] == "i" {
			t.Fatalf("redacted input exported data: %v", ev)
		}
	}
}

// TestAsciicastExportNonUTF8 covers per-stream UTF-8 decoding: a CJK
// character split across two events is rejoined, interleaved streams do not
// mix their partial bytes, a truly invalid byte becomes U+FFFD, and a
// sequence still incomplete at the end becomes U+FFFD.
func TestAsciicastExportNonUTF8(t *testing.T) {
	zhong := []byte("中") // e4 b8 ad
	_, evs := export(t, ExportSession{SessionID: "s", Complete: true, Events: []ExportEvent{
		{Seq: 1, Stream: StreamTTYOutput, OffsetNanos: 1, Data: append([]byte("x"), zhong[:2]...)},
		{Seq: 2, Stream: StreamTTYInput, OffsetNanos: 2, Data: []byte("q")},
		{Seq: 3, Stream: StreamTTYOutput, OffsetNanos: 3, Data: append(zhong[2:], 'y', 0xff, 'z')},
		{Seq: 4, Stream: StreamTTYOutput, OffsetNanos: 4, Data: zhong[:1]},
	}})
	var out, in strings.Builder
	for _, ev := range evs {
		switch ev[1] {
		case "o":
			out.WriteString(ev[2].(string))
		case "i":
			in.WriteString(ev[2].(string))
		}
	}
	if out.String() != "x中y�z�" {
		t.Fatalf("output text = %q, want %q", out.String(), "x中y�z�")
	}
	if in.String() != "q" {
		t.Fatalf("input text = %q", in.String())
	}
}
