package sessionrecording

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// ExportEvent is one stored event as the session-store read API returns it.
type ExportEvent struct {
	Seq           uint64
	Stream        string
	OffsetNanos   int64
	Data          []byte
	Rows, Cols    int
	RedactedBytes int
}

// ExportGap is a missing seq range.
type ExportGap struct{ FromSeq, ToSeq uint64 }

// ExportSession is everything an asciicast export needs from the store.
type ExportSession struct {
	SessionID string
	StartedAt time.Time
	Complete  bool
	Gaps      []ExportGap
	Events    []ExportEvent // in seq order
}

// WriteAsciicastV2 converts a stored PTR/1 recording to asciicast v2
// (per-host recording spec §28). The conversion is lossy by nature: bytes
// become UTF-8 text decoded per stream, and resizes, gaps, incompleteness
// and redacted input become "m" marker events. The canonical recording is
// never modified.
func WriteAsciicastV2(w io.Writer, s ExportSession) error {
	width, height := 80, 24
	for _, ev := range s.Events {
		if ev.Stream == StreamResize && ev.Rows > 0 && ev.Cols > 0 {
			width, height = ev.Cols, ev.Rows
			break
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	header := map[string]any{
		"version": 2, "width": width, "height": height,
		"timestamp": s.StartedAt.Unix(), "title": "pilot session " + s.SessionID,
	}
	if err := enc.Encode(header); err != nil {
		return err
	}
	x := &asciicastWriter{enc: enc, pending: map[string][]byte{}}
	if !s.Complete {
		x.line(0, "m", "pilot: RECORDING INCOMPLETE")
	}

	gaps := s.Gaps
	var t float64
	for _, ev := range s.Events {
		t = float64(ev.OffsetNanos) / 1e9
		for len(gaps) > 0 && gaps[0].ToSeq < ev.Seq {
			x.gap(t, gaps[0])
			gaps = gaps[1:]
		}
		switch ev.Stream {
		case StreamTTYOutput:
			x.text(t, "o", ev.Data)
		case StreamTTYInput:
			if ev.RedactedBytes > 0 {
				x.line(t, "m", fmt.Sprintf("pilot: input redacted (%d bytes)", ev.RedactedBytes))
			} else {
				x.text(t, "i", ev.Data)
			}
		case StreamResize:
			x.line(t, "r", fmt.Sprintf("%dx%d", ev.Cols, ev.Rows))
		}
	}
	for _, g := range gaps {
		x.gap(t, g)
	}
	x.flushPending(t)
	return x.err
}

// asciicastWriter streams event lines, decoding UTF-8 per stream so a
// multibyte character split across two events (the recorder reads 4096-byte
// chunks) is rejoined rather than replaced.
type asciicastWriter struct {
	enc     *json.Encoder
	pending map[string][]byte // incomplete trailing sequence per stream code
	err     error
}

func (x *asciicastWriter) line(t float64, code, data string) {
	if x.err == nil {
		x.err = x.enc.Encode([]any{t, code, data})
	}
}

// text decodes pending+data, keeps a trailing incomplete sequence for the
// next event of the same stream, and replaces only truly invalid bytes.
func (x *asciicastWriter) text(t float64, code string, data []byte) {
	buf := append(x.pending[code], data...)
	delete(x.pending, code)
	var b strings.Builder
	for i := 0; i < len(buf); {
		r, size := utf8.DecodeRune(buf[i:])
		if r == utf8.RuneError && size <= 1 {
			if !utf8.FullRune(buf[i:]) {
				x.pending[code] = append([]byte(nil), buf[i:]...)
				break
			}
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	if b.Len() > 0 {
		x.line(t, code, b.String())
	}
}

// flushPending ends every stream's incomplete sequence as U+FFFD.
func (x *asciicastWriter) flushPending(t float64) {
	for _, code := range []string{"o", "i"} {
		if len(x.pending[code]) > 0 {
			x.line(t, code, string(utf8.RuneError))
			delete(x.pending, code)
		}
	}
}

// gap marks lost events; bytes around the gap can no longer be joined.
func (x *asciicastWriter) gap(t float64, g ExportGap) {
	x.flushPending(t)
	x.line(t, "m", fmt.Sprintf("pilot: gap seq %d-%d", g.FromSeq, g.ToSeq))
}
