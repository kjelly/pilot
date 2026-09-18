package sessionrecording

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Sink is where TerminalEvent records go. Phase 8 builds the real
// durable, encrypted pilot-session-store-backed sink; this phase only
// needs the interface plus simple, real implementations for its own
// verification (spec.md §35: "可以先以 test sink 驗證 recorder protocol，
// 但 production default 保持 metadata").
type Sink interface {
	Write(ctx context.Context, ev TerminalEvent) error
	Close() error
}

// NullSink discards every event. Used when recording mode is "metadata"
// — the recorder subsystem is not constructed at all in that mode (see
// the call site in cmd/pilot/cmd/portal_session_connect.go), so NullSink
// exists mainly for tests that want a Sink which never fails.
type NullSink struct{}

func (NullSink) Write(context.Context, TerminalEvent) error { return nil }
func (NullSink) Close() error                               { return nil }

// FileSink appends NDJSON lines to a local file. Deliberately plain: no
// encryption, no rotation, no batching — an explicit stopgap for this
// phase's own live verification and for an operator who wants something
// durable before Phase 8's real session-store sink exists, never a
// production security claim (spec.md §28 owns encryption-at-rest,
// retention, and auditor-only read access; none of that exists here).
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink opens (creating if needed) path for append, mode 0600 —
// this file can contain terminal_io input, so it must never be
// world/group readable by anything looser than the operator explicitly
// arranges around it.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open recording sink file %s: %w", path, err)
	}
	return &FileSink{f: f}, nil
}

func (s *FileSink) Write(_ context.Context, ev TerminalEvent) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal terminal event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(line)
	return err
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
