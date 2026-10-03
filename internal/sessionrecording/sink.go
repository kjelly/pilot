package sessionrecording

import "context"

// Sink is where TerminalEvent records go. The only production Sink is
// HTTPSink (pilot-session-store); there is no local-file sink, so a
// recorded session never leaves a recording on the gateway's disk
// (per-host recording spec §18.4).
//
// WriteBatch ships events in seq order; the recorder batches them
// (§19.4). Finish is called exactly once, by Recorder.Run, after the
// writer has stopped: it reports whether the recording is complete and the
// last seq the recorder assigned (including events it lost), so the store
// can detect losses at the tail (per-host recording spec §19.6/§19.7).
type Sink interface {
	WriteBatch(ctx context.Context, events []TerminalEvent) error
	Finish(ctx context.Context, info FinishInfo) error
}

// FinishInfo is the recorder's end-of-session report.
type FinishInfo struct {
	// Complete is true only for a clean end with nothing lost.
	Complete bool
	// LastSeq is the last seq the recorder assigned, including lost events.
	LastSeq uint64
	// Reason is empty when Complete, otherwise one of fail_closed |
	// dropped | sink_error | drain_timeout | aborted | target_connect_failed
	// | session_start_failed | internal_error. It is reported in the
	// client's audit trail, not sent to the store.
	Reason string
}

// NullSink discards every event. The recorder subsystem is not constructed
// at all for metadata sessions, so NullSink exists for tests that want a
// Sink which never fails.
type NullSink struct{}

// WriteBatch discards events.
func (NullSink) WriteBatch(context.Context, []TerminalEvent) error { return nil }

// Finish does nothing.
func (NullSink) Finish(context.Context, FinishInfo) error { return nil }
