package identityreconcile

import (
	"context"
	"time"
)

// The run journal (spec §7.7, D21): what the executor records of a run, as events a
// sink stores. The sink is an interface so that this package does not know the
// delivery store; P2-6 implements it on the run's delivery.RunWriter.

// The kinds of event the executor records. Their payloads hold operations,
// outcomes, FreeIPA's error names and codes and counts: never a password, a cookie,
// a key or a vault value.
const (
	// EventOp: a batch or a single call, once before it is sent (Phase "sending")
	// and once after (Phase "result", with every item's outcome).
	EventOp = "identity.op"
	// EventVerify: what the read after the writes found.
	EventVerify = "identity.verify"
	// EventAuthCache: what the authorization cache entry did or found.
	EventAuthCache = "identity.auth_cache"
)

// evidenceAppendTimeout bounds one append to the journal, which runs on a context
// detached from the run's cancellation: the run's outcome must be recorded after
// Ctrl-C, --timeout and a lost lock too, and an append that waited for a context
// that is already cancelled would fail and hide it (spec §4.4, the class rule; T1).
const evidenceAppendTimeout = 5 * time.Second

// Event is one entry of the journal.
type Event struct {
	// Kind is one of the Event constants.
	Kind string
	// ID is unique within the run, and "sending" and "result" of one batch have
	// different ones: a store refuses a second event with the same id and another
	// payload (spec §7.7).
	ID string
	// Payload is JSON-encodable.
	Payload any
}

// Journal stores the events of a run. Record must return an error when the event is
// not durable. Execute calls it only on a context that is not cancelled and ends
// within evidenceAppendTimeout, so an implementation need not guard against
// cancellation itself (and cannot be the reason a recorded outcome is lost to it).
type Journal interface {
	Record(ctx context.Context, ev Event) error
}

// record appends ev on a context detached from ctx's cancellation and bounded, the
// one place the executor writes to the journal.
func record(ctx context.Context, j Journal, ev Event) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), evidenceAppendTimeout)
	defer cancel()
	return j.Record(rctx, ev)
}
