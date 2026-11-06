// Package livehooks holds the injection points of the live test driver of the Go
// identity reconcile (spec 2026-11-06 phase 2 §10.2, D31): places in a run where the
// driver must act at a known moment, which a sleep cannot give it. The driver builds
// pilot with the build tag identity_live_hooks; a pilot built without it, which is the
// one that is released, has none of this code in it: this file and hooks_off.go are all
// that is compiled, and every function here does nothing.
//
// The points a tagged binary can stop at, named like this in the driver's list:
//
//	after_entry              the entry has run and its result was observed, before the
//	                         read that follows it (the obligation is recorded, nothing
//	                         is written yet)
//	before_stage:S<n>        before stage n is scheduled
//	before_batch:S<n>:<k>    before the k-th batch or call of stage n is recorded or sent
//	after_send:S<n>:<k>      the request of that batch or call has been written to the
//	                         tunnel and its answer has not been read: the answer is held
//	                         back until the driver releases it, so a driver that kills the
//	                         tunnel, the lock or pilot at this point makes a write that
//	                         has really left and has not been answered
//
// The driver names the points to stop at in PILOT_IDENTITY_LIVE_HOOKS_POINTS (a comma
// separated list) and a directory in PILOT_IDENTITY_LIVE_HOOKS_DIR. A stop appends the
// line "<n> <point>" to notify in that directory and waits for the file go.<n>, whose
// content is "resume" or, for after_send, "drop": drop discards the held answer and fails
// the connection, as a tunnel that died before it was read would. The files are polled,
// not FIFOs, because opening a FIFO blocks until the other side has opened it and a
// driver that was killed would leave pilot stuck there for good.
package livehooks

// The names of the environment variables the tagged build reads.
const (
	EnvDir    = "PILOT_IDENTITY_LIVE_HOOKS_DIR"
	EnvPoints = "PILOT_IDENTITY_LIVE_HOOKS_POINTS"
)
