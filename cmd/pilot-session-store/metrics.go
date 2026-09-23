package main

import (
	"net/http"

	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/promtext"
)

// storeMetrics are pilot-session-store's node_exporter textfile series
// (per-host recording spec §31). Labels are fixed enums; never a user,
// session id or target. A nil *storeMetrics records nothing.
type storeMetrics struct {
	registry  *promtext.Registry
	lastWrite *promtext.Vec

	ingestRequests   *promtext.Vec
	authFailures     *promtext.Vec
	sessionsFinished *promtext.Vec
	gapRanges        *promtext.Vec
	readRequests     *promtext.Vec
}

func newStoreMetrics() *storeMetrics {
	r := promtext.NewRegistry()
	return &storeMetrics{
		registry: r,
		ingestRequests: r.Counter("pilot_session_store_ingest_requests_total",
			"Ingest requests by endpoint and status class.", "endpoint", "code"),
		authFailures: r.Counter("pilot_session_store_ingest_auth_failures_total",
			"Ingest requests rejected by token or session binding checks, by reason.", "reason"),
		sessionsFinished: r.Counter("pilot_session_store_sessions_finished_total",
			"Recorded sessions finished, by mode and stored completeness.", "mode", "complete"),
		gapRanges: r.Counter("pilot_session_store_gap_ranges_detected_total",
			"Missing seq ranges found when sessions finished."),
		readRequests: r.Counter("pilot_session_store_read_requests_total",
			"Read API requests by action and result.", "action", "result"),
		lastWrite: r.Gauge("pilot_session_store_metrics_last_write_timestamp_seconds",
			"Unix time of the last metrics textfile write."),
	}
}

// authFailureReasons are the reason label values; anything else counts as
// malformed.
var authFailureReasons = map[string]bool{
	ingesttoken.ReasonMalformed: true, ingesttoken.ReasonUnknownKey: true, ingesttoken.ReasonBadSignature: true,
	ingesttoken.ReasonNotYetValid: true, ingesttoken.ReasonExpired: true, ingesttoken.ReasonStartWindowClosed: true,
	ingesttoken.ReasonInvalidClaims: true, "claims_mismatch": true, "session_id_mismatch": true, "session_finished": true,
}

func (m *storeMetrics) ingestRequest(endpoint string, status int) {
	if m == nil {
		return
	}
	code := "2xx"
	switch {
	case status >= 500:
		code = "5xx"
	case status >= 400:
		code = "4xx"
	}
	m.ingestRequests.Inc(endpoint, code)
}

func (m *storeMetrics) authFailure(reason string) {
	if m == nil {
		return
	}
	if !authFailureReasons[reason] {
		reason = ingesttoken.ReasonMalformed
	}
	m.authFailures.Inc(reason)
}

func (m *storeMetrics) sessionFinished(mode string, complete bool, gapRanges int) {
	if m == nil {
		return
	}
	c := "false"
	if complete {
		c = "true"
	}
	m.sessionsFinished.Inc(mode, c)
	m.gapRanges.Add(float64(gapRanges))
}

func (m *storeMetrics) readRequest(action, result string) {
	if m != nil {
		m.readRequests.Inc(action, result)
	}
}

// statusRecorder captures a handler's response status.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// counted counts every request to one ingest endpoint by status class.
func (s *ingestServer) counted(endpoint string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		s.metrics.ingestRequest(endpoint, rec.status)
	}
}
