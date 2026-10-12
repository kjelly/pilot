package gatewayapi

import "github.com/kjelly/pilot/internal/promtext"

// Metrics are the gateway's node_exporter textfile series (per-host
// recording spec §31). Labels are fixed enums; never a user, session id or
// target. A nil *Metrics records nothing.
type Metrics struct {
	Registry *promtext.Registry
	// LastWrite is set by the textfile writer before every write.
	LastWrite *promtext.Vec

	authorize          *promtext.Vec
	authorizedSessions *promtext.Vec
}

// Authorize result reasons that are not recording deny reasons.
const (
	metricsReasonNone         = "none"
	metricsReasonAccessDenied = "access_denied"
	metricsReasonError        = "error"
)

// NewMetrics registers the gateway's series on a fresh registry.
func NewMetrics() *Metrics {
	r := promtext.NewRegistry()
	m := &Metrics{
		Registry: r,
		authorize: r.Counter("pilot_gateway_connect_authorize_total",
			"Connect authorize decisions by result and reason.", "result", "reason"),
		authorizedSessions: r.Counter("pilot_gateway_recording_authorized_sessions_total",
			"Allowed connects by effective recording mode and policy source.", "mode", "source"),
		LastWrite: r.Gauge("pilot_gateway_metrics_last_write_timestamp_seconds",
			"Unix time of the last metrics textfile write."),
	}
	// Every authorize outcome starts at 0: Prometheus's increase() cannot
	// see the first increment of a series that appears already at 1, so an
	// alert on denials would miss the first one after every restart.
	m.authorize.Add(0, "allowed", metricsReasonNone)
	for _, reason := range []string{
		metricsReasonAccessDenied, metricsReasonError,
		DenyReasonRecordingPolicyUnavailable, DenyReasonRecordingPolicyInvalid,
		DenyReasonRecordingBackend, DenyReasonRecordingSessionID,
	} {
		m.authorize.Add(0, "denied", reason)
	}
	return m
}

func (m *Metrics) authorizeDenied(reason string) {
	if m != nil {
		m.authorize.Inc("denied", reason)
	}
}

func (m *Metrics) authorizeAllowed(mode, source string) {
	if m != nil {
		m.authorize.Inc("allowed", metricsReasonNone)
		m.authorizedSessions.Inc(mode, source)
	}
}
