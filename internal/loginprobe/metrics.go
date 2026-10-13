package loginprobe

import (
	"time"

	"github.com/kjelly/pilot/internal/promtext"
)

// Metrics is the probe's textfile-collector registry. Label names are
// deliberately limited to probe_target and stage: a pilot_host, instance,
// job or site label would collide with Prometheus's own target labels and
// be renamed to exported_*, breaking the alert rules' label_replace.
type Metrics struct {
	Registry *promtext.Registry
	// LastWrite is pilot_login_probe_metrics_last_write_timestamp_seconds,
	// set by the textfile writer loop (PilotLoginProbeStale reads it).
	LastWrite *promtext.Vec

	success       *promtext.Vec
	lastSuccessTS *promtext.Vec
	lastStage     *promtext.Vec
	attempts      *promtext.Vec
	failures      *promtext.Vec
	duration      *promtext.Vec
	targets       *promtext.Vec
	rounds        *promtext.Vec
	overruns      *promtext.Vec
}

// Metric family names, shared with the alert rules and the verification spec.
const (
	MetricSuccess       = "pilot_login_probe_success"
	MetricLastSuccessTS = "pilot_login_probe_last_success_timestamp_seconds"
	MetricLastStage     = "pilot_login_probe_last_stage"
	MetricAttempts      = "pilot_login_probe_attempts_total"
	MetricFailures      = "pilot_login_probe_failures_total"
	MetricDuration      = "pilot_login_probe_duration_seconds"
	MetricTargets       = "pilot_login_probe_targets"
	MetricRounds        = "pilot_login_probe_rounds_total"
	MetricOverruns      = "pilot_login_probe_round_overruns_total"
	MetricLastWrite     = "pilot_login_probe_metrics_last_write_timestamp_seconds"
)

// NewMetrics registers every family and pre-seeds each target's series at 0
// so Prometheus's increase()/changes() see the first real event (the
// session-store registry documents the same trap).
func NewMetrics(targets []Target) *Metrics {
	r := promtext.NewRegistry()
	m := &Metrics{
		Registry:      r,
		success:       r.Gauge(MetricSuccess, "1 when the most recent login attempt to probe_target fully succeeded, else 0.", "probe_target"),
		lastSuccessTS: r.Gauge(MetricLastSuccessTS, "Unix time of the most recent successful login to probe_target (0 = never).", "probe_target"),
		lastStage:     r.Gauge(MetricLastStage, "1 for the stage where the most recent attempt to probe_target ended (exactly one stage per target is 1).", "probe_target", "stage"),
		attempts:      r.Counter(MetricAttempts, "Login attempts to probe_target since the daemon started.", "probe_target"),
		failures:      r.Counter(MetricFailures, "Failed login attempts to probe_target by the stage they failed in.", "probe_target", "stage"),
		duration:      r.Gauge(MetricDuration, "Wall-clock seconds of the most recent attempt to probe_target.", "probe_target"),
		targets:       r.Gauge(MetricTargets, "Number of configured probe targets."),
		rounds:        r.Counter(MetricRounds, "Completed probe rounds since the daemon started."),
		overruns:      r.Counter(MetricOverruns, "Scheduled rounds skipped because the previous round was still running."),
		LastWrite:     r.Gauge(MetricLastWrite, "Unix time of the last metrics textfile write."),
	}
	m.targets.Set(float64(len(targets)))
	m.rounds.Add(0)
	m.overruns.Add(0)
	for _, t := range targets {
		m.success.Set(0, t.Name)
		m.lastSuccessTS.Set(0, t.Name)
		m.attempts.Add(0, t.Name)
		m.duration.Set(0, t.Name)
		for _, s := range AllStages {
			m.lastStage.Set(0, t.Name, string(s))
		}
		for _, s := range FailureStages {
			m.failures.Add(0, t.Name, string(s))
		}
	}
	return m
}

// Observe records one finished attempt.
func (m *Metrics) Observe(o Outcome) {
	name := o.Target.Name
	m.attempts.Inc(name)
	m.duration.Set(o.Duration.Seconds(), name)
	for _, s := range AllStages {
		v := 0.0
		if s == o.Stage {
			v = 1
		}
		m.lastStage.Set(v, name, string(s))
	}
	if o.Stage == StageOK {
		m.success.Set(1, name)
		m.lastSuccessTS.Set(float64(o.At.Unix()), name)
		return
	}
	m.success.Set(0, name)
	m.failures.Inc(name, string(o.Stage))
}

// RoundDone counts a completed round; overruns is the scheduler's running
// total, copied so the counter stays monotonic.
func (m *Metrics) RoundDone(overruns int64) {
	m.rounds.Inc()
	m.overruns.Set(float64(overruns))
}

// Outcome is one classified attempt.
type Outcome struct {
	Target   Target
	Stage    Stage
	ExitCode int
	Duration time.Duration
	At       time.Time
	// Summary is a one-line, redacted description of why the attempt ended
	// where it did (the last relevant OpenSSH message). Safe to log.
	Summary string
}
