package loginprobe

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Prober runs one round of attempts against every configured target.
type Prober struct {
	Config  Config
	Runner  Runner
	Metrics *Metrics
	Logger  *slog.Logger
	// Classify maps a raw result to a stage; defaults to Classify.
	Classify func(RawResult) (Stage, string)
	// now is injectable for tests.
	now func() time.Time
}

// NewProber wires a Prober for cfg.
func NewProber(cfg Config, runner Runner, metrics *Metrics, logger *slog.Logger) *Prober {
	if logger == nil {
		logger = slog.Default()
	}
	return &Prober{Config: cfg, Runner: runner, Metrics: metrics, Logger: logger, Classify: Classify, now: time.Now}
}

// Round probes every target with at most Config.Concurrency attempts in
// flight and returns the outcomes in target order. When ctx ends mid-round,
// the attempts it cut short, and the targets it never reached, come back
// Canceled and are not recorded in Metrics.
func (p *Prober) Round(ctx context.Context) []Outcome {
	outcomes := make([]Outcome, len(p.Config.Targets))
	for i, t := range p.Config.Targets {
		outcomes[i] = Outcome{Target: t, Canceled: true}
	}
	sem := make(chan struct{}, p.Config.Concurrency)
	var wg sync.WaitGroup
	for i, t := range p.Config.Targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes[i] = p.probeOne(ctx, t)
		}(i, t)
	}
	wg.Wait()
	sort.SliceStable(outcomes, func(a, b int) bool { return outcomes[a].Target.Name < outcomes[b].Target.Name })
	return outcomes
}

func (p *Prober) probeOne(ctx context.Context, t Target) Outcome {
	raw := p.Runner.Run(ctx, t)
	if raw.Canceled {
		p.Logger.Debug("login probe attempt canceled", "target", t.Name, "host", t.Host)
		return Outcome{Target: t, Duration: raw.Duration, At: p.now(), Canceled: true}
	}
	stage, why := p.Classify(raw)
	o := Outcome{Target: t, Stage: stage, ExitCode: raw.ExitCode, Duration: raw.Duration, At: p.now(), Summary: Redact(why)}
	if p.Metrics != nil {
		p.Metrics.Observe(o)
	}
	attrs := []any{"target", t.Name, "host", t.Host, "stage", string(stage), "exit_code", raw.ExitCode, "duration_ms", raw.Duration.Milliseconds()}
	if stage == StageOK {
		p.Logger.Debug("login probe ok", attrs...)
	} else {
		p.Logger.Warn("login probe failed", append(attrs, "summary", o.Summary)...)
	}
	return o
}
