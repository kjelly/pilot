package detection

import (
	"context"
	"sync"
	"time"
)

// GlobalRateLimit is spec §35's global token-bucket cap: 60 requests/minute.
const GlobalRateLimit = 60

// RateLimiter is a simple thread-safe token bucket (spec §35). When
// exhausted, callers fall back to local scoring for this cycle only — no
// persistent candidate backlog; the next cycle reevaluates fresh.
type RateLimiter struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	perSecond  float64
	lastRefill time.Time
	Now        func() time.Time
}

// NewRateLimiter builds a token bucket that refills to ratePerMinute
// tokens over 60 seconds, starting full.
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	now := time.Now
	return &RateLimiter{
		capacity:   float64(ratePerMinute),
		tokens:     float64(ratePerMinute),
		perSecond:  float64(ratePerMinute) / 60.0,
		lastRefill: now(),
		Now:        now,
	}
}

// TryAcquire attempts to take one token, returning false if none are
// available right now.
func (r *RateLimiter) TryAcquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	if elapsed > 0 {
		r.tokens += elapsed * r.perSecond
		if r.tokens > r.capacity {
			r.tokens = r.capacity
		}
		r.lastRefill = now
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// ModelCycleStats is one RunCycle's model-provider observability, read by
// the caller (main.go's serve loop) to populate status.json/metrics (spec
// §37/§38). It is always the zero value when the provider is disabled.
type ModelCycleStats struct {
	CandidatesTotal int64
	DroppedTotal    map[string]int64    // reason -> count ("cap", "rate_limited")
	RequestTotal    map[[2]string]int64 // [protocol, result] -> count ("ok","insufficient_data","error")
	RequestDuration map[string]float64  // protocol -> most recent request's duration (seconds)
	ProviderUp      bool
	CircuitOpen     bool
}

func newModelCycleStats() ModelCycleStats {
	return ModelCycleStats{
		DroppedTotal:    map[string]int64{},
		RequestTotal:    map[[2]string]int64{},
		RequestDuration: map[string]float64{},
	}
}

// scoreCandidatesWithProvider implements spec §35's batching/cost-bound
// and calls e.Provider for each batch, filling `fused` for every candidate
// (including ones dropped by the cap or the rate limiter, which fall back
// to FuseLocalOnly). It never blocks lifecycle advancement on more than
// MaxBatchesPerCycle concurrent requests, since SelectCandidates already
// caps candidates at MaxCandidatesPerCycle == MaxBatchesPerCycle*ModelBatchSize.
func (e *Engine) scoreCandidatesWithProvider(ctx context.Context, candidates []Candidate, evaluationTime int64, fused map[string]FusedResult) ModelCycleStats {
	stats := newModelCycleStats()
	stats.CandidatesTotal = int64(len(candidates))

	kept, dropped := SelectCandidates(candidates)
	for _, c := range dropped {
		fused[c.Subject.ID] = FuseLocalOnly(c.LocalScore)
	}
	if len(dropped) > 0 {
		stats.DroppedTotal["cap"] = int64(len(dropped))
	}

	batches := ChunkBatches(kept)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, batch := range batches {
		batch := batch
		if e.RateLimiter != nil && !e.RateLimiter.TryAcquire() {
			mu.Lock()
			stats.DroppedTotal["rate_limited"] += int64(len(batch))
			mu.Unlock()
			for _, c := range batch {
				fused[c.Subject.ID] = FuseLocalOnly(c.LocalScore)
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.scoreOneBatch(ctx, batch, evaluationTime, fused, &stats, &mu)
		}()
	}
	wg.Wait()

	if cr, ok := e.Provider.(circuitReporter); ok {
		stats.CircuitOpen = cr.CircuitState(time.Now()) == "open"
	}
	// "Up" mirrors the circuit breaker's own health judgment (spec §34's
	// rolling health-failure window) — the definitive reachability signal
	// this package already computes, rather than a second ad hoc heuristic.
	stats.ProviderUp = !stats.CircuitOpen
	return stats
}

func (e *Engine) scoreOneBatch(ctx context.Context, batch []Candidate, evaluationTime int64, fused map[string]FusedResult, stats *ModelCycleStats, mu *sync.Mutex) {
	req := ModelBatchRequest{
		SchemaVersion: 2,
		PromptVersion: PromptVersion,
		WindowSeconds: 600,
		Candidates:    make([]ModelCandidateRequest, 0, len(batch)),
	}
	requestID, err := NewULID()
	if err != nil {
		requestID = "unavailable"
	}
	req.RequestID = requestID
	for _, c := range batch {
		pilotHost := ""
		if c.Subject.IsManagedHost() {
			pilotHost = c.Subject.ID
		}
		req.Candidates = append(req.Candidates, ModelCandidateRequest{
			CandidateID:    c.Subject.ID,
			SubjectID:      c.Subject.ID,
			SubjectKind:    c.Subject.Kind,
			PilotHost:      pilotHost,
			Site:           c.Subject.Site,
			EvaluationTime: evaluationTime,
			Current:        c.Current,
		})
	}

	start := time.Now()
	resp, err := e.Provider.Score(ctx, req)
	duration := time.Since(start).Seconds()

	mu.Lock()
	stats.RequestDuration[e.ProviderProtocol] = duration
	mu.Unlock()

	if err != nil {
		mu.Lock()
		stats.RequestTotal[[2]string{e.ProviderProtocol, "error"}]++
		mu.Unlock()
		for _, c := range batch {
			mu.Lock()
			fused[c.Subject.ID] = FuseLocalOnly(c.LocalScore)
			mu.Unlock()
		}
		return
	}

	mu.Lock()
	stats.RequestTotal[[2]string{e.ProviderProtocol, resp.Status}]++
	mu.Unlock()

	byID := make(map[string]ModelCandidateResponse, len(resp.Candidates))
	for _, rc := range resp.Candidates {
		byID[rc.CandidateID] = rc
	}
	for _, c := range batch {
		mu.Lock()
		switch {
		case resp.Status == "insufficient_data":
			fused[c.Subject.ID] = FuseInsufficientData(c.LocalScore)
		default:
			if rc, ok := byID[c.Subject.ID]; ok {
				fused[c.Subject.ID] = FuseCandidate(c.LocalScore, rc)
			} else {
				// Should not happen — ValidateBatchResponse already
				// enforces exact candidate-ID set equality — but never
				// suppress local detection on an unexpected gap.
				fused[c.Subject.ID] = FuseLocalOnly(c.LocalScore)
			}
		}
		mu.Unlock()
	}
}
