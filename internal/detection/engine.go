package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// AlertmanagerPayload is the alert body shape Alertmanager's POST
// /api/v2/alerts expects — one element per alert (spec §22).
type AlertmanagerPayload struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

// alertmanagerRefreshWindow and alertmanagerEndsAtHorizon implement the
// refresh cadence from spec §22.1: refresh every 60s, endsAt = now+180s.
const (
	alertmanagerEndsAtHorizon = 180 * time.Second
)

func buildAlertPayload(host, site, severity, signalID string, score, confidence float64, categoryHint string, contributors []Contributor, profile string, startsAt, now time.Time) AlertmanagerPayload {
	top := make([]string, 0, len(contributors))
	for _, c := range contributors {
		top = append(top, c.Feature)
	}
	topJSON, _ := json.Marshal(top)
	return AlertmanagerPayload{
		Labels: map[string]string{
			"alertname":  "PilotAdaptiveAnomaly",
			"source":     "detection-engine",
			"pilot_host": host,
			"site":       site,
			"severity":   severity,
		},
		Annotations: map[string]string{
			"signal_id":        signalID,
			"score":            formatFloat(score),
			"confidence":       formatFloat(confidence),
			"category_hint":    categoryHint,
			"top_contributors": string(topJSON),
			"profile":          profile,
		},
		StartsAt: startsAt.UTC().Format(time.RFC3339),
		EndsAt:   now.Add(alertmanagerEndsAtHorizon).UTC().Format(time.RFC3339),
	}
}

// Engine wires the source client, feature profile, per-host baseline/
// lifecycle state, and the SQLite store into one repeatable detection
// cycle (spec §10.1's Stage A-1 data flow: Thanos source -> normalize ->
// baseline/cohort -> lifecycle -> SQLite/outbox).
type Engine struct {
	Profile   FeatureProfile
	Source    *ThanosClient
	Baselines *HostBaselineStore
	Store     *Store
	// Cohorts assigns each known subject to a cohort (spec §17's
	// detection_cohort metadata); a host absent from this map has no
	// cohort and cohort-outlier-v1 is not applicable for it.
	Cohorts map[string]string

	// Provider is nil for Stage A (provider disabled): every host is then
	// fused via FuseLocalOnly, byte-identical to pre-Stage-B behavior.
	// ProviderProtocol labels observability output ("openai-responses" |
	// "ollama-chat"); RateLimiter is the global token bucket (spec §35),
	// also nil-safe (nil == unlimited, used only when Provider is nil).
	Provider         *ManagedProvider
	ProviderProtocol string
	RateLimiter      *RateLimiter

	// LastModelStats is this Engine's most recent RunCycle's model-
	// provider observability (spec §37/§38) — always the zero value while
	// Provider is nil.
	LastModelStats ModelCycleStats

	lifecycles map[string]*HostLifecycle
}

// NewEngine constructs an Engine with empty runtime state.
func NewEngine(profile FeatureProfile, source *ThanosClient, store *Store, cohorts map[string]string) *Engine {
	return &Engine{
		Profile:    profile,
		Source:     source,
		Baselines:  NewHostBaselineStore(),
		Store:      store,
		Cohorts:    cohorts,
		lifecycles: map[string]*HostLifecycle{},
	}
}

func (e *Engine) lifecycleFor(host string) *HostLifecycle {
	lc, ok := e.lifecycles[host]
	if !ok {
		lc = NewHostLifecycle()
		e.lifecycles[host] = lc
	}
	return lc
}

// HostCycleOutcome is one host's result from a single RunCycle call,
// returned for observability/metrics — RunCycle itself already persisted
// any lifecycle transition.
type HostCycleOutcome struct {
	Host       string
	Valid      bool
	LocalScore LocalScoreResult
	// Fused is the score/category/contributors actually used to advance
	// the lifecycle this cycle (spec §19): equal to LocalScore when the
	// provider is disabled/unavailable/insufficient_data, model-escalated
	// otherwise. Zero value when Valid is false.
	Fused      FusedResult
	Transition Transition
}

// RunCycle executes one full evaluation cycle at evaluationTime across
// every feature in the profile, for every subject the Thanos query
// discovers. It queries each feature once (an instant query already
// covers every subject via the profile's `by (pilot_host, site)` PromQL),
// classifies samples per spec §13, scores baseline/cohort per §15/§17,
// advances each valid host's lifecycle per §20, and persists any
// resulting transition atomically per §25 — including queuing the
// Alertmanager outbox rows for that transition. It deliberately does not
// call HostLifecycle.Advance for a host whose cycle was invalid (spec
// §20.7).
func (e *Engine) RunCycle(ctx context.Context, evaluationTime int64) ([]HostCycleOutcome, error) {
	perHost := map[SeriesKey]map[string]FeatureSampleResult{}
	siteByHost := map[string]string{}

	for _, feature := range e.Profile.Features {
		metrics, samples, err := e.Source.InstantQuery(ctx, feature.PromQL, evaluationTime)
		if err != nil {
			return nil, fmt.Errorf("query feature %s: %w", feature.Name, err)
		}
		grouped := GroupSamplesByKey(metrics, samples)
		for key, raw := range grouped {
			value, validity := ClassifySample(raw, evaluationTime, feature)
			if perHost[key] == nil {
				perHost[key] = map[string]FeatureSampleResult{}
			}
			perHost[key][feature.Name] = FeatureSampleResult{Feature: feature.Name, Value: value, Validity: validity}
			siteByHost[key.PilotHost] = key.Site
		}
	}

	// Build cohort snapshots from every host with at least one valid
	// reading this cycle, regardless of whether its OWN cycle is valid —
	// a peer contributes its valid features even on a cycle where one of
	// its OTHER (unrelated) required features was invalid.
	hosts := make([]string, 0, len(siteByHost))
	for host := range siteByHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var snapshots []HostCycleSnapshot
	for _, host := range hosts {
		key := SeriesKey{PilotHost: host, Site: siteByHost[host]}
		snapshots = append(snapshots, HostCycleSnapshot{
			Host:    host,
			Cohort:  e.Cohorts[host],
			Current: ValidCurrentValues(perHost[key]),
		})
	}

	type pendingHost struct {
		snap  HostCycleSnapshot
		site  string
		local LocalScoreResult
	}

	var outcomes []HostCycleOutcome
	var pending []pendingHost
	for _, snap := range snapshots {
		key := SeriesKey{PilotHost: snap.Host, Site: siteByHost[snap.Host]}
		results := perHost[key]
		valid := HostCycleValid(e.Profile, results)

		outcome := HostCycleOutcome{Host: snap.Host, Valid: valid}
		if !valid {
			outcomes = append(outcomes, outcome)
			continue // spec §20.7: invalid cycle advances nothing
		}

		history := map[string][]float64{}
		for name := range snap.Current {
			history[name] = e.Baselines.History(snap.Host, name)
		}
		baselineResult := ComputeBaselineHostScore(e.Profile, history, snap.Current)
		cohortResult := ComputeCohortHostScore(e.Profile, snap, snapshots)
		local := ComputeLocalScore(baselineResult, cohortResult)
		outcome.LocalScore = local

		if !local.Valid {
			outcomes = append(outcomes, outcome)
			continue // both detectors invalid -> host cycle invalid (spec §18)
		}

		outcomes = append(outcomes, outcome)
		pending = append(pending, pendingHost{snap: snap, site: key.Site, local: local})
	}

	// Model-assisted fusion (spec §19/§35): disabled/unavailable candidates
	// and every non-candidate host fuse to local-only, byte-identical to
	// Stage A. Only score>=CandidateThreshold hosts ever reach the
	// provider, batched and rate/circuit-limited.
	fused := make(map[string]FusedResult, len(pending))
	var candidates []Candidate
	for _, ph := range pending {
		if e.Provider != nil && IsCandidate(ph.local.Score) {
			candidates = append(candidates, Candidate{Host: ph.snap.Host, Site: ph.site, LocalScore: ph.local, Current: ph.snap.Current})
			continue
		}
		fused[ph.snap.Host] = FuseLocalOnly(ph.local)
	}
	if e.Provider != nil {
		e.LastModelStats = e.scoreCandidatesWithProvider(ctx, candidates, evaluationTime, fused)
	} else {
		e.LastModelStats = ModelCycleStats{}
	}

	// Advance lifecycle for every pending host, in the same deterministic
	// order as before, using its fused (not raw local) score/category —
	// baseline learning below still uses the RAW local score, since a
	// model's influence must never bias the statistical baseline itself.
	outcomeIdx := make(map[string]int, len(outcomes))
	for i, o := range outcomes {
		outcomeIdx[o.Host] = i
	}
	for _, ph := range pending {
		fr := fused[ph.snap.Host]
		lc := e.lifecycleFor(ph.snap.Host)
		transition := lc.Advance(fr.Score)

		idx := outcomeIdx[ph.snap.Host]
		outcomes[idx].Fused = fr
		outcomes[idx].Transition = transition

		if err := e.persistTransition(ph.snap.Host, ph.site, fr, transition, evaluationTime); err != nil {
			return outcomes, fmt.Errorf("persist transition for %s: %w", ph.snap.Host, err)
		}

		if ShouldUpdateBaseline(lc.State, ph.local.Score, true) {
			for name, value := range ph.snap.Current {
				e.Baselines.Observe(ph.snap.Host, name, evaluationTime, value)
			}
		}
		for name := range ph.snap.Current {
			e.Baselines.Evict(ph.snap.Host, name, evaluationTime)
		}
	}
	return outcomes, nil
}

// persistTransition maps one lifecycle Transition onto the SQLite
// episode/history/outbox write (spec §25) and, for warning->critical
// escalation, enqueues the two outbox rows in the resolve-then-fire order
// spec §22.2 requires. `fused` is the score/category/contributors that
// actually drove this transition — local-only for Stage A/non-candidates,
// model-escalated per spec §19 otherwise.
func (e *Engine) persistTransition(host, site string, fused FusedResult, tr Transition, evaluationTime int64) error {
	local := fused
	if tr.Action == ActionNone {
		return nil
	}
	now := time.Unix(evaluationTime, 0).UTC()
	fingerprint := Fingerprint(host, e.Profile.ID, e.Profile.Version)

	switch tr.Action {
	case ActionCreateWarning, ActionCreateCritical:
		signalID, err := NewULID()
		if err != nil {
			return err
		}
		episode := EpisodeRecord{
			SignalID: signalID, Fingerprint: fingerprint, PilotHost: host, Site: site,
			ProfileID: e.Profile.ID, ProfileVersion: e.Profile.Version,
			State: string(StateFiring), Severity: string(tr.Severity), CategoryHint: local.Category,
			CreatedAt: now, UpdatedAt: now, Revision: 1,
			LastScore: &local.Score,
		}
		payload, _ := json.Marshal(buildAlertPayload(host, site, string(tr.Severity), signalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, now, now))
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: signalID, Revision: 1, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: signalID, Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: string(payload), NextAttemptAt: now}},
		)

	case ActionEscalateCritical:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("escalate: no active episode for fingerprint (host=%s): %w", host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.Severity = string(SeverityCritical)
		episode.CategoryHint = local.Category
		episode.UpdatedAt = now
		episode.Revision = revision
		episode.LastScore = &local.Score

		resolvePayload, _ := json.Marshal(buildAlertPayload(host, site, string(SeverityWarning), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, existing.CreatedAt, now))
		firePayload, _ := json.Marshal(buildAlertPayload(host, site, string(SeverityCritical), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, now, now))
		resolveID, err := NewULID()
		if err != nil {
			return err
		}
		fireID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(firePayload), CreatedAt: now},
			[]OutboxRecord{
				{ID: resolveID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "resolve_warning", PayloadJSON: string(resolvePayload), NextAttemptAt: now},
				{ID: fireID, SignalID: existing.SignalID, Revision: revision, Sequence: 2, Kind: "fire_critical", PayloadJSON: string(firePayload), NextAttemptAt: now},
			},
		)

	case ActionEnterRecovering, ActionReturnToFiring:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("%s: no active episode for fingerprint (host=%s): %w", tr.Action, host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.State = string(tr.ToState)
		episode.Severity = string(tr.Severity)
		episode.UpdatedAt = now
		episode.Revision = revision
		episode.LastScore = &local.Score
		payload, _ := json.Marshal(buildAlertPayload(host, site, string(tr.Severity), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, existing.CreatedAt, now))
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "refresh", PayloadJSON: string(payload), NextAttemptAt: now}},
		)

	case ActionResolve:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("resolve: no active episode for fingerprint (host=%s): %w", host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.State = "resolved"
		episode.Severity = ""
		episode.UpdatedAt = now
		episode.Revision = revision
		payload, _ := json.Marshal(map[string]any{"signal_id": existing.SignalID, "pilot_host": host, "site": site})
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "resolve", PayloadJSON: string(payload), NextAttemptAt: now}},
		)
	}
	return nil
}
