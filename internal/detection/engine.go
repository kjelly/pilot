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

	var outcomes []HostCycleOutcome
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

		lc := e.lifecycleFor(snap.Host)
		transition := lc.Advance(local.Score)
		outcome.Transition = transition

		if err := e.persistTransition(snap.Host, key.Site, local, transition, evaluationTime); err != nil {
			return outcomes, fmt.Errorf("persist transition for %s: %w", snap.Host, err)
		}

		allRequiredValid := valid
		if ShouldUpdateBaseline(lc.State, local.Score, allRequiredValid) {
			for name, value := range snap.Current {
				e.Baselines.Observe(snap.Host, name, evaluationTime, value)
			}
		}
		for name := range snap.Current {
			e.Baselines.Evict(snap.Host, name, evaluationTime)
		}

		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// persistTransition maps one lifecycle Transition onto the SQLite
// episode/history/outbox write (spec §25) and, for warning->critical
// escalation, enqueues the two outbox rows in the resolve-then-fire order
// spec §22.2 requires.
func (e *Engine) persistTransition(host, site string, local LocalScoreResult, tr Transition, evaluationTime int64) error {
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
