// replay.go — an offline backtesting prototype (not yet part of any spec
// row): re-runs robust-baseline-v1 and the lifecycle state machine against
// ALREADY-RETAINED historical Thanos data, so a tuned feature-profile.yaml
// (different scaleFloor/validMin/validMax) can be evaluated against real
// history before ever touching a live deployment. It reuses the exact
// same pure functions the live engine calls (ComputeBaselineHostScore,
// ComputeLocalScore, FuseLocalOnly, HostLifecycle.Advance,
// ShouldUpdateBaseline) so its verdicts are not a reimplementation that
// could drift from production behavior.
//
// Known, deliberate v1 gaps (not silently papered over):
//   - cohort-outlier-v1 is never evaluated — production itself never
//     assigns any host to a cohort either (runServe always constructs the
//     Engine with cohorts=nil), so replaying it would test a code path
//     nothing live exercises today.
//   - the log detector is never evaluated — replaying it needs a
//     historical, windowed Loki query (current + baseline windows per
//     bucket), which is real additional complexity left for a follow-up.
//   - Model Provider fusion is never evaluated — this tool only answers
//     "what would local-only scoring have decided."
//   - per-sample staleness/future-skew classification (source.go's
//     ClassifySample, tuned for live transport lag) does not apply to
//     already-retained history; a bucket counts as valid here whenever
//     every required feature has a finite, in-[validMin,validMax] value.
//   - the contamination-protection check (ShouldUpdateBaseline) reads the
//     lifecycle state BEFORE this bucket's own Advance() call, for every
//     bucket uniformly; production reads it after Advance() specifically
//     for hosts that already had a valid score that cycle. This only
//     matters for the exact bucket a transition occurs on and has no
//     effect on aggregate transition counts over a real backtest window.
package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"time"

	"github.com/kjelly/pilot/internal/detection"
	"github.com/spf13/cobra"
)

func newReplayCmd() *cobra.Command {
	var thanosURL, profilePath, startStr, endStr string
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Backtest robust-baseline-v1 + lifecycle against historical Thanos data (prototype, local-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			start, err := time.Parse(time.RFC3339, startStr)
			if err != nil {
				return fmt.Errorf("--start: %w", err)
			}
			end, err := time.Parse(time.RFC3339, endStr)
			if err != nil {
				return fmt.Errorf("--end: %w", err)
			}
			if !end.After(start) {
				return fmt.Errorf("--end must be after --start")
			}
			profile, err := detection.LoadFeatureProfile(profilePath)
			if err != nil {
				return fmt.Errorf("load feature profile: %w", err)
			}
			client := detection.NewThanosClient(thanosURL, detection.QueryTimeout)
			return runReplay(cmd.Context(), os.Stdout, client, profile, start, end)
		},
	}
	cmd.Flags().StringVar(&thanosURL, "thanos", "", "Thanos/Prometheus-compatible query base URL, e.g. http://10.0.0.5:10912 (required)")
	cmd.Flags().StringVar(&profilePath, "profile", "", "path to the feature-profile.yaml to replay — point at a tuned copy to backtest a threshold change (required)")
	cmd.Flags().StringVar(&startStr, "start", "", "RFC3339 start of the historical window, e.g. 2026-08-01T00:00:00Z (required)")
	cmd.Flags().StringVar(&endStr, "end", "", "RFC3339 end of the historical window (required)")
	cmd.MarkFlagRequired("thanos")
	cmd.MarkFlagRequired("profile")
	cmd.MarkFlagRequired("start")
	cmd.MarkFlagRequired("end")
	return cmd
}

// replayStep is the bucket granularity — fixed at 60s to match
// BucketOf/HostBaselineStore's own minute buckets exactly, so replayed
// history composes with ComputeBaselineHostScore identically to how a
// live Observe() call would.
const replayStep = 60

// hostSeries holds one feature's historical values for one host, keyed by
// bucket timestamp (already BucketOf-aligned).
type hostSeries map[string]map[string]map[int64]float64 // host -> feature -> bucket -> value

func runReplay(ctx context.Context, out io.Writer, client *detection.ThanosClient, profile detection.FeatureProfile, start, end time.Time) error {
	identity := profile.EffectiveIdentity()
	series := hostSeries{}
	siteByHost := map[string]string{}
	bucketSet := map[int64]bool{}

	for _, feature := range profile.Features {
		rangeSeries, err := client.RangeQuery(ctx, feature.PromQL, start.Unix(), end.Unix(), replayStep)
		if err != nil {
			return fmt.Errorf("range query feature %s: %w", feature.Name, err)
		}
		for _, rs := range rangeSeries {
			host := rs.Metric[identity.Label]
			if host == "" {
				continue
			}
			siteByHost[host] = rs.Metric[identity.SiteLabel]
			if series[host] == nil {
				series[host] = map[string]map[int64]float64{}
			}
			if series[host][feature.Name] == nil {
				series[host][feature.Name] = map[int64]float64{}
			}
			for _, sm := range rs.Samples {
				bucket := detection.BucketOf(sm.Timestamp)
				series[host][feature.Name][bucket] = sm.Value
				bucketSet[bucket] = true
			}
		}
	}

	buckets := make([]int64, 0, len(bucketSet))
	for b := range bucketSet {
		buckets = append(buckets, b)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i] < buckets[j] })

	hosts := make([]string, 0, len(series))
	for h := range series {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	baselines := detection.NewHostBaselineStore()
	lifecycles := map[string]*detection.HostLifecycle{}
	required := profile.RequiredFeatures()

	counts := map[detection.LifecycleAction]int{}
	fmt.Fprintf(out, "replay window: %s .. %s (%d buckets, %d hosts)\n\n", start.Format(time.RFC3339), end.Format(time.RFC3339), len(buckets), len(hosts))

	for _, bucket := range buckets {
		bucketTime := time.Unix(bucket, 0).UTC()
		for _, host := range hosts {
			current := map[string]float64{}
			for name, byBucket := range series[host] {
				if v, ok := byBucket[bucket]; ok {
					current[name] = v
				}
			}
			if !replayHostCycleValid(required, current) {
				continue // spec §20.7: invalid cycle advances nothing
			}

			history := map[string][]float64{}
			for name := range current {
				history[name] = baselines.History(host, name)
			}
			baselineResult := detection.ComputeBaselineHostScore(profile, history, current)
			local := detection.ComputeLocalScore(baselineResult,
				detection.HostFeatureScoreResult{Valid: false}, // cohort: never assigned in production either
				detection.HostFeatureScoreResult{Valid: false}, // log: out of scope for this prototype
			)

			lc, ok := lifecycles[host]
			if !ok {
				lc = detection.NewHostLifecycle()
				lifecycles[host] = lc
			}

			// History accumulation must NOT be gated behind local.Valid —
			// baseline only becomes Valid after 120 buckets of history,
			// and with cohort/log hardcoded invalid above, local.Valid
			// could otherwise never become true even once (the exact
			// engine.go cold-start deadlock this tool exists to replay
			// around). Seed history on every genuinely-valid bucket,
			// using the raw local score (0 while nothing is Valid yet).
			if detection.ShouldUpdateBaseline(lc.State, local.Score, true) {
				for name, value := range current {
					baselines.Observe(host, name, bucket, value)
				}
			}
			for name := range current {
				baselines.Evict(host, name, bucket)
			}

			if !local.Valid {
				continue
			}
			fused := detection.FuseLocalOnly(local)

			transition := lc.Advance(fused.Score)
			if transition.Action != detection.ActionNone {
				counts[transition.Action]++
				fmt.Fprintf(out, "%s  %-20s %-20s score=%.3f category=%q %s -> %s (severity=%s)\n",
					bucketTime.Format(time.RFC3339), host, transition.Action, fused.Score, fused.Category,
					transition.FromState, transition.ToState, transition.Severity)
			}
		}
	}

	fmt.Fprintf(out, "\nsummary:\n")
	for _, action := range []detection.LifecycleAction{
		detection.ActionCreateWarning, detection.ActionCreateCritical, detection.ActionEscalateCritical,
		detection.ActionEnterRecovering, detection.ActionReturnToFiring, detection.ActionResolve,
	} {
		fmt.Fprintf(out, "  %-20s %d\n", action, counts[action])
	}
	return nil
}

// replayHostCycleValid is the replay-appropriate simplification of
// source.go's HostCycleValid: every required feature must have a finite
// reading within its [validMin, validMax] range at this bucket. It
// deliberately skips the staleness/future-skew checks ClassifySample
// applies in production — those exist for live transport lag, which
// doesn't apply to already-retained historical samples.
func replayHostCycleValid(required []detection.Feature, current map[string]float64) bool {
	for _, f := range required {
		v, ok := current[f.Name]
		if !ok {
			return false
		}
		if math.IsNaN(v) || math.IsInf(v, 0) || v < f.ValidMin || v > f.ValidMax {
			return false
		}
	}
	return true
}
