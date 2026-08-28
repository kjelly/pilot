package detection

import (
	"regexp"
	"sort"
	"strings"
)

// Log detector tuning constants (spec1.md §17/§18/§41/§42). These are
// fixed constants rather than YAML-configurable — consistent with how
// this package's other detector thresholds (CandidateThreshold,
// minReadyBuckets) are already fixed, not runtime-tunable.
const (
	LogMaxSamplesPerTemplate    = 3
	LogMaxTemplatesPerCandidate = 8

	logBurstMinCurrentCount     = 5   // floor: never fire burst on 1-4 stray lines
	logBurstMultiplier          = 5.0 // current count must clear baseline-scaled-rate * this
	logRareBaselineMax          = 2   // baseline count 1..2 => "rare"; 0 => "new"
	logErrorRateSpikeMultiplier = 3.0
	logErrorRateMinCurrentCount = 5
	logErrorRateMinRate         = 0.1
)

// knownCriticalPatterns is spec1.md §17.5's hard-trigger pattern list —
// any match is a HARD TRIGGER (spec §37/§56 Invariant C: this Engine
// implements it as Option B — the log detector simply reports Score=1.0
// for this cycle; existing lifecycle hysteresis in HostLifecycle.Advance
// is untouched, since ComputeLocalScore already takes the max of every
// detector, so a 1.0 here can never be suppressed by a lower baseline/
// cohort/other-log-template score).
var knownCriticalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)out of memory`),
	regexp.MustCompile(`(?i)kernel panic`),
	regexp.MustCompile(`(?i)segfault`),
	regexp.MustCompile(`(?i)\bI/O error\b`),
	regexp.MustCompile(`(?i)(uncorrectable.*ECC|ECC.*uncorrectable)`),
	regexp.MustCompile(`(?i)(read-only file ?system|filesystem.*read.?only)`),
}

func matchesKnownCriticalPattern(line string) bool {
	for _, p := range knownCriticalPatterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// LogTemplateBucket is one template's activity within a single window
// (current or baseline): a count plus a bounded number of raw-message
// samples (spec1.md §18's evidence sampling — never every line).
type LogTemplateBucket struct {
	Count   int
	Samples []string
}

// LogWindowSummary is one host's log activity summarized into per-
// template counts for a single window.
type LogWindowSummary struct {
	TotalCount int
	ErrorCount int
	Templates  map[string]*LogTemplateBucket
}

// SummarizeLogWindow builds a LogWindowSummary from normalized entries
// (spec1.md §14: aggregate before anything reaches a detector or the LLM).
func SummarizeLogWindow(entries []LogEntry) LogWindowSummary {
	summary := LogWindowSummary{Templates: map[string]*LogTemplateBucket{}}
	for _, e := range entries {
		summary.TotalCount++
		if isErrorSeverity(e.Severity) {
			summary.ErrorCount++
		}
		b, ok := summary.Templates[e.TemplateID]
		if !ok {
			b = &LogTemplateBucket{}
			summary.Templates[e.TemplateID] = b
		}
		b.Count++
		if len(b.Samples) < LogMaxSamplesPerTemplate {
			b.Samples = append(b.Samples, e.Message)
		}
	}
	return summary
}

func isErrorSeverity(sev string) bool {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "error", "err", "critical", "crit", "fatal", "emerg", "emergency", "alert":
		return true
	default:
		return false
	}
}

func capScore(s float64) float64 {
	if s > 1 {
		return 1
	}
	if s < 0 {
		return 0
	}
	return s
}

// scoreLogTemplate implements spec1.md §17.1-§17.3 (burst/new-template/
// rare-template) as one combined 0-1 score for a single template.
// baselineWindowScale is (current window length / baseline window
// length), used to project the baseline's total count down to a
// current-window-sized expected rate.
func scoreLogTemplate(currentCount, baselineCount int, baselineWindowScale float64) (score float64, category string) {
	switch {
	case baselineCount == 0 && currentCount >= 1:
		// New template: never seen in the reference window at all.
		return capScore(0.5 + 0.1*float64(currentCount-1)), "new_template"
	case baselineCount <= logRareBaselineMax && currentCount > baselineCount:
		// Rare template: almost never seen, and now appearing more.
		return capScore(0.4 + 0.1*float64(currentCount-baselineCount)), "rare_template"
	default:
		expectedRate := float64(baselineCount) * baselineWindowScale
		floor := float64(logBurstMinCurrentCount)
		if expectedRate > floor {
			floor = expectedRate
		}
		if float64(currentCount) >= floor*logBurstMultiplier && currentCount >= logBurstMinCurrentCount {
			ratio := float64(currentCount) / floor
			return capScore(0.5 + 0.05*ratio), "burst"
		}
	}
	return 0, ""
}

// scoreErrorRate implements spec1.md §17.4: the error/total ratio spiking
// well above baseline.
func scoreErrorRate(current, baseline LogWindowSummary, baselineWindowScale float64) (float64, bool) {
	if current.TotalCount < logErrorRateMinCurrentCount {
		return 0, false
	}
	currentRate := float64(current.ErrorCount) / float64(current.TotalCount)
	if currentRate < logErrorRateMinRate {
		return 0, false
	}
	baselineRate := 0.0
	if baseline.TotalCount > 0 {
		baselineRate = float64(baseline.ErrorCount) / float64(baseline.TotalCount)
	}
	if currentRate <= baselineRate*logErrorRateSpikeMultiplier {
		return 0, false
	}
	return capScore(0.4 + currentRate), true
}

// ComputeLogHostScore implements spec1.md §17's log detectors end to end,
// returning a HostFeatureScoreResult shaped exactly like
// baseline.go/cohort.go's own output — the third, equally-weighted
// detector ComputeLocalScore takes the max across (spec1.md §66's "no
// separate schema, no separate detector tier").
func ComputeLogHostScore(current, baseline LogWindowSummary, baselineWindowScale float64) HostFeatureScoreResult {
	if current.TotalCount == 0 {
		return HostFeatureScoreResult{Valid: false}
	}

	// Hard trigger — checked first, short-circuits everything else.
	for templateID, bucket := range current.Templates {
		for _, sample := range bucket.Samples {
			if matchesKnownCriticalPattern(sample) {
				return HostFeatureScoreResult{
					Valid:    true,
					Score:    1.0,
					Category: "known_critical_pattern",
					Contributors: []Contributor{
						{Feature: "log:" + shortTemplateID(templateID), Category: "known_critical_pattern", Score: 1.0},
					},
				}
			}
		}
	}

	var contributors []Contributor
	best := 0.0
	bestCategory := ""

	for templateID, bucket := range current.Templates {
		baselineCount := 0
		if bb, ok := baseline.Templates[templateID]; ok {
			baselineCount = bb.Count
		}
		score, category := scoreLogTemplate(bucket.Count, baselineCount, baselineWindowScale)
		if score <= 0 {
			continue
		}
		contributors = append(contributors, Contributor{Feature: "log:" + shortTemplateID(templateID), Category: category, Score: score})
		if score > best {
			best, bestCategory = score, category
		}
	}

	if errScore, ok := scoreErrorRate(current, baseline, baselineWindowScale); ok {
		contributors = append(contributors, Contributor{Feature: "log:error_rate", Category: "error_rate", Score: errScore})
		if errScore > best {
			best, bestCategory = errScore, "error_rate"
		}
	}

	sort.Slice(contributors, func(i, j int) bool { return contributors[i].Score > contributors[j].Score })
	if len(contributors) > 5 {
		contributors = contributors[:5]
	}
	return HostFeatureScoreResult{Valid: true, Score: best, Category: bestCategory, Contributors: contributors}
}

func shortTemplateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
