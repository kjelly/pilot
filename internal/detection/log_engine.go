package detection

import (
	"context"
	"time"
)

// DefaultLogCurrentWindow and DefaultLogBaselineWindow are spec1.md §12's
// example windows — used whenever an Engine has LogSource set but leaves
// LogCurrentWindow/LogBaselineWindow at their zero value.
const (
	DefaultLogCurrentWindow  = 10 * time.Minute
	DefaultLogBaselineWindow = 6 * time.Hour
)

// queryLogWindows fetches the current and (non-overlapping) baseline log
// windows in two Loki calls, groups every line by its stream's pilot_host
// label, and returns per-host summaries plus the current/baseline window
// length ratio ComputeLogHostScore needs for burst scaling. A nil
// LogSource, or any query error, degrades to "no log signal this cycle"
// (nil maps) rather than failing the whole engine cycle — logs are an
// OPTIONAL peer to baseline/cohort, never a hard dependency (matches the
// same "missing optional feature doesn't invalidate the cycle" philosophy
// baseline/cohort already follow).
func (e *Engine) queryLogWindows(ctx context.Context, evaluationTime int64) (current, baseline map[string]LogWindowSummary, scale float64) {
	if e.LogSource == nil || e.LogQuery == "" {
		return nil, nil, 0
	}
	currentWindow := e.LogCurrentWindow
	if currentWindow <= 0 {
		currentWindow = DefaultLogCurrentWindow
	}
	baselineWindow := e.LogBaselineWindow
	if baselineWindow <= 0 {
		baselineWindow = DefaultLogBaselineWindow
	}

	now := time.Unix(evaluationTime, 0).UTC()
	currentStart := now.Add(-currentWindow)
	baselineStart := now.Add(-baselineWindow)

	currentLines, err := e.LogSource.QueryRange(ctx, e.LogQuery, currentStart, now, 0)
	if err != nil {
		return nil, nil, 0
	}
	// The baseline window is the reference period BEFORE the current
	// window, non-overlapping — spec1.md §12's baseline is a reference,
	// not "current window included in a longer average."
	baselineLines, err := e.LogSource.QueryRange(ctx, e.LogQuery, baselineStart, currentStart, 0)
	if err != nil {
		baselineLines = nil // still show the current window; baseline just reads as "no history"
	}

	current = summarizeLogLinesByHost(currentLines)
	baseline = summarizeLogLinesByHost(baselineLines)
	scale = currentWindow.Seconds() / baselineWindow.Seconds()
	return current, baseline, scale
}

// summarizeLogLinesByHost normalizes every raw line and groups it by its
// stream's pilot_host label (spec1.md §15) — a line with no pilot_host
// label can't be attributed to a subject and is dropped, not guessed at.
func summarizeLogLinesByHost(lines []RawLogLine) map[string]LogWindowSummary {
	byHost := map[string][]LogEntry{}
	for _, l := range lines {
		host := l.Stream["pilot_host"]
		if host == "" {
			continue
		}
		site := l.Stream["site"]
		severity := l.Stream["level"]
		if severity == "" {
			severity = l.Stream["severity"]
		}
		byHost[host] = append(byHost[host], NormalizeLogEntry(l.Timestamp, host, site, severity, l.Line))
	}
	out := make(map[string]LogWindowSummary, len(byHost))
	for host, entries := range byHost {
		out[host] = SummarizeLogWindow(entries)
	}
	return out
}
