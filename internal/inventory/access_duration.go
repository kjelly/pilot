package inventory

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// accessDurationRe matches the duration grammar spec.md §12 documents
// (30m, 1h, 8h, 24h, 7d, ...): a positive integer count followed by a
// single m/h/d unit. This is the one grammar shared by breakglass
// activation.max_duration (§6.3/§7) and, from v3.0 Phase 2 onward,
// security.grant_policies[].require.max_duration (§12) — kept in one place
// so both sections reject the same malformed strings.
var accessDurationRe = regexp.MustCompile(`^([0-9]+)([mhd])$`)

// ParseAccessDuration parses s under the supported duration grammar. It
// deliberately does not accept seconds, fractional counts, or any other
// time.ParseDuration syntax — only what spec.md §12 enumerates.
func ParseAccessDuration(s string) (time.Duration, error) {
	m := accessDurationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("duration %q must match <count>m|h|d (e.g. 30m, 1h, 8h, 24h, 7d)", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("duration %q must have a positive count", s)
	}
	switch m[2] {
	case "m":
		return time.Duration(n) * time.Minute, nil
	case "h":
		return time.Duration(n) * time.Hour, nil
	case "d":
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("duration %q has an unsupported unit", s)
}

// ValidAccessDuration reports whether s parses cleanly under
// ParseAccessDuration, for callers that only need a yes/no validity check.
func ValidAccessDuration(s string) bool {
	_, err := ParseAccessDuration(s)
	return err == nil
}
