package inventory

import (
	"testing"
	"time"
)

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}

func TestEvaluateGrantLifecycle_Absent(t *testing.T) {
	now := mustParseTime(t, "2026-08-25T00:00:00Z")
	validity := GrantValidity{NotAfter: mustParseTime(t, "2026-08-31T00:00:00Z")}
	if got := EvaluateGrantLifecycle("absent", validity, now); got != GrantAbsent {
		t.Fatalf("got %v, want absent", got)
	}
}

func TestEvaluateGrantLifecycle_PendingBeforeNotBefore(t *testing.T) {
	now := mustParseTime(t, "2026-08-01T00:00:00Z")
	validity := GrantValidity{
		NotBefore: mustParseTime(t, "2026-08-21T09:00:00Z"),
		NotAfter:  mustParseTime(t, "2026-08-31T18:00:00Z"),
	}
	if got := EvaluateGrantLifecycle("present", validity, now); got != GrantPending {
		t.Fatalf("got %v, want pending", got)
	}
}

func TestEvaluateGrantLifecycle_ActiveWithinWindow(t *testing.T) {
	now := mustParseTime(t, "2026-08-25T00:00:00Z")
	validity := GrantValidity{
		NotBefore: mustParseTime(t, "2026-08-21T09:00:00Z"),
		NotAfter:  mustParseTime(t, "2026-08-31T18:00:00Z"),
	}
	if got := EvaluateGrantLifecycle("present", validity, now); got != GrantActive {
		t.Fatalf("got %v, want active", got)
	}
}

func TestEvaluateGrantLifecycle_ActiveWithoutNotBefore(t *testing.T) {
	now := mustParseTime(t, "2026-08-01T00:00:00Z")
	validity := GrantValidity{NotAfter: mustParseTime(t, "2026-08-31T18:00:00Z")}
	if got := EvaluateGrantLifecycle("present", validity, now); got != GrantActive {
		t.Fatalf("got %v, want active (no lower bound)", got)
	}
}

func TestEvaluateGrantLifecycle_ExpiredAfterNotAfter(t *testing.T) {
	now := mustParseTime(t, "2026-09-01T00:00:00Z")
	validity := GrantValidity{
		NotBefore: mustParseTime(t, "2026-08-21T09:00:00Z"),
		NotAfter:  mustParseTime(t, "2026-08-31T18:00:00Z"),
	}
	if got := EvaluateGrantLifecycle("present", validity, now); got != GrantExpired {
		t.Fatalf("got %v, want expired", got)
	}
}

func TestEvaluateGrantLifecycle_ExpiredAtExactBoundary(t *testing.T) {
	notAfter := mustParseTime(t, "2026-08-31T18:00:00Z")
	validity := GrantValidity{NotAfter: notAfter}
	if got := EvaluateGrantLifecycle("present", validity, notAfter); got != GrantExpired {
		t.Fatalf("got %v, want expired at exactly not_after (half-open interval)", got)
	}
}

func TestEvaluateGrantLifecycle_UsesUTCComparison(t *testing.T) {
	// now is 2026-08-31T17:00:00-08:00 == 2026-09-01T01:00:00Z, which is
	// after a not_after of 2026-08-31T18:00:00Z — a naive non-UTC string/
	// wall-clock comparison could get this backwards.
	loc := time.FixedZone("UTC-8", -8*60*60)
	now := time.Date(2026, 8, 31, 17, 0, 0, 0, loc)
	validity := GrantValidity{NotAfter: mustParseTime(t, "2026-08-31T18:00:00Z")}
	if got := EvaluateGrantLifecycle("present", validity, now); got != GrantExpired {
		t.Fatalf("got %v, want expired under UTC-normalized comparison", got)
	}
}

func TestNextGrantTransition_Pending(t *testing.T) {
	now := mustParseTime(t, "2026-08-01T00:00:00Z")
	notBefore := mustParseTime(t, "2026-08-21T09:00:00Z")
	validity := GrantValidity{NotBefore: notBefore, NotAfter: mustParseTime(t, "2026-08-31T18:00:00Z")}
	got := NextGrantTransition("present", validity, now)
	if got == nil || !got.Equal(notBefore) {
		t.Fatalf("got %v, want %v", got, notBefore)
	}
}

func TestNextGrantTransition_Active(t *testing.T) {
	now := mustParseTime(t, "2026-08-25T00:00:00Z")
	notAfter := mustParseTime(t, "2026-08-31T18:00:00Z")
	validity := GrantValidity{NotAfter: notAfter}
	got := NextGrantTransition("present", validity, now)
	if got == nil || !got.Equal(notAfter) {
		t.Fatalf("got %v, want %v", got, notAfter)
	}
}

func TestNextGrantTransition_ExpiredAndAbsentHaveNone(t *testing.T) {
	now := mustParseTime(t, "2026-09-01T00:00:00Z")
	validity := GrantValidity{NotAfter: mustParseTime(t, "2026-08-31T18:00:00Z")}
	if got := NextGrantTransition("present", validity, now); got != nil {
		t.Fatalf("expected no further transition once expired, got %v", got)
	}
	if got := NextGrantTransition("absent", validity, now); got != nil {
		t.Fatalf("expected no transition for an absent grant, got %v", got)
	}
}

func TestParseGrantValidity_RequiresNotAfter(t *testing.T) {
	if _, err := ParseGrantValidity(map[string]any{}); err == nil {
		t.Fatal("expected an error when not_after is missing")
	}
}

func TestParseGrantValidity_RejectsNonRFC3339(t *testing.T) {
	if _, err := ParseGrantValidity(map[string]any{"not_after": "2026-08-31"}); err == nil {
		t.Fatal("expected an error for a non-RFC3339 not_after")
	}
}

func TestParseGrantValidity_RejectsNotAfterNotAfterNotBefore(t *testing.T) {
	_, err := ParseGrantValidity(map[string]any{
		"not_before": "2026-08-31T18:00:00Z",
		"not_after":  "2026-08-21T09:00:00Z",
	})
	if err == nil {
		t.Fatal("expected an error when not_after is before not_before")
	}
}

func TestParseGrantValidity_OptionalNotBefore(t *testing.T) {
	v, err := ParseGrantValidity(map[string]any{"not_after": "2026-08-31T18:00:00Z"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.NotBefore.IsZero() {
		t.Fatalf("expected zero NotBefore when omitted, got %v", v.NotBefore)
	}
}
