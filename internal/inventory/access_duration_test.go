package inventory

import (
	"testing"
	"time"
)

func TestParseAccessDuration_SupportedGrammar(t *testing.T) {
	cases := map[string]time.Duration{
		"30m": 30 * time.Minute,
		"1h":  time.Hour,
		"8h":  8 * time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
	}
	for s, want := range cases {
		got, err := ParseAccessDuration(s)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("%q: got %v, want %v", s, got, want)
		}
	}
}

func TestParseAccessDuration_RejectsUnsupportedForms(t *testing.T) {
	for _, s := range []string{"", "30", "30s", "-1h", "1.5h", "1H", "h1", "1w"} {
		if _, err := ParseAccessDuration(s); err == nil {
			t.Errorf("%q: expected an error, got none", s)
		}
	}
}

func TestValidAccessDuration(t *testing.T) {
	if !ValidAccessDuration("1h") {
		t.Fatal("expected 1h to be valid")
	}
	if ValidAccessDuration("1w") {
		t.Fatal("expected 1w to be invalid")
	}
}
