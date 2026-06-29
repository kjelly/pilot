package ui

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSummarizeArgs_StripsMetaAndCompactsCommonTools pins that the
// approval screen shows the tool's real arguments with pilot-internal
// metadata stripped, and that single-arg probes get a compact one-liner.
func TestSummarizeArgs_StripsMetaAndCompactsCommonTools(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string // exact match for compact forms; substring for JSON
		json bool   // when true, `want` is checked as a substring
	}{
		{
			name: "run_command compact",
			args: `{"command":"find . -name inventory","_rationale":"look for inventory","_risk_level":"low"}`,
			want: "find . -name inventory",
		},
		{
			name: "read_file compact",
			args: `{"path":"/etc/hosts","_risk_level":"low"}`,
			want: "/etc/hosts",
		},
		{
			name: "multi-field falls back to JSON",
			args: `{"playbook":"site.yml","check":true,"_rationale":"apply"}`,
			want: `"playbook": "site.yml"`,
			json: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeArgs(json.RawMessage(tt.args))
			if tt.json {
				if !strings.Contains(got, tt.want) {
					t.Errorf("want substring %q in %q", tt.want, got)
				}
				// meta must never leak into the action view
				if strings.Contains(got, "_rationale") || strings.Contains(got, "_risk_level") {
					t.Errorf("meta field leaked into action view: %q", got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSummarizeArgs_EmptyAndMetaOnly pins that there's nothing to show
// when args are empty or contain only metadata fields.
func TestSummarizeArgs_EmptyAndMetaOnly(t *testing.T) {
	if got := summarizeArgs(nil); got != "" {
		t.Errorf("nil args should yield empty, got %q", got)
	}
	if got := summarizeArgs(json.RawMessage(`{"_rationale":"x","_risk_level":"low"}`)); got != "" {
		t.Errorf("meta-only args should yield empty, got %q", got)
	}
}
