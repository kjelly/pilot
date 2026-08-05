package diagnose

import (
	"testing"

	"github.com/kjelly/pilot/internal/networkcheck"
)

func TestValidateHost_ExactMatch(t *testing.T) {
	resolved := networkcheck.ResolvedInventory{
		HostVars: map[string]map[string]any{"web1": {"ansible_host": "10.0.0.1"}},
	}
	if err := ValidateHost(resolved, "web1"); err != nil {
		t.Fatalf("ValidateHost() error = %v, want nil for an exact inventory host", err)
	}
}

func TestValidateHost_UnknownHostFails(t *testing.T) {
	resolved := networkcheck.ResolvedInventory{
		HostVars: map[string]map[string]any{"web1": {"ansible_host": "10.0.0.1"}},
	}
	if err := ValidateHost(resolved, "web2"); err == nil {
		t.Fatal("ValidateHost() error = nil, want an error for an unknown host")
	}
}

// TestValidateHost_PatternsAreRejected guards the specific vulnerability
// this check exists to close: an MCP caller's host string must never be
// treated as an ansible pattern/group name, or "all"/"*" would silently
// expand to the whole fleet.
func TestValidateHost_PatternsAreRejected(t *testing.T) {
	resolved := networkcheck.ResolvedInventory{
		GroupHosts: map[string][]string{"all": {"web1", "web2"}},
		HostVars:   map[string]map[string]any{"web1": {}, "web2": {}},
	}
	for _, pattern := range []string{"all", "*", "webservers"} {
		if err := ValidateHost(resolved, pattern); err == nil {
			t.Fatalf("ValidateHost(%q) error = nil, want an error — patterns/group names must never validate as a host", pattern)
		}
	}
}
