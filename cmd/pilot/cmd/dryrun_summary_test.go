package cmd

import (
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/anomalyco/pilot/internal/store"
)

func TestProposalOneLineSummaryUsesRationale(t *testing.T) {
	p := &agent.Proposal{
		Tool:      "run_ansible",
		Rationale: "Disable PermitRootLogin per CIS 5.2.1",
	}
	got := proposalOneLineSummary(p)
	if got != "Disable PermitRootLogin per CIS 5.2.1" {
		t.Errorf("expected rationale verbatim, got: %q", got)
	}
}

func TestProposalOneLineSummaryFallsBackToArgs(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{"playbook arg", `{"playbook":"/etc/ssh/site.yml"}`, "/etc/ssh/site.yml"},
		{"path arg", `{"path":"/etc/hosts"}`, "/etc/hosts"},
		{"command arg", `{"command":"systemctl status sshd"}`, "systemctl status sshd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &agent.Proposal{Tool: "run_ansible", Args: []byte(c.args)}
			got := proposalOneLineSummary(p)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestProposalOneLineSummaryEmpty(t *testing.T) {
	p := &agent.Proposal{Tool: "run_ansible"}
	got := proposalOneLineSummary(p)
	if got != "(no rationale)" {
		t.Errorf("expected '(no rationale)' fallback, got: %q", got)
	}
}

func TestProposalsFromStore(t *testing.T) {
	src := []*store.Proposal{
		{ID: "p1", Tool: "read_file", RiskLevel: "low", Rationale: "check config"},
		{ID: "p2", Tool: "run_ansible", RiskLevel: "high", CISControl: "5.2.1"},
	}
	out := proposalsFromStore(src)
	if len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
	if out[0].ID != "p1" || out[0].Tool != "read_file" || out[0].RiskLevel != "low" {
		t.Errorf("p1 fields wrong: %+v", out[0])
	}
	if out[1].CISControl != "5.2.1" {
		t.Errorf("p2 CISControl not copied: %+v", out[1])
	}
}

func TestProposalsFromStoreEmpty(t *testing.T) {
	out := proposalsFromStore(nil)
	if len(out) != 0 {
		t.Errorf("got %d, want 0", len(out))
	}
}

// Sanity: the WOULD-DO summary text contains "WOULD-DO" when there's at
// least one proposal; otherwise the function returns without printing.
func TestPrintDryRunWouldDoEmptyIsNoop(t *testing.T) {
	// No proposals → no output to stderr. We can't easily assert on
	// stderr here, but at least the function should not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printDryRunWouldDo panicked: %v", r)
		}
	}()
	printDryRunWouldDo(nil)
	// Empty Results slice with no proposals shouldn't render anything.
	printDryRunWouldDo([]batchResult{{Playbook: "x.yml"}})
}

// String-trim helper for nicer error messages (re-using the codebase's
// truncate style).
var _ = strings.TrimSpace
