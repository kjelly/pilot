package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/anomalyco/pilot/internal/agent"
	"github.com/manifoldco/promptui"
)

type Approver = agent.Approver
type Decision = agent.Decision

// ConsoleApprover is the default human-in-the-loop approver, backed by
// promptui.
type ConsoleApprover struct {
	AutoApprove string // "never" | "low" | "medium" | "high"
	NoInput     bool   // when true, never prompt (used by --check / --dry-run)
	mu          sync.Mutex
	approveAll  bool
}

func NewConsoleApprover(autoApprove string) *ConsoleApprover {
	return &ConsoleApprover{AutoApprove: autoApprove}
}

func (c *ConsoleApprover) Ask(p *agent.Proposal) Decision {
	// Auto-approve based on risk level
	switch c.AutoApprove {
	case "low":
		if p.RiskLevel == agent.RiskLow {
			fmt.Fprintf(os.Stderr, "[auto-approve low] %s on %s\n", p.Tool, p.Host)
			return agent.DecisionApproved
		}
	case "medium":
		if p.RiskLevel == agent.RiskLow || p.RiskLevel == agent.RiskMedium {
			fmt.Fprintf(os.Stderr, "[auto-approve medium] %s on %s\n", p.Tool, p.Host)
			return agent.DecisionApproved
		}
	}

	if c.NoInput {
		return agent.DecisionRejected
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.approveAll {
		fmt.Fprintf(os.Stderr, "[batch-approve] %s on %s\n", p.Tool, p.Host)
		return agent.DecisionApproved
	}

	for {
		printProposal(p)

		prompt := promptui.Select{
			Label: "Action",
			Items: []string{
				"✓ Approve and execute",
				"✓ Approve all remaining in this batch",
				"✗ Reject (skip this step)",
				"🔧 Show full details",
				"⛔ Abort entire run",
			},
			Stdout: os.Stderr,
		}
		idx, _, err := prompt.Run()
		if err != nil {
			// Likely Ctrl-C or EOF
			return agent.DecisionAbort
		}
		switch idx {
		case 0:
			return agent.DecisionApproved
		case 1:
			c.approveAll = true
			return agent.DecisionApproved
		case 2:
			return agent.DecisionRejected
		case 3:
			printFullProposal(p)
			// continue loop to ask again
		case 4:
			return agent.DecisionAbort
		}
	}
}

func printProposal(p *agent.Proposal) {
	fmt.Fprintln(os.Stderr, strings.Repeat("═", 70))
	fmt.Fprintf(os.Stderr, "📋 AI 提議  #%s\n", shortID(p.ID))
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 70))
	fmt.Fprintf(os.Stderr, "  主機:     %s\n", displayHost(p.Host))
	fmt.Fprintf(os.Stderr, "  工具:     %s\n", p.Tool)
	fmt.Fprintf(os.Stderr, "  風險:     %s\n", colorizeRisk(p.RiskLevel))
	if p.CISControl != "" {
		fmt.Fprintf(os.Stderr, "  CIS:      %s\n", p.CISControl)
	}
	fmt.Fprintf(os.Stderr, "  可逆:     %s\n", boolMark(p.Reversible))
	fmt.Fprintln(os.Stderr)
	// 操作: the tool's actual arguments — what will really happen. Without
	// this, run_command/read_file proposals hid the concrete command/path
	// behind "Show full details". Meta fields (_rationale/_risk_level/…)
	// are stripped since they're surfaced separately.
	if action := summarizeArgs(p.Args); action != "" {
		fmt.Fprintf(os.Stderr, "  📦 操作（實際參數）:\n")
		for _, line := range strings.Split(action, "\n") {
			fmt.Fprintf(os.Stderr, "     %s\n", line)
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintf(os.Stderr, "  💭 理由:\n")
	for _, line := range wrap(p.Rationale, 60) {
		fmt.Fprintf(os.Stderr, "     %s\n", line)
	}
	if p.DryRunOutput != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  🔍 預演輸出（ansible --check 結果）:\n")
		dry := p.DryRunOutput
		if len(dry) > 1500 {
			dry = dry[:1500] + "\n... [truncated]"
		}
		for _, line := range strings.Split(dry, "\n") {
			fmt.Fprintf(os.Stderr, "     %s\n", colorizeLine(line))
		}
	}
	fmt.Fprintln(os.Stderr, strings.Repeat("─", 70))
}

// summarizeArgs renders a tool's real arguments for the approval screen.
// pilot-internal metadata fields (_rationale / _risk_level / _host /
// _cis_control) are stripped because they are shown separately. Common
// single-argument tools (run_command, read_file) get a compact one-line
// form; everything else is pretty-printed JSON. Returns "" when there is
// nothing meaningful to show.
func summarizeArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not a JSON object (or malformed) — show the raw text.
		return truncateStr(strings.TrimSpace(string(raw)), 800)
	}
	for _, k := range []string{"_rationale", "_risk_level", "_host", "_cis_control"} {
		delete(m, k)
	}
	if len(m) == 0 {
		return ""
	}
	// Compact one-liner for the common read-only probes so the actual
	// command/path is front-and-centre, not buried in JSON braces.
	if cmd, ok := m["command"].(string); ok && len(m) == 1 {
		return truncateStr(strings.TrimSpace(cmd), 800)
	}
	if path, ok := m["path"].(string); ok && len(m) == 1 {
		return truncateStr(strings.TrimSpace(path), 800)
	}
	pretty, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return truncateStr(strings.TrimSpace(string(raw)), 800)
	}
	return truncateStr(string(pretty), 800)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... [truncated, use 🔧 Show full details for everything]"
}

func colorizeLine(line string) string {
	if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
		return "\033[32m" + line + "\033[0m" // Green
	}
	if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
		return "\033[31m" + line + "\033[0m" // Red
	}
	if strings.HasPrefix(line, "@@") {
		return "\033[36m" + line + "\033[0m" // Cyan
	}
	return line
}

func printFullProposal(p *agent.Proposal) {
	fmt.Fprintln(os.Stderr, "\n📋 Full proposal details:")
	fmt.Fprintf(os.Stderr, "ID:        %s\n", p.ID)
	fmt.Fprintf(os.Stderr, "RunID:     %s\n", p.RunID)
	fmt.Fprintf(os.Stderr, "Tool:      %s\n", p.Tool)
	fmt.Fprintf(os.Stderr, "Args:      %s\n", string(p.Args))
	fmt.Fprintf(os.Stderr, "Rationale: %s\n", p.Rationale)
	fmt.Fprintf(os.Stderr, "Risk:      %s\n", p.RiskLevel)
	fmt.Fprintf(os.Stderr, "CIS:       %s\n", p.CISControl)
	fmt.Fprintf(os.Stderr, "Reversible:%v\n", p.Reversible)
	fmt.Fprintf(os.Stderr, "Created:   %s\n", p.CreatedAt.Format("2006-01-02 15:04:05"))
	if p.DryRunOutput != "" {
		fmt.Fprintln(os.Stderr, "\n--- Dry run output ---")
		for _, line := range strings.Split(p.DryRunOutput, "\n") {
			fmt.Fprintln(os.Stderr, colorizeLine(line))
		}
	}
	fmt.Fprintln(os.Stderr)
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func displayHost(h string) string {
	if h == "" {
		return "(any host)"
	}
	return h
}

func colorizeRisk(r string) string {
	switch r {
	case agent.RiskLow:
		return "🟢 LOW"
	case agent.RiskMedium:
		return "🟡 MEDIUM"
	case agent.RiskHigh:
		return "🔴 HIGH"
	}
	return r
}

func boolMark(b bool) string {
	if b {
		return "✓ yes"
	}
	return "✗ no"
}

func wrap(s string, w int) []string {
	if s == "" {
		return []string{""}
	}
	words := strings.Fields(s)
	var out []string
	var line string
	for _, word := range words {
		if line == "" {
			line = word
		} else if len(line)+1+len(word) > w {
			out = append(out, line)
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func (c *ConsoleApprover) AskRollback(question string) bool {
	if c.NoInput {
		return false
	}

	prompt := promptui.Prompt{
		Label:     question,
		IsConfirm: true,
		Stdout:    os.Stderr,
	}
	_, err := prompt.Run()
	return err == nil
}
