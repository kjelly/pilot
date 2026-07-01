package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sanitizer"
	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/sandbox"
	"github.com/anomalyco/pilot/internal/store"
	"github.com/anomalyco/pilot/internal/tools"
)

// maxToolArgsBytes is the per-call upper bound on the JSON-encoded
// arguments the model sends to a tool. The model can otherwise
// ship an entire playbook as a base64 string and exhaust the
// context window before the tool even runs. 64 KiB is generous
// for any real Ansible task; anything larger is almost certainly
// abuse.
const maxToolArgsBytes = 64 * 1024

// Config holds runtime configuration for the agent
type Config struct {
	RunID        string
	DataDir      string
	Ollama       *ollama.Client
	Tools        *tools.Registry
	Store        *store.Store
	Sanitizer    *sanitizer.Redactor
	Approver     Approver
	Stream       bool
	MaxIter      int
	SystemPrompt string
	StreamWriter io.Writer // usually os.Stderr
	// TUI is an optional TUI bridge. When non-nil, LLM streaming chunks
	// and tool events are sent to the TUI in addition to (or instead of)
	// StreamWriter. Approver is still the source of truth for decisions.
	TUI TUIEmitter
	// Runner is the ansible runner used by tools and by the pre-flight
	// dry-run preview before approval. May be nil in tests that
	// don't exercise ansible.
	Runner *ansible.Runner
	// Env is the sandbox environment (if any)
	Env sandbox.Environment
	// DryRun, when true, runs the full agent loop but intercepts any
	// tool call that would mutate the system. Read-only tools still
	// execute; write tools are recorded as "[DRY-RUN] would call X"
	// proposals. All proposals/agent messages are still persisted so
	// the dry-run is auditable.
	DryRun bool
	// AllowDisposableApply bypasses high risk escalation on VM/sandbox targets
	AllowDisposableApply bool
}

// TUIEmitter is the subset of the TUI Program API used by the agent loop.
// Defining it here as an interface avoids an import cycle between
// internal/agent and internal/ui/tui.
type TUIEmitter interface {
	SendLLMChunk(content, thinking string)
	SendLLMDone()
	SendToolCall(tool, args string)
	SendToolResult(tool, summary string, isErr bool)
	SendStatus(iter, maxIter, proposalCount, pendingCount int, tool, host string)
	SendRunStart(runID, goal string)
	SendRunFinish(runID, status string)
	SendError(msg string)
}

// Loop is the ReAct-style agent loop.
type Loop struct {
	cfg     Config
	history []ollama.Message
	dedup   *DedupTracker

	// recentRejections is a small LRU of (tool+args to count) used by
	// reflectOnRejection / reflectOnFailure to avoid pushing the same
	// mistake into the context window more than twice. Reset at the
	// start of each new user turn.
	recentRejections map[string]int

	// recentToolCalls counts consecutive identical tool calls. When
	// the same tool+args fires 3 times in a row, the loop guard
	// aborts to prevent the user from being stuck in an infinite
	// "let me try the same thing again" loop. Reset whenever the LLM
	// calls a different tool or with different args.
	recentToolCalls map[string]int

	// playbookSucceeded is set once a run_ansible / apply_playbook
	// call returns a non-error result (exit 0). It powers the
	// post-success spiral guard: weaker models often keep issuing
	// read-only probes after the playbook is already done instead of
	// concluding. Reset to false if a later playbook run fails (the
	// model legitimately gets a fresh budget to fix it).
	playbookSucceeded bool
	// postSuccessProbes counts consecutive read-only probes
	// (run_command / read_file / run_inspec …) issued AFTER the
	// playbook succeeded, regardless of args. This is what makes the
	// guard catch spirals that recentToolCalls misses (each probe
	// uses different args, so the identical-args guard never fires).
	postSuccessProbes int

	// lastAssistantText holds the assistant message content of the
	// current turn. It is the fallback rationale for a proposal when
	// the model did not supply an explicit _rationale arg: the model
	// almost always narrates its reason in prose ("Let me check …"),
	// and that sentence is far more useful to the human reviewer than
	// a blank 理由. Set in runSession before each tool-call dispatch.
	lastAssistantText string
}

// NewLoop constructs an agent loop ready to run.
func NewLoop(cfg Config) *Loop {
	if cfg.StreamWriter == nil {
		cfg.StreamWriter = os.Stderr
	}
	return &Loop{
		cfg:              cfg,
		dedup:            NewDedupTracker(cfg.Store),
		history:          []ollama.Message{},
		recentRejections: make(map[string]int),
		recentToolCalls:  make(map[string]int),
	}
}

// SetDryRun enables or disables dry-run mode after construction.
// Useful when the dry-run flag is determined by CLI flags processed
// after the loop is built.
func (l *Loop) SetDryRun(on bool) {
	l.cfg.DryRun = on
}

// Tools returns the registry the loop will dispatch tool calls to.
// Exposed for tests and (in the future) tooling that needs to inspect
// the available tool set without running the loop.
func (l *Loop) Tools() *tools.Registry {
	return l.cfg.Tools
}

// Run executes the agent loop for the given user goal. The system
// prompt configured on the Loop is prepended on the first call. Use
// RunOnce for subsequent turns in an interactive REPL.
func (l *Loop) Run(ctx context.Context, userGoal string) error {
	if l.cfg.SystemPrompt != "" && !l.systemPromptSeeded() {
		l.history = append(l.history,
			ollama.Message{Role: "system", Content: l.cfg.SystemPrompt},
		)
	}
	return l.runSession(ctx, userGoal, true /* emitAssistantText */)
}

// RunOnce runs one round of the agent loop with a fresh user message,
// preserving history (and the seeded system prompt) across calls. Use
// this for interactive REPL.
func (l *Loop) RunOnce(ctx context.Context, userGoal string) error {
	return l.runSession(ctx, userGoal, true /* emitAssistantText */)
}

// systemPromptSeeded returns true when a system message is already at
// the head of the history. Used to decide whether Run needs to prepend
// the configured SystemPrompt (RunOnce never re-seeds).
func (l *Loop) systemPromptSeeded() bool {
	for _, m := range l.history {
		if m.Role == "system" {
			return true
		}
	}
	return false
}

// runSession is the single iteration engine shared by Run and RunOnce.
// emitAssistantText controls whether the assistant's text response is
// echoed to the stream writer (it is, except when the TUI is doing
// its own rendering of the same content).
func (l *Loop) runSession(ctx context.Context, userGoal string, emitAssistantText bool) error {
	l.history = append(l.history,
		ollama.Message{Role: "user", Content: userGoal},
	)
	l.persistMessage("user", userGoal, nil)

	for i := 0; i < l.cfg.MaxIter; i++ {
		resp, err := l.callModel(ctx)
		if err != nil {
			return fmt.Errorf("ollama call failed at iter %d: %w", i, err)
		}
		sanitized := l.cfg.Sanitizer.Sanitize(resp.Message.Content)
		resp.Message.Content = sanitized
		l.history = append(l.history, resp.Message)
		l.persistMessage("assistant", sanitized, marshalToolCalls(resp.Message.ToolCalls))

		if emitAssistantText && resp.Message.Content != "" && l.cfg.TUI == nil {
			fmt.Fprintf(l.cfg.StreamWriter, "\n🤖 %s\n", resp.Message.Content)
		}
		if l.cfg.TUI != nil {
			l.cfg.TUI.SendLLMDone()
		}

		if len(resp.Message.ToolCalls) == 0 {
			return nil
		}

		// Remember this turn's prose so handleToolCall can use it as a
		// fallback rationale when the model omits an explicit _rationale.
		l.lastAssistantText = resp.Message.Content

		abort := false
		for _, tc := range resp.Message.ToolCalls {
			dec, err := l.handleToolCall(ctx, tc)
			if err != nil {
				return err
			}
			if dec == DecisionAbort {
				abort = true
				break
			}
		}
		if abort {
			return nil
		}
	}
	return fmt.Errorf("max iterations (%d) reached without conclusion", l.cfg.MaxIter)
}

func (l *Loop) callModel(ctx context.Context) (*ollama.ChatResponse, error) {
	if l.cfg.Stream {
		return l.cfg.Ollama.ChatStream(ctx, l.history, l.cfg.Tools.OllamaTools(), l.onChunk)
	}
	return l.cfg.Ollama.Chat(ctx, l.history, l.cfg.Tools.OllamaTools())
}

func (l *Loop) onChunk(content, thinking string) {
	if l.cfg.TUI != nil {
		l.cfg.TUI.SendLLMChunk(content, thinking)
		return
	}
	if content != "" {
		fmt.Fprint(l.cfg.StreamWriter, content)
	}
	if thinking != "" {
		// show thinking dimmed
		fmt.Fprintf(l.cfg.StreamWriter, "\033[2m%s\033[0m", thinking)
	}
}

// handleToolCall processes a single tool call from the model.
// The model may include optional "rationale" and "risk_level" alongside the
// tool arguments; we extract them as proposal metadata. We do this in a
// best-effort way: if the args object has those fields, use them; otherwise
// default to medium risk.
func (l *Loop) handleToolCall(ctx context.Context, tc ollama.ToolCall) (Decision, error) {
	toolSpec, ok := l.cfg.Tools.Get(tc.Function.Name)
	if !ok {
		return DecisionRejected, fmt.Errorf("model called unknown tool %q", tc.Function.Name)
	}

	// Size cap: refuse tool calls with huge args. The model could
	// otherwise pass an entire playbook as a base64 string and
	// exhaust the context window before the tool even runs. We
	// treat this as a recoverable rejection: persist a failed
	// proposal, surface the error to the model as a tool result,
	// and continue the loop so the model can retry with smaller
	// args.
	if len(tc.Function.Arguments) > maxToolArgsBytes {
		errMsg := fmt.Sprintf("tool %q args too large: %d bytes (limit %d)",
			tc.Function.Name, len(tc.Function.Arguments), maxToolArgsBytes)
		p := NewProposal(
			l.cfg.RunID,
			"", "", json.RawMessage(tc.Function.Arguments),
			errMsg, RiskMedium, "", false,
		)
		p.Status = StatusRejected
		l.saveProposal(p)
		l.appendToolResult(tc, "ERROR: "+errMsg)
		if l.cfg.TUI != nil {
			l.cfg.TUI.SendToolResult(tc.Function.Name, errMsg, true)
		}
		return DecisionRejected, nil
	}

	// Sanitize the incoming arguments (defense in depth)
	sanitizedArgs := l.cfg.Sanitizer.Sanitize(string(tc.Function.Arguments))

	// Extract proposal metadata from the args
	host, rationale, risk, cis := extractProposalMeta(tc.Function.Arguments)
	// Fallback: when the model didn't fill an explicit _rationale arg,
	// use this turn's narration so the reviewer sees *why*, not a blank.
	if rationale == "" {
		if fb := strings.TrimSpace(l.lastAssistantText); fb != "" {
			rationale = truncate(fb, 600)
		}
	}
	risk = l.upgradeRiskForApply(risk, tc.Function.Name, tc.Function.Arguments)

	p := NewProposal(
		l.cfg.RunID,
		host,
		tc.Function.Name,
		json.RawMessage(sanitizedArgs),
		rationale,
		risk,
		cis,
		toolSpec.Reversible,
	)

	// Notify the TUI that a tool is about to be called (before approval)
	if l.cfg.TUI != nil {
		l.cfg.TUI.SendToolCall(tc.Function.Name, truncateArgs(string(sanitizedArgs), 200))
	}

	// For run_ansible / apply_playbook, run a real --check --diff
	// pre-flight so the human can see the actual proposed changes
	// before approving. The check is run synchronously here (with a
	// generous timeout) so the prompt the user sees contains the
	// diff. If check=false is explicitly requested we still attempt
	// it — it's read-only on the target.
	if tc.Function.Name == "run_ansible" || tc.Function.Name == "apply_playbook" {
		p.DryRunOutput = previewAnsibleRun(ctx, sanitizedArgs, l.cfg.Runner)
	}

	// Ask the human
	decision := l.cfg.Approver.Ask(p)
	switch decision {
	case DecisionRejected:
		p.Status = StatusRejected
		l.saveProposal(p)
		l.appendToolResult(tc, "Skipped by user")
		if l.cfg.TUI != nil {
			l.cfg.TUI.SendToolResult(tc.Function.Name, "rejected by user", false)
		}
		return decision, nil
	case DecisionAbort:
		p.Status = StatusRejected
		l.saveProposal(p)
		if l.cfg.TUI != nil {
			l.cfg.TUI.SendToolResult(tc.Function.Name, "aborted by user", true)
		}
		return decision, nil
	}

	// Approved → execute
	p.Status = StatusApproved
	p.DryRun = l.cfg.DryRun
	now := time.Now()
	p.ReviewedAt = &now

	// Run the tool's Interceptor hook (may rewrite args or
	// short-circuit). The Interceptor is the SINGLE place where dry-run
	// policy is encoded; per-tool logic lives next to its Spec, not
	// in the agent loop.
	if toolSpec.Interceptor != nil {
		ctxWithDryRun := tools.ContextWithDryRun(ctx, l.cfg.DryRun)
		interceptResult, err := toolSpec.Interceptor(ctxWithDryRun, json.RawMessage(sanitizedArgs))
		if err != nil {
			l.reflectOnFailure(p, err.Error())
			return DecisionRejected, fmt.Errorf("interceptor for %q failed: %w", tc.Function.Name, err)
		}
		if interceptResult != nil {
			// Interceptor short-circuited the call.
			return l.applySyntheticResult(tc, p, toolSpec, interceptResult)
		}
		// Interceptor may have signalled "rewrite args" by returning
		// (nil, nil) under dry-run for run_ansible — apply the known
		// rewrite. Other tools can extend this pattern by exposing a
		// helper on the Spec (see RunPlaybookTool.OverrideCheckFlag).
		if tc.Function.Name == "run_ansible" && l.cfg.DryRun {
			var a struct {
				Check *bool `json:"check"`
			}
			_ = json.Unmarshal(json.RawMessage(sanitizedArgs), &a)
			if a.Check == nil || !*a.Check {
				rewritten, err := tools.OverrideCheckFlag(json.RawMessage(sanitizedArgs))
				if err != nil {
					return DecisionRejected, err
				}
				sanitizedArgs = string(rewritten)
				p.Args = json.RawMessage(sanitizedArgs)
			}
		}
	}

	// Dry-run: tool is not safe to execute; record a "would do" proposal.
	if l.cfg.DryRun && !toolSpec.DryRunSafe {
		l.saveProposal(p)
		return l.recordDryRunSkip(tc, p, "tool not safe under --dry-run-all")
	}

	l.saveProposal(p)

	if l.cfg.TUI == nil {
		if l.cfg.DryRun {
			fmt.Fprintf(l.cfg.StreamWriter, "\n🔍 [DRY-RUN] would call: %s ...\n", tc.Function.Name)
		} else {
			fmt.Fprintf(l.cfg.StreamWriter, "\n▶ 執行中: %s ...\n", tc.Function.Name)
		}
	}

	// Docker snapshot pre-execution: if sandbox is a Snapshotable, take a commit snapshot.
	var snapshotID string
	var snapshotErr error
	var snapshotable sandbox.Snapshotable
	if !l.cfg.DryRun && l.cfg.Env != nil && (tc.Function.Name == "run_ansible" || tc.Function.Name == "apply_playbook") {
		var a struct {
			Check *bool `json:"check"`
		}
		_ = json.Unmarshal([]byte(sanitizedArgs), &a)
		if a.Check != nil && !*a.Check {
			if snap, ok := l.cfg.Env.(sandbox.Snapshotable); ok {
				snapshotable = snap
				if l.cfg.TUI == nil {
					fmt.Fprintln(l.cfg.StreamWriter, "📸 正在建立 Docker 沙箱狀態快照...")
				}
				snapshotID, snapshotErr = snap.CreateSnapshot(ctx)
				if snapshotErr != nil {
					if l.cfg.TUI == nil {
						fmt.Fprintf(l.cfg.StreamWriter, "⚠️  建立快照失敗: %v\n", snapshotErr)
					}
				} else {
					if l.cfg.TUI == nil {
						fmt.Fprintf(l.cfg.StreamWriter, "✓ 快照建立成功: %s\n", snapshotID)
					}
				}
			}
		}
	}

	result, err := toolSpec.Execute(ctx, json.RawMessage(sanitizedArgs))
	if err != nil {
		p.Status = StatusFailed
		p.ResultContent = err.Error()
		p.ResultIsError = true
		l.saveProposal(p)
		l.appendToolResult(tc, fmt.Sprintf("ERROR: %v", err))
		return decision, nil
	}

	p.Status = StatusApplied
	if result != nil {
		// sanitize result too
		p.ResultContent = l.cfg.Sanitizer.Sanitize(result.Content)
		p.ResultIsError = result.IsError
	}
	applied := time.Now()
	p.AppliedAt = &applied
	l.saveProposal(p)

	// Build a short summary for the model
	summary := ""
	if result != nil {
		summary = result.Content
		if len(summary) > 3000 {
			summary = summary[:3000] + "\n... [truncated for context window]"
		}
	}
	l.appendToolResult(tc, summary)

	// Loop guard: if the LLM calls the SAME tool with the SAME args
	// twice in a row, it is almost certainly stuck in a retry loop
	// (e.g. "let me run the playbook again with slightly different
	// args"). We bail out with a clear message so the user can see
	// the final state instead of getting an infinite run. The first
	// run is allowed; the second identical call gets a warning;
	// the third is rejected and the loop ends.
	if l.recordAndMaybeBreakLoop(tc, summary) {
		// Agent has been calling the same tool with the same args 3
		// times in a row. The LOOP GUARD footer was just appended;
		// signal runSession to stop at the next iteration boundary.
		return DecisionAbort, nil
	}

	// Post-success spiral guard: once the playbook has run cleanly,
	// further read-only probing (with whatever args) is the classic
	// "weaker model won't stop" pattern. Unlike recordAndMaybeBreakLoop
	// this does NOT require identical args.
	if l.recordAndMaybeBreakPostSuccess(tc, result) {
		return DecisionAbort, nil
	}

	// Send tool result to TUI activity log
	if l.cfg.TUI != nil {
		isErr := result != nil && result.IsError
		sum := summary
		if len(sum) > 200 {
			sum = sum[:200] + "…"
		}
		l.cfg.TUI.SendToolResult(tc.Function.Name, sum, isErr)
	}

	// One-click rollback / recovery if a playbook run fails
	if result != nil && result.IsError && (tc.Function.Name == "run_ansible" || tc.Function.Name == "apply_playbook") {
		restored := false
		if snapshotable != nil && snapshotID != "" {
			if rollbacker, ok := l.cfg.Approver.(interface{ AskRollback(string) bool }); ok {
				if rollbacker.AskRollback("⚠️  Playbook 執行失敗！是否直接還原 Docker 沙箱至執行前快照狀態？（注意：外部掛載卷 Volume 的修改將不會被還原）") {
					if l.cfg.TUI == nil {
						fmt.Fprintln(l.cfg.StreamWriter, "🔄 正在還原 Docker 沙箱狀態（注意：外部掛載卷 Volume 的修改無法還原）...")
					}
					if rerr := snapshotable.RestoreSnapshot(ctx, snapshotID); rerr == nil {
						if l.cfg.TUI == nil {
							fmt.Fprintln(l.cfg.StreamWriter, "✓ 沙箱狀態還原成功。")
						} else {
							l.cfg.TUI.SendToolResult("run_ansible", "Docker sandbox restored to pre-apply snapshot", false)
						}
						_ = snapshotable.DeleteSnapshot(ctx, snapshotID)
						restored = true
					} else {
						if l.cfg.TUI == nil {
							fmt.Fprintf(l.cfg.StreamWriter, "❌ 還原沙箱狀態失敗: %v\n", rerr)
						} else {
							l.cfg.TUI.SendToolResult("run_ansible", "Failed to restore Docker snapshot: "+rerr.Error(), true)
						}
					}
				}
			}
		}
		if !restored {
			if rollbacker, ok := l.cfg.Approver.(interface{ AskRollback(string) bool }); ok {
				if rollbacker.AskRollback("⚠️  Playbook 執行失敗！是否要一鍵還原 (Generate & Run Rollback)？") {
				if l.cfg.TUI == nil {
					fmt.Fprintln(l.cfg.StreamWriter, "🔄 正在生成還原 Playbook...")
				}
				rollbackTool, okGen := l.cfg.Tools.Get("generate_rollback")
				runAnsibleTool, okRun := l.cfg.Tools.Get("run_ansible")
				if okGen && okRun {
					// 1. Generate rollback
					genArgs, _ := json.Marshal(map[string]any{
						"proposal_id":   p.ID,
						"description":   p.Rationale,
						"original_tool": p.Tool,
						"original_args": string(p.Args),
						"context":       result.Content,
					})
					genRes, err := rollbackTool.Execute(ctx, genArgs)
					if err == nil && genRes != nil && !genRes.IsError {
						var path string
						if len(genRes.Metadata) > 0 {
							var meta struct {
								RollbackPath string `json:"rollback_path"`
							}
							if err := json.Unmarshal(genRes.Metadata, &meta); err == nil && meta.RollbackPath != "" {
								path = meta.RollbackPath
							}
						}
						if path == "" {
							const prefix = "Rollback playbook written to: "
							idxPath := strings.Index(genRes.Content, prefix)
							if idxPath != -1 {
								rem := genRes.Content[idxPath+len(prefix):]
								endIdx := strings.Index(rem, "\n")
								if endIdx != -1 {
									path = strings.TrimSpace(rem[:endIdx])
								}
							}
						}
						if path != "" {
							if l.cfg.TUI == nil {
								fmt.Fprintf(l.cfg.StreamWriter, "▶ 正在套用還原 Playbook: %s...\n", path)
							}
							var orig struct {
								Inventory string `json:"inventory"`
								Limit     string `json:"limit"`
							}
							_ = json.Unmarshal(p.Args, &orig)

							runArgs, _ := json.Marshal(map[string]any{
								"playbook":  path,
								"check":     false,
								"inventory": orig.Inventory,
								"limit":     orig.Limit,
							})
							runRes, runErr := runAnsibleTool.Execute(ctx, runArgs)
							if runErr == nil && runRes != nil && !runRes.IsError {
								if l.cfg.TUI == nil {
									fmt.Fprintln(l.cfg.StreamWriter, "✓ 一鍵還原執行成功！系統已復原。")
								} else {
									l.cfg.TUI.SendToolResult("run_ansible", "Rollback applied successfully", false)
								}
							} else {
								errMsg := ""
								if runRes != nil {
									errMsg = runRes.Content
								} else if runErr != nil {
									errMsg = runErr.Error()
								}
								if l.cfg.TUI == nil {
									fmt.Fprintf(l.cfg.StreamWriter, "❌ 一鍵還原執行失敗: %s\n", errMsg)
								} else {
									l.cfg.TUI.SendToolResult("run_ansible", "Rollback failed: "+errMsg, true)
								}
							}
						}
					}
				}
			}
		}
		}
	}

	// Per-host failure dedup: if tool errored, give model a chance to diagnose
	// but only for the first failure per host per run.
	if result != nil && result.IsError && host != "" {
		if l.dedup.ShouldDiagnose(l.cfg.RunID, host) {
			if l.cfg.TUI == nil {
				fmt.Fprintf(l.cfg.StreamWriter, "🔍 First failure for host %s — agent will consider diagnosis in next iteration.\n", host)
			}
		}
	}
	if snapshotable != nil && snapshotID != "" && (result == nil || !result.IsError) {
		_ = snapshotable.DeleteSnapshot(ctx, snapshotID)
	}
	return decision, nil
}

func (l *Loop) saveProposal(p *Proposal) {
	// 1. SQLite
	if l.cfg.Store != nil {
		_ = l.cfg.Store.SaveProposal(&store.Proposal{
			ID:         p.ID,
			RunID:      p.RunID,
			Host:       p.Host,
			Tool:       p.Tool,
			Args:       p.Args,
			Rationale:  p.Rationale,
			RiskLevel:  p.RiskLevel,
			CISControl: p.CISControl,
			Status:     p.Status,
			Reversible: p.Reversible,
			DryRun:     p.DryRun,
			CreatedAt:  p.CreatedAt,
			ReviewedAt: p.ReviewedAt,
			AppliedAt:  p.AppliedAt,
		})
	}
	// 2. YAML file artifact
	if l.cfg.DataDir != "" {
		dir := filepath.Join(l.cfg.DataDir, "proposals")
		_ = os.MkdirAll(dir, 0o755)
		path := filepath.Join(dir, p.ID+".yaml")
		// Use simple key=value format rather than pulling in yaml.Marshal twice
		writeProposalYAML(path, p)
		p.FilePath = path
	}
}

func (l *Loop) persistMessage(role, content string, toolCalls json.RawMessage) {
	if l.cfg.Store == nil {
		return
	}
	_ = l.cfg.Store.SaveAgentMessage(&store.AgentMessage{
		RunID:     l.cfg.RunID,
		Role:      role,
		Content:   content,
		ToolCalls: toolCalls,
		CreatedAt: time.Now(),
	})
}

// recordAndMaybeBreakLoop tracks the most recent N tool calls. If the
// LLM calls the same tool+args twice in a row, we know it is stuck in
// a retry loop (the classic "let me try the same thing one more time"
// pattern that wastes cycles and confuses the user). On the SECOND
// identical call we add a strong hint to the next tool result. On the
// THIRD identical call we return DecisionAbort so the loop ends.
//
// This is a guard, not a hard kill: a legitimate "rerun the playbook
// with the same args" workflow is rare, and even when it happens the
// hint will help the LLM understand why we're stopping.
//
// Hash key is sha256(toolName + sorted args) — order-independent so
// {"a":1,"b":2} and {"b":2,"a":1} are considered identical.
// recordAndMaybeBreakLoop tracks the most recent N tool calls. If the
// LLM calls the same tool+args twice in a row, it is almost certainly
// stuck in a retry loop (the classic "let me try the same thing one
// more time" pattern). On the THIRD identical call we:
//   1. Append a "LOOP GUARD" footer to the tool result so the user
//      sees the final state.
//   2. Return true so the agent loop can abort cleanly with a
//      clear final message instead of looping forever.
//
// Returns true when the loop should abort, false otherwise.
func (l *Loop) recordAndMaybeBreakLoop(tc ollama.ToolCall, summary string) bool {
	key := l.toolCallKey(tc)
	count := l.recentToolCalls[key]
	l.recentToolCalls[key] = count + 1
	if count+1 >= 3 {
		l.appendToolResult(tc, "\n=== LOOP GUARD ===\nYou have called "+tc.Function.Name+" with the same arguments 3 times in a row. The agent loop is now aborting. If you believe further action is needed, the user can re-run pilot manually with adjusted arguments. Do NOT call any more tools.\n==================")
		return true
	}
	return false
}

// recordAndMaybeBreakPostSuccess implements the post-success spiral
// guard. It complements recordAndMaybeBreakLoop, which only catches
// the SAME tool+args repeated; this one catches the more common
// real-world spiral where the playbook has already finished with
// failed=0 but the model keeps issuing DIFFERENT read-only probes
// ("let me check one more thing") and never concludes.
//
// State machine:
//   - A successful run_ansible / apply_playbook sets playbookSucceeded
//     and resets the probe counter (the apply itself is not a probe).
//   - A FAILED playbook run clears playbookSucceeded — the model
//     legitimately needs a fresh budget of probes to diagnose/fix.
//   - Each read-only probe after success increments the counter:
//       1st probe → allowed silently (verifying the result is fine)
//       2nd probe → soft nudge appended to the tool result
//       3rd probe → LOOP GUARD footer appended and the loop aborts
//
// Mutating tools (run_ansible/apply_playbook) and ask_user are never
// counted as probes — they represent real follow-up work.
//
// Returns true when the loop should abort.
func (l *Loop) recordAndMaybeBreakPostSuccess(tc ollama.ToolCall, result *tools.Result) bool {
	name := tc.Function.Name
	if name == "run_ansible" || name == "apply_playbook" {
		l.playbookSucceeded = result != nil && !result.IsError
		l.postSuccessProbes = 0
		return false
	}
	// Not a playbook run. Only count when we're already in the
	// post-success window; ask_user is a legitimate way to get a new
	// goal so it doesn't count.
	if !l.playbookSucceeded || name == "ask_user" {
		return false
	}
	l.postSuccessProbes++
	if l.postSuccessProbes >= 3 {
		l.appendToolResult(tc, fmt.Sprintf("\n=== LOOP GUARD ===\nThe playbook already completed successfully (failed=0) and you have issued %d further read-only probes without concluding. The task is DONE — the agent loop is now aborting. Do NOT call any more tools; just summarise the result for the user.\n==================", l.postSuccessProbes))
		return true
	}
	if l.postSuccessProbes == 2 {
		l.appendToolResult(tc, "\n=== NOTE ===\nThe playbook already completed successfully (failed=0). If nothing else genuinely needs fixing, STOP now: reply with a short summary and do NOT call any more tools.\n============")
	}
	return false
}

func (l *Loop) toolCallKey(tc ollama.ToolCall) string {
	// Hash the tool name + args. We don't normalise arg order —
	// JSON maps are already canonicalised by the Go encoder.
	h := sha256.New()
	h.Write([]byte(tc.Function.Name))
	h.Write([]byte{0})
	h.Write([]byte(tc.Function.Arguments))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (l *Loop) appendToolResult(tc ollama.ToolCall, content string) {
	// Sanitize the tool result before adding to history.
	content = l.cfg.Sanitizer.Sanitize(content)
	// Wrap in an <untrusted_tool_output> marker to mitigate prompt
	// injection from tool output. The system prompt instructs the model
	// to treat content inside these markers as data, never as instructions.
	wrapped := WrapUntrusted(tc.Function.Name, content)
	msg := ollama.Message{
		Role:       "tool",
		Content:    wrapped,
		ToolCallID: tc.Function.Name, // Ollama uses tool name as id
	}
	l.history = append(l.history, msg)
	// Persist the wrapped form so audit logs reflect what the model saw.
	l.persistMessage("tool", wrapped, nil)
}


func marshalToolCalls(tcs []ollama.ToolCall) json.RawMessage {
	if len(tcs) == 0 {
		return nil
	}
	b, _ := json.Marshal(tcs)
	return b
}

// extractProposalMeta looks for known metadata fields in the tool-call args.
// The LLM is instructed to include them, but if absent we default safely.
func extractProposalMeta(args json.RawMessage) (host, rationale, risk, cis string) {
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return "", "", RiskMedium, ""
	}
	if v, ok := m["_host"].(string); ok {
		host = v
	}
	if v, ok := m["_rationale"].(string); ok {
		rationale = v
	}
	if v, ok := m["_risk_level"].(string); ok {
		risk = strings.ToLower(v)
	}
	if risk != RiskLow && risk != RiskMedium && risk != RiskHigh {
		risk = RiskMedium
	}
	if v, ok := m["_cis_control"].(string); ok {
		cis = v
	}
	return
}

// writeProposalYAML writes the proposal as a simple YAML artifact for git tracking.
func writeProposalYAML(path string, p *Proposal) {
	// Hand-format to avoid pulling yaml.v3 into agent package; keeps the file
	// readable when inspected directly.
	var sb strings.Builder
	fmt.Fprintf(&sb, "id: %s\n", p.ID)
	fmt.Fprintf(&sb, "run_id: %s\n", p.RunID)
	fmt.Fprintf(&sb, "host: %q\n", p.Host)
	fmt.Fprintf(&sb, "tool: %s\n", p.Tool)
	fmt.Fprintf(&sb, "risk_level: %s\n", p.RiskLevel)
	if p.CISControl != "" {
		fmt.Fprintf(&sb, "cis_control: %s\n", p.CISControl)
	}
	fmt.Fprintf(&sb, "reversible: %v\n", p.Reversible)
	fmt.Fprintf(&sb, "status: %s\n", p.Status)
	fmt.Fprintf(&sb, "created_at: %s\n", p.CreatedAt.Format(time.RFC3339))
	if p.ReviewedAt != nil {
		fmt.Fprintf(&sb, "reviewed_at: %s\n", p.ReviewedAt.Format(time.RFC3339))
	}
	if p.AppliedAt != nil {
		fmt.Fprintf(&sb, "applied_at: %s\n", p.AppliedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&sb, "rationale: |\n")
	for _, line := range strings.Split(p.Rationale, "\n") {
		fmt.Fprintf(&sb, "  %s\n", line)
	}
	fmt.Fprintf(&sb, "args:\n")
	// indent args json by 2 spaces
	for _, line := range strings.Split(string(p.Args), "\n") {
		fmt.Fprintf(&sb, "  %s\n", line)
	}
	if p.ResultContent != "" {
		fmt.Fprintf(&sb, "result: |\n")
		for _, line := range strings.Split(truncate(p.ResultContent, 4000), "\n") {
			fmt.Fprintf(&sb, "  %s\n", line)
		}
		fmt.Fprintf(&sb, "result_is_error: %v\n", p.ResultIsError)
	}
	_ = os.WriteFile(path, []byte(sb.String()), 0o644)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... [truncated]"
}

func truncateArgs(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}


// applySyntheticResult is called when a tool's Interceptor short-circuits
// the actual execution (e.g. to surface a synthetic dry-run preview).
// We mark the proposal as applied, persist the synthetic content, and
// feed it back to the model so the loop can continue.
func (l *Loop) applySyntheticResult(tc ollama.ToolCall, p *Proposal, toolSpec *tools.Spec, synth *tools.Result) (Decision, error) {
	p.Status = StatusApplied
	p.DryRunOutput = synth.Content
	applied := time.Now()
	p.AppliedAt = &applied
	l.saveProposal(p)
	l.appendToolResult(tc, synth.Content)
	if l.cfg.TUI != nil {
		isErr := synth.IsError
		sum := synth.Content
		if len(sum) > 200 {
			sum = sum[:200] + "…"
		}
		l.cfg.TUI.SendToolResult(tc.Function.Name, sum, isErr)
	}
	return DecisionApproved, nil
}

// recordDryRunSkip is called when --dry-run-all is on and the LLM
// asked for a tool that would mutate the system. We do NOT execute;
// instead we record a proposal with status=approved (the user did
// approve) but mark it as would-have-run, and feed the model a fake
// "tool result" so it can continue its reasoning.
func (l *Loop) recordDryRunSkip(tc ollama.ToolCall, p *Proposal, reason string) (Decision, error) {
	p.Status = StatusApplied
	now := time.Now()
	p.AppliedAt = &now
	p.ResultContent = fmt.Sprintf("[DRY-RUN] would call %s (skipped: %s)", tc.Function.Name, reason)
	p.ResultIsError = false
	l.saveProposal(p)

	summary := p.ResultContent
	if len(summary) > 200 {
		summary = summary[:200] + "…"
	}
	l.appendToolResult(tc, summary)
	if l.cfg.TUI != nil {
		l.cfg.TUI.SendToolResult(tc.Function.Name, summary, false)
	}
	return DecisionApproved, nil
}

// overrideCheckFlag patches a JSON args blob so that "check":false
// becomes "check":true (or adds "check":true if absent). Used when
// --dry-run-all is on and the LLM asks run_ansible to apply.
func overrideCheckFlag(args string, check bool) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(args), &m); err != nil {
		// If args isn't a JSON object, can't safely override; return as-is.
		return args
	}
	m["check"] = check
	out, _ := json.Marshal(m)
	return string(out)
}

// isDisposable checks if the target environment is a docker sandbox or
// a managed pilot vm-target, representing a safe sandbox execution context.
func (l *Loop) isDisposable(args json.RawMessage) bool {
	// 1. Docker sandbox is always disposable
	if l.cfg.Env != nil && l.cfg.Env.Name() != "local" {
		return true
	}

	// 2. Parse inventory from args to check if it's a pilot vm-target
	var a struct {
		Inventory string `json:"inventory"`
	}
	if err := json.Unmarshal(args, &a); err == nil && a.Inventory != "" {
		base := filepath.Base(a.Inventory)
		if strings.HasPrefix(base, "pilot-vt-inv-") {
			return true
		}
		// Or read the first few bytes to check if it is a generated inventory
		if data, err := os.ReadFile(a.Inventory); err == nil {
			if strings.Contains(string(data), "Generated by pilot vm-target") {
				return true
			}
		}
	}
	return false
}

// upgradeRiskForApply bumps a tool call's risk to "high" when the call
// would apply a change rather than preview it. Currently the only
// trigger is run_ansible / apply_playbook with check=false.
//
// This is a deliberate fail-closed policy: even when --auto-approve is
// set to medium, an apply-mode playbook must still get explicit
// human approval, UNLESS allow_disposable_apply is enabled and the
// target is a disposable container or VM.
func (l *Loop) upgradeRiskForApply(currentRisk, toolName string, args json.RawMessage) string {
	if toolName != "run_ansible" && toolName != "apply_playbook" {
		return currentRisk
	}
	var a struct {
		Check *bool `json:"check"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		// If we can't tell whether it's check or apply, treat as the
		// more dangerous case (apply) — fail closed.
		return RiskHigh
	}
	// check=true (or unspecified default in RunPlaybookTool is true)
	// stays at the spec's declared risk.
	if a.Check != nil && !*a.Check {
		if l.cfg.AllowDisposableApply && l.isDisposable(args) {
			return currentRisk
		}
		return RiskHigh
	}
	return currentRisk
}

// previewAnsibleRun executes ansible-playbook --check --diff for
// the given args and returns a short human-readable summary
// (truncated to ~2000 chars). If the runner isn't configured,
// ansible isn't installed, or the playbook path is rejected, the
// returned string is still informative — it explains why the
// preview failed, so the user sees the failure alongside the
// proposal rather than a generic placeholder.
func previewAnsibleRun(ctx context.Context, args string, runner *ansible.Runner) string {
	if runner == nil {
		return "(ansible runner not configured; cannot preview)"
	}
	// Parse the args to extract playbook + optional inventory +
	// the 11 new ansible-playbook flags. The same field set used
	// by the tool's Execute() so the preview exactly mirrors the
	// real run.
	var a struct {
		Playbook          string            `json:"playbook"`
		Inventory         string            `json:"inventory"`
		Limit             string            `json:"limit"`
		Check             *bool             `json:"check"`
		Tags              []string          `json:"tags"`
		SkipTags          []string          `json:"skip_tags"`
		ExtraVars         map[string]any    `json:"extra_vars"`
		RawExtraVars      string            `json:"extra_vars_raw"`
		Become            *bool             `json:"become"`
		Forks             *int              `json:"forks"`
		User              string            `json:"user"`
		Connection        string            `json:"connection"`
		VaultPasswordFile string            `json:"vault_password_file"`
		Diff              *bool             `json:"diff"`
		Timeout           *int              `json:"timeout"`
		FlushCache        *bool             `json:"flush_cache"`
	}
	if err := json.Unmarshal([]byte(args), &a); err != nil {
		return fmt.Sprintf("(could not parse args for preview: %v)", err)
	}
	if a.Playbook == "" {
		return "(no playbook in args; nothing to preview)"
	}

	// Preview must mirror the tool's logic for extra_vars — write
	// the object to a temp JSON file and pass via -e @<file>.
	var extraVarsFile string
	if a.ExtraVars != nil {
		data, err := json.Marshal(a.ExtraVars)
		if err != nil {
			return fmt.Sprintf("(could not marshal extra_vars for preview: %v)", err)
		}
		f, err := os.CreateTemp("", "pilot-preview-vars-*.json")
		if err != nil {
			return fmt.Sprintf("(could not write extra_vars tmpfile for preview: %v)", err)
		}
		_ = f.Chmod(0o600)
		if _, err := f.Write(data); err != nil {
			f.Close()
			os.Remove(f.Name())
			return fmt.Sprintf("(could not write extra_vars tmpfile for preview: %v)", err)
		}
		f.Close()
		extraVarsFile = f.Name()
		defer os.Remove(extraVarsFile)
	}

	// Force check=true for the preview regardless of the LLM's
	// choice — the preview is always read-only. We pass --check --diff
	// before the playbook arg, then the rest from BuildArgs.
	allArgs := []string{"--check", "--diff"}
	allArgs = append(allArgs, ansible.BuildArgs(ansible.PlaybookArgs{
		Playbook:          a.Playbook,
		Inventory:         a.Inventory,
		Limit:             a.Limit,
		Tags:              a.Tags,
		SkipTags:          a.SkipTags,
		ExtraVarsFile:     extraVarsFile,
		RawExtraVars:      a.RawExtraVars,
		Become:            a.Become,
		Forks:             a.Forks,
		User:              a.User,
		Connection:        a.Connection,
		VaultPasswordFile: a.VaultPasswordFile,
		Diff:              a.Diff,
		Timeout:           a.Timeout,
		FlushCache:        a.FlushCache,
	})...)

	previewCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := runner.Run(previewCtx, allArgs...)
	if err != nil {
		return fmt.Sprintf("(preview failed: %v; stderr: %s)",
			err, truncate(res.Stderr, 1000))
	}
	if res.ExitCode != 0 {
		return fmt.Sprintf("(preview exited %d; stderr: %s)",
			res.ExitCode, truncate(res.Stderr, 1000))
	}
	// Parse the diff into a structured summary so the proposal
	// shows per-file Before/After instead of raw stdout. Falls back
	// to a short truncated stdout if parsing yields nothing useful.
	summary := ansible.ParseDiff(res.Stdout)
	if summary.FilesTotal == 0 {
		if res.Stdout == "" {
			return "(preview produced no diff — playbook would be a no-op)"
		}
		diff := res.Stdout
		if len(diff) > 2000 {
			diff = diff[:2000] + "\n... [truncated]"
		}
		return diff
	}
	out, _ := json.MarshalIndent(summary, "", "  ")
	return string(out)
}
