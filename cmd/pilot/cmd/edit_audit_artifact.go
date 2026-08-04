// edit_audit_artifact.go is the plan/apply audit directory's
// non-streaming half: a real AuditRecorder implementation that writes
// a standard asciicast v2 session.cast (Phase 1 only shipped the
// no-op default), plus the writer for the static files a plan run
// produces once it finishes (metadata.json, scenario.redacted.json,
// diff.patch, validation.json). trace.jsonl is written by Phase 1's
// existing automationTraceSink — see mcp_edit_tools.go's plan handler
// for how the two are wired to the same run.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// castAuditRecorder implements AuditRecorder by writing a standard
// asciicast v2 stream: a JSON header object, then one `[t, "o", text]`
// event per RecordFrame/action-boundary call. It never alters router
// state or sends keys itself (see edit_audit.go's AuditRecorder
// contract) — it only observes.
type castAuditRecorder struct {
	enc   *json.Encoder
	start time.Time
}

// newCastAuditRecorder writes the asciicast header line immediately
// (a real player/reader expects it first) and returns a recorder ready
// to receive automationDriver's notifications. width/height are cast
// metadata only — the automation path never depends on a real terminal
// size (selectModel/multiSelectModel already fall back to a fixed
// window when no WindowSizeMsg has been sent).
func newCastAuditRecorder(w io.Writer, title string, width, height int) (*castAuditRecorder, error) {
	enc := json.NewEncoder(w)
	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": time.Now().Unix(),
		"title":     title,
	}
	if err := enc.Encode(header); err != nil {
		return nil, fmt.Errorf("write session.cast header: %w", err)
	}
	return &castAuditRecorder{enc: enc, start: time.Now()}, nil
}

func (r *castAuditRecorder) writeEvent(text string) error {
	elapsed := time.Since(r.start).Seconds()
	if err := r.enc.Encode([]any{elapsed, "o", text}); err != nil {
		return fmt.Errorf("write session.cast event: %w", err)
	}
	return nil
}

func (r *castAuditRecorder) RecordActionStart(step editAction) error {
	return r.writeEvent(fmt.Sprintf("\n── %s ──\n", step.Action))
}

// RecordKeys is a no-op here: the keys themselves already land in
// trace.jsonl via automationDriver's existing trace callback: this
// recorder only needs to capture the resulting frames.
func (r *castAuditRecorder) RecordKeys([]string) error { return nil }

func (r *castAuditRecorder) RecordFrame(f FrameEvent) error {
	return r.writeEvent(f.View)
}

func (r *castAuditRecorder) RecordActionResult(step editAction, err error) error {
	if err != nil {
		return r.writeEvent(fmt.Sprintf("✗ %s failed: %v\n", step.Action, err))
	}
	return r.writeEvent(fmt.Sprintf("✓ %s ok\n", step.Action))
}

// auditMetadata is metadata.json's content — see the spec's "Audit
// Artifacts" > metadata.json section.
type auditMetadata struct {
	SessionID         string    `json:"session_id"`
	Kind              string    `json:"kind"`
	PilotVersion      string    `json:"pilot_version"`
	GitRevision       string    `json:"git_revision,omitempty"`
	MCPClient         string    `json:"mcp_client,omitempty"`
	Workspace         string    `json:"workspace"`
	Start             time.Time `json:"start"`
	Finish            time.Time `json:"finish"`
	ScenarioHash      string    `json:"scenario_hash"`
	WorkspaceRevision string    `json:"workspace_revision"`
	Width             int       `json:"width"`
	Height            int       `json:"height"`
	Recorder          string    `json:"recorder"`
}

// auditRefs is the audit-artifact reference block a tool result embeds
// — matches spec's `pilot_edit_plan` output's "audit" object exactly.
type auditRefs struct {
	Directory string `json:"directory"`
	Recording string `json:"recording"`
	Trace     string `json:"trace"`
	Diff      string `json:"diff"`
}

// writePlanAuditArtifacts writes the static (non-streaming) files a
// finished plan run produces: metadata.json, scenario.redacted.json,
// diff.patch, validation.json. trace.jsonl and session.cast are
// already closed by the caller by the time this runs (they're written
// live, during the scenario run itself).
//
// scenario.redacted.json is the scenario exactly as submitted: it
// never carries a resolved secret value (only value_env variable
// *names*), and no vault action can reach this far (MCP policy filters
// them out before a plan is ever attempted) — so no separate
// redaction pass is needed yet. Phase 5 revisits this once vault
// actions exist on this path.
func writePlanAuditArtifacts(dir string, meta auditMetadata, scenario editScenario, result *editPlanResult) error {
	if err := writeJSONFile(filepath.Join(dir, "metadata.json"), meta); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "scenario.redacted.json"), scenario); err != nil {
		return err
	}
	if err := writeTextFile(filepath.Join(dir, "diff.patch"), result.Diff); err != nil {
		return err
	}
	validation := validationSummary{Blocking: result.Blocking, Warnings: result.Warnings}
	if err := writeJSONFile(filepath.Join(dir, "validation.json"), validation); err != nil {
		return err
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	return writeTextFile(path, string(data)+"\n")
}

func writeTextFile(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// gitRevision best-effort resolves dir's current git HEAD — spec's
// metadata.json field is explicitly optional ("若目前位於 Git
// repository"), so any failure (not a repo, git missing, detached
// weirdness) just yields "" rather than an error.
func gitRevision(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
