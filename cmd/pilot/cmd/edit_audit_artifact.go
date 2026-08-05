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
	"crypto/sha256"
	"encoding/hex"
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

// redactScenarioForAudit returns a copy of scenario with Value cleared
// on every step whose Action is a secret action (mcpSecretActionNames) —
// the value_env-only MCP policy (validateNoLiteralSecretValues) already
// guarantees an *accepted* secret step never carries a literal Value,
// so this is belt-and-suspenders: even a future bug in that upstream
// check still can't put a secret into scenario.redacted.json, since
// this runs unconditionally right before every write of that file.
func redactScenarioForAudit(scenario editScenario) editScenario {
	redacted := scenario
	redacted.Steps = make([]editAction, len(scenario.Steps))
	copy(redacted.Steps, scenario.Steps)
	for i, step := range redacted.Steps {
		if mcpSecretActionNames[step.Action] && step.Value != "" {
			step.Value = "«redacted»"
			redacted.Steps[i] = step
		}
	}
	return redacted
}

// writePlanAuditArtifacts writes the static (non-streaming) files a
// finished plan run produces: metadata.json, scenario.redacted.json,
// diff.patch, validation.json. trace.jsonl and session.cast are
// already closed by the caller by the time this runs (they're written
// live, during the scenario run itself).
func writePlanAuditArtifacts(dir string, meta auditMetadata, scenario editScenario, result *editPlanResult) error {
	if err := writeJSONFile(filepath.Join(dir, "metadata.json"), meta); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "scenario.redacted.json"), redactScenarioForAudit(scenario)); err != nil {
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

// managedFileManifestEntry is one row of managed-files-before.json /
// managed-files-after.json — a compact manifest (content hash only,
// not the full content, which is already fully visible in diff.patch).
type managedFileManifestEntry struct {
	RelPath       string `json:"rel_path"`
	Mode          string `json:"mode"`
	IsSymlink     bool   `json:"is_symlink"`
	ContentSHA256 string `json:"content_sha256"`
}

func manifestFor(entries []managedFileEntry) []managedFileManifestEntry {
	out := make([]managedFileManifestEntry, len(entries))
	for i, e := range entries {
		sum := sha256.Sum256(e.Content)
		out[i] = managedFileManifestEntry{
			RelPath:       e.RelPath,
			Mode:          e.Mode.String(),
			IsSymlink:     e.IsSymlink,
			ContentSHA256: hex.EncodeToString(sum[:]),
		}
	}
	return out
}

// resultSummary is result.json's content — apply-specific (a plan
// never rolls back a real mutation, so it has no comparable file).
type resultSummary struct {
	Result           string `json:"result"` // "applied" | "failed"
	FailedStep       *int   `json:"failed_step"`
	RolledBack       bool   `json:"rolled_back"`
	RevisionBefore   string `json:"revision_before"`
	RevisionAfter    string `json:"revision_after"`
	ValidationPassed bool   `json:"validation_passed"`
}

// writeApplyAuditArtifacts writes the full apply audit file set:
// everything writePlanAuditArtifacts writes, plus
// managed-files-before.json/managed-files-after.json and result.json —
// rollback bookkeeping that only matters once something can actually
// roll back. FailedStep is always nil: automationDriver's error
// doesn't currently carry a structured step index outside its wrapped
// error string, though the precise failed step is always visible in
// this same directory's trace.jsonl.
func writeApplyAuditArtifacts(dir string, meta auditMetadata, scenario editScenario, result *editApplyResult) error {
	if err := writeJSONFile(filepath.Join(dir, "metadata.json"), meta); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "scenario.redacted.json"), redactScenarioForAudit(scenario)); err != nil {
		return err
	}
	if err := writeTextFile(filepath.Join(dir, "diff.patch"), result.Diff); err != nil {
		return err
	}
	validation := validationSummary{Blocking: result.Blocking, Warnings: result.Warnings}
	if err := writeJSONFile(filepath.Join(dir, "validation.json"), validation); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "managed-files-before.json"), manifestFor(result.Before)); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "managed-files-after.json"), manifestFor(result.After)); err != nil {
		return err
	}
	resultKind := "applied"
	if result.RolledBack {
		resultKind = "failed"
	}
	summary := resultSummary{
		Result:           resultKind,
		RolledBack:       result.RolledBack,
		RevisionBefore:   result.RevisionBefore,
		RevisionAfter:    result.RevisionAfter,
		ValidationPassed: len(result.Blocking) == 0,
	}
	return writeJSONFile(filepath.Join(dir, "result.json"), summary)
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
