package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/networkcheck"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	diagnoseEvidenceSchemaVersion = 2
	maxDiagnoseRecordBytes        = 16 << 20
	maxDiagnosePageBytes          = 32 << 10 // base64 plus metadata remains below 64 KiB
)

var diagnoseObservedUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.@\\-]*[$]?$`)

var diagnoseEvidenceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,159}$`)

type diagnoseProvenance struct {
	ServerExecutableSHA256  string    `json:"server_executable_sha256,omitempty"`
	ServerGoVersion         string    `json:"server_go_version,omitempty"`
	ServerModuleVersion     string    `json:"server_module_version,omitempty"`
	WorkspaceTree           string    `json:"workspace_tree,omitempty"`
	WorkspaceModified       bool      `json:"workspace_modified"`
	ServerVersion           string    `json:"server_version"`
	ServerRevision          string    `json:"server_revision,omitempty"`
	ServerRevisionSource    string    `json:"server_revision_source"`
	ServerModified          bool      `json:"server_modified"`
	WorkspaceRevision       string    `json:"workspace_revision,omitempty"`
	InventoryRevision       string    `json:"inventory_revision,omitempty"`
	InventorySHA256         string    `json:"inventory_sha256,omitempty"`
	ResolvedInventorySHA256 string    `json:"resolved_inventory_sha256,omitempty"`
	InventoryCapturedAt     time.Time `json:"inventory_captured_at"`
	ControllerUID           int       `json:"controller_uid"`
}

type diagnoseExecutionIdentity struct {
	Host                  string             `json:"host"`
	ResolvedAddr          string             `json:"resolved_addr"`
	Connection            string             `json:"connection,omitempty"`
	ConfiguredRemoteUser  string             `json:"configured_remote_user,omitempty"`
	ConfiguredBecomeUser  string             `json:"configured_become_user,omitempty"`
	ConfiguredBecome      string             `json:"configured_become,omitempty"`
	ObservedEffectiveUser string             `json:"observed_effective_user,omitempty"`
	Observation           string             `json:"observation"`
	Evidence              *diagnoseStepAudit `json:"evidence,omitempty"`
}

type diagnoseEvidenceContextKey struct{}

// One collector belongs to one invocation. Inventory is captured at resolution,
// before execution, rather than re-read after commands may have changed it.
type diagnoseEvidenceContext struct {
	mu         sync.Mutex
	resolved   networkcheck.ResolvedInventory
	provenance diagnoseProvenance
	steps      []diagnose.StepResult
}

func diagnoseAuditRoot(opts diagnoseMCPToolsOptions) string {
	if opts.AuditDir != "" {
		return opts.AuditDir
	}
	return filepath.Join(diagnoseWorkspaceRoot(opts), ".pilot", "audit", "edit")
}

func captureDiagnoseInventory(ctx context.Context, opts diagnoseMCPToolsOptions, resolved networkcheck.ResolvedInventory) {
	collector, ok := ctx.Value(diagnoseEvidenceContextKey{}).(*diagnoseEvidenceContext)
	if !ok {
		return
	}
	provenance := diagnoseProvenance{
		ServerVersion: rootCmd.Version, ServerRevisionSource: "unavailable",
		WorkspaceRevision: gitRevision(diagnoseWorkspaceRoot(opts)),
		InventoryRevision: gitRevision(filepath.Dir(opts.Inventory)),
		ControllerUID:     os.Geteuid(), InventoryCapturedAt: time.Now().UTC(),
	}
	provenance.ServerExecutableSHA256 = diagnoseServerExecutableSHA256()
	root := diagnoseWorkspaceRoot(opts)
	if output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD^{tree}").Output(); err == nil {
		provenance.WorkspaceTree = strings.TrimSpace(string(output))
	}
	if output, err := exec.Command("git", "-C", root, "status", "--porcelain", "--untracked-files=no").Output(); err == nil {
		provenance.WorkspaceModified = len(output) > 0
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		provenance.ServerGoVersion, provenance.ServerModuleVersion = info.GoVersion, info.Main.Version
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				provenance.ServerRevision, provenance.ServerRevisionSource = setting.Value, "go_build_info"
			case "vcs.modified":
				provenance.ServerModified = setting.Value == "true"
			}
		}
	}
	if data, err := os.ReadFile(opts.Inventory); err == nil {
		provenance.InventorySHA256 = diagnoseSHA256(data)
	}
	if data, err := json.Marshal(resolved); err == nil {
		provenance.ResolvedInventorySHA256 = diagnoseSHA256(data)
	}
	collector.mu.Lock()
	collector.resolved, collector.provenance = resolved, provenance
	collector.mu.Unlock()
}

var diagnoseExecutableHash struct {
	once  sync.Once
	value string
}

func diagnoseServerExecutableSHA256() string {
	diagnoseExecutableHash.once.Do(func() {
		// The executable pathname may already name a replacement while this
		// long-lived server still runs the original inode.
		file, err := os.Open("/proc/self/exe")
		if err != nil {
			return
		}
		defer file.Close()
		digest := sha256.New()
		if _, err := io.Copy(digest, file); err == nil {
			diagnoseExecutableHash.value = hex.EncodeToString(digest.Sum(nil))
		}
	})
	return diagnoseExecutableHash.value
}

func diagnoseSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// withDiagnoseEvidence wraps the factory's handler, so direct Go calls and MCP
// calls persist exactly the same sanitized final diagnosis. Preliminary records
// remain explicitly incomplete if execution or final publication is interrupted.
func withDiagnoseEvidence[In, Out any](opts diagnoseMCPToolsOptions, check string, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		collector := &diagnoseEvidenceContext{}
		ctx = context.WithValue(ctx, diagnoseEvidenceContextKey{}, collector)
		ctx = diagnose.WithStepObserver(ctx, func(results []diagnose.StepResult) {
			collector.mu.Lock()
			collector.steps = append(collector.steps, results...)
			collector.mu.Unlock()
		})
		started := time.Now().UTC()
		result, out, err := handler(ctx, req, in)

		handlerErr := err
		failed := err != nil || (result != nil && result.IsError)
		collector.mu.Lock()
		executed := len(collector.steps) > 0
		collector.mu.Unlock()
		if failed && !executed {
			return result, out, err
		}

		safe, sanitizeErr := sanitizeDiagnoseOutput(out)
		if sanitizeErr != nil {
			return nil, out, sanitizeErr
		}
		out = safe
		data, marshalErr := json.Marshal(out)
		if marshalErr != nil {
			return nil, out, marshalErr
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, out, err
		}

		var toolFailure mcpToolError
		if failed {
			toolFailure = diagnoseErrorForEvidence(result, handlerErr)
			fields["tool_error"], _ = json.Marshal(toolFailure)
		}
		var auditDir string
		_ = json.Unmarshal(fields["audit_directory"], &auditDir)
		var rec diagnoseAuditRecord
		if auditDir != "" {
			var readErr error
			rec, _, readErr = readDiagnoseArtifact(auditDir)
			if readErr != nil {
				out = withDiagnoseAuditFields(out, auditStatusFor(fmt.Errorf("read preliminary evidence: %w", readErr)))
				return result, out, nil
			}
		} else {
			// File/history diagnostics do not execute ad-hoc commands, but their
			// structured conclusion still requires durable, retrievable evidence.
			id, idErr := newID()
			if idErr != nil {
				return result, withDiagnoseAuditFields(out, auditStatusFor(idErr)), nil
			}
			auditDir, err = prepareDiagnoseAuditDir(opts, strings.ToLower(check), id, started)
			if err != nil {
				return result, withDiagnoseAuditFields(out, auditStatusFor(err)), nil
			}
			rec = diagnoseAuditRecord{SessionID: id, Check: strings.ToLower(check), PilotVersion: rootCmd.Version, Inventory: opts.Inventory, Start: started, Finish: time.Now().UTC(), MCPClient: mcpClientString(req)}
			_ = json.Unmarshal(fields["host"], &rec.Host)
		}
		collector.mu.Lock()
		resolved, provenance := collector.resolved, collector.provenance
		rec.Steps = stepAuditList(collector.steps)
		collector.mu.Unlock()
		rec.SchemaVersion, rec.EvidenceID = diagnoseEvidenceSchemaVersion, filepath.Base(auditDir)
		rec.Provenance, rec.GitRevision = provenance, provenance.WorkspaceRevision
		rec.Finalized = true
		rec.EvidenceCompleteness, rec.IncompleteReasons = "complete", nil
		rec.EvidenceReferences = nil
		for i := range rec.Steps {
			step := &rec.Steps[i]
			step.EvidenceRef = fmt.Sprintf("%s#steps/%d", rec.EvidenceID, i)
			step.ResolvedAddr = resolved.HostAddr(step.Host)
			rec.EvidenceReferences = append(rec.EvidenceReferences, step.EvidenceRef)
			rec.Redacted, rec.Truncated = rec.Redacted || step.Redacted, rec.Truncated || step.Truncated
			if step.Host == "" || step.StartedAt.IsZero() || step.FinishedAt.IsZero() {
				incompleteDiagnose(&rec, "step_execution_provenance_missing")
			}
			if step.Outcome == "unknown" || step.Outcome == "unreachable" || step.Outcome == "auth_required" {
				incompleteDiagnose(&rec, "step_evidence_unavailable")
			}
			if step.Truncated {
				incompleteDiagnose(&rec, "step_output_truncated")
			}
		}
		rec.Identities = collectDiagnoseIdentities(ctx, opts, resolved, rec.Steps)
		for i := range rec.Identities {
			identity := &rec.Identities[i]
			if identity.Observation != "observed" {
				incompleteDiagnose(&rec, "execution_identity_unknown")
			}
			if identity.Evidence != nil {
				rec.Redacted, rec.Truncated = rec.Redacted || identity.Evidence.Redacted, rec.Truncated || identity.Evidence.Truncated
				if identity.Evidence.Truncated {
					incompleteDiagnose(&rec, "identity_evidence_truncated")
				}
				identity.Evidence.EvidenceRef = fmt.Sprintf("%s#identities/%d/evidence", rec.EvidenceID, i)
				rec.EvidenceReferences = append(rec.EvidenceReferences, identity.Evidence.EvidenceRef)
			}
		}
		if provenance.InventorySHA256 == "" || provenance.ResolvedInventorySHA256 == "" {
			incompleteDiagnose(&rec, "inventory_provenance_missing")
		}
		if value := diagnoseJSONText(fields["verdict"]); value != "" {
			rec.Verdict = value
		} else if value := diagnoseJSONText(fields["status"]); value != "" {
			rec.Verdict = value
		} else if value := diagnoseJSONText(fields["outcome"]); value != "" {
			rec.Verdict = value
		} else {
			rec.Verdict = "observations_recorded"
		}

		if failed {
			rec.Verdict = "tool_error"
			incompleteDiagnose(&rec, "diagnosis_failed_after_execution")
		}
		if diagnosticJSONIncomplete(fields) {
			incompleteDiagnose(&rec, "diagnosis_reported_missing_evidence")
		}
		var truncated bool
		_ = json.Unmarshal(fields["truncated"], &truncated)
		if truncated {
			rec.Truncated = true
			incompleteDiagnose(&rec, "diagnosis_truncated")
		}
		var redacted bool
		_ = json.Unmarshal(fields["redacted"], &redacted)
		rec.Redacted = rec.Redacted || redacted
		// Remove storage bookkeeping from the replayable diagnosis. It is
		// separately represented in the record and returned response metadata.
		for _, key := range []string{"audit_status", "audit_error", "audit_directory", "evidence_id", "evidence_completeness", "evidence_references"} {
			delete(fields, key)
		}

		if rec.Truncated {
			incompleteDiagnose(&rec, "evidence_truncated")
		}
		fields["redacted"], _ = json.Marshal(rec.Redacted)
		fields["truncated"], _ = json.Marshal(rec.Truncated)
		rec.Diagnosis, err = json.Marshal(fields)
		if err != nil {
			return nil, out, err
		}
		rec.Finish = time.Now().UTC()
		status := auditStatusFor(writeDiagnoseAudit(auditDir, rec))
		status.EvidenceID, status.EvidenceCompleteness, status.EvidenceReferences = rec.EvidenceID, rec.EvidenceCompleteness, rec.EvidenceReferences
		status.Redacted, status.Truncated = rec.Redacted, rec.Truncated

		out = withDiagnoseAuditFields(out, status)
		if failed {
			toolFailure.EvidenceID, toolFailure.AuditStatus, toolFailure.EvidenceCompleteness = status.EvidenceID, status.AuditStatus, status.EvidenceCompleteness
			toolFailure.AuditError = status.AuditError
			return toolErrorResult(toolFailure), out, nil
		}
		return result, out, nil
	}
}

func diagnoseErrorForEvidence(result *mcp.CallToolResult, err error) mcpToolError {
	failure := mcpToolError{Code: mcpErrInternal, Message: "diagnosis failed after target execution"}
	if err != nil {
		failure.Message = err.Error()
	}
	if result != nil {
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				if json.Unmarshal([]byte(text.Text), &failure) != nil {
					failure.Message = text.Text
				}
				break
			}
		}
	}
	return failure
}

func withDiagnoseAuditFields[Out any](out Out, status diagnoseAuditStatus) Out {
	data, err := json.Marshal(out)
	if err != nil {
		return out
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return out
	}

	var wasRedacted, wasTruncated bool
	_ = json.Unmarshal(fields["redacted"], &wasRedacted)
	_ = json.Unmarshal(fields["truncated"], &wasTruncated)
	fields["redacted"], _ = json.Marshal(wasRedacted || status.Redacted)
	fields["truncated"], _ = json.Marshal(wasTruncated || status.Truncated)
	for key, value := range map[string]any{"audit_status": status.AuditStatus, "audit_error": status.AuditError, "evidence_id": status.EvidenceID, "evidence_completeness": status.EvidenceCompleteness, "evidence_references": status.EvidenceReferences} {
		fields[key], _ = json.Marshal(value)
	}
	data, err = json.Marshal(fields)
	if err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func incompleteDiagnose(rec *diagnoseAuditRecord, reason string) {
	rec.EvidenceCompleteness = "incomplete"
	for _, existing := range rec.IncompleteReasons {
		if existing == reason {
			return
		}
	}
	rec.IncompleteReasons = append(rec.IncompleteReasons, reason)
}

func diagnoseJSONText(data json.RawMessage) string {
	var value string
	_ = json.Unmarshal(data, &value)
	return value
}

func diagnosticJSONIncomplete(fields map[string]json.RawMessage) bool {
	for key, value := range fields {
		switch {
		case key == "error" || strings.HasSuffix(key, "_note"):
			if diagnoseJSONText(value) != "" {
				return true
			}
		case key == "http_status":
			var status int
			_ = json.Unmarshal(value, &status)
			if status >= 400 {
				return true
			}
		case key == "warnings":
			var warnings []json.RawMessage
			_ = json.Unmarshal(value, &warnings)
			if len(warnings) > 0 {
				return true
			}
		case key == "verdict" || key == "outcome" || key == "status" || key == "state":
			switch diagnoseJSONText(value) {
			case "unknown", "insufficient_evidence", "unreachable", "auth_required", "workspace_incomplete", "incomplete", "not_configured", "not_observed":
				return true
			}
		}

		if len(value) > 0 && value[0] == '[' {
			var items []json.RawMessage
			if json.Unmarshal(value, &items) == nil {
				for _, item := range items {
					if diagnosticJSONIncomplete(map[string]json.RawMessage{"item": item}) {
						return true
					}
				}
			}
		}
		if len(value) > 0 && value[0] == '{' {
			var nested map[string]json.RawMessage
			if json.Unmarshal(value, &nested) == nil && diagnosticJSONIncomplete(nested) {
				return true
			}
		}
	}
	return false
}

func collectDiagnoseIdentities(ctx context.Context, opts diagnoseMCPToolsOptions, resolved networkcheck.ResolvedInventory, steps []diagnoseStepAudit) []diagnoseExecutionIdentity {
	hosts := map[string]bool{}
	for _, step := range steps {
		if step.Host != "" {
			hosts[step.Host] = true
		}
	}
	ordered := make([]string, 0, len(hosts))
	for host := range hosts {
		ordered = append(ordered, host)
	}
	sort.Strings(ordered)
	var identities []diagnoseExecutionIdentity
	for _, host := range ordered {
		identity := diagnoseExecutionIdentity{Host: host, ResolvedAddr: resolved.HostAddr(host), Observation: "unknown"}
		identity.ConfiguredRemoteUser, _ = resolved.HostVar(host, "ansible_user")
		identity.ConfiguredBecomeUser, _ = resolved.HostVar(host, "ansible_become_user")
		identity.Connection, _ = resolved.HostVar(host, "ansible_connection")
		if value, ok := resolved.HostVars[host]["ansible_become"]; ok {
			identity.ConfiguredBecome = fmt.Sprint(value)
		}
		// DNS architecture already probes id -un using the same execution
		// context. Reuse this observed evidence rather than add another call.
		for _, step := range steps {
			if step.Host != host {
				continue
			}
			section, ok := diagnose.ParseDNSArchSections(step.Stdout)["whoami"]
			if ok && section.Complete && section.RC == 0 && validObservedDiagnoseUser(strings.TrimSpace(section.Output)) {
				identity.ObservedEffectiveUser, identity.Observation = strings.TrimSpace(section.Output), "observed"
				copy := step
				identity.Evidence = &copy
				break
			}
		}
		if identity.Observation != "observed" {
			runner := opts.IdentityRunner
			if runner == nil && opts.AdHocRunner == nil {
				runner = realDiagnoseAdHocRunner()
			}
			if runner != nil {
				probeCtx := withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
				results := diagnose.RunSteps(probeCtx, runner, opts.Inventory, host, []diagnose.Step{{ID: "execution_identity", Description: "observe the effective user under the same Ansible inventory privilege settings", Module: "command", Command: "id -un"}}, minDiagnoseTimeout(opts.StepTimeout, 5*time.Second))
				ev := stepAuditList(results)[0]
				ev.ResolvedAddr = identity.ResolvedAddr
				identity.Evidence = &ev
				if ev.OK && validObservedDiagnoseUser(strings.TrimSpace(ev.Stdout)) {
					identity.ObservedEffectiveUser, identity.Observation = strings.TrimSpace(ev.Stdout), "observed"
				}
			}
		}
		identities = append(identities, identity)
	}
	return identities
}

func validObservedDiagnoseUser(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	return diagnoseObservedUserPattern.MatchString(value)
}

// Audit records are evidence artifacts, not mutable target state. Publish an
// entire private document atomically; never expose partially written JSON.
func publishDiagnoseArtifact(dir string, rec diagnoseAuditRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxDiagnoseRecordBytes {
		return fmt.Errorf("diagnose evidence exceeds %d-byte storage bound", maxDiagnoseRecordBytes)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if existing, _, readErr := readDiagnoseArtifact(dir); readErr == nil && existing.Finalized {
		return errors.New("diagnose evidence is already finalized")
	}
	id, err := newID()
	if err != nil {
		return err
	}
	name := ".record-" + id + ".tmp"
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(name) }()
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.Rename(name, "record.json")
}

func readDiagnoseArtifact(dir string) (diagnoseAuditRecord, []byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return diagnoseAuditRecord{}, nil, err
	}
	defer func() { _ = root.Close() }()
	return readDiagnoseArtifactRoot(root)
}

func readDiagnoseArtifactRoot(root *os.Root) (diagnoseAuditRecord, []byte, error) {
	file, err := root.OpenFile("record.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return diagnoseAuditRecord{}, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return diagnoseAuditRecord{}, nil, err
	}
	if !info.Mode().IsRegular() {
		return diagnoseAuditRecord{}, nil, errors.New("diagnose evidence is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDiagnoseRecordBytes+1))
	if err != nil {
		return diagnoseAuditRecord{}, nil, err
	}
	if len(data) > maxDiagnoseRecordBytes {
		return diagnoseAuditRecord{}, nil, errors.New("diagnose evidence exceeds storage bound")
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, nil, err
	}
	if rec.SchemaVersion != diagnoseEvidenceSchemaVersion {
		return rec, nil, fmt.Errorf("unsupported diagnose evidence schema %d", rec.SchemaVersion)
	}
	safe, err := sanitizeDiagnoseOutput(rec)
	if err != nil {
		return rec, nil, err
	}
	canonical, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		return rec, nil, err
	}
	canonical = append(canonical, '\n')
	// Generated artifacts have exactly this canonical representation. Comparing
	// every byte also rejects unknown fields and duplicate JSON keys whose
	// original values would otherwise be lost by typed/generic decoding.
	if !bytes.Equal(data, canonical) {
		return rec, nil, errors.New("stored evidence violates canonical sanitization policy")
	}
	return safe, data, nil

}

type diagnoseEvidenceGetInput struct {
	EvidenceID string `json:"evidence_id" jsonschema:"opaque evidence_id returned by a diagnose tool; never a filesystem path"`
	Offset     int    `json:"offset,omitempty" jsonschema:"byte offset from the previous response next_offset; starts at zero"`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum decoded bytes for this page; default and maximum 32768"`
	SHA256     string `json:"sha256,omitempty" jsonschema:"record sha256 from the previous page; rejects a changed preliminary record"`
}

type diagnoseEvidenceGetOutput struct {
	EvidenceID           string `json:"evidence_id"`
	SchemaVersion        int    `json:"schema_version"`
	Finalized            bool   `json:"finalized"`
	EvidenceCompleteness string `json:"evidence_completeness"`
	SHA256               string `json:"sha256"`
	Offset               int    `json:"offset"`
	NextOffset           int    `json:"next_offset"`
	TotalBytes           int    `json:"total_bytes"`
	EOF                  bool   `json:"eof"`
	Encoding             string `json:"encoding"`
	Data                 string `json:"data"`
}

func registerDiagnoseEvidenceTool(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{Name: "pilot_diagnose_evidence_get", Description: "read-only bounded retrieval of sanitized persisted diagnosis evidence by opaque evidence_id; concatenate base64-decoded pages in offset order to reconstruct the complete JSON record, carrying sha256 on later pages; no host commands or filesystem writes"}, diagnoseEvidenceGetHandler(opts))
}

func diagnoseEvidenceGetHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseEvidenceGetInput, diagnoseEvidenceGetOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in diagnoseEvidenceGetInput) (*mcp.CallToolResult, diagnoseEvidenceGetOutput, error) {
		fail := func(err error) (*mcp.CallToolResult, diagnoseEvidenceGetOutput, error) {
			return toolErrorResult(mcpToolError{Code: mcpErrInvalidParam, Message: err.Error()}), diagnoseEvidenceGetOutput{}, nil
		}
		if !diagnoseEvidenceIDPattern.MatchString(in.EvidenceID) {
			return fail(errors.New("invalid evidence_id"))
		}
		if in.Offset < 0 || in.Limit < 0 || in.Limit > maxDiagnosePageBytes {
			return fail(errors.New("invalid evidence page bounds"))
		}
		limit := in.Limit
		if limit == 0 {
			limit = maxDiagnosePageBytes
		}
		parent, err := os.OpenFile(filepath.Join(diagnoseAuditRoot(opts), "diagnose"), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fail(errors.New("evidence store is unavailable"))
		}
		defer parent.Close()
		// openat with O_NOFOLLOW binds the child directory to this parent inode
		// even if another process replaces the path between lookup and open.
		fd, err := syscall.Openat(int(parent.Fd()), in.EvidenceID, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fail(errors.New("evidence_id not found or unsafe"))
		}
		dirFile := os.NewFile(uintptr(fd), in.EvidenceID)
		defer dirFile.Close()
		root, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil {
			return fail(errors.New("cannot open evidence directory"))
		}
		defer func() { _ = root.Close() }()
		rec, data, err := readDiagnoseArtifactRoot(root)
		if err != nil {
			return fail(fmt.Errorf("read evidence: %w", err))
		}
		if rec.EvidenceID != in.EvidenceID {
			return fail(errors.New("evidence identity mismatch"))
		}
		digest := diagnoseSHA256(data)
		if in.SHA256 != "" && in.SHA256 != digest {
			return fail(errors.New("evidence changed; restart pagination at offset zero"))
		}
		if in.Offset > len(data) {
			return fail(errors.New("evidence offset exceeds record length"))
		}
		end := min(len(data), in.Offset+limit)
		return nil, diagnoseEvidenceGetOutput{EvidenceID: rec.EvidenceID, SchemaVersion: rec.SchemaVersion, Finalized: rec.Finalized, EvidenceCompleteness: rec.EvidenceCompleteness, SHA256: digest, Offset: in.Offset, NextOffset: end, TotalBytes: len(data), EOF: end == len(data), Encoding: "base64", Data: base64.StdEncoding.EncodeToString(data[in.Offset:end])}, nil
	}
}
