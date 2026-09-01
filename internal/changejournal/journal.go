// Package changejournal answers "what changed shortly before this
// incident?" (Agent Monitoring Phase 2 §6/§7) by correlating pilot's
// EXISTING durable mutation records — it deliberately does not introduce
// a second, competing store.
//
// pilot already has one unified, queryable, append-only journal for
// deploy/reconcile outcomes: internal/store's DeliveryRun/ListRuns
// (SQLite, one row per pilot deploy run). QueryDeployChanges adapts that
// directly. MCP edit-apply mutations (cmd/pilot/cmd/mcp_edit_tools.go)
// have no equivalent queryable index yet — only a per-invocation
// metadata.json on disk — so QueryEditApplyChanges reads exactly those
// existing files rather than duplicating pilot_edit_apply's own write
// path with a second persistence mechanism.
//
// There is currently no remediation/repair mutation boundary at all
// (Phase 3+ is not implemented) — ChangeKindRemediate exists in the enum
// for forward compatibility, but no query function produces it yet, and
// none should be added until Phase 3's own executor actually exists.
package changejournal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ChangeKind is the fixed enum of mutation boundaries this journal can
// report on (Agent Monitoring Phase 2 §7's ChangeRecord.Kind).
type ChangeKind string

const (
	ChangeKindEditApply ChangeKind = "edit_apply"
	ChangeKindDeploy    ChangeKind = "deploy"
	ChangeKindReconcile ChangeKind = "reconcile"
	ChangeKindRemediate ChangeKind = "remediate"
)

// ChangeRecord is one durable mutation event, normalized from whichever
// underlying store actually recorded it. Never carries a vault value,
// password, token, private key, or secret env content — see each Query*
// function's own doc comment for why its particular source can't leak
// one.
type ChangeRecord struct {
	ID                string
	Kind              ChangeKind
	StartedAt         time.Time
	FinishedAt        time.Time
	Actor             string
	WorkspaceRevision string
	InventoryRef      string
	Hosts             []string
	Components        []string
	Result            string
	ChangedCount      int
	AuditRef          string
}

// TimeWindow bounds a query — both ends inclusive. A ChangeRecord is
// included when its StartedAt falls within [Start, End].
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

func (w TimeWindow) contains(t time.Time) bool {
	return !t.Before(w.Start) && !t.After(w.End)
}

// sortByStartedAtDesc is shared by every Query* function so a caller
// combining multiple sources gets one consistent, canonical ordering
// (Phase 2 §7: "canonical sorted host/component lists" extends naturally
// to canonical record ordering too).
func sortByStartedAtDesc(records []ChangeRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].StartedAt.After(records[j].StartedAt)
	})
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// editApplyAuditMetadata mirrors cmd/pilot/cmd/edit_audit_artifact.go's
// unexported auditMetadata — duplicated here (not imported) because
// cmd/pilot/cmd cannot be imported from internal/ without an import
// cycle (cmd/pilot/cmd is what will call INTO this package). Only the
// fields this package actually reads are declared; Go's JSON decoder
// ignores every other key already present in a real metadata.json.
type editApplyAuditMetadata struct {
	SessionID         string    `json:"session_id"`
	Kind              string    `json:"kind"`
	Workspace         string    `json:"workspace"`
	Start             time.Time `json:"start"`
	Finish            time.Time `json:"finish"`
	WorkspaceRevision string    `json:"workspace_revision"`
}

// QueryEditApplyChanges scans auditDir (opts.AuditDir, the SAME
// directory pilot_edit_apply already writes
// "<timestamp>-<sessionID>-apply/metadata.json" into) for apply-kind
// sessions started within window. metadata.json never contains a
// secret — cmd/pilot/cmd/edit_audit_artifact.go's auditMetadata has no
// such field — so there is nothing to redact here.
func QueryEditApplyChanges(auditDir string, window TimeWindow) ([]ChangeRecord, error) {
	entries, err := os.ReadDir(auditDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var out []ChangeRecord
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(auditDir, entry.Name(), "metadata.json")
		data, readErr := os.ReadFile(metaPath)
		if readErr != nil {
			continue // not every audit subdirectory is an edit-apply session
		}
		var meta editApplyAuditMetadata
		if jsonErr := json.Unmarshal(data, &meta); jsonErr != nil {
			continue
		}
		if meta.Kind != "apply" {
			continue
		}
		if !window.contains(meta.Start) {
			continue
		}
		out = append(out, ChangeRecord{
			ID:                meta.SessionID,
			Kind:              ChangeKindEditApply,
			StartedAt:         meta.Start,
			FinishedAt:        meta.Finish,
			WorkspaceRevision: meta.WorkspaceRevision,
			Result:            "applied",
			AuditRef:          filepath.Join(auditDir, entry.Name()),
		})
	}
	sortByStartedAtDesc(out)
	return out, nil
}

// DeployRunSource is the read-only subset of *internal/store.Store this
// package needs — an interface (not the concrete type) so tests can
// supply a fake without a real SQLite file, and so this package never
// gains a compile-time dependency on internal/store's full surface.
type DeployRunSource interface {
	ListRuns(filter DeployRunFilter) ([]DeployRun, error)
}

// DeployRunFilter/DeployRun mirror internal/store's RunFilter/DeliveryRun
// shape exactly (field-for-field) so cmd/pilot/cmd's adapter is a
// trivial 1:1 struct conversion, not a translation layer with its own
// bugs to have.
type DeployRunFilter struct {
	Limit     int
	Host      string
	Component string
}

type DeployRun struct {
	RunID      string
	StartedAt  string // RFC3339, matching internal/store's own on-disk format
	FinishedAt string
	Outcome    string
	Component  string
	Components []string
	Inventory  string
	Hosts      []string
}

// QueryDeployChanges adapts internal/store's existing DeliveryRun rows
// into ChangeRecord — pilot's already-durable, already-queryable
// deploy/reconcile journal (Agent Monitoring Phase 2 §7's "unified one"
// that already exists for this mutation boundary). No secret ever
// reaches a DeliveryRun row (internal/store's own redaction pipeline is
// upstream of this), so there is nothing to redact here either.
func QueryDeployChanges(source DeployRunSource, host, component string, window TimeWindow, limit int) ([]ChangeRecord, error) {
	runs, err := source.ListRuns(DeployRunFilter{Limit: limit, Host: host, Component: component})
	if err != nil {
		return nil, err
	}
	var out []ChangeRecord
	for _, r := range runs {
		started, perr := time.Parse(time.RFC3339, r.StartedAt)
		if perr != nil {
			continue
		}
		if !window.contains(started) {
			continue
		}
		finished, _ := time.Parse(time.RFC3339, r.FinishedAt)
		components := r.Components
		if len(components) == 0 && r.Component != "" {
			components = []string{r.Component}
		}
		out = append(out, ChangeRecord{
			ID:           r.RunID,
			Kind:         ChangeKindDeploy,
			StartedAt:    started,
			FinishedAt:   finished,
			InventoryRef: r.Inventory,
			Hosts:        sortedUnique(r.Hosts),
			Components:   sortedUnique(components),
			Result:       r.Outcome,
			AuditRef:     r.RunID,
		})
	}
	sortByStartedAtDesc(out)
	return out, nil
}
