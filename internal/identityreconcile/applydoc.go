package identityreconcile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ApplyDocumentSchema names the result file of a users-groups --force run (spec §8.6, D30).
const ApplyDocumentSchema = "pilot.identity-apply/v1"

// The verdicts of an apply, for the operator and the file: how the run ended in one word.
const (
	// VerdictOK: every operation was applied and verified and nothing is owed: the run
	// with exit code 0, which for this scope is one that wrote nothing and whose probe
	// found the obligation settled.
	VerdictOK = "ok"
	// VerdictUnsettled: every operation was applied and verified; the authorization cache
	// obligation is owed (exit code 4).
	VerdictUnsettled = "unsettled"
	// VerdictBlocked: the plan has blocked objects; nothing was written (exit code 3).
	VerdictBlocked = "blocked"
	// VerdictPartial: some of the run's work was committed (or may have been) and it did
	// not finish or verify (partial_failed, exit code 1).
	VerdictPartial = "partial"
	// VerdictFailed: nothing was written, or nothing that changed anything (exit code 1).
	VerdictFailed = "failed"
)

// ObligationDoc is what the run found of the authorization cache obligation: no
// playbook ran to settle it, so it is owed whenever the entry ran or the probe found
// it so. It is the identity.auth_cache event, in the file.
type ObligationDoc struct {
	Owed   bool   `json:"owed"`
	Source string `json:"source,omitempty"`
	// EntryRan: the entry's prepare ran and its result was accepted.
	EntryRan bool `json:"entry_ran"`
	// ProbePending is what the probe of an idle run found (absent when it did not run).
	ProbePending *bool `json:"probe_pending,omitempty"`
	// ObservedAcked is always false for this scope: it runs no playbook that settles
	// and acknowledges (spec §6.2).
	ObservedAcked bool `json:"observed_acked"`
}

// ApplyDocument is the result file: the plans, what became of each operation, the
// verification, the obligation and the transaction's outcome. It holds no password,
// cookie, vault content or SSH key body (I6): the operations carry names and the fields
// they change, as the plan does.
type ApplyDocument struct {
	Schema          string        `json:"schema"`
	Engine          Engine        `json:"engine"`
	Scope           string        `json:"scope"`
	Stage           string        `json:"stage"`
	RunID           string        `json:"run_id,omitempty"`
	Verdict         string        `json:"verdict"`
	Outcome         string        `json:"outcome"`
	FailedStep      string        `json:"failed_step,omitempty"`
	ExitCode        int           `json:"exit_code"`
	Error           string        `json:"error,omitempty"`
	Target          Target        `json:"target"`
	Server          Server        `json:"server"`
	DesiredRevision string        `json:"desired_revision"`
	Authorization   ObligationDoc `json:"authorization_cache"`
	Result
	Stats Stats `json:"stats"`
}

// maxApplyErrorBytes bounds the error text kept in the file.
const maxApplyErrorBytes = 4000

// ApplyDocumentInput is what NewApplyDocument takes.
type ApplyDocumentInput struct {
	Desired    Desired
	Result     Result
	Target     Target
	Server     Server
	Revision   string
	Stage      string
	RunID      string
	Outcome    string
	FailedStep string
	ExitCode   int
	Err        error
	Stats      Stats
}

// NewApplyDocument builds the result file of a run that was observed (Result.Observed).
func NewApplyDocument(in ApplyDocumentInput) ApplyDocument {
	ob := in.Result.Obligation()
	doc := ApplyDocument{
		Schema:          ApplyDocumentSchema,
		Engine:          Engine{Name: EngineName, PilotRevision: in.Revision},
		Scope:           ScopeUsersGroups,
		Stage:           in.Stage,
		RunID:           in.RunID,
		Outcome:         in.Outcome,
		FailedStep:      in.FailedStep,
		ExitCode:        in.ExitCode,
		Target:          in.Target,
		Server:          in.Server,
		DesiredRevision: fingerprint(in.Desired),
		Authorization: ObligationDoc{
			Owed: ob.Owed, Source: ob.Source, EntryRan: in.Result.Entry.Ran, ProbePending: in.Result.Entry.Pending,
		},
		Result: in.Result,
		Stats:  in.Stats,
	}
	if in.Err != nil {
		doc.Error = in.Err.Error()
		if len(doc.Error) > maxApplyErrorBytes {
			doc.Error = doc.Error[:maxApplyErrorBytes] + "…"
		}
	}
	switch {
	case in.Err == nil && !ob.Owed:
		doc.Verdict = VerdictOK
	case in.Err == nil || errors.Is(in.Err, ErrUnsettled):
		doc.Verdict = VerdictUnsettled
	case errors.Is(in.Err, ErrBlocked):
		doc.Verdict = VerdictBlocked
	case in.Outcome == "partial_failed":
		doc.Verdict = VerdictPartial
	default:
		doc.Verdict = VerdictFailed
	}
	return doc
}

// Render is the file's bytes: indented JSON and a newline.
func (d ApplyDocument) Render() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseApplyDocument reads a result file: exactly this schema, no field it does not know.
func ParseApplyDocument(data []byte) (ApplyDocument, error) {
	var d ApplyDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return ApplyDocument{}, fmt.Errorf("parse the apply result: %w", err)
	}
	if dec.More() {
		return ApplyDocument{}, errors.New("parse the apply result: data after the document")
	}
	if d.Schema != ApplyDocumentSchema {
		return ApplyDocument{}, fmt.Errorf("parse the apply result: schema %q, want %q", d.Schema, ApplyDocumentSchema)
	}
	return d, nil
}
