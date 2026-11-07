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

// ObligationDoc is what the run found of the authorization cache obligation. In the
// users-groups scope no playbook ran to settle it, so it is owed whenever the entry ran or
// the probe found it so; in the mixed scope it is owed unless the identity playbook's
// observation says it acknowledged it. It is the identity.auth_cache event, in the file.
type ObligationDoc struct {
	Owed   bool   `json:"owed"`
	Source string `json:"source,omitempty"`
	// EntryRan: the entry's prepare ran and its result was accepted.
	EntryRan bool `json:"entry_ran"`
	// ProbePending is what the probe of an idle run found (absent when it did not run).
	ProbePending *bool `json:"probe_pending,omitempty"`
	// ObservedAcked: the identity playbook's observation of the run said it acknowledged
	// the obligation. Always false in the users-groups scope, which runs no playbook that
	// settles and acknowledges (spec §6.2).
	ObservedAcked bool `json:"observed_acked"`
}

// ObservationDoc is the identity playbook's own account of a mixed run's authorization cache
// work (the "observe" result file, spec §5.5), as the run accepted it.
type ObservationDoc struct {
	Prepared  bool  `json:"prepared"`
	Dirty     *bool `json:"dirty"`
	Refreshed bool  `json:"refreshed"`
	Acked     bool  `json:"acked"`
}

// PlaybookReport is what the identity playbook did in a mixed run, after the Go writer.
type PlaybookReport struct {
	// Ran: the playbook was started. A run the Go phase ended before that (a blocked plan, a failed
	// write, a verification that did not pass) never starts it (spec §7.6).
	Ran bool `json:"ran"`
	// Observation is what its observe task wrote, when the file was accepted.
	Observation *ObservationDoc `json:"observation,omitempty"`
	// ObservationError says why no observation was accepted, for a playbook that ran: an empty
	// file (no host matched, a skipped task, a tag selection without the settle) reads as
	// "not settled", never as "nothing owed".
	ObservationError string `json:"observation_error,omitempty"`
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
	// Playbook is the mixed scope's account of the identity playbook; absent in users-groups.
	Playbook *PlaybookReport `json:"playbook,omitempty"`
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
	// Scope is ScopeFull for a mixed run; empty is ScopeUsersGroups.
	Scope string
	// Playbook is the mixed run's account of the identity playbook (nil for users-groups).
	Playbook *PlaybookReport
}

// fullObligation is the authorization cache obligation after a mixed run: the identity
// playbook settles it (its own settle, its refresh of the enrolled clients and its
// acknowledgement), so it is owed unless the observation of the run says it acknowledged
// (spec §6.2): no observation, an unacknowledged one and a playbook that never ran all leave
// it owed, from this run when the entry ran in it.
func fullObligation(res Result, pb *PlaybookReport) Obligation {
	if pb != nil && pb.Observation != nil && pb.Observation.Acked {
		return Obligation{}
	}
	if res.Entry.Ran {
		return Obligation{Owed: true, Source: ObligationThisRun}
	}
	if pb != nil && pb.Ran {
		return Obligation{Owed: true, Source: ObligationPreviousRun}
	}
	// The Go phase stopped the run before the playbook and before any entry: nothing this run did
	// put the obligation there, and none was read.
	return Obligation{}
}

// NewApplyDocument builds the result file of a run that was observed (Result.Observed).
func NewApplyDocument(in ApplyDocumentInput) ApplyDocument {
	ob := in.Result.Obligation()
	scope := ScopeUsersGroups
	if in.Scope == ScopeFull {
		scope = ScopeFull
		ob = fullObligation(in.Result, in.Playbook)
	}
	doc := ApplyDocument{
		Schema:          ApplyDocumentSchema,
		Engine:          Engine{Name: EngineName, PilotRevision: in.Revision},
		Scope:           scope,
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
		Playbook: in.Playbook,
		Result:   in.Result,
		Stats:    in.Stats,
	}
	if in.Playbook != nil && in.Playbook.Observation != nil {
		doc.Authorization.ObservedAcked = in.Playbook.Observation.Acked
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
