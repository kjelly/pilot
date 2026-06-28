package agent

// Decision is the human's response to a proposal.
type Decision int

const (
	DecisionApproved Decision = iota
	DecisionRejected
	DecisionEdit
	DecisionAbort
	DecisionApprovedAll
)

func (d Decision) String() string {
	switch d {
	case DecisionApproved:
		return "approved"
	case DecisionRejected:
		return "rejected"
	case DecisionEdit:
		return "edit"
	case DecisionAbort:
		return "abort"
	case DecisionApprovedAll:
		return "approved_all"
	}
	return "unknown"
}

// Approver is implemented by the UI layer (terminal, web, etc.) to get
// a human-in-the-loop decision on each proposal.
type Approver interface {
	Ask(p *Proposal) Decision
}
