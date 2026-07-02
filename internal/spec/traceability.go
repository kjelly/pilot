package spec

import (
	"fmt"
)

// Checkpoint is the persisted (spec_id, run_id, task_index, row_id)
// mapping. The store layer uses this to answer:
//
//	"Which task in run X satisfied requirement C2.5.1?"
//	"Have all rows of spec docs/verification/bastion.md been applied?"
//
// Checkpoints are written when a spec is compiled into a playbook,
// and again when each generated proposal is reviewed/applied, so the
// audit trail captures the full lifecycle.
type Checkpoint struct {
	SpecPath     string // source spec path (relative to repo root)
	RowID        string // e.g. "C2.5.1"
	RunID        string // pilot run UUID
	ProposalID   string // corresponding proposal (set on apply)
	TaskIndex    int    // index into the generated playbook.Tasks slice
	Module       string // e.g. "ansible.builtin.lineinfile"
	ParamHash    string // sha256(module + params); mirrors Generator dedup key
	Status       string // "compiled" | "applied" | "verified-pass" | "verified-fail"
	VerifiedAt   string // RFC3339 timestamp set on verify completion
	VerifyDetail string // human-readable NDJSON `detail` for the latest run
}

// Coverage is a roll-up of all checkpoints for a spec.
type Coverage struct {
	SpecPath     string
	Total        int
	Compiled     int
	Applied      int
	Verified     int
	VerifiedPass int
	VerifiedFail int
}

// Coverage computes the roll-up from a slice of Checkpoints for a
// single spec. It is a pure function so the CLI can recompute it
// after every run without storing aggregates.
func CoverageFor(specPath string, cps []Checkpoint) Coverage {
	c := Coverage{SpecPath: specPath, Total: len(cps)}
	for _, cp := range cps {
		switch cp.Status {
		case "compiled":
			c.Compiled++
		case "applied":
			c.Applied++
		case "verified-pass":
			c.Verified++
			c.VerifiedPass++
		case "verified-fail":
			c.Verified++
			c.VerifiedFail++
		}
	}
	return c
}

// CoveragePercent returns the verified-pass fraction in 0..100.
// Returns 0 when no rows have been verified yet.
func (c Coverage) CoveragePercent() float64 {
	if c.Verified == 0 {
		return 0
	}
	return 100 * float64(c.VerifiedPass) / float64(c.Verified)
}

// String renders a one-line summary suitable for `pilot spec --status`.
func (c Coverage) String() string {
	return fmt.Sprintf("spec=%s total=%d compiled=%d applied=%d verified=%d (pass=%d fail=%d) coverage=%.1f%%",
		c.SpecPath, c.Total, c.Compiled, c.Applied, c.Verified, c.VerifiedPass, c.VerifiedFail, c.CoveragePercent())
}
