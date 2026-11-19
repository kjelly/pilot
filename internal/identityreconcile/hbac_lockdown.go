package identityreconcile

// LockdownReport is what the lockdown stage (H8) did: the proofs with hbactest, the disable
// and the rollback. It is filled by the lockdown in the next commit of this phase; until
// then the stage refuses (below), so no run disables allow_all without the proofs.
type LockdownReport struct {
	// Before and After are what the hbactest proofs answered: "granted", "denied" or
	// "error: <why>"; "" when the proof was not run.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	// Disabled: hbacrule_disable allow_all was sent and answered success.
	Disabled bool `json:"disabled"`
	// Rollback is what became of the re-enabling of allow_all: "" when none was needed,
	// "re-enabled" when the rollback succeeded, "FAILED: <why>" when it did not.
	Rollback string `json:"rollback,omitempty"`
	// Detail says what happened, in words.
	Detail string `json:"detail,omitempty"`
}

// runLockdown is H8. It refuses until the proofs are implemented: nothing is sent.
func (r *hbacRunner) runLockdown(idxs []int) {
	for _, i := range idxs {
		r.conflict(i, "the lockdown of allow_all is not implemented in this build")
	}
	r.stopAt(H8, "the lockdown of allow_all is not implemented in this build")
}
