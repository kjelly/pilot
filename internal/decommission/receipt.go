package decommission

// Receipt is the durable completion record for a finished decommission
// (spec.md §26). No finalizer writes one yet in Phase 1 (that's Phase 2's
// job) — this type exists now because `pilot host decommission show`'s
// output shape (for an eventually-completed plan) is modeled on it, and
// Phase 2's finalizer/store code should not need to invent a new shape
// later. Never carries a secret value (spec.md §31.10) — every field here
// is either an identifier, a timestamp, or a small closed-vocabulary
// status string.
type Receipt struct {
	DecommissionID string
	Host           string
	FQDN           string
	Environment    string
	Reason         string

	StartedAt   string // RFC3339Nano
	CompletedAt string // RFC3339Nano

	PlanHash                 string
	InitialInventoryRevision string
	FinalInventoryRevision   string

	Components     []string
	CompletedSteps []string

	RetentionDisposition map[string]RetentionDisposition
	OfflineDisposition   OfflineDisposition

	Verified                  bool
	HistoricalRecordsRetained bool

	Warnings []string
}
