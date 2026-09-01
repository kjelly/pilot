package detection

import "fmt"

// SubjectKindManagedHost is the fixed Kind for every subject discovered
// through the existing Pilot-managed-host identity path (inventory
// hostname). It is the only Kind a repair/autonomy plan may ever act
// on (see internal/repair's fail-closed guard) — every other Kind
// value names an externally monitored, non-managed subject (spec
// docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md
// §9.2/§10.6).
const SubjectKindManagedHost = "managed_host"

// SubjectKey generalizes the Detection Engine's per-subject identity
// beyond the historical `pilot_host`-only shape (spec §9.2). A managed
// Linux host's SubjectKey has ID = inventory hostname, Kind =
// SubjectKindManagedHost; an external monitored target (e.g. an SNMP
// device) has ID = Monitoring Target Registry name, Kind = its
// subjectKind (network_device, ups, pdu, ...). A SubjectKey MUST NOT be
// constructed by aliasing a non-managed ID as SubjectKindManagedHost —
// that is exactly the "core-sw-01 → pilot_host=core-sw-01" shortcut
// spec Appendix B prohibits.
type SubjectKey struct {
	ID   string
	Kind string
	Site string
}

// IsManagedHost reports whether k identifies a Pilot-managed host — the
// only case where legacy `pilot_host`-keyed behavior (persistence
// mirror column, alert label, repair eligibility) applies.
func (k SubjectKey) IsManagedHost() bool {
	return k.Kind == SubjectKindManagedHost
}

// IsValid reports whether k has the minimum fields required to
// identify a subject cycle. An empty ID or Kind can never be
// classified — callers must treat that as invalid_reason
// "missing_identity" (spec §9.4 rule 1), not a zero-value subject.
func (k SubjectKey) IsValid() bool {
	return k.ID != "" && k.Kind != ""
}

// String renders a SubjectKey for logs/errors. It never includes
// anything beyond ID/Kind/Site — a SubjectKey carries no credential or
// free-text field by construction.
func (k SubjectKey) String() string {
	return fmt.Sprintf("%s/%s@%s", k.Kind, k.ID, k.Site)
}
