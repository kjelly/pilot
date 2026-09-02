package decommission

// OwnershipConfidence is the ownership-evidence confidence ladder from
// spec.md §5.6, highest first:
//
//  1. existing Pilot ownership ledger
//  2. exact canonical roster declaration + deterministic resource identity
//  3. exact component-managed state written by a Pilot playbook
//  4. exact local identity that proves the central object
//  5. legacy discovery that is unique and independently cross-checked
//
// Anything below OwnershipLegacyCrossChecked, or any non-exact match
// (a name/hostname substring alone), is FOREIGN_UNKNOWN and must never be
// scheduled for auto-deletion (INV-6).
type OwnershipConfidence int

const (
	OwnershipUnknown OwnershipConfidence = iota
	OwnershipLegacyCrossChecked
	OwnershipLocalIdentity
	OwnershipComponentManaged
	OwnershipCanonicalRosterExact
	OwnershipLedger
)

// classifyOwnership turns a confidence tier plus "was this an exact
// structural identity match" flag into a Reference classification. exact
// must be true only for a deterministic identity match (e.g. an exact
// entry in a membership.hosts[] list) — never for a name/description
// substring match, which always yields ForeignUnknown regardless of tier
// (spec.md §5.6: "a name similarity or hostname substring alone is NOT
// ownership evidence").
func classifyOwnership(confidence OwnershipConfidence, exact bool) ReferenceClassification {
	if !exact || confidence == OwnershipUnknown {
		return ForeignUnknown
	}
	return AutoRemove
}
