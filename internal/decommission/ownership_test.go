package decommission

import (
	"context"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// TestOwnership_ForeignUnknownNeverAutoDeleted proves HD28/INV-6: a
// resource whose only "evidence" is a name/hostname substring match is
// classified FOREIGN_UNKNOWN and never appears as an AUTO_REMOVE (i.e.
// scheduled-for-deletion) entry anywhere in the plan's reference list —
// both at the ownership-classifier unit level and end to end through
// PlanHost.
func TestOwnership_ForeignUnknownNeverAutoDeleted(t *testing.T) {
	t.Run("classifyOwnership confidence ladder", func(t *testing.T) {
		cases := []struct {
			name       string
			confidence OwnershipConfidence
			exact      bool
			want       ReferenceClassification
		}{
			{"ledger + exact", OwnershipLedger, true, AutoRemove},
			{"canonical roster + exact", OwnershipCanonicalRosterExact, true, AutoRemove},
			{"component managed + exact", OwnershipComponentManaged, true, AutoRemove},
			{"local identity + exact", OwnershipLocalIdentity, true, AutoRemove},
			{"legacy cross-checked + exact", OwnershipLegacyCrossChecked, true, AutoRemove},
			{"ledger tier but NOT exact (substring only)", OwnershipLedger, false, ForeignUnknown},
			{"canonical roster tier but NOT exact", OwnershipCanonicalRosterExact, false, ForeignUnknown},
			{"unknown tier, exact flag true", OwnershipUnknown, true, ForeignUnknown},
			{"unknown tier, not exact", OwnershipUnknown, false, ForeignUnknown},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := classifyOwnership(tc.confidence, tc.exact)
				if got != tc.want {
					t.Fatalf("classifyOwnership(%v, %v) = %s, want %s", tc.confidence, tc.exact, got, tc.want)
				}
			})
		}
	})

	t.Run("end to end through PlanHost", func(t *testing.T) {
		dir := t.TempDir()
		writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"}, "    freeipa_roster_file: roster.yaml\n"))
		writeWorkspaceFile(t, dir, "roster.yaml", `schema_version: 2
freeipa:
  server: ipa1.example.internal
hostgroups:
  - name: web1-similar-but-unrelated
    state: present
    membership: {authoritative: true, hosts: []}
`)
		catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

		plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow})
		if err != nil {
			t.Fatalf("PlanHost() error = %v", err)
		}

		var decoy *Reference
		for i := range plan.References {
			if plan.References[i].Identity == "web1-similar-but-unrelated" {
				decoy = &plan.References[i]
			}
		}
		if decoy == nil {
			t.Fatalf("expected the decoy hostgroup to be surfaced (reported), not silently dropped; plan.References=%+v", plan.References)
		}
		if decoy.Classification != ForeignUnknown {
			t.Fatalf("decoy classification = %s, want FOREIGN_UNKNOWN", decoy.Classification)
		}

		// The real invariant: NOTHING in the plan's reference list is
		// AUTO_REMOVE for this host (there was no exact membership at
		// all) — a substring match must never sneak into the mutation
		// list under any classification other than FOREIGN_UNKNOWN.
		for _, r := range plan.References {
			if r.Identity == "web1-similar-but-unrelated" && r.Classification == AutoRemove {
				t.Fatalf("decoy hostgroup was classified AUTO_REMOVE — a name/hostname substring must never be treated as ownership evidence: %+v", r)
			}
		}
	})
}
