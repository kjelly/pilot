package decommission

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestStore_NoSecretValuesInPersistedRecords proves HD26: no persisted
// decommission record ever contains a secret-shaped value verbatim. The
// Phase 1 Plan model carries no raw secret VALUE field at all — this
// asserts the structural guard that would catch one anyway: encoding
// refuses (fail-closed) the moment a persisted field/key name matches a
// secret/vault-like pattern, and Store.SavePlan propagates that refusal
// rather than silently writing the row.
func TestStore_NoSecretValuesInPersistedRecords(t *testing.T) {
	secretPlan := &Plan{
		ID:     "hd-secret-1",
		Status: PlanStatusBlocked,
		Host: HostSnapshot{
			Name: "h1",
			Extra: map[string]string{
				"ipa_admin_password": "hunter2-should-never-be-persisted",
			},
		},
		PlanHash:  "deadbeef",
		CreatedAt: time.Now().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano),
	}

	if _, err := EncodePlanJSON(secretPlan); !errors.Is(err, ErrSecretLikeField) {
		t.Fatalf("EncodePlanJSON() error = %v, want ErrSecretLikeField", err)
	}

	db := openTestStore(t)
	s := NewStore(db)
	if err := s.SavePlan(secretPlan); !errors.Is(err, ErrSecretLikeField) {
		t.Fatalf("SavePlan() error = %v, want ErrSecretLikeField (must refuse to persist, not silently drop the field)", err)
	}
	if _, err := s.LoadPlan(secretPlan.ID); err == nil {
		t.Fatal("LoadPlan() succeeded for a plan SavePlan() refused to persist — the row must not exist")
	}

	// A clean plan (no secret-shaped keys) encodes and round-trips fine,
	// and the persisted JSON blob genuinely contains no secret-looking
	// substring either — a second, independent check beyond the key-name
	// guard above.
	cleanPlan := &Plan{
		ID:        "hd-clean-1",
		Status:    PlanStatusBlocked,
		Host:      HostSnapshot{Name: "h2", Extra: map[string]string{"deployment_ring": "canary"}},
		PlanHash:  "cafef00d",
		CreatedAt: time.Now().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano),
	}
	if err := s.SavePlan(cleanPlan); err != nil {
		t.Fatalf("SavePlan() on a clean plan error = %v, want nil", err)
	}
	rec, err := db.GetDecommissionPlan(cleanPlan.ID)
	if err != nil {
		t.Fatalf("GetDecommissionPlan() error = %v", err)
	}
	lower := strings.ToLower(rec.PlanJSON)
	for _, needle := range []string{"password", "secret", "vault", "credential", "hunter2"} {
		if strings.Contains(lower, needle) {
			t.Fatalf("persisted plan_json for a clean plan unexpectedly contains %q: %s", needle, rec.PlanJSON)
		}
	}

	loaded, err := s.LoadPlan(cleanPlan.ID)
	if err != nil {
		t.Fatalf("LoadPlan() error = %v", err)
	}
	if loaded.Host.Name != "h2" {
		t.Fatalf("loaded.Host.Name = %q, want h2", loaded.Host.Name)
	}
}

// TestApproval_BoundToExactPlanHash proves HD27: plan/apply approval is
// bound to the exact plan_hash — a changed plan hash invalidates any
// prior approval, even for the same plan_id.
func TestApproval_BoundToExactPlanHash(t *testing.T) {
	s := NewStore(openTestStore(t))
	now := time.Now()

	if err := s.RecordApproval("plan-1", "hash-A", "alice", "approve", "looks safe", now); err != nil {
		t.Fatalf("RecordApproval() error = %v", err)
	}

	ok, err := s.ApprovedForHash("plan-1", "hash-A")
	if err != nil {
		t.Fatalf("ApprovedForHash() error = %v", err)
	}
	if !ok {
		t.Fatal("ApprovedForHash(plan-1, hash-A) = false, want true (an approval was just recorded for exactly this hash)")
	}

	// The plan changed (e.g. hosts.yml mutated) -> a new hash. The old
	// approval must NOT carry over.
	ok, err = s.ApprovedForHash("plan-1", "hash-B")
	if err != nil {
		t.Fatalf("ApprovedForHash() error = %v", err)
	}
	if ok {
		t.Fatal("ApprovedForHash(plan-1, hash-B) = true, want false — an approval bound to hash-A must not apply to a changed plan hash-B")
	}

	// A never-approved plan/hash pair reports false, not an error.
	ok, err = s.ApprovedForHash("plan-2", "hash-anything")
	if err != nil {
		t.Fatalf("ApprovedForHash() error = %v", err)
	}
	if ok {
		t.Fatal("ApprovedForHash(plan-2, hash-anything) = true, want false — no approval was ever recorded for plan-2")
	}

	// Re-approving under the NEW hash restores approved status only for
	// that hash.
	if err := s.RecordApproval("plan-1", "hash-B", "alice", "approve", "re-reviewed after plan changed", now.Add(time.Minute)); err != nil {
		t.Fatalf("RecordApproval() error = %v", err)
	}
	ok, err = s.ApprovedForHash("plan-1", "hash-B")
	if err != nil {
		t.Fatalf("ApprovedForHash() error = %v", err)
	}
	if !ok {
		t.Fatal("ApprovedForHash(plan-1, hash-B) = false after a fresh approval, want true")
	}
	// The original hash-A approval is untouched history — it still
	// legitimately reports approved for EXACTLY hash-A (an approval row
	// is never deleted/revoked by a later plan revision); what matters,
	// and what is asserted above, is that it never leaked to hash-B.
	ok, err = s.ApprovedForHash("plan-1", "hash-A")
	if err != nil {
		t.Fatalf("ApprovedForHash() error = %v", err)
	}
	if !ok {
		t.Fatal("ApprovedForHash(plan-1, hash-A) = false, want true — that historical approval record still exists and still matches exactly hash-A")
	}
}
