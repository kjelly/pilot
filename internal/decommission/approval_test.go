package decommission

import "testing"

// TestApply_RequiresHumanApprovalAllEnvironments proves HD5/INV-4: apply is
// refused when no approval record exists for exactly (plan_id, plan_hash),
// in every environment this repo uses — sandbox, staging, prod — and once
// approved, the same environments proceed. There is no "autonomous" value
// that bypasses the gate.
func TestApply_RequiresHumanApprovalAllEnvironments(t *testing.T) {
	environments := []string{"sandbox", "staging", "prod", "autonomous", ""}

	for _, env := range environments {
		t.Run(env, func(t *testing.T) {
			st := openTestStore(t)
			ds := NewStore(st)

			planID := "hd-" + env + "-plan"
			planHash := "hash-" + env

			if err := RequireApproval(ds, planID, planHash, env); err == nil {
				t.Fatalf("environment %q: RequireApproval succeeded with no approval recorded — expected approval_required", env)
			} else if ClassOf(err) != ErrApprovalRequired {
				t.Fatalf("environment %q: error class = %q, want %q", env, ClassOf(err), ErrApprovalRequired)
			}

			if err := ds.RecordApproval(planID, planHash, "human-operator", "approve", "confirmed", fixedNow()); err != nil {
				t.Fatalf("RecordApproval: %v", err)
			}

			if err := RequireApproval(ds, planID, planHash, env); err != nil {
				t.Fatalf("environment %q: RequireApproval failed after a real human approval was recorded: %v", env, err)
			}
		})
	}
}

// TestApply_ApprovalDoesNotCarryOverToAChangedHash is a companion check
// (HD27's underlying mechanism, reused by HD5's gate): an approval bound
// to one plan_hash never satisfies RequireApproval for a different hash of
// the same plan_id — a stale plan can never borrow a prior approval.
func TestApply_ApprovalDoesNotCarryOverToAChangedHash(t *testing.T) {
	st := openTestStore(t)
	ds := NewStore(st)

	if err := ds.RecordApproval("hd-1", "hash-A", "human-operator", "approve", "", fixedNow()); err != nil {
		t.Fatalf("RecordApproval: %v", err)
	}
	if err := RequireApproval(ds, "hd-1", "hash-A", "prod"); err != nil {
		t.Fatalf("RequireApproval(hash-A) after approving hash-A: %v", err)
	}
	if err := RequireApproval(ds, "hd-1", "hash-B", "prod"); err == nil {
		t.Fatal("RequireApproval(hash-B) succeeded despite the recorded approval being bound to hash-A")
	}
}
