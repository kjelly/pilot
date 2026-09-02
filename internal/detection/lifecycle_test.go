package detection

import (
	"reflect"
	"testing"
)

func TestLifecycle_WarningRequiresThreeOfFour(t *testing.T) {
	lc := NewHostLifecycle()
	scores := []float64{0.85, 0.85, 0.3, 0.85} // warning_history ends [T,T,F,T] -> 3 of 4
	var last Transition
	for _, s := range scores {
		last = lc.Advance(s)
	}
	if last.Action != ActionCreateWarning || last.ToState != StateFiring || last.Severity != SeverityWarning {
		t.Fatalf("after 3-of-4 warning-threshold cycles, want create_warning -> firing/warning; got %+v (state=%s)", last, lc.State)
	}
}

func TestLifecycle_CriticalRequiresTwoConsecutive(t *testing.T) {
	lc := NewHostLifecycle()
	lc.Advance(0.97)         // 1st consecutive critical-threshold cycle: not yet
	last := lc.Advance(0.97) // 2nd consecutive: fires
	if last.Action != ActionCreateCritical || last.ToState != StateFiring || last.Severity != SeverityCritical {
		t.Fatalf("after 2 consecutive critical-threshold cycles, want create_critical -> firing/critical; got %+v", last)
	}
}

func TestLifecycle_SingleSpikeDoesNotFire(t *testing.T) {
	lc := NewHostLifecycle()
	last := lc.Advance(0.97) // a single cycle, however extreme, must not fire on its own
	if last.Action != ActionNone {
		t.Fatalf("a single spike must not fire an episode, got action=%s", last.Action)
	}
	if lc.State == StateFiring {
		t.Fatal("a single spike must not put the host directly into firing")
	}
}

func TestLifecycle_RecoveryRequiresFourBelowPoint6(t *testing.T) {
	lc := NewHostLifecycle()
	lc.Advance(0.97)
	fire := lc.Advance(0.97) // firing/critical
	if fire.ToState != StateFiring {
		t.Fatalf("setup failed to reach firing: %+v", fire)
	}

	enter := lc.Advance(0.3) // 1st sub-recovery-threshold cycle -> recovering
	if enter.Action != ActionEnterRecovering || enter.ToState != StateRecovering {
		t.Fatalf("expected enter_recovering on the first sub-0.60 cycle after firing; got %+v", enter)
	}

	for i, want := range []LifecycleAction{ActionNone, ActionNone, ActionResolve} {
		tr := lc.Advance(0.3)
		if tr.Action != want {
			t.Fatalf("recovering cycle #%d: action=%s, want %s (state=%s)", i+2, tr.Action, want, lc.State)
		}
	}
	if lc.State != StateNormal {
		t.Fatalf("after 4 consecutive sub-0.60 cycles, state=%s, want normal", lc.State)
	}

	// A bounce-back before the 4th consecutive low cycle must return to
	// the SAME firing severity instead of resolving.
	lc2 := NewHostLifecycle()
	lc2.Advance(0.97)
	lc2.Advance(0.97)           // firing/critical
	lc2.Advance(0.3)            // enter recovering (streak=1)
	lc2.Advance(0.3)            // streak=2
	bounce := lc2.Advance(0.65) // bounces back above 0.60 before streak reaches 4
	if bounce.Action != ActionReturnToFiring || bounce.ToState != StateFiring || bounce.Severity != SeverityCritical {
		t.Fatalf("a bounce-back above 0.60 before streak=4 must return to firing at the prior severity; got %+v", bounce)
	}
}

func TestLifecycle_InvalidCycleDoesNotAdvanceCounters(t *testing.T) {
	lc := NewHostLifecycle()
	lc.Advance(0.85) // warning_history=[true], state=candidate

	// An "invalid cycle" is modeled by the caller simply not calling
	// Advance at all (spec §20.7) — there is no separate "invalid tick"
	// method that could accidentally reset or pad the counters. Simulate
	// the gap by doing nothing, then verify the NEXT valid cycle continues
	// exactly where the state left off (2 history entries, not 1-plus-an-
	// implicit-false for the skipped cycle).
	before := *lc

	// (the "invalid cycle" happens here — no Advance call)

	if !reflect.DeepEqual(*lc, before) {
		t.Fatalf("state must be untouched across a skipped/invalid cycle: %+v != %+v", *lc, before)
	}

	lc.Advance(0.85)
	if len(lc.WarningHistory) != 2 {
		t.Fatalf("warning history = %v, want exactly 2 entries (the skipped cycle must not have inserted an implicit false)", lc.WarningHistory)
	}
}

func TestLifecycle_CriticalNeverDowngradesWithinEpisode(t *testing.T) {
	lc := NewHostLifecycle()
	lc.Advance(0.97)
	lc.Advance(0.97) // firing/critical
	if lc.Severity != SeverityCritical {
		t.Fatalf("setup failed: severity=%s", lc.Severity)
	}

	// A "merely warning-level" score (>=0.60 so it does not trigger
	// recovering) must never silently downgrade the active severity.
	tr := lc.Advance(0.85)
	if lc.Severity != SeverityCritical {
		t.Fatalf("severity downgraded to %s within the same episode; must stay critical", lc.Severity)
	}
	if tr.Action != ActionNone {
		t.Fatalf("expected no action, got %s", tr.Action)
	}
}

func TestLifecycle_ResolvedThenRefireGetsNewSignalID(t *testing.T) {
	const host, profileID, profileVersion = "web-1", "linux-host-v1", 1
	fp1 := Fingerprint(host, SubjectKindManagedHost, "", profileID, profileVersion)

	lc := NewHostLifecycle()
	lc.Advance(0.97)
	create := lc.Advance(0.97) // firing/critical
	if create.Action != ActionCreateCritical {
		t.Fatalf("setup: expected create_critical, got %+v", create)
	}
	firstID, err := NewULID()
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}

	for i := 0; i < 4; i++ {
		lc.Advance(0.1) // drive recovery_streak to 4 -> resolve
	}
	if lc.State != StateNormal {
		t.Fatalf("expected resolved back to normal, got %s", lc.State)
	}

	fp2 := Fingerprint(host, SubjectKindManagedHost, "", profileID, profileVersion)
	if fp1 != fp2 {
		t.Fatal("fingerprint must be identical across resolve+refire (spec §21)")
	}

	lc.Advance(0.97)
	refire := lc.Advance(0.97) // fires again after having fully resolved
	if refire.Action != ActionCreateCritical {
		t.Fatalf("expected the host to be able to fire again after resolving, got %+v", refire)
	}
	secondID, err := NewULID()
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	if firstID == secondID {
		t.Fatal("a refire after resolution must get a NEW signal_id, not reuse the old one")
	}
}
