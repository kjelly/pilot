package identityreconcile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDocumentWithHBACIsAMixedRunsDocument(t *testing.T) {
	d := desired(t, validRoster)
	base := NewDocument(d, Observation{}, Plan{Operations: []Operation{}, Blocked: []Blocked{}}, Target{}, Server{}, "rev", time.Unix(0, 0), Stats{})
	raw, _ := json.Marshal(base)
	if strings.Contains(string(raw), `"hbac"`) || base.Scope != ScopeUsersGroups {
		t.Fatalf("the users-groups document carries an hbac part or the wrong scope: %s", raw)
	}
	plan := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: baseObs(), Preview: true})
	full := base.WithHBAC(NewHBACPlanDoc(plan, baseObs(), true))
	if full.Scope != ScopeFull || full.HBAC == nil || !full.HBAC.Preview || full.Result != ResultOK {
		t.Fatalf("scope %q hbac %+v result %q", full.Scope, full.HBAC, full.Result)
	}
	if full.HBAC.Observation.Rules != 2 || full.HBAC.Observation.Domain != lab || len(full.HBAC.Operations) == 0 {
		t.Errorf("the observation summary or the operations are not the plan's: %+v", full.HBAC)
	}
	if base.HBAC != nil || base.Scope != ScopeUsersGroups {
		t.Error("WithHBAC changed the document it was called on")
	}
	if same := base.WithHBAC(nil); same.Scope != ScopeUsersGroups || same.HBAC != nil {
		t.Error("WithHBAC(nil) is not the document itself")
	}

	// A blocked HBAC plan makes the whole document blocked, and only that does.
	blocked := BuildHBAC(HBACInput{Desired: hbacDesired(t, hbacRosterDoc), Obs: func() HBACObservation {
		o := baseObs()
		o.Hostgroups = nil
		return o
	}()})
	if len(blocked.Blocked) == 0 {
		t.Fatal("the plan is not blocked")
	}
	if got := base.WithHBAC(NewHBACPlanDoc(blocked, baseObs(), false)); got.Result != ResultBlocked {
		t.Errorf("a blocked HBAC plan left the result %q", got.Result)
	}
}

func TestDesiredWithoutNotInScopeKeepsTheRest(t *testing.T) {
	d := Desired{NotInScope: []string{"hbac", "sudo"}}
	got := d.WithoutNotInScope("hbac")
	if !slices.Equal(got.NotInScope, []string{"sudo"}) || !slices.Equal(d.NotInScope, []string{"hbac", "sudo"}) {
		t.Fatalf("got %v, original %v", got.NotInScope, d.NotInScope)
	}
	if only := (Desired{NotInScope: []string{"hbac"}}).WithoutNotInScope("hbac"); only.NotInScope != nil {
		t.Errorf("nothing left should be nil: %v", only.NotInScope)
	}
	if d := desired(t, strings.Replace(hbacRosterDoc, "schema_version: 3", "schema_version: 3\nsudo: {rules: []}", 1)); !slices.Contains(d.NotInScope, "hbac") {
		t.Errorf("the roster's hbac section is not reported as outside the users/groups scope: %v", d.NotInScope)
	}
}

func TestApplyDocumentOfAMixedRunCarriesTheHBACStageAndItsObligation(t *testing.T) {
	d := desired(t, validRoster)
	idle := Result{Observed: true}
	hbacRan := func(entry bool) *HBACReport {
		return &HBACReport{Ran: true, Result: &HBACResult{Observed: true, Entry: EntryReport{Ran: entry}}}
	}
	input := func(pb *PlaybookReport, hbac *HBACReport, scope string) ApplyDocumentInput {
		return ApplyDocumentInput{Desired: d, Result: idle, Revision: "rev", Stage: "sandbox", Outcome: "success", Scope: scope, Playbook: pb, HBAC: hbac}
	}
	acked := &PlaybookReport{Ran: true, Observation: &ObservationDoc{Prepared: true, Acked: true, Refreshed: true}}
	notAcked := &PlaybookReport{Ran: true, Observation: &ObservationDoc{Prepared: true}}

	for name, tc := range map[string]struct {
		pb       *PlaybookReport
		hbac     *HBACReport
		wantOwed bool
		wantSrc  string
	}{
		"the second run acknowledged after the stage wrote": {acked, hbacRan(true), false, ""},
		"the stage wrote and nothing acknowledged":          {notAcked, hbacRan(true), true, ObligationThisRun},
		"the stage ran idle and nothing acknowledged":       {notAcked, hbacRan(false), true, ObligationPreviousRun},
		"no stage, nothing acknowledged":                    {notAcked, nil, true, ObligationPreviousRun},
	} {
		t.Run(name, func(t *testing.T) {
			doc := NewApplyDocument(input(tc.pb, tc.hbac, ScopeFull))
			if doc.Authorization.Owed != tc.wantOwed || doc.Authorization.Source != tc.wantSrc || doc.HBAC != tc.hbac {
				t.Fatalf("owed %v source %q hbac %+v", doc.Authorization.Owed, doc.Authorization.Source, doc.HBAC)
			}
		})
	}

	// The users-groups scope never carries an HBAC part, whatever it was handed.
	if doc := NewApplyDocument(input(nil, hbacRan(true), ScopeUsersGroups)); doc.HBAC != nil {
		t.Errorf("a users-groups document has an hbac part: %+v", doc.HBAC)
	}

	// The part is in the file and survives a read of it (no field the reader does not know).
	doc := NewApplyDocument(input(acked, &HBACReport{Ran: true, Skipped: "", Error: "boom", Stats: Stats{Writes: 2},
		Result: &HBACResult{Observed: true, Lockdown: &LockdownReport{Detail: "kept allow_all"}}}, ScopeFull))
	data, err := doc.Render()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseApplyDocument(data)
	if err != nil {
		t.Fatalf("the file is not read back: %v\n%s", err, data)
	}
	if back.HBAC == nil || back.HBAC.Error != "boom" || back.HBAC.Stats.Writes != 2 || back.HBAC.Result == nil || back.HBAC.Result.Lockdown == nil {
		t.Errorf("hbac part after a round trip: %+v", back.HBAC)
	}
	if skipped := NewApplyDocument(input(notAcked, &HBACReport{Skipped: "the first playbook run failed"}, ScopeFull)); skipped.HBAC == nil || skipped.HBAC.Ran || skipped.HBAC.Skipped == "" {
		t.Errorf("a stage that did not run is not reported as skipped: %+v", skipped.HBAC)
	}
}
