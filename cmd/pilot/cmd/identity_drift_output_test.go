package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/accessgrants"
)

func TestIdentityDriftJSONStableAndPartial(t *testing.T) {
	r := accessgrants.DriftReport{Items: []accessgrants.DriftItem{{Category: "user_missing", Name: "z", Action: "create"}, {Category: "group_unexpected", Name: "a", Action: "report"}}}
	a, _ := json.Marshal(identityDriftJSON(r, true))
	r.Items[0], r.Items[1] = r.Items[1], r.Items[0]
	b, _ := json.Marshal(identityDriftJSON(r, true))
	if string(a) != string(b) {
		t.Fatalf("unstable ordering: %s / %s", a, b)
	}
	if !strings.Contains(string(a), `"complete":false`) {
		t.Fatal("partial coverage must be explicit")
	}
	clean, _ := json.Marshal(identityDriftJSON(accessgrants.DriftReport{}, false))
	if !strings.Contains(string(clean), `"items":[]`) {
		t.Fatalf("empty items must be array: %s", clean)
	}
}

func TestIdentityDriftCIStatuses(t *testing.T) {
	for _, tc := range []struct {
		report accessgrants.DriftReport
		code   int
	}{
		{accessgrants.DriftReport{}, 3},
		{accessgrants.DriftReport{Items: []accessgrants.DriftItem{{Category: "user_unexpected", Action: "report"}}}, 3},
		{accessgrants.DriftReport{Items: []accessgrants.DriftItem{{Category: "group_member_extra", Action: "remove_member"}}}, 2},
	} {
		var status ExitCoder
		if !errors.As(identityDriftStatus(tc.report), &status) || status.ExitCode() != tc.code {
			t.Fatalf("want status %d", tc.code)
		}
	}
}

func TestIdentityDriftCLIExitCodeAndIncompleteObservation(t *testing.T) {
	resetDriftCmdState(t)
	fakeDriftAnsible(t)
	ws := newDriftWorkspace(t, "")
	out, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory, "--format", "json", "--exit-code")
	var status ExitCoder
	// This fixture has compiled grants missing live: actionable drift wins.
	if !errors.As(err, &status) || status.ExitCode() != 2 {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if !strings.Contains(out, `"schema_version": 1`) {
		t.Fatalf("no versioned JSON: %s", out)
	}
	out, err = runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory, "--include-users-groups")
	if err == nil || !strings.Contains(err.Error(), "identity object observation is missing") {
		t.Fatalf("missing observation passed: %v %s", err, out)
	}
}
