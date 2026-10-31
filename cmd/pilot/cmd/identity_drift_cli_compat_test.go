package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/accessgrants"
)

func sameSet(a, b []string) bool {
	a, b = append([]string{}, a...), append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

// rosterWithoutGrants is the access fixture minus everything that compiles to
// rules or policies, so a probe that finds nothing live leaves no drift.
func rosterWithoutGrants(t *testing.T) string {
	t.Helper()
	cut := strings.Index(accessCLIFixtureRoster, "grants:")
	if cut < 0 {
		t.Fatal("the fixture roster no longer has a grants section")
	}
	return accessCLIFixtureRoster[:cut]
}

// TestIdentityDriftRepairManagedKeepsItsOutputContract: --repair-managed prints
// the apply run's own stdout, as it does on main and as 'pilot access drift
// --repair-managed' still does, and still combines with --format json. Only the
// new, opt-in flags are refused together with a repair.
func TestIdentityDriftRepairManagedKeepsItsOutputContract(t *testing.T) {
	const applyLine = "RECONCILE-APPLY-STDOUT-LINE changed=3"
	for _, c := range []struct {
		name string
		args []string
	}{
		{"identity drift", []string{"identity", "drift"}},
		{"access drift", []string{"access", "drift"}},
	} {
		t.Run(c.name+"/prints the apply output", func(t *testing.T) {
			resetDriftCmdState(t)
			fakeDriftAnsible(t)
			stdout := filepath.Join(t.TempDir(), "apply.stdout")
			if err := os.WriteFile(stdout, []byte(applyLine+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FAKE_ANSIBLE_STDOUT_FILE", stdout)
			ws := newDriftWorkspace(t, "")
			out, err := runDriftCmd(t, append(c.args, ws.roster, "-i", ws.inventory, "--repair-managed")...)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !strings.Contains(out, applyLine) {
				t.Errorf("the apply output was dropped:\n%s", out)
			}
			if strings.Contains(out, "apply exit code") {
				t.Errorf("the raw apply output was replaced by a summary:\n%s", out)
			}
		})
	}

	t.Run("identity drift --repair-managed --format json is still accepted", func(t *testing.T) {
		resetDriftCmdState(t)
		fakeDriftAnsible(t)
		ws := newDriftWorkspace(t, "")
		out, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory, "--repair-managed", "--format", "json")
		if err != nil {
			t.Fatalf("--repair-managed --format json was refused (it works on main): %v\n%s", err, out)
		}
		if !strings.HasPrefix(out, "{") || !strings.Contains(out, `"schema_version"`) {
			t.Errorf("the drift report is not printed as JSON first:\n%s", out)
		}
	})

	// The new flags are what a repair run must not be mistaken for.
	for _, flag := range []string{"--include-users-groups", "--exit-code"} {
		t.Run("identity drift --repair-managed "+flag+" is refused before any probe", func(t *testing.T) {
			resetDriftCmdState(t)
			argv := fakeDriftAnsible(t)
			ws := newDriftWorkspace(t, "")
			out, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory, "--repair-managed", flag)
			if err == nil || !strings.Contains(err.Error(), "--repair-managed cannot be combined with") {
				t.Fatalf("err = %v\n%s", err, out)
			}
			if _, statErr := os.Stat(argv); statErr == nil {
				t.Error("ansible-playbook ran although the flags are refused")
			}
		})
	}
}

// TestIdentityDriftJSONEnvelopeIsPinnedWithTheFlagOff pins the version 1
// envelope every 'identity drift --format json' user now gets (it replaced
// {"Items": [...]}): the stable key set, the explicit coverage lists, and
// items as [] rather than null, with --include-users-groups off and on.
func TestIdentityDriftJSONEnvelopeIsPinnedWithTheFlagOff(t *testing.T) {
	run := func(t *testing.T, extra ...string) (string, map[string]any) {
		t.Helper()
		resetDriftCmdState(t)
		fakeDriftAnsible(t)
		ws := newDriftWorkspace(t, "")
		if err := os.WriteFile(ws.roster, []byte(rosterWithoutGrants(t)), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runDriftCmd(t, append([]string{"identity", "drift", ws.roster, "-i", ws.inventory, "--format", "json"}, extra...)...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		return out, doc
	}
	strs := func(v any) []string {
		var out []string
		for _, e := range v.([]any) {
			out = append(out, e.(string))
		}
		return out
	}

	out, doc := run(t)
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	if want := []string{"complete", "covered", "items", "schema_version", "uncovered"}; !sameSet(keys, want) {
		t.Fatalf("envelope keys = %v, want %v\n%s", keys, want, out)
	}
	if _, old := doc["Items"]; old {
		t.Error("the pre-envelope shape {\"Items\": ...} is back")
	}
	if doc["schema_version"] != float64(1) || doc["complete"] != false {
		t.Errorf("schema_version=%v complete=%v, want 1 and false\n%s", doc["schema_version"], doc["complete"], out)
	}
	wantCovered := []string{"account_expiration", "auth_indicator", "compiled_rule_existence", "password_policy", "static_hbac_absence", "user_auth_type"}
	if got := strs(doc["covered"]); !reflect.DeepEqual(got, wantCovered) {
		t.Errorf("covered = %v, want %v", got, wantCovered)
	}
	wantUncovered := []string{"hbac_sudo_attachments", "hosts_hostgroups_netgroups", "password_actions", "users_groups"}
	if got := strs(doc["uncovered"]); !reflect.DeepEqual(got, wantUncovered) {
		t.Errorf("uncovered = %v, want %v (users_groups is not inspected without the flag)", got, wantUncovered)
	}
	if items, ok := doc["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("items = %#v, want an empty array\n%s", doc["items"], out)
	}
	if !strings.Contains(out, `"items": []`) {
		t.Errorf("an empty report must print items as [], not null:\n%s", out)
	}

	// With the flag the line moves from uncovered to covered. The probe answer
	// here has no observation, so this only needs the envelope: use the
	// renderer the command uses.
	on := identityDriftJSON(accessgrants.DriftReport{}, true)
	if !containsString(on.Covered, "users_groups") || containsString(on.Uncovered, "users_groups") {
		t.Errorf("with the flag: covered=%v uncovered=%v", on.Covered, on.Uncovered)
	}
	if on.Complete {
		t.Error("coverage is partial; complete must stay false")
	}
}

// TestIdentityDriftTableStatesItsCoverage pins the two text lines this change
// added to the default (table) output.
func TestIdentityDriftTableStatesItsCoverage(t *testing.T) {
	resetDriftCmdState(t)
	fakeDriftAnsible(t)
	ws := newDriftWorkspace(t, "")
	if err := os.WriteFile(ws.roster, []byte(rosterWithoutGrants(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"partial coverage; not inspected: [hbac_sudo_attachments hosts_hostgroups_netgroups password_actions users_groups]",
		"no drift found within inspected scope",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// TestIdentityDriftExitCodeNeedsTheFlag: without --exit-code the command returns
// nil on drift, exactly as before; with it, drift is a coded error.
func TestIdentityDriftExitCodeNeedsTheFlag(t *testing.T) {
	resetDriftCmdState(t)
	fakeDriftAnsible(t)
	ws := newDriftWorkspace(t, "")
	if out, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory); err != nil {
		t.Fatalf("plain drift with findings must still succeed: %v\n%s", err, out)
	}
	resetDriftCmdState(t)
	_, err := runDriftCmd(t, "identity", "drift", ws.roster, "-i", ws.inventory, "--exit-code")
	var coded ExitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != 2 {
		t.Fatalf("--exit-code with actionable drift: err = %v", err)
	}
}

// TestIdentityDriftExitCodeHelpSaysZeroIsNotReachable: what the help promises
// must be what the command does. While coverage is partial (complete is always
// false) a clean run returns 3, never 0 (identity_drift_objects_cli_test.go
// pins the behaviour); the flag help and the long help must not offer 0 as a
// state a CI job can reach.
func TestIdentityDriftExitCodeHelpSaysZeroIsNotReachable(t *testing.T) {
	flag := identityDriftCmd.Flags().Lookup("exit-code")
	if flag == nil {
		t.Fatal("--exit-code is not registered")
	}
	if !strings.Contains(flag.Usage, "not reachable yet") || !strings.Contains(flag.Usage, "a clean run returns 3") {
		t.Errorf("--exit-code usage promises an exit status 0 it cannot give: %q", flag.Usage)
	}
	if strings.Contains(flag.Usage, "0 fully clean") {
		t.Errorf("--exit-code usage still says %q", "0 fully clean")
	}
	if !strings.Contains(identityDriftCmd.Long, "not reachable yet") || !strings.Contains(identityDriftCmd.Long, "even a clean run returns 3") {
		t.Errorf("the long help does not say a clean run returns 3:\n%s", identityDriftCmd.Long)
	}
}
