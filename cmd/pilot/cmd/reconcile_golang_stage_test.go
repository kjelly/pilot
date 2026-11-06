package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The Go engine's stage rules live in two functions that the Ansible engine does not share with
// it: golangPreviewStage decides whether the host may have the stage (the playbook's three
// cross-check asserts), and the entry playbook is told the stage through golangStageVars, which
// is the Ansible engine's own stageDecisionFromFlag. AGENTS.md §5.7: two places that must
// agree need a test that fails when one of them changes. This one takes every combination of
// (--stage, --staging-attested-within-hours, the host's environment group), asks the whole
// chain of the Go engine (the flag validation of the entry, golangPreviewStage, then the entry
// playbook's gates fed with the variables golangStageVars gives it) and the Ansible engine's
// chain (the same flag validation, stageDecisionFromFlag, the apply playbook's gates), and requires
// the same verdict and the same stage and confirm variables.

// playbookStageGates reads the stage gates of a playbook from its source, so that the model below
// cannot drift from what the playbook says: the three cross-check lines and the confirm and
// attestation expressions. It fails the test when the playbook's text is not what the model is of.
func playbookStageGates(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"- not ('prod' in group_names and stage != 'prod')",
		"- not ('staging' in group_names and stage != 'staging')",
		"- not (stage in ['staging', 'prod'] and stage not in group_names)",
		"(stage == 'sandbox') or",
		"(stage == 'staging' and confirm_staging | bool) or",
		"(stage == 'prod' and confirm_prod | bool)",
		"(staging_attested_within_hours | int) <= 168",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("%s no longer holds %q: the model of the stage gates below must be updated with it", path, want)
		}
	}
}

// playbookAccepts is the model of the stage gates of the identity apply playbook and of the
// entry playbook (the same lines in both, checked by playbookStageGates), given the extra
// variables the engine passed and the host's environment groups.
func playbookAccepts(vars map[string]string, envGroup string) bool {
	stage := vars["stage"]
	if stage == "" {
		stage = "sandbox" // the play's default
	}
	confirmed := map[string]bool{"confirm_staging": vars["confirm_staging"] == "true", "confirm_prod": vars["confirm_prod"] == "true"}
	if stage != "sandbox" && !(stage == "staging" && confirmed["confirm_staging"]) && !(stage == "prod" && confirmed["confirm_prod"]) {
		return false
	}
	inGroup := func(g string) bool { return envGroup == g }
	if inGroup("prod") && stage != "prod" || inGroup("staging") && stage != "staging" || (stage == "staging" || stage == "prod") && !inGroup(stage) {
		return false
	}
	if stage == "prod" {
		h, err := strconv.Atoi(strings.TrimSpace(vars["staging_attested_within_hours"]))
		if err != nil || h > 168 {
			return false
		}
	}
	return true
}

func varsOf(kv []string) map[string]string {
	out := map[string]string{}
	for _, s := range kv {
		k, v, _ := strings.Cut(s, "=")
		out[k] = v
	}
	return out
}

func TestGolangStageRulesAgree(t *testing.T) {
	root := filepath.Join("..", "..", "..", "playbooks", "apply")
	playbookStageGates(t, filepath.Join(root, "freeipa-identity-apply.yml"))
	playbookStageGates(t, filepath.Join(root, "freeipa-identity-auth-cache.yml"))

	var checked, accepted int
	for _, stage := range []string{"", "sandbox", "staging", "prod", "production"} {
		for _, hours := range []string{"", "0", "24", "168", "169", "-1", "soon"} {
			for _, env := range []string{"", "staging", "prod"} {
				groups := map[string][]string{}
				if env != "" {
					groups[env] = []string{"ipa-1"}
				}
				// Both engines refuse a bad flag first, with the same function.
				if validateStageFlags(stage, hours) != nil {
					continue
				}
				// The Ansible engine: the stage decision from the flag, and the playbook's gates
				// (the model of the lines playbookStageGates just found in the source).
				d := stageDecisionFromFlag(discardWriter{}, "freeipa-identity", stage, hours)
				ansVars := varsOf(append([]string{"stage=" + d.Stage}, d.ConfirmVars...))
				want := playbookAccepts(ansVars, env)
				// The Go engine's own stage gate, alone: it must accept exactly what the playbook accepts,
				// or the run would be refused where the playbook runs (or the other way round, and the
				// entry's gate would be the only one left).
				goStage, goErr := golangPreviewStage("ipa-1", groups, stage, hours)
				if (goErr == nil) != want {
					t.Errorf("--stage %q, hours %q, host in %q: golangPreviewStage says %v (%v), the playbook's gates say %v", stage, hours, env, goErr == nil, goErr, want)
					continue
				}
				checked++
				if goErr == nil {
					accepted++
					// And the entry is told the same stage and confirmations the Ansible engine's playbook gets.
					goVars := varsOf(golangStageVars(goStage, hours))
					if !slices.Equal(sortedVars(goVars), sortedVars(ansVars)) {
						t.Errorf("--stage %q, hours %q, host in %q: the entry is told %v, the Ansible engine's playbook %v", stage, hours, env, sortedVars(goVars), sortedVars(ansVars))
					}
					if !playbookAccepts(goVars, env) {
						t.Errorf("--stage %q, hours %q, host in %q: the entry's own gates would refuse the variables it was given: %v", stage, hours, env, sortedVars(goVars))
					}
				}
			}
		}
	}
	if checked != 18 || accepted != 6 {
		t.Fatalf("checked %d combinations, accepted %d: the matrix does not reach both verdicts", checked, accepted)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func sortedVars(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// The extra variables of the entry are exactly the stage ones: the gate reads stage and the
// confirm variables and nothing else, and a variable it is handed that it does not read would be
// an input nobody checks.
func TestGolangStageVarsAreOnlyTheStageGatesInputs(t *testing.T) {
	re := regexp.MustCompile(`^(stage|confirm_staging|confirm_prod|staging_attested_within_hours)=`)
	for _, tc := range []struct{ stage, hours string }{{"sandbox", ""}, {"staging", ""}, {"prod", "24"}} {
		for _, v := range golangStageVars(tc.stage, tc.hours) {
			if !re.MatchString(v) {
				t.Errorf("golangStageVars(%s) holds %q", tc.stage, v)
			}
		}
	}
	if got := golangStageVars("prod", " 24 "); !slices.Contains(got, "staging_attested_within_hours=24") {
		t.Errorf("an attestation with blanks around it is not trimmed: %v", got)
	}
}
