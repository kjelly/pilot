package diagnose

import "testing"

func TestSudoSteps_TemplatesUserIntoIDAndSudoL(t *testing.T) {
	steps := SudoSteps("alice")
	byID := map[string]Step{}
	for _, s := range steps {
		byID[s.ID] = s
		if s.Module == "shell" {
			t.Fatalf("step %s uses module %q, want \"command\" — no step here needs shell interpretation", s.ID, s.Module)
		}
	}
	if byID["C5"].Command != "id alice" {
		t.Fatalf("C5 command = %q, want \"id alice\"", byID["C5"].Command)
	}
	if byID["C8"].Command != "sudo -l -U alice" {
		t.Fatalf("C8 command = %q, want \"sudo -l -U alice\"", byID["C8"].Command)
	}
}

func stepResult(id string, rc int, stdout string) StepResult {
	return StepResult{Step: Step{ID: id}, Result: AdHocResult{RC: rc, Stdout: stdout}}
}

func TestBuildSudoOutput_VerdictBranches(t *testing.T) {
	allGood := []StepResult{
		stepResult("C2", 0, "active"),
		stepResult("C4", 0, "host/web1@REALM"),
		stepResult("C5", 0, "uid=1000(alice)"),
		stepResult("C6", 0, ""),
		stepResult("C7", 0, ""),
		stepResult("C8", 0, "(root) NOPASSWD: ALL"),
	}

	cases := []struct {
		name        string
		mutate      func([]StepResult) []StepResult
		wantAllGood bool // true if every boolean field should be true
		checkField  func(SudoOutput) bool
	}{
		{
			name:       "sssd down",
			mutate:     func(rs []StepResult) []StepResult { rs[0] = stepResult("C2", 3, "inactive"); return rs },
			checkField: func(o SudoOutput) bool { return !o.SssdActive },
		},
		{
			name:       "no kerberos identity",
			mutate:     func(rs []StepResult) []StepResult { rs[1] = stepResult("C4", 1, ""); return rs },
			checkField: func(o SudoOutput) bool { return o.SssdActive && !o.HasKerberosMachineIdentity },
		},
		{
			name:       "account does not resolve",
			mutate:     func(rs []StepResult) []StepResult { rs[2] = stepResult("C5", 2, ""); return rs },
			checkField: func(o SudoOutput) bool { return o.HasKerberosMachineIdentity && !o.AccountResolvesViaSSSD },
		},
		{
			name:       "access_provider not ipa",
			mutate:     func(rs []StepResult) []StepResult { rs[3] = stepResult("C6", 1, ""); return rs },
			checkField: func(o SudoOutput) bool { return o.AccountResolvesViaSSSD && !o.AccessProviderIsIPA },
		},
		{
			name:       "nsswitch not routed",
			mutate:     func(rs []StepResult) []StepResult { rs[4] = stepResult("C7", 1, ""); return rs },
			checkField: func(o SudoOutput) bool { return o.AccessProviderIsIPA && !o.SudoersRoutedThroughSSSD },
		},
		{
			name:       "no central sudo rule",
			mutate:     func(rs []StepResult) []StepResult { rs[5] = stepResult("C8", 1, "not allowed"); return rs },
			checkField: func(o SudoOutput) bool { return o.SudoersRoutedThroughSSSD && !o.CentralSudoRuleGrantsAccess },
		},
		{
			name:        "everything works",
			mutate:      func(rs []StepResult) []StepResult { return rs },
			wantAllGood: true,
			checkField: func(o SudoOutput) bool {
				return o.SssdActive && o.HasKerberosMachineIdentity && o.AccountResolvesViaSSSD &&
					o.AccessProviderIsIPA && o.SudoersRoutedThroughSSSD && o.CentralSudoRuleGrantsAccess
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := append([]StepResult(nil), allGood...)
			results = tc.mutate(results)
			out := BuildSudoOutput("alice", results)
			if !tc.checkField(out) {
				t.Fatalf("%s: BuildSudoOutput() = %+v, want condition to hold", tc.name, out)
			}
			if out.Verdict == "" {
				t.Fatalf("%s: Verdict is empty", tc.name)
			}
		})
	}
}
