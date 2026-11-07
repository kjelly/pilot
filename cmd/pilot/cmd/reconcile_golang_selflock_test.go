package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The self-lockout check (spec §7.10) from the command: a plan that would take the
// engine's own login away, and reads that cannot say what a plan takes away, are a
// produced plan with a blocked object, exit 3 and the plan written to --plan-out,
// like every other blocked plan (spec §2.3). The preview could not exit 3 for
// protected_object before P2-5.
func TestReconcileGolangPreviewBlocksWhatWouldLockTheEngineOut(t *testing.T) {
	for _, tc := range []struct {
		name   string
		roster string // %s is the login shell of p1-self
		setup  func(f *fakeIPA)
		want   string // in the plan JSON and the output
	}{
		{name: "the roster disables the login", roster: "/bin/sh, state: disabled",
			want: "would be disabled after S7"},
		{name: "user_find lists admins and the group read has no admins group (the reads disagree)", roster: "/bin/sh",
			setup: func(f *fakeIPA) { f.answers = map[string]string{"group_find": "group-find-no-match"} },
			want:  "the reads disagree"},
		{name: "the reads agree and the roster leaves the login alone: nothing is blocked", roster: "/bin/sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeIPA(t, "p1-self")
			withFakeDialer(t, f)
			if tc.setup != nil {
				tc.setup(f)
			}
			dir := golangWorkspace(t, strings.Replace(captureRoster, "%s", tc.roster, 1), nil)
			plan := filepath.Join(dir, "p.json")
			out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v\n%s", err, out)
				}
				return
			}
			if err == nil || processExitCode(err) != 3 || !strings.Contains(err.Error(), "個物件被阻擋") {
				t.Fatalf("err = %v, exit %d, want exit 3 for a blocked object\n%s", err, processExitCode(err), out)
			}
			data, rerr := os.ReadFile(plan)
			if rerr != nil || !strings.Contains(string(data), `"result": "blocked"`) || !strings.Contains(string(data), "protected_object") || !strings.Contains(string(data), tc.want) {
				t.Fatalf("plan (%v) = %s, want a protected_object holding %q", rerr, data, tc.want)
			}
			if !strings.Contains(out, "protected_object") || !strings.Contains(out, tc.want) {
				t.Fatalf("the output does not say what blocked it:\n%s", out)
			}
			assertNoSecretAnywhere(t, err, out, plan)
		})
	}
}
