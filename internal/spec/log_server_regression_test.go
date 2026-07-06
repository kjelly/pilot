package spec

import (
	"strings"
	"testing"
)

// TestRegression_LogServerSpec locks the structure of
// docs/verification/log-server.md (v1.0 — rsyslog central SIEM receiver):
//
//	C1     rsyslog package installed
//	C2     rsyslog.service active
//	C3     receiver drop-in config file exists
//	C4/C5  imudp/imtcp module + input present in the drop-in
//	C6/C7  UDP/TCP 514 actually listening
//	C8     landing directory /var/log/siem exists
//	C9/C10 local6/authpriv selftest messages route into the dynaFile paths
//	C11    logrotate policy file exists
//	C12    logrotate policy passes a dry-run
//
// Cross-row invariants locked below:
//
//   - C1/C2/C4/C5/C6/C7/C12 must use positive-logic rc (`; echo $?` or a
//     native rc), never a reverse-logic grep with a numeric expected —
//     the ad-hoc `host | CHANGED | rc=0 >>` wrapper corrupts the real rc
//     to 2 when the underlying pipeline's own exit code is non-zero on
//     the healthy path (see verification-spec-template.md trap 1).
//   - C6/C7 must use the `sh -c '... && echo 0 || echo 1'` form so the
//     outer command always exits 0 regardless of match outcome.
//   - C9/C10 must use `~contains` (never a `^`-anchored regex) and must
//     neutralize a non-matching grep's non-zero rc (via `; true` or
//     equivalent) so a legitimate "not routed yet" FAIL renders as a
//     clean mismatch instead of a corrupted ansible FAILED wrapper.
//   - No row may use `~active` (matches `inactive` as a substring).
func TestRegression_LogServerSpec(t *testing.T) {
	const specPath = "../../docs/verification/log-server.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// Positive-logic rc rows: rc-based numeric expected, never a bare
	// reverse-logic grep feeding a "1 means healthy" expected.
	for _, id := range []string{"C1", "C2", "C4", "C5", "C12"} {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}

	// C6/C7: sh -c '... && echo 0 || echo 1' so the outer command always
	// exits 0 (ansible never sees a FAILED-wrapper on the unhealthy path).
	for _, id := range []string{"C6", "C7"} {
		if !strings.Contains(cmd[id], "&& echo 0") || !strings.Contains(cmd[id], "|| echo 1") {
			t.Errorf("%s must use the `... && echo 0 || echo 1` form, got %q", id, cmd[id])
		}
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}

	// C9/C10: contains-match, never a ^-anchored regex, and the grep's
	// own non-zero rc on a legitimate miss must be neutralized.
	for _, id := range []string{"C9", "C10"} {
		if !strings.HasPrefix(exp[id], "~") {
			t.Errorf("%s expected should be a ~contains match, got %q", id, exp[id])
		}
		if strings.HasPrefix(exp[id], "^") {
			t.Errorf("%s must not use a ^-anchored regex, got %q", id, exp[id])
		}
		if !strings.Contains(cmd[id], "; true") {
			t.Errorf("%s must neutralize a non-matching grep's rc (e.g. `; true`), got %q", id, cmd[id])
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}
