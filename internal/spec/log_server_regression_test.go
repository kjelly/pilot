package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_LogServerSpec locks the structure of
// docs/verification/log-server.md (v1.2 — rsyslog central SIEM receiver,
// TCP only):
//
//	C1  rsyslog package installed
//	C2  rsyslog.service active
//	C3  receiver drop-in config file exists
//	C4  imtcp module + input present in the drop-in
//	C5  TCP 514 actually listening
//	C6  landing directory /var/log/siem exists
//	C7/C8 local6/authpriv selftest messages route into the dynaFile paths
//	C9  logrotate policy file exists
//	C10 logrotate policy passes a dry-run
//	C11 the imtcp input is bound to its own dedicated ruleset, not the
//	    default ruleset (v1.3 — without this, a host that is both
//	    log-server and an audit-log-forwarding client forwards its own
//	    traffic to itself, and the received copy re-enters the default
//	    ruleset's forwarding rule and re-forwards itself forever; confirmed
//	    live 2026-08-07, minimal-poc round 20, filled a 77GB disk in under
//	    an hour)
//
// v1.0/v1.1 also had a UDP receiver (imudp) and its own C4/C6 rows; v1.2
// removed UDP entirely (nothing in this repo ever forwards over UDP — see
// the spec's own §1 note) rather than keep it conditional, so this test's
// row count/IDs reflect the smaller v1.2 checklist, not the historical one.
//
// Cross-row invariants locked below:
//
//   - C1/C2/C4/C5/C10 must use positive-logic rc (`; echo $?` or a
//     native rc), never a reverse-logic grep with a numeric expected —
//     the ad-hoc `host | CHANGED | rc=0 >>` wrapper corrupts the real rc
//     to 2 when the underlying pipeline's own exit code is non-zero on
//     the healthy path (see verification-spec-template.md trap 1).
//   - C5 must use the `sh -c '... && echo 0 || echo 1'` form so the
//     outer command always exits 0 regardless of match outcome.
//   - C7/C8 must use `~contains` (never a `^`-anchored regex) and must
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

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"}
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
	for _, id := range []string{"C1", "C2", "C4", "C10", "C11"} {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}

	// C11 must check the imtcp input is bound to the dedicated siemReceiver
	// ruleset, not left in the default ruleset (the self-forwarding loop
	// fix).
	if !strings.Contains(cmd["C11"], "ruleset=") || !strings.Contains(cmd["C11"], "siemReceiver") {
		t.Errorf("C11 must check the imtcp input is bound to ruleset=\"siemReceiver\", got %q", cmd["C11"])
	}

	// C5: sh -c '... && echo 0 || echo 1' so the outer command always
	// exits 0 (ansible never sees a FAILED-wrapper on the unhealthy path).
	if !strings.Contains(cmd["C5"], "&& echo 0") || !strings.Contains(cmd["C5"], "|| echo 1") {
		t.Errorf("C5 must use the `... && echo 0 || echo 1` form, got %q", cmd["C5"])
	}
	if exp["C5"] != "0" {
		t.Errorf("C5 expected must be rc-based `0`, got %q", exp["C5"])
	}

	// C7/C8: contains-match, never a ^-anchored regex, and the grep's
	// own non-zero rc on a legitimate miss must be neutralized.
	for _, id := range []string{"C7", "C8"} {
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

// TestRegression_LogServerCoexistsWithWazuhManagerTCPOnly locks a real
// production incident fix (2026-08-06, two rounds):
//
//  1. The apply playbook used to unconditionally end_play this ENTIRE host
//     whenever ANY host in inventory had wazuh-manager, on the false
//     assumption that wazuh-manager's own 514/udp docker-compose port
//     mapping made it "a syslog collector" (git log: "avoid
//     double-deployed syslog collectors"). That port is never wired into
//     anything that parses local6/auth/authpriv content — confirmed via a
//     real incident where 6 client hosts forwarded to a wazuh-manager host
//     with no TCP/514 listener at all, and via wazuh-manager.md's own §5
//     note that the port is intentionally unused.
//  2. A first fix kept UDP conditional (disabled only when co-located with
//     wazuh-manager). Since nothing in this repo ever forwards over UDP,
//     that conditional was itself unnecessary complexity — v1.2 removed
//     UDP entirely instead, which incidentally also removes any possible
//     514/udp conflict with wazuh-manager's compose.
//
// log-server must run on every host assigned to it regardless of
// wazuh-manager's presence, and must never define a UDP receiver again.
func TestRegression_LogServerCoexistsWithWazuhManagerTCPOnly(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-server-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	if strings.Contains(s, "Skip log-server if wazuh-manager is enabled") {
		t.Error("log-server-apply.yml must not skip this host just because a wazuh-manager host exists somewhere in inventory — that port is never actually wired into anything (see wazuh-manager.md §5)")
	}
	// Forbid the actual UDP receiver constructs, not mere mentions of the
	// words (the header comment legitimately explains this history by
	// name — see docs/verification/log-server.md v1.2 changelog).
	for _, forbidden := range []string{
		`when: groups['wazuh-manager'] | default([]) | length > 0`,
		`module(load="imudp")`,
		"siem_receiver_udp_enabled:",
		"siem_receiver_udp_port:",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("log-server-apply.yml must not contain %q — UDP support was removed entirely (v1.2), not made conditional", forbidden)
		}
	}

	if !strings.Contains(s, `module(load="imtcp")`) {
		t.Fatal("rendered rsyslog config must always include module(load=\"imtcp\")")
	}
	if !strings.Contains(s, "siem_receiver_tcp_port") {
		t.Error(`log-server-apply.yml must still define siem_receiver_tcp_port`)
	}
}

// TestRegression_LogServerReceiverUsesDedicatedRuleset locks a real
// production incident fix (2026-08-07, minimal-poc round 20):
//
// This topology always co-locates log-server with an audit-log-forwarding
// client on the same host (the central SIEM host needs its own logs
// collected too). That host's audit-log-forwarding role forwards its own
// local6/auth/authpriv traffic to itself over TCP. Before this fix, the
// imtcp input had no dedicated ruleset, so a network-received message fell
// into rsyslog's default ruleset — the SAME ruleset that carries
// audit-log-forwarding-apply.yml's own forwarding rule — and got forwarded
// again, forever. Confirmed live: one host's auth.log reached 121M+ lines
// (13GB) and filled a 77GB disk to 100% in under an hour.
//
// The fix binds the imtcp input to its own ruleset so a received message is
// written to the dynaFile exactly once and never re-enters the forwarding
// rule.
func TestRegression_LogServerReceiverUsesDedicatedRuleset(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-server-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	if !strings.Contains(s, `ruleset(name="siemReceiver")`) {
		t.Error(`log-server-apply.yml must define ruleset(name="siemReceiver") to isolate received messages from the default ruleset`)
	}
	if !strings.Contains(s, `input(type="imtcp" port="{{ siem_receiver_tcp_port }}" ruleset="siemReceiver")`) {
		t.Error(`log-server-apply.yml's imtcp input must bind ruleset="siemReceiver" — otherwise a host that is both log-server and an audit-log-forwarding client self-forwards in an infinite loop`)
	}
	// The dynaFile actions must live inside the dedicated ruleset, not
	// dangling in the default ruleset alongside the forwarding rule.
	rulesetIdx := strings.Index(s, `ruleset(name="siemReceiver")`)
	inputIdx := strings.Index(s, `input(type="imtcp"`)
	if rulesetIdx < 0 || inputIdx < 0 || rulesetIdx > inputIdx {
		t.Fatalf("ruleset(name=\"siemReceiver\") must be defined before the imtcp input that references it")
	}
	rulesetBlock := s[rulesetIdx:inputIdx]
	for _, action := range []string{`dynaFile="SiemAuditPath"`, `dynaFile="SiemAuthPath"`} {
		if !strings.Contains(rulesetBlock, action) {
			t.Errorf("siemReceiver ruleset block must contain %q, got block:\n%s", action, rulesetBlock)
		}
	}
}
