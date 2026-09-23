package spec

import (
	"os"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/gatewayapi"
)

// Alignment note (AGENTS.md §3): this spec's §1 group
// (pilot-access-target-policy) is exactly the group the reference topology
// docs/topologies/pilot-access-transport-topology.yaml gives tx-target, and
// the playbook defaults its hosts: pattern to it. That topology — not the
// single-VM vm-target reference inventory — is where the spec is verified,
// so TestRegression_SpecAndInventoryAgree's single-VM template does not
// apply here.

const targetPolicySpecPath = "../../docs/verification/pilot-access-target-policy.md"
const targetPolicyPlaybookPath = "../../playbooks/apply/pilot-access-target-policy-apply.yml"

func TestRegression_PilotAccessTargetPolicySpec(t *testing.T) {
	s, err := Parse(targetPolicySpecPath)
	if err != nil {
		t.Fatalf("parse %s: %v", targetPolicySpecPath, err)
	}
	wantIDs := []string{"TP01", "TP02", "TP03", "TP04", "TP05"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, row := range s.Rows {
		if row.ID != wantIDs[i] {
			t.Errorf("row[%d].ID=%q want=%q", i, row.ID, wantIDs[i])
		}
		if strings.TrimSpace(row.Expected) == "" || strings.TrimSpace(row.Command) == "" {
			t.Errorf("row %s has empty expected or command", row.ID)
		}
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Fatalf("spec lint errors:\n%s", fsToString(findings))
	}

	rows := map[string]Row{}
	for _, row := range s.Rows {
		rows[row.ID] = row
	}
	// The expected effective values are the real `sshd -T -C` output
	// captured in docs/evidence/pilot-access-gateway/2026-09-23-ad6d552.md §3.
	for id, tokens := range map[string][]string{
		"TP01": {"06-pilot-access-target-policy.conf", "root:root 644", "Match Address"},
		"TP03": {"allowstreamlocalforwarding no", "permitlisten none", "gatewayports no", "allowagentforwarding no", "x11forwarding no", "permittunnel no", "addr=$a"},
		"TP04": {"allowtcpforwarding no", "permitopen none", "allowtcpforwarding local", "permitopen localhost:* 127.0.0.1:* [::1]:*"},
		"TP05": {"addr=192.0.2.1", "sshd -T |"},
	} {
		for _, tok := range tokens {
			if !strings.Contains(rows[id].Command, tok) {
				t.Errorf("%s command must contain %q, got %q", id, tok, rows[id].Command)
			}
		}
	}
}

// TestRegression_PilotAccessTargetPolicyPlaybook locks the playbook-side
// invariants of spec §13: address-keyed Match, the exact per-profile
// directives, validated install with rollback, TEST-NET equality, the
// pilot-transport-ready literal the gateway gates on, and the safe absent
// order (leave the hostgroup before removing the policy).
func TestRegression_PilotAccessTargetPolicyPlaybook(t *testing.T) {
	raw, err := os.ReadFile(targetPolicyPlaybookPath)
	if err != nil {
		t.Fatalf("read playbook: %v", err)
	}
	pb := string(raw)

	if want := "pilot_access_target_ready_hostgroup: " + gatewayapi.TransportReadyHostgroup + "\n"; !strings.Contains(pb, want) {
		t.Errorf("playbook ready hostgroup must equal gatewayapi.TransportReadyHostgroup: missing %q", want)
	}
	for _, required := range []string{
		`hosts: "{{ target_group | default('pilot-access-target-policy') }}"`,
		"Match Address {{ pilot_access_target_gateway_addresses | join(',') }}",
		"AllowTcpForwarding {{ 'no' if pilot_access_target_effective_forwarding_profile == 'strict' else 'local' }}",
		"PermitOpen {{ 'none' if pilot_access_target_effective_forwarding_profile == 'strict' else 'localhost:* 127.0.0.1:* [::1]:*' }}",
		"AllowStreamLocalForwarding no",
		"PermitListen none",
		"GatewayPorts no",
		"AllowAgentForwarding no",
		"X11Forwarding no",
		"PermitTunnel no",
		"validate: /usr/sbin/sshd -t -f %s",
		"rescue:",
		"pilot_access_target_testnet_addr: 192.0.2.1",
		"pilot_access_target_after_global.stdout == pilot_access_target_baseline_global.stdout",
		"pilot_access_target_after_testnet.stdout == pilot_access_target_baseline_testnet.stdout",
		"state: reloaded",
		"'pilot-access-gateway' not in group_names",
		"'pilot-access-directory' not in group_names",
		"stage == 'sandbox'",
		"not ('prod' in group_names and stage != 'prod')",
	} {
		if !strings.Contains(pb, required) {
			t.Errorf("playbook missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"Match Group",
		"state: restarted",
		"PermitUserEnvironment",
	} {
		if strings.Contains(pb, forbidden) {
			t.Errorf("playbook must not contain %q", forbidden)
		}
	}
	for _, tag := range []string{"tags: [TP01]", "tags: [TP02]", "tags: [TP03, TP04]", "tags: [TP05]"} {
		if !strings.Contains(pb, tag) {
			t.Errorf("playbook missing row tag %q", tag)
		}
	}

	// absent: leave pilot-transport-ready BEFORE removing the drop-in, so a
	// transport can never reach a host whose restrictions are already gone.
	absent := pb[strings.Index(pb, `name: "Target policy — absent"`):]
	leave := strings.Index(absent, "hostgroup-remove-member")
	remove := strings.Index(absent, "Remove the policy drop-in")
	if leave < 0 || remove < 0 || leave > remove {
		t.Errorf("absent must remove the host from the ready hostgroup (at %d) before removing the drop-in (at %d)", leave, remove)
	}
	// present: join pilot-transport-ready only AFTER the policy block.
	present := pb[strings.Index(pb, `name: "Target policy — present"`):strings.Index(pb, `name: "Target policy — absent"`)]
	install := strings.Index(present, "TP01: install the policy drop-in")
	join := strings.Index(present, "hostgroup-add-member")
	if install < 0 || join < 0 || join < install {
		t.Errorf("present must install/verify the policy (at %d) before joining the ready hostgroup (at %d)", install, join)
	}
}
