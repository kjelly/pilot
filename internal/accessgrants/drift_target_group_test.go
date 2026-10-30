package accessgrants

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These tests are the issue #179 review finding: the vault vars file is a
// whole `-e @file` handed to the probe, so a Pilot-owned input that Pilot omits
// is decided by whatever the vault happens to contain. target_group was
// omitted when the operator gave no --target-group, so a vault `target_group:
// all` retargeted the probe at client hosts.

func driftProbePlaybookText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", DriftProbePlaybook))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDriftProbe_TargetGroupIsAlwaysInThePilotParams checks the params file
// (the last -e, which outranks the vault) for every combination of flag and
// vault. The "omitted" cases must trigger the fixed default, never leave the
// key out.
func TestDriftProbe_TargetGroupIsAlwaysInThePilotParams(t *testing.T) {
	rosterPath := writeDriftTestRoster(t)
	vaultPath := filepath.Join(t.TempDir(), "main.yaml")
	if err := os.WriteFile(vaultPath, []byte("ipa_admin_password: Vault-Passing-Pw-31\ntarget_group: all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, group, varsFile, want string
	}{
		{name: "omitted, no vault", want: "freeipa-server"},
		{name: "omitted, vault has target_group: all", varsFile: vaultPath, want: "freeipa-server"},
		{name: "explicit, no vault", group: "ipa-alt", want: "ipa-alt"},
		{name: "explicit, vault has target_group: all", group: "ipa-alt", varsFile: vaultPath, want: "ipa-alt"},
		{name: "explicit freeipa-server, vault has target_group: all", group: "freeipa-server", varsFile: vaultPath, want: "freeipa-server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}
			_, err := DriftOnce(context.Background(), DriftProbeOptions{
				RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner,
				TargetGroup: tc.group, VarsFile: tc.varsFile,
				Now: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := runner.capturedVars["target_group"].(string); !ok || got != tc.want {
				t.Fatalf("params target_group = %v, want %q (vars %v)", runner.capturedVars["target_group"], tc.want, runner.capturedVars)
			}
			// The params file must be the LAST -e so it outranks the vault.
			last := -1
			for i := 0; i+1 < len(runner.lastArgs); i++ {
				if runner.lastArgs[i] == "-e" {
					last = i + 1
				}
			}
			if tc.varsFile != "" {
				if v := driftArgIndex(runner.lastArgs, "@"+tc.varsFile); v < 0 || v >= last {
					t.Fatalf("the vault file must precede the params file: %v", runner.lastArgs)
				}
			}
		})
	}
}

// TestDriftProbe_EveryPilotOwnedInputIsAlwaysEmitted parses the probe
// playbook's documented extra-vars and requires DriftProbe to emit every one
// even when its options are all empty, so no key a vault file carries can
// stand in for a decision Pilot makes. A new documented input that DriftProbe
// forgets to emit fails here.
func TestDriftProbe_EveryPilotOwnedInputIsAlwaysEmitted(t *testing.T) {
	header := driftProbePlaybookText(t)
	header = header[:strings.Index(header, "# Output contract")]
	start := strings.Index(header, "# Required extra-vars:")
	if start < 0 {
		t.Fatal("the playbook header no longer has a 'Required extra-vars' section")
	}
	re := regexp.MustCompile(`(?m)^#   ([a-z][a-z_]+)\s*(?:--|$)`)
	var documented []string
	for _, m := range re.FindAllStringSubmatch(header[start:], -1) {
		documented = append(documented, m[1])
	}
	if len(documented) < 7 {
		t.Fatalf("parsed only %v from the playbook header; the parser needs updating", documented)
	}

	runner := &fakeDriftRunner{live: LiveState{HBACExists: map[string]bool{}}}
	if _, err := DriftOnce(context.Background(), DriftProbeOptions{
		RosterFile: writeDriftTestRoster(t), Inventory: "inv.yml", Runner: runner,
		Now: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range documented {
		if _, ok := runner.capturedVars[name]; !ok {
			t.Errorf("the probe's documented input %q is not in the params file; a vault key of that name would win: %v", name, runner.capturedVars)
		}
	}
}

// TestDriftTargetGroupDefaultMatchesPlaybook locks DefaultDriftTargetGroup to
// the probe playbook's own `hosts:` default (AGENTS.md section 5.7).
func TestDriftTargetGroupDefaultMatchesPlaybook(t *testing.T) {
	m := regexp.MustCompile(`(?m)^\s*hosts:\s*"\{\{\s*target_group\s*\|\s*default\('([^']+)'\)\s*\}\}"\s*$`).FindStringSubmatch(driftProbePlaybookText(t))
	if m == nil {
		t.Fatal("the probe playbook no longer has a `hosts: \"{{ target_group | default('...') }}\"` line")
	}
	if m[1] != DefaultDriftTargetGroup {
		t.Fatalf("playbook default %q != DefaultDriftTargetGroup %q", m[1], DefaultDriftTargetGroup)
	}
}

// targetGroupInventory is a server + client inventory for the real-ansible
// tests: ipa1 (freeipa-server) and ipa2 (ipa-alt) are reachable (local
// connection); client1 (clients) refuses every connection. A probe that
// targets client1 fails, so success proves which groups it did NOT touch.
const targetGroupInventory = `all:
  children:
    freeipa-server:
      hosts:
        ipa1:
          ansible_connection: local
    ipa-alt:
      hosts:
        ipa2:
          ansible_connection: local
    clients:
      hosts:
        client1:
          ansible_connection: ssh
          ansible_host: 127.0.0.1
          ansible_port: 1
          ansible_ssh_common_args: "-o ConnectTimeout=3 -o BatchMode=yes"
`

// deadServerInventory is the reverse: the default group freeipa-server holds
// only an unreachable host, the explicit group ipa-alt a reachable one.
const deadServerInventory = `all:
  children:
    freeipa-server:
      hosts:
        client1:
          ansible_connection: ssh
          ansible_host: 127.0.0.1
          ansible_port: 1
          ansible_ssh_common_args: "-o ConnectTimeout=3 -o BatchMode=yes"
    ipa-alt:
      hosts:
        ipa2:
          ansible_connection: local
`

// TestRegression_IdentitySecretDriftProbeDefaultScopeSurvivesAVaultTargetGroup runs the
// real probe (DriftProbe and EvaluateHealth, which back `identity drift`,
// `access drift` and `access health`) with a vault vars file that carries a
// target_group. Default freeipa-server scope survives conflicting
// auto-loaded target_group: all. Each pass case has a should-fail twin.
func TestRegression_IdentitySecretDriftProbeDefaultScopeSurvivesAVaultTargetGroup(t *testing.T) {
	requireRealAnsible(t, "ssh")
	const pw = "ipa_admin_password: Vault-Passing-Pw-31\n"
	for _, tc := range []struct {
		name, inventory, vault, group string
		wantOK                        bool
	}{
		// Should pass: the vault cannot retarget an omitted --target-group.
		{name: "omitted flag, vault target_group: all", inventory: targetGroupInventory, vault: pw + "target_group: all\n", wantOK: true},
		{name: "omitted flag, vault target_group: clients", inventory: targetGroupInventory, vault: pw + "target_group: clients\n", wantOK: true},
		{name: "explicit default group, vault target_group: all", inventory: targetGroupInventory, vault: pw + "target_group: all\n", group: "freeipa-server", wantOK: true},
		{name: "explicit alternate group wins over the vault", inventory: deadServerInventory, vault: pw + "target_group: all\n", group: "ipa-alt", wantOK: true},
		// Should trigger: the probe really contacts what it targets, so these
		// fail where the case above passes.
		{name: "explicit group with an unreachable host fails", inventory: targetGroupInventory, vault: pw, group: "clients"},
		{name: "omitted flag still means freeipa-server", inventory: deadServerInventory, vault: pw + "target_group: ipa-alt\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newRealProbeEnv(t, "", "")
			if err := os.WriteFile(env.inventory, []byte(tc.inventory), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := env.opts(t, env.vault(t, "main.yaml", tc.vault), "")
			opts.TargetGroup = tc.group

			_, probeErr := DriftProbe(context.Background(), opts)
			health, err := EvaluateHealth(context.Background(), HealthOptions{DriftProbeOptions: opts})
			if err != nil {
				t.Fatalf("a failed probe is status unknown, not an error: %v", err)
			}
			if tc.wantOK {
				if probeErr != nil {
					t.Fatalf("DriftProbe failed: %v", probeErr)
				}
				if health.Status == HealthUnknown || health.ProbeError != "" || !health.FreeIPAReachable {
					t.Fatalf("health = %+v, want a reachable, known status", health)
				}
				return
			}
			if probeErr == nil {
				t.Fatal("DriftProbe succeeded although it should have reached an unreachable host")
			}
			if !strings.Contains(probeErr.Error(), "client1") {
				t.Fatalf("the failure should be the unreachable client1, got: %v", probeErr)
			}
			if health.Status != HealthUnknown {
				t.Fatalf("health status = %q, want unknown", health.Status)
			}
		})
	}
}
