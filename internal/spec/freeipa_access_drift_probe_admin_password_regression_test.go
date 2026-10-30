package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	driftProbePath     = "../../playbooks/check/freeipa-access-drift-probe.yml"
	driftProbeKinit    = "Kinit admin for read-only drift probe"
	driftProbePwGate   = "Gate: a FreeIPA admin password is available (vault or roster)"
	driftProbeRosterEx = "{{ ipa_admin_password }}"
	// driftProbeBadTemplate raises "division by zero" when ansible renders it.
	driftProbeBadTemplate = "{{ 1 / 0 }}"
)

// driftProbeTasks returns the production probe's pre_tasks, every one of
// them, plus its kinit task. The harness runs them on localhost with a fake
// kinit, so the real password resolution and the real kinit stdin wiring are
// what is under test.
func driftProbeTasks(t *testing.T, bin string) []any {
	t.Helper()
	doc, ok := loadYAML(t, driftProbePath).([]any)
	if !ok || len(doc) != 1 {
		t.Fatal("drift probe: want exactly one play")
	}
	play := doc[0].(map[string]any)
	tasks := append([]any{}, play["pre_tasks"].([]any)...)
	kinit := findNamedTask(t, doc, driftProbeKinit)
	kinit["environment"] = map[string]any{
		"PATH":             bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_KINIT_STDIN": filepath.Join(filepath.Dir(bin), "kinit-stdin"),
		"KRB5CCNAME":       "FILE:" + filepath.Join(filepath.Dir(bin), "krb5cc"),
	}
	return append(tasks, kinit)
}

// TestRegression_IdentitySecretDriftProbeAdminPassword is the runtime proof
// for issue #179: `pilot identity drift`, `pilot access drift` and `pilot
// access health` hand the drift probe the vault vars file, and the probe
// takes the FreeIPA admin password vault-first (like
// freeipa-identity-apply.yml) with the roster as the fallback. Each case
// runs the probe's real pre_tasks and kinit task with real ansible-playbook
// and a fake kinit recording its stdin. Before the fix the probe read only
// the roster, so a roster password of '{{ ipa_admin_password }}' (or none)
// failed even though the vault had the password.
func TestRegression_IdentitySecretDriftProbeAdminPassword(t *testing.T) {
	const (
		vaultSecret  = "Vault-S3ntinel-pw-7c1d"
		rosterSecret = "Roster-S3ntinel-pw-4a9e"
		shortSecret  = "Sh0rt!"
	)
	bothSources := []string{"ipa_admin_password", "freeipa.admin.password", "missing or too short"}

	for _, tc := range []struct {
		name string
		// vault is the ipa_admin_password in the vault vars file; roster the
		// roster's freeipa.admin.password. "" omits the key; vaultKey false
		// means there is no vault file at all.
		vault, roster string
		noVaultFile   bool
		args          []string
		wantStdin     string // "" means the probe must fail before kinit
	}{
		{name: "vault literal, roster has no password", vault: vaultSecret, wantStdin: vaultSecret},
		{name: "vault wins over a roster template", vault: vaultSecret, roster: driftProbeRosterEx, wantStdin: vaultSecret},
		{name: "roster literal, no vault file", roster: rosterSecret, noVaultFile: true, wantStdin: rosterSecret},
		{name: "roster literal, vault without the key", roster: rosterSecret, wantStdin: rosterSecret},
		{name: "both set: vault wins like apply", vault: vaultSecret, roster: rosterSecret, wantStdin: vaultSecret},
		{name: "tagged run still resolves the password", vault: vaultSecret, roster: driftProbeRosterEx, args: []string{"--tags", "drift"}, wantStdin: vaultSecret},
		// A vault value that is itself a template which raises used to end the
		// play in a censored no_log failure; it now counts as "no vault
		// password", so the roster is used or the gate speaks.
		{name: "vault template that raises falls back to the roster", vault: driftProbeBadTemplate, roster: rosterSecret, wantStdin: rosterSecret},
		{name: "vault template that raises and no roster password hits the gate", vault: driftProbeBadTemplate},
		{name: "vault template over an undefined variable hits the gate", vault: "{{ nope.x.y | upper }}"},
		{name: "neither source fails before kinit", noVaultFile: true},
		{name: "vault without the key and no roster password fails before kinit"},
		{name: "vault too short and no roster password fails before kinit", vault: shortSecret},
		{name: "vault too short wins over a roster literal like apply", vault: shortSecret, roster: rosterSecret},
		{name: "roster too short and no vault fails before kinit", roster: shortSecret, noVaultFile: true},
		{name: "roster template and no vault fails with the clear message", roster: driftProbeRosterEx, noVaultFile: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\ncat > \"$FAKE_KINIT_STDIN\"\n"
			if err := os.WriteFile(filepath.Join(bin, "kinit"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}

			admin := map[string]any{"principal": "admin"}
			if tc.roster != "" {
				admin["password"] = tc.roster
			}
			rosterBody, err := yaml.Marshal(map[string]any{"schema_version": 3, "freeipa": map[string]any{"domain": "ipa.pilot.internal", "admin": admin}})
			if err != nil {
				t.Fatal(err)
			}
			rosterPath := filepath.Join(dir, "roster.yaml")
			if err := os.WriteFile(rosterPath, rosterBody, 0o600); err != nil {
				t.Fatal(err)
			}

			// freeipa_roster_file/pilot_drift_output are -e @params.json and
			// the vault -e @vault.yaml, in the order pilot passes them.
			args := []string{}
			if !tc.noVaultFile {
				vaultVars := map[string]any{"unrelated_vault_key": "x"}
				if tc.vault != "" {
					vaultVars["ipa_admin_password"] = tc.vault
				}
				vaultBody, err := yaml.Marshal(vaultVars)
				if err != nil {
					t.Fatal(err)
				}
				vaultPath := filepath.Join(dir, "main.yaml")
				if err := os.WriteFile(vaultPath, vaultBody, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-e", "@"+vaultPath)
			}
			params := fmt.Sprintf(`{"freeipa_roster_file": %q, "pilot_drift_output": %q}`, rosterPath, filepath.Join(dir, "out.json"))
			paramsPath := filepath.Join(dir, "params.json")
			if err := os.WriteFile(paramsPath, []byte(params), 0o600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-e", "@"+paramsPath)
			args = append(args, tc.args...)

			vars := map[string]any{"freeipa_roster": map[string]any{}}
			res := runGatewayTasks(t, dir, driftProbeTasks(t, bin), vars, nil, args...)

			for _, secret := range []string{vaultSecret, rosterSecret, shortSecret} {
				if strings.Contains(res.raw, secret) || strings.Contains(res.stderr, secret) {
					t.Fatalf("Ansible output leaked %q-class password:\n%s\n%s", secret[:5], res.raw, res.stderr)
				}
			}

			stdin, readErr := os.ReadFile(filepath.Join(dir, "kinit-stdin"))
			if tc.wantStdin != "" {
				if res.rc != 0 {
					t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
				}
				if readErr != nil || strings.TrimSuffix(string(stdin), "\n") != tc.wantStdin {
					t.Fatalf("kinit stdin = %q (%v), want the %q-class password", stdin, readErr, tc.wantStdin[:5])
				}
				return
			}
			if res.rc == 0 {
				t.Fatalf("probe succeeded without a usable admin password\n%s", res.raw)
			}
			if readErr == nil {
				t.Fatalf("kinit ran (stdin %q) although no usable password existed", stdin)
			}
			// The failure must be the gate's fixed message, not a censored
			// no_log error from some earlier task.
			msg := failureOf(res, driftProbePwGate)
			if msg == "" {
				t.Fatalf("the password gate did not fail; failures: %v", res.failures)
			}
			for _, want := range bothSources {
				if !strings.Contains(msg, want) {
					t.Errorf("gate message %q does not name %q", msg, want)
				}
			}
			// A rescued failure is also reported as failed by the callback
			// (the vault-template cases), so look at the run's end state: the
			// gate is the failure that stopped it, and nothing after it ran.
			if last := res.failures[len(res.failures)-1]; !strings.HasPrefix(last, driftProbePwGate) {
				t.Errorf("the last failure must be the gate, got %v", res.failures)
			}
		})
	}
}

// TestRegression_DriftProbeResolvesThePasswordUnderEveryTag locks the gate
// and its inputs to `always` (AGENTS section 4.3/4.4): a tagged run must not skip the
// resolution that the tagged kinit reads, nor the gate that guards it.
func TestRegression_DriftProbeResolvesThePasswordUnderEveryTag(t *testing.T) {
	doc := loadYAML(t, driftProbePath)
	for _, name := range []string{
		"Resolve the FreeIPA admin password from the vault variable",
		"Read the vault admin password",
		"Treat an unresolvable vault admin password as missing",
		"Fall back to the roster admin password when the vault has none",
		"Read the roster admin password",
		"Treat an unresolvable roster admin password as missing",
		"Check the resolved FreeIPA admin password length",
		driftProbePwGate,
	} {
		task := findNamedTask(t, doc, name)
		tags, _ := task["tags"].([]any)
		if len(tags) != 1 || tags[0] != "always" {
			t.Errorf("%s: tags = %v, want [always]", name, task["tags"])
		}
		_, isBlock := task["block"]
		if name != driftProbePwGate && !isBlock && task["no_log"] != true {
			t.Errorf("%s touches the password and must keep no_log: true", name)
		}
	}
	if gate := findNamedTask(t, doc, driftProbePwGate); gate["no_log"] == true {
		t.Error("the password gate must keep its fixed message visible; it must not be no_log")
	}
}
