package accessgrants

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file runs the production probe (playbooks/check/freeipa-access-drift-
// probe.yml) through DriftProbe and EvaluateHealth with REAL ansible-playbook,
// a localhost inventory whose group is the hyphenated freeipa-server (so
// ansible writes its "Invalid characters in group names" warning to stderr,
// as it does on every real pilot inventory), and fake kinit/ipa binaries.
// It is the issue #179 proof that
//
//   - the gate's fixed message reaches `identity drift`, `access drift` and
//     `access health` (it is on stdout; stderr only has the warning), and
//   - a vault vars file that ansible cannot parse never has its content echoed
//     into the probe error or the health line.
//
// `make identity-secret-test` runs it with PILOT_REQUIRE_CONTAINER_TESTS=1, so
// a missing ansible fails instead of skipping.

const (
	realProbePlaybook = "../../playbooks/check/freeipa-access-drift-probe.yml"
	probeVaultSecret  = "Sup3rS3cretPw"
	probeKinitSecret  = "K1nit-Leak-Sentinel-77"
)

func requireRealAnsible(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"ansible-playbook"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatalf("required %s not installed: %v", tool, err)
			}
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
}

// realProbeEnv is one workspace for the real probe: an inventory, a roster, a
// vault file and fake kinit/ipa on PATH. kinit records its stdin.
type realProbeEnv struct {
	dir, inventory, roster, kinitStdin string
}

func newRealProbeEnv(t *testing.T, rosterPassword, kinitBody string) realProbeEnv {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	e := realProbeEnv{dir: dir, inventory: filepath.Join(dir, "inventory.yml"), roster: filepath.Join(dir, "roster.yaml"), kinitStdin: filepath.Join(dir, "kinit-stdin")}
	if kinitBody == "" {
		kinitBody = "cat > \"" + e.kinitStdin + "\""
	}
	write := func(path, body string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "kinit"), "#!/bin/sh\n"+kinitBody+"\n", 0o755)
	write(filepath.Join(bin, "ipa"), "#!/bin/sh\nexit 0\n", 0o755)
	write(e.inventory, "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa1:\n          ansible_connection: local\n", 0o600)
	admin := "{principal: admin}"
	if rosterPassword != "" {
		admin = "{principal: admin, password: " + rosterPassword + "}"
	}
	write(e.roster, strings.Replace(healthTestRosterNoGrants, "{principal: admin, password: x}", admin, 1), 0o600)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return e
}

func (e realProbeEnv) vault(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(e.dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (e realProbeEnv) opts(t *testing.T, varsFile, passwordFile string) DriftProbeOptions {
	t.Helper()
	pb, err := filepath.Abs(realProbePlaybook)
	if err != nil {
		t.Fatal(err)
	}
	return DriftProbeOptions{
		RosterFile: e.roster, Inventory: e.inventory, Playbook: pb,
		VarsFile: varsFile, VaultPasswordFile: passwordFile,
		Now: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
	}
}

// TestRegression_IdentitySecretDriftProbeFailureIsSafe is the real-ansible
// matrix for the probe's failure reporting through DriftProbe (what `identity
// drift` and `access drift` print) and EvaluateHealth (`access health`'s
// probe_error).
func TestRegression_IdentitySecretDriftProbeFailureIsSafe(t *testing.T) {
	requireRealAnsible(t, "ansible-vault")
	const gate = "No usable FreeIPA admin password"
	bothSources := []string{gate, "ipa_admin_password", "freeipa.admin.password", "Both are missing or too short"}

	for _, tc := range []struct {
		name           string
		rosterPassword string
		vault          string // body of the vault vars file; "" means no file
		encrypt        bool   // encrypt the vault file; no password file is given
		kinit          string
		want           []string
		notWant        []string
	}{
		{name: "no password anywhere: the gate message, not the group-name warning", want: bothSources, notWant: []string{"Invalid characters", "Origin:"}},
		{name: "vault without the key and no roster password", vault: "unrelated: 1\n", want: bothSources},
		{name: "vault password too short", vault: "ipa_admin_password: Sh0rt!\n", want: bothSources, notWant: []string{"Sh0rt!"}},
		{name: "roster password is a template and there is no vault", rosterPassword: `"{{ ipa_admin_password }}"`, want: bothSources},
		{
			// A vault value that is itself a failing template used to end the
			// play in a censored no_log failure before the gate could speak.
			name: "vault password is a template that raises", vault: "ipa_admin_password: \"{{ 1 / 0 }}\"\n",
			want: bothSources, notWant: []string{"no_log", "censored"},
		},
		{
			name: "vault password is a template over an undefined variable", vault: "ipa_admin_password: \"{{ nope.x.y | upper }}\"\n",
			want: bothSources, notWant: []string{"no_log", "censored"},
		},
		{
			// The leak: ansible prints the offending source line of a vars file
			// it cannot parse. None of it may reach the error.
			name: "malformed vault YAML never echoes the file", vault: "ipa_admin_password: " + probeVaultSecret + ": oops\nother: 1\n",
			want:    []string{"could not parse", "valid YAML", "main.yaml:1:"},
			notWant: []string{probeVaultSecret, "oops", "ipa_admin_password", "Colons in unquoted values"},
		},
		{
			name: "encrypted vault without a password file", vault: "ipa_admin_password: " + probeVaultSecret + "\n", encrypt: true,
			want:    []string{"Attempting to decrypt but no vault secrets found"},
			notWant: []string{probeVaultSecret},
		},
		{
			// A failing kinit prints its stderr; the task is no_log.
			name: "kinit fails and its output stays hidden", vault: "ipa_admin_password: " + probeVaultSecret + "\n",
			kinit: "cat >/dev/null; echo 'kinit: " + probeKinitSecret + " " + probeVaultSecret + "' >&2; exit 1",
			want:  []string{"Kinit admin for read-only drift probe", "hidden by no_log"}, notWant: []string{probeKinitSecret, probeVaultSecret, "Module failed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newRealProbeEnv(t, tc.rosterPassword, tc.kinit)
			varsFile := ""
			if tc.vault != "" {
				varsFile = env.vault(t, "main.yaml", tc.vault)
				if tc.encrypt {
					plain := varsFile
					varsFile = filepath.Join(env.dir, "encrypted.yaml")
					passFile := env.vault(t, "vault-pass", "pw\n")
					if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", passFile, "--output", varsFile, plain).CombinedOutput(); err != nil {
						t.Fatalf("ansible-vault encrypt: %v\n%s", err, out)
					}
				}
			}

			_, probeErr := DriftProbe(context.Background(), env.opts(t, varsFile, ""))
			if probeErr == nil {
				t.Fatal("the probe succeeded without a usable admin password")
			}
			health, err := EvaluateHealth(context.Background(), HealthOptions{DriftProbeOptions: env.opts(t, varsFile, "")})
			if err != nil {
				t.Fatalf("a failed probe is status unknown, not an error: %v", err)
			}
			healthJSON, err := json.Marshal(health)
			if err != nil {
				t.Fatal(err)
			}
			if health.Status != HealthUnknown {
				t.Fatalf("health status = %q, want unknown", health.Status)
			}
			for where, text := range map[string]string{"DriftProbe error": probeErr.Error(), "Health.ProbeError": health.ProbeError} {
				for _, w := range tc.want {
					if !strings.Contains(text, w) {
						t.Errorf("%s does not contain %q:\n%s", where, w, text)
					}
				}
				for _, w := range tc.notWant {
					if strings.Contains(text, w) {
						t.Errorf("%s must not contain %q:\n%s", where, w, text)
					}
				}
				if strings.ContainsAny(text, "\n\r") && where == "Health.ProbeError" {
					t.Errorf("%s spans several lines", where)
				}
			}
			for _, secret := range []string{probeVaultSecret, probeKinitSecret} {
				if strings.Contains(probeErr.Error(), secret) || strings.Contains(string(healthJSON), secret) {
					t.Fatalf("a secret leaked into the probe error or the health report:\n%s\n%s", probeErr, healthJSON)
				}
			}
			if _, statErr := os.Stat(env.kinitStdin); statErr == nil && !strings.Contains(tc.name, "kinit") {
				t.Error("kinit ran although no usable admin password existed")
			}
		})
	}
}

// TestRegression_IdentitySecretDriftProbeWithRealAnsiblePasses is the passing
// counterpart: with a usable admin password from the vault, or from the roster
// when the vault has none, the real probe runs to the end, kinit receives that
// password on stdin and the health check is not unknown.
func TestRegression_IdentitySecretDriftProbeWithRealAnsiblePasses(t *testing.T) {
	requireRealAnsible(t)
	const vaultPW, rosterPW = "Vault-Passing-Pw-31", "Roster-Passing-Pw-77"
	for _, tc := range []struct {
		name, roster, vault, wantPW string
	}{
		{name: "vault password, roster has none", vault: "ipa_admin_password: " + vaultPW + "\n", wantPW: vaultPW},
		{name: "vault wins over a roster password", roster: rosterPW, vault: "ipa_admin_password: " + vaultPW + "\n", wantPW: vaultPW},
		{name: "roster password when the vault has none", roster: rosterPW, vault: "unrelated: 1\n", wantPW: rosterPW},
		{name: "roster password, no vault file", roster: rosterPW, wantPW: rosterPW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newRealProbeEnv(t, tc.roster, "")
			varsFile := ""
			if tc.vault != "" {
				varsFile = env.vault(t, "main.yaml", tc.vault)
			}
			live, err := DriftProbe(context.Background(), env.opts(t, varsFile, ""))
			if err != nil {
				t.Fatalf("probe failed: %v", err)
			}
			if live.SchemaVersion != 1 {
				t.Fatalf("schema_version = %d", live.SchemaVersion)
			}
			got, err := os.ReadFile(env.kinitStdin)
			if err != nil || strings.TrimSuffix(string(got), "\n") != tc.wantPW {
				t.Fatalf("kinit stdin = %q (%v), want the %q password", got, err, tc.wantPW[:5])
			}
			if tc.vault == "" || tc.roster != "" {
				return // one health evaluation is enough; each costs a full probe run
			}
			health, err := EvaluateHealth(context.Background(), HealthOptions{DriftProbeOptions: env.opts(t, varsFile, "")})
			if err != nil || health.Status == HealthUnknown || !health.FreeIPAReachable || health.ProbeError != "" {
				t.Fatalf("health = %+v, err = %v; want a reachable, known status", health, err)
			}
		})
	}
}

// TestRegression_IdentitySecretDriftProbeIgnoresTheOperatorsOutputSettings:
// the failure extraction reads ansible's default callback output, so DriftProbe
// pins it (driftProbeEnv). With the operator's environment or ansible.cfg
// selecting another callback, colour, or a YAML result format, the gate message
// must still be shown and a gate text that names .vault/main.yaml must not be
// reported as a parse error, while a real malformed vault still is.
func TestRegression_IdentitySecretDriftProbeIgnoresTheOperatorsOutputSettings(t *testing.T) {
	requireRealAnsible(t)
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ansible.cfg")
	if err := os.WriteFile(cfgPath, []byte("[defaults]\nstdout_callback = minimal\nforce_color = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		// raw reports whether this setting visibly changes a plain run, so
		// the case proves the environment is effective and not a no-op.
		raw func(stdout string) bool
	}{
		{"force color", map[string]string{"ANSIBLE_FORCE_COLOR": "1"}, func(o string) bool { return strings.Contains(o, "\x1b[") }},
		{"minimal callback", map[string]string{"ANSIBLE_STDOUT_CALLBACK": "minimal"}, func(o string) bool { return !strings.Contains(o, "fatal: [") }},
		{"json callback", map[string]string{"ANSIBLE_STDOUT_CALLBACK": "json"}, func(o string) bool { return strings.HasPrefix(strings.TrimSpace(o), "{") }},
		{"oneline callback", map[string]string{"ANSIBLE_STDOUT_CALLBACK": "oneline"}, func(o string) bool { return !strings.Contains(o, "TASK [") }},
		{"yaml result format", map[string]string{"ANSIBLE_CALLBACK_RESULT_FORMAT": "yaml"}, func(o string) bool { return !strings.Contains(o, `"msg": "`) }},
		{"ansible.cfg stdout_callback and color", map[string]string{"ANSIBLE_CONFIG": cfgPath}, func(o string) bool { return !strings.Contains(o, "fatal: [") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			pb, err := filepath.Abs(realProbePlaybook)
			if err != nil {
				t.Fatal(err)
			}

			// should-trigger: the gate fails, and the message reaches the error.
			env := newRealProbeEnv(t, "", "")
			noKey := env.vault(t, "nokey.yaml", "unrelated: 1\n")
			raw := exec.Command("ansible-playbook", pb, "-i", env.inventory, "-e", "@"+noKey,
				"-e", `{"freeipa_roster_file":"`+env.roster+`","pilot_drift_output":"/dev/null"}`)
			rawOut, _ := raw.Output()
			if !tc.raw(string(rawOut)) {
				t.Fatalf("this setting no longer changes ansible's output; the case proves nothing:\n%s", rawOut)
			}
			_, probeErr := DriftProbe(context.Background(), env.opts(t, noKey, ""))
			if probeErr == nil {
				t.Fatal("the probe succeeded without a usable admin password")
			}
			for _, w := range []string{"No usable FreeIPA admin password", "Both are missing or too short"} {
				if !strings.Contains(probeErr.Error(), w) {
					t.Errorf("the gate message is lost (%q missing): %v", w, probeErr)
				}
			}
			for _, w := range []string{"could not parse", "no recognisable failure", "\x1b"} {
				if strings.Contains(probeErr.Error(), w) {
					t.Errorf("wrong diagnosis (%q): %v", w, probeErr)
				}
			}

			// should-trigger: a malformed vault is still a parse error, and
			// its content still never reaches the error.
			bad := env.vault(t, "bad.yaml", "ipa_admin_password: "+probeVaultSecret+": oops\n")
			_, probeErr = DriftProbe(context.Background(), env.opts(t, bad, ""))
			if probeErr == nil || !strings.Contains(probeErr.Error(), "could not parse") || !strings.Contains(probeErr.Error(), "bad.yaml:1:") {
				t.Errorf("a malformed vault is not diagnosed as a parse error: %v", probeErr)
			} else if strings.Contains(probeErr.Error(), probeVaultSecret) || strings.Contains(probeErr.Error(), "oops") {
				t.Errorf("the malformed vault's content leaked: %v", probeErr)
			}

			// should-pass: with a usable password the probe still succeeds.
			good := env.vault(t, "good.yaml", "ipa_admin_password: Vault-Passing-Pw-31\n")
			if _, err := DriftProbe(context.Background(), env.opts(t, good, "")); err != nil {
				t.Errorf("the probe failed under this setting although the password is usable: %v", err)
			}
		})
	}
}
