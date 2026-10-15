package spec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// Run the actual sim entry points with transport/identity tools replaced by
// deterministic processes. The policy starts absent, just as for a rule added
// after SSSD's last refresh; no stdout format is used as a readiness signal.
func TestRegression_FreeIPASimsWaitForSudoPolicy(t *testing.T) {
	for _, fixture := range []struct{ file, tag, user string }{
		{"freeipa-hostauthz-sim.yml", "positive", "hz_web"},
		{"freeipa-hostauthz-sim.yml", "sim", "hz_web"},
		{"freeipa-audit-sim.yml", "sim", "audituser"},
	} {
		t.Run(fixture.file+"/"+fixture.tag, func(t *testing.T) {
			for _, mode := range []string{"ready", "delayed", "missing", "hung", "overgrant", "password"} {
				t.Run(mode, func(t *testing.T) {
					if _, err := exec.LookPath("ansible-playbook"); err != nil {
						t.Skip("ansible-playbook is required for the sim behavior test")
					}
					dir := t.TempDir()
					write := func(name, data string) {
						t.Helper()
						if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0700); err != nil {
							t.Fatal(err)
						}
					}
					write("kinit", "#!/bin/sh\ncat >/dev/null\n")
					write("kdestroy", "#!/bin/sh\nexit 0\n")
					write("sudo", `#!/bin/sh
printf '%s\n' "$*" >> "$SIM_TEST_DIR/probes"
n=0
test ! -f "$SIM_TEST_DIR/count" || n=$(cat "$SIM_TEST_DIR/count")
n=$((n + 1))
printf '%s' "$n" > "$SIM_TEST_DIR/count"
case "$SIM_TEST_MODE" in
  hung) sleep 5; exit 1 ;;
  missing) exit 1 ;;
  delayed) test "$n" -ge 3 || exit 1 ;;
esac
touch "$SIM_TEST_DIR/ready"
exit 0
`)
					write("ssh", `#!/bin/sh
printf '%s\n' "$*" >> "$SIM_TEST_DIR/ssh-calls"
case "$*" in
  *hz_db@localhost*"-- whoami"*) exit 1 ;;
  *"-- whoami"*|*"-- whoami; id"*) printf '%s\n' "$SIM_TEST_USER"; exit 0 ;;
  *"sudo -n"*)
    test -f "$SIM_TEST_DIR/ready" || { echo 'sudo ran before policy readiness'; exit 99; }
    test "$SIM_TEST_MODE" != overgrant || exit 0
    test "$SIM_TEST_MODE" != password || exit 1
    case "$*" in
      *hz_db@localhost*|*"ps aux"*) exit 1 ;;
      *) exit 0 ;;
    esac ;;
esac
exit 1
`)
					pb, err := filepath.Abs(filepath.Join("../../playbooks/test/fixtures", fixture.file))
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "ansible-playbook", "-i", "localhost,", "-c", "local", pb,
						"--tags", fixture.tag, "-e", "target_group=all", "-e", "sim_target_group=all",
						"-e", "ipa_server_ip=192.0.2.1",
						"-e", "ansible_become=false", "-e", "sim_sudo_policy_retries=3",
						"-e", "sim_sudo_policy_delay=0", "-e", "sim_sudo_policy_probe_timeout=1")
					cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SIM_TEST_DIR="+dir,
						"SIM_TEST_MODE="+mode, "SIM_TEST_USER="+fixture.user, "ANSIBLE_NOCOLOR=1",
						"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "ansible-local"),
						"ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "ansible-remote"), "ANSIBLE_LOG_PATH="+filepath.Join(dir, "ansible.log"))
					out, runErr := cmd.CombinedOutput()
					notReady := mode == "missing" || mode == "hung"
					wantFailure := notReady || mode == "overgrant" || mode == "password"
					if (runErr != nil) != wantFailure || ctx.Err() != nil {
						t.Fatalf("mode %s: err=%v, context=%v\n%s", mode, runErr, ctx.Err(), out)
					}
					probes, _ := os.ReadFile(filepath.Join(dir, "probes"))
					if !strings.Contains(string(probes), "-n -l -U "+fixture.user+" -- /usr/bin/") {
						t.Fatalf("missing command-specific sudo policy probe: %s\n%s", probes, out)
					}
					if mode == "delayed" && strings.Count(string(probes), "\n") != 3 {
						t.Fatalf("did not wait for the newly published rule: %s\n%s", probes, out)
					}
					calls, _ := os.ReadFile(filepath.Join(dir, "ssh-calls"))
					if notReady {
						if !strings.Contains(string(out), "SUDO_POLICY_NOT_READY") || strings.Contains(string(calls), "sudo -n") {
							t.Fatalf("missing policy must stop before authorization assertions with an actionable diagnostic\n%s\n%s", calls, out)
						}
					} else {
						if !strings.Contains(string(calls), "sudo -n") || strings.Contains(string(out), "SUDO_POLICY_NOT_READY") {
							t.Fatalf("readiness replaced the real SSH sudo allow/deny checks\n%s", out)
						}
						if !wantFailure && strings.Count(string(calls), "sudo -n") != 2 {
							t.Fatalf("must still exercise both allow and deny over SSH: %s", calls)
						}
					}
				})
			}
		})
	}
}

func TestRegression_FreeIPASudoPolicyReadinessTagScope(t *testing.T) {
	for _, file := range []string{"freeipa-hostauthz-sim.yml", "freeipa-audit-sim.yml"} {
		raw, err := os.ReadFile(filepath.Join("../../playbooks/test/fixtures", file))
		if err != nil {
			t.Fatal(err)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, value := range plays[0]["tasks"].([]any) {
			task := value.(map[string]any)
			include, _ := task["ansible.builtin.include_tasks"].(map[string]any)
			if include["file"] != "freeipa-sudo-policy-ready.yml" {
				continue
			}
			found = true
			tags, _ := yaml.Marshal(task["tags"])
			applied, _ := yaml.Marshal(include["apply"])
			if !strings.Contains(string(tags), "sim") || !strings.Contains(string(applied), "sim") {
				t.Errorf("%s: --tags sim must run both include and its tasks", file)
			}
			if file == "freeipa-hostauthz-sim.yml" && (!strings.Contains(string(tags), "positive") || !strings.Contains(string(applied), "positive") || strings.Contains(string(tags), "negative")) {
				t.Errorf("%s: policy readiness belongs to the positive sudo phase only", file)
			}
		}
		if !found {
			t.Errorf("%s has no bounded sudo policy readiness check", file)
		}
	}
}
