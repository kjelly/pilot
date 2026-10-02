package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// AG82 removes the gateway's former static session-store bearer token.
// Before per-session tokens, the operator chose that file's path
// (pilot_access_gateway_recording_session_store_ingest_token_file) and the
// playbook wrote it into the gateway config as
// gateway.recording.session_store_ingest_token_file. AG82 used to remove only
// the documented default path, so an upgrade from a gateway whose config
// named another path left the secret on disk while AG82 still passed. These
// tests run the playbook's own tasks from the config read to AG82's removal
// (gatewayActivationTasks), extracted by name in playbook order, on localhost
// against a temporary config and token files.

const gatewayApplyPath = "../../playbooks/apply/pilot-access-gateway-apply.yml"

// gatewayPlay returns the gateway playbook's play vars and tasks.
func gatewayPlay(t *testing.T) (map[string]any, []any) {
	t.Helper()
	raw, err := os.ReadFile(gatewayApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	vars, _ := plays[0]["vars"].(map[string]any)
	return vars, plays[0]["tasks"].([]any)
}

// gatewayAG82HealthTask asks the running gateway for /v1/health before
// AG82 removes anything; gatewayTasks runs ag82_test_health_cmd instead.
const gatewayAG82HealthTask = "AG82: the gateway answers its health check"

// gatewayTasks returns the playbook's tasks whose name keep accepts, in
// playbook order, made runnable by an unprivileged user on localhost: copy
// and file tasks lose owner/group, a systemd task becomes a debug task
// printing "SYSTEMD <unit> <state>" under the same when:, so a test sees
// whether the playbook would have restarted the service, and AG82's health
// probe runs ag82_test_health_cmd.
func gatewayTasks(t *testing.T, keep func(name string) bool) []any {
	t.Helper()
	_, all := gatewayPlay(t)
	var out []any
	for _, raw := range all {
		task := raw.(map[string]any)
		name, _ := task["name"].(string)
		if !keep(name) {
			continue
		}
		c := map[string]any{}
		for k, v := range task {
			c[k] = v
		}
		for _, mod := range []string{"ansible.builtin.copy", "ansible.builtin.file"} {
			if args, ok := c[mod].(map[string]any); ok {
				a := map[string]any{}
				for k, v := range args {
					if k != "owner" && k != "group" {
						a[k] = v
					}
				}
				c[mod] = a
			}
		}
		if args, ok := c["ansible.builtin.systemd"].(map[string]any); ok {
			delete(c, "ansible.builtin.systemd")
			c["ansible.builtin.debug"] = map[string]any{"msg": fmt.Sprintf("SYSTEMD %v %v", args["name"], args["state"])}
		}
		if name == gatewayAG82HealthTask {
			c["ansible.builtin.command"] = map[string]any{"argv": "{{ ag82_test_health_cmd }}"}
		}
		out = append(out, c)
	}
	return out
}

type ag82Run struct {
	rc       int
	failures []string
	messages []string
	// items lists, per task name, the loop items that were not skipped.
	items map[string][]string
	// changed lists the tasks that reported a change.
	changed map[string]bool
	raw     string
}

// gatewayHealthy and gatewayUnhealthy are ag82_test_health_cmd values: a
// gateway answering /v1/health, and curl failing to connect.
var (
	gatewayHealthy   = []any{"printf", "%s", `{"status":"ok"}`}
	gatewayUnhealthy = []any{"sh", "-c", "echo 'curl: (7) Failed to connect' >&2; exit 7"}
)

// gatewayTestPaths points the playbook's files into dir, the test's
// /etc/pilot (and /run for the activation marker).
func gatewayTestPaths(dir string) map[string]any {
	return map[string]any{
		"ag82_test_health_cmd":                    gatewayHealthy,
		"gateway_config_file":                     filepath.Join(dir, "access-gateway.yaml"),
		"gateway_legacy_session_store_token_file": filepath.Join(dir, "session-store-ingest-token"),
		"gateway_session_store_signing_key_file":  filepath.Join(dir, "session-store-ingest-signing.key"),
		"gateway_keytab_file":                     filepath.Join(dir, "pilot-access-gateway.keytab"),
		"gateway_legacy_token_pending_file":       filepath.Join(dir, "session-store-legacy-token-files.pending"),
		"gateway_activation_pending_marker":       filepath.Join(dir, "apply-pending"),
	}
}

// runGatewayAG82 runs gatewayActivationTasks with dir as the gateway's
// /etc/pilot.
func runGatewayAG82(t *testing.T, dir string, extra map[string]any, args ...string) ag82Run {
	t.Helper()
	return runGatewayTasks(t, dir, gatewayActivationTasks(t, false), gatewayActivationVars(t, dir), extra, args...)
}

// runGatewayTasks runs tasks on localhost with vars, then extra, as play
// vars.
func runGatewayTasks(t *testing.T, dir string, tasks []any, vars, extra map[string]any, args ...string) ag82Run {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	merged := map[string]any{}
	for k, v := range vars {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	play := []map[string]any{{
		"name": "gateway tasks", "hosts": "localhost", "connection": "local",
		"gather_facts": false, "become": false, "vars": merged, "tasks": tasks,
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(t.TempDir(), "ag82.yml")
	if err := os.WriteFile(pb, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", "localhost,", pb}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	out, runErr := cmd.Output()
	res := ag82Run{raw: string(out), items: map[string][]string{}, changed: map[string]bool{}}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed  bool `json:"failed"`
					Changed bool `json:"changed"`
					Msg     any  `json:"msg"`
					Results []struct {
						Skipped bool `json:"skipped"`
						Msg     any  `json:"msg"`
						Item    any  `json:"item"`
					} `json:"results"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				msg, _ := json.Marshal(h.Msg)
				if h.Changed {
					res.changed[task.Task.Name] = true
				}
				if h.Failed {
					res.failures = append(res.failures, task.Task.Name+": "+string(msg))
				} else if h.Msg != nil {
					res.messages = append(res.messages, task.Task.Name+": "+string(msg))
				}
				for _, r := range h.Results {
					if item, ok := r.Item.(string); ok && !r.Skipped {
						res.items[task.Task.Name] = append(res.items[task.Task.Name], item)
					}
					if !r.Skipped && r.Msg != nil {
						itemMsg, _ := json.Marshal(r.Msg)
						res.messages = append(res.messages, task.Task.Name+": "+string(itemMsg))
					}
				}
			}
		}
	}
	return res
}

// oldGatewayConfig is the recording section main's
// pilot-access-gateway-apply.yml (56080a8) renders with a session store,
// pointing at tokenFile.
func oldGatewayConfig(tokenFile string) string {
	return `gateway:
  id: gpu-01
  scope: gpu
  fqdn: gw.ipa.pilot.internal
  target_hostgroup: pilot-target-gpu
  socket_path: /run/pilot/access-gateway.sock
  portal_user_group: pilot-portal-users
  freeipa:
    servers:
      - ipa1.ipa.pilot.internal
    ca_file: /etc/ipa/ca.crt
    service_principal: pilot-access-gateway/gw.ipa.pilot.internal@IPA.PILOT.INTERNAL
    keytab: /etc/pilot/pilot-access-gateway.keytab
    request_timeout: 5s
  recording:
    mode: "terminal_output"
    failure_policy: "best_effort"
    session_store_url: "https://store.ipa.pilot.internal:8443"
    session_store_ingest_token_file: "` + tokenFile + `"
  transport:
    enabled: true
`
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestRegression_GatewayAG82RemovesTheConfiguredTokenFile(t *testing.T) {
	// --tags AG82 alone does not replace the old config, so it keeps the
	// token (TestRegression_GatewayAG82OnlyRunWaitsForTheGateway).
	for _, tags := range []string{"", "AG_config,AG_service"} {
		t.Run("tags="+tags, func(t *testing.T) {
			dir := t.TempDir()
			custom := filepath.Join(dir, "custom-ingest-token")
			def := filepath.Join(dir, "session-store-ingest-token")
			unrelated := filepath.Join(dir, "unrelated")
			signing := filepath.Join(dir, "session-store-ingest-signing.key")
			writeFiles(t, map[string]string{
				filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(custom),
				custom: "secret\n", def: "secret\n", unrelated: "keep\n", signing: "key\n",
			})
			var args []string
			if tags != "" {
				args = []string{"--tags", tags}
			}
			res := runGatewayAG82(t, dir, nil, args...)
			if res.rc != 0 {
				t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
			}
			if exists(custom) {
				t.Errorf("the token file the installed config named (%s) is still there", custom)
			}
			if exists(def) {
				t.Errorf("the default legacy token file is still there")
			}
			if !exists(unrelated) || !exists(signing) {
				t.Errorf("a file AG82 does not own was removed: unrelated=%v signing key=%v", exists(unrelated), exists(signing))
			}
		})
	}
}

func TestRegression_GatewayAG82FreshHostIsANoOp(t *testing.T) {
	dir := t.TempDir()
	unrelated := filepath.Join(dir, "unrelated")
	writeFiles(t, map[string]string{unrelated: "keep\n"})
	res := runGatewayAG82(t, dir, nil)
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
	}
	if !exists(unrelated) {
		t.Errorf("unrelated file removed on a host with no installed gateway config")
	}
	for name := range res.changed {
		if strings.Contains(name, "AG82") {
			t.Errorf("%s reported a change on a host with nothing to remove", name)
		}
	}
}

func TestRegression_GatewayAG82RemovesTheInventoryTokenFileAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	invToken := filepath.Join(dir, "inventory-token")
	// The installed config is already the new format: no token file in it.
	writeFiles(t, map[string]string{
		filepath.Join(dir, "access-gateway.yaml"): "gateway:\n  recording:\n    mode: \"terminal_output\"\n",
		invToken: "secret\n",
	})
	res := runGatewayAG82(t, dir, map[string]any{"pilot_access_gateway_recording_session_store_ingest_token_file": invToken})
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
	}
	if exists(invToken) {
		t.Errorf("the token file the inventory still names is still there")
	}
	if !strings.Contains(strings.Join(res.messages, "\n"), "is no longer") {
		t.Errorf("no message tells the operator the variable is unused:\n%v", res.messages)
	}
}

func TestRegression_GatewayAG82RefusesUnsafePaths(t *testing.T) {
	cases := []struct {
		name  string
		setup func(dir string) (configured, survivor string)
	}{
		{"relative path", func(dir string) (string, string) {
			f := filepath.Join(dir, "relative-token")
			writeFiles(t, map[string]string{f: "x\n"})
			return "relative-token", f
		}},
		{"path with ..", func(dir string) (string, string) {
			f := filepath.Join(dir, "dotdot-token")
			writeFiles(t, map[string]string{f: "x\n"})
			// Not filepath.Join: it would clean the "..".
			return dir + "/sub/../dotdot-token", f
		}},
		{"directory", func(dir string) (string, string) {
			d := filepath.Join(dir, "token-dir")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFiles(t, map[string]string{filepath.Join(d, "inner"): "x\n"})
			return d, filepath.Join(d, "inner")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			configured, survivor := tc.setup(dir)
			writeFiles(t, map[string]string{filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(configured)})
			res := runGatewayAG82(t, dir, nil)
			if res.rc == 0 {
				t.Fatalf("AG82 accepted %q; want a failure before anything is removed", configured)
			}
			if !strings.Contains(strings.Join(res.failures, "\n"), "Refusing to remove") {
				t.Errorf("failure does not say why:\n%v", res.failures)
			}
			// The message names the refused path (a '\\.' regex inside the
			// fail_msg template listed none, PR #19).
			if tc.name != "directory" && !strings.Contains(strings.Join(res.failures, "\n"), configured) {
				t.Errorf("failure does not name %q:\n%v", configured, res.failures)
			}
			if !exists(survivor) {
				t.Errorf("%s was removed", survivor)
			}
		})
	}
}

func TestRegression_GatewayAG82KeepsFilesThePlaybookManages(t *testing.T) {
	dir := t.TempDir()
	signing := filepath.Join(dir, "session-store-ingest-signing.key")
	writeFiles(t, map[string]string{
		filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(signing),
		signing: "key\n",
	})
	res := runGatewayAG82(t, dir, nil)
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
	}
	if !exists(signing) {
		t.Errorf("AG82 removed the current signing key because the old config named the same path")
	}
}

// TestRegression_GatewayAG82KeepsAliasesOfFilesThePlaybookManages: the old
// config may name a file the playbook manages now under another spelling
// (an extra slash, a "." segment, a symlinked directory). AG82 used to
// compare raw strings, so such a path was not excluded and the cleanup
// deleted the signing key AG81 had just installed (PR #19 review). Each
// managed file must survive, while the distinct default legacy token in
// the same run is removed.
func TestRegression_GatewayAG82KeepsAliasesOfFilesThePlaybookManages(t *testing.T) {
	managed := map[string]string{
		"config":      "access-gateway.yaml",
		"signing key": "session-store-ingest-signing.key",
		"keytab":      "pilot-access-gateway.keytab",
	}
	aliases := map[string]func(dir, name string) string{
		"double slash":         func(dir, name string) string { return dir + "//" + name },
		"dot segment":          func(dir, name string) string { return dir + "/./" + name },
		"leading double slash": func(dir, name string) string { return "/" + dir + "/" + name },
		"symlinked directory":  func(dir, name string) string { return dir + "/link/" + name },
	}
	for what, name := range managed {
		for form, alias := range aliases {
			t.Run(what+"/"+form, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Symlink(".", filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				config := filepath.Join(dir, "access-gateway.yaml")
				def := filepath.Join(dir, "session-store-ingest-token")
				files := map[string]string{
					config: oldGatewayConfig(alias(dir, name)),
					def:    "secret\n",
					filepath.Join(dir, "session-store-ingest-signing.key"): "key\n",
					filepath.Join(dir, "pilot-access-gateway.keytab"):      "keytab\n",
				}
				writeFiles(t, files)
				res := runGatewayAG82(t, dir, nil)
				if res.rc != 0 {
					t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
				}
				for path := range files {
					if path == def {
						continue
					}
					if !exists(path) {
						t.Errorf("AG82 removed %s: the old config named it as %s", path, alias(dir, name))
					}
				}
				if exists(def) {
					t.Errorf("the default legacy token file is still there")
				}
				// Only a symlinked directory needs the file identity check;
				// the other spellings are normalized away before it.
				if form == "symlinked directory" && !strings.Contains(strings.Join(res.messages, "\n"), "Not removing") {
					t.Errorf("no message says why %s was kept:\n%v", alias(dir, name), res.messages)
				}
			})
		}
	}
}

// TestRegression_GatewayAG82RemovesASymlinkToAManagedFile: a former token
// path that is itself a symlink to a managed file names the link, not the
// file; removing it leaves the managed file in place.
func TestRegression_GatewayAG82RemovesASymlinkToAManagedFile(t *testing.T) {
	dir := t.TempDir()
	signing := filepath.Join(dir, "session-store-ingest-signing.key")
	link := filepath.Join(dir, "old-token-link")
	writeFiles(t, map[string]string{
		filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(link),
		signing: "key\n",
	})
	if err := os.Symlink(signing, link); err != nil {
		t.Fatal(err)
	}
	res := runGatewayAG82(t, dir, nil)
	if res.rc != 0 {
		t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
	}
	if exists(link) {
		t.Errorf("the former token symlink %s is still there", link)
	}
	if !exists(signing) {
		t.Errorf("AG82 removed the signing key the former token symlink pointed at")
	}
}

// TestRegression_GatewayAG82NormalizesPathsBeforeComparing: "//", "/./"
// and a trailing "/" are removed before the managed files are subtracted,
// so such a path never reaches stat or the removal loop, even when the
// managed file does not exist yet (the identity check needs it on disk).
// The normalization once used '\\.' in a template, which ansible-core 2.19
// keeps as two backslashes: "/./" was never collapsed and only the
// identity check caught it (PR #19).
func TestRegression_GatewayAG82NormalizesPathsBeforeComparing(t *testing.T) {
	for _, form := range []string{"%s//%s", "%s/./%s", "%s/././%s", "/%s/%s"} {
		t.Run(form, func(t *testing.T) {
			dir := t.TempDir()
			alias := fmt.Sprintf(form, dir, "session-store-ingest-signing.key")
			def := filepath.Join(dir, "session-store-ingest-token")
			writeFiles(t, map[string]string{
				filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(alias),
				def: "secret\n",
			})
			res := runGatewayAG82(t, dir, nil)
			if res.rc != 0 {
				t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
			}
			const stat = "AG82: stat the former token files"
			if got := res.items[stat]; len(got) != 1 || got[0] != def {
				t.Errorf("%s items = %q, want only %s (%s is the signing key)", stat, got, def, alias)
			}
		})
	}
	t.Run("trailing slash", func(t *testing.T) {
		dir := t.TempDir()
		custom := filepath.Join(dir, "custom-ingest-token")
		writeFiles(t, map[string]string{
			filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(custom + "/"),
		})
		res := runGatewayAG82(t, dir, nil)
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
		}
		const stat = "AG82: stat the former token files"
		want := []string{filepath.Join(dir, "session-store-ingest-token"), custom}
		got := append([]string(nil), res.items[stat]...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s items = %q, want %q", stat, got, want)
		}
	})
}

// gatewayActivationTasks are the tasks from reading the installed config to
// AG82's removal that decide what a run writes, whether the gateway is
// restarted and what is removed: the config read and the recording policy
// guard, AG82, the activation marker, Step 11, AG81, the socket and service
// restarts (debug observers, see gatewayTasks) and AG82's health probe (a
// stub). Left out are the tasks that need the real host (ssh_config, ipa,
// binaries, unit files, Step 17's curl). fail is inserted after AG81 when
// injectFailure is set.
func gatewayActivationTasks(t *testing.T, injectFailure bool) []any {
	t.Helper()
	tasks := gatewayTasks(t, func(name string) bool {
		return strings.HasPrefix(name, "Recording policy: ") || strings.Contains(name, "AG82") ||
			strings.HasPrefix(name, "Activation: ") ||
			name == "Step 11: install access-gateway.yaml" ||
			strings.HasSuffix(name, "(AG81)") ||
			strings.HasPrefix(name, "Restart pilot-access-gateway.")
	})
	if len(tasks) < 25 {
		t.Fatalf("found %d tasks in %s, want at least 25", len(tasks), gatewayApplyPath)
	}
	if !injectFailure {
		return tasks
	}
	var out []any
	for _, task := range tasks {
		out = append(out, task)
		if task.(map[string]any)["name"] == "Install the session-store ingest signing key (AG81)" {
			out = append(out, map[string]any{"name": "injected failure after AG81", "ansible.builtin.fail": map[string]any{"msg": "injected"}})
		}
	}
	return out
}

// gatewayActivationVars are the playbook's own play vars with the paths
// moved into dir and the facts the pre_tasks would set.
func gatewayActivationVars(t *testing.T, dir string) map[string]any {
	t.Helper()
	playVars, _ := gatewayPlay(t)
	vars := map[string]any{}
	for k, v := range playVars {
		vars[k] = v
	}
	for k, v := range gatewayTestPaths(dir) {
		vars[k] = v
	}
	for k, v := range map[string]any{
		"gateway_id": "gpu-01", "gateway_scope": "gpu",
		"gateway_effective_fqdn":                           "gw.ipa.pilot.internal",
		"gateway_effective_portal_user_group":              "pilot-portal-users",
		"gateway_effective_freeipa_servers":                []any{"ipa1.ipa.pilot.internal"},
		"gateway_effective_ipa_realm":                      "IPA.PILOT.INTERNAL",
		"gateway_metrics_textfile_path":                    "",
		"pilot_access_gateway_recording_mode":              "terminal_output",
		"pilot_access_gateway_recording_session_store_url": "https://store.ipa.pilot.internal:8443",
		"pilot_session_store_ingest_signing_key":           strings.Repeat("ab", 32),
	} {
		vars[k] = v
	}
	return vars
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func restarted(res ag82Run) bool {
	return strings.Contains(strings.Join(res.messages, "\n"), "SYSTEMD pilot-access-gateway.service restarted")
}

// TestRegression_GatewayAG82RefusalChangesNothingAndTheRetryActivates: AG82
// used to refuse a bad former token path only after Step 11 and AG81 had
// replaced the config and the key. The replaced config no longer named the
// custom token, so a retry succeeded without removing it, and with the
// config and key unchanged it did not restart the gateway either (PR #19
// review). Now the refusal comes first: nothing changes, and the corrected
// retry removes the token and restarts the gateway.
func TestRegression_GatewayAG82RefusalChangesNothingAndTheRetryActivates(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "access-gateway.yaml")
	key := filepath.Join(dir, "session-store-ingest-signing.key")
	custom := filepath.Join(dir, "custom-token")
	oldConfig := oldGatewayConfig(dir + "/sub/../custom-token")
	writeFiles(t, map[string]string{config: oldConfig, key: "old-key\n", custom: "secret\n"})
	vars := gatewayActivationVars(t, dir)

	first := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
	if first.rc == 0 || !strings.Contains(strings.Join(first.failures, "\n"), "Refusing to remove") {
		t.Fatalf("first run: rc=%d failures=%v, want the \"..\" refusal", first.rc, first.failures)
	}
	if got := readString(t, config); got != oldConfig {
		t.Errorf("the refused run replaced the config:\n%s", got)
	}
	if got := readString(t, key); got != "old-key\n" {
		t.Errorf("the refused run replaced the signing key")
	}
	if !exists(custom) || restarted(first) {
		t.Errorf("the refused run removed the token (%v) or restarted the gateway (%v)", !exists(custom), restarted(first))
	}

	// The operator fixes the path in the installed config.
	writeFiles(t, map[string]string{config: oldGatewayConfig(custom)})
	second := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
	if second.rc != 0 {
		t.Fatalf("corrected retry: rc=%d failures=%v", second.rc, second.failures)
	}
	if strings.Contains(readString(t, config), "session_store_ingest_token_file") {
		t.Errorf("the retry did not install the new config")
	}
	if got := readString(t, key); got != strings.Repeat("ab", 32)+"\n" {
		t.Errorf("the retry did not install the signing key")
	}
	if exists(custom) {
		t.Errorf("the retry left the custom token %s", custom)
	}
	if !restarted(second) {
		t.Errorf("the retry changed the config and key but did not restart the gateway:\n%v", second.messages)
	}

	third := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
	if third.rc != 0 || restarted(third) || strings.Contains(third.raw, `"changed": true`) {
		t.Errorf("third run: rc=%d restarted=%v, want rc 0, no restart, no change", third.rc, restarted(third))
	}
	for _, f := range []string{vars["gateway_legacy_token_pending_file"].(string), vars["gateway_activation_pending_marker"].(string)} {
		if exists(f) {
			t.Errorf("%s is left after a successful run", f)
		}
	}
}

// TestRegression_GatewayAG82FailedRunIsFinishedByTheRetry: a run that fails
// after Step 11 and AG81 wrote the new config and key must not lose either
// the former token path the old config named or the pending restart.
func TestRegression_GatewayAG82FailedRunIsFinishedByTheRetry(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "access-gateway.yaml")
	key := filepath.Join(dir, "session-store-ingest-signing.key")
	custom := filepath.Join(dir, "custom-token")
	writeFiles(t, map[string]string{config: oldGatewayConfig(custom), key: "old-key\n", custom: "secret\n"})
	vars := gatewayActivationVars(t, dir)
	pending := vars["gateway_legacy_token_pending_file"].(string)
	marker := vars["gateway_activation_pending_marker"].(string)

	failed := runGatewayTasks(t, dir, gatewayActivationTasks(t, true), vars, nil)
	if failed.rc == 0 {
		t.Fatal("the injected failure did not fail the run")
	}
	if strings.Contains(readString(t, config), "session_store_ingest_token_file") {
		t.Fatalf("Step 11 did not run before the injected failure")
	}
	listed := exists(pending) && strings.Contains(readString(t, pending), custom)
	if !exists(custom) || !listed || !exists(marker) {
		t.Fatalf("after the failed run: token kept=%v pending list names it=%v marker=%v, want all three",
			exists(custom), listed, exists(marker))
	}

	retry := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
	if retry.rc != 0 {
		t.Fatalf("retry: rc=%d failures=%v", retry.rc, retry.failures)
	}
	if !restarted(retry) {
		t.Errorf("the retry found the config and key already written and did not restart the gateway")
	}
	if exists(custom) {
		t.Errorf("the retry did not remove %s, which only the pending list still named", custom)
	}
	if exists(pending) || exists(marker) {
		t.Errorf("records left after the retry: pending=%v marker=%v", exists(pending), exists(marker))
	}

	again := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
	if again.rc != 0 || restarted(again) || strings.Contains(again.raw, `"changed": true`) {
		t.Errorf("run after the retry: rc=%d restarted=%v, want rc 0, no restart, no change", again.rc, restarted(again))
	}
}

// gatewayTaskTags returns the tags of the playbook task named name.
func gatewayTaskTags(t *testing.T, name string) []string {
	t.Helper()
	_, tasks := gatewayPlay(t)
	for _, raw := range tasks {
		task := raw.(map[string]any)
		if task["name"] != name {
			continue
		}
		var tags []string
		for _, tag := range task["tags"].([]any) {
			tags = append(tags, tag.(string))
		}
		return tags
	}
	t.Fatalf("no task %q in %s", name, gatewayApplyPath)
	return nil
}

const gatewayStep11 = "Step 11: install access-gateway.yaml"

// gatewayConfigWriteTags are the tags that select Step 11.
func gatewayConfigWriteTags(t *testing.T) []string {
	t.Helper()
	tags := gatewayTaskTags(t, gatewayStep11)
	if len(tags) < 5 {
		t.Fatalf("Step 11 tags = %v, want at least AG_config, AG01, AG41, AG42, AG94", tags)
	}
	return tags
}

func missingTags(have, want []string) []string {
	set := map[string]bool{}
	for _, tag := range have {
		set[tag] = true
	}
	var missing []string
	for _, tag := range want {
		if !set[tag] {
			missing = append(missing, tag)
			set[tag] = true
		}
	}
	return missing
}

// TestRegression_GatewayWritesFollowTheirChecks: every tag that selects a
// write must also select what has to run before it. Step 11 had AG94 and
// AG81's key tasks had AG81 while the recording policy guard had neither,
// so `--tags AG94` rewrote and `--tags AG81` removed the key without the
// downgrade refusal. AG82's cleanup source had only AG82, so `--tags AG01`
// replaced the config that named a custom token without recording the path
// (PR #19 review of 25c423e).
func TestRegression_GatewayWritesFollowTheirChecks(t *testing.T) {
	config := gatewayConfigWriteTags(t)
	key := append(gatewayTaskTags(t, "Install the session-store ingest signing key (AG81)"),
		gatewayTaskTags(t, "Remove the session-store ingest signing key when no store is configured (AG81)")...)
	var units []string
	for _, name := range []string{"Step 10: install pilot-access-gateway binary", "Step 15: install pilot-access-gateway.socket", "Step 15: install pilot-access-gateway.service"} {
		units = append(units, gatewayTaskTags(t, name)...)
	}
	_, tasks := gatewayPlay(t)
	beforeStep11 := true
	checked := 0
	for _, raw := range tasks {
		name, _ := raw.(map[string]any)["name"].(string)
		if name == gatewayStep11 {
			beforeStep11 = false
		}
		var want []string
		switch {
		case strings.HasPrefix(name, "Recording policy: "):
			want = append(append([]string{}, config...), key...)
		case beforeStep11 && strings.HasPrefix(name, "AG82: "):
			want = config
		case strings.HasPrefix(name, "Activation: ") && !strings.HasPrefix(name, "Activation: the gateway runs") && !strings.HasPrefix(name, "Activation: no restart"):
			want = append(append(append([]string{}, config...), key...), units...)
		default:
			continue
		}
		checked++
		if missing := missingTags(gatewayTaskTags(t, name), want); len(missing) > 0 {
			t.Errorf("%q lacks %v: those tags select a write that must follow it", name, missing)
		}
	}
	if checked < 16 {
		t.Errorf("checked %d tasks, want at least 16 (5 recording policy, 9 AG82, 3 activation)", checked)
	}
}

// TestRegression_GatewayAG82TagScopedConfigWriteKeepsTheToken: a run with a
// tag that selects Step 11 replaces the old config that named a custom
// token, without restarting the gateway. It must record the path and keep
// the token; the next full apply restarts the gateway and removes it. On
// 25c423e, `--tags AG01` recorded nothing, so the full apply left the token
// for good, and `--tags AG_config` removed it while the old gateway still
// ran (PR #19 review).
func TestRegression_GatewayAG82TagScopedConfigWriteKeepsTheToken(t *testing.T) {
	for _, tag := range gatewayConfigWriteTags(t) {
		t.Run(tag, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			config := filepath.Join(dir, "access-gateway.yaml")
			custom := filepath.Join(dir, "custom-token")
			writeFiles(t, map[string]string{config: oldGatewayConfig(custom), custom: "secret\n",
				filepath.Join(dir, "session-store-ingest-signing.key"): "old-key\n"})
			vars := gatewayActivationVars(t, dir)
			pending := vars["gateway_legacy_token_pending_file"].(string)
			marker := vars["gateway_activation_pending_marker"].(string)

			first := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil, "--tags", tag)
			if first.rc != 0 {
				t.Fatalf("--tags %s: rc=%d failures=%v", tag, first.rc, first.failures)
			}
			if strings.Contains(readString(t, config), "session_store_ingest_token_file") {
				t.Fatalf("--tags %s did not replace the config", tag)
			}
			listed := exists(pending) && strings.Contains(readString(t, pending), custom)
			if !exists(custom) || !listed || !exists(marker) || restarted(first) {
				t.Fatalf("after --tags %s: token kept=%v pending list names it=%v marker=%v restarted=%v; want kept, listed, marker, no restart",
					tag, exists(custom), listed, exists(marker), restarted(first))
			}
			if tag == "AG_config" && !strings.Contains(strings.Join(first.messages, "\n"), "restart of pilot-access-gateway is pending") {
				t.Errorf("--tags AG_config kept the token without saying why:\n%v", first.messages)
			}

			full := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
			if full.rc != 0 {
				t.Fatalf("full apply: rc=%d failures=%v", full.rc, full.failures)
			}
			if !restarted(full) || exists(custom) || exists(pending) || exists(marker) {
				t.Errorf("full apply after --tags %s: restarted=%v token left=%v pending left=%v marker left=%v",
					tag, restarted(full), exists(custom), exists(pending), exists(marker))
			}

			again := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), vars, nil)
			if again.rc != 0 || restarted(again) || len(again.changed) > 0 {
				t.Errorf("run after the full apply: rc=%d restarted=%v changed=%v", again.rc, restarted(again), again.changed)
			}
		})
	}
}

// TestRegression_GatewayAG82OnlyRunWaitsForTheGateway: `--tags AG82` writes
// neither the config nor restarts the gateway, so it removes former token
// files only when the gateway runs a config that names none and answers
// its health check. Before, it removed them right after recording them,
// whatever the gateway still ran.
func TestRegression_GatewayAG82OnlyRunWaitsForTheGateway(t *testing.T) {
	t.Run("old config still installed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		custom := filepath.Join(dir, "custom-token")
		def := filepath.Join(dir, "session-store-ingest-token")
		writeFiles(t, map[string]string{filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(custom),
			custom: "secret\n", def: "secret\n"})
		res := runGatewayAG82(t, dir, nil, "--tags", "AG82")
		if res.rc != 0 {
			t.Fatalf("rc=%d failures=%v", res.rc, res.failures)
		}
		if !exists(custom) || !exists(def) {
			t.Errorf("--tags AG82 removed a token while the installed config still names %s: custom=%v default=%v", custom, exists(custom), exists(def))
		}
		if msgs := strings.Join(res.messages, "\n"); !strings.Contains(msgs, "still names "+custom) {
			t.Errorf("no message says why the files were kept:\n%s", msgs)
		}
		full := runGatewayAG82(t, dir, nil)
		if full.rc != 0 || exists(custom) || exists(def) {
			t.Errorf("full apply: rc=%d custom left=%v default left=%v", full.rc, exists(custom), exists(def))
		}
	})

	t.Run("restart pending", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		custom := filepath.Join(dir, "custom-token")
		writeFiles(t, map[string]string{filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(custom), custom: "secret\n"})
		if res := runGatewayAG82(t, dir, nil, "--tags", "AG01"); res.rc != 0 {
			t.Fatalf("--tags AG01: rc=%d failures=%v", res.rc, res.failures)
		}
		res := runGatewayAG82(t, dir, nil, "--tags", "AG82")
		if res.rc != 0 {
			t.Fatalf("--tags AG82: rc=%d failures=%v", res.rc, res.failures)
		}
		if !exists(custom) {
			t.Errorf("--tags AG82 removed %s before the pending restart", custom)
		}
		if msgs := strings.Join(res.messages, "\n"); !strings.Contains(msgs, "restart of pilot-access-gateway is pending") {
			t.Errorf("no message says why the token was kept:\n%s", msgs)
		}
	})

	t.Run("health check fails", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFiles(t, map[string]string{filepath.Join(dir, "access-gateway.yaml"): oldGatewayConfig(filepath.Join(dir, "none"))})
		if res := runGatewayAG82(t, dir, nil); res.rc != 0 {
			t.Fatalf("install: rc=%d failures=%v", res.rc, res.failures)
		}
		def := filepath.Join(dir, "session-store-ingest-token")
		pending := filepath.Join(dir, "session-store-legacy-token-files.pending")
		writeFiles(t, map[string]string{def: "secret\n"})
		down := runGatewayAG82(t, dir, map[string]any{"ag82_test_health_cmd": gatewayUnhealthy}, "--tags", "AG82")
		if down.rc != 0 {
			t.Fatalf("--tags AG82 with the gateway down: rc=%d failures=%v", down.rc, down.failures)
		}
		if !exists(def) || !exists(pending) {
			t.Errorf("with the gateway down: token kept=%v pending list kept=%v, want both", exists(def), exists(pending))
		}
		if msgs := strings.Join(down.messages, "\n"); !strings.Contains(msgs, "did not pass its health check") || !strings.Contains(msgs, "Failed to connect") {
			t.Errorf("no message says the health check failed:\n%s", msgs)
		}
		up := runGatewayAG82(t, dir, nil, "--tags", "AG82")
		if up.rc != 0 || exists(def) || exists(pending) {
			t.Errorf("--tags AG82 with the gateway up: rc=%d token left=%v pending left=%v", up.rc, exists(def), exists(pending))
		}
	})
}

// TestRegression_GatewayRecordingGuardRunsForEveryWriteTag: lowering the
// recording policy is refused under every tag that writes the config or the
// signing key, and nothing is changed. On 25c423e, `--tags AG94` installed
// the lowered config and `--tags AG81` removed the signing key.
func TestRegression_GatewayRecordingGuardRunsForEveryWriteTag(t *testing.T) {
	tags := append(gatewayConfigWriteTags(t), "AG81")
	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			config := filepath.Join(dir, "access-gateway.yaml")
			key := filepath.Join(dir, "session-store-ingest-signing.key")
			old := oldGatewayConfig(filepath.Join(dir, "none"))
			writeFiles(t, map[string]string{config: old, key: "old-key\n"})
			lowered := map[string]any{"pilot_access_gateway_recording_mode": "metadata", "pilot_access_gateway_recording_session_store_url": ""}
			res := runGatewayTasks(t, dir, gatewayActivationTasks(t, false), gatewayActivationVars(t, dir), lowered, "--tags", tag)
			if res.rc == 0 || !strings.Contains(strings.Join(res.failures, "\n"), "Refusing to lower") {
				t.Errorf("--tags %s with a lowered policy: rc=%d failures=%v, want the downgrade refusal", tag, res.rc, res.failures)
			}
			if readString(t, config) != old || !exists(key) || readString(t, key) != "old-key\n" {
				t.Errorf("--tags %s changed the config or the key while lowering the policy", tag)
			}
		})
	}
}
