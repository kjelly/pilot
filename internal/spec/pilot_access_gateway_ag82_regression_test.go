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
// tests run the playbook's own config-read and AG82 tasks, extracted by name,
// on localhost against a temporary config and token files.

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

// gatewayTasks returns the playbook's tasks whose name keep accepts, in
// playbook order, made runnable by an unprivileged user on localhost: copy
// and file tasks lose owner/group, and a systemd task becomes a debug task
// printing "SYSTEMD <unit> <state>" under the same when:, so a test sees
// whether the playbook would have restarted the service.
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
		out = append(out, c)
	}
	return out
}

func isGatewayConfigRead(name string) bool {
	return strings.HasPrefix(name, "Recording policy: stat the currently installed") ||
		strings.HasPrefix(name, "Recording policy: read the currently installed") ||
		strings.HasPrefix(name, "Recording policy: extract the installed")
}

// gatewayAG82Tasks returns the tasks that read the installed config and the
// AG82 tasks, in playbook order.
func gatewayAG82Tasks(t *testing.T) []any {
	t.Helper()
	out := gatewayTasks(t, func(name string) bool { return isGatewayConfigRead(name) || strings.Contains(name, "AG82") })
	if len(out) < 4 {
		t.Fatalf("found %d config-read/AG82 tasks in %s, want at least 4", len(out), gatewayApplyPath)
	}
	return out
}

type ag82Run struct {
	rc       int
	failures []string
	messages []string
	// items lists, per task name, the loop items that were not skipped.
	items map[string][]string
	raw   string
}

// gatewayTestPaths points the playbook's files into dir, the test's
// /etc/pilot (and /run for the activation marker).
func gatewayTestPaths(dir string) map[string]any {
	return map[string]any{
		"gateway_config_file":                     filepath.Join(dir, "access-gateway.yaml"),
		"gateway_legacy_session_store_token_file": filepath.Join(dir, "session-store-ingest-token"),
		"gateway_session_store_signing_key_file":  filepath.Join(dir, "session-store-ingest-signing.key"),
		"gateway_keytab_file":                     filepath.Join(dir, "pilot-access-gateway.keytab"),
		"gateway_legacy_token_pending_file":       filepath.Join(dir, "session-store-legacy-token-files.pending"),
		"gateway_activation_pending_marker":       filepath.Join(dir, "apply-pending"),
	}
}

// runGatewayAG82 runs the extracted tasks with dir as the gateway's /etc/pilot.
func runGatewayAG82(t *testing.T, dir string, extra map[string]any, args ...string) ag82Run {
	t.Helper()
	return runGatewayTasks(t, dir, gatewayAG82Tasks(t), gatewayTestPaths(dir), extra, args...)
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
	res := ag82Run{raw: string(out), items: map[string][]string{}}
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
	for _, tags := range []string{"", "AG82"} {
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
	if strings.Contains(res.raw, `"changed": true`) {
		t.Errorf("a fresh host must report no change:\n%s", res.raw)
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

// gatewayActivationTasks are the tasks between reading the installed config
// and AG82's removal that decide what a run writes and whether the gateway
// is restarted: the config read, AG82, the activation marker, Step 11,
// AG81 and the service restart (a debug observer, see gatewayTasks). fail
// is inserted after AG81 when injectFailure is set.
func gatewayActivationTasks(t *testing.T, injectFailure bool) []any {
	t.Helper()
	tasks := gatewayTasks(t, func(name string) bool {
		return isGatewayConfigRead(name) || strings.Contains(name, "AG82") ||
			strings.HasPrefix(name, "Activation: ") ||
			name == "Step 11: install access-gateway.yaml" ||
			name == "Install the session-store ingest signing key (AG81)" ||
			strings.HasPrefix(name, "Restart pilot-access-gateway.service")
	})
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
