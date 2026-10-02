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

// gatewayAG82Tasks returns the tasks that read the installed config and the
// AG82 tasks, in playbook order.
func gatewayAG82Tasks(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile(gatewayApplyPath)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	var out []any
	for _, task := range plays[0]["tasks"].([]any) {
		name, _ := task.(map[string]any)["name"].(string)
		if strings.HasPrefix(name, "Recording policy: stat the currently installed") ||
			strings.HasPrefix(name, "Recording policy: read the currently installed") ||
			strings.HasPrefix(name, "Recording policy: extract the installed") ||
			strings.Contains(name, "AG82") {
			out = append(out, task)
		}
	}
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

// runGatewayAG82 runs the extracted tasks with dir as the gateway's /etc/pilot.
func runGatewayAG82(t *testing.T, dir string, extra map[string]any, args ...string) ag82Run {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	vars := map[string]any{
		"gateway_config_file":                     filepath.Join(dir, "access-gateway.yaml"),
		"gateway_legacy_session_store_token_file": filepath.Join(dir, "session-store-ingest-token"),
		"gateway_session_store_signing_key_file":  filepath.Join(dir, "session-store-ingest-signing.key"),
		"gateway_keytab_file":                     filepath.Join(dir, "pilot-access-gateway.keytab"),
	}
	for k, v := range extra {
		vars[k] = v
	}
	play := []map[string]any{{
		"name": "AG82 tasks", "hosts": "localhost", "connection": "local",
		"gather_facts": false, "become": false, "vars": vars, "tasks": gatewayAG82Tasks(t),
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
