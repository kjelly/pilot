package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeSSH installs a stand-in for /usr/bin/ssh that replays a real
// capture (internal/loginprobe/testdata/capture) for the host named in its
// argv, so the CLI is exercised from its real entry point (AGENTS.md §5.15)
// without a network.
func writeFakeSSH(t *testing.T, dir string) string {
	t.Helper()
	captures, err := filepath.Abs("../../internal/loginprobe/testdata/capture")
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
for a in "$@"; do host_prev="$host"; host="$a"; done
# argv ends with "<host> <command>": the host is the second-to-last argument.
case "$host_prev" in
  ok.example.internal)     c=ok-ubuntu ;;
  denied.example.internal) c=account-hbac-disabled-ubuntu ;;
  *)                       c=transport-unresolvable ;;
esac
cat "` + captures + `/$c/stderr" >&2
rc=$(sed -n 's/^rc=//p' "` + captures + `/$c/meta")
exit "$rc"
`
	path := filepath.Join(dir, "ssh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeConfig(t *testing.T, dir, ssh string, targets ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("interval: 60s\nssh_binary: " + ssh + "\nssh_config: /dev/null\ntextfile: " + filepath.Join(dir, "out.prom") + "\ntargets:\n")
	for _, tg := range targets {
		b.WriteString("  - {name: " + strings.Split(tg, ".")[0] + ", host: " + tg + "}\n")
	}
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRun_ProbeExitCodesAndJSON(t *testing.T) {
	dir := t.TempDir()
	ssh := writeFakeSSH(t, dir)

	okCfg := writeConfig(t, dir, ssh, "ok.example.internal")
	var out, errOut bytes.Buffer
	if code := run([]string{"probe", "--config", okCfg, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("all-ok round: exit %d, stderr %q", code, errOut.String())
	}

	mixedCfg := writeConfig(t, dir, ssh, "ok.example.internal", "denied.example.internal", "gone.example.internal")
	out.Reset()
	errOut.Reset()
	code := run([]string{"probe", "--config", mixedCfg, "--json"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("a failing target must exit 2 (login-probe-apply.yml accepts 0/2 only), got %d; stderr %q", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("exit 2 must not print an error line, got %q", errOut.String())
	}
	var rows []probeOutput
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("probe --json is not JSON: %v\n%s", err, out.String())
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Target] = r.Stage
	}
	want := map[string]string{"ok": "ok", "denied": "account", "gone": "transport"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("target %s: stage %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestRun_ConfigErrorsExitOne(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(bad, []byte("intervall: 60s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"config", "validate", "--config", bad}, &out, &errOut); code != 1 {
		t.Fatalf("invalid config: exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "Error:") {
		t.Errorf("config error must be printed, got %q", errOut.String())
	}
	good := writeConfig(t, dir, "/usr/bin/ssh", "a.example.internal")
	out.Reset()
	if code := run([]string{"config", "validate", "--config", good}, &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != "config valid" {
		t.Fatalf("valid config: exit %d, stdout %q", code, out.String())
	}
}

func TestRun_VersionContract(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("version: exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "pilot-login-probe ") || !strings.Contains(out.String(), "(") {
		t.Errorf("version output %q does not match `pilot-login-probe <version> (<commit>)`", out.String())
	}
}
