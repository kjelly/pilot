package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeDiagnoseFixtureInventory writes a minimal ansible-inventory-parseable
// fixture with one host reachable via ansible_connection: local — the same
// pattern network_check_test.go uses so tests exercise the real
// ansible-inventory binary without needing any real SSH-reachable box.
func writeDiagnoseFixtureInventory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	inv := `all:
  hosts:
    web1: {ansible_connection: local, ansible_host: 127.0.0.1}
`
	path := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(path, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// diagnoseFakeRunner records every ad-hoc invocation and returns a canned
// ansible.posix.json doc keyed by the command string, so handler tests
// never depend on a real reachable host or real sssd/DNS state.
type diagnoseFakeRunner struct {
	byCommand map[string]func() (string, int, error)
	calls     []string
}

func (f *diagnoseFakeRunner) run(_ context.Context, args []string, _ int) (string, int, error) {
	command := args[len(args)-1]
	f.calls = append(f.calls, command)
	fn, ok := f.byCommand[command]
	if !ok {
		return "", 0, fmt.Errorf("no fake response configured for command %q", command)
	}
	return fn()
}

// writeDiagnoseGroupFixtureInventory writes a fixture inventory whose
// only non-"all" group is group, containing hosts (each reachable via
// ansible_connection: local, same as writeDiagnoseFixtureInventory) — used
// to exercise ResolveSingletonGroupHost's zero/one/many-host branches for
// pilot_diagnose_logs/metrics, which auto-resolve dashboard/thanos-query
// instead of taking a host parameter.
func writeDiagnoseGroupFixtureInventory(t *testing.T, group string, hosts []string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("all:\n  children:\n    ")
	b.WriteString(group)
	b.WriteString(":\n")
	if len(hosts) == 0 {
		b.WriteString("      hosts: {}\n")
	} else {
		b.WriteString("      hosts:\n")
		for _, h := range hosts {
			b.WriteString("        " + h + ": {ansible_connection: local, ansible_host: 127.0.0.1}\n")
		}
	}
	path := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func diagnoseOKDoc(t *testing.T, host string, rc int, stdout string) string {
	t.Helper()
	doc := map[string]any{
		"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
			host: map[string]any{"stdout": stdout, "rc": rc, "failed": rc != 0, "unreachable": false},
		}}}}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func baseDiagnoseOpts(t *testing.T, inventory string, runner diagnose.AdHocRunner) diagnoseMCPToolsOptions {
	t.Helper()
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return diagnoseMCPToolsOptions{
		Inventory:      inventory,
		AuditDir:       t.TempDir(),
		StepTimeout:    5 * time.Second,
		AnsibleRuntime: runtime,
		AdHocRunner:    runner,
	}
}

// ---- scopedDiagnoseAnsibleRuntime ---------------------------------------

// findEnv returns the value of the first entry in env with the given
// KEY= prefix, or "" if absent.
func findEnv(env []string, prefix string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv
		}
	}
	return ""
}

func TestScopedDiagnoseAnsibleRuntime_TwoCallsGetDistinctControlPaths(t *testing.T) {
	base, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	first := scopedDiagnoseAnsibleRuntime(base)
	second := scopedDiagnoseAnsibleRuntime(base)

	firstArgs := findEnv(first.Env, "ANSIBLE_SSH_ARGS=")
	secondArgs := findEnv(second.Env, "ANSIBLE_SSH_ARGS=")
	if firstArgs == "" || secondArgs == "" {
		t.Fatalf("expected both scoped runtimes to carry ANSIBLE_SSH_ARGS, got first=%q second=%q", firstArgs, secondArgs)
	}
	if firstArgs == secondArgs {
		t.Fatalf("two independent diagnose calls got the identical ANSIBLE_SSH_ARGS (%q) — concurrent calls to the same host would share one SSH ControlPath again", firstArgs)
	}
	if !strings.Contains(firstArgs, base.SSHControlDir) || !strings.Contains(secondArgs, base.SSHControlDir) {
		t.Fatalf("expected both ControlPaths to stay rooted under %q, got first=%q second=%q", base.SSHControlDir, firstArgs, secondArgs)
	}

	// Only ANSIBLE_SSH_ARGS should change — everything else base set up
	// (ANSIBLE_HOME, temp dir, fact cache, etc.) must survive untouched.
	for _, prefix := range []string{"ANSIBLE_HOME=", "ANSIBLE_LOCAL_TEMP=", "ANSIBLE_CACHE_PLUGIN_CONNECTION=", "ANSIBLE_LOG_PATH=", "ANSIBLE_FORKS="} {
		baseVal := findEnv(base.Env, prefix)
		scopedVal := findEnv(first.Env, prefix)
		if baseVal == "" || baseVal != scopedVal {
			t.Fatalf("expected %s to be preserved unchanged, base=%q scoped=%q", prefix, baseVal, scopedVal)
		}
	}
	if first.TempDir != base.TempDir || first.SSHControlDir != base.SSHControlDir {
		t.Fatalf("expected TempDir/SSHControlDir to be preserved, got %+v want TempDir=%q SSHControlDir=%q", first, base.TempDir, base.SSHControlDir)
	}

	// No duplicate ANSIBLE_SSH_ARGS entries — the old one must actually be
	// removed, not just shadowed by a second, later entry.
	var count int
	for _, kv := range first.Env {
		if strings.HasPrefix(kv, "ANSIBLE_SSH_ARGS=") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one ANSIBLE_SSH_ARGS entry, got %d in %v", count, first.Env)
	}
}

func TestResolveDiagnoseInventory_RefreshFailureIsNotSilentlyIgnored(t *testing.T) {
	// A bad sibling hosts.yml must not leave a live diagnostic using a stale
	// inventory whose hosts could now point to a different machine.
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    web1: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte("hosts: [not-a-map]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveDiagnoseInventory(withDeployAnsibleRuntime(context.Background(), runtime), diagnoseMCPToolsOptions{Inventory: inv, StepTimeout: time.Second, AnsibleRuntime: runtime})
	if err == nil || !strings.Contains(err.Error(), "refresh inventory") {
		t.Fatalf("resolveDiagnoseInventory() error = %v, want explicit refresh failure", err)
	}
}

func TestRealDiagnoseAdHocRunner_TimeoutReturnsWhenSSHChildKeepsPipesOpen(t *testing.T) {
	// Reproduce the failure mode behind a stuck MCP call: killing the direct
	// ansible process is insufficient when its ssh child still owns stdout.
	// The runner must return the context timeout after WaitDelay, rather than
	// wait for that descendant indefinitely.
	binDir := t.TempDir()
	ansible := filepath.Join(binDir, "ansible")
	if err := os.WriteFile(ansible, []byte("#!/bin/sh\nsleep 30 &\nwait\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	start := time.Now()
	_, _, err := realDiagnoseAdHocRunner()(context.Background(), []string{"web1"}, 1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runner error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("runner returned after %s, want bounded timeout (<= 5s)", elapsed)
	}
}

// ---- pilot_diagnose_sudo ------------------------------------------------

func TestDiagnoseSudoHandler_InvalidUserRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseSudoHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSudoInput{Host: "web1", User: "alice; rm -rf /"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an invalid user", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — invalid input must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseSudoHandler_UnknownHostRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseSudoHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSudoInput{Host: "doesnotexist", User: "alice"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an unknown host", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — an unknown host must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseSudoHandler_SuccessBuildsOutputAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active sssd":       func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
		"sudo klist -k /etc/krb5.keytab": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "host/web1@REALM"), 0, nil },
		"id alice":                       func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "uid=1000(alice)"), 0, nil },
		`sudo grep -qE "^access_provider *= *ipa" /etc/sssd/sssd.conf`: func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
		`grep -qE "^sudoers:.*sss" /etc/nsswitch.conf`:                 func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
		"sudo -l -U alice": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "(root) NOPASSWD: ALL"), 0, nil },
	}}
	handler := diagnoseSudoHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSudoInput{Host: "web1", User: "alice"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if !out.SssdActive || !out.HasKerberosMachineIdentity || !out.AccountResolvesViaSSSD ||
		!out.AccessProviderIsIPA || !out.SudoersRoutedThroughSSSD || !out.CentralSudoRuleGrantsAccess {
		t.Fatalf("out = %+v, want every fact true", out)
	}
	if len(out.Steps) != 6 {
		t.Fatalf("len(out.Steps) = %d, want 6", len(out.Steps))
	}
	if out.AuditDirectory == "" {
		t.Fatal("AuditDirectory is empty")
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "sudo" || rec.Host != "web1" || rec.Params["user"] != "alice" {
		t.Fatalf("audit record = %+v, want check=sudo host=web1 params.user=alice", rec)
	}
	if len(rec.Steps) != 6 {
		t.Fatalf("audit record has %d steps, want 6", len(rec.Steps))
	}
}

// ---- pilot_diagnose_dns ------------------------------------------------

func TestDiagnoseDNSHandler_InvalidNameRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseDNSHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseDNSInput{Host: "web1", Name: "not a valid name!"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an invalid name", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseDNSHandler_UnknownHostRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseDNSHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseDNSInput{Host: "doesnotexist"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an unknown host", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseDNSHandler_SuccessWithNameBuildsOutputAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		`awk 'NR==1{print $2}' /etc/resolv.conf`:                    func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5"), 0, nil },
		"systemctl is-active systemd-resolved":                      func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
		`ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`: func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "udp UNCONN 0 0 10.0.0.5:53"), 0, nil },
		`dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`: func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "1"), 0, nil
		},
		"getent hosts keycloak.infra.internal": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "10.0.0.5 keycloak.infra.internal"), 0, nil
		},
		"dig +short keycloak.infra.internal @127.0.0.1": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5"), 0, nil },
	}}
	handler := diagnoseDNSHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseDNSInput{Host: "web1", Name: "keycloak.infra.internal"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Nameserver != "10.0.0.5" || !out.SystemdResolvedActive || !out.LocalDaemonListening || !out.DNSDaemonInstalled {
		t.Fatalf("out = %+v, want all facts true/set", out)
	}
	if !out.ResolvesViaNSS || !out.ResolvesViaDirectQuery {
		t.Fatalf("out = %+v, want both resolution paths to succeed", out)
	}
	if len(out.Steps) != 6 {
		t.Fatalf("len(out.Steps) = %d, want 6", len(out.Steps))
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "dns" || rec.Params["name"] != "keycloak.infra.internal" {
		t.Fatalf("audit record = %+v, want check=dns params.name=keycloak.infra.internal", rec)
	}
}

func TestDiagnoseDNSHandler_SuccessWithoutNameOmitsNameSteps(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		`awk 'NR==1{print $2}' /etc/resolv.conf`:                    func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "127.0.0.1"), 0, nil },
		"systemctl is-active systemd-resolved":                      func() (string, int, error) { return diagnoseOKDoc(t, "web1", 3, ""), 0, nil },
		`ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`: func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
		`dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`: func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "0"), 0, nil
		},
	}}
	handler := diagnoseDNSHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseDNSInput{Host: "web1"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.NameQueried {
		t.Fatal("NameQueried = true, want false when no name supplied")
	}
	if len(out.Steps) != 4 {
		t.Fatalf("len(out.Steps) = %d, want 4 (name-based steps omitted)", len(out.Steps))
	}
	if len(fake.calls) != 4 {
		t.Fatalf("fake runner recorded %d calls, want 4", len(fake.calls))
	}
}

// ---- pilot_diagnose_logs --------------------------------------------------

func TestDiagnoseLogsHandler_EmptyQueryRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "   "})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an empty query", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseLogsHandler_NoDashboardGroupRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t) // no "dashboard" group in this inventory at all
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "up"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result when no dashboard group exists", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — an inventory-shape problem must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseLogsHandler_MultipleDashboardHostsRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1", "dash2"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "up"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result when the dashboard group has more than one host", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseLogsHandler_SuccessBuildsOutputAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	query := `{job="pilot-siem"} |= "error"`
	// The fixture inventory sets no ansible_user, so the default noise
	// exclusion only ever appends the BECOME-SUCCESS clause here.
	wantQuery := diagnose.ExcludeAnsibleNoise(query, nil)
	steps := diagnose.LogsSteps(wantQuery, "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "dash1", 0, `{"status":"success","data":{}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: query})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Host != "dash1" {
		t.Fatalf("out.Host = %q, want dash1 — auto-resolved, there is no host parameter", out.Host)
	}
	if out.Query != wantQuery {
		t.Fatalf("out.Query = %q, want %q — ansible noise exclusion should be appended by default", out.Query, wantQuery)
	}
	if out.HTTPStatus != 200 || out.ResultJSON != `{"status":"success","data":{}}` {
		t.Fatalf("out = %+v, want http_status=200 and the raw Loki body split from the trailing status", out)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("fake runner recorded %d calls, want exactly 1", len(fake.calls))
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "logs" || rec.Host != "dash1" || rec.Params["query"] != wantQuery {
		t.Fatalf("audit record = %+v, want check=logs host=dash1 params.query=%q", rec, wantQuery)
	}
}

func TestDiagnoseLogsHandler_IncludeAnsibleNoiseOptsOutOfExclusion(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	query := `{job="pilot-siem"} |= "error"`
	steps := diagnose.LogsSteps(query, "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "dash1", 0, `{"status":"success","data":{}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: query, IncludeAnsibleNoise: true})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Query != query {
		t.Fatalf("out.Query = %q, want %q verbatim — include_ansible_noise=true must skip the exclusion filters", out.Query, query)
	}
}

func TestDiagnoseLogsHandler_UnreachableSurfacesAsFieldNotError(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	steps := diagnose.LogsSteps(diagnose.ExcludeAnsibleNoise("up", nil), "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
				"dash1": map[string]any{"stdout": "", "rc": 0, "failed": true, "unreachable": true},
			}}}}}}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			return string(data), 0, nil
		},
	}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "up"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil — an unreachable target is a normal result field, not a tool error", result)
	}
	if !out.Unreachable {
		t.Fatal("out.Unreachable = false, want true")
	}
}

// ---- pilot_diagnose_security_logs ------------------------------------------

func TestDiagnoseSecurityLogsHandler_NoDashboardGroupRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t) // no "dashboard" group in this inventory at all
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseSecurityLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSecurityLogsInput{})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result when no dashboard group exists", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseSecurityLogsHandler_SuccessWithNoFiltersBuildsOutputAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	wantQuery := diagnose.ExcludeAnsibleNoise(diagnose.SecurityLogsQuery("", ""), nil)
	steps := diagnose.LogsSteps(wantQuery, "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "dash1", 0, `{"status":"success","data":{}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseSecurityLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSecurityLogsInput{})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success) — every field is optional", result)
	}
	if out.Host != "dash1" {
		t.Fatalf("out.Host = %q, want dash1 — auto-resolved, there is no host parameter", out.Host)
	}
	if out.Query != wantQuery {
		t.Fatalf("out.Query = %q, want %q — ansible noise exclusion should be appended by default", out.Query, wantQuery)
	}
	if out.HTTPStatus != 200 || out.ResultJSON != `{"status":"success","data":{}}` {
		t.Fatalf("out = %+v, want http_status=200 and the raw Loki body", out)
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "security_logs" || rec.Host != "dash1" || rec.Params["query"] != wantQuery {
		t.Fatalf("audit record = %+v, want check=security_logs host=dash1 params.query=%q", rec, wantQuery)
	}
}

func TestDiagnoseSecurityLogsHandler_HostAndSearchComposeIntoQuery(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	host, search := "web1", "Failed password"
	wantQuery := diagnose.ExcludeAnsibleNoise(diagnose.SecurityLogsQuery(host, search), nil)
	steps := diagnose.LogsSteps(wantQuery, "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "dash1", 0, `{"status":"success","data":{}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseSecurityLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSecurityLogsInput{Host: host, Search: search})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Query != wantQuery {
		t.Fatalf("out.Query = %q, want %q", out.Query, wantQuery)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("fake runner recorded %d calls, want exactly 1 — host/search must select the exact composed-query command the fake was keyed on", len(fake.calls))
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Params["host"] != host || rec.Params["search"] != search || rec.Params["query"] != wantQuery {
		t.Fatalf("audit record params = %+v, want host/search/query recorded verbatim", rec.Params)
	}
}

func TestDiagnoseSecurityLogsHandler_UnreachableSurfacesAsFieldNotError(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "dashboard", []string{"dash1"})
	steps := diagnose.LogsSteps(diagnose.ExcludeAnsibleNoise(diagnose.SecurityLogsQuery("", ""), nil), "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
				"dash1": map[string]any{"stdout": "", "rc": 0, "failed": true, "unreachable": true},
			}}}}}}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			return string(data), 0, nil
		},
	}}
	handler := diagnoseSecurityLogsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseSecurityLogsInput{})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil — an unreachable target is a normal result field, not a tool error", result)
	}
	if !out.Unreachable {
		t.Fatal("out.Unreachable = false, want true")
	}
}

// ---- pilot_diagnose_login ------------------------------------------------

// writeDiagnoseLoginFixtureInventory writes a fixture with one target host
// (web1, carrying a freeipa_roster_file extra var pointing at rosterPath so
// discoverRosterFilePath finds it the same way it would from a real
// freeipa-server/freeipa-nfs-server host) plus, when withDashboard is set,
// a one-host "dashboard" group for the security-logs section.
func writeDiagnoseLoginFixtureInventory(t *testing.T, rosterPath string, withDashboard bool) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("all:\n  hosts:\n    web1:\n      ansible_connection: local\n      ansible_host: 127.0.0.1\n")
	if rosterPath != "" {
		b.WriteString("      freeipa_roster_file: " + rosterPath + "\n")
	}
	if withDashboard {
		b.WriteString("  children:\n    dashboard:\n      hosts:\n        dash1: {ansible_connection: local, ansible_host: 127.0.0.1}\n")
	}
	path := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// diagnosePrefixRunner is diagnoseFakeRunner's exact-match lookup plus a
// prefix-matched fallback — needed for pilot_diagnose_login's security-logs
// step, whose curl command embeds a real time.Now()-derived timestamp
// (normalizeLokiRange's lookback resolution) that a test cannot predict
// exactly, unlike every other fixed-literal step in this file.
type diagnosePrefixRunner struct {
	byCommand map[string]func() (string, int, error)
	byPrefix  map[string]func() (string, int, error)
	calls     []string
}

func (f *diagnosePrefixRunner) run(_ context.Context, args []string, _ int) (string, int, error) {
	command := args[len(args)-1]
	f.calls = append(f.calls, command)
	if fn, ok := f.byCommand[command]; ok {
		return fn()
	}
	for prefix, fn := range f.byPrefix {
		if strings.HasPrefix(command, prefix) {
			return fn()
		}
	}
	return "", 0, fmt.Errorf("no fake response configured for command %q", command)
}

func TestDiagnoseLoginHandler_NoUsersRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for zero users", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseLoginHandler_InvalidUserRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1", Users: []string{"alice; rm -rf /"}})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an invalid user", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — invalid input must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseLoginHandler_InvalidLookbackRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1", Users: []string{"alice"}, Lookback: "not-a-duration"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an unparseable lookback", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — an invalid lookback must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseLoginHandler_UnknownHostRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "doesnotexist", Users: []string{"alice"}})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an unknown host", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

// TestDiagnoseLoginHandler_NoDashboardGroupSkipsSecurityLogsGracefully
// covers the core best-effort design decision: an inventory with no
// dashboard role deployed must still succeed with every other section
// intact, only noting that the recent-login-records section was skipped —
// never turn that into a hard failure of the whole composite tool.
func TestDiagnoseLoginHandler_NoDashboardGroupSkipsSecurityLogsGracefully(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseLoginFixtureInventory(t, "", false)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active sssd":       func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
		"sudo klist -k /etc/krb5.keytab": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "host/web1@REALM"), 0, nil },
		`D=$(sudo sssctl domain-list 2>/dev/null | head -n1); [ -n "$D" ] && sudo sssctl domain-status "$D" 2>&1 || echo "no sssd domain configured"`: func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "Domain: example.test\nOnline status: Online"), 0, nil
		},
		"awk 'NR==1{print $2}' /etc/resolv.conf":                    func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.1"), 0, nil },
		"systemctl is-active systemd-resolved":                      func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
		`ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`: func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
		`dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`: func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "0"), 0, nil
		},
		"getent hosts web1":          func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5 web1"), 0, nil },
		"dig +short web1 @127.0.0.1": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5"), 0, nil },
		"getent passwd alice": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "alice:x:1000:1000::/home/alice:/bin/bash"), 0, nil
		},
		"sudo -l -U alice": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "(root) NOPASSWD: ALL"), 0, nil },
	}}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1", Users: []string{"alice"}})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil — a missing dashboard group must not fail the whole call", result)
	}
	if out.SecurityLogs.SkippedReason == "" {
		t.Fatal("SecurityLogs.SkippedReason is empty, want an explanation for why it was skipped")
	}
	if !out.SssdActive || !out.HasKerberosMachineIdentity || len(out.Users) != 1 || !out.Users[0].AccountResolvesViaSSSD {
		t.Fatalf("out = %+v, want host/user sections intact despite the skipped security-logs section", out)
	}
	if out.RosterAvailable {
		t.Fatalf("out.RosterAvailable = true, want false — no freeipa_roster_file anywhere in this fixture")
	}
	if out.RosterNote == "" {
		t.Fatal("out.RosterNote is empty, want an explanation for why roster comparison was skipped")
	}
}

func TestDiagnoseLoginHandler_SuccessBuildsOutputRosterDriftAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	rosterDir := t.TempDir()
	rosterPath := filepath.Join(rosterDir, "roster.yaml")
	roster := `
hbac:
  rules:
    - name: allow-web-login
      subjects: {users: [alice]}
      targets: {hosts: [web1]}
      services: [sshd]
sudo:
  rules:
    - name: allow-bob-sudo
      subjects: {users: [bob]}
      targets: {hosts: [web1]}
      commands: {all: true}
`
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := writeDiagnoseLoginFixtureInventory(t, rosterPath, true)

	fake := &diagnosePrefixRunner{
		byCommand: map[string]func() (string, int, error){
			"systemctl is-active sssd":       func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
			"sudo klist -k /etc/krb5.keytab": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "host/web1@REALM"), 0, nil },
			`D=$(sudo sssctl domain-list 2>/dev/null | head -n1); [ -n "$D" ] && sudo sssctl domain-status "$D" 2>&1 || echo "no sssd domain configured"`: func() (string, int, error) {
				return diagnoseOKDoc(t, "web1", 0, "Domain: example.test\nOnline status: Online"), 0, nil
			},
			"awk 'NR==1{print $2}' /etc/resolv.conf":                    func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.1"), 0, nil },
			"systemctl is-active systemd-resolved":                      func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
			`ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`: func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
			`dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`: func() (string, int, error) {
				return diagnoseOKDoc(t, "web1", 0, "0"), 0, nil
			},
			"getent hosts web1":          func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5 web1"), 0, nil },
			"dig +short web1 @127.0.0.1": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "10.0.0.5"), 0, nil },
			// alice: roster declares HBAC but no sudo rule, and live sudo -l
			// reports none either — no drift for alice, but the roster/live
			// facts must both come through as "no sudo access".
			"getent passwd alice": func() (string, int, error) {
				return diagnoseOKDoc(t, "web1", 0, "alice:x:1000:1000::/home/alice:/bin/bash"), 0, nil
			},
			"sudo -l -U alice": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 1, "not allowed"), 0, nil },
			// bob: roster declares a sudo rule but live sudo -l already
			// grants it too (consistent), while roster declares no HBAC rule
			// for bob at all.
			"getent passwd bob": func() (string, int, error) {
				return diagnoseOKDoc(t, "web1", 0, "bob:x:1001:1001::/home/bob:/bin/bash"), 0, nil
			},
			"sudo -l -U bob": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "(root) NOPASSWD: ALL"), 0, nil },
		},
		byPrefix: map[string]func() (string, int, error){
			"curl -sS -G http://127.0.0.1:3100/loki/api/v1/query_range": func() (string, int, error) {
				return diagnoseOKDoc(t, "dash1", 0, `{"status":"success","data":{}}`+"\nHTTP_STATUS:200"), 0, nil
			},
		},
	}
	handler := diagnoseLoginHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLoginInput{Host: "web1", Users: []string{"alice", "bob"}})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if !out.RosterAvailable {
		t.Fatalf("out.RosterAvailable = false, want true; note=%q", out.RosterNote)
	}
	if out.SecurityLogs.HTTPStatus != 200 || out.SecurityLogs.ResultJSON != `{"status":"success","data":{}}` {
		t.Fatalf("out.SecurityLogs = %+v, want http_status=200 and the raw Loki body", out.SecurityLogs)
	}
	if len(out.Users) != 2 {
		t.Fatalf("len(out.Users) = %d, want 2", len(out.Users))
	}
	byUser := map[string]diagnoseLoginUserOutput{out.Users[0].User: out.Users[0], out.Users[1].User: out.Users[1]}
	alice, bob := byUser["alice"], byUser["bob"]
	if !alice.RosterHBACAuthorized || alice.RosterSudoAuthorized || alice.CentralSudoRuleGrantsAccess {
		t.Fatalf("alice = %+v, want HBAC-authorized and no sudo either side (no drift)", alice)
	}
	if !strings.Contains(alice.Verdict, "no config/live drift") {
		t.Fatalf("alice.Verdict = %q, want no drift reported", alice.Verdict)
	}
	if bob.RosterHBACAuthorized {
		t.Fatalf("bob = %+v, want RosterHBACAuthorized=false (roster declares no HBAC rule for bob)", bob)
	}
	if !bob.RosterSudoAuthorized || !bob.CentralSudoRuleGrantsAccess {
		t.Fatalf("bob = %+v, want roster and live sudo to agree (both true)", bob)
	}
	if !strings.Contains(bob.Verdict, "no roster HBAC rule") {
		t.Fatalf("bob.Verdict = %q, want it to flag the missing HBAC rule", bob.Verdict)
	}

	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "login" || rec.Host != "web1" || rec.Params["users"] != "alice,bob" {
		t.Fatalf("audit record = %+v, want check=login host=web1 params.users=alice,bob", rec)
	}
	// Host-level (3 login-specific + 6 from DNSSteps(host)) + 2 users * 2 + 1 security-logs step.
	if len(rec.Steps) != 9+4+1 {
		t.Fatalf("audit record has %d steps, want %d", len(rec.Steps), 9+4+1)
	}
}

// ---- pilot_diagnose_metrics ------------------------------------------------

func TestDiagnoseMetricsHandler_EmptyQueryRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseMetricsHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseMetricsInput{Query: ""})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an empty query", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseMetricsHandler_StartWithoutEndRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseMetricsHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseMetricsInput{Query: "up", Start: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result when start is set without end", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseMetricsHandler_NoThanosQueryGroupRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t) // no "thanos-query" group in this inventory at all
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseMetricsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseMetricsInput{Query: "up"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result when no thanos-query group exists", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseMetricsHandler_SuccessInstantQueryBuildsOutputAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "thanos-query", []string{"tq1"})
	query := `up{job="prometheus"}`
	steps := diagnose.MetricsSteps(query, "", "", "", "")
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "tq1", 0, `{"status":"success","data":{"resultType":"vector","result":[]}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseMetricsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseMetricsInput{Query: query})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Host != "tq1" {
		t.Fatalf("out.Host = %q, want tq1 — auto-resolved, there is no host parameter", out.Host)
	}
	if out.HTTPStatus != 200 || out.ResultJSON != `{"status":"success","data":{"resultType":"vector","result":[]}}` {
		t.Fatalf("out = %+v, want http_status=200 and the raw Thanos body", out)
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "metrics" || rec.Host != "tq1" || rec.Params["query"] != query {
		t.Fatalf("audit record = %+v, want check=metrics host=tq1 params.query=%q", rec, query)
	}
}

func TestDiagnoseMetricsHandler_SuccessRangeQueryPassesStartEndStepThrough(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseGroupFixtureInventory(t, "thanos-query", []string{"tq1"})
	query, start, end, step := "up", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "30s"
	steps := diagnose.MetricsSteps(query, "", start, end, step)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		steps[0].Command: func() (string, int, error) {
			return diagnoseOKDoc(t, "tq1", 0, `{"status":"success","data":{"resultType":"matrix","result":[]}}`+"\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseMetricsHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseMetricsInput{Query: query, Start: start, End: end, Step: step})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("fake runner recorded %d calls, want exactly 1 — start/end/step must select the range-query URL the fake was keyed on", len(fake.calls))
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Params["start"] != start || rec.Params["end"] != end || rec.Params["step"] != step {
		t.Fatalf("audit record params = %+v, want start/end/step to be recorded verbatim", rec.Params)
	}
}

// ---- pilot_diagnose_run --------------------------------------------------

func TestDiagnoseRunHandler_EmptyCommandRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseRunHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRunInput{Host: "web1", Command: "   "})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an empty command", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0", len(fake.calls))
	}
}

func TestDiagnoseRunHandler_UnknownHostRejectedBeforeAnyCall(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseRunHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRunInput{Host: "doesnotexist", Command: "id alice"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want an IsError result for an unknown host", result)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("fake runner recorded %d calls, want 0 — an unknown host must never reach an ad-hoc call", len(fake.calls))
	}
}

func TestDiagnoseRunHandler_SuccessRunsExactCommandAndWritesAudit(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"cat /etc/hostname": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "web1.example.internal"), 0, nil },
	}}
	handler := diagnoseRunHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRunInput{Host: "web1", Command: "cat /etc/hostname"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.RC != 0 || out.Stdout != "web1.example.internal" {
		t.Fatalf("out = %+v, want rc=0 stdout=web1.example.internal", out)
	}
	if len(fake.calls) != 1 || fake.calls[0] != "cat /etc/hostname" {
		t.Fatalf("fake.calls = %v, want exactly [\"cat /etc/hostname\"] — the command must be run verbatim, unmodified", fake.calls)
	}
	data, err := os.ReadFile(filepath.Join(out.AuditDirectory, "record.json"))
	if err != nil {
		t.Fatalf("read audit record: %v", err)
	}
	var rec diagnoseAuditRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse audit record: %v", err)
	}
	if rec.Check != "run" || rec.Params["command"] != "cat /etc/hostname" {
		t.Fatalf("audit record = %+v, want check=run params.command=\"cat /etc/hostname\"", rec)
	}
}

func TestDiagnoseRunHandler_NonzeroRCIsNotAnMCPError(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active sssd": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 3, "inactive"), 0, nil },
	}}
	handler := diagnoseRunHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRunInput{Host: "web1", Command: "systemctl is-active sssd"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil — a clean nonzero remote rc is a normal result, not a tool error", result)
	}
	if out.RC != 3 {
		t.Fatalf("out.RC = %d, want 3", out.RC)
	}
}

// ---- resolveDiagnoseInventory (auto-regenerate from sibling hosts.yml) ----

// TestResolveDiagnoseInventory_RegeneratesFreshOnEveryCallNotJustAtStartup
// proves the auto-regenerate hook (autoRegenerateInventoryFromHosts,
// inventory.go) runs on every pilot_diagnose_* call, not once when the
// server starts: a hosts.yml edit made between two calls to the same
// handler (modeling an mcp serve process that stays up across a
// separate `pilot edit` session touching the same workspace) must be
// picked up by the very next call, with no restart.
func TestResolveDiagnoseInventory_RegeneratesFreshOnEveryCallNotJustAtStartup(t *testing.T) {
	requireRealAnsible(t)
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inventory.yml")
	hostsPath := filepath.Join(dir, "hosts.yml")
	if err := os.WriteFile(invPath, []byte("all:\n  hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsPath, []byte("hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseLogsHandler(baseDiagnoseOpts(t, invPath, fake.run))

	result1, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "up"})
	if err != nil {
		t.Fatalf("first handler() call error = %v", err)
	}
	if result1 == nil || !result1.IsError {
		t.Fatalf("first call result = %+v, want an IsError result — hosts.yml declares no dashboard host yet", result1)
	}

	// Simulate a hosts.yml edit made while the (conceptual) long-running
	// mcp serve process stays up — e.g. via a separate `pilot edit` session.
	hostsWithDashboard := "hosts:\n  dash1:\n    ansible_host: 127.0.0.1\n    ansible_connection: local\n    roles: [dashboard]\n"
	if err := os.WriteFile(hostsPath, []byte(hostsWithDashboard), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := diagnose.LogsSteps(diagnose.ExcludeAnsibleNoise("up", nil), "", "", "", "")
	fake.byCommand[steps[0].Command] = func() (string, int, error) {
		return diagnoseOKDoc(t, "dash1", 0, `{"status":"success"}`+"\nHTTP_STATUS:200"), 0, nil
	}

	result2, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseLogsInput{Query: "up"})
	if err != nil {
		t.Fatalf("second handler() call error = %v", err)
	}
	if result2 != nil {
		t.Fatalf("second call result = %+v, want nil (success) — hosts.yml now declares a dashboard host, and this call must see it without a restart", result2)
	}
	if out2.Host != "dash1" {
		t.Fatalf("out2.Host = %q, want dash1", out2.Host)
	}
}
