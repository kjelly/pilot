package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	return diagnoseMCPToolsOptions{
		Inventory:   inventory,
		AuditDir:    t.TempDir(),
		StepTimeout: 5 * time.Second,
		AdHocRunner: runner,
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
