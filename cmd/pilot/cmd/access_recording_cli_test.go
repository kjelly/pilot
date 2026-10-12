package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayconfig"
)

const accessRecordingTestConfig = `gateway:
  id: gpu-01
  scope: gpu
  fqdn: pilot-gw-gpu-01.linker.internal
  target_hostgroup: pilot-target-gpu
  freeipa:
    servers: [ipa1.linker.internal]
    ca_file: /etc/ipa/ca.crt
    service_principal: pilot-access-gateway/pilot-gw-gpu-01.linker.internal
    keytab: /etc/pilot/pilot-access-gateway.keytab
`

// withAccessRecordingEnv runs the command as root against provider.
func withAccessRecordingEnv(t *testing.T, provider *fakeGatewayProvider, extraConfig string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access-gateway.yaml")
	if err := os.WriteFile(path, []byte(accessRecordingTestConfig+extraConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	oldEUID, oldProvider := accessRecordingEUID, newAccessRecordingProvider
	accessRecordingEUID = func() int { return 0 }
	newAccessRecordingProvider = func(gatewayconfig.Config) (freeipaaccess.Provider, error) { return provider, nil }
	t.Cleanup(func() { accessRecordingEUID, newAccessRecordingProvider = oldEUID, oldProvider })
	return path
}

func TestAccessRecordingShow_NonRootRejected(t *testing.T) {
	old := accessRecordingEUID
	accessRecordingEUID = func() int { return 1000 }
	t.Cleanup(func() { accessRecordingEUID = old })
	err := runAccessRecordingShow(context.Background(), &bytes.Buffer{}, "db.example.com", "/nonexistent", "text")
	var coded ExitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != 2 || err.Error() != "must run as root on a pilot-access-gateway host" {
		t.Fatalf("non-root = %v, want exit 2 root refusal", err)
	}
}

func TestAccessRecordingShow_PolicyStates(t *testing.T) {
	cases := map[string]struct {
		policy freeipaaccess.HostRecordingPolicy
		lines  []string
	}{
		"inherit": {freeipaaccess.HostRecordingPolicy{Valid: true}, []string{
			"Host policy:      inherit", "Gateway default:  unset (built-in metadata)", "Effective:        metadata", "Policy source:    built_in_default"}},
		"off": {freeipaaccess.HostRecordingPolicy{Present: true, Mode: "off", Valid: true}, []string{
			"Host policy:      off", "Effective:        metadata", "Policy source:    host"}},
		"terminal_output": {freeipaaccess.HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}, []string{
			"Host policy:      terminal_output", "Effective:        terminal_output", "Policy source:    host", "Reason:           recording_backend_unavailable"}},
		"unknown": {freeipaaccess.HostRecordingPolicy{Unreadable: true, Reason: "userclass_unreadable"}, []string{
			"Host policy:      unknown", "Effective:        none — Connect will be refused", "Reason:           userclass_unreadable"}},
		"invalid": {freeipaaccess.HostRecordingPolicy{Present: true, Reason: "duplicate"}, []string{
			"Host policy:      invalid", "Effective:        none — Connect will be refused", "Reason:           duplicate"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			policy := c.policy
			cfg := withAccessRecordingEnv(t, &fakeGatewayProvider{recording: &policy}, "")
			var out bytes.Buffer
			if err := runAccessRecordingShow(context.Background(), &out, "DB.Example.com", cfg, "text"); err != nil {
				t.Fatalf("show: %v", err)
			}
			for _, line := range append([]string{"Host:             db.example.com", "FreeIPA source:   userClass pilot.policy.ssh-recording"}, c.lines...) {
				if !strings.Contains(out.String(), line+"\n") {
					t.Errorf("output lacks %q:\n%s", line, out.String())
				}
			}
		})
	}
}

func TestAccessRecordingShow_JSONWithGatewayDefault(t *testing.T) {
	cfg := withAccessRecordingEnv(t, &fakeGatewayProvider{recording: &freeipaaccess.HostRecordingPolicy{Valid: true}},
		"  recording:\n    mode: terminal_output\n    session_store_url: https://store:8443\n    session_store_ingest_signing_key_file: /etc/pilot/k\n")
	var out bytes.Buffer
	if err := runAccessRecordingShow(context.Background(), &out, "db.example.com", cfg, "json"); err != nil {
		t.Fatalf("show: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	want := map[string]string{"host": "db.example.com", "host_policy": "inherit", "gateway_default": "terminal_output", "effective": "terminal_output", "policy_source": "gateway_default"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (%v)", k, got[k], v, got)
		}
	}
	if _, ok := got["reason"]; ok {
		t.Errorf("a resolvable policy carries a reason: %v", got)
	}
}

func TestAccessRecordingShow_HostNotFound(t *testing.T) {
	cfg := withAccessRecordingEnv(t, &fakeGatewayProvider{hostShowErr: &freeipaaccess.RPCError{Code: 4001, Name: "NotFound", Message: "db.example.com: host not found"}}, "")
	err := runAccessRecordingShow(context.Background(), &bytes.Buffer{}, "db.example.com", cfg, "text")
	var coded ExitCoder
	if !errors.As(err, &coded) || coded.ExitCode() != 1 || !strings.Contains(err.Error(), "host not found in FreeIPA") {
		t.Fatalf("missing host = %v, want exit 1 host not found", err)
	}
	cfg = withAccessRecordingEnv(t, &fakeGatewayProvider{hostShowErr: errors.New("dial tcp: connection refused")}, "")
	if err := runAccessRecordingShow(context.Background(), &bytes.Buffer{}, "db.example.com", cfg, "text"); err == nil || !strings.Contains(err.Error(), "query FreeIPA host_show") {
		t.Fatalf("unreachable FreeIPA = %v", err)
	}
}
