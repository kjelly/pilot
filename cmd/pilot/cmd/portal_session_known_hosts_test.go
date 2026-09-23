package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// realHostKeys loads the ipasshpubkey values from the real host_show
// response captured in the captive-transport Phase 0 run (AGENTS.md §5.6).
func realHostKeys(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "freeipaaccess", "testdata", "host_show_ipasshpubkey.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var env struct {
		Result struct {
			Result struct {
				IPASSHPubKey []string `json:"ipasshpubkey"`
			} `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(env.Result.Result.IPASSHPubKey) != 3 {
		t.Fatalf("fixture has %d keys, want 3", len(env.Result.Result.IPASSHPubKey))
	}
	return env.Result.Result.IPASSHPubKey
}

// TestKnownHostsLine is AG58's key validation: every real FreeIPA key
// renders as "<host> <type> <base64>" with the comment dropped; unknown
// types, broken base64, and a blob whose embedded type disagrees with the
// declared type are all rejected.
func TestKnownHostsLine(t *testing.T) {
	for _, key := range realHostKeys(t) {
		fields := strings.Fields(key)
		line, ok := knownHostsLine("tx-target.ipa.pilot.internal", key)
		if !ok || line != "tx-target.ipa.pilot.internal "+fields[0]+" "+fields[1] {
			t.Errorf("knownHostsLine(%q...) = (%q, %v)", key[:24], line, ok)
		}
	}
	ed25519 := strings.Fields(realHostKeys(t)[0])[1]
	for name, key := range map[string]string{
		"unknown type":       "ssh-dss " + ed25519,
		"cert type":          "ssh-ed25519-cert-v01@openssh.com " + ed25519,
		"broken base64":      "ssh-ed25519 not*base64",
		"type/blob mismatch": "ssh-rsa " + ed25519,
		"truncated blob":     "ssh-ed25519 AAAA",
		"single field":       "ssh-ed25519",
		"empty":              "",
	} {
		if line, ok := knownHostsLine("h.example", key); ok {
			t.Errorf("%s: knownHostsLine accepted %q -> %q", name, key, line)
		}
	}
}

// TestRunPortalKnownHosts covers AG58 end to end through the real gateway
// API (fake FreeIPA provider) and AG56 for this state: stdout carries only
// complete known_hosts lines, or nothing.
func TestRunPortalKnownHosts(t *testing.T) {
	keys := realHostKeys(t)
	t.Run("allowed", func(t *testing.T) {
		client, _ := startFakeTransportGateway(t, transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}, hostKeys: append(keys, "ssh-dss AAAAbogus")})
		var out bytes.Buffer
		audit := &syncBuffer{}
		if err := runPortalKnownHosts(context.Background(), client, sessionaudit.NewEmitterWithWriter("t", audit), &out, "gpu-a.example.com"); err != nil {
			t.Fatalf("runPortalKnownHosts: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		if len(lines) != 3 {
			t.Fatalf("got %d lines, want 3 (the bogus key dropped): %q", len(lines), out.String())
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "gpu-a.example.com ") || strings.Contains(l, "root@tx-target") {
				t.Errorf("line %q: want host-prefixed, comment dropped", l)
			}
		}
		evs := audit.events(t)
		if len(evs) != 1 || evs[0].Kind != sessionaudit.KindGatewayKnownHostsServed || evs[0].HostKeyCount == nil || *evs[0].HostKeyCount != 3 {
			t.Fatalf("audit = %+v", evs)
		}
	})
	for _, tc := range []struct {
		name    string
		opts    transportGatewayOpts
		target  string
		wantMsg string
	}{
		{"transport disabled", transportGatewayOpts{enabled: false, ready: []string{"gpu-a.example.com"}, hostKeys: keys}, "gpu-a.example.com", knownHostsMsgAccessDenied},
		{"target not ready", transportGatewayOpts{enabled: true, hostKeys: keys}, "gpu-a.example.com", knownHostsMsgAccessDenied},
		{"out of scope", transportGatewayOpts{enabled: true, ready: []string{"gpu-z.example.com"}, hostKeys: keys}, "gpu-z.example.com", knownHostsMsgAccessDenied},
		{"no usable key", transportGatewayOpts{enabled: true, ready: []string{"gpu-a.example.com"}, hostKeys: []string{"ssh-dss AAAAbogus"}}, "gpu-a.example.com", knownHostsMsgNoHostKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := startFakeTransportGateway(t, tc.opts)
			var out bytes.Buffer
			err := runPortalKnownHosts(context.Background(), client, sessionaudit.NewEmitterWithWriter("t", &syncBuffer{}), &out, tc.target)
			if err == nil || err.Error() != tc.wantMsg {
				t.Fatalf("err = %v, want %q", err, tc.wantMsg)
			}
			if out.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", out.String())
			}
		})
	}
	t.Run("gateway unreachable", func(t *testing.T) {
		var out bytes.Buffer
		err := runPortalKnownHosts(context.Background(), newPortalClient(t.TempDir()+"/none.sock"), sessionaudit.NewEmitterWithWriter("t", &syncBuffer{}), &out, "gpu-a.example.com")
		if err == nil || err.Error() != knownHostsMsgUnavailable || out.Len() != 0 {
			t.Fatalf("err = %v stdout=%q, want %q and empty stdout", err, out.String(), knownHostsMsgUnavailable)
		}
	})
}
