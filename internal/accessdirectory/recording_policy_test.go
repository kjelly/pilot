package accessdirectory

import (
	"context"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
)

func TestDirectoryResolve_CarriesRecordingOverride(t *testing.T) {
	p := multiScopeProvider()
	p.hosts = map[string]freeipaaccess.Host{
		"shared-a.ipa.pilot.internal": {FQDN: "shared-a.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}},
		"gpu-b.ipa.pilot.internal":    {FQDN: "gpu-b.ipa.pilot.internal", SSHRecording: freeipaaccess.HostRecordingPolicy{Present: true, Reason: "duplicate"}},
	}
	access, err := LoadDirectoryAccess(context.Background(), p, p, "alice", "pilot-target-", "pilot-gateway-", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("LoadDirectoryAccess: %v", err)
	}
	byFQDN := map[string]DirectoryTarget{}
	for _, target := range access.Targets {
		byFQDN[target.FQDN] = target
	}
	// shared-a is reachable through two scopes but is one FreeIPA host
	// object: one merged entry carrying its override.
	if got := byFQDN["shared-a.ipa.pilot.internal"].Recording; got.Status() != accessportal.RecordingStatusTerminalOutput {
		t.Errorf("shared-a Recording = %+v, want terminal_output", got)
	}
	if got := byFQDN["gpu-b.ipa.pilot.internal"].Recording; got.Status() != accessportal.RecordingStatusInvalid {
		t.Errorf("gpu-b Recording = %+v, want invalid", got)
	}
	if got := byFQDN["gpu-a.ipa.pilot.internal"].Recording; got.Status() != accessportal.RecordingStatusInherit {
		t.Errorf("gpu-a Recording = %+v, want inherit", got)
	}
}

func TestMergeRecordingPolicy(t *testing.T) {
	unknown := accessportal.SSHRecordingAccessPolicy{Reason: "host_show_failed"}
	invalid := accessportal.SSHRecordingAccessPolicy{Known: true, Reason: "duplicate"}
	output := accessportal.SSHRecordingAccessPolicy{Known: true, Valid: true, Override: "terminal_output"}
	cases := []struct {
		name string
		a, b accessportal.SSHRecordingAccessPolicy
		want accessportal.SSHRecordingAccessPolicy
	}{
		{"known beats unknown", unknown, output, output},
		{"known beats unknown (reverse)", output, unknown, output},
		{"invalid beats valid", output, invalid, invalid},
		{"invalid beats unknown", unknown, invalid, invalid},
		{"both unknown stays unknown", unknown, unknown, unknown},
	}
	for _, c := range cases {
		if got := mergeRecordingPolicy(c.a, c.b); got != c.want {
			t.Errorf("%s: merge = %+v, want %+v", c.name, got, c.want)
		}
	}
}
