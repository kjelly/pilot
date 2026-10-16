package loginprobe

import (
	"strings"
	"testing"
	"time"
)

const validConfig = `
interval: 60s
connect_timeout: 10s
total_timeout: 30s
concurrency: 2
user: pilot-login-canary
command: /bin/true
ssh_binary: /usr/bin/ssh
ssh_config: /etc/pilot/login-probe/ssh_config
textfile: /var/lib/node_exporter/textfile/pilot_login_probe.prom
targets:
  - {name: lp-target, host: lp-target.ipa.pilot.internal}
  - {name: lp-target-el, host: lp-target-el.ipa.pilot.internal, port: 2222}
`

func TestParseConfig_DefaultsAndPorts(t *testing.T) {
	cfg, err := ParseConfig([]byte("targets:\n  - {name: a, host: a.example.internal}\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Interval != DefaultInterval || cfg.ConnectTimeout != DefaultConnectTimeout || cfg.TotalTimeout != DefaultTotalTimeout {
		t.Errorf("timing defaults not applied: %+v", cfg)
	}
	if cfg.User != DefaultUser || cfg.Command != DefaultCommand || cfg.SSHConfig != DefaultSSHConfig || cfg.Textfile != DefaultTextfile {
		t.Errorf("string defaults not applied: %+v", cfg)
	}
	if cfg.Targets[0].Port != DefaultPort {
		t.Errorf("port default = %d, want %d", cfg.Targets[0].Port, DefaultPort)
	}
}

func TestParseConfig_Valid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Targets[1].Port != 2222 || cfg.Concurrency != 2 || cfg.Interval != time.Minute {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestParseConfig_EmptyTargetsIsValid(t *testing.T) {
	if _, err := ParseConfig([]byte("targets: []\n")); err != nil {
		t.Fatalf("empty targets must be valid (PilotLoginProbeNoTargets reports it): %v", err)
	}
}

func TestParseConfig_Rejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":                     "intervall: 60s\n",
		"interval below minimum":          "interval: 5s\n",
		"total shorter than connect":      "connect_timeout: 20s\ntotal_timeout: 10s\n",
		"total not shorter than interval": "interval: 30s\ntotal_timeout: 30s\n",
		"zero concurrency":                "concurrency: -1\n",
		"bad user":                        "user: 'Canary User'\n",
		"multi-line command":              "command: \"/bin/true\\n/bin/false\"\n",
		"relative ssh_config":             "ssh_config: etc/ssh_config\n",
		"relative textfile":               "textfile: metrics.prom\n",
		"upper-case target name":          "targets:\n  - {name: LP-Target, host: a.example.internal}\n",
		"address as target name":          "targets:\n  - {name: 192.168.1.1, host: a.example.internal}\n",
		"duplicate target name":           "targets:\n  - {name: a, host: a.example.internal}\n  - {name: a, host: b.example.internal}\n",
		"empty host":                      "targets:\n  - {name: a, host: ''}\n",
		"host with option prefix":         "targets:\n  - {name: a, host: '-oProxyCommand=x'}\n",
		"port out of range":               "targets:\n  - {name: a, host: a.example.internal, port: 70000}\n",
	}
	for name, body := range cases {
		if _, err := ParseConfig([]byte(body)); err == nil {
			t.Errorf("%s: expected an error for %q", name, strings.TrimSpace(body))
		}
	}
}

func TestParseConfig_AddressAsTargetNameIsRejectedButHostMayBeAddressLike(t *testing.T) {
	// A target's probe_target label is an identity, never an address
	// (AGENTS.md §5.13); the host is whatever OpenSSH should connect to.
	_, err := ParseConfig([]byte("targets:\n  - {name: lp-target, host: lp-target.ipa.pilot.internal}\n"))
	if err != nil {
		t.Fatalf("FQDN host must be accepted: %v", err)
	}
}
