package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Real outputs captured on 2026-10-01 from an Ubuntu 24.04 vm-target after
// core-infra-provider-apply.yml -e infra_role=ntp (chrony), and from an
// Ubuntu 24.04 vm-target that keeps systemd-timesyncd.
const (
	chronyTrackingSynced = `Reference ID    : 7F7F0101 ()
Stratum         : 3
Ref time (UTC)  : Thu Oct 01 09:45:14 2026
System time     : 0.131187066 seconds slow of NTP time
Last offset     : -0.001273402 seconds
RMS offset      : 0.001273402 seconds
Frequency       : 0.000 ppm slow
Residual freq   : +0.000 ppm
Skew            : 0.000 ppm
Root delay      : 0.000000000 seconds
Root dispersion : 0.000000000 seconds
Update interval : 2.0 seconds
Leap status     : Normal
`
	// chronyd stopped: the message goes to stdout, rc 1.
	chronyTrackingStopped = "506 Cannot talk to daemon\n"
	// timedatectl show-timesync on the chrony host (timesyncd inactive):
	// nothing on stdout, rc 1.
	timesyncOnChronyHostErr = "Failed to parse bus message: No route to host\n"
	timesyncSynced          = `FallbackNTPServers=ntp.ubuntu.com
ServerName=ntp.ubuntu.com
ServerAddress=185.125.190.57
RootDistanceMaxUSec=5s
PollIntervalMinUSec=32s
PollIntervalMaxUSec=34min 8s
PollIntervalUSec=4min 16s
NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=2, Precision=-25, RootDelay=6.500ms, RootDispersion=335us, Reference=1D586304, OriginateTimestamp=Thu 2026-10-01 09:34:59 UTC, ReceiveTimestamp=Thu 2026-10-01 09:34:59 UTC, TransmitTimestamp=Thu 2026-10-01 09:34:59 UTC, DestinationTimestamp=Thu 2026-10-01 09:34:59 UTC, Ignored=no, PacketCount=4, Jitter=15.684ms }
Frequency=-1788024
`
)

// fakeTool is what a fake command prints and returns.
type fakeTool struct {
	stdout, stderr string
	rc             int
}

// runNTPC3 runs core-infra-provider.md C3 as parsed, with chronyc and
// timedatectl replaced by fakes.
func runNTPC3(t *testing.T, chronyc, timedatectl fakeTool) string {
	t.Helper()
	s, err := Parse("../../docs/verification/core-infra-provider.md")
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, r := range s.Rows {
		if r.ID == "C3" {
			if r.Expected != "~stratum-ok" {
				t.Fatalf("C3 expected = %q, want ~stratum-ok", r.Expected)
			}
			command = r.Command
		}
	}
	if command == "" {
		t.Fatal("C3 not found")
	}
	bin := t.TempDir()
	for name, tool := range map[string]fakeTool{"chronyc": chronyc, "timedatectl": timedatectl} {
		dir := t.TempDir()
		out, errOut := filepath.Join(dir, "out"), filepath.Join(dir, "err")
		if err := os.WriteFile(out, []byte(tool.stdout), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(errOut, []byte(tool.stderr), 0o644); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\ncat '" + out + "'\ncat '" + errOut + "' >&2\nexit " + strconv.Itoa(tool.rc) + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
	got, err := cmd.Output()
	if err != nil {
		t.Fatalf("C3 command failed to run: %v\n%s", err, got)
	}
	return strings.TrimSpace(string(got))
}

// TestRegression_CoreInfraProviderStratum locks C3 against the real
// command outputs above. Until v3.1 the command escaped its pipes as `\|`,
// which the parser keeps, so the shell passed `|` and `grep` to chronyc as
// arguments; the output always contained "Stratum" and `~Stratum` always
// passed.
func TestRegression_CoreInfraProviderStratum(t *testing.T) {
	notFound := fakeTool{stderr: "sh: 1: chronyc: not found\n", rc: 127}
	timesyncDown := fakeTool{stderr: timesyncOnChronyHostErr, rc: 1}
	cases := []struct {
		name                 string
		chronyc, timedatectl fakeTool
		want                 string
	}{
		{"chrony synced", fakeTool{stdout: chronyTrackingSynced}, timesyncDown, "stratum-ok"},
		{"timesyncd synced, no chrony", notFound, fakeTool{stdout: timesyncSynced}, "stratum-ok"},
		{"chronyd stopped", fakeTool{stdout: chronyTrackingStopped, rc: 1}, timesyncDown, "stratum-not-ok"},
		{"chrony unsynchronised (stratum 0)", fakeTool{stdout: strings.Replace(chronyTrackingSynced, "Stratum         : 3", "Stratum         : 0", 1)}, timesyncDown, "stratum-not-ok"},
		{"chrony stratum 12", fakeTool{stdout: strings.Replace(chronyTrackingSynced, "Stratum         : 3", "Stratum         : 12", 1)}, timesyncDown, "stratum-not-ok"},
		{"timesyncd stratum 0", notFound, fakeTool{stdout: strings.Replace(timesyncSynced, "Stratum=2,", "Stratum=0,", 1)}, "stratum-not-ok"},
		{"timesyncd stratum 12", notFound, fakeTool{stdout: strings.Replace(timesyncSynced, "Stratum=2,", "Stratum=12,", 1)}, "stratum-not-ok"},
		{"no NTP client at all", notFound, fakeTool{stderr: "sh: 1: timedatectl: not found\n", rc: 127}, "stratum-not-ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runNTPC3(t, tc.chronyc, tc.timedatectl); got != tc.want {
				t.Errorf("C3 printed %q, want %q", got, tc.want)
			}
		})
	}
}
