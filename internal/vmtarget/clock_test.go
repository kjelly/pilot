package vmtarget

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Captured by `pilot vm-target exec --name i111-el -- date -u +%s` on
// AlmaLinux 9.8; raw stdout/stderr are retained with issue-111 evidence.
const capturedGuestEpoch = "1792468486"

func TestRollbackClockRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, user, reply, wantErr string
		reset, stopped, revertFail bool
		wantCalls                  int
	}{
		{name: "root", user: "root", reply: "echo " + capturedGuestEpoch, wantCalls: 1},
		{name: "retry then recover", user: "root", reply: `if [ "$(grep -c pilot-restore-clock "$CLOCK_LOG")" -eq 1 ]; then echo 1792466686; else echo ` + capturedGuestEpoch + `; fi`, wantCalls: 2},
		{name: "within tolerance", user: "root", reply: "echo 1792468481", wantCalls: 1},
		{name: "outside tolerance", user: "root", reply: "echo 1792468480", wantErr: "outside host clock", wantCalls: 3},
		{name: "reset non-root", user: "ubuntu", reply: "echo " + capturedGuestEpoch, reset: true, wantCalls: 1},
		{name: "behind", user: "root", reply: "echo 1792466686", wantErr: "outside host clock", wantCalls: 3},
		{name: "ahead", user: "root", reply: "echo 1792470286", wantErr: "outside host clock", wantCalls: 3},
		{name: "malformed", user: "root", reply: "echo garbage", wantErr: "invalid guest clock", wantCalls: 1},
		{name: "empty", user: "root", reply: "exit 0", wantErr: "invalid guest clock", wantCalls: 1},
		{name: "permission denied", user: "ubuntu", reply: "echo denied >&2; exit 1", wantErr: "exited 1: denied", wantCalls: 1},
		{name: "stopped snapshot", user: "root", stopped: true},
		{name: "failed revert", user: "root", revertFail: true, wantErr: "snapshot-revert failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, base := newTestManager(t, happyVirsh)
			if _, err := m.Up(context.Background(), Options{Name: "clock", BaseImage: base, SSHUser: tc.user}); err != nil {
				t.Fatal(err)
			}
			m.now = func() time.Time { return time.Unix(1792468486, 0) }
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			t.Setenv("CLOCK_LOG", log)
			status := "running"
			if tc.stopped {
				status = "shut off"
			}
			revert := "exit 0"
			if tc.revertFail {
				revert = "exit 1"
			}
			writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", `
case "$1" in
  domstate) echo '`+status+`' ;;
  snapshot-revert) echo revert >> "$CLOCK_LOG"; `+revert+` ;;
esac`)
			writeShim(t, dir, "ssh", "PILOT_SSH_BIN", `
case "$*" in
  *pilot-restore-clock*)
    echo "$*" >> "$CLOCK_LOG"
    `+tc.reply+` ;;
esac`)
			var err error
			if tc.reset {
				err = m.Reset(context.Background(), "clock")
			} else {
				err = m.Rollback(context.Background(), "clock", "baseline")
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error=%v, want %q", err, tc.wantErr)
			}
			if tc.wantCalls > 0 && tc.wantErr != "" && !strings.Contains(err.Error(), "clock recovery failed") {
				t.Fatalf("recovery failure must say snapshot was restored: %v", err)
			}
			data, readErr := os.ReadFile(log)
			if readErr != nil {
				t.Fatal(readErr)
			}
			calls := string(data)
			if !strings.HasPrefix(calls, "revert\n") || strings.Count(calls, "pilot-restore-clock") != tc.wantCalls {
				t.Fatalf("unexpected recovery order/count: %s", calls)
			}
			if tc.wantCalls > 0 {
				if !strings.Contains(calls, "@"+capturedGuestEpoch) {
					t.Fatalf("host time not sent to guest: %s", calls)
				}
				if got := strings.Contains(calls, "sudo -n --"); got != (tc.user != "root") {
					t.Fatalf("sudo used=%t for user %s", got, tc.user)
				}
			}
		})
	}
}

func TestRestoreGuestClockWaitIsBounded(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	m.sshTimeout = 30 * time.Millisecond
	writeShim(t, t.TempDir(), "ssh", "PILOT_SSH_BIN", "exit 255")
	start := time.Now()
	err := m.restoreGuestClock(context.Background(), &Target{Name: "offline", Status: StatusRunning, IP: "192.0.2.1"})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("unreachable guest must fail promptly: %v", err)
	}
}

func TestRestoreGuestClockHonorsCancellation(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.restoreGuestClock(ctx, &Target{Name: "cancelled", Status: StatusRunning, IP: "192.0.2.1"})
	if err == nil {
		t.Fatal("cancelled recovery succeeded")
	}
}

func TestRestoreGuestClockRejectsSlowSSH(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	// Readiness succeeds, but host time has advanced by 30s when each clock
	// read returns. Matching the sent timestamp must not count as success.
	log := filepath.Join(t.TempDir(), "clock-reads")
	t.Setenv("CLOCK_LOG", log)
	m.now = func() time.Time {
		data, _ := os.ReadFile(log)
		return time.Unix(1792468486+int64(len(data))*30, 0)
	}
	writeShim(t, t.TempDir(), "ssh", "PILOT_SSH_BIN", `
case "$*" in
  *pilot-restore-clock*) printf x >> "$CLOCK_LOG"; echo `+capturedGuestEpoch+` ;;
esac`)
	err := m.restoreGuestClock(context.Background(), &Target{Name: "slow", Status: StatusRunning, IP: "192.0.2.1", SSHUser: "root"})
	if err == nil || !strings.Contains(err.Error(), "outside host clock") {
		t.Fatalf("slow SSH accepted stale time: %v", err)
	}
}

func TestRestoreClockScript(t *testing.T) {
	for _, active := range []string{"chronyd.service", "chrony.service", "systemd-timesyncd.service", "none"} {
		t.Run(active, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			t.Setenv("CLOCK_LOG", log)
			t.Setenv("ACTIVE_SERVICE", active)
			writeShim(t, dir, "systemctl", "UNUSED_SYSTEMCTL_BIN", `
case "$1" in
  is-active) [ "$3" = "$ACTIVE_SERVICE" ] ;;
  restart) echo "restart $2" >> "$CLOCK_LOG" ;;
  *) exit 1 ;;
esac`)
			writeShim(t, dir, "date", "UNUSED_DATE_BIN", `echo "date $*" >> "$CLOCK_LOG"; echo `+capturedGuestEpoch)
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			out, err := exec.Command("sh", "-c", restoreGuestClockScript, "clock-test", "@"+capturedGuestEpoch).CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != capturedGuestEpoch {
				t.Fatalf("output=%s error=%v", out, err)
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			want := "date -u -s @" + capturedGuestEpoch + "\n"
			if active != "none" {
				want += "restart " + active + "\n"
			}
			want += "date -u +%s\n"
			if string(data) != want {
				t.Fatalf("calls=%s, want=%s", data, want)
			}
		})
	}
}
