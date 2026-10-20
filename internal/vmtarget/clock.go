package vmtarget

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A host-derived step works even when NTP is unreachable or chronyd's
// restored tracking state claims an almost-zero offset. Restart only active
// time daemons so they discard their pre-restore measurements; do not change
// configuration or enable a service the operator had stopped.
const restoreGuestClockScript = `set -eu
date -u -s "$1" >/dev/null
if command -v systemctl >/dev/null 2>&1; then
  for service in chronyd.service chrony.service systemd-timesyncd.service; do
    if systemctl is-active --quiet "$service"; then
      systemctl restart "$service"
    fi
  done
fi
date -u +%s
`

// Five seconds is comfortably below Kerberos' usual five-minute skew limit,
// while allowing whole-second date output and normal local SSH latency.
const restoredClockMaxSkew = 5 * time.Second

func (m *Manager) restoreGuestClock(ctx context.Context, t *Target) error {
	if t.Status != StatusRunning || t.IP == "" {
		return fmt.Errorf("cannot recover clock: guest status=%s IP=%q", t.Status, t.IP)
	}
	ctx, cancel := context.WithTimeout(ctx, m.sshTimeout)
	defer cancel()
	if err := m.waitForSSH(ctx, t, m.sshTimeout); err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		argv := []string{"sh", "-c", restoreGuestClockScript, "pilot-restore-clock", "@" + strconv.FormatInt(m.now().Unix(), 10)}
		if t.SSHUser != "root" {
			argv = append([]string{"sudo", "-n", "--"}, argv...)
		}
		res, err := m.ssh(ctx, t, argv, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("set/read guest clock exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		guest, err := strconv.ParseInt(strings.TrimSpace(res.Stdout), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid guest clock %q: %w", strings.TrimSpace(res.Stdout), err)
		}
		// Compare with the host AFTER SSH completes. A slow connection must
		// not validate an old timestamp just because it matches the value sent.
		host := m.now().Unix()
		limit := int64(restoredClockMaxSkew / time.Second)
		if guest >= host-limit && guest <= host+limit {
			return nil
		}
		lastErr = fmt.Errorf("guest clock %d outside host clock %d ±%ds", guest, host, limit)
	}
	return lastErr
}
