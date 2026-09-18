package sessionrecording

import (
	"testing"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// TestIsEchoOffAgreesWithRealTermiosToggle proves the low-level IOCTL
// mechanism against a REAL pty pair, not a guess: opens a real Unix98 pty
// (github.com/creack/pty), flips ECHO on the SLAVE side via a real
// unix.IoctlSetTermios call, and asserts isEchoOff (reading the MASTER
// fd) agrees at every step with no propagation delay.
//
// This proves the mechanism, not the assumption that a real `ssh -tt`
// child (the only thing this recorder ever actually wraps) toggles its
// OWN local pty's ECHO specifically during a remote password prompt —
// live-verified against a real target to be FALSE (see isEchoOff's doc
// comment and docs/evidence/pilot-access-directory/2026-09-18-phase7-pty-recorder.md).
// Do not read a pass here as "echo-off redaction works end-to-end."
func TestIsEchoOffAgreesWithRealTermiosToggle(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	// A freshly opened pty defaults to ECHO on (matches a real login
	// shell's initial state before any password prompt).
	off, err := isEchoOff(ptmx.Fd())
	if err != nil {
		t.Fatalf("isEchoOff (initial): %v", err)
	}
	if off {
		t.Fatalf("isEchoOff = true on a freshly opened pty, want false (ECHO on by default)")
	}

	// Flip ECHO off on the SLAVE side (matches what login/sudo/ssh does
	// internally right before reading a password on a real target).
	term, err := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("IoctlGetTermios(slave): %v", err)
	}
	term.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(pts.Fd()), unix.TCSETS, term); err != nil {
		t.Fatalf("IoctlSetTermios(slave, ECHO off): %v", err)
	}

	off, err = isEchoOff(ptmx.Fd())
	if err != nil {
		t.Fatalf("isEchoOff (after ECHO off): %v", err)
	}
	if !off {
		t.Fatalf("isEchoOff = false after disabling ECHO on the slave, want true — master-side read did not observe the slave's termios change")
	}

	// Flip it back on and confirm isEchoOff tracks that too (not just a
	// one-way/cached read).
	term.Lflag |= unix.ECHO
	if err := unix.IoctlSetTermios(int(pts.Fd()), unix.TCSETS, term); err != nil {
		t.Fatalf("IoctlSetTermios(slave, ECHO on): %v", err)
	}
	off, err = isEchoOff(ptmx.Fd())
	if err != nil {
		t.Fatalf("isEchoOff (after ECHO restored): %v", err)
	}
	if off {
		t.Fatalf("isEchoOff = true after re-enabling ECHO on the slave, want false")
	}
}
