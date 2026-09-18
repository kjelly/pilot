package sessionrecording

import "golang.org/x/sys/unix"

// isEchoOff reports whether fd's current termios has ECHO disabled.
//
// The underlying IOCTL mechanism is verified correct: redaction_test.go
// opens a real pty pair (github.com/creack/pty), flips ECHO on the SLAVE
// side via a real unix.IoctlSetTermios call, and confirms isEchoOff
// (reading the MASTER fd) agrees at every step with no propagation delay.
//
// BUT — verified live against a real Gateway->target session (`alice`
// SSH'd to ag-target01 via `ssh -tt`, deliberately triggering a genuine
// password-required `sudo` prompt; see docs/evidence/pilot-access-directory/
// 2026-09-18-phase7-pty-recorder.md for the full transcript) — this check
// does NOT distinguish "the remote target is showing a password prompt"
// from "normal remote shell interaction" for the one child process this
// recorder actually ever wraps: an `ssh -tt <target>` client. OpenSSH's
// client puts ITS OWN local controlling terminal (the master/slave pty
// pair Gateway allocates for it via pty.Start) into raw mode — ECHO and
// ICANON both off — for the ENTIRE interactive session, from
// authentication completing until the session tears down, regardless of
// what the REMOTE target's shell is doing. It relies entirely on the
// REMOTE pty's own echo behavior to reflect typed characters back over
// the wire for display; the SSH wire protocol has no signal a client can
// introspect for "the remote side just disabled its own echo" during an
// already-established interactive session (unlike keyboard-interactive
// AUTHENTICATION prompts, which do carry an explicit per-prompt echo
// flag — but that happens in Phase A, before this recorder ever starts,
// per spec.md §24).
//
// Practical effect measured live: with 20ms polling resolution across a
// 14-second session spanning a normal command, `sudo -k`, a real
// password-required `sudo whoami`, password entry, and a post-prompt
// command, ECHO/ICANON went to false at t=0.59s (session start) and
// stayed false continuously until t=14.03s (session end) — one
// transition each way, neither anywhere near the actual password prompt.
// This means today, in terminal_io mode, virtually every input chunk
// evaluates isEchoOff=true and gets redacted to a byte-count — the
// recorder does NOT currently capture real typed command text via this
// SSH-relay path, only via terminal_output's unaffected output-side
// recording. This is a real, known gap (not a hidden one — see the
// evidence doc), not the "ECHO toggles specifically during a password
// prompt" behavior spec.md §26 assumed. It is SAFE (over-redacting can
// never leak a secret) but not currently USEFUL for its stated
// distinguishing purpose. A real fix needs an output-stream prompt-text
// heuristic (à la `expect`), not a termios read on this particular child
// — deliberately NOT attempted here: an under-tested heuristic risks
// under-redacting (a real secret leaking because a prompt phrasing wasn't
// in the pattern list), which is a strictly worse failure mode than the
// current over-redaction. Left as required follow-up work, not
// implemented in Phase 7.
func isEchoOff(fd uintptr) (bool, error) {
	t, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return false, err
	}
	return t.Lflag&unix.ECHO == 0, nil
}
