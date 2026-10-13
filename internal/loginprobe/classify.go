package loginprobe

import (
	"regexp"
	"strconv"
)

// The markers below come from real OpenSSH 9.6p1 (Ubuntu 24.04) and 9.9p1
// (AlmaLinux 9) `ssh -v` client output, captured against FreeIPA-enrolled
// targets on 2026-10-13 (internal/loginprobe/testdata/capture, AGENTS.md
// §5.6). Every pattern is anchored to a whole line so text a remote banner
// or command prints mid-line cannot match.
var (
	// The login completed: authentication AND PAM account both passed.
	authenticatedRe = regexp.MustCompile(`(?m)^Authenticated to \S+ (?:\(via proxy\) |\[[^\]]*\]:\d+ )?using "publickey"\.\r?$`)
	// sshd accepted the canary's key (it is published and AuthorizedKeysCommand
	// returned it); a disconnect after this is PAM account management.
	serverAcceptsKeyRe = regexp.MustCompile(`(?m)^debug1: Server accepts key: `)
	// sshd refused every offered key.
	permissionDeniedRe = regexp.MustCompile(`(?m)^\S+: Permission denied \([a-z0-9,@.-]+\)\.\r?$`)
	hostKeyFailedRe    = regexp.MustCompile(`(?m)^Host key verification failed\.\r?$`)
	// The SSH identification banner arrived: transport is up.
	remoteBannerRe = regexp.MustCompile(`(?m)^debug1: Remote protocol version \d+\.\d+, remote software version `)
	// ServerAlive or connect/banner timeout reported by the client.
	timedOutRe = regexp.MustCompile(`(?m)^(?:Connection to \S+ port \d+ timed out|Connection timed out during banner exchange|ssh: connect to host \S+ port \d+: Connection timed out)\r?$`)
)

// Classify maps one attempt to the stage it ended in, plus a short reason.
// The order is significant: a completed login is judged by its exit status
// alone (whatever the remote command printed), and the pre-auth markers are
// only consulted when no login happened.
//
// Captured signatures (testdata/capture):
//
//	ok        "Authenticated to … using publickey", exit 0
//	session   "Authenticated to …", non-zero exit (command failed or the
//	          session dropped)
//	hostkey   "Host key verification failed." (re-keyed host, or a name
//	          SSSD/FreeIPA holds no host key for)
//	auth      "Permission denied (publickey,…)" and the key was never
//	          accepted (unknown account, key not published)
//	account   "Server accepts key" without "Authenticated to", closed by
//	          the server (HBAC rule disabled, `ipa user-disable`: sshd logs
//	          "Access denied for user … by PAM account configuration")
//	timeout   banner exchanged, then a client-side timeout: sssd_be,
//	          sssd_pam or sssd_nss frozen, or sssd stopped, while the
//	          login hangs instead of failing; or total_timeout expired
//	transport no SSH banner: refused, dropped (banner-exchange timeout),
//	          unresolvable name, or ssh could not be started
func Classify(r RawResult) (Stage, string) {
	if r.StartErr != nil {
		return StageTransport, r.StartErr.Error()
	}
	if r.TimedOut {
		return StageTimeout, "attempt exceeded total_timeout: " + Summarize(r.Stderr)
	}
	stderr := r.Stderr
	if authenticatedRe.MatchString(stderr) {
		if r.ExitCode == 0 {
			return StageOK, ""
		}
		return StageSession, "authenticated, but the session ended with exit status " + strconv.Itoa(r.ExitCode)
	}
	if r.ExitCode == 0 {
		// Exit 0 without the authentication line means the output was not
		// what this classifier was built from (e.g. -v missing): never
		// report success that was not observed.
		return StageSession, "exit status 0 without an authentication record in the ssh output"
	}
	switch {
	case hostKeyFailedRe.MatchString(stderr):
		return StageHostKey, "host key verification failed"
	case serverAcceptsKeyRe.MatchString(stderr):
		if timedOutRe.MatchString(stderr) {
			return StageTimeout, "key accepted, then the login stalled: " + Summarize(stderr)
		}
		return StageAccount, "key accepted, then the server closed the connection before the session (PAM account denial)"
	case permissionDeniedRe.MatchString(stderr):
		return StageAuth, "publickey authentication refused"
	case remoteBannerRe.MatchString(stderr):
		if timedOutRe.MatchString(stderr) {
			return StageTimeout, "transport up, then the login stalled before an authentication result: " + Summarize(stderr)
		}
		return StageTransport, "transport up, but the connection ended before an authentication result: " + Summarize(stderr)
	default:
		return StageTransport, Summarize(stderr)
	}
}
