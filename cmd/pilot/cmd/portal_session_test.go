package cmd

import (
	"strings"
	"testing"
)

// TestParsePortalSSHOriginalCommand_Empty proves an empty
// SSH_ORIGINAL_COMMAND dispatches to the interactive TUI (spec.md §17).
func TestParsePortalSSHOriginalCommand_Empty(t *testing.T) {
	cmd, err := parsePortalSSHOriginalCommand("")
	if err != nil || cmd.Kind != portalSessionInteractive {
		t.Fatalf("got (%+v, %v), want interactive", cmd, err)
	}
}

// TestParsePortalSSHOriginalCommand_ValidConnect proves the exact grammar
// match parses both the session-id and the target correctly.
func TestParsePortalSSHOriginalCommand_ValidConnect(t *testing.T) {
	cmd, err := parsePortalSSHOriginalCommand("pilot-connect 0d33c638-83fa-4d77-9811-a97a7a7af1d5 gpu01.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Kind != portalSessionConnect || cmd.SessionID != "0d33c638-83fa-4d77-9811-a97a7a7af1d5" || cmd.Target != "gpu01.example.com" {
		t.Fatalf("cmd = %+v, want connect with session_id/target parsed out", cmd)
	}
}

// TestParsePortalSSHOriginalCommand_ValidTransport / _ValidKnownHosts are
// captive-transport spec AG45: the exact one-token grammars parse into their
// own states and never into the legacy connect state.
func TestParsePortalSSHOriginalCommand_ValidTransport(t *testing.T) {
	cmd, err := parsePortalSSHOriginalCommand("pilot-transport-v1 gpu01.example.internal")
	if err != nil || cmd.Kind != portalSessionTransport || cmd.Target != "gpu01.example.internal" || cmd.SessionID != "" {
		t.Fatalf("got (%+v, %v), want transport to gpu01.example.internal", cmd, err)
	}
}

func TestParsePortalSSHOriginalCommand_ValidKnownHosts(t *testing.T) {
	cmd, err := parsePortalSSHOriginalCommand("pilot-known-hosts-v1 gpu01.example.internal")
	if err != nil || cmd.Kind != portalSessionKnownHosts || cmd.Target != "gpu01.example.internal" {
		t.Fatalf("got (%+v, %v), want known-hosts for gpu01.example.internal", cmd, err)
	}
}

// TestParsePortalSSHOriginalCommand_Rejects covers spec.md §40's full ban
// list for the Gateway-side handoff grammar: shell metacharacters, IP
// literals, user@host, leading "-", trailing ".", embedded newline,
// malformed/non-UUID session ids, wrong argument counts, arbitrary
// commands, and Directory's OWN grammar (which must not be accepted here
// — the two ForceCommand parsers must never cross-recognize each other's
// grammar).
func TestParsePortalSSHOriginalCommand_Rejects(t *testing.T) {
	const uuid = "0d33c638-83fa-4d77-9811-a97a7a7af1d5"
	cases := []string{
		"sh",
		"bash -c id",
		"pilot-connect",               // no session id or target
		"pilot-connect " + uuid,       // no target
		"pilot-connect " + uuid + " ", // empty target
		"not-a-uuid gpu01.example.com",
		"pilot-connect not-a-uuid gpu01.example.com",
		"pilot-connect " + uuid + " host;id",
		"pilot-connect " + uuid + " host$(id)",
		"pilot-connect " + uuid + " host`id`",
		"pilot-connect " + uuid + " user@host.example.com",
		"pilot-connect " + uuid + " 1.2.3.4",
		"pilot-connect " + uuid + " [::1]",
		"pilot-connect " + uuid + " -oProxyCommand=x",
		"pilot-connect " + uuid + " --help",
		"pilot-connect " + uuid + " host name.example.com", // extra argument
		"pilot-connect " + uuid + " host\nid.example.com",
		"pilot-connect " + uuid + " HOST.EXAMPLE.COM",      // must be lowercase
		"pilot-connect " + uuid + " host.example.com.",     // trailing dot
		"pilot-connect " + uuid + " onelabel",              // not FQDN-shaped
		"pilot-directory-connect gpu-a.ipa.pilot.internal", // Directory's own grammar, not Gateway's
	}
	for _, c := range cases {
		if cmd, err := parsePortalSSHOriginalCommand(c); err == nil {
			t.Errorf("parsePortalSSHOriginalCommand(%q) = (%+v, nil), want an error", c, cmd)
		}
	}
}

// TestParsePortalSSHOriginalCommand_RejectsTransport is captive-transport
// spec AG46, applied to both new grammars: nothing but exactly one
// lowercase, multi-label, non-IP FQDN is accepted — never a port, an
// address, a user, an option, shell syntax, or a second token.
func TestParsePortalSSHOriginalCommand_RejectsTransport(t *testing.T) {
	badTargets := []string{
		"",                                  // bare prefix + space
		" gpu01.example.internal",           // double space
		"gpu01.example.internal extra",      // extra token
		"gpu01.example.internal 22",         // port as a token
		"gpu01.example.internal:22",         // port in the target
		"gpu01",                             // single label
		"localhost",                         // single label
		"10.0.0.1",                          // IPv4 literal
		"::1",                               // IPv6 literal
		"[::1]",                             // bracketed IPv6
		"user@gpu01.example.internal",       // user@host
		"GPU01.example.internal",            // uppercase
		"gpu01.example.internal.",           // trailing dot
		"gpu01;id.example.internal",         // shell metacharacter
		"gpu01$(id).example.internal",       // command substitution
		"gpu01`id`.example.internal",        // backticks
		"-oProxyCommand=x",                  // option injection
		"gpu01.example.internal\tx",         // tab
		"gpu01.example.internal\nid",        // embedded newline
		"gpu01.example.internal ",           // trailing space
		"gpu01.example.internal/22",         // path/port smuggling
		"gpu01.example.internal\\x.example", // backslash
	}
	for _, prefix := range []string{"pilot-transport-v1 ", "pilot-known-hosts-v1 "} {
		for _, target := range badTargets {
			raw := prefix + target
			cmd, err := parsePortalSSHOriginalCommand(raw)
			if err == nil {
				t.Errorf("parsePortalSSHOriginalCommand(%q) = (%+v, nil), want an error", raw, cmd)
				continue
			}
			wantUsage := transportMsgUsage
			if strings.HasPrefix(prefix, "pilot-known-hosts") {
				wantUsage = knownHostsMsgUsage
			}
			if !strings.Contains(err.Error(), wantUsage) {
				t.Errorf("parsePortalSSHOriginalCommand(%q) error %q lacks %q", raw, err, wantUsage)
			}
		}
	}
	// Near-miss verbs never reach either state at all.
	for _, raw := range []string{
		"pilot-transport-v1",
		"pilot-known-hosts-v1",
		"pilot-transport-v2 gpu01.example.internal",
		"PILOT-TRANSPORT-V1 gpu01.example.internal",
		"pilot-transport gpu01.example.internal",
		" pilot-transport-v1 gpu01.example.internal",
	} {
		cmd, err := parsePortalSSHOriginalCommand(raw)
		if err == nil || cmd.Kind != portalSessionUnknown {
			t.Errorf("parsePortalSSHOriginalCommand(%q) = (%+v, %v), want unrecognized", raw, cmd, err)
		}
	}
}

func TestRunPortalSessionRejectsInvalidCommand(t *testing.T) {
	if err := runPortalSession(nil, "sh -c id"); err == nil {
		t.Fatalf("expected runPortalSession to reject an arbitrary command")
	}
}

// withPortalSessionTTY fakes the TTY probes for one test.
func withPortalSessionTTY(t *testing.T, stdin, stdout bool, sshTTY string) {
	t.Helper()
	origIn, origOut, origEnv := portalSessionStdinIsTTY, portalSessionStdoutIsTTY, portalSessionGetenv
	portalSessionStdinIsTTY = func() bool { return stdin }
	portalSessionStdoutIsTTY = func() bool { return stdout }
	portalSessionGetenv = func(key string) string {
		if key == "SSH_TTY" {
			return sshTTY
		}
		return ""
	}
	t.Cleanup(func() {
		portalSessionStdinIsTTY, portalSessionStdoutIsTTY, portalSessionGetenv = origIn, origOut, origEnv
	})
}

// TestRunPortalSession_TTYPolicy is captive-transport spec AG47: the
// interactive Portal and pilot-connect refuse to run without a TTY on
// stdin (the Go-side replacement for the wrapper's `[ -t 0 ] || exit 1`),
// and both transport states refuse ANY TTY — before contacting the gateway
// socket at all (portalSocketFlag points nowhere, so reaching the API would
// fail with a different error).
func TestRunPortalSession_TTYPolicy(t *testing.T) {
	orig := portalSocketFlag
	portalSocketFlag = t.TempDir() + "/no-such.sock"
	t.Cleanup(func() { portalSocketFlag = orig })

	const uuid = "0d33c638-83fa-4d77-9811-a97a7a7af1d5"
	cases := []struct {
		name         string
		raw          string
		stdin        bool
		stdout       bool
		sshTTY       string
		wantContains string
	}{
		{"interactive without TTY", "", false, false, "", "a TTY is required"},
		{"connect without TTY", "pilot-connect " + uuid + " gpu01.example.internal", false, false, "", "a TTY is required"},
		{"transport with stdin TTY", "pilot-transport-v1 gpu01.example.internal", true, false, "", transportMsgTTYNotAllowed},
		{"transport with stdout TTY", "pilot-transport-v1 gpu01.example.internal", false, true, "", transportMsgTTYNotAllowed},
		{"transport with SSH_TTY", "pilot-transport-v1 gpu01.example.internal", false, false, "/dev/pts/3", transportMsgTTYNotAllowed},
		{"known-hosts with SSH_TTY", "pilot-known-hosts-v1 gpu01.example.internal", false, false, "/dev/pts/3", knownHostsMsgTTYNotAllowed},
		{"transport without TTY reaches the API", "pilot-transport-v1 gpu01.example.internal", false, false, "", transportMsgUnavailable},
		{"known-hosts without TTY reaches the API", "pilot-known-hosts-v1 gpu01.example.internal", false, false, "", knownHostsMsgUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPortalSessionTTY(t, tc.stdin, tc.stdout, tc.sshTTY)
			err := runPortalSession(nil, tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.wantContains) {
				t.Fatalf("runPortalSession(%q) = %v, want an error containing %q", tc.raw, err, tc.wantContains)
			}
		})
	}
}
