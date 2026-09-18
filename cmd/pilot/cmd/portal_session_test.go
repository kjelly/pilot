package cmd

import "testing"

// TestParsePortalSSHOriginalCommand_Empty proves an empty
// SSH_ORIGINAL_COMMAND dispatches to the interactive TUI (spec.md §17).
func TestParsePortalSSHOriginalCommand_Empty(t *testing.T) {
	cmd, interactive, err := parsePortalSSHOriginalCommand("")
	if err != nil || !interactive || cmd != nil {
		t.Fatalf("got (%v, %v, %v), want (nil, true, nil)", cmd, interactive, err)
	}
}

// TestParsePortalSSHOriginalCommand_ValidConnect proves the exact grammar
// match parses both the session-id and the target correctly.
func TestParsePortalSSHOriginalCommand_ValidConnect(t *testing.T) {
	cmd, interactive, err := parsePortalSSHOriginalCommand("pilot-connect 0d33c638-83fa-4d77-9811-a97a7a7af1d5 gpu01.example.com")
	if err != nil || interactive {
		t.Fatalf("got (%v, %v, %v)", cmd, interactive, err)
	}
	if cmd == nil || cmd.SessionID != "0d33c638-83fa-4d77-9811-a97a7a7af1d5" || cmd.Target != "gpu01.example.com" {
		t.Fatalf("cmd = %+v, want session_id/target parsed out", cmd)
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
		if cmd, interactive, err := parsePortalSSHOriginalCommand(c); err == nil {
			t.Errorf("parsePortalSSHOriginalCommand(%q) = (%v, %v, nil), want an error", c, cmd, interactive)
		}
	}
}

func TestRunPortalSessionRejectsInvalidCommand(t *testing.T) {
	if err := runPortalSession(nil, "sh -c id"); err == nil {
		t.Fatalf("expected runPortalSession to reject an arbitrary command")
	}
}
