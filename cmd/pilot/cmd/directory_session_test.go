package cmd

import "testing"

// TestParseDirectorySSHOriginalCommand_Empty proves an empty
// SSH_ORIGINAL_COMMAND dispatches to the interactive TUI (spec.md §14).
func TestParseDirectorySSHOriginalCommand_Empty(t *testing.T) {
	fqdn, interactive, err := parseDirectorySSHOriginalCommand("")
	if err != nil || !interactive || fqdn != "" {
		t.Fatalf("got (%q, %v, %v), want (\"\", true, nil)", fqdn, interactive, err)
	}
}

// TestParseDirectorySSHOriginalCommand_ValidConnect proves the exact
// grammar match parses correctly.
func TestParseDirectorySSHOriginalCommand_ValidConnect(t *testing.T) {
	fqdn, interactive, err := parseDirectorySSHOriginalCommand("pilot-directory-connect gpu-a.ipa.pilot.internal")
	if err != nil || interactive || fqdn != "gpu-a.ipa.pilot.internal" {
		t.Fatalf("got (%q, %v, %v), want (\"gpu-a.ipa.pilot.internal\", false, nil)", fqdn, interactive, err)
	}
}

// TestParseDirectorySSHOriginalCommand_Rejects covers spec.md §17.1's
// full ban list, adapted to Directory's own handoff grammar: shell
// metacharacters, IP literals, user@host, leading "-", trailing ".",
// arbitrary commands, extra arguments, and the empty-target edge case.
func TestParseDirectorySSHOriginalCommand_Rejects(t *testing.T) {
	cases := []string{
		"sh",
		"bash -c id",
		"pilot-directory-connect",  // no target at all
		"pilot-directory-connect ", // empty target
		"pilot-directory-connect host;id",
		"pilot-directory-connect host$(id)",
		"pilot-directory-connect host`id`",
		"pilot-directory-connect user@host.example.com",
		"pilot-directory-connect 1.2.3.4",
		"pilot-directory-connect [::1]",
		"pilot-directory-connect -oProxyCommand=x",
		"pilot-directory-connect --help",
		"pilot-directory-connect host name.example.com", // extra argument
		"pilot-directory-connect host\nid.example.com",
		"pilot-directory-connect HOST.EXAMPLE.COM",                             // must be lowercase
		"pilot-directory-connect host.example.com.",                            // trailing dot
		"pilot-directory-connect onelabel",                                     // not FQDN-shaped
		"pilot-connect 0d33c638-83fa-4d77-9811-a97a7a7af1d5 gpu01.example.com", // Gateway's own grammar, not Directory's
	}
	for _, c := range cases {
		if fqdn, interactive, err := parseDirectorySSHOriginalCommand(c); err == nil {
			t.Errorf("parseDirectorySSHOriginalCommand(%q) = (%q, %v, nil), want an error", c, fqdn, interactive)
		}
	}
}

func TestRunDirectorySessionRejectsInvalidCommand(t *testing.T) {
	if err := runDirectorySession(nil, "sh -c id"); err == nil {
		t.Fatalf("expected runDirectorySession to reject an arbitrary command")
	}
}

func TestRunDirectorySessionStubsOneShotConnect(t *testing.T) {
	err := runDirectorySession(nil, "pilot-directory-connect gpu-a.ipa.pilot.internal")
	if err == nil {
		t.Fatalf("expected the Phase 4 stub to return a non-nil, non-panicking error")
	}
}
