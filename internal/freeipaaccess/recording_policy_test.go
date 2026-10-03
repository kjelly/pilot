package freeipaaccess

import (
	"testing"
)

// The real-fixture tests below read JSON-RPC host_show responses captured as
// a pilot-access-gateway service principal against FreeIPA 4.13.1
// (per-host recording spec §9 Phase 0; see
// docs/evidence/pilot-access-gateway/2026-09-23-phase0-userclass-capture.md).

func parseHostFixture(t *testing.T, name string) Host {
	t.Helper()
	m, err := decodeShow(loadFixture(t, name))
	if err != nil {
		t.Fatalf("decodeShow(%s): %v", name, err)
	}
	return parseHost(m)
}

func TestParseHost_RealUserClassFixture(t *testing.T) {
	h := parseHostFixture(t, "host_show_userclass_rights.json")
	if h.FQDN != "phr-ta.ipa.pilot.internal" {
		t.Fatalf("FQDN = %q", h.FQDN)
	}
	want := HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}
	if h.SSHRecording != want {
		t.Fatalf("SSHRecording = %+v, want %+v", h.SSHRecording, want)
	}
	if got := h.Annotations["location"]; got != "DC1" {
		t.Fatalf("annotation location = %q, want DC1 (annotations unaffected by the policy parser)", got)
	}
	if _, leaked := h.Annotations["ssh-recording"]; leaked || len(h.Annotations) != 1 {
		t.Fatalf("policy marker leaked into annotations: %v", h.Annotations)
	}
}

// Branch R: a response without attributelevelrights (the request did not ask
// for rights, or the server withheld them) proves nothing about the marker.
func TestParseHost_UserClassUnreadableIsUnavailable(t *testing.T) {
	h := parseHostFixture(t, "host_show_userclass.json")
	if !h.SSHRecording.Unreadable || h.SSHRecording.Valid || h.SSHRecording.Reason != "userclass_unreadable" {
		t.Fatalf("SSHRecording = %+v, want unreadable", h.SSHRecording)
	}

	m, err := decodeShow(loadFixture(t, "host_show_userclass_rights.json"))
	if err != nil {
		t.Fatal(err)
	}
	rights := m["attributelevelrights"].(map[string]any)
	rights["userclass"] = "sc"
	if got := parseHost(m).SSHRecording; !got.Unreadable {
		t.Fatalf("userclass rights without r: SSHRecording = %+v, want unreadable", got)
	}
	delete(rights, "userclass")
	if got := parseHost(m).SSHRecording; !got.Unreadable {
		t.Fatalf("userclass rights missing: SSHRecording = %+v, want unreadable", got)
	}
}

func TestParseHostSSHRecording(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want HostRecordingPolicy
	}{
		{"Absent", []string{"external-provisioning", "pilot.annotation.location=DC1"}, HostRecordingPolicy{Valid: true}},
		{"AbsentEmpty", nil, HostRecordingPolicy{Valid: true}},
		{"Off", []string{"pilot.policy.ssh-recording=off"}, HostRecordingPolicy{Present: true, Mode: "off", Valid: true}},
		{"TerminalOutput", []string{"x", "pilot.policy.ssh-recording=terminal_output"}, HostRecordingPolicy{Present: true, Mode: "terminal_output", Valid: true}},
		{"DuplicateInvalid", []string{"pilot.policy.ssh-recording=off", "pilot.policy.ssh-recording=terminal_output"}, HostRecordingPolicy{Present: true, Reason: "duplicate"}},
		{"EmptyInvalid", []string{"pilot.policy.ssh-recording="}, HostRecordingPolicy{Present: true, Reason: "malformed"}},
		{"CaseVariantPrefixMalformed", []string{"Pilot.Policy.SSH-Recording=terminal_output"}, HostRecordingPolicy{Present: true, Reason: "malformed"}},
		{"UnknownInvalid", []string{"pilot.policy.ssh-recording=banana"}, HostRecordingPolicy{Present: true, Reason: "unknown_value"}},
		{"TerminalIOReservedInvalid", []string{"pilot.policy.ssh-recording=terminal_io"}, HostRecordingPolicy{Present: true, Reason: "unknown_value"}},
		{"ValueCaseIsExact", []string{"pilot.policy.ssh-recording=Terminal_Output"}, HostRecordingPolicy{Present: true, Reason: "unknown_value"}},
		{"OtherPolicyNamespaceIgnored", []string{"pilot.policy.userclass-canary=1"}, HostRecordingPolicy{Valid: true}},
		{"PrefixOnlySubstringIgnored", []string{"x-pilot.policy.ssh-recording=off"}, HostRecordingPolicy{Valid: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseHostSSHRecordingPolicy(c.in); got != c.want {
				t.Fatalf("parseHostSSHRecordingPolicy(%q) = %+v, want %+v", c.in, got, c.want)
			}
		})
	}
}

func TestParseHostSSHRecording_NotInAnnotations(t *testing.T) {
	uc := []string{"pilot.policy.ssh-recording=terminal_output", "pilot.annotation.owner=qa"}
	if got := parseAnnotations(uc); len(got) != 1 || got["owner"] != "qa" {
		t.Fatalf("parseAnnotations = %v, want only owner", got)
	}
}

func TestNewHostWithoutPolicy(t *testing.T) {
	h := NewHostWithoutPolicy("a.example")
	if h.FQDN != "a.example" || h.SSHRecording != (HostRecordingPolicy{Valid: true}) {
		t.Fatalf("NewHostWithoutPolicy = %+v", h)
	}
	if (Host{}).SSHRecording.Valid {
		t.Fatal("zero-value Host must not report a valid policy (fail closed)")
	}
}
