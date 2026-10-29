package accessgrants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readCapture loads a REAL ansible-playbook capture of the drift probe from
// testdata/ansible (stdout and stderr kept apart, exactly as ansible wrote
// them; only the machine's paths were rewritten to /work, /repo and /scratch).
// The captures came from running playbooks/check/freeipa-access-drift-probe.yml
// with ansible-core 2.19.2 against a localhost inventory with a hyphenated
// group (freeipa-server, the shape pilot inventories use), as
// testdata/ansible/README documents.
func readCapture(t *testing.T, name string) (stdout, stderr string) {
	t.Helper()
	out, err := os.ReadFile(filepath.Join("testdata", "ansible", name+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errOut, err := os.ReadFile(filepath.Join("testdata", "ansible", name+".stderr"))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), string(errOut)
}

// TestSummarizeAnsibleFailure_RealCaptures runs the extraction over real
// captures of every way the probe fails, on both streams. Each case has a
// should-trigger side (the message an operator needs is shown) and a
// should-not-leak side (nothing from the vault file's content, and none of
// ansible's snippet lines, survives).
func TestSummarizeAnsibleFailure_RealCaptures(t *testing.T) {
	const sentinel = "Sup3rS3cretPw"
	for _, tc := range []struct {
		name     string
		varsFile string
		want     []string
		notWant  []string
	}{
		{
			// stdout carries the gate message, stderr only the hyphenated-group
			// warning: the message must win over the warning.
			name:    "gate_missing",
			want:    []string{"No usable FreeIPA admin password", "ipa_admin_password", "freeipa.admin.password", "Both are missing or too short"},
			notWant: []string{"Invalid characters were found in group names", "Origin:", "^ column"},
		},
		{
			// {{ 1 / 0 }} as the vault value: rescued, so the gate speaks.
			name:    "vault_template_unresolvable",
			want:    []string{"No usable FreeIPA admin password", "Both are missing or too short"},
			notWant: []string{"censored", "hidden by no_log"},
		},
		{
			// The vault file is not valid YAML: ansible prints the source line.
			name:     "vault_bad_yaml",
			varsFile: "/repo/.vault/main.yaml",
			want:     []string{"could not parse /work/bad-vault.yaml:1:34", "valid YAML", "withheld"},
			notWant:  []string{sentinel, "oops", "ipa_admin_password", "Colons in unquoted values", "column 34", "raw: echo"},
		},
		{
			name:    "vault_encrypted_no_password",
			want:    []string{"Attempting to decrypt but no vault secrets found"},
			notWant: []string{"Failed to parse inventory", "<<< caused by >>>"},
		},
		{
			name:    "vault_wrong_password",
			want:    []string{"Decryption failed"},
			notWant: []string{"Failed to parse inventory", "<<< caused by >>>"},
		},
		{
			// kinit failed; the task is no_log, so ansible printed "censored".
			name:    "kinit_censored",
			want:    []string{"Kinit admin for read-only drift probe", "hidden by no_log"},
			notWant: []string{"Python interpreter", "Origin:", "Module failed"},
		},
		{
			name:    "host_unreachable",
			want:    []string{"ipa1 is unreachable", "Connection refused"},
			notWant: []string{"Origin:", "^ column"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr := readCapture(t, tc.name)
			got := summarizeAnsibleFailure(stdout, stderr, tc.varsFile)
			if got == "" {
				t.Fatalf("nothing extracted from a real failure\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q does not contain %q", got, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("summary %q must not contain %q", got, w)
				}
			}
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("summary spans several lines: %q", got)
			}
		})
	}

	// The should-trigger for the leak: the real capture of a malformed vault
	// really does carry the secret, so the absence above is the extraction's
	// doing and not an empty fixture.
	t.Run("the malformed-vault capture really contains the secret", func(t *testing.T) {
		_, stderr := readCapture(t, "vault_bad_yaml")
		if !strings.Contains(stderr, sentinel) {
			t.Fatalf("the vault_bad_yaml capture no longer echoes the vault line; it can no longer prove the leak:\n%s", stderr)
		}
	})
}

// TestSummarizeAnsibleFailure_NothingRecognisable: output with no failure
// message yields "", and DriftProbe then says so instead of dumping the
// transcript.
func TestSummarizeAnsibleFailure_NothingRecognisable(t *testing.T) {
	for _, tc := range []struct{ name, stdout, stderr string }{
		{"empty", "", ""},
		{"warning only", "", "[WARNING]: Invalid characters were found in group names but not replaced, use -vvvv to see details\n"},
		{"a source snippet alone", "", "1 ipa_admin_password: Sup3rS3cretPw: oops\n                                   ^ column 34\n"},
	} {
		if got := summarizeAnsibleFailure(tc.stdout, tc.stderr, ""); got != "" {
			t.Errorf("%s: summary = %q, want none", tc.name, got)
		}
	}
}

// TestRedactSecretish blanks password-shaped pairs and leaves the gate's own
// message (which names the keys but carries no value) alone.
func TestRedactSecretish(t *testing.T) {
	gate := "No usable FreeIPA admin password for the drift probe. Set ipa_admin_password (at least 8 characters) in the vault vars file, or freeipa.admin.password (at least 8 characters, not a template) in the roster."
	if got := redactSecretish(gate); got != gate {
		t.Errorf("the gate message was altered: %q", got)
	}
	for in, want := range map[string]string{
		"ipa_admin_password: Hunter2Hunter2":      "ipa_admin_password: [redacted]",
		`"ipa_admin_password": "Hunter2 Hunter2"`: `"ipa_admin_password": [redacted]`,
		"password=Hunter2Hunter2 next":            "password=[redacted] next",
		"freeipa.admin.password: 'a b c'":         "freeipa.admin.password: [redacted]",
	} {
		if got := redactSecretish(in); got != want {
			t.Errorf("redactSecretish(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSummarizeAnsibleFailure_ParseErrorWithoutOriginHintsTheVarsFile: when
// ansible gives no Origin for a parse error, the hint names the vars file the
// probe was given and still echoes nothing from ansible's message.
func TestSummarizeAnsibleFailure_ParseErrorWithoutOriginHintsTheVarsFile(t *testing.T) {
	got := summarizeAnsibleFailure("", "[ERROR]: Syntax Error while loading YAML.\n  found Sup3rS3cretPw\n", "/ws/.vault/main.yaml")
	if !strings.Contains(got, "check that /ws/.vault/main.yaml is valid YAML") || strings.Contains(got, "Sup3rS3cretPw") || strings.Contains(got, "Syntax Error") {
		t.Fatalf("summary = %q", got)
	}
}
