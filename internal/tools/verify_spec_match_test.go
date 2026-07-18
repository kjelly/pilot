package tools

import (
	"testing"
)

// TestVerifySpec_MatchExpected locks the fix for the
// "Expected vs captured-rc" matrix.
//
// The integration bug in pam-oidc-sshd was:
//
//	ansible <host> -m command -a "sh -c 'dpkg -s kc-ssh-pam >/dev/null 2>&1; echo $?'"
//	→ ansible's exit code is 0 (the wrapper), while stdout is "1" (the real result).
//	Pre-fix verifier saw rc=0 → reported PASS.
//	Post-fix verifier extracts rc-from-stdout=1 and compares to expected 0 → FAIL.
//
// The cases below exercise every branch the post-fix switch handles.
// To prove they aren't tautological, replace the typed compatibility adapter with the
// pre-fix default ("return rc == 0") and these tests all FAIL.
func TestVerifySpec_EvaluateV1Expected(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		detail   string
		rc       int
		wantPass bool
	}{
		// The C1 misclass integration bug: stdout "1", expected "0".
		// Pre-fix: PASS (rc=0). Post-fix: FAIL (rc-from-stdout=1).
		{"C1 missing rc-echo", "0", "(rc=0) 1", 0, false},

		// Symmetric: stdout "0", expected "0".
		{"C1 happy rc-echo", "0", "(rc=0) 0", 0, true},

		// Regex expected (C6): "OK provider=..."
		{"regex match", "^OK provider=kc-ssh-pam", "(rc=0) OK provider=kc-ssh-pam", 0, true},
		{"regex mismatch", "^OK provider=kc-ssh-pam", "(rc=0) something else", 0, false},

		// expected=present: rc=0 wins.
		{"present rc=0 pass", "present", "(rc=0) anything", 0, true},
		{"present rc=1 fail", "present", "(rc=1) anything", 1, false},

		// No Expected set: legacy behavior is preserved (rc-only).
		{"empty expected rc=0", "", "(rc=0) stuff", 0, true},
		{"empty expected rc=2", "", "(rc=2) stuff", 2, false},

		// Exact-string match expected, with the runner prefix stripped.
		{"exact match", "OK provider=kc-ssh-pam", "(rc=0) OK provider=kc-ssh-pam", 0, true},
		{"exact mismatch", "OK provider=kc-ssh-pam", "(rc=0) DIFFERENT", 0, false},

		// Real ansible ad-hoc (`-i inventory -l host`, i.e. every
		// `pilot vm-target verify` and any `pilot verify -i ...` call)
		// wraps stdout in its own "--one-line" callback format instead of
		// returning bare stdout: "<host> | CHANGED | rc=0 | (stdout) <val>".
		// Before the unwrapAdhocOneline fix, extractRC's isInt() check saw
		// this whole wrapped string (not a bare integer), returned -1, and
		// the former compatibility code fell back to comparing the ANSIBLE PROCESS's own
		// exit code (rc param, always 0 for the `cmd; echo $?` idiom, since
		// the trailing echo always succeeds) against expected — meaning a
		// numeric check using this repo's own recommended idiom ALWAYS
		// reported PASS under ad-hoc verify, regardless of the real result.
		// Caught live: `getent hosts siem-log-server >/dev/null 2>&1;
		// echo $?` on a host with no such alias genuinely printed "2", but
		// pre-fix verify reported PASS against expected "0".
		{
			"ad-hoc oneline real failure (getent rc=2, wrapped)",
			"0",
			"(rc=0) audit-log-forwarding | CHANGED | rc=0 | (stdout) 2",
			0, false,
		},
		{
			"ad-hoc oneline real success (rc=0, wrapped)",
			"0",
			"(rc=0) audit-log-forwarding | CHANGED | rc=0 | (stdout) 0",
			0, true,
		},
		// Same, but with the [WARNING]/[DEPRECATION WARNING] lines ansible
		// actually prepends in this environment (confirmed via `pilot
		// verify --probe` against a live vm-target) — the result line is
		// scanned from the end, so leading noise must not defeat it.
		{
			"ad-hoc oneline with deprecation warnings ahead of the result line",
			"0",
			"(rc=0) [WARNING]: Deprecation warnings can be disabled by setting `deprecation_warnings=False` in ansible.cfg.\n[DEPRECATION WARNING]: The '--one-line' argument is deprecated. This feature will be removed from ansible-core version 2.23.\naudit-log-forwarding | CHANGED | rc=0 | (stdout) 2",
			0, false,
		},
		// ~contains against a wrapped oneline result must match the real
		// stdout tail, not merely happen to find the substring somewhere in
		// the noisy wrapper text.
		{
			"ad-hoc oneline ~contains match",
			"~PILOT-SELFTEST",
			"(rc=0) log-server | CHANGED | rc=0 | (stdout) PILOT-SELFTEST-MARKER",
			0, true,
		},
		// When the command also wrote to stderr (e.g. `grep` on a missing
		// file: "grep: <path>: No such file or directory"), ansible appends
		// " (stderr) <text>" right after "(stdout) <text>" on the SAME
		// line with no separator. That tail must not be folded into the
		// captured stdout value — caught live via `pilot verify --probe`
		// against docs/verification/audit-log-forwarding.md's C16 with no
		// forward config present: real stdout was "2", but the unwrapped
		// value became "2 (stderr) grep: ... No such file or directory"
		// (not a pure integer) and the former compatibility code fell back to the always-0
		// ansible process rc — the exact same false-PASS this fix targets.
		{
			"ad-hoc oneline stdout + stderr on one line",
			"0",
			"(rc=0) audit-log-forwarding | CHANGED | rc=0 | (stdout) 2 (stderr) grep: /etc/rsyslog.d/99-siem-forward.conf: No such file or directory",
			0, false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, msg := evaluateV1Expected(c.expected, c.detail, c.rc)
			if got != c.wantPass {
				t.Errorf("evaluateV1Expected(%q, %q, rc=%d) = %v (msg=%q), want %v",
					c.expected, c.detail, c.rc, got, msg, c.wantPass)
			}
		})
	}
}

// TestVerifySpec_StripRunnerPrefix is the tiny unit that backs the
// integration fix. The pre-fix code never stripped "rc echo"
// integers from the captured detail; this regression would have
// silently re-introduced C1 misclassification.
//
// To prove the test isn't tautological: replace stripRunnerPrefix with
// `return s` — the integer-only case stops returning "" and the
// helper stops recognizing rc-echo.
func TestVerifySpec_StripRunnerPrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1", ""},
		{"0", ""},
		{"42", ""},
		{"(rc=0) actual stdout", "actual stdout"},
		{"(rc=1) anything", "anything"},
		{"(rc=0)", ""},
		{"hello world", "hello world"},
	}
	for _, c := range cases {
		got := stripRunnerPrefix(c.in)
		if got != c.want {
			t.Errorf("stripRunnerPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVerifySpec_ExtractRC — the helper that recovers the rc-echo
// from stdout, ignoring the runner's own prepended rc.
//
// Pre-fix: extractRC always returned -1 or 0; the verifier never
// realized stdout carried the real rc.
//
// To prove the test isn't tautological: revert extractRC to a
// simple `return -1` — all rc-echo cases stop working.
func TestVerifySpec_ExtractRC(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		// Pure rc-echo integer.
		{"0", 0},
		{"1", 1},
		{"42", 42},
		// Runner prefix + rc-echo integer (the common shape).
		{"(rc=0) 0", 0},
		{"(rc=1) 1", 1},
		{"(rc=0) long output", -1},
		// No rc anywhere.
		{"hello", -1},
		{"", -1},
	}
	for _, c := range cases {
		got := extractRC(c.in)
		if got != c.want {
			t.Errorf("extractRC(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestVerifySpec_MatchExpected_Substring locks the `~` prefix that lets
// a spec say "stdout contains substring". This is the same substring
// mode the C5 os-patch-sla row uses: systemctl is-active returns
// `active` somewhere inside multi-line stdout, and we only care that
// the substring is present.
func TestVerifySpec_EvaluateV1Expected_Substring(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		detail   string
		wantPass bool
	}{
		{"substring present", "~active", "(rc=0) test-vm | CHANGED | rc=0 | (stdout) active", true},
		{"substring absent", "~running", "(rc=0) test-vm | CHANGED | rc=0 | (stdout) inactive", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := evaluateV1Expected(c.expected, c.detail, 0)
			if got != c.wantPass {
				t.Errorf("evaluateV1Expected(%q, %q) = %v want %v", c.expected, c.detail, got, c.wantPass)
			}
		})
	}
}
