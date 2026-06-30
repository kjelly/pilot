package tools

import (
	"testing"
)

// TestVerifySpec_MatchExpected locks the fix for the
// "Expected vs captured-rc" matrix.
//
// The integration bug in pam-oidc-sshd was:
//
//   ansible <host> -m command -a "sh -c 'dpkg -s kc-ssh-pam >/dev/null 2>&1; echo $?'"
//   → ansible's exit code is 0 (the wrapper), while stdout is "1" (the real result).
//   Pre-fix verifier saw rc=0 → reported PASS.
//   Post-fix verifier extracts rc-from-stdout=1 and compares to expected 0 → FAIL.
//
// The cases below exercise every branch the post-fix switch handles.
// To prove they aren't tautological, point matchExpected back at the
// pre-fix default ("return rc == 0") and these tests all FAIL.
func TestVerifySpec_MatchExpected(t *testing.T) {
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
		{"regex match",   "^OK provider=kc-ssh-pam", "(rc=0) OK provider=kc-ssh-pam", 0, true},
		{"regex mismatch", "^OK provider=kc-ssh-pam", "(rc=0) something else", 0, false},

		// expected=present: rc=0 wins.
		{"present rc=0 pass", "present", "(rc=0) anything", 0, true},
		{"present rc=1 fail", "present", "(rc=1) anything", 1, false},

		// No Expected set: legacy behavior is preserved (rc-only).
		{"empty expected rc=0", "", "(rc=0) stuff", 0, true},
		{"empty expected rc=2", "", "(rc=2) stuff", 2, false},

		// Exact-string match expected, with the runner prefix stripped.
		{"exact match",   "OK provider=kc-ssh-pam", "(rc=0) OK provider=kc-ssh-pam", 0, true},
		{"exact mismatch", "OK provider=kc-ssh-pam", "(rc=0) DIFFERENT", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, msg := matchExpected(c.expected, c.detail, c.rc)
			if got != c.wantPass {
				t.Errorf("matchExpected(%q, %q, rc=%d) = %v (msg=%q), want %v",
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
func TestVerifySpec_MatchExpected_Substring(t *testing.T) {
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
			got, _ := matchExpected(c.expected, c.detail, 0)
			if got != c.wantPass {
				t.Errorf("matchExpected(%q, %q) = %v want %v", c.expected, c.detail, got, c.wantPass)
			}
		})
	}
}
