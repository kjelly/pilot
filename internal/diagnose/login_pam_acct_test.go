package diagnose

import (
	"strings"
	"testing"
)

// Real `sssctl user-checks -a acct -s sshd <user>` output captured on an
// Ubuntu 24.04 FreeIPA client (SSSD 2.9.4) on 2026-10-13. The verdict line is
// on stderr and the exit status is 0 in every case — including the denial.
const (
	sssctlStdoutKnownUser = "user: pilot-login-canary\naction: acct\nservice: sshd\n\nSSSD nss user lookup result:\n - user name: pilot-login-canary\n - user id: 273800003\n - group id: 273800003\n - gecos: Pilot LoginCanary\n - home directory: /home/pilot-login-canary\n - shell: /bin/sh\n\nSSSD InfoPipe user lookup result:\n - name: pilot-login-canary\n - uidNumber: 273800003\n - gidNumber: 273800003\n - gecos: Pilot LoginCanary\n - homeDirectory: /home/pilot-login-canary\n - loginShell: /bin/sh\n\ntesting pam_acct_mgmt\n\n"
	sssctlStderrAllowed   = "pam_acct_mgmt: Success\n\nPAM Environment:\n - no env -\n"
	sssctlStderrDenied    = "pam_acct_mgmt: Permission denied\n\nPAM Environment:\n - no env -\n"
	sssctlStdoutUnknown   = "user: nosuchcanary\naction: acct\nservice: sshd\n\ntesting pam_acct_mgmt\n\n"
	sssctlStderrUnknown   = "sss_getpwnam_r failed with [0].\nUser name lookup with [nosuchcanary] failed.\nInfoPipe User lookup with [nosuchcanary] failed.\npam_acct_mgmt: Authentication failure\n\nPAM Environment:\n - no env -\n"
)

func TestLoginSteps_PamAccountStepPerUser(t *testing.T) {
	steps := LoginSteps("web1", []string{"alice"})
	for _, s := range steps {
		if s.ID == "pam-acct-sshd:alice" {
			if s.Module != "command" || s.Command != "sudo sssctl user-checks -a acct -s sshd alice" {
				t.Fatalf("pam-acct-sshd step = %+v", s)
			}
			return
		}
	}
	t.Fatal("missing pam-acct-sshd:alice step")
}

func TestParsePamAcctResult_RealCaptures(t *testing.T) {
	cases := []struct {
		name          string
		res           AdHocResult
		want          string
		wantFound     bool
		wantAllowedOK bool
	}{
		{"allowed", AdHocResult{RCKnown: true, RC: 0, Stdout: sssctlStdoutKnownUser, Stderr: sssctlStderrAllowed}, "Success", true, true},
		{"hbac denied (rc 0!)", AdHocResult{RCKnown: true, RC: 0, Stdout: sssctlStdoutKnownUser, Stderr: sssctlStderrDenied}, "Permission denied", true, false},
		{"unknown user", AdHocResult{RCKnown: true, RC: 0, Stdout: sssctlStdoutUnknown, Stderr: sssctlStderrUnknown}, "Authentication failure", true, false},
		// The "testing pam_acct_mgmt" banner on stdout must not count as a result.
		{"stdout only, no verdict", AdHocResult{RCKnown: true, RC: 0, Stdout: sssctlStdoutKnownUser}, "", false, false},
	}
	for _, c := range cases {
		got, found := parsePamAcctResult(c.res)
		if got != c.want || found != c.wantFound {
			t.Errorf("%s: parse = (%q, %v), want (%q, %v)", c.name, got, found, c.want, c.wantFound)
		}
		if found && (got == "Success") != c.wantAllowedOK {
			t.Errorf("%s: allowed = %v, want %v", c.name, got == "Success", c.wantAllowedOK)
		}
	}
}

func TestBuildLoginUserOutput_PamAccountDenialVerdict(t *testing.T) {
	hostOK := LoginHostOutput{SssdActive: true, HasKerberosMachineIdentity: true}
	base := func(stderr string) []StepResult {
		return []StepResult{
			stepResult("getent-passwd:canary", 0, "pilot-login-canary:*:273800003:273800003::/home/pilot-login-canary:/bin/sh"),
			stepResult("sudo-l:canary", 1, "User pilot-login-canary is not allowed to run sudo on web1."),
			{Step: Step{ID: "pam-acct-sshd:canary"}, Result: AdHocResult{RCKnown: true, RC: 0, Stdout: sssctlStdoutKnownUser, Stderr: stderr}},
		}
	}
	denied := BuildLoginUserOutput("canary", "web1", hostOK, base(sssctlStderrDenied), false, nil, nil)
	if !denied.PamAccountChecked || denied.PamAccountAllowed || denied.PamAccountResult != "Permission denied" {
		t.Fatalf("denied = %+v", denied)
	}
	if !strings.Contains(denied.Verdict, "PAM account management for sshd denies") {
		t.Errorf("denied verdict = %q", denied.Verdict)
	}
	allowed := BuildLoginUserOutput("canary", "web1", hostOK, base(sssctlStderrAllowed), false, nil, nil)
	if !allowed.PamAccountChecked || !allowed.PamAccountAllowed || strings.Contains(allowed.Verdict, "denies") {
		t.Fatalf("allowed = %+v", allowed)
	}
	// A host-level failure still wins over the per-user PAM result.
	hostDown := BuildLoginUserOutput("canary", "web1", LoginHostOutput{}, base(sssctlStderrDenied), false, nil, nil)
	if !strings.Contains(hostDown.Verdict, "host-level failure") {
		t.Errorf("host-level failure must take precedence, got %q", hostDown.Verdict)
	}
}

func TestDecodeAdHocResult_KeepsStderr(t *testing.T) {
	doc := `{"plays":[{"tasks":[{"hosts":{"web1":{"stdout":"testing pam_acct_mgmt","stderr":"pam_acct_mgmt: Permission denied","rc":0}}}]}]}`
	got, err := DecodeAdHocResult(doc, "web1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Stderr != "pam_acct_mgmt: Permission denied" || got.RC != 0 {
		t.Fatalf("decoded = %+v", got)
	}
}
