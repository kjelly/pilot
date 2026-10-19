package loginprobe

import (
	"strings"
	"testing"
)

func TestRedact_RemovesKeyMaterial(t *testing.T) {
	in := "debug1: Offering public key: /etc/pilot/login-probe/id_ed25519 ED25519 SHA256:abc\n" +
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n" +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxkZXh0cmFleGFtcGxlZXhhbXBsZWV4YW1wbGU canary\n" +
		"Load key \"/etc/pilot/login-probe/id_ed25519\": Permission denied"
	out := Redact(in)
	for _, leak := range []string{"BEGIN OPENSSH", "b3BlbnNzaC1", "AAAAC3NzaC1lZDI1NTE5"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked through Redact:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "Permission denied") {
		t.Errorf("non-secret diagnostics must survive: %s", out)
	}
}

func TestSummarize_PrefersTheLastNonDebugLine(t *testing.T) {
	stderr := "debug1: Connecting to a.x port 22.\ndebug1: Server accepts key: /etc/pilot/login-probe/id_ed25519\nConnection closed by 192.0.2.1 port 22\r\n"
	if got := Summarize(stderr); got != "Connection closed by 192.0.2.1 port 22" {
		t.Errorf("Summarize = %q", got)
	}
	if got := Summarize("debug1: only debug\n"); got != "debug1: only debug" {
		t.Errorf("Summarize with only debug lines = %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := Summarize(long); len(got) > maxSummaryLen+4 {
		t.Errorf("Summarize did not truncate: %d", len(got))
	}
}
