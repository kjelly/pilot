package sanitizer

import "testing"

func TestSanitizePasswords(t *testing.T) {
	r := New()
	in := `password=secret123 token=abc.foo.bar api_key=xyz`
	out := r.Sanitize(in)
	if want := "password=[REDACTED]"; !contains(out, want) {
		t.Errorf("expected %q in output, got: %s", want, out)
	}
}

func TestSanitizePrivateKey(t *testing.T) {
	r := New()
	in := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
-----END OPENSSH PRIVATE KEY-----`
	out := r.Sanitize(in)
	if contains(out, "b3BlbnNzaC1rZXktdjEAAAA") {
		t.Errorf("private key was not redacted: %s", out)
	}
	if !contains(out, "[REDACTED-PRIVATE-KEY]") {
		t.Errorf("expected redaction marker, got: %s", out)
	}
}

func TestSanitizeShadow(t *testing.T) {
	r := New()
	in := `root:$6$abc$xyz:19000:0:99999:7:::`
	out := r.Sanitize(in)
	if contains(out, "$6$abc$xyz") {
		t.Errorf("shadow hash was not redacted: %s", out)
	}
}

func TestSanitizeIPv4IsOptIn(t *testing.T) {
	// Default New() does NOT redact IPv4 — the previous behaviour was
	// too aggressive (it stripped IPs from inventory output).
	r := New()
	in := `Server is at 10.0.1.42 but the controller is 192.168.1.1.`
	out := r.Sanitize(in)
	if !contains(out, "10.0.1.42") {
		t.Errorf("default Sanitize should preserve IPv4 (it is opt-in now): %s", out)
	}

	// NewWith(OptInRules...) DOES redact IPv4 — useful when scrubbing
	// logs for sharing with third parties.
	agg := NewWith(OptInRules...)
	out = agg.Sanitize(in)
	if contains(out, "10.0.1.42") || contains(out, "192.168.1.1") {
		t.Errorf("NewWith+OptInRules should redact IPv4: %s", out)
	}
	if !contains(out, "[REDACTED-IP]") {
		t.Errorf("expected [REDACTED-IP] marker: %s", out)
	}
}

func TestWithExtraRules(t *testing.T) {
	r := New().WithExtraRules(OptInRules...)
	in := `host 10.0.0.1; password=hunter2; admin@x.io`
	out := r.Sanitize(in)
	if contains(out, "10.0.0.1") {
		t.Errorf("extra IPv4 rule did not apply: %s", out)
	}
	if contains(out, "hunter2") {
		t.Errorf("default password rule still missing: %s", out)
	}
	if contains(out, "admin@x.io") {
		t.Errorf("default email rule still missing: %s", out)
	}
}

func TestSanitizeEmail(t *testing.T) {
	r := New()
	in := `contact admin@example.com for help`
	out := r.Sanitize(in)
	if contains(out, "admin@example.com") {
		t.Errorf("email not redacted: %s", out)
	}
}

func TestSanitizeNoop(t *testing.T) {
	r := New()
	in := `this is a perfectly normal log line\nwith some output`
	if got := r.Sanitize(in); got != in {
		t.Errorf("expected no change, got: %s", got)
	}
}

func TestSanitizePasswordsFineGrained(t *testing.T) {
	r := New()
	tests := []struct {
		in   string
		want string
	}{
		{`password: "{{ mysql_pwd }}"`, `password: "{{ mysql_pwd }}"`},
		{`secret: yes`, `secret: yes`},
		{`secret: true`, `secret: true`},
		{`password: "secret123"`, `password: "[REDACTED]"`},
	}
	for _, tc := range tests {
		got := r.Sanitize(tc.in)
		if got != tc.want {
			t.Errorf("Sanitize(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
