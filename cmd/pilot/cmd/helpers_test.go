package cmd

import "testing"

func TestShortID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"abcdefgh", "abcdefgh"},
		{"abcdefghij", "abcdefgh"},
		{"abc", "abc"},
		{"", ""},
	}
	for _, c := range cases {
		if got := shortID(c.in); got != c.want {
			t.Errorf("shortID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncateForErr(t *testing.T) {
	short := "hello"
	if got := truncateForErr(short, 100); got != short {
		t.Errorf("short input should be unchanged, got %q", got)
	}
	long := "abcdefghijklmnopqrstuvwxyz0123456789"
	got := truncateForErr(long, 10)
	if len(got) <= 10 {
		t.Errorf("expected truncation marker, got %q", got)
	}
	if !contains(got, "[truncated]") {
		t.Errorf("truncation marker missing: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
