package diagnose

import (
	"reflect"
	"strings"
	"testing"
)

// testShlexSplit is a minimal, self-contained POSIX-word-splitting
// tokenizer (whitespace separates tokens; single- and double-quoted runs
// are literal and can concatenate with adjacent runs into the same
// token) — enough to verify shlexQuote/curlQueryCommand round-trip the
// way ansible's own shlex-based command-module tokenizer would, without
// depending on python/ansible being installed in the test environment.
// Double-quote handling matters here even though shlexQuote only ever
// emits single-quoted tokens: its '"'"' escape for an embedded single
// quote alternates through a double-quoted region, so a tokenizer that
// only understood single quotes would misparse that escape.
func testShlexSplit(s string) []string {
	var tokens []string
	var cur strings.Builder
	inToken := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n':
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
			i++
		case '\'':
			inToken = true
			i++
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			i++ // skip closing quote
		case '"':
			inToken = true
			i++
			for i < len(s) && s[i] != '"' {
				cur.WriteByte(s[i])
				i++
			}
			i++ // skip closing quote
		default:
			inToken = true
			cur.WriteByte(c)
			i++
		}
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func TestShlexQuote_RoundTripsTrickyValues(t *testing.T) {
	cases := []string{
		`{job="pilot-siem"} |= "error"`,
		`it's a test`,
		`a'b'c`,
		`plain`,
		``,
		`  leading and trailing spaces  `,
		`nested "double" 'single' quotes`,
	}
	for _, in := range cases {
		quoted := shlexQuote(in)
		got := testShlexSplit(quoted)
		if len(got) != 1 || got[0] != in {
			t.Errorf("shlexQuote(%q) = %q, testShlexSplit round-trip = %#v, want single token %q", in, quoted, got, in)
		}
	}
}

func TestCurlQueryCommand_BuildsExpectedTokensAndSkipsEmptyParams(t *testing.T) {
	cmd := curlQueryCommand("http://127.0.0.1:3100/loki/api/v1/query_range", [][2]string{
		{"query", `{job="pilot-siem"} |= "error"`},
		{"start", ""},
		{"end", "now"},
		{"limit", ""},
	})
	got := testShlexSplit(cmd)
	want := []string{
		"curl", "-sS", "-G", "http://127.0.0.1:3100/loki/api/v1/query_range",
		"--data-urlencode", `query={job="pilot-siem"} |= "error"`,
		"--data-urlencode", "end=now",
		"-w", `\nHTTP_STATUS:%{http_code}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("curlQueryCommand tokens = %#v, want %#v", got, want)
	}
}

func TestCurlQueryCommand_AllParamsPresent(t *testing.T) {
	cmd := curlQueryCommand("http://127.0.0.1:10912/api/v1/query_range", [][2]string{
		{"query", "up"},
		{"start", "2026-01-01T00:00:00Z"},
		{"end", "2026-01-01T01:00:00Z"},
		{"step", "30s"},
	})
	got := testShlexSplit(cmd)
	want := []string{
		"curl", "-sS", "-G", "http://127.0.0.1:10912/api/v1/query_range",
		"--data-urlencode", "query=up",
		"--data-urlencode", "start=2026-01-01T00:00:00Z",
		"--data-urlencode", "end=2026-01-01T01:00:00Z",
		"--data-urlencode", "step=30s",
		"-w", `\nHTTP_STATUS:%{http_code}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("curlQueryCommand tokens = %#v, want %#v", got, want)
	}
}

func TestSplitHTTPStatus_ExtractsBodyAndStatus(t *testing.T) {
	body, status, ok := SplitHTTPStatus("{\"status\":\"success\"}\nHTTP_STATUS:200")
	if !ok || body != `{"status":"success"}` || status != 200 {
		t.Fatalf("SplitHTTPStatus() = (%q, %d, %v), want (%q, 200, true)", body, status, ok, `{"status":"success"}`)
	}
}

func TestSplitHTTPStatus_UsesLastMarkerWhenBodyContainsLookalikeText(t *testing.T) {
	stdout := "{\"msg\":\"saw HTTP_STATUS:999 in a log line\"}\nHTTP_STATUS:200"
	body, status, ok := SplitHTTPStatus(stdout)
	if !ok || status != 200 || body != `{"msg":"saw HTTP_STATUS:999 in a log line"}` {
		t.Fatalf("SplitHTTPStatus() = (%q, %d, %v), want the real trailing marker (200), not the lookalike text", body, status, ok)
	}
}

func TestSplitHTTPStatus_MissingMarkerFails(t *testing.T) {
	if _, _, ok := SplitHTTPStatus("no marker here"); ok {
		t.Fatal("SplitHTTPStatus() ok = true, want false when the marker is absent")
	}
}

func TestSplitHTTPStatus_NonNumericStatusFails(t *testing.T) {
	if _, _, ok := SplitHTTPStatus("body\nHTTP_STATUS:notanumber"); ok {
		t.Fatal("SplitHTTPStatus() ok = true, want false when the status isn't a valid integer")
	}
}
