package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		" warn": slog.LevelWarn,
		"error": slog.LevelError,
		"":      slog.LevelWarn, // default
		"bogus": slog.LevelWarn, // unknown → default
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestInit_LevelFilters(t *testing.T) {
	var buf bytes.Buffer
	Init("warn", "text", &buf)

	slog.Debug("dbg-should-be-hidden")
	slog.Info("info-should-be-hidden")
	slog.Warn("warn-should-show", "k", "v")

	out := buf.String()
	if strings.Contains(out, "dbg-should-be-hidden") || strings.Contains(out, "info-should-be-hidden") {
		t.Errorf("sub-warn levels leaked at WARN level:\n%s", out)
	}
	if !strings.Contains(out, "warn-should-show") || !strings.Contains(out, "k=v") {
		t.Errorf("WARN with attrs missing:\n%s", out)
	}
	// Text handler drops the timestamp for cleaner CLI output.
	if strings.Contains(out, "time=") {
		t.Errorf("text handler should elide the time attr:\n%s", out)
	}
}

func TestInit_DebugLevelShowsDebug(t *testing.T) {
	var buf bytes.Buffer
	Init("debug", "text", &buf)
	slog.Debug("trace-visible", "cmd", "ls")
	if !strings.Contains(buf.String(), "trace-visible") {
		t.Errorf("debug not shown at debug level:\n%s", buf.String())
	}
}

func TestInit_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	Init("info", "json", &buf)
	slog.Info("hello", "n", 1)
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") || !strings.Contains(out, `"msg":"hello"`) {
		t.Errorf("expected JSON line, got:\n%s", out)
	}
}

func TestRedirect_SwitchesWriterKeepsLevel(t *testing.T) {
	var first, second bytes.Buffer
	Init("warn", "text", &first)
	Redirect(&second)

	slog.Warn("after-redirect")
	if first.Len() != 0 {
		t.Errorf("output went to the old writer after Redirect:\n%s", first.String())
	}
	if !strings.Contains(second.String(), "after-redirect") {
		t.Errorf("output did not go to the new writer:\n%s", second.String())
	}
	// Level (warn) must be preserved across the redirect.
	slog.Debug("still-hidden")
	if strings.Contains(second.String(), "still-hidden") {
		t.Errorf("Redirect did not preserve the WARN level:\n%s", second.String())
	}
}
