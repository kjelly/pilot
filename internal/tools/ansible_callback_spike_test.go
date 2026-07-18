package tools

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeAnsibleCallbackSpike(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		expected   []string
		wantStatus callbackProbeStatus
		wantRC     int
		wantOut    string
		wantErr    string
	}{
		{
			name:       "multiline success",
			fixture:    "success.json",
			expected:   []string{"localhost"},
			wantStatus: callbackStatusOK,
			wantRC:     0,
			wantOut:    "line1\nline2",
		},
		{
			name:       "module error",
			fixture:    "module-error.json",
			expected:   []string{"localhost"},
			wantStatus: callbackStatusModuleError,
			wantRC:     7,
			wantOut:    "bad-out",
		},
		{
			name:       "unreachable",
			fixture:    "unreachable.json",
			expected:   []string{"missing"},
			wantStatus: callbackStatusUnreachable,
			wantRC:     -1,
		},
		{
			name:       "complete callback missing expected host",
			fixture:    "empty.json",
			expected:   []string{"missing"},
			wantStatus: callbackStatusMissing,
			wantRC:     -1,
		},
		{
			name:     "truncated callback is runner error input",
			fixture:  "truncated.json",
			expected: []string{"localhost"},
			wantErr:  "decode ansible callback JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "ansible-callback", tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			results, err := decodeAnsibleCallbackSpike(raw, tt.expected)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("decode error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}
			got := results[0]
			if got.Status != tt.wantStatus || got.ExitCode != tt.wantRC || got.Stdout != tt.wantOut {
				t.Fatalf("result = %#v, want status=%s rc=%d stdout=%q", got, tt.wantStatus, tt.wantRC, tt.wantOut)
			}
		})
	}
}

func TestDecodeAnsibleCallbackSpike_UnexpectedHostFailsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ansible-callback", "success.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeAnsibleCallbackSpike(raw, []string{"other"})
	if err == nil || !strings.Contains(err.Error(), "unexpected hosts: localhost") {
		t.Fatalf("decode error = %v, want unexpected-host error", err)
	}
}

func TestCallbackRunnerErrorResults_InvocationTimeoutIsNotPerHostTimeout(t *testing.T) {
	results := callbackRunnerErrorResults(
		[]string{"host-a", "host-b"},
		errors.New("invocation timeout: callback document incomplete"),
	)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.Status != callbackStatusRunnerError {
			t.Fatalf("%s status = %s, want runner_error", result.Host, result.Status)
		}
	}
}

func TestNormalizeCallbackText_RemovesExactlyOneTrailingNewline(t *testing.T) {
	if got := normalizeCallbackText("line\r\n\r\n"); got != "line\n" {
		t.Fatalf("normalizeCallbackText() = %q, want %q", got, "line\n")
	}
}
