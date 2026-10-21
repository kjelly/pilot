package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replay actual versioned output so the supported error/warning distinction
// stays covered when the test host has a different logrotate version.
func TestRegression_LogrotateValidatorCapturedVersions(t *testing.T) {
	for _, version := range []string{"3.21.0", "3.22.0"} {
		for _, name := range []string{"valid", "unknown-option"} {
			t.Run(version+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				policy := filepath.Join(dir, "candidate [literal]' policy")
				if err := os.WriteFile(policy, []byte("# candidate\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				capture, err := os.ReadFile(filepath.Join("testdata", "logrotate-validation", version+"-"+name+".stderr"))
				if err != nil {
					t.Fatal(err)
				}
				capturePath := filepath.Join(dir, "capture")
				if err := os.WriteFile(capturePath, []byte(strings.ReplaceAll(string(capture), "POLICY_PATH", policy)), 0o600); err != nil {
					t.Fatal(err)
				}
				// These real captures all returned 0, including unknown options.
				// Locale is part of the contract because the diagnostic is parsed.
				bin := filepath.Join(dir, "logrotate")
				if err := os.WriteFile(bin, []byte("#!/bin/sh\ntest \"$LC_ALL\" = C || exit 42\n/bin/cat \"$CAPTURE\" >&2\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				env := append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "CAPTURE="+capturePath)
				_, err = runLogrotateValidate(policy, env)
				if (err == nil) != (name == "valid") {
					t.Errorf("%s/%s validation error=%v", version, name, err)
				}
				// A diagnostic about a different policy must not reject this one.
				if err := os.WriteFile(capturePath, capture, 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := runLogrotateValidate(policy, env); err != nil {
					t.Errorf("unrelated policy diagnostic rejected candidate: %v\n%s", err, out)
				}
			})
		}
	}
}
