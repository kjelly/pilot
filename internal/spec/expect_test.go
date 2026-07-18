package spec

import "testing"

func TestCompileV1ExpectedAndEval(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		probe    ProbeResult
		pass     bool
	}{
		{"empty defaults to rc zero", "", ProbeResult{ExitCode: 0}, true},
		{"present rejects nonzero", "present", ProbeResult{ExitCode: 2}, false},
		{"regex", "^ready", ProbeResult{Stdout: "ready\n", ExitCode: 0}, true},
		{"contains", "~world", ProbeResult{Stdout: "hello world"}, true},
		{"equals", "active", ProbeResult{Stdout: "active"}, true},
		{"legacy rc echo wins over controller rc", "0", ProbeResult{Stdout: "1", ExitCode: 0, LegacyExitCode: intPtr(1)}, false},
		{"legacy rc falls back to process rc", "2", ProbeResult{ExitCode: 2}, true},
		{"legacy negative preserves old atoi quirk", "-1", ProbeResult{ExitCode: 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := CompileV1Expected(tt.expected)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher.Eval(tt.probe).Pass; got != tt.pass {
				t.Fatalf("Eval(%q, %#v)=%v want=%v", tt.expected, tt.probe, got, tt.pass)
			}
		})
	}
}

func TestExpectEvalTypedStringMatchers(t *testing.T) {
	value := "alpha\n"
	expect := Expect{ExitCode: intPtr(0), Stdout: &StringMatcher{NotContains: stringPtr("beta")}, Stderr: &StringMatcher{Contains: stringPtr("warn")}}
	if verdict := expect.Eval(ProbeResult{Stdout: value, Stderr: "warning", ExitCode: 0}); !verdict.Pass {
		t.Fatalf("typed matcher should pass: %+v", verdict)
	}
	if verdict := (Expect{Stdout: &StringMatcher{Equals: stringPtr("a"), Contains: stringPtr("a")}}).Eval(ProbeResult{Stdout: "a"}); verdict.Pass {
		t.Fatalf("invalid union unexpectedly passed: %+v", verdict)
	}
	if _, err := CompileV1Expected("^["); err == nil {
		t.Fatal("invalid v1 regex compiled")
	}
}
