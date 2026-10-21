package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// callbackDoc builds a minimal single-task ansible.posix.json callback
// document for host, mirroring what ANSIBLE_STDOUT_CALLBACK=ansible.posix.json
// actually writes for one ad-hoc command.
func callbackDoc(t *testing.T, host string, rc int, stdout string, failed, unreachable bool) string {
	t.Helper()
	doc := map[string]any{
		"plays": []any{
			map[string]any{
				"tasks": []any{
					map[string]any{
						"hosts": map[string]any{
							host: map[string]any{
								"stdout":      stdout,
								"rc":          rc,
								"failed":      failed,
								"unreachable": unreachable,
							},
						},
					},
				},
			},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDecodeAdHocResult_Success(t *testing.T) {
	raw := callbackDoc(t, "web1", 0, "hello\n", false, false)
	got, err := DecodeAdHocResult(raw, "web1")
	if err != nil {
		t.Fatalf("DecodeAdHocResult() error = %v", err)
	}
	if got.RC != 0 || got.Stdout != "hello\n" || got.Failed || got.Unreachable {
		t.Fatalf("DecodeAdHocResult() = %+v, want rc=0 stdout=hello", got)
	}
}

func TestDecodeAdHocResult_NonzeroRCIsNotAnError(t *testing.T) {
	raw := callbackDoc(t, "web1", 3, "", true, false)
	got, err := DecodeAdHocResult(raw, "web1")
	if err != nil {
		t.Fatalf("DecodeAdHocResult() error = %v, want a decoded result (nonzero rc is data, not an error)", err)
	}
	if got.RC != 3 || !got.Failed {
		t.Fatalf("DecodeAdHocResult() = %+v, want rc=3 failed=true", got)
	}
}

func TestDecodeAdHocResult_Unreachable(t *testing.T) {
	raw := callbackDoc(t, "web1", 0, "", false, true)
	got, err := DecodeAdHocResult(raw, "web1")
	if err != nil {
		t.Fatalf("DecodeAdHocResult() error = %v", err)
	}
	if !got.Unreachable {
		t.Fatalf("DecodeAdHocResult() = %+v, want unreachable=true", got)
	}
}

func TestDecodeAdHocResult_MissingHostIsAnError(t *testing.T) {
	raw := callbackDoc(t, "web1", 0, "hello", false, false)
	if _, err := DecodeAdHocResult(raw, "web2"); err == nil {
		t.Fatal("DecodeAdHocResult() error = nil, want an error for a host absent from the callback doc")
	}
}

func TestDecodeAdHocResult_MalformedJSONIsAnError(t *testing.T) {
	if _, err := DecodeAdHocResult("not json", "web1"); err == nil {
		t.Fatal("DecodeAdHocResult() error = nil, want an error for malformed JSON")
	}
}

// These decoder cases consume actual Ansible captures, not invented CLI output.
func TestDecodeAdHocResult_CapturedStreams(t *testing.T) {
	for _, tc := range []struct {
		name, stdout, stderr string
		rc                   int
		unreachable          bool
	}{
		{"both", "out", "err", 7, false},
		{"stderr", "", "stderr only", 9, false},
		{"unreachable", "", "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/adhoc/" + tc.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeAdHocResult(string(data), "localhost")
			if err != nil {
				t.Fatal(err)
			}
			if got.Stdout != tc.stdout || got.Stderr != tc.stderr || got.RC != tc.rc || got.Unreachable != tc.unreachable || got.Message == "" || got.RCKnown == tc.unreachable {
				t.Fatalf("decoded = %+v", got)
			}
		})
	}
}

func TestRunSteps_TimeoutRetainsDecodedFacts(t *testing.T) {
	raw, err := os.ReadFile("testdata/adhoc/both.json")
	if err != nil {
		t.Fatal(err)
	}
	runner := func(context.Context, []string, int) (string, int, error) {
		return string(raw), 2, context.DeadlineExceeded
	}
	got := RunSteps(context.Background(), runner, "unused", "localhost", []Step{{ID: "partial"}}, time.Second)[0].Result
	if !errors.Is(got.RunErr, context.DeadlineExceeded) || got.Stdout != "out" || got.Stderr != "err" || got.RC != 7 || !got.RCKnown {
		t.Fatalf("timeout facts = %+v", got)
	}
}

func TestDNSArchKerberos_RunnerFailureIsUnknown(t *testing.T) {
	result := StepResult{Step: Step{ID: "auth"}, Result: AdHocResult{RunErr: context.DeadlineExceeded}}
	facts, kerberos := BuildDNSArchObservedFreeIPA("ipa", "reader@EXAMPLE.TEST", "/reader.keytab", result)
	if kerberos.State != FactUnknown || facts.GlobalForwarders.State != FactUnknown {
		t.Fatalf("runner failure mislabeled as unreachable: kerberos=%+v facts=%+v", kerberos, facts)
	}
	result.Result = AdHocResult{Unreachable: true, Message: "transport unavailable"}
	facts, kerberos = BuildDNSArchObservedFreeIPA("ipa", "reader@EXAMPLE.TEST", "/reader.keytab", result)
	if kerberos.State != FactUnreachable || facts.GlobalForwarders.Detail != "transport unavailable" {
		t.Fatalf("unreachable message was lost: kerberos=%+v facts=%+v", kerberos, facts)
	}
}

func TestSynthesis_UnavailableResultNeverBecomesSuccess(t *testing.T) {
	for _, name := range []string{"unreachable", "module-failure"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/adhoc/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			result, err := DecodeAdHocResult(string(data), "localhost")
			if err != nil {
				t.Fatal(err)
			}
			if result.HasCommandResult() || result.CommandSucceeded() {
				t.Fatalf("unavailable result accepted: %+v", result)
			}
			component := BuildComponentOutput("systemd", "", nil, true, []StepResult{{Step: Step{ID: "runtime-state"}, Result: result}})
			if component.RuntimePresent || component.RuntimeRunning || component.Verdict != "insufficient_evidence" {
				t.Fatalf("component=%+v", component)
			}
			health := BuildHostHealthOutput(true, []StepResult{{Step: Step{ID: "node-exporter"}, Result: result}})
			if health.NodeExporterActive || health.Verdict != "insufficient_evidence" {
				t.Fatalf("health=%+v", health)
			}
			path := BuildNetworkPathOutput("example.test", 80, "http", false, false, true, []StepResult{{Step: Step{ID: "name_resolution"}, Result: result}})
			if path.Verdict != "insufficient_evidence" || path.Layers[0].Passed || path.Layers[0].Evidence == "" {
				t.Fatalf("path=%+v", path)
			}
		})
	}
}
