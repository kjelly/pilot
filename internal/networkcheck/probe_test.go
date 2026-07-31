package networkcheck

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// fakeRunner records every ad-hoc invocation and returns a canned
// script-module-envelope response per host, so Probe's parsing path is
// exercised exactly as it would be against real ansible output.
type fakeRunner struct {
	byHost map[string]func(args []string) (string, int, error)
	calls  []string
}

func (f *fakeRunner) run(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
	f.calls = append(f.calls, args[0])
	fn, ok := f.byHost[args[0]]
	if !ok {
		return "", 1, fmt.Errorf("no fake response configured for host %q", args[0])
	}
	return fn(args)
}

// scriptModuleResult wraps a JSON payload the way ansible ad-hoc's default
// (non --one-line) callback renders a `script` module result: a leading
// "<host> | CHANGED =>" header, then the module's own JSON envelope with
// our probe script's stdout embedded as a JSON string field. Mirrors what
// `ansible <host> -m script -a "..."` actually printed in a live smoke test
// (ansible-core 2.19) — see network-connectivity-preflight-plan.
func scriptModuleResult(t *testing.T, host, payload string) string {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"changed": true,
		"rc":      0,
		"stdout":  payload + "\n",
		"stderr":  "",
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s | CHANGED => %s", host, envelope)
}

func decodeRequestArg(t *testing.T, args []string) []probeRequest {
	t.Helper()
	// args = [host, "-i", inv, "-m", "script", "-a", "<path> <b64>", ...]
	var adhocArg string
	for i, a := range args {
		if a == "-a" {
			adhocArg = args[i+1]
			break
		}
	}
	parts := strings.SplitN(adhocArg, " ", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed -a arg: %q", adhocArg)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode probe payload: %v", err)
	}
	var reqs []probeRequest
	if err := json.Unmarshal(raw, &reqs); err != nil {
		t.Fatalf("unmarshal probe payload: %v", err)
	}
	return reqs
}

func TestProbe_PassAndFailMapCorrectly(t *testing.T) {
	edges := []Edge{
		{Requirement: "c->p.ldap", SourceHost: "src1", SourceAddr: "192.168.110.35", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389, EndpointName: "ldap"},
		{Requirement: "c->p.s3", SourceHost: "src1", SourceAddr: "192.168.110.35", TargetHost: "10.1.58.12", TargetKind: TargetInventory, Protocol: "tcp", Port: 8333, EndpointName: "s3"},
	}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			reqs := decodeRequestArg(t, args)
			if len(reqs) != 2 {
				t.Fatalf("expected 2 batched probes, got %d", len(reqs))
			}
			payload, _ := json.Marshal([]probeResponse{
				{Status: "reachable", Detail: "connected", ResolvedIP: "10.1.58.11", DurationMs: 5},
				{Status: "unreachable", Detail: "timeout", ResolvedIP: "10.1.58.12", DurationMs: 3000},
			})
			return scriptModuleResult(t, "src1", string(payload)), 0, nil
		},
	}}

	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Status != StatusPass {
		t.Fatalf("edge 0 status = %v, want PASS", results[0].Status)
	}
	if results[1].Status != StatusFail || results[1].Hint == "" {
		t.Fatalf("edge 1 = %+v, want FAIL with a non-empty hint", results[1])
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected edges sharing a source host to batch into 1 ad-hoc call, got %d", len(fr.calls))
	}
}

func TestProbe_UDPReachableUnconfirmedNeverReportsAsPass(t *testing.T) {
	edges := []Edge{
		{SourceHost: "src1", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "udp", Port: 88, EndpointName: "kerberosUdp"},
	}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			payload, _ := json.Marshal([]probeResponse{{Status: "reachable-unconfirmed", Detail: "datagram sent", ResolvedIP: "10.1.58.11"}})
			return scriptModuleResult(t, "src1", string(payload)), 0, nil
		},
	}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusReachableUnconfirmed {
		t.Fatalf("status = %v, want REACHABLE-UNCONFIRMED", results[0].Status)
	}
}

func TestProbe_SkipEdgesNeverReachTheNetwork(t *testing.T) {
	edges := []Edge{
		{SourceHost: "src1", TargetKind: TargetSkip, SkipReason: "no binding to check"},
	}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 0 {
		t.Fatalf("skip edge triggered an ad-hoc call: %v", fr.calls)
	}
	if results[0].Status != StatusSkip || results[0].Detail != "no binding to check" {
		t.Fatalf("unexpected skip result: %+v", results[0])
	}
}

func TestProbe_RunnerErrorMarksAllEdgesForThatHostAsError(t *testing.T) {
	edges := []Edge{
		{SourceHost: "src1", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389},
		{SourceHost: "src1", TargetHost: "10.1.58.12", TargetKind: TargetInventory, Protocol: "tcp", Port: 8333},
	}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			return "", 0, fmt.Errorf("ansible not found")
		},
	}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if r.Status != StatusError {
			t.Fatalf("edge %d status = %v, want ERROR", i, r.Status)
		}
	}
}

func TestProbe_UnparseableOutputBecomesErrorNotSilentSkip(t *testing.T) {
	edges := []Edge{{SourceHost: "src1", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389}}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			return "src1 | UNREACHABLE! => not connected to remote host", 4, nil
		},
	}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusError || results[0].Detail == "" {
		t.Fatalf("unparseable ansible output must surface as ERROR with detail, got %+v", results[0])
	}
}

func TestProbe_BatchesMultipleHostsIntoSeparateCalls(t *testing.T) {
	edges := []Edge{
		{SourceHost: "src1", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389},
		{SourceHost: "src2", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389},
	}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			payload, _ := json.Marshal([]probeResponse{{Status: "reachable", ResolvedIP: "10.1.58.11"}})
			return scriptModuleResult(t, "src1", string(payload)), 0, nil
		},
		"src2": func(args []string) (string, int, error) {
			payload, _ := json.Marshal([]probeResponse{{Status: "reachable", ResolvedIP: "10.1.58.11"}})
			return scriptModuleResult(t, "src2", string(payload)), 0, nil
		},
	}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 2 {
		t.Fatalf("distinct source hosts must not share a call, got calls=%v", fr.calls)
	}
	for _, r := range results {
		if r.Status != StatusPass {
			t.Fatalf("unexpected result: %+v", r)
		}
	}
}

func TestExtractScriptModuleStdout_SkipsDeprecationWarningsBeforeEnvelope(t *testing.T) {
	raw := "[DEPRECATION WARNING]: something.\n" +
		`src1 | CHANGED => {"changed": true, "rc": 0, "stdout": "[{\"status\":\"reachable\"}]\n", "stderr": ""}`
	got, err := extractScriptModuleStdout(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"status":"reachable"}]`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExtractScriptModuleStdout_NonZeroRCIsAnError(t *testing.T) {
	raw := `src1 | CHANGED => {"changed": true, "rc": 1, "stdout": "", "stderr": "Traceback..."}`
	if _, err := extractScriptModuleStdout(raw); err == nil {
		t.Fatal("non-zero script rc must surface as an error")
	}
}

func TestProbe_UnreachableHostEnvelopeBecomesError(t *testing.T) {
	// Real ansible ad-hoc shape for a connection failure: an envelope with
	// no "stdout"/"rc" fields at all. extractScriptModuleStdout decodes it
	// fine (Stdout ends up "") — Probe's outer "did we get N responses"
	// check is what actually turns this into ERROR, not the extractor.
	edges := []Edge{{SourceHost: "src1", TargetHost: "10.1.58.11", TargetKind: TargetInventory, Protocol: "tcp", Port: 389}}
	fr := &fakeRunner{byHost: map[string]func([]string) (string, int, error){
		"src1": func(args []string) (string, int, error) {
			return `src1 | UNREACHABLE! => {"unreachable": true, "msg": "Failed to connect"}`, 4, nil
		},
	}}
	results, err := Probe(context.Background(), edges, ProbeOptions{Inventory: "inv.yml"}, fr.run)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusError || results[0].Detail == "" {
		t.Fatalf("unreachable host must surface as ERROR with detail, got %+v", results[0])
	}
}
