package diagnose

import (
	"encoding/json"
	"testing"
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
