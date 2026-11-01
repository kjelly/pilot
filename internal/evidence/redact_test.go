package evidence

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretSourcesAndScan(t *testing.T) {
	root := filepath.Join("testdata", "closure")
	sources, skipped := SecretSources(root, []string{
		"-e", "@vaultdir/sandbox.yaml", "-e", "@vaultdir/encrypted.yaml", "-e", "@vaultdir/missing.yaml",
		"-e", "target_group=all", "-e", "api_token=tok-0123456789", "-e", "ssh_private_key_file=/tmp/key",
	})
	keys := map[string]bool{}
	for _, s := range sources {
		keys[s.Key] = true
	}
	// Secret values, including short ones, are scanned; domains and paths are excluded.
	for _, want := range []string{"vaultdir/sandbox.yaml:ipa_admin_password", "-e api_token", "vaultdir/sandbox.yaml:short_pw"} {
		if !keys[want] {
			t.Fatalf("missing source %q in %v", want, keys)
		}
	}
	for _, not := range []string{"vaultdir/sandbox.yaml:ipa_domain", "vaultdir/sandbox.yaml:ssh_private_key_file", "-e ssh_private_key_file", "-e target_group"} {
		if keys[not] {
			t.Fatalf("unexpected source %q", not)
		}
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %v", skipped)
	}
	outputs := map[string]string{
		"L4 apply": "TASK [kinit]\nchanged: [ipa] => {\"cmd\": \"kinit\", \"stdin\": \"Sup3rS3cretPw!\"}\n",
		"L6 idem":  "clean output\n",
		"L5":       "token tok-0123456789 printed twice tok-0123456789",
	}
	red := Redact(outputs, sources, skipped)
	if red.Sources != len(sources) || len(red.Hits) != 2 {
		t.Fatalf("redaction = %+v", red)
	}
	if red.Hits[0] != (Hit{Step: "L4 apply", Key: "vaultdir/sandbox.yaml:ipa_admin_password", Count: 1}) {
		t.Fatalf("hit[0] = %+v", red.Hits[0])
	}
	if red.Hits[1] != (Hit{Step: "L5", Key: "-e api_token", Count: 2}) {
		t.Fatalf("hit[1] = %+v", red.Hits[1])
	}
	clean := Redact(map[string]string{"x": "nothing"}, sources, nil)
	if len(clean.Hits) != 0 || clean.Hits == nil {
		t.Fatalf("clean scan must report an empty, non-nil hit list: %+v", clean.Hits)
	}
}

func TestInlinePayloadSecretsAreRedactedAndScanned(t *testing.T) {
	const sentinel = "SentinelValue-225"
	cases := [][]string{
		{"-e", "target_group=all api_token=" + sentinel},
		{"--extra-vars", `{"target_group":"all","api_token":"` + sentinel + `"}`},
		{"-eapi_token=" + sentinel},
		{"-e=api_token=" + sentinel},
		{"--extra-vars=api_token=" + sentinel},
		{"-e", "target_group=all api_token='" + sentinel + " with spaces'"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if got := RedactCommandLine(args); strings.Contains(got, sentinel) || !strings.Contains(got, "<redacted>") {
				t.Fatalf("unsafe command: %s", got)
			}
			sources, skipped := SecretSources(t.TempDir(), args)
			if len(sources) != 1 || len(skipped) != 0 {
				t.Fatalf("secret not scanned: sources=%+v skipped=%v", sources, skipped)
			}
			if hits := Scan(map[string]string{"step": sources[0].value}, sources); len(hits) != 1 {
				t.Fatalf("sentinel output not detected: %+v", hits)
			}
			rec := &Record{Error: "failed with " + sources[0].value, Operator: sources[0].value, Steps: []Step{{Note: sources[0].value}}}
			if err := SanitizeRecord(rec, sources); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(rec)
			if strings.Contains(string(raw), sentinel) {
				t.Fatalf("secret persisted: %s", raw)
			}
		})
	}
	sources, skipped := SecretSources(t.TempDir(), []string{"-e", `api_token='unterminated`})
	if len(sources) != 0 || len(skipped) != 1 || strings.Contains(skipped[0], "unterminated") {
		t.Fatalf("unsupported syntax must be explicitly skipped without payload: %+v %v", sources, skipped)
	}
}

func TestShortSecretsSanitizeMetadataWithoutCorruptingFingerprints(t *testing.T) {
	sources, skipped := SecretSources(t.TempDir(), []string{"-e", "api_token=abc"})
	if len(sources) != 1 || len(skipped) != 0 {
		t.Fatalf("short known secret ignored: %+v %v", sources, skipped)
	}
	hash := "abc" + strings.Repeat("0", 61)
	rec := &Record{Error: "failed abc", PilotBinary: Binary{SHA256: hash}}
	if err := SanitizeRecord(rec, sources); err != nil {
		t.Fatal(err)
	}
	if rec.Error != "failed <redacted>" || rec.PilotBinary.SHA256 != hash {
		t.Fatalf("metadata/fingerprint sanitization: %+v", rec)
	}
}
