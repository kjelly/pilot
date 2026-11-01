package evidence

import (
	"encoding/json"
	"fmt"
	"os"
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

func TestSecretKeyAncestryAndScalarSpellings(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "vars.yaml")
	raw := `api_token: /SlashLiteralSentinel225
admin_password: ~TildeLiteralSentinel225
client_secret: '{{BraceLiteralSentinel225}}'
credentials:
  value: NestedCredentialSentinel225
password:
  - value: ListedPasswordSentinel225
numeric_token: 0x75BCD15
boolean_secret: true
ssh_private_key_file: /tmp/explicit-key-reference
`
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	sources, skipped := SecretSources(root, []string{"-e", "@vars.yaml"})
	expected := []string{"/SlashLiteralSentinel225", "~TildeLiteralSentinel225", "{{BraceLiteralSentinel225}}", "NestedCredentialSentinel225", "ListedPasswordSentinel225", "0x75BCD15", "123456789", "true", "True"}
	for _, sentinel := range expected {
		if hits := Scan(map[string]string{"stderr": sentinel}, sources); len(hits) == 0 {
			t.Errorf("known literal/scalar secret was omitted: %q sources=%+v", sentinel, sources)
		}
		record := &Record{Error: "failed " + sentinel, Operator: sentinel, Steps: []Step{{Note: sentinel}}}
		if err := SanitizeRecord(record, sources); err != nil {
			t.Fatal(err)
		}
		doc, _ := json.Marshal(record)
		if strings.Contains(string(doc), sentinel) {
			t.Errorf("secret persisted in metadata: %s", doc)
		}
	}
	if len(skipped) == 0 || !strings.Contains(strings.Join(skipped, " "), "runtime result not scanned") {
		t.Fatalf("templated secret runtime uncertainty hidden: %v", skipped)
	}
	for _, source := range sources {
		if strings.Contains(source.Key, "ssh_private_key_file") {
			t.Fatalf("explicit file reference should remain a reference: %+v", source)
		}
	}
	jsonArgs := []string{"--extra-vars", `{"credentials":{"value":"NestedJsonSentinel225"},"password":[{"value":"ListJsonSentinel225"}],"numeric_token":123456789,"boolean_secret":true}`}
	sources, skipped = SecretSources(root, jsonArgs)
	if len(skipped) != 0 {
		t.Fatal(skipped)
	}
	for _, sentinel := range []string{"NestedJsonSentinel225", "ListJsonSentinel225", "123456789", "true"} {
		if len(Scan(map[string]string{"out": sentinel}, sources)) == 0 {
			t.Errorf("JSON scalar secret omitted: %s", sentinel)
		}
	}
	// All supported inline forms retain literal prefixes instead of inferring a path.
	for _, prefix := range []string{"/", "~", "{{"} {
		sentinel := prefix + "InlineLiteralSentinel225"
		for _, args := range [][]string{{"-e", "api_token=" + sentinel}, {"-eapi_token=" + sentinel}, {"-e=api_token=" + sentinel}, {"--extra-vars=api_token=" + sentinel}} {
			got, _ := SecretSources(root, args)
			if len(Scan(map[string]string{"out": sentinel}, got)) == 0 {
				t.Errorf("inline literal omitted: %s", fmt.Sprint(args))
			}
		}
	}
}

func TestJSONEncodedSecretDisclosureIsScannedAndSanitized(t *testing.T) {
	for _, sentinel := range []string{`Sentinel\Password225`, `Sentinel"Password225`, "Sentinel\nPassword225", "Sentinel<Password>225"} {
		t.Run(sentinel, func(t *testing.T) {
			payload, err := json.Marshal(map[string]string{"api_token": sentinel})
			if err != nil {
				t.Fatal(err)
			}
			sources, skipped := SecretSources(t.TempDir(), []string{"--extra-vars", string(payload)})
			if len(skipped) != 0 {
				t.Fatal(skipped)
			}
			// Native producer, rather than a test imitation of the escape algorithm.
			output, err := json.Marshal(map[string]string{"msg": sentinel})
			if err != nil {
				t.Fatal(err)
			}
			if len(Scan(map[string]string{"stderr": string(output)}, sources)) == 0 {
				t.Fatalf("JSON-encoded secret disclosure was reported clean: %s", output)
			}
			rec := &Record{Error: string(output), Steps: []Step{{Note: string(output)}}}
			if err := SanitizeRecord(rec, sources); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(rec)
			if strings.Contains(rec.Error, sentinel) || strings.Contains(rec.Error, string(output)) || !strings.Contains(rec.Error, "<redacted>") {
				t.Fatalf("encoded secret persisted: %s", raw)
			}
		})
	}
}

func TestSecretAliasExpansionIsBoundedAndAtomic(t *testing.T) {
	for _, levels := range []int{12, 16} {
		t.Run(fmt.Sprint(levels), func(t *testing.T) {
			root := t.TempDir()
			var raw strings.Builder
			raw.WriteString("api_token: PartialSecretSentinel225\na0: &a0 [AliasLeafSecretSentinel225]\n")
			for i := 1; i <= levels; i++ {
				fmt.Fprintf(&raw, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
			}
			fmt.Fprintf(&raw, "credentials: *a%d\n", levels)
			if err := os.WriteFile(filepath.Join(root, "vars.yaml"), []byte(raw.String()), 0600); err != nil {
				t.Fatal(err)
			}
			sources, skipped := SecretSources(root, []string{"-e", "@vars.yaml"})
			if len(sources) != 0 || len(skipped) != 1 || !strings.Contains(skipped[0], "traversal limit") {
				t.Fatalf("alias expansion guard must discard partial file scan: sources=%d skipped=%v", len(sources), skipped)
			}
			if strings.Contains(skipped[0], "Sentinel225") {
				t.Fatalf("payload leaked in skipped marker: %v", skipped)
			}
		})
	}
}

func TestSecretAliasCyclesAndOrdinaryAliases(t *testing.T) {
	t.Run("cyclic input is discarded", func(t *testing.T) {
		root := t.TempDir()
		raw := "api_token: PartialSecretSentinel225\ncredentials: &loop [*loop]\n"
		if err := os.WriteFile(filepath.Join(root, "vars.yaml"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		sources, skipped := SecretSources(root, []string{"-e", "@vars.yaml", "-e", "api_token=IndependentFileSentinel225"})
		if len(sources) != 1 || sources[0].value != "IndependentFileSentinel225" || len(skipped) != 1 || !strings.Contains(skipped[0], "cyclic alias") {
			t.Fatalf("cyclic input must discard only its own sources: %+v %v", sources, skipped)
		}
	})
	t.Run("inline mapping uses the same atomic guard", func(t *testing.T) {
		payload := `{api_token: InlinePartialSecretSentinel225, credentials: &loop [*loop]}`
		sources, skipped := SecretSources(t.TempDir(), []string{"--extra-vars", payload})
		if len(sources) != 0 || len(skipped) != 1 || !strings.Contains(skipped[0], "cyclic alias") || strings.Contains(skipped[0], "Sentinel225") {
			t.Fatalf("inline cyclic scan must be atomically skipped: %+v %v", sources, skipped)
		}
	})
	t.Run("ordinary aliases preserve secrecy ancestry and scalar spellings", func(t *testing.T) {
		root := t.TempDir()
		raw := `common: &common
  value: AnchoredSecretSentinel225
  numeric: 0x75BCD15
  boolean: true
credentials: *common
password: [*common, *common]
`
		if err := os.WriteFile(filepath.Join(root, "vars.yaml"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		sources, skipped := SecretSources(root, []string{"-e", "@vars.yaml"})
		if len(skipped) != 0 {
			t.Fatalf("valid aliases must remain supported: %v", skipped)
		}
		for _, value := range []string{"AnchoredSecretSentinel225", "0x75BCD15", "123456789", "true", "True"} {
			hits := Scan(map[string]string{"output": value}, sources)
			if len(hits) == 0 {
				t.Errorf("valid alias lost inherited secret scalar %q", value)
			}
		}
		parents := map[string]bool{}
		for _, source := range sources {
			parents[source.Key] = true
		}
		if !parents["vars.yaml:credentials.value"] || !parents["vars.yaml:password.value"] {
			t.Fatalf("alias result lost parent secrecy: %+v", parents)
		}
	})
}

func TestSanitizeRecordPreservesSchemaAndRedactsShortSecretData(t *testing.T) {
	sources := []SecretSource{{Key: "secret", value: "no"}, {Key: "other", value: "false"}, {Key: "fingerprint-part", value: "ab"}}
	rec := &Record{Schema: Schema, Feature: "no", Outcome: "success", Error: "false", Operator: "no", Steps: []Step{{Name: "L4", Note: "no false"}}, Candidate: Candidate{Commit: strings.Repeat("ab", 20), Tree: strings.Repeat("ab", 20)}, PilotBinary: Binary{Path: "no", SHA256: strings.Repeat("ab", 32)}, Targets: []Target{{BaseImageSHA256: "no"}}, Tooling: map[string]string{"no": "false"}, Inventory: Inventory{Groups: map[string][]string{"no": {"false"}}}}
	if err := SanitizeRecord(rec, sources); err != nil {
		t.Fatal(err)
	}
	if rec.Schema != Schema || rec.Steps[0].Name != "L4" || rec.Steps[0].Note != "<redacted> <redacted>" {
		t.Fatalf("schema field lost or note secret survived: %+v", rec)
	}
	if rec.Feature != "<redacted>" || rec.Error != "<redacted>" || rec.Operator != "<redacted>" || rec.PilotBinary.Path != "<redacted>" {
		t.Fatalf("metadata survived: %+v", rec)
	}
	if rec.Candidate.Commit != strings.Repeat("ab", 20) || rec.Candidate.Tree != strings.Repeat("ab", 20) || rec.PilotBinary.SHA256 != strings.Repeat("ab", 32) {
		t.Fatal("fingerprint identity changed")
	}
	if rec.Targets[0].BaseImageSHA256 != "<redacted>" {
		t.Fatal("arbitrary string under fingerprint field escaped sanitization")
	}
	if rec.Tooling["<redacted>"] != "<redacted>" || rec.Inventory.Groups["<redacted>"][0] != "<redacted>" {
		t.Fatal("dynamic map key/value escaped sanitization")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"note":`) {
		t.Fatalf("schema key renamed: %s", raw)
	}
}

func TestSecretBackslashPayloadsRefuseAllForwardedForms(t *testing.T) {
	root := t.TempDir()
	for _, payload := range []string{`api_token=Sentinel\Password225`, `api_token='Sentinel\nPassword225'`, `api_token="Sentinel\\Password225" other=literal`} {
		for _, args := range [][]string{{"-e", payload}, {"-e" + payload}, {"-e=" + payload}, {"--extra-vars", payload}, {"--extra-vars=" + payload}} {
			sources, skipped := SecretSources(root, args)
			if len(sources) != 0 || len(skipped) != 1 || skipped[0] != "inline extra-vars (backslash escape syntax not scanned)" {
				t.Fatalf("unsupported escape syntax falsely scanned as complete: sources=%d skipped=%v", len(sources), skipped)
			}
			closure, err := ComputeClosure(ClosureInput{Root: root, ExtraArgs: args})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ref := range closure.Unresolved {
				if ref.From == "extra-vars" && ref.Ref == "inline extra-vars expression" {
					found = true
				}
			}
			if !found {
				t.Fatal("unsupported escape grammar missing explicit inline closure refusal")
			}
			raw, err := json.Marshal(closure)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "Sentinel") || strings.Contains(RedactCommandLine(args), "Sentinel") {
				t.Fatal("unsupported escape payload leaked")
			}
		}
	}
}
