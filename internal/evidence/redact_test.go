package evidence

import (
	"path/filepath"
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
	// password: scanned; domain: not secret-named; path and short values: filtered.
	for _, want := range []string{"vaultdir/sandbox.yaml:ipa_admin_password", "-e api_token"} {
		if !keys[want] {
			t.Fatalf("missing source %q in %v", want, keys)
		}
	}
	for _, not := range []string{"vaultdir/sandbox.yaml:ipa_domain", "vaultdir/sandbox.yaml:ssh_private_key_file", "vaultdir/sandbox.yaml:short_pw", "-e ssh_private_key_file", "-e target_group"} {
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
