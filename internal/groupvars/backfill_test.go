package groupvars

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const backfillExample = `---
# 外部 upstream DNS。
# dns_upstream: [1.1.1.1]

# ============================================================================
# 快取上限(秒)。
# dns_cache_max_ttl: 300

# 已經生效的範例值。
dns_listen_addr: 10.0.0.53

# dns_zones:
#   - name: pilot.lan
`

func TestMissingKeysFrom_ReportsOnlyKeysTheFileNeverMentions(t *testing.T) {
	file := Parse([]byte("---\n# dns_upstream: [9.9.9.9]\ndns_listen_addr: 10.0.0.1\n"))
	got := file.MissingKeysFrom(Parse([]byte(backfillExample)))
	if want := []string{"dns_cache_max_ttl"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingKeysFrom = %v, want %v", got, want)
	}
}

func TestMissingKeysFrom_NothingMissingWhenFileMentionsEveryKey(t *testing.T) {
	file := Parse([]byte(backfillExample))
	if got := file.MissingKeysFrom(Parse([]byte(backfillExample))); len(got) != 0 {
		t.Fatalf("MissingKeysFrom(self) = %v, want none", got)
	}
}

func TestMissingKeysFrom_CountsABlockCollectionAsMentioned(t *testing.T) {
	example := Parse([]byte("# dns_zones: []\n"))
	file := Parse([]byte("dns_zones:\n  - name: a.lan\n"))
	if got := file.MissingKeysFrom(example); len(got) != 0 {
		t.Fatalf("MissingKeysFrom = %v, want none (dns_zones is set as a block list)", got)
	}
}

func TestAppendMissingFrom_AppendsCommentedDefaultsAndLeavesExistingLines(t *testing.T) {
	original := "---\n# 我自己的註解\ndns_upstream: 1.1.1.1\n"
	file := Parse([]byte(original))
	appended := file.AppendMissingFrom(Parse([]byte(backfillExample)))
	if want := []string{"dns_cache_max_ttl", "dns_listen_addr"}; !reflect.DeepEqual(appended, want) {
		t.Fatalf("appended = %v, want %v", appended, want)
	}
	out := string(file.Bytes())
	if !strings.HasPrefix(out, original) {
		t.Fatalf("existing lines changed:\n%s", out)
	}
	for _, want := range []string{
		"# 快取上限(秒)。\n# dns_cache_max_ttl: 300\n",
		// An active example value is appended commented out: backfill must
		// never change what the playbook does.
		"# 已經生效的範例值。\n# dns_listen_addr: 10.0.0.53\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "====") {
		t.Fatalf("decorative banner copied:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("trailing newline lost:\n%q", out)
	}
	for _, e := range file.Entries() {
		if e.Key != "dns_upstream" && e.Active {
			t.Fatalf("appended key %s is active, want commented", e.Key)
		}
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(file.Bytes(), &parsed); err != nil {
		t.Fatalf("result is not valid YAML: %v\n%s", err, out)
	}
	if want := map[string]any{"dns_upstream": "1.1.1.1"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("effective YAML = %v, want only %v", parsed, want)
	}
	// A second run finds nothing more to add.
	if again := file.AppendMissingFrom(Parse([]byte(backfillExample))); len(again) != 0 {
		t.Fatalf("second AppendMissingFrom appended %v, want none", again)
	}
}

// TestAppendMissingFrom_RealDNSExample backfills an old-style workspace
// dns.yml (the pre-2026-10-01 example) from the real shipped example and
// checks every new dns setting becomes editable without changing the
// effective values.
func TestAppendMissingFrom_RealDNSExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "group_vars", "dns.example.yml"))
	if err != nil {
		t.Skipf("real group_vars/dns.example.yml not found: %v", err)
	}
	old := "---\ndns_listen_addr: 10.0.0.53\ndns_upstream: 1.1.1.1\n"
	file := Parse([]byte(old))
	appended := file.AppendMissingFrom(Parse(data))
	want := []string{"dns_freeipa_zones", "dns_stub_zones", "dns_access_control", "dns_cache_max_ttl", "dns_cache_max_negative_ttl", "dns_dnssec_validation"}
	if !reflect.DeepEqual(appended, want) {
		t.Fatalf("appended = %v, want %v", appended, want)
	}
	editable := map[string]bool{}
	for _, e := range file.Entries() {
		editable[e.Key] = true
	}
	for _, e := range file.ListEntries() {
		editable[e.Key] = true
	}
	for _, k := range want {
		if !editable[k] {
			t.Fatalf("%s not editable after backfill:\n%s", k, file.Bytes())
		}
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(file.Bytes(), &parsed); err != nil {
		t.Fatalf("result is not valid YAML: %v", err)
	}
	if wantVals := map[string]any{"dns_listen_addr": "10.0.0.53", "dns_upstream": "1.1.1.1"}; !reflect.DeepEqual(parsed, wantVals) {
		t.Fatalf("effective YAML = %v, want unchanged %v", parsed, wantVals)
	}
}
