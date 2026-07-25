package groupvars

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleDoc = `# ============================================================================
#  group_vars/dns.example.yml
# ============================================================================

# DNS 服務對外監聽的位址(這台 DNS 機器的 IP)
dns_listen_addr: 10.0.0.53

# 上游遞迴 DNS(解析不到本地區域時往哪送);預設 1.1.1.1
dns_upstream: 1.1.1.1

# realm 名稱不照慣例時才覆寫:
# freeipa_realm: IPA.PILOT.INTERNAL
`

func TestEntries(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	entries := doc.Entries()
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}

	if entries[0].Key != "dns_listen_addr" || entries[0].Value != "10.0.0.53" || !entries[0].Active {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[0].Description != "DNS 服務對外監聽的位址(這台 DNS 機器的 IP)" {
		t.Errorf("entries[0].Description = %q", entries[0].Description)
	}

	if entries[1].Key != "dns_upstream" || entries[1].Value != "1.1.1.1" || !entries[1].Active {
		t.Errorf("entries[1] = %+v", entries[1])
	}

	if entries[2].Key != "freeipa_realm" || entries[2].Value != "IPA.PILOT.INTERNAL" || entries[2].Active {
		t.Errorf("entries[2] = %+v", entries[2])
	}
	if entries[2].Description != "realm 名稱不照慣例時才覆寫:" {
		t.Errorf("entries[2].Description = %q", entries[2].Description)
	}
}

// Mirrors group_vars/prometheus.example.yml, whose prose comments embed
// indented YAML illustrations (host_vars snippets, an alert-rule body).
// Those must not become editable rows: the real pilot-edit wizard showed
// three prometheus_site_label entries and "setting" the site-b one
// rewrote a documentation line (found 2026-07-17 during the minimal-poc
// re-verification).
const illustratedDoc = `# 建議直接放進 host_vars/<主機短名>.yml:
#
#   # host_vars/site-a.yml
#   prometheus_site_label: site-a
#
#   # host_vars/site-b.yml
#   prometheus_site_label: site-b
prometheus_site_label: ""

# 備份目的地(SeaweedFS S3 gateway)的 IP 或 FQDN。
thanos_s3_target_host: ""

# 走外部 S3 時,取消註解並覆寫:
# thanos_s3_endpoint: "s3.internal.example.com:443"

# 範例 rules 檔內容:
#   groups:
#     - name: mysite-rules
#       rules:
#         - alert: DiskSpaceLow
#           expr: node_filesystem_avail_bytes{mountpoint="/"} < 5e9
#           for: 5m
#           labels: { severity: warning }
`

func TestEntries_SkipsIndentedCommentIllustrations(t *testing.T) {
	doc := Parse([]byte(illustratedDoc))
	entries := doc.Entries()

	var keys []string
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	want := []string{"prometheus_site_label", "thanos_s3_target_host", "thanos_s3_endpoint"}
	if len(entries) != len(want) {
		t.Fatalf("got keys %v, want %v", keys, want)
	}
	for i, k := range want {
		if entries[i].Key != k {
			t.Fatalf("got keys %v, want %v", keys, want)
		}
	}

	// The one prometheus_site_label offered must be the real (active)
	// line, not one of the commented host_vars illustrations.
	if !entries[0].Active {
		t.Errorf("prometheus_site_label entry should be the active line: %+v", entries[0])
	}
	// thanos_s3_endpoint is a genuine top-level commented default.
	if entries[2].Active || entries[2].Value != "s3.internal.example.com:443" {
		t.Errorf("thanos_s3_endpoint entry = %+v", entries[2])
	}
}

func TestEntries_SkipsBlockScalarBody(t *testing.T) {
	// alertmanager.example.yml embeds the whole Alertmanager YAML as a
	// block scalar. Its indented body lines were already excluded as
	// "not vars" — but the header line itself ("alertmanager_config: |")
	// must ALSO be excluded, not just its body: SetValue only ever
	// rewrites one line, so "editing" the header here would replace it
	// with a plain scalar while stranding the body below as orphaned raw
	// lines — genuine YAML corruption, reproduced against the real
	// group_vars/alertmanager.example.yml (found while evaluating pilot
	// edit's group_vars gaps). BlockScalarKeys() is how a caller finds out
	// this key exists at all, so it can be surfaced instead of vanishing.
	doc := Parse([]byte("alertmanager_config: |\n  route:\n    receiver: 'null'\n    group_wait: 30s\n"))
	if entries := doc.Entries(); len(entries) != 0 {
		t.Fatalf("got %+v, want alertmanager_config excluded entirely", entries)
	}
	if keys := doc.BlockScalarKeys(); len(keys) != 1 || keys[0] != "alertmanager_config" {
		t.Fatalf("BlockScalarKeys() = %v, want [alertmanager_config]", keys)
	}
}

func TestEntries_SkipsBlockScalarHeaderVariants(t *testing.T) {
	for _, header := range []string{"|", "|-", "|+", ">", ">-", ">+", "|2"} {
		doc := Parse([]byte("cfg: " + header + "\n  body line\n"))
		if entries := doc.Entries(); len(entries) != 0 {
			t.Fatalf("header %q: got %+v, want excluded", header, entries)
		}
		if keys := doc.BlockScalarKeys(); len(keys) != 1 || keys[0] != "cfg" {
			t.Fatalf("header %q: BlockScalarKeys() = %v, want [cfg]", header, keys)
		}
	}
}

func TestEntries_PlainScalarStartingWithPipeCharIsNotABlockScalar(t *testing.T) {
	// a value merely containing '|'/'>' shouldn't be mistaken for a block
	// scalar header — only a BARE header (nothing else on the line) counts.
	doc := Parse([]byte(`path: "a|b"` + "\n"))
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Key != "path" || entries[0].Value != "a|b" {
		t.Fatalf("got %+v, want path=a|b treated as an ordinary scalar", entries)
	}
	if keys := doc.BlockScalarKeys(); len(keys) != 0 {
		t.Fatalf("BlockScalarKeys() = %v, want none", keys)
	}
}

func TestBlockScalarKeys_EmptyWhenNoneExist(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	if keys := doc.BlockScalarKeys(); len(keys) != 0 {
		t.Fatalf("BlockScalarKeys() = %v, want none", keys)
	}
}

// TestEntries_SkipsFlowListValue proves a second live corruption bug found
// while evaluating pilot edit's group_vars gaps, same class as the block
// scalar one: keyLineRe already matched a bare "[a, b]" flow list as an
// ordinary scalar value, and SetValue's formatValue only allow-lists plain
// alphanumeric-ish characters — anything else gets double-quoted, so
// "editing" restic_backup_paths here would have turned a real YAML list
// into a YAML *string* (`restic_backup_paths: "[\"/etc\"]"`). Reproduced
// against the real group_vars/restic-backup.example.yml before fixing.
func TestEntries_SkipsFlowListValue(t *testing.T) {
	doc := Parse([]byte(`# restic_backup_paths: ["/etc"]` + "\n"))
	if entries := doc.Entries(); len(entries) != 0 {
		t.Fatalf("got %+v, want restic_backup_paths excluded entirely from Entries", entries)
	}
	le := doc.ListEntries()
	if len(le) != 1 || le[0].Key != "restic_backup_paths" {
		t.Fatalf("ListEntries() = %+v, want [restic_backup_paths]", le)
	}
	if le[0].Active {
		t.Fatalf("ListEntries()[0].Active = true, want false (commented default)")
	}
	if len(le[0].Values) != 1 || le[0].Values[0] != "/etc" {
		t.Fatalf("ListEntries()[0].Values = %v, want [/etc]", le[0].Values)
	}
}

func TestEntries_SkipsFlowMapValue(t *testing.T) {
	doc := Parse([]byte("labels: {severity: warning}\n"))
	if entries := doc.Entries(); len(entries) != 0 {
		t.Fatalf("got %+v, want labels excluded entirely from Entries", entries)
	}
	if keys := doc.FlowMapKeys(); len(keys) != 1 || keys[0] != "labels" {
		t.Fatalf("FlowMapKeys() = %v, want [labels]", keys)
	}
}

func TestFlowMapKeys_EmptyWhenNoneExist(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	if keys := doc.FlowMapKeys(); len(keys) != 0 {
		t.Fatalf("FlowMapKeys() = %v, want none", keys)
	}
}

func TestListEntries_ActivatesAndDedupesLikeEntries(t *testing.T) {
	doc := Parse([]byte("paths: [/etc]\n\n# paths: [/var]\n"))
	le := doc.ListEntries()
	if len(le) != 1 || le[0].Key != "paths" || !le[0].Active || len(le[0].Values) != 1 || le[0].Values[0] != "/etc" {
		t.Fatalf("ListEntries() = %+v, want the active [/etc] entry only (commented default suppressed)", le)
	}
}

func TestSetList_ActivatesAndAppendsItem(t *testing.T) {
	doc := Parse([]byte(`# restic_backup_paths: ["/etc"]` + "\n"))
	entries := doc.ListEntries()
	if err := doc.SetList(entries[0].Line, append(append([]string{}, entries[0].Values...), "/srv/data")); err != nil {
		t.Fatalf("SetList() error = %v", err)
	}
	got := doc.ListEntries()
	if len(got) != 1 || !got[0].Active {
		t.Fatalf("after SetList, ListEntries() = %+v, want an active entry", got)
	}
	if len(got[0].Values) != 2 || got[0].Values[0] != "/etc" || got[0].Values[1] != "/srv/data" {
		t.Fatalf("after SetList, Values = %v, want [/etc /srv/data]", got[0].Values)
	}
	if !strings.Contains(string(doc.Bytes()), "restic_backup_paths: [/etc, /srv/data]") {
		t.Fatalf("rendered doc = %q, want an uncommented flow list", doc.Bytes())
	}
}

func TestSetList_QuotesValuesContainingCommas(t *testing.T) {
	doc := Parse([]byte("paths: [/etc]\n"))
	if err := doc.SetList(0, []string{"/etc", "a value, with comma"}); err != nil {
		t.Fatalf("SetList() error = %v", err)
	}
	// round-trips correctly even though the value contains the list's own
	// separator character.
	reparsed := Parse(doc.Bytes()).ListEntries()
	if len(reparsed) != 1 || len(reparsed[0].Values) != 2 || reparsed[0].Values[1] != "a value, with comma" {
		t.Fatalf("round-tripped ListEntries() = %+v, want the comma-containing value preserved", reparsed)
	}
}

func TestSetList_EmptyValuesRendersBareEmptyList(t *testing.T) {
	doc := Parse([]byte("paths: [/etc]\n"))
	if err := doc.SetList(0, nil); err != nil {
		t.Fatalf("SetList() error = %v", err)
	}
	if !strings.Contains(string(doc.Bytes()), "paths: []") {
		t.Fatalf("rendered doc = %q, want paths: []", doc.Bytes())
	}
}

func TestEntries_DeduplicatesRepeatedCommentedKey(t *testing.T) {
	doc := Parse([]byte("# retention: 6h\n\n# retention: 12h\n"))
	entries := doc.Entries()
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Key != "retention" || entries[0].Value != "6h" || entries[0].Active {
		t.Errorf("entries[0] = %+v", entries[0])
	}
}

func TestSetValue_ActivatesAndRewritesInPlace(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	entries := doc.Entries()
	dnsListen := entries[0]

	if err := doc.SetValue(dnsListen.Line, "10.0.0.99"); err != nil {
		t.Fatal(err)
	}

	out := string(doc.Bytes())
	if !strings.Contains(out, "\ndns_listen_addr: 10.0.0.99\n") {
		t.Errorf("value not updated:\n%s", out)
	}
	// Everything else — comments, other keys — untouched.
	if !strings.Contains(out, "# DNS 服務對外監聽的位址(這台 DNS 機器的 IP)") {
		t.Errorf("comment lost:\n%s", out)
	}
	if !strings.Contains(out, "dns_upstream: 1.1.1.1") {
		t.Errorf("unrelated key mutated:\n%s", out)
	}
}

func TestSetValue_ActivatesACommentedOutLine(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	entries := doc.Entries()
	realm := entries[2]
	if realm.Active {
		t.Fatal("expected freeipa_realm to start commented out")
	}

	if err := doc.SetValue(realm.Line, "EXAMPLE.TEST"); err != nil {
		t.Fatal(err)
	}

	out := string(doc.Bytes())
	if !strings.Contains(out, "\nfreeipa_realm: EXAMPLE.TEST\n") {
		t.Errorf("line not activated:\n%s", out)
	}
	if strings.Contains(out, "# freeipa_realm") {
		t.Errorf("expected the comment prefix to be gone:\n%s", out)
	}
}

func TestSetValue_QuotesValuesThatArentPlainScalars(t *testing.T) {
	doc := Parse([]byte("greeting: hello\n"))
	entries := doc.Entries()

	if err := doc.SetValue(entries[0].Line, "hello world"); err != nil {
		t.Fatal(err)
	}

	out := string(doc.Bytes())
	if !strings.Contains(out, `greeting: "hello world"`) {
		t.Errorf("expected the space-containing value to be quoted:\n%s", out)
	}
}

func TestCommentOut_RevertsToBuiltInDefault(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	entries := doc.Entries()
	dnsListen := entries[0]

	if err := doc.CommentOut(dnsListen.Line); err != nil {
		t.Fatal(err)
	}

	out := string(doc.Bytes())
	if !strings.Contains(out, "\n# dns_listen_addr: 10.0.0.53\n") {
		t.Errorf("expected the line to be commented out with its value preserved:\n%s", out)
	}

	// Re-parsing sees it as inactive now.
	doc2 := Parse(doc.Bytes())
	for _, e := range doc2.Entries() {
		if e.Key == "dns_listen_addr" && e.Active {
			t.Fatal("dns_listen_addr should be inactive after CommentOut")
		}
	}
}

func TestCommentOut_AlreadyCommentedIsNoop(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	entries := doc.Entries()
	realm := entries[2]

	before := string(doc.Bytes())
	if err := doc.CommentOut(realm.Line); err != nil {
		t.Fatal(err)
	}
	if got := string(doc.Bytes()); got != before {
		t.Errorf("CommentOut on an already-commented line changed the doc:\nbefore=%q\nafter=%q", before, got)
	}
}

func TestSetValue_InvalidLineIndexErrors(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	if err := doc.SetValue(0, "x"); err == nil {
		t.Fatal("expected an error setting a value on a non-key line")
	}
	if err := doc.SetValue(999, "x"); err == nil {
		t.Fatal("expected an error setting a value out of range")
	}
}

func TestBytes_RoundTripsUntouchedInput(t *testing.T) {
	doc := Parse([]byte(sampleDoc))
	if got := string(doc.Bytes()); got != sampleDoc {
		t.Errorf("Bytes() without any edits should equal the original input\ngot:\n%s\nwant:\n%s", got, sampleDoc)
	}
}

// TestListEntries_RealResticBackupExampleFile ties the flow-list guard to
// the actual shipped group_vars/restic-backup.example.yml (not just a
// synthetic fixture) — catches a future edit to that file's format
// silently breaking the corruption fix.
func TestListEntries_RealResticBackupExampleFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "group_vars", "restic-backup.example.yml"))
	if err != nil {
		t.Skipf("real group_vars/restic-backup.example.yml not found: %v", err)
	}
	doc := Parse(data)
	for _, e := range doc.Entries() {
		if e.Key == "restic_backup_paths" {
			t.Fatalf("restic_backup_paths should not be offered as a scalar entry, got %+v", e)
		}
	}
	var found bool
	for _, e := range doc.ListEntries() {
		if e.Key == "restic_backup_paths" {
			found = true
			if len(e.Values) != 1 || e.Values[0] != "/etc" {
				t.Fatalf("ListEntries() restic_backup_paths = %+v, want [/etc]", e)
			}
		}
	}
	if !found {
		t.Fatal("restic_backup_paths not found via ListEntries() against the real example file")
	}
}
