package groupvars

import (
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
	// block scalar; its indented body lines are text, not vars.
	doc := Parse([]byte("alertmanager_config: |\n  route:\n    receiver: 'null'\n    group_wait: 30s\n"))
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Key != "alertmanager_config" {
		t.Fatalf("got %+v, want only alertmanager_config", entries)
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
