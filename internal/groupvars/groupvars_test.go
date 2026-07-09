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
