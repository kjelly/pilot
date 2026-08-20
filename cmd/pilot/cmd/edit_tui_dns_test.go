package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/inventory"
)

func writeDNSTestHostsFile(t *testing.T, dir string) {
	t.Helper()
	fixture := "hosts:\n  nexus:\n    ansible_host: 192.168.122.81\n    ansible_user: ubuntu\n    roles: []\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newDNSTeatestModel(t *testing.T, router editRouterModel) (*teatest.TestModel, func(want string)) {
	t.Helper()
	// Wider than edit_tui_flows_test.go's usual 100 columns: several of
	// these tests confirm a question that embeds t.TempDir()'s path,
	// which includes the (often long) test name — at 100 columns that
	// can wrap mid-phrase and break a plain substring waitFor match.
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(220, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}
	return tm, waitFor
}

// TestEditRouter_Teatest_DNSManifestFlow_CreateSkeletonThenAddZone covers
// docs/specs/freeipa-dns.md §15 Phase 4's manifest-creation and zone-add
// screens end to end, starting from a manifest file that doesn't exist yet
// (the pushDNSManifestManager -> pushDNSManifestCreateConfirm chain).
// Record creation is covered separately (see
// TestEditRouter_Teatest_DNSRecordFlow_CreateThreeServiceRecords) since it
// has its own multi-step chain and re-testing it here on top of this one
// would just make both more brittle without covering anything new.
func TestEditRouter_Teatest_DNSManifestFlow_CreateSkeletonThenAddZone(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := filepath.Join(dir, "freeipa-dns.yaml")

	var router editRouterModel
	pushDNSManifestManager(&router, dir, path, "")
	tm, waitFor := newDNSTeatestModel(t, router)

	// Create the minimal skeleton.
	waitFor("不存在，要建立最小")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm (default yes)
	waitFor("FreeIPA domain")
	tm.Type("ipa.pilot.internal")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	// Checks the label's post-"FreeIPA " suffix rather than the full
	// "FreeIPA realm" phrase: Bubble Tea v2's renderer diffs at the cell
	// level, and since the previous screen's label ("FreeIPA domain(...)")
	// shares the literal 8-character prefix "FreeIPA " with this one at
	// the same screen position, it only ever retransmits the differing
	// suffix ("realm(...)" replacing "domain(...)") — "FreeIPA " itself is
	// never rewritten once it's already on screen. This is a genuine,
	// permanent v2 rendering optimization (confirmed by direct model
	// inspection, not a business-logic bug), not a timing fluke.
	waitFor("realm(必須與 freeipa_realm 一致")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept the IPA.PILOT.INTERNAL default
	waitFor("ipa1.ipa.pilot.internal")           // auto-derived default: ipa1.<domain>
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept the auto-detected default
	waitFor("已建立最小 freeipa-dns manifest 骨架")

	// Manager menu: cursor starts at item 0, "🌐 Zones".
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("目前沒有任何 zone")
	// Zones menu is empty, so item 0 is already "➕ 新增 zone".
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("新 zone 的名稱")
	tm.Type("example.com.")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("已新增 zone example.com.")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	root, err := inventory.LoadDNSManifest(path)
	if err != nil {
		t.Fatalf("LoadDNSManifest() error = %v", err)
	}
	if v := inventory.ValidateDNSManifest(root, inventory.DNSValidateOptions{}); len(v) != 0 {
		t.Fatalf("final manifest violations: %v", v)
	}
	names, err := inventory.DNSManifestZoneNames(path)
	if err != nil || len(names) != 1 || names[0] != "example.com." {
		t.Fatalf("DNSManifestZoneNames() = %v, err=%v, want [example.com.]", names, err)
	}
}

// TestEditRouter_Teatest_DNSRecordFlow_AddARecordFromInventoryHost drives
// the record-add chain starting from a zone already selected — this is
// the flow spec §15 Phase 4's "建立三筆 service records" DoD actually
// exercises, kept independent from the top-of-wizard skeleton-creation
// flow above so a change to one doesn't make the other brittle.
func TestEditRouter_Teatest_DNSRecordFlow_AddARecordFromInventoryHost(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := filepath.Join(dir, "freeipa-dns.yaml")
	fixture := "schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      state: present\n" +
		"      records: []\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushDNSRecordsMenu(&router, dir, path, "example.com.", "")
	tm, waitFor := newDNSTeatestModel(t, router)

	waitFor("這個 zone 目前沒有任何 record")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // cursor starts at "➕ 新增 record" (no records exist yet)
	waitFor("新 record 的類型")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "A" (first choice)
	waitFor("新 record 的名稱")
	tm.Type("grafana")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("值的來源")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "從 inventory host 解析"
	waitFor("要解析哪個 inventory host")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "nexus" (only host)
	waitFor("已新增 record grafana")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	record, found, err := inventory.DNSManifestRecord(path, "example.com.", "grafana", "A")
	if err != nil || !found {
		t.Fatalf("DNSManifestRecord() found=%v err=%v", found, err)
	}
	target := dnsSubmap(record, "target")
	if got := dnsStringValue(target, "inventory_host"); got != "nexus" {
		t.Fatalf("record target.inventory_host = %q, want nexus", got)
	}

	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		t.Fatalf("loadDNSHostvars() error = %v", err)
	}
	root, err := inventory.LoadDNSManifest(path)
	if err != nil {
		t.Fatalf("LoadDNSManifest() error = %v", err)
	}
	if v := inventory.ValidateDNSManifest(root, inventory.DNSValidateOptions{Hostvars: hostvars}); len(v) != 0 {
		t.Fatalf("final manifest violations: %v", v)
	}
	normalized := inventory.NormalizeDNSManifest(root, hostvars)
	if len(normalized.Zones) != 1 || len(normalized.Zones[0].Records) != 1 {
		t.Fatalf("normalized manifest = %+v, want exactly one zone with one record", normalized)
	}
	if got := normalized.Zones[0].Records[0].Values; len(got) != 1 || got[0] != "192.168.122.81" {
		t.Fatalf("resolved value = %v, want [192.168.122.81]", got)
	}
}

// TestEditRouter_Teatest_DNSRecordFlow_CreateThreeServiceRecords is the
// literal Phase 4 Definition of Done: three service records (grafana/
// wazuh/s3), all resolved via target.inventory_host, none of it via a
// hand-edited YAML file.
func TestEditRouter_Teatest_DNSRecordFlow_CreateThreeServiceRecords(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := filepath.Join(dir, "freeipa-dns.yaml")
	fixture := "schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      state: present\n" +
		"      records: []\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	// The records list is always [...existing records..., "➕ 新增
	// record", "↩ 返回"], cursor starting at index 0 — so "➕ 新增 record"
	// sits at index len(existing), one press of "down" per
	// already-added record before this call.
	existing := 0
	addOne := func(name string) {
		var router editRouterModel
		pushDNSRecordsMenu(&router, dir, path, "example.com.", "")
		tm, waitFor := newDNSTeatestModel(t, router)

		waitFor("Records")
		for i := 0; i < existing; i++ {
			tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
		}
		existing++
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
		waitFor("新 record 的類型")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "A"
		waitFor("新 record 的名稱")
		tm.Type(name)
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
		waitFor("值的來源")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "從 inventory host 解析"
		waitFor("要解析哪個 inventory host")
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "nexus"
		waitFor("已新增 record " + name)

		if err := tm.Quit(); err != nil {
			t.Fatal(err)
		}
		tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
	}

	addOne("grafana")
	addOne("wazuh")
	addOne("s3")

	records, err := inventory.DNSManifestRecords(path, "example.com.")
	if err != nil {
		t.Fatalf("DNSManifestRecords() error = %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3: %v", len(records), records)
	}
	seen := map[string]bool{}
	for _, rec := range records {
		seen[dnsStringValue(rec, "name")] = true
		if got := dnsStringValue(dnsSubmap(rec, "target"), "inventory_host"); got != "nexus" {
			t.Errorf("record %q target.inventory_host = %q, want nexus", dnsStringValue(rec, "name"), got)
		}
	}
	for _, want := range []string{"grafana", "wazuh", "s3"} {
		if !seen[want] {
			t.Errorf("missing record %q", want)
		}
	}

	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		t.Fatalf("loadDNSHostvars() error = %v", err)
	}
	root, err := inventory.LoadDNSManifest(path)
	if err != nil {
		t.Fatalf("LoadDNSManifest() error = %v", err)
	}
	if v := inventory.ValidateDNSManifest(root, inventory.DNSValidateOptions{Hostvars: hostvars}); len(v) != 0 {
		t.Fatalf("final manifest violations: %v", v)
	}
}

// TestEditRouter_Teatest_DNSRecordFlow_RejectsInvalidCNAMEWithoutWriting
// mirrors the roster editor's validation-gate coverage: a write that fails
// inventory.ValidateDNSManifest must never reach disk, and the violation
// is shown as a banner on the same menu instead.
func TestEditRouter_Teatest_DNSRecordFlow_RejectsInvalidCNAMEWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := filepath.Join(dir, "freeipa-dns.yaml")
	fixture := "schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      state: present\n" +
		"      records: []\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := string(beforeBytes)

	var router editRouterModel
	pushDNSRecordsMenu(&router, dir, path, "example.com.", "")
	tm, waitFor := newDNSTeatestModel(t, router)

	waitFor("Records")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // cursor starts at "➕ 新增 record" (no records exist yet)
	waitFor("新 record 的類型")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "CNAME"
	waitFor("新 record 的名稱")
	tm.Type("docs")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("CNAME 目標")
	tm.Type("not-an-fqdn-missing-trailing-dot") // invalid: no trailing "."
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("驗證沒過")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != before {
		t.Fatal("a validation-rejected record must never be written to disk")
	}
	if _, found, err := inventory.DNSManifestRecord(path, "example.com.", "docs", "CNAME"); err != nil || found {
		t.Fatalf("rejected record present on disk: found=%v err=%v", found, err)
	}
}

// TestEditRouter_Teatest_DNSZoneFlow_ToggleStateToAbsent covers editing an
// existing zone's state field — declarative delete-request, not an
// in-wizard destructive action (see edit_tui_dns.go's package doc comment).
func TestEditRouter_Teatest_DNSZoneFlow_ToggleStateToAbsent(t *testing.T) {
	dir := t.TempDir()
	writeDNSTestHostsFile(t, dir)
	path := filepath.Join(dir, "freeipa-dns.yaml")
	fixture := "schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  safety: {allow_zone_delete: true}\n" +
		"  zones:\n" +
		"    - name: old-svc.example.com.\n" +
		"      state: present\n" +
		"      records: []\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushDNSZoneDetail(&router, dir, path, "old-svc.example.com.", "")
	tm, waitFor := newDNSTeatestModel(t, router)

	waitFor("state：present")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> state field
	waitFor("state（absent")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "absent"
	waitFor("已更新")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	zone, found, err := inventory.DNSManifestZone(path, "old-svc.example.com.")
	if err != nil || !found {
		t.Fatalf("DNSManifestZone() found=%v err=%v", found, err)
	}
	if got := dnsStringValue(zone, "state"); got != "absent" {
		t.Fatalf("zone state = %q, want absent", got)
	}
}
