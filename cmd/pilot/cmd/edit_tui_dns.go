// edit_tui_dns.go implements the freeipa-dns manifest screens of the
// `pilot edit` router (edit_tui.go): a manager for the freeipa-dns
// declarative manifest (docs/specs/freeipa-dns.md) covering zones and
// A/AAAA/CNAME records. Every write goes through
// internal/inventory.Simulate{Add,Set}DNS{Zone,Record} first (mirroring
// playbooks/apply/freeipa-dns-apply.yml's own preflight gates via
// inventory.ValidateDNSManifest) so a mistake is caught before it ever
// touches disk, then Append/SetDNS{Zone,Record} persists via yaml.Node
// surgery — never a full-struct remarshal, so no comment or section this
// wizard doesn't know about is disturbed.
//
// "state: absent" IS offered here for both zones and records — unlike the
// roster editor's users/groups, a DNS zone/record's absent state is a
// first-class declarative reconcile request (docs/specs/freeipa-dns.md
// §6.1/§6.3), not a destructive action this wizard performs directly; the
// real deletion happens later, at apply time, behind its own independent
// safety gates (allow_zone_delete/allow_authoritative_prune +
// confirm_dns_zone_delete). Writing state: absent here is exactly as safe
// as writing any other field.
//
// Deliberately out of scope: editing a zone's `delegation` block (verify/
// expected_nameservers) — not part of docs/specs/freeipa-dns.md §11.1's
// minimum TUI feature list; add a dedicated screen later if needed.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// ---- entry point + manifest-level manager -------------------------------

func pushDNSManifestPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, "freeipa-dns.yaml")
	return r.transitionTo(newTextInputModelWithScreenID("dns.path", "freeipa-dns manifest 檔路徑", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushDNSManifestManager(r, dir, strings.TrimSpace(m.Value()), "")
	})
}

func pushDNSManifestManager(r *editRouterModel, dir, path, banner string) tea.Cmd {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// A missing manifest on first visit is entirely foreseeable —
			// offer to auto-generate the minimal skeleton instead of
			// killing the whole `pilot edit` session over it.
			return pushDNSManifestCreateConfirm(r, dir, path)
		}
		r.err = fmt.Errorf("stat %s: %w", path, err)
		return nil
	}

	items := []string{
		"🌐 Zones",
		"📋 顯示 normalized preview(套用後的最終 desired state)",
		"↩  返回",
	}
	title := fmt.Sprintf("管理 %s", path)
	return r.transitionTo(newSelectModelWithScreenID("dns.manager", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushDNSZonesMenu(r, dir, path, "")
		case 1:
			return pushDNSManifestPreview(r, dir, path, "")
		case 2:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// pushDNSManifestCreateConfirm offers to auto-generate the smallest
// schema-valid manifest skeleton when path doesn't exist yet — same
// recoverable posture as pushRosterCreateConfirm.
func pushDNSManifestCreateConfirm(r *editRouterModel, dir, path string) tea.Cmd {
	question := fmt.Sprintf("%s 不存在，要建立最小 freeipa-dns manifest 骨架嗎？", path)
	return r.transitionTo(newConfirmModelWithScreenID("dns.create_confirm", question, true), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushTopMenu(r, dir, "")
		}
		return pushDNSManifestCreateDomainPrompt(r, dir, path)
	})
}

// pushDNSManifestCreateDomainPrompt collects freeipa.domain/realm/server —
// the three fields playbooks/apply/freeipa-dns-apply.yml's own gate
// requires to exactly match this deployment's freeipa_domain/
// freeipa_realm/freeipa_server_fqdn (docs/specs/freeipa-dns.md §5.2), so
// they can't be safely invented — domain defaults from
// group_vars/freeipa.yml when present (inventory.FreeIPADomain), same
// source the roster creation flow already trusts for this.
func pushDNSManifestCreateDomainPrompt(r *editRouterModel, dir, path string) tea.Cmd {
	def, _ := inventory.FreeIPADomain(dir)
	label := "FreeIPA domain(必須與 group_vars/freeipa.yml 的 freeipa_domain 一致)"
	return r.transitionTo(newTextInputModelWithScreenID("dns.create_domain", label, def, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		domain := strings.TrimSpace(m.Value())
		return pushDNSManifestCreateRealmPrompt(r, dir, path, domain)
	})
}

func pushDNSManifestCreateRealmPrompt(r *editRouterModel, dir, path, domain string) tea.Cmd {
	label := "FreeIPA realm(必須與 freeipa_realm 一致；預設是 domain 全大寫)"
	return r.transitionTo(newTextInputModelWithScreenID("dns.create_realm", label, strings.ToUpper(domain), nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		realm := strings.TrimSpace(m.Value())
		return pushDNSManifestCreateServerPrompt(r, dir, path, domain, realm)
	})
}

func pushDNSManifestCreateServerPrompt(r *editRouterModel, dir, path, domain, realm string) tea.Cmd {
	// Same default the apply playbooks fall back to when freeipa_server_fqdn
	// isn't overridden ("ipa1." + domain) — prefer an explicit override from
	// group_vars/freeipa.yml when present, since that's the deployment's
	// actual authority for this value.
	def := "ipa1." + domain
	if fqdn, err := inventory.FreeIPAServerFQDN(dir); err == nil && strings.TrimSpace(fqdn) != "" {
		def = fqdn
	}
	label := "FreeIPA server FQDN(必須與 freeipa_server_fqdn 一致)"
	return r.transitionTo(newTextInputModelWithScreenID("dns.create_server", label, def, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		server := strings.TrimSpace(m.Value())
		if err := inventory.CreateMinimalDNSManifest(path, domain, realm, server); err != nil {
			r.err = err
			return nil
		}
		return pushDNSManifestManager(r, dir, path, fmt.Sprintf("✅ 已建立最小 freeipa-dns manifest 骨架 %s", path))
	})
}

// ---- zones ---------------------------------------------------------------

func pushDNSZonesMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.DNSManifestZoneNames(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}

	note := "目前沒有任何 zone。"
	if len(names) > 0 {
		note = "選一個查看/編輯，或新增一個。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := make([]string, 0, len(names)+2)
	for _, n := range names {
		items = append(items, "🌐 "+n)
	}
	items = append(items, "➕ 新增 zone", "↩  返回")

	return r.transitionTo(newSelectModelWithScreenID("dns.zones.list", fmt.Sprintf("Zones — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSManifestManager(r, dir, path, "")
		}
		switch {
		case m.Selected() < len(names):
			return pushDNSZoneDetail(r, dir, path, names[m.Selected()], "")
		case m.Selected() == len(names):
			return pushDNSZoneAddName(r, dir, path)
		default:
			return pushDNSManifestManager(r, dir, path, "")
		}
	})
}

func pushDNSZoneAddName(r *editRouterModel, dir, path string) tea.Cmd {
	label := "新 zone 的名稱(絕對 FQDN，例如 example.com.)"
	return r.transitionTo(newTextInputModelWithScreenID("dns.zone.add_name", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushDNSZonesMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		zone := map[string]any{"name": name, "state": "present", "records": []any{}}

		hostvars, err := loadDNSHostvars(dir)
		if err != nil {
			r.err = err
			return nil
		}
		violations, err := inventory.SimulateAddDNSZone(path, zone, dnsValidateOptsFor(path, hostvars))
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushDNSZonesMenu(r, dir, path, formatDNSViolations(violations))
		}
		if err := inventory.AppendDNSZone(path, zone); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushDNSZonesMenu(r, dir, path, fmt.Sprintf(
			"✅ 已新增 zone %s；選這個 zone 可繼續編輯 records_mode、新增 records 等欄位。", name))
	})
}

func pushDNSZoneDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	fields, found, err := inventory.DNSManifestZone(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushDNSZonesMenu(r, dir, path, fmt.Sprintf("⚠️  zone %q 已不存在", name))
	}
	records, err := inventory.DNSManifestRecords(path, name)
	if err != nil {
		r.err = err
		return nil
	}

	items := []string{
		fmt.Sprintf("name：%s（唯讀，records 會用這個名稱互相參照）", name),
		fmt.Sprintf("state：%s", dnsStringOr(fields, "state", "present")),
		fmt.Sprintf("records_mode：%s", dnsStringOr(fields, "records_mode", "(使用 manifest 預設)")),
		fmt.Sprintf("acknowledge_split_horizon：%s", dnsBoolDisplay(fields, "acknowledge_split_horizon")),
		fmt.Sprintf("Records（共 %d 筆）", len(records)),
		"↩  返回",
	}
	return r.transitionTo(newSelectModelWithScreenID("dns.zone.detail", fmt.Sprintf("Zone %q — %s", name, path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSZonesMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushDNSZoneDetail(r, dir, path, name, "name 不可修改：records 會用這個名稱互相參照")
		case 1:
			return pushDNSZoneStateField(r, dir, path, name)
		case 2:
			return pushDNSZoneRecordsModeField(r, dir, path, name)
		case 3:
			return pushDNSZoneSplitHorizonField(r, dir, path, name)
		case 4:
			return pushDNSRecordsMenu(r, dir, path, name, "")
		case 5:
			return pushDNSZonesMenu(r, dir, path, "")
		}
		return nil
	})
}

// dnsApplyZoneEdit re-reads name's current fields, applies mutate to a
// clone, and simulates-then-writes exactly like pushDNSZoneAddName's own
// gate chain (Simulate first, only write once it reports no violations).
func dnsApplyZoneEdit(dir, path, name string, mutate func(map[string]any)) (banner string, err error) {
	fields, found, err := inventory.DNSManifestZone(path, name)
	if err != nil {
		return "", err
	}
	if !found {
		return fmt.Sprintf("⚠️  zone %q 已不存在（可能被其他流程移除）", name), nil
	}
	updated := cloneDNSFields(fields)
	mutate(updated)
	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		return "", err
	}
	violations, _, err := inventory.SimulateSetDNSZone(path, name, updated, dnsValidateOptsFor(path, hostvars))
	if err != nil {
		return "", err
	}
	if len(violations) > 0 {
		return formatDNSViolations(violations), nil
	}
	if err := inventory.SetDNSZone(path, name, updated); err != nil {
		return "", err
	}
	return "✅ 已更新", nil
}

func pushDNSEditZone(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	banner, err := dnsApplyZoneEdit(dir, path, name, mutate)
	if err != nil {
		r.err = err
		return nil
	}
	return pushDNSZoneDetail(r, dir, path, name, banner)
}

var dnsZoneStateChoices = []string{"present", "absent"}

func pushDNSZoneStateField(r *editRouterModel, dir, path, name string) tea.Cmd {
	title := "state（absent 代表要求 reconciler 刪除這個 zone；實際刪除仍受 apply 端 allow_zone_delete + confirm_dns_zone_delete 雙重確認保護，這裡寫入 absent 本身是安全的）"
	return r.transitionTo(newSelectModelWithScreenID("dns.zone.field_state", title, dnsZoneStateChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSZoneDetail(r, dir, path, name, "")
		}
		value := dnsZoneStateChoices[m.Selected()]
		return pushDNSEditZone(r, dir, path, name, func(f map[string]any) { f["state"] = value })
	})
}

var dnsRecordsModeChoices = []string{"merge", "authoritative"}

func pushDNSZoneRecordsModeField(r *editRouterModel, dir, path, name string) tea.Cmd {
	title := "records_mode（authoritative 會在套用時清除 manifest 未宣告的 supported-type record，另外需要 apply 端的 allow_authoritative_prune 安全旗標）"
	return r.transitionTo(newSelectModelWithScreenID("dns.zone.field_records_mode", title, dnsRecordsModeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSZoneDetail(r, dir, path, name, "")
		}
		value := dnsRecordsModeChoices[m.Selected()]
		return pushDNSEditZone(r, dir, path, name, func(f map[string]any) { f["records_mode"] = value })
	})
}

var dnsBoolChoices = []string{"true", "false"}

func pushDNSZoneSplitHorizonField(r *editRouterModel, dir, path, name string) tea.Cmd {
	title := "acknowledge_split_horizon（若這個 zone 名稱已存在於外部 DNS，必須設 true 才能在 apply 端建立，否則會被拒絕）"
	return r.transitionTo(newSelectModelWithScreenID("dns.zone.field_split_horizon", title, dnsBoolChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSZoneDetail(r, dir, path, name, "")
		}
		value := m.Selected() == 0
		return pushDNSEditZone(r, dir, path, name, func(f map[string]any) { f["acknowledge_split_horizon"] = value })
	})
}

// ---- records ---------------------------------------------------------------

func pushDNSRecordsMenu(r *editRouterModel, dir, path, zoneName, banner string) tea.Cmd {
	records, err := inventory.DNSManifestRecords(path, zoneName)
	if err != nil {
		r.err = err
		return nil
	}

	note := "這個 zone 目前沒有任何 record。"
	if len(records) > 0 {
		note = "選一筆查看/編輯，或新增一筆。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := make([]string, 0, len(records)+2)
	for _, rec := range records {
		items = append(items, dnsRecordSummary(rec))
	}
	items = append(items, "➕ 新增 record", "↩  返回")

	return r.transitionTo(newSelectModelWithScreenID("dns.records.list", fmt.Sprintf("Records — zone %q", zoneName), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSZoneDetail(r, dir, path, zoneName, "")
		}
		switch {
		case m.Selected() < len(records):
			rec := records[m.Selected()]
			return pushDNSRecordDetail(r, dir, path, zoneName, dnsStringValue(rec, "name"), dnsStringOr(rec, "type", ""), "")
		case m.Selected() == len(records):
			return pushDNSRecordAddType(r, dir, path, zoneName)
		default:
			return pushDNSZoneDetail(r, dir, path, zoneName, "")
		}
	})
}

func dnsRecordSummary(rec map[string]any) string {
	name := dnsStringOr(rec, "name", "?")
	rtype := dnsStringOr(rec, "type", "?")
	state := dnsStringOr(rec, "state", "present")
	host := dnsStringValue(dnsSubmap(rec, "target"), "inventory_host")
	value := host
	if host != "" {
		value = "→inventory_host:" + host
	} else {
		value = strings.Join(dnsStringSlice(rec, "values"), ",")
	}
	return fmt.Sprintf("%s %s %s (%s)", name, rtype, value, state)
}

var dnsRecordTypeChoices = []string{"A", "AAAA", "CNAME"}

func pushDNSRecordAddType(r *editRouterModel, dir, path, zoneName string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("dns.record.add_type", "新 record 的類型", dnsRecordTypeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		return pushDNSRecordAddName(r, dir, path, zoneName, dnsRecordTypeChoices[m.Selected()])
	})
}

func pushDNSRecordAddName(r *editRouterModel, dir, path, zoneName, recordType string) tea.Cmd {
	label := "新 record 的名稱(zone-relative owner，例如 grafana；apex 用 @)"
	return r.transitionTo(newTextInputModelWithScreenID("dns.record.add_name", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		name := strings.TrimSpace(m.Value())
		if recordType == "CNAME" {
			// CNAME must always use an explicit FQDN value — a
			// target.inventory_host resolves to an IP, which is never a
			// valid CNAME value (internal/inventory/freeipa_dns_validate.go's
			// "cname target" gate rejects it), so there is no
			// value-source choice to offer for this type.
			return pushDNSRecordAddValues(r, dir, path, zoneName, recordType, name)
		}
		return pushDNSRecordAddValueSource(r, dir, path, zoneName, recordType, name)
	})
}

var dnsValueSourceChoices = []string{"從 inventory host 解析(target.inventory_host)", "明確指定值(values)"}

func pushDNSRecordAddValueSource(r *editRouterModel, dir, path, zoneName, recordType, name string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("dns.record.add_value_source", "值的來源", dnsValueSourceChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		if m.Selected() == 0 {
			return pushDNSRecordAddHostPicker(r, dir, path, zoneName, recordType, name)
		}
		return pushDNSRecordAddValues(r, dir, path, zoneName, recordType, name)
	})
}

func pushDNSRecordAddHostPicker(r *editRouterModel, dir, path, zoneName, recordType, name string) tea.Cmd {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		r.err = err
		return nil
	}
	names := hostNames(hf)
	if len(names) == 0 {
		return pushDNSRecordsMenu(r, dir, path, zoneName, "⚠️  hosts.yml 沒有任何主機可選；請先在 hosts.yml 新增主機，或改用明確指定值(values)")
	}
	return r.transitionTo(newSelectModelWithScreenID("dns.record.add_host_picker", "要解析哪個 inventory host 的 ansible_host？", names), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		host := names[m.Selected()]
		record := map[string]any{
			"name": name, "type": recordType, "state": "present",
			"target": map[string]any{"inventory_host": host},
		}
		return pushDNSRecordCommitAdd(r, dir, path, zoneName, record)
	})
}

func pushDNSRecordAddValues(r *editRouterModel, dir, path, zoneName, recordType, name string) tea.Cmd {
	label := "明確指定的值（逗號分隔）"
	if recordType == "CNAME" {
		label = "CNAME 目標(單一完整 FQDN，以 . 結尾，例如 nexus.ipa.pilot.internal.)"
	}
	return r.transitionTo(newTextInputModelWithScreenID("dns.record.add_values", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		values := rosterCommaList(m.Value())
		record := map[string]any{"name": name, "type": recordType, "state": "present", "values": values}
		return pushDNSRecordCommitAdd(r, dir, path, zoneName, record)
	})
}

func pushDNSRecordCommitAdd(r *editRouterModel, dir, path, zoneName string, record map[string]any) tea.Cmd {
	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		r.err = err
		return nil
	}
	violations, zoneFound, err := inventory.SimulateAddDNSRecord(path, zoneName, record, dnsValidateOptsFor(path, hostvars))
	if err != nil {
		r.err = fmt.Errorf("%s: %w", path, err)
		return nil
	}
	if !zoneFound {
		return pushDNSZonesMenu(r, dir, path, fmt.Sprintf("⚠️  zone %q 已不存在", zoneName))
	}
	if len(violations) > 0 {
		return pushDNSRecordsMenu(r, dir, path, zoneName, formatDNSViolations(violations))
	}
	if err := inventory.AppendDNSRecord(path, zoneName, record); err != nil {
		r.err = fmt.Errorf("write %s: %w", path, err)
		return nil
	}
	return pushDNSRecordsMenu(r, dir, path, zoneName, fmt.Sprintf("✅ 已新增 record %s", dnsStringValue(record, "name")))
}

func pushDNSRecordDetail(r *editRouterModel, dir, path, zoneName, recordName, recordType, banner string) tea.Cmd {
	fields, found, err := inventory.DNSManifestRecord(path, zoneName, recordName, recordType)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushDNSRecordsMenu(r, dir, path, zoneName, fmt.Sprintf("⚠️  record (%s,%s) 已不存在", recordName, recordType))
	}

	host := dnsStringValue(dnsSubmap(fields, "target"), "inventory_host")
	valueLabel, valueDisplay := "values", strings.Join(dnsStringSlice(fields, "values"), ", ")
	if host != "" {
		valueLabel, valueDisplay = "target.inventory_host", host
	} else if valueDisplay == "" {
		valueDisplay = "(未設定)"
	}

	items := []string{
		fmt.Sprintf("name：%s（唯讀）", recordName),
		fmt.Sprintf("type：%s（唯讀）", recordType),
		fmt.Sprintf("state：%s", dnsStringOr(fields, "state", "present")),
		fmt.Sprintf("%s：%s", valueLabel, valueDisplay),
		fmt.Sprintf("ttl：%s", dnsIntDisplay(fields, "ttl")),
		"↩  返回",
	}
	title := fmt.Sprintf("Record %s %s — zone %q", recordName, recordType, zoneName)
	return r.transitionTo(newSelectModelWithScreenID("dns.record.detail", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		switch m.Selected() {
		case 0, 1:
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "name/type 不可修改：其他地方會用這兩個值互相參照")
		case 2:
			return pushDNSRecordStateField(r, dir, path, zoneName, recordName, recordType)
		case 3:
			if recordType == "CNAME" {
				return pushDNSRecordValuesField(r, dir, path, zoneName, recordName, recordType)
			}
			return pushDNSRecordValueSourceField(r, dir, path, zoneName, recordName, recordType)
		case 4:
			return pushDNSRecordTTLField(r, dir, path, zoneName, recordName, recordType)
		case 5:
			return pushDNSRecordsMenu(r, dir, path, zoneName, "")
		}
		return nil
	})
}

// dnsApplyRecordEdit is dnsApplyZoneEdit's per-record counterpart.
func dnsApplyRecordEdit(dir, path, zoneName, recordName, recordType string, mutate func(map[string]any)) (banner string, err error) {
	fields, found, err := inventory.DNSManifestRecord(path, zoneName, recordName, recordType)
	if err != nil {
		return "", err
	}
	if !found {
		return fmt.Sprintf("⚠️  record (%s,%s) 已不存在（可能被其他流程移除）", recordName, recordType), nil
	}
	updated := cloneDNSFields(fields)
	mutate(updated)
	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		return "", err
	}
	violations, _, err := inventory.SimulateSetDNSRecord(path, zoneName, recordName, recordType, updated, dnsValidateOptsFor(path, hostvars))
	if err != nil {
		return "", err
	}
	if len(violations) > 0 {
		return formatDNSViolations(violations), nil
	}
	if err := inventory.SetDNSRecord(path, zoneName, recordName, recordType, updated); err != nil {
		return "", err
	}
	return "✅ 已更新", nil
}

func pushDNSEditRecord(r *editRouterModel, dir, path, zoneName, recordName, recordType string, mutate func(map[string]any)) tea.Cmd {
	banner, err := dnsApplyRecordEdit(dir, path, zoneName, recordName, recordType, mutate)
	if err != nil {
		r.err = err
		return nil
	}
	return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, banner)
}

var dnsRecordStateChoices = []string{"present", "absent"}

func pushDNSRecordStateField(r *editRouterModel, dir, path, zoneName, recordName, recordType string) tea.Cmd {
	title := "state（absent 代表要求 reconciler 刪除這個 RRset；只影響這個 type，不影響同 owner 的其他 record type）"
	return r.transitionTo(newSelectModelWithScreenID("dns.record.field_state", title, dnsRecordStateChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "")
		}
		value := dnsRecordStateChoices[m.Selected()]
		return pushDNSEditRecord(r, dir, path, zoneName, recordName, recordType, func(f map[string]any) { f["state"] = value })
	})
}

func pushDNSRecordValueSourceField(r *editRouterModel, dir, path, zoneName, recordName, recordType string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("dns.record.field_value_source", "值的來源", dnsValueSourceChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "")
		}
		if m.Selected() == 0 {
			return pushDNSRecordTargetField(r, dir, path, zoneName, recordName, recordType)
		}
		return pushDNSRecordValuesField(r, dir, path, zoneName, recordName, recordType)
	})
}

func pushDNSRecordValuesField(r *editRouterModel, dir, path, zoneName, recordName, recordType string) tea.Cmd {
	fields, _, err := inventory.DNSManifestRecord(path, zoneName, recordName, recordType)
	if err != nil {
		r.err = err
		return nil
	}
	current := strings.Join(dnsStringSlice(fields, "values"), ", ")
	label := "values（逗號分隔；設定這個欄位會清除 target.inventory_host）"
	if recordType == "CNAME" {
		label = "values（CNAME 只能有一個完整 FQDN，以 . 結尾）"
	}
	return r.transitionTo(newTextInputModelWithScreenID("dns.record.field_values", label, current, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "")
		}
		values := rosterCommaList(m.Value())
		return pushDNSEditRecord(r, dir, path, zoneName, recordName, recordType, func(f map[string]any) {
			f["values"] = values
			delete(f, "target")
		})
	})
}

func pushDNSRecordTargetField(r *editRouterModel, dir, path, zoneName, recordName, recordType string) tea.Cmd {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		r.err = err
		return nil
	}
	names := hostNames(hf)
	if len(names) == 0 {
		return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "⚠️  hosts.yml 沒有任何主機可選")
	}
	return r.transitionTo(newSelectModelWithScreenID("dns.record.field_target", "要解析哪個 inventory host 的 ansible_host？", names), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "")
		}
		host := names[m.Selected()]
		return pushDNSEditRecord(r, dir, path, zoneName, recordName, recordType, func(f map[string]any) {
			f["target"] = map[string]any{"inventory_host": host}
			delete(f, "values")
		})
	})
}

func pushDNSRecordTTLField(r *editRouterModel, dir, path, zoneName, recordName, recordType string) tea.Cmd {
	fields, _, err := inventory.DNSManifestRecord(path, zoneName, recordName, recordType)
	if err != nil {
		r.err = err
		return nil
	}
	label := "ttl（留空 = 使用 zone/manifest 預設；60-86400）"
	return r.transitionTo(newTextInputModelWithScreenID("dns.record.field_ttl", label, dnsIntValue(fields, "ttl"), dnsTTLValidator), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushDNSRecordDetail(r, dir, path, zoneName, recordName, recordType, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushDNSEditRecord(r, dir, path, zoneName, recordName, recordType, func(f map[string]any) {
			if value == "" {
				delete(f, "ttl")
				return
			}
			n, _ := strconv.Atoi(value)
			f["ttl"] = n
		})
	})
}

func dnsTTLValidator(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 60 || n > 86400 {
		return fmt.Errorf("必須留空，或是 60-86400 之間的整數")
	}
	return nil
}

// ---- normalized preview ----------------------------------------------------

// pushDNSManifestPreview shows inventory.NormalizeDNSManifest's resolved
// desired state (target.inventory_host already turned into the current
// ansible_host) — the Phase 1 "read-only plan" artifact, rendered here
// instead of via a live playbook run. Only shown when the manifest
// currently validates clean; an invalid manifest's "resolved" preview
// could otherwise be misleading (e.g. a missing target host silently
// contributing no value at all).
func pushDNSManifestPreview(r *editRouterModel, dir, path, banner string) tea.Cmd {
	root, err := inventory.LoadDNSManifest(path)
	if err != nil {
		r.err = err
		return nil
	}
	hostvars, err := loadDNSHostvars(dir)
	if err != nil {
		r.err = err
		return nil
	}
	opts := dnsValidateOptsFor(path, hostvars)
	if violations := inventory.ValidateDNSManifest(root, opts); len(violations) > 0 {
		return pushDNSManifestManager(r, dir, path, formatDNSViolations(violations))
	}
	text := formatDNSPreview(inventory.NormalizeDNSManifest(root, hostvars))
	if banner != "" {
		text = banner + "\n\n" + text
	}
	return pushDNSManifestManager(r, dir, path, text)
}

func formatDNSPreview(m inventory.NormalizedDNSManifest) string {
	if len(m.Zones) == 0 {
		return "📋 目前沒有任何 zone。"
	}
	lines := []string{"📋 Normalized preview（套用後的最終 desired state）："}
	for _, z := range m.Zones {
		lines = append(lines, fmt.Sprintf("  %s state=%s records_mode=%s", z.Name, z.State, z.RecordsMode))
		for _, rec := range z.Records {
			lines = append(lines, fmt.Sprintf("    %s.%s %s state=%s ttl=%d values=%s",
				rec.Name, z.Name, rec.Type, rec.State, rec.TTL, strings.Join(rec.Values, ",")))
		}
	}
	return strings.Join(lines, "\n")
}

// ---- shared helpers ---------------------------------------------------------

func formatDNSViolations(violations []inventory.DNSViolation) string {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, fmt.Sprintf("⚠️  驗證沒過，尚未寫入(%d 項)：", len(violations)))
	for _, v := range violations {
		lines = append(lines, "  - "+v.String())
	}
	return strings.Join(lines, "\n")
}

// loadHostsFileForDNS reads dir/hosts.yml for the target.inventory_host
// picker — independent of the manifest file itself, since a DNS record's
// target resolves against the deployment's real inventory. A missing
// hosts.yml is not an error here (just an empty picker) since a brand-new
// workspace may legitimately not have one yet.
func loadHostsFileForDNS(dir string) (*inventory.HostsFile, error) {
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		if os.IsNotExist(err) {
			return &inventory.HostsFile{}, nil
		}
		return nil, fmt.Errorf("read hosts.yml: %w", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse hosts.yml: %w", err)
	}
	return hf, nil
}

// loadDNSHostvars builds the {hostname: {"ansible_host": ip}} shape
// DNSValidateOptions/NormalizeDNSManifest expect, from hosts.yml.
func loadDNSHostvars(dir string) (map[string]map[string]any, error) {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(hf.Hosts))
	for _, h := range hf.Hosts {
		out[h.Name] = map[string]any{"ansible_host": h.AnsibleHost}
	}
	return out, nil
}

// dnsValidateOptsFor supplies the protected-zone list (the FreeIPA
// identity domain) from the manifest's own freeipa.domain field —
// ShadowedZones is deliberately left nil: split-horizon detection needs a
// live upstream `dig`, which this offline wizard has no business
// performing (that gate is exercised for real at apply time).
func dnsValidateOptsFor(path string, hostvars map[string]map[string]any) inventory.DNSValidateOptions {
	opts := inventory.DNSValidateOptions{Hostvars: hostvars}
	if domain, err := inventory.DNSManifestDomain(path); err == nil && domain != "" {
		opts.ProtectedZones = []string{strings.ToLower(strings.TrimSuffix(domain, ".")) + "."}
	}
	return opts
}

func cloneDNSFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func dnsStringOr(fields map[string]any, key, def string) string {
	if s, ok := fields[key].(string); ok && s != "" {
		return s
	}
	return def
}

func dnsStringValue(fields map[string]any, key string) string {
	s, _ := fields[key].(string)
	return s
}

func dnsBoolDisplay(fields map[string]any, key string) string {
	if b, ok := fields[key].(bool); ok {
		return strconv.FormatBool(b)
	}
	return "false"
}

func dnsIntValue(fields map[string]any, key string) string {
	switch v := fields[key].(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

func dnsIntDisplay(fields map[string]any, key string) string {
	if v := dnsIntValue(fields, key); v != "" {
		return v
	}
	return "(使用預設)"
}

func dnsStringSlice(fields map[string]any, key string) []string {
	raw, _ := fields[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func dnsSubmap(fields map[string]any, key string) map[string]any {
	if sub, ok := fields[key].(map[string]any); ok {
		return sub
	}
	return map[string]any{}
}
