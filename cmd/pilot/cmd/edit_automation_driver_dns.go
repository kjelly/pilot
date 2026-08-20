// edit_automation_driver_dns.go drives the freeipa-dns manifest screens
// (edit_tui_dns.go) for create_dns_manifest/create_dns_zone/
// set_dns_zone_field/create_dns_record/set_dns_record_field/
// set_dns_record_values/set_dns_record_target_host (Phase 6 increment
// 4), using the stable screen IDs added to those screens instead of
// title-substring matching, mirroring the roster driver files' pattern.
// Automation only supports the manifest's default path
// (dir/freeipa-dns.yaml, pushDNSManifestPathPrompt's prefill), matching
// the roster automation's own non-goal precedent — create_dns_manifest
// must run first on a genuinely fresh workspace before any other DNS
// action.
package cmd

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/tui"
)

func (d *automationDriver) ensureDNSManifestPathPrompt(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "dns.path":
			return nil
		case "edit.top":
			if err := d.choose(r, "freeipa-dns manifest"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to dns manifest path prompt from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to dns manifest path prompt")
}

// createDNSManifest replays pushDNSManifestCreateConfirm's full flow
// (confirm -> domain -> realm -> server), the only way to produce the
// manifest file at all. domain/realm/server's prompts all start pre-filled
// (FreeIPADomain(dir) / strings.ToUpper(domain) /
// inventory.FreeIPAServerFQDN(dir) falling back to "ipa1."+domain), so all
// three use replace=true.
func (d *automationDriver) createDNSManifest(r *editRouterModel, domain, realm, server string) error {
	if err := d.ensureDNSManifestPathPrompt(r); err != nil {
		return err
	}
	if err := d.enter(r); err != nil { // accept the prefilled default path
		return err
	}
	if err := d.confirmYesNo(r, true); err != nil {
		return err
	}
	if err := d.typeText(r, domain, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, realm, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, server, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureDNSManifestManager(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "dns.manager":
			return nil
		case "edit.top":
			if err := d.choose(r, "freeipa-dns manifest"); err != nil {
				return err
			}
		case "dns.path":
			// Only reachable when the manifest already exists — see the
			// package doc comment above.
			if err := d.enter(r); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to dns manifest manager from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to dns manifest manager")
}

func (d *automationDriver) ensureDNSZonesList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "dns.zones.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "freeipa-dns manifest"); err != nil {
				return err
			}
		case "dns.path":
			if err := d.enter(r); err != nil {
				return err
			}
		case "dns.manager":
			if err := d.choose(r, "🌐 Zones"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to dns zones list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to dns zones list")
}

func (d *automationDriver) createDNSZone(r *editRouterModel, zone string) error {
	if err := d.ensureDNSZonesList(r); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 zone"); err != nil {
		return err
	}
	if err := d.typeText(r, zone, false); err != nil {
		return err
	}
	return d.enter(r)
}

// listTitleNamesDNSZone reports whether title is pushDNSZoneDetail's
// title for exactly this zone — `Zone "name" — path`.
func listTitleNamesDNSZone(title, zone string) bool {
	return strings.HasPrefix(title, fmt.Sprintf("Zone %q ", zone))
}

func (d *automationDriver) ensureDNSZoneDetail(r *editRouterModel, zone string) error {
	if automationScreenID(r) == "dns.zone.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && listTitleNamesDNSZone(st.Title, zone) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureDNSZonesList(r); err != nil {
		return err
	}
	return d.choose(r, "🌐 "+zone)
}

// setDNSZoneField covers state/records_mode/acknowledge_split_horizon —
// all three are select-screen widgets in the TUI (never a text field),
// so this always chooses the target field then chooses value.
func (d *automationDriver) setDNSZoneField(r *editRouterModel, zone, field, value string) error {
	if err := d.ensureDNSZoneDetail(r, zone); err != nil {
		return err
	}
	if err := d.choose(r, field); err != nil {
		return err
	}
	return d.choose(r, value)
}

func (d *automationDriver) ensureDNSRecordsMenu(r *editRouterModel, zone string) error {
	if automationScreenID(r) == "dns.records.list" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == fmt.Sprintf("Records — zone %q", zone) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureDNSZoneDetail(r, zone); err != nil {
		return err
	}
	return d.choose(r, "Records（共")
}

// createDNSRecord replays the full creation wizard (type -> name ->
// (value-source, skipped for CNAME) -> host-picker or values) in one
// atomic step, matching the TUI: there is no "create an empty record"
// primitive to decouple creation from its value source. Exactly one of
// targetHost/values must be set for a non-CNAME record; CNAME requires
// values and ignores targetHost entirely (mirrors
// pushDNSRecordAddName's own branch — CNAME never even offers a
// value-source choice).
func (d *automationDriver) createDNSRecord(r *editRouterModel, zone, recordType, name, targetHost string, values []string) error {
	if err := d.ensureDNSRecordsMenu(r, zone); err != nil {
		return err
	}
	if err := d.choose(r, "➕ 新增 record"); err != nil {
		return err
	}
	if err := d.choose(r, recordType); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if recordType == "CNAME" {
		if err := d.typeText(r, strings.Join(values, ", "), false); err != nil {
			return err
		}
		return d.enter(r)
	}
	if targetHost != "" {
		if err := d.choose(r, "從 inventory host 解析"); err != nil {
			return err
		}
		return d.choose(r, targetHost)
	}
	if err := d.choose(r, "明確指定值"); err != nil {
		return err
	}
	if err := d.typeText(r, strings.Join(values, ", "), false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) ensureDNSRecordDetail(r *editRouterModel, zone, recordName, recordType string) error {
	wantTitle := fmt.Sprintf("Record %s %s — zone %q", recordName, recordType, zone)
	if automationScreenID(r) == "dns.record.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && st.Title == wantTitle {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureDNSRecordsMenu(r, zone); err != nil {
		return err
	}
	// dnsRecordSummary's item text starts with "<name> <type> " — a
	// (name,type) pair is the schema's own uniqueness key, so this
	// prefix always matches exactly one item.
	return d.choose(r, fmt.Sprintf("%s %s ", recordName, recordType))
}

// setDNSRecordField covers state (select) and ttl (text) — the two
// record fields whose widget doesn't depend on whether values or
// target.inventory_host is currently set. See setDNSRecordValues/
// setDNSRecordTargetHost for the value-source field, which does.
func (d *automationDriver) setDNSRecordField(r *editRouterModel, zone, recordName, recordType, field, value string) error {
	if err := d.ensureDNSRecordDetail(r, zone, recordName, recordType); err != nil {
		return err
	}
	switch field {
	case "state":
		if err := d.choose(r, "state"); err != nil {
			return err
		}
		return d.choose(r, value)
	case "ttl":
		if err := d.choose(r, "ttl"); err != nil {
			return err
		}
		if err := d.typeText(r, value, true); err != nil {
			return err
		}
		return d.enter(r)
	}
	return fmt.Errorf("unsupported dns record field %q", field)
}

// dnsRecordValueItemIndex is pushDNSRecordDetail's fixed item index for
// its value-source row — its label text is either "values：..." or
// "target.inventory_host：...", depending on which the record currently
// has, so there is no single label substring both forms share; the
// index is stable regardless (name=0, type=1, state=2, value=3, ttl=4,
// back=5).
const dnsRecordValueItemIndex = 3

// setDNSRecordValues bulk-replaces a record's explicit values (clearing
// target.inventory_host, matching pushDNSRecordValuesField's own
// delete(f, "target")). For a non-CNAME record this must first choose
// "明確指定值" on the intermediate value-source screen; CNAME skips
// straight to the text field.
func (d *automationDriver) setDNSRecordValues(r *editRouterModel, zone, recordName, recordType string, values []string) error {
	if err := d.ensureDNSRecordDetail(r, zone, recordName, recordType); err != nil {
		return err
	}
	if err := d.moveCursor(r, dnsRecordValueItemIndex); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if recordType != "CNAME" {
		if err := d.choose(r, "明確指定值"); err != nil {
			return err
		}
	}
	if err := d.typeText(r, strings.Join(values, ", "), true); err != nil {
		return err
	}
	return d.enter(r)
}

// setDNSRecordTargetHost sets target.inventory_host (clearing values,
// matching pushDNSRecordTargetField's own delete(f, "values")). Never
// valid for CNAME — the TUI itself never offers this choice for that
// type (pushDNSRecordDetail routes CNAME straight to
// pushDNSRecordValuesField).
func (d *automationDriver) setDNSRecordTargetHost(r *editRouterModel, zone, recordName, recordType, host string) error {
	if recordType == "CNAME" {
		return fmt.Errorf("CNAME records cannot use target.inventory_host")
	}
	if err := d.ensureDNSRecordDetail(r, zone, recordName, recordType); err != nil {
		return err
	}
	if err := d.moveCursor(r, dnsRecordValueItemIndex); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.choose(r, "從 inventory host 解析"); err != nil {
		return err
	}
	return d.choose(r, host)
}
