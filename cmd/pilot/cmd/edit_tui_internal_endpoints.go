// edit_tui_internal_endpoints.go implements the internal-endpoints manifest
// screens of the `pilot edit` router (edit_tui.go): a manager for the
// internal-endpoint declarative manifest (spec.md §8-§24) covering FQDN,
// state, DNS zone/TTL, route (direct/reverse_proxy), and TLS
// (disabled/freeipa + direct-mode sink). Every write goes through
// internal/inventory.Simulate{Add,Set}InternalEndpoint first (mirroring
// playbooks/apply/internal-endpoint-apply.yml's own preflight gates via
// inventory.ValidateInternalEndpointManifest) so a mistake is caught before
// it ever touches disk, then Append/SetInternalEndpoint persists via
// yaml.Node surgery — never a full-struct remarshal — same convention as
// edit_tui_dns.go.
//
// "state: absent" IS offered here — like freeipa-dns's zones/records, it is
// a first-class declarative reconcile request (spec.md §31), not a
// destructive action this wizard performs directly; the real deletion
// happens later, at apply time, behind its own independent safety gates
// (safety.allow_endpoint_delete + confirm_endpoint_delete). Writing
// state: absent here is exactly as safe as writing any other field.
//
// Unlike freeipa-dns, this manifest declares no freeipa.{domain,realm,server}
// identity block of its own (spec.md §8/§9), so manifest creation needs no
// prompts beyond the path itself. Live-state gates (TLS owner enrollment,
// ownership-ledger presence, route-owner migration) are intentionally left
// unchecked here — internalEndpointValidateOptsFor leaves those maps nil,
// which internal/inventory's own gates treat as "skip" (same posture as
// edit_tui_dns.go's ShadowedZones-left-nil for split-horizon detection):
// this offline wizard has no live FreeIPA/ledger state to check against,
// and those gates are exercised for real at apply time.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// ---- entry point + manifest-level manager -------------------------------

func pushInternalEndpointManifestPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, "internal-endpoints.yaml")
	return r.transitionTo(newTextInputModelWithScreenID("iep.path", "internal-endpoints manifest 檔路徑", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushInternalEndpointManifestManager(r, dir, strings.TrimSpace(m.Value()), "")
	})
}

func pushInternalEndpointManifestManager(r *editRouterModel, dir, path, banner string) tea.Cmd {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// A missing manifest on first visit is entirely foreseeable —
			// offer to auto-generate the minimal skeleton instead of
			// killing the whole `pilot edit` session over it.
			return pushInternalEndpointManifestCreateConfirm(r, dir, path)
		}
		r.err = fmt.Errorf("stat %s: %w", path, err)
		return nil
	}

	items := []string{
		"🔌 Endpoints",
		"📋 顯示 normalized preview(套用後的最終 desired state)",
		"↩  返回",
	}
	title := fmt.Sprintf("管理 %s", path)
	return r.transitionTo(newSelectModelWithScreenID("iep.manager", title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushInternalEndpointsMenu(r, dir, path, "")
		case 1:
			return pushInternalEndpointManifestPreview(r, dir, path, "")
		case 2:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// pushInternalEndpointManifestCreateConfirm offers to auto-generate the
// smallest schema-valid manifest skeleton when path doesn't exist yet —
// same recoverable posture as pushDNSManifestCreateConfirm/
// pushRosterCreateConfirm. No domain/realm/server prompts needed (unlike
// DNS) — this manifest declares no freeipa identity block.
func pushInternalEndpointManifestCreateConfirm(r *editRouterModel, dir, path string) tea.Cmd {
	question := fmt.Sprintf("%s 不存在，要建立最小 internal-endpoints manifest 骨架嗎？", path)
	return r.transitionTo(newConfirmModelWithScreenID("iep.create_confirm", question, true), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return pushTopMenu(r, dir, "")
		}
		if err := inventory.CreateMinimalInternalEndpointManifest(path); err != nil {
			r.err = err
			return nil
		}
		return pushInternalEndpointManifestManager(r, dir, path, fmt.Sprintf("✅ 已建立最小 internal-endpoints manifest 骨架 %s", path))
	})
}

// ---- endpoints list + create ---------------------------------------------

func pushInternalEndpointsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	fqdns, err := inventory.InternalEndpointManifestFQDNs(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}

	note := "目前沒有任何 endpoint。"
	if len(fqdns) > 0 {
		note = "選一個查看/編輯，或新增一個。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := make([]string, 0, len(fqdns)+3)
	for _, f := range fqdns {
		items = append(items, "🔌 "+f)
	}
	items = append(items, "➕ 新增 endpoint", "🔎 從已部署服務建議 endpoint", "↩  返回")

	return r.transitionTo(newSelectModelWithScreenID("iep.list", fmt.Sprintf("Endpoints — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointManifestManager(r, dir, path, "")
		}
		switch {
		case m.Selected() < len(fqdns):
			return pushInternalEndpointDetail(r, dir, path, fqdns[m.Selected()], "")
		case m.Selected() == len(fqdns):
			return pushInternalEndpointAddFQDN(r, dir, path)
		case m.Selected() == len(fqdns)+1:
			return pushInternalEndpointSuggestMenu(r, dir, path)
		default:
			return pushInternalEndpointManifestManager(r, dir, path, "")
		}
	})
}

// ---- suggest from deployed services ---------------------------------------

// pushInternalEndpointSuggestMenu is the interactive counterpart of `pilot
// internal-endpoint suggest`: it resolves the same contracts +
// hosts.yml/freeipa-dns.yaml inputs the CLI takes as flags, but only for the
// unambiguous common case (exactly one reverse-proxy host, exactly one
// freeipa-dns zone) — anything ambiguous bails out to a banner pointing at
// the CLI's --proxy-host/--zone overrides instead of guessing. Accepted
// candidates still go through the exact same SimulateAddInternalEndpoint ->
// AppendInternalEndpoint chain as a manually authored entry (see
// pushInternalEndpointAddTargetHost) — this menu item only pre-fills the
// wizard, it never writes around its gates.
func pushInternalEndpointSuggestMenu(r *editRouterModel, dir, path string) tea.Cmd {
	root, err := resolveContractRoot("")
	if err != nil {
		r.err = err
		return nil
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		r.err = err
		return nil
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		r.err = err
		return nil
	}

	groups, err := resolveInventoryGroups(context.Background(), filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  無法讀取 hosts.yml 的 inventory groups：%v", err))
	}

	proxyHosts := groups["reverse-proxy"]
	if len(proxyHosts) != 1 {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf(
			"⚠️  reverse-proxy 主機不是唯一一台（%d 台），這裡無法自動判斷；改用 `pilot internal-endpoint suggest --proxy-host <host>` 手動指定。", len(proxyHosts)))
	}

	dnsManifestPath := filepath.Join(dir, "freeipa-dns.yaml")
	zones, err := inventory.DNSManifestZoneNames(dnsManifestPath)
	if err != nil || len(zones) != 1 {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf(
			"⚠️  %s 沒有恰好一個 zone，這裡無法自動判斷 dns.zone；改用 `pilot internal-endpoint suggest --zone <zone>` 手動指定。", dnsManifestPath))
	}

	existing, err := inventory.LoadInternalEndpointManifest(path)
	if err != nil {
		r.err = err
		return nil
	}

	result := inventory.SuggestInternalEndpoints(catalog.Components(), groups, proxyHosts[0], zones[0], existing)
	if len(result.Candidates) == 0 {
		banner := "沒有符合條件的候選 endpoint。"
		for _, skip := range result.Skipped {
			banner += fmt.Sprintf("\n  %s/%s：%s", skip.Component, skip.Endpoint, skip.Reason)
		}
		return pushInternalEndpointsMenu(r, dir, path, banner)
	}

	byLabel := make(map[string]inventory.InternalEndpointCandidate, len(result.Candidates))
	items := make([]multiSelectItem, len(result.Candidates))
	for i, c := range result.Candidates {
		route := iepMapField(c.Manifest, "route")
		upstream := iepMapField(route, "upstream")
		label := fmt.Sprintf("%s  [%s/%s → %s:%s]", c.FQDN, c.Component, c.Endpoint,
			iepStringValue(upstream, "inventory_host"), iepIntDisplay(upstream, "port", ""))
		byLabel[label] = c
		items[i] = multiSelectItem{Label: label}
	}

	title := "選要建立的 endpoint（space 勾選、enter 確認）"
	return r.transitionTo(newMultiSelectModelWithScreenID("iep.suggest.pick", title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		opts := internalEndpointValidateOptsFor(dir)
		var added []string
		var rejected []string
		for _, label := range m.CheckedLabels() {
			c, ok := byLabel[label]
			if !ok {
				continue
			}
			violations, err := inventory.SimulateAddInternalEndpoint(path, c.Manifest, opts)
			if err != nil {
				r.err = fmt.Errorf("%s: %w", path, err)
				return nil
			}
			if len(violations) > 0 {
				rejected = append(rejected, fmt.Sprintf("%s：%s", c.FQDN, formatIEPViolations(violations)))
				continue
			}
			if err := inventory.AppendInternalEndpoint(path, c.Manifest); err != nil {
				r.err = fmt.Errorf("write %s: %w", path, err)
				return nil
			}
			added = append(added, c.FQDN)
		}
		banner := "沒有勾選任何 endpoint。"
		if len(added) > 0 {
			banner = fmt.Sprintf("✅ 已新增 %d 個 endpoint：%s", len(added), strings.Join(added, ", "))
		}
		if len(rejected) > 0 {
			banner += "\n⚠️  以下候選未通過驗證，未寫入：\n" + strings.Join(rejected, "\n")
		}
		return pushInternalEndpointsMenu(r, dir, path, banner)
	})
}

// pushInternalEndpointAddFQDN starts the minimal creation wizard: fqdn ->
// dns.zone -> direct route target (inventory_host) -> create with
// tls.mode: disabled (the always-valid default; use the detail screen's
// route/tls editors afterward to switch to reverse_proxy/freeipa). Every
// endpoint needs a real route+tls to pass ValidateInternalEndpointManifest
// at all (spec.md §10.1), so — unlike a freeipa-dns zone, which can start
// with an empty records: [] — creation can't be split into "just a name"
// the way pushDNSZoneAddName is.
func pushInternalEndpointAddFQDN(r *editRouterModel, dir, path string) tea.Cmd {
	label := "新 endpoint 的 FQDN(例如 grafana.linker.internal)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.add.fqdn", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		return pushInternalEndpointAddZone(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

// iepDefaultZoneForFQDN picks the freeipa-dns.yaml zone fqdn belongs to —
// the same apex-or-strict-descendant relationship
// ValidateInternalEndpointManifest's dns.zone check requires — preferring
// the longest (most specific) match when more than one declared zone
// qualifies. Returns "" (leaving the field free-text) when none match.
func iepDefaultZoneForFQDN(dir, fqdn string) string {
	zones, err := inventory.DNSManifestZoneNames(filepath.Join(dir, "freeipa-dns.yaml"))
	if err != nil {
		return ""
	}
	target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	best, bestLen := "", -1
	for _, z := range zones {
		zoneName := strings.ToLower(strings.TrimSuffix(z, "."))
		if zoneName == "" {
			continue
		}
		if target == zoneName || strings.HasSuffix(target, "."+zoneName) {
			if len(zoneName) > bestLen {
				best, bestLen = z, len(zoneName)
			}
		}
	}
	return best
}

func pushInternalEndpointAddZone(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	def := iepDefaultZoneForFQDN(dir, fqdn)
	label := "dns.zone(絕對 FQDN，必須是 endpoint fqdn 本身或其上層 zone，例如 linker.internal.)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.add.zone", label, def, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		return pushInternalEndpointAddTargetHost(r, dir, path, fqdn, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointAddTargetHost(r *editRouterModel, dir, path, fqdn, zone string) tea.Cmd {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		r.err = err
		return nil
	}
	names := hostNames(hf)
	if len(names) == 0 {
		return pushInternalEndpointsMenu(r, dir, path, "⚠️  hosts.yml 沒有任何主機可選；請先在 hosts.yml 新增主機")
	}
	title := "route.target.inventory_host(direct route 的目標 inventory host；之後可在 detail 畫面改成 reverse_proxy)"
	return r.transitionTo(newSelectModelWithScreenID("iep.add.target_host", title, names), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		targetHost := names[m.Selected()]
		endpoint := map[string]any{
			"fqdn":  fqdn,
			"state": "present",
			"dns":   map[string]any{"zone": zone},
			"route": map[string]any{
				"mode":   "direct",
				"target": map[string]any{"inventory_host": targetHost},
			},
			"tls": map[string]any{"mode": "disabled"},
		}
		opts := internalEndpointValidateOptsFor(dir)
		violations, err := inventory.SimulateAddInternalEndpoint(path, endpoint, opts)
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushInternalEndpointsMenu(r, dir, path, formatIEPViolations(violations))
		}
		if err := inventory.AppendInternalEndpoint(path, endpoint); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushInternalEndpointDetail(r, dir, path, fqdn, fmt.Sprintf(
			"✅ 已新增 endpoint %s（tls.mode=disabled）；可在這裡繼續編輯 route/tls 等欄位。", fqdn))
	})
}

// ---- endpoint detail -------------------------------------------------------

func pushInternalEndpointDetail(r *editRouterModel, dir, path, fqdn, banner string) tea.Cmd {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  endpoint %q 已不存在", fqdn))
	}

	dns := iepMapField(fields, "dns")
	route := iepMapField(fields, "route")
	tls := iepMapField(fields, "tls")

	items := []string{
		fmt.Sprintf("fqdn：%s（唯讀，主鍵）", fqdn),
		fmt.Sprintf("state：%s", iepStringOr(fields, "state", "present")),
		fmt.Sprintf("dns：zone=%s ttl=%s", iepStringValue(dns, "zone"), iepIntDisplay(dns, "ttl", "(manifest 預設)")),
		fmt.Sprintf("route：%s", iepRouteSummary(route)),
		fmt.Sprintf("tls：%s", iepTLSSummary(tls)),
		"↩  返回",
	}
	return r.transitionTo(newSelectModelWithScreenID("iep.detail", fmt.Sprintf("Endpoint %q — %s", fqdn, path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushInternalEndpointDetail(r, dir, path, fqdn, "fqdn 不可修改：這是這個 endpoint 的主鍵")
		case 1:
			return pushInternalEndpointStateField(r, dir, path, fqdn)
		case 2:
			return pushInternalEndpointDNSZoneField(r, dir, path, fqdn)
		case 3:
			return pushInternalEndpointRouteMenu(r, dir, path, fqdn)
		case 4:
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		case 5:
			return pushInternalEndpointsMenu(r, dir, path, "")
		}
		return nil
	})
}

// iepApplyEdit re-reads fqdn's current fields, applies mutate to a clone,
// and simulates-then-writes exactly like pushInternalEndpointAddTargetHost's
// own gate chain (Simulate first, only write once it reports no
// violations) — the internal-endpoint counterpart of dnsApplyZoneEdit.
func iepApplyEdit(dir, path, fqdn string, mutate func(map[string]any)) (banner string, err error) {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		return "", err
	}
	if !found {
		return fmt.Sprintf("⚠️  endpoint %q 已不存在（可能被其他流程移除）", fqdn), nil
	}
	updated := cloneIEPFields(fields)
	mutate(updated)
	violations, _, err := inventory.SimulateSetInternalEndpoint(path, fqdn, updated, internalEndpointValidateOptsFor(dir))
	if err != nil {
		return "", err
	}
	if len(violations) > 0 {
		return formatIEPViolations(violations), nil
	}
	if err := inventory.SetInternalEndpoint(path, fqdn, updated); err != nil {
		return "", err
	}
	return "✅ 已更新", nil
}

func pushInternalEndpointEditDetail(r *editRouterModel, dir, path, fqdn string, mutate func(map[string]any)) tea.Cmd {
	banner, err := iepApplyEdit(dir, path, fqdn, mutate)
	if err != nil {
		r.err = err
		return nil
	}
	return pushInternalEndpointDetail(r, dir, path, fqdn, banner)
}

var iepStateChoices = []string{"present", "absent"}

func pushInternalEndpointStateField(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	title := "state（absent 代表要求 reconciler 刪除這個 endpoint；實際刪除仍受 apply 端 safety.allow_endpoint_delete + confirm_endpoint_delete 雙重確認保護，這裡寫入 absent 本身是安全的）"
	return r.transitionTo(newSelectModelWithScreenID("iep.field.state", title, iepStateChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		value := iepStateChoices[m.Selected()]
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) { f["state"] = value })
	})
}

func pushInternalEndpointDNSZoneField(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  endpoint %q 已不存在", fqdn))
	}
	def := iepStringValue(iepMapField(fields, "dns"), "zone")
	label := "dns.zone(絕對 FQDN，必須是 endpoint fqdn 本身或其上層 zone)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.field.dns_zone", label, def, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointDNSTTLField(r, dir, path, fqdn, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointDNSTTLField(r *editRouterModel, dir, path, fqdn, zone string) tea.Cmd {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  endpoint %q 已不存在", fqdn))
	}
	def := iepIntValue(iepMapField(fields, "dns"), "ttl")
	label := "dns.ttl(留空使用 manifest 的 defaults.dns.ttl)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.field.dns_ttl", label, def, iepOptionalInt), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		ttlText := strings.TrimSpace(m.Value())
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
			dns := map[string]any{"zone": zone}
			if ttlText != "" {
				if n, err := strconv.Atoi(ttlText); err == nil {
					dns["ttl"] = n
				}
			}
			f["dns"] = dns
		})
	})
}

// ---- route ------------------------------------------------------------

var iepRouteModeChoices = []string{"direct", "reverse_proxy"}

func pushInternalEndpointRouteMenu(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	title := "route.mode（direct/reverse_proxy 之間切換屬於 route owner migration，實際套用時 v1 一律拒絕就地遷移 — 這裡的寫入只影響 manifest 意圖，之後 apply 會依 spec.md §30 檢查）"
	return r.transitionTo(newSelectModelWithScreenID("iep.route.menu", title, iepRouteModeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		if iepRouteModeChoices[m.Selected()] == "direct" {
			return pushInternalEndpointRouteDirectSource(r, dir, path, fqdn)
		}
		return pushInternalEndpointRouteProxyHost(r, dir, path, fqdn)
	})
}

var iepTargetSourceChoices = []string{"從 inventory host 解析", "手動輸入 IP"}

func pushInternalEndpointRouteDirectSource(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("iep.route.direct.source", "route.target 的值來源", iepTargetSourceChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		if m.Selected() == 0 {
			return pushInternalEndpointRouteDirectHostPicker(r, dir, path, fqdn)
		}
		return pushInternalEndpointRouteDirectAddress(r, dir, path, fqdn)
	})
}

// pushInternalEndpointRouteDirectHostPicker renders the real hosts.yml
// entries as a select list — same convention as edit_tui_dns.go's
// pushDNSRecordAddHostPicker — rather than free text, so an
// inventory_host reference can't be misspelled.
func pushInternalEndpointRouteDirectHostPicker(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		r.err = err
		return nil
	}
	names := hostNames(hf)
	if len(names) == 0 {
		return pushInternalEndpointDetail(r, dir, path, fqdn, "⚠️  hosts.yml 沒有任何主機可選；請改用「手動輸入 IP」")
	}
	return r.transitionTo(newSelectModelWithScreenID("iep.route.direct.host", "route.target.inventory_host", names), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		host := names[m.Selected()]
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
			f["route"] = map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": host}}
		})
	})
}

func pushInternalEndpointRouteDirectAddress(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	label := "route.target.address(literal IP)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.route.direct.address", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
			f["route"] = map[string]any{"mode": "direct", "target": map[string]any{"address": value}}
		})
	})
}

// iepDefaultReverseProxyHost mirrors pushInternalEndpointSuggestMenu's own
// detection: only pre-fill when exactly one host carries the reverse-proxy
// role, since with more than one there's no deterministically-correct
// choice — the field stays free-text (unprefilled) in that case.
func iepDefaultReverseProxyHost(dir string) string {
	hosts, err := loadIEPReverseProxyHosts(dir)
	if err != nil || len(hosts) != 1 {
		return ""
	}
	for h := range hosts {
		return h
	}
	return ""
}

func pushInternalEndpointRouteProxyHost(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	def := iepDefaultReverseProxyHost(dir)
	label := "route.proxy.inventory_host(必須是有 reverse-proxy role 的 host)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.route.proxy.host", label, def, nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointRouteUpstreamScheme(r, dir, path, fqdn, strings.TrimSpace(m.Value()))
	})
}

var iepUpstreamSchemeChoices = []string{"http", "https"}

func pushInternalEndpointRouteUpstreamScheme(r *editRouterModel, dir, path, fqdn, proxyHost string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("iep.route.upstream.scheme", "upstream.scheme（省略即 fail — spec.md §12.3 必填）", iepUpstreamSchemeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointRouteUpstreamSource(r, dir, path, fqdn, proxyHost, iepUpstreamSchemeChoices[m.Selected()])
	})
}

func pushInternalEndpointRouteUpstreamSource(r *editRouterModel, dir, path, fqdn, proxyHost, scheme string) tea.Cmd {
	return r.transitionTo(newSelectModelWithScreenID("iep.route.upstream.source", "upstream 的值來源", iepTargetSourceChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		if m.Selected() == 0 {
			return pushInternalEndpointRouteUpstreamHostPicker(r, dir, path, fqdn, proxyHost, scheme)
		}
		return pushInternalEndpointRouteUpstreamAddress(r, dir, path, fqdn, proxyHost, scheme)
	})
}

// pushInternalEndpointRouteUpstreamHostPicker is
// pushInternalEndpointRouteDirectHostPicker's upstream.inventory_host
// counterpart — same real-hosts.yml select-list convention.
func pushInternalEndpointRouteUpstreamHostPicker(r *editRouterModel, dir, path, fqdn, proxyHost, scheme string) tea.Cmd {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		r.err = err
		return nil
	}
	names := hostNames(hf)
	if len(names) == 0 {
		return pushInternalEndpointDetail(r, dir, path, fqdn, "⚠️  hosts.yml 沒有任何主機可選；請改用「手動輸入 IP」")
	}
	return r.transitionTo(newSelectModelWithScreenID("iep.route.upstream.host", "upstream.inventory_host", names), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointRouteUpstreamPort(r, dir, path, fqdn, proxyHost, scheme, names[m.Selected()], "")
	})
}

func pushInternalEndpointRouteUpstreamAddress(r *editRouterModel, dir, path, fqdn, proxyHost, scheme string) tea.Cmd {
	label := "upstream.address(literal IP)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.route.upstream.address", label, "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		value := strings.TrimSpace(m.Value())
		return pushInternalEndpointRouteUpstreamPort(r, dir, path, fqdn, proxyHost, scheme, "", value)
	})
}

func pushInternalEndpointRouteUpstreamPort(r *editRouterModel, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress string) tea.Cmd {
	label := "upstream.port(1..65535)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.route.upstream.port", label, "", iepValidPort), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		port, _ := strconv.Atoi(strings.TrimSpace(m.Value()))
		if scheme == "http" {
			return pushInternalEndpointApplyRouteProxy(r, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress, port, nil, "")
		}
		return pushInternalEndpointRouteUpstreamVerify(r, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress, port)
	})
}

var iepBoolChoices = []string{"true", "false"}

func pushInternalEndpointRouteUpstreamVerify(r *editRouterModel, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress string, port int) tea.Cmd {
	title := "upstream.tls.verify（https upstream 必填，明確表示是否驗證 upstream 憑證 — false 仍然是加密 TLS，只是不驗證身分，spec.md §12.4.3）"
	return r.transitionTo(newSelectModelWithScreenID("iep.route.upstream.verify", title, iepBoolChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		verify := m.Selected() == 0
		return pushInternalEndpointRouteUpstreamSNI(r, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress, port, verify)
	})
}

func pushInternalEndpointRouteUpstreamSNI(r *editRouterModel, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress string, port int, verify bool) tea.Cmd {
	label := "upstream.tls.server_name(SNI；upstream.address 或 verify=true 時建議明確填寫，留空由 inventory host 的 canonical FQDN 推導，spec.md §12.4.6)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.route.upstream.sni", label, "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		sni := strings.TrimSpace(m.Value())
		tlsVerify := verify
		return pushInternalEndpointApplyRouteProxy(r, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress, port, &tlsVerify, sni)
	})
}

func pushInternalEndpointApplyRouteProxy(r *editRouterModel, dir, path, fqdn, proxyHost, scheme, upstreamHost, upstreamAddress string, port int, verify *bool, sni string) tea.Cmd {
	return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
		upstream := map[string]any{"scheme": scheme, "port": port}
		if upstreamHost != "" {
			upstream["inventory_host"] = upstreamHost
		} else {
			upstream["address"] = upstreamAddress
		}
		if verify != nil {
			tls := map[string]any{"verify": *verify}
			if sni != "" {
				tls["server_name"] = sni
			}
			upstream["tls"] = tls
		}
		f["route"] = map[string]any{
			"mode":     "reverse_proxy",
			"proxy":    map[string]any{"provider": "nginx", "inventory_host": proxyHost},
			"upstream": upstream,
		}
	})
}

// ---- tls ------------------------------------------------------------

var iepTLSModeChoices = []string{"disabled", "freeipa"}

func pushInternalEndpointTLSMenu(r *editRouterModel, dir, path, fqdn, banner string) tea.Cmd {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  endpoint %q 已不存在", fqdn))
	}
	tls := iepMapField(fields, "tls")
	route := iepMapField(fields, "route")
	isDirect := iepStringValue(route, "mode") == "direct"
	isFreeIPA := iepStringValue(tls, "mode") == "freeipa"

	items := []string{
		fmt.Sprintf("mode：%s", iepStringOr(tls, "mode", "disabled")),
		fmt.Sprintf("port：%s（僅 freeipa 適用）", iepIntDisplay(tls, "port", "(使用預設 443)")),
		"sink（cert_file/key_file/reload...；僅 direct route 適用）",
		"↩  返回",
	}
	return r.transitionTo(newSelectModelWithScreenID("iep.tls.menu", fmt.Sprintf("Endpoint %q tls", fqdn), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		switch m.Selected() {
		case 0:
			return pushInternalEndpointTLSModeField(r, dir, path, fqdn)
		case 1:
			if !isFreeIPA {
				return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "⚠️  port 只適用於 tls.mode=freeipa")
			}
			return pushInternalEndpointTLSPortField(r, dir, path, fqdn)
		case 2:
			// Deliberately gated on isDirect alone, NOT isDirect && isFreeIPA:
			// checkIEPDirectTLSSink requires tls.sink to already be fully
			// populated the moment tls.mode flips to freeipa on a direct
			// route, so sink must be reachable and fillable *before* mode is
			// freeipa — gating this on isFreeIPA too would make the two
			// requirements mutually impossible to satisfy (spec.md §22).
			if !isDirect {
				return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "⚠️  sink 只適用於 route.mode=direct")
			}
			return pushInternalEndpointTLSSinkCertFile(r, dir, path, fqdn)
		case 3:
			return pushInternalEndpointDetail(r, dir, path, fqdn, "")
		}
		return nil
	})
}

func pushInternalEndpointTLSModeField(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	title := "tls.mode（freeipa 需要 route owner host 已有 live FreeIPA enrollment，套用時才會檢查 — spec.md §16）"
	return r.transitionTo(newSelectModelWithScreenID("iep.tls.field_mode", title, iepTLSModeChoices), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		value := iepTLSModeChoices[m.Selected()]
		banner, err := iepApplyEdit(dir, path, fqdn, func(f map[string]any) {
			if value == "disabled" {
				f["tls"] = map[string]any{"mode": "disabled"}
				return
			}
			// Carry over any port/sink already entered, regardless of the
			// previous mode: sink in particular can only ever be filled in
			// while mode is still "disabled" (checkIEPDirectTLSSink
			// requires it complete the instant mode becomes "freeipa", so
			// the TUI lets it be prepared beforehand — see
			// pushInternalEndpointTLSMenu's case 2 doc comment). Dropping
			// it here would make that preparation pointless.
			tls := map[string]any{"mode": "freeipa"}
			if existing := iepMapField(f, "tls"); existing != nil {
				if port, ok := existing["port"]; ok {
					tls["port"] = port
				}
				if sink, ok := existing["sink"]; ok {
					tls["sink"] = sink
				}
			}
			f["tls"] = tls
		})
		if err != nil {
			r.err = err
			return nil
		}
		return pushInternalEndpointTLSMenu(r, dir, path, fqdn, banner)
	})
}

func pushInternalEndpointTLSPortField(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushInternalEndpointsMenu(r, dir, path, fmt.Sprintf("⚠️  endpoint %q 已不存在", fqdn))
	}
	def := iepIntValue(iepMapField(fields, "tls"), "port")
	label := "tls.port(留空使用 scheme 預設 443)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.field_port", label, def, iepOptionalPort), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		portText := strings.TrimSpace(m.Value())
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
			tls := cloneIEPFields(iepMapField(f, "tls"))
			if portText == "" {
				delete(tls, "port")
			} else if n, err := strconv.Atoi(portText); err == nil {
				tls["port"] = n
			}
			f["tls"] = tls
		})
	})
}

// ---- tls.sink (direct + freeipa only, spec.md §22) -----------------------

func pushInternalEndpointTLSSinkCertFile(r *editRouterModel, dir, path, fqdn string) tea.Cmd {
	fields, _, _ := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	sink := iepMapField(iepMapField(fields, "tls"), "sink")
	label := "tls.sink.cert_file(絕對路徑)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.cert_file", label, iepStringValue(sink, "cert_file"), iepAbsolutePath), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointTLSSinkKeyFile(r, dir, path, fqdn, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointTLSSinkKeyFile(r *editRouterModel, dir, path, fqdn, certFile string) tea.Cmd {
	fields, _, _ := inventory.InternalEndpointManifestEndpoint(path, fqdn)
	sink := iepMapField(iepMapField(fields, "tls"), "sink")
	label := "tls.sink.key_file(絕對路徑，不可與 cert_file 相同)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.key_file", label, iepStringValue(sink, "key_file"), iepAbsolutePath), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointTLSSinkKeyOwner(r, dir, path, fqdn, certFile, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointTLSSinkKeyOwner(r *editRouterModel, dir, path, fqdn, certFile, keyFile string) tea.Cmd {
	label := "tls.sink.key_owner(預設 root)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.key_owner", label, "root", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointTLSSinkKeyGroup(r, dir, path, fqdn, certFile, keyFile, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointTLSSinkKeyGroup(r *editRouterModel, dir, path, fqdn, certFile, keyFile, keyOwner string) tea.Cmd {
	label := "tls.sink.key_group(預設 root)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.key_group", label, "root", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointTLSSinkKeyMode(r, dir, path, fqdn, certFile, keyFile, keyOwner, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointTLSSinkKeyMode(r *editRouterModel, dir, path, fqdn, certFile, keyFile, keyOwner, keyGroup string) tea.Cmd {
	label := "tls.sink.key_mode(預設 0600)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.key_mode", label, "0600", iepOctalMode), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		return pushInternalEndpointTLSSinkReloadUnit(r, dir, path, fqdn, certFile, keyFile, keyOwner, keyGroup, strings.TrimSpace(m.Value()))
	})
}

func pushInternalEndpointTLSSinkReloadUnit(r *editRouterModel, dir, path, fqdn, certFile, keyFile, keyOwner, keyGroup, keyMode string) tea.Cmd {
	label := "tls.sink.reload.unit(systemd unit 名稱，例如 myapp.service；v1 只支援 systemd，spec.md §23)"
	return r.transitionTo(newTextInputModelWithScreenID("iep.tls.sink.reload_unit", label, "", iepSystemdUnitName), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushInternalEndpointTLSMenu(r, dir, path, fqdn, "")
		}
		reloadUnit := strings.TrimSpace(m.Value())
		return pushInternalEndpointEditDetail(r, dir, path, fqdn, func(f map[string]any) {
			tls := cloneIEPFields(iepMapField(f, "tls"))
			tls["sink"] = map[string]any{
				"cert_file": certFile,
				"key_file":  keyFile,
				"key_owner": keyOwner,
				"key_group": keyGroup,
				"key_mode":  keyMode,
				"reload":    map[string]any{"mode": "systemd", "unit": reloadUnit},
			}
			f["tls"] = tls
		})
	})
}

// ---- normalized preview ---------------------------------------------------

func pushInternalEndpointManifestPreview(r *editRouterModel, dir, path, banner string) tea.Cmd {
	root, err := inventory.LoadInternalEndpointManifest(path)
	if err != nil {
		r.err = err
		return nil
	}
	hostvars, err := loadIEPHostvars(dir)
	if err != nil {
		r.err = err
		return nil
	}
	opts := internalEndpointValidateOptsFor(dir)
	if violations := inventory.ValidateInternalEndpointManifest(root, opts); len(violations) > 0 {
		return pushInternalEndpointManifestManager(r, dir, path, formatIEPViolations(violations))
	}
	text := formatIEPPreview(inventory.NormalizeInternalEndpointManifest(root, hostvars))
	if banner != "" {
		text = banner + "\n\n" + text
	}
	return pushInternalEndpointManifestManager(r, dir, path, text)
}

func formatIEPPreview(m inventory.NormalizedInternalEndpointManifest) string {
	if len(m.Endpoints) == 0 {
		return "📋 目前沒有任何 endpoint。"
	}
	lines := []string{"📋 Normalized preview（套用後的最終 desired state）："}
	for _, e := range m.Endpoints {
		lines = append(lines, fmt.Sprintf("  %s state=%s route=%s tls=%s",
			e.FQDN, e.State, e.RouteMode, e.TLSMode))
		lines = append(lines, fmt.Sprintf("    dns: %s.%s %s -> %s (ttl=%d)",
			e.DNSOwner, e.DNSZone, e.DNSRecordType, e.DNSValue, e.TTL))
		if e.RouteMode == "reverse_proxy" {
			lines = append(lines, fmt.Sprintf("    upstream: %s://%s:%d verify=%v",
				e.UpstreamScheme, e.UpstreamIP, e.UpstreamPort, e.UpstreamTLSVerify))
		}
		if e.TLSMode == "freeipa" {
			lines = append(lines, fmt.Sprintf("    cert: owner=%s principal=%s", e.CertificateOwner, e.ServicePrincipal))
		}
	}
	return strings.Join(lines, "\n")
}

// ---- shared helpers ---------------------------------------------------------

func formatIEPViolations(violations []inventory.InternalEndpointViolation) string {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, fmt.Sprintf("⚠️  驗證沒過，尚未寫入(%d 項)：", len(violations)))
	for _, v := range violations {
		lines = append(lines, "  - "+v.String())
	}
	return strings.Join(lines, "\n")
}

// loadIEPHostvars mirrors loadDNSHostvars — independent of the manifest
// file itself, since route.target/proxy/upstream inventory_host references
// resolve against the deployment's real inventory.
func loadIEPHostvars(dir string) (map[string]map[string]any, error) {
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

// loadIEPReverseProxyHosts reads hosts.yml for which hosts carry the
// reverse-proxy role (spec.md §6.2) — needed to enforce
// route.proxy.inventory_host actually runs nginx.
func loadIEPReverseProxyHosts(dir string) (map[string]bool, error) {
	hf, err := loadHostsFileForDNS(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, h := range hf.Hosts {
		for _, role := range h.Roles {
			if role == "reverse-proxy" {
				out[h.Name] = true
				break
			}
		}
	}
	return out, nil
}

// internalEndpointValidateOptsFor supplies the static, offline-derivable
// facts ValidateInternalEndpointManifest needs (Hostvars,
// ReverseProxyHosts). EnrolledHosts/FreeIPADNSZones/LedgerFQDNs/
// PreviousRoutes are deliberately left nil — those are live-state/
// cross-manifest facts this offline wizard has no business asserting;
// internal/inventory's own gates treat a nil map as "skip this check"
// (same posture as edit_tui_dns.go's dnsValidateOptsFor leaving
// ShadowedZones nil for split-horizon detection). Those gates are
// exercised for real at apply time (playbooks/apply/internal-endpoint-apply.yml).
func internalEndpointValidateOptsFor(dir string) inventory.InternalEndpointValidateOptions {
	hostvars, _ := loadIEPHostvars(dir)
	reverseProxyHosts, _ := loadIEPReverseProxyHosts(dir)
	return inventory.InternalEndpointValidateOptions{
		Hostvars:          hostvars,
		ReverseProxyHosts: reverseProxyHosts,
	}
}

// iepMapField is internal/inventory's own unexported mapField, duplicated
// here since the cmd package can't import an unexported helper from
// another package — needed to drill into internal-endpoint's nested
// sub-objects (dns/route/tls/sink), which DNS's own edit_tui_dns.go never
// needed since freeipa-dns zone/record fields are all flat.
func iepMapField(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]any)
	return v
}

func cloneIEPFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}

func iepStringOr(fields map[string]any, key, def string) string {
	if s, ok := fields[key].(string); ok && s != "" {
		return s
	}
	return def
}

func iepStringValue(fields map[string]any, key string) string {
	s, _ := fields[key].(string)
	return s
}

func iepIntValue(fields map[string]any, key string) string {
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

func iepIntDisplay(fields map[string]any, key, def string) string {
	if v := iepIntValue(fields, key); v != "" {
		return v
	}
	return def
}

func iepRouteSummary(route map[string]any) string {
	mode := iepStringOr(route, "mode", "(未設定)")
	switch mode {
	case "direct":
		target := iepMapField(route, "target")
		if h := iepStringValue(target, "inventory_host"); h != "" {
			return fmt.Sprintf("direct -> %s", h)
		}
		return fmt.Sprintf("direct -> %s", iepStringValue(target, "address"))
	case "reverse_proxy":
		proxy := iepMapField(route, "proxy")
		upstream := iepMapField(route, "upstream")
		upstreamHost := iepStringValue(upstream, "inventory_host")
		if upstreamHost == "" {
			upstreamHost = iepStringValue(upstream, "address")
		}
		return fmt.Sprintf("reverse_proxy via %s -> %s://%s:%s",
			iepStringValue(proxy, "inventory_host"), iepStringOr(upstream, "scheme", "?"), upstreamHost, iepIntDisplay(upstream, "port", "?"))
	}
	return mode
}

func iepTLSSummary(tls map[string]any) string {
	mode := iepStringOr(tls, "mode", "disabled")
	if mode != "freeipa" {
		return mode
	}
	return fmt.Sprintf("freeipa port=%s", iepIntDisplay(tls, "port", "(預設 443)"))
}

func iepOptionalInt(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := strconv.Atoi(strings.TrimSpace(value)); err != nil {
		return fmt.Errorf("必須是整數")
	}
	return nil
}

func iepValidPort(value string) error {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("必須是 1..65535 之間的整數")
	}
	return nil
}

func iepOptionalPort(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return iepValidPort(value)
}

func iepAbsolutePath(value string) error {
	if !strings.HasPrefix(strings.TrimSpace(value), "/") {
		return fmt.Errorf("必須是絕對路徑")
	}
	return nil
}

func iepOctalMode(value string) error {
	v := strings.TrimSpace(value)
	if len(v) < 3 || len(v) > 4 {
		return fmt.Errorf("必須是 3-4 位數的 octal mode，例如 0600")
	}
	for _, r := range v {
		if r < '0' || r > '7' {
			return fmt.Errorf("必須是 3-4 位數的 octal mode，例如 0600")
		}
	}
	return nil
}

func iepSystemdUnitName(value string) error {
	v := strings.TrimSpace(value)
	if v == "" || !strings.Contains(v, ".") {
		return fmt.Errorf("必須是 systemd unit 名稱，例如 myapp.service")
	}
	return nil
}
