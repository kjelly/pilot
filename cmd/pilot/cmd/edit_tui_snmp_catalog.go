// edit_tui_snmp_catalog.go implements the SNMP catalog screens of the
// `pilot edit` router: modules and auth profiles for
// monitoring/snmp/catalog.yml (docs/verification/snmp-exporter.md,
// contracts/snmp-exporter.yaml). This is the version-controlled,
// secret-free half of SNMP configuration — the actual credential values
// (credentialRef -> username/authPassword/privPassword or community) live
// in a vault file and are edited from edit_tui_snmp_credentials.go instead,
// same split as the on-disk files themselves (spec §6.4 rule 3: the
// catalog must never contain a secret-like key).
//
// Every mutation follows the same load -> mutate in memory -> Validate ->
// (save | show violation, don't save) discipline as
// edit_tui_monitoring.go's saveMonitoringTargets/saveMonitoringProfiles.
package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/tui"
)

func loadSNMPCatalogOrBanner(r *editRouterModel, dir string) (monitoring.SNMPCatalog, bool) {
	c, err := monitoring.LoadSNMPCatalog(monitoringSNMPCatalogPath(dir))
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", monitoringSNMPCatalogPath(dir), err)
		return monitoring.SNMPCatalog{}, false
	}
	return c, true
}

// saveSNMPCatalogOrBanner validates c before writing it, returning the
// banner to show on whatever screen the caller falls back to when
// validation fails — the catalog on disk is left untouched in that case.
func saveSNMPCatalogOrBanner(dir string, c monitoring.SNMPCatalog) (banner string, ok bool) {
	if err := c.Validate(); err != nil {
		return fmt.Sprintf("⚠️  驗證失敗，未存檔：%v", err), false
	}
	if err := monitoring.SaveSNMPCatalog(monitoringSNMPCatalogPath(dir), c); err != nil {
		return fmt.Sprintf("⚠️  存檔失敗：%v", err), false
	}
	return fmt.Sprintf("✅ 已存檔 %s", monitoringSNMPCatalogPath(dir)), true
}

// ---- top menu -------------------------------------------------------------

func pushSNMPCatalogMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "mon.snmp.catalog.modules", Label: "🧩 Modules(OID mapping 檔案，由官方 generator 產出)"},
		{ID: "mon.snmp.catalog.authprofiles", Label: "🔐 Auth Profiles(SNMP 版本/security level/credentialRef)"},
		{ID: "mon.snmp.catalog.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.catalog", Title: fmt.Sprintf("SNMP Catalog — %s", monitoringSNMPCatalogPath(dir)), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringManager(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushSNMPModulesMenu(r, dir, "")
		case 1:
			return pushSNMPAuthProfilesMenu(r, dir, "")
		default:
			return pushMonitoringManager(r, dir, "")
		}
	})
}

// pushSNMPBootstrapConfirm creates the standard non-secret if_mib baseline
// from assets embedded in the pilot binary. Existing workspace files are
// preserved; a conflicting if_mib declaration fails closed rather than being
// silently replaced.
func pushSNMPBootstrapConfirm(r *editRouterModel, dir string) tea.Cmd {
	catalogPath := monitoringSNMPCatalogPath(dir)
	modulePath := filepath.Join(dir, "monitoring", "snmp", "generated", "if_mib.yml")
	question := fmt.Sprintf(
		"建立標準 SNMP 基線？\n%s\n%s\n只建立缺少檔案；不會覆寫既有 catalog/module，也不會建立認證。",
		catalogPath, modulePath,
	)
	spec := tui.ConfirmSpec{ScreenID: "mon.snmp.bootstrap.confirm", Title: question, Default: true}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushMonitoringManager(r, dir, "已取消建立標準 SNMP 基線。")
		}
		result, err := monitoring.BootstrapSNMPBaseline(dir)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  建立 SNMP 基線失敗：%v", err))
		}
		if !result.CatalogCreated && !result.CatalogUpdated && !result.IFMIBCreated {
			return pushMonitoringManager(r, dir, "✅ 標準 SNMP 基線已存在，未覆寫任何檔案。")
		}
		return pushMonitoringManager(r, dir, "✅ 已建立/補齊標準 SNMP 基線：catalog.yml + generated/if_mib.yml。")
	})
}

// ---- modules ----------------------------------------------------------

func pushSNMPModulesMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(c.Modules))
	for id := range c.Modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	choices := make([]tui.Choice, 0, len(ids)+2)
	for _, id := range ids {
		choices = append(choices, tui.Choice{ID: id, Label: fmt.Sprintf("🧩 %s → %s", id, c.Modules[id].File)})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.snmp.module.add", Label: "➕ 新增 module"},
		tui.Choice{ID: "mon.snmp.module.back", Label: "↩  返回"},
	)

	spec := tui.SelectSpec{ScreenID: "mon.snmp.module.list", Title: "SNMP Modules", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPCatalogMenu(r, dir, "")
		}
		switch {
		case m.Selected() < len(ids):
			return pushSNMPModuleDetail(r, dir, ids[m.Selected()], "")
		case m.Selected() == len(ids):
			return pushSNMPModuleAddID(r, dir)
		default:
			return pushSNMPCatalogMenu(r, dir, "")
		}
	})
}

func pushSNMPModuleAddID(r *editRouterModel, dir string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if !monitoring.ValidSNMPCatalogName(s) {
			return fmt.Errorf("名稱只能是小寫英數字/連字號/底線，且以英數字開頭")
		}
		if _, exists := c.Modules[s]; exists {
			return fmt.Errorf("module %q 已存在", s)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.module.add.id", Title: "新 module ID(例如 if_mib)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPModulesMenu(r, dir, "")
		}
		return pushSNMPModuleAddFile(r, dir, strings.TrimSpace(m.Value()))
	})
}

func pushSNMPModuleAddFile(r *editRouterModel, dir, id string) tea.Cmd {
	validate := func(s string) error {
		return monitoring.ValidateSNMPModuleFilePath(strings.TrimSpace(s))
	}
	title := fmt.Sprintf("module %q 的檔案路徑(相對於 monitoring/snmp/，例如 generated/if_mib.yml)", id)
	spec := tui.InputSpec{ScreenID: "mon.snmp.module.add.file", Title: title, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPModuleAddID(r, dir)
		}
		c, ok := loadSNMPCatalogOrBanner(r, dir)
		if !ok {
			return nil
		}
		if c.Modules == nil {
			c.Modules = map[string]monitoring.SNMPModule{}
		}
		c.Modules[id] = monitoring.SNMPModule{File: strings.TrimSpace(m.Value())}
		banner, _ := saveSNMPCatalogOrBanner(dir, c)
		return pushSNMPModulesMenu(r, dir, banner)
	})
}

func pushSNMPModuleDetail(r *editRouterModel, dir, id, banner string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	module, exists := c.Modules[id]
	if !exists {
		return pushSNMPModulesMenu(r, dir, "")
	}
	title := fmt.Sprintf("module %q → %s", id, module.File)
	choices := []tui.Choice{
		{ID: "mon.snmp.module.detail.file", Label: "修改檔案路徑"},
		{ID: "mon.snmp.module.detail.delete", Label: "🗑  刪除"},
		{ID: "mon.snmp.module.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.module.detail", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPModulesMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushSNMPModuleEditFile(r, dir, id)
		case 1:
			return pushSNMPModuleConfirmDelete(r, dir, id)
		default:
			return pushSNMPModulesMenu(r, dir, "")
		}
	})
}

func pushSNMPModuleEditFile(r *editRouterModel, dir, id string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	validate := func(s string) error {
		return monitoring.ValidateSNMPModuleFilePath(strings.TrimSpace(s))
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.module.edit.file", Title: fmt.Sprintf("module %q 的新檔案路徑", id), Default: c.Modules[id].File, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPModuleDetail(r, dir, id, "")
		}
		c, ok := loadSNMPCatalogOrBanner(r, dir)
		if !ok {
			return nil
		}
		module := c.Modules[id]
		module.File = strings.TrimSpace(m.Value())
		c.Modules[id] = module
		banner, _ := saveSNMPCatalogOrBanner(dir, c)
		return pushSNMPModuleDetail(r, dir, id, banner)
	})
}

func pushSNMPModuleConfirmDelete(r *editRouterModel, dir, id string) tea.Cmd {
	spec := tui.ConfirmSpec{ScreenID: "mon.snmp.module.delete.confirm", Title: fmt.Sprintf("確定刪除 module %q？", id), Default: false}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushSNMPModuleDetail(r, dir, id, "")
		}
		c, ok := loadSNMPCatalogOrBanner(r, dir)
		if !ok {
			return nil
		}
		delete(c.Modules, id)
		banner, _ := saveSNMPCatalogOrBanner(dir, c)
		return pushSNMPModulesMenu(r, dir, banner)
	})
}

// ---- auth profiles ------------------------------------------------------

func pushSNMPAuthProfilesMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(c.AuthProfiles))
	for id := range c.AuthProfiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	choices := make([]tui.Choice, 0, len(ids)+2)
	for _, id := range ids {
		a := c.AuthProfiles[id]
		choices = append(choices, tui.Choice{ID: id, Label: fmt.Sprintf("🔐 %s (v%d/%s, credentialRef=%s)", id, a.Version, a.SecurityLevel, a.CredentialRef)})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.snmp.auth.add", Label: "➕ 新增 auth profile"},
		tui.Choice{ID: "mon.snmp.auth.back", Label: "↩  返回"},
	)

	spec := tui.SelectSpec{ScreenID: "mon.snmp.auth.list", Title: "SNMP Auth Profiles", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPCatalogMenu(r, dir, "")
		}
		switch {
		case m.Selected() < len(ids):
			return pushSNMPAuthProfileDetail(r, dir, ids[m.Selected()], "")
		case m.Selected() == len(ids):
			return pushSNMPAuthProfileAddID(r, dir)
		default:
			return pushSNMPCatalogMenu(r, dir, "")
		}
	})
}

func pushSNMPAuthProfileAddID(r *editRouterModel, dir string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if !monitoring.ValidSNMPCatalogName(s) {
			return fmt.Errorf("名稱只能是小寫英數字/連字號/底線，且以英數字開頭")
		}
		if _, exists := c.AuthProfiles[s]; exists {
			return fmt.Errorf("authProfile %q 已存在", s)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.auth.add.id", Title: "新 auth profile ID(例如 core-switch-v3)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPAuthProfilesMenu(r, dir, "")
		}
		return pushSNMPAuthProfileAddVersion(r, dir, strings.TrimSpace(m.Value()))
	})
}

// snmpAuthVersionChoices are the SNMP protocol versions snmp_exporter
// understands. "2" means v2c — the catalog field is a bare int (spec
// §6.4), so the label spells out the "c" that the stored value doesn't.
var snmpAuthVersionChoices = []struct {
	label   string
	version int
}{
	{"SNMPv3(建議：搭配 authPriv)", 3},
	{"SNMPv2c", 2},
	{"SNMPv1", 1},
}

func pushSNMPAuthProfileAddVersion(r *editRouterModel, dir, id string) tea.Cmd {
	choices := make([]tui.Choice, len(snmpAuthVersionChoices))
	for i, v := range snmpAuthVersionChoices {
		choices[i] = tui.Choice{ID: fmt.Sprintf("%d", v.version), Label: v.label}
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.auth.add.version", Title: fmt.Sprintf("authProfile %q 的 SNMP 版本", id), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPAuthProfileAddID(r, dir)
		}
		return pushSNMPAuthProfileAddSecurityLevel(r, dir, id, snmpAuthVersionChoices[m.Selected()].version)
	})
}

func pushSNMPAuthProfileAddSecurityLevel(r *editRouterModel, dir, id string, version int) tea.Cmd {
	levels := monitoring.SNMPAuthSecurityLevels()
	choices := make([]tui.Choice, len(levels))
	for i, lvl := range levels {
		choices[i] = tui.Choice{ID: lvl, Label: lvl}
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.auth.add.securitylevel", Title: fmt.Sprintf("authProfile %q 的 securityLevel(prod 只接受 authPriv，除非有 exception)", id), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPAuthProfileAddVersion(r, dir, id)
		}
		level := levels[m.Selected()]
		if version == 3 {
			return pushSNMPAuthProfileAddProtocol(r, dir, id, version, level, "SHA-256", "authProtocol(例如 SHA-256、MD5)")
		}
		return pushSNMPAuthProfileAddCredentialRef(r, dir, id, monitoring.SNMPAuthProfile{Version: version, SecurityLevel: level})
	})
}

// pushSNMPAuthProfileAddProtocol prompts authProtocol then privProtocol for
// a v3 profile — snmp_exporter's own protocol names aren't validated by
// this package's Validate() (spec §6.4 leaves that to the exporter itself),
// so this is free text with a sane default, not a fixed choice list.
func pushSNMPAuthProfileAddProtocol(r *editRouterModel, dir, id string, version int, level, defaultValue, title string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "mon.snmp.auth.add.authprotocol", Title: fmt.Sprintf("authProfile %q %s", id, title), Default: defaultValue}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPAuthProfileAddSecurityLevel(r, dir, id, version)
		}
		authProtocol := strings.TrimSpace(m.Value())
		return pushSNMPAuthProfileAddPrivProtocol(r, dir, id, version, level, authProtocol)
	})
}

func pushSNMPAuthProfileAddPrivProtocol(r *editRouterModel, dir, id string, version int, level, authProtocol string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "mon.snmp.auth.add.privprotocol", Title: fmt.Sprintf("authProfile %q privProtocol(例如 AES、DES)", id), Default: "AES"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPAuthProfileAddProtocol(r, dir, id, version, level, authProtocol, "authProtocol(例如 SHA-256、MD5)")
		}
		privProtocol := strings.TrimSpace(m.Value())
		return pushSNMPAuthProfileAddCredentialRef(r, dir, id, monitoring.SNMPAuthProfile{
			Version: version, SecurityLevel: level, AuthProtocol: authProtocol, PrivProtocol: privProtocol,
		})
	})
}

func pushSNMPAuthProfileAddCredentialRef(r *editRouterModel, dir, id string, partial monitoring.SNMPAuthProfile) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	hint := "credentialRef — 之後要到「SNMP 認證(vault)」用同一個名字建立密碼；不是密碼本身"
	spec := tui.InputSpec{ScreenID: "mon.snmp.auth.add.credentialref", Title: hint, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPAuthProfilesMenu(r, dir, "")
		}
		partial.CredentialRef = strings.TrimSpace(m.Value())
		return commitSNMPAuthProfileAdd(r, dir, id, partial)
	})
}

func commitSNMPAuthProfileAdd(r *editRouterModel, dir, id string, profile monitoring.SNMPAuthProfile) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	if c.AuthProfiles == nil {
		c.AuthProfiles = map[string]monitoring.SNMPAuthProfile{}
	}
	c.AuthProfiles[id] = profile
	banner, _ := saveSNMPCatalogOrBanner(dir, c)
	return pushSNMPAuthProfilesMenu(r, dir, banner)
}

func pushSNMPAuthProfileDetail(r *editRouterModel, dir, id, banner string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	a, exists := c.AuthProfiles[id]
	if !exists {
		return pushSNMPAuthProfilesMenu(r, dir, "")
	}
	title := fmt.Sprintf("authProfile %q: version=%d securityLevel=%s authProtocol=%s privProtocol=%s credentialRef=%s",
		id, a.Version, a.SecurityLevel, a.AuthProtocol, a.PrivProtocol, a.CredentialRef)
	choices := []tui.Choice{
		{ID: "mon.snmp.auth.detail.credentialref", Label: "修改 credentialRef"},
		{ID: "mon.snmp.auth.detail.delete", Label: "🗑  刪除"},
		{ID: "mon.snmp.auth.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.snmp.auth.detail", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushSNMPAuthProfilesMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushSNMPAuthProfileEditCredentialRef(r, dir, id)
		case 1:
			return pushSNMPAuthProfileConfirmDelete(r, dir, id)
		default:
			return pushSNMPAuthProfilesMenu(r, dir, "")
		}
	})
}

// pushSNMPAuthProfileEditCredentialRef only lets an existing profile's
// credentialRef change in place — version/securityLevel/protocols are
// security-relevant enough (spec §13.2's prod gate keys off exactly these
// fields) that changing them is deliberately "delete and re-add", not a
// quiet in-place edit.
func pushSNMPAuthProfileEditCredentialRef(r *editRouterModel, dir, id string) tea.Cmd {
	c, ok := loadSNMPCatalogOrBanner(r, dir)
	if !ok {
		return nil
	}
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.snmp.auth.edit.credentialref", Title: fmt.Sprintf("authProfile %q 的新 credentialRef", id), Default: c.AuthProfiles[id].CredentialRef, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushSNMPAuthProfileDetail(r, dir, id, "")
		}
		c, ok := loadSNMPCatalogOrBanner(r, dir)
		if !ok {
			return nil
		}
		a := c.AuthProfiles[id]
		a.CredentialRef = strings.TrimSpace(m.Value())
		c.AuthProfiles[id] = a
		banner, _ := saveSNMPCatalogOrBanner(dir, c)
		return pushSNMPAuthProfileDetail(r, dir, id, banner)
	})
}

func pushSNMPAuthProfileConfirmDelete(r *editRouterModel, dir, id string) tea.Cmd {
	spec := tui.ConfirmSpec{ScreenID: "mon.snmp.auth.delete.confirm", Title: fmt.Sprintf("確定刪除 authProfile %q？(不會刪除 vault 裡對應的 credentialRef)", id), Default: false}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushSNMPAuthProfileDetail(r, dir, id, "")
		}
		c, ok := loadSNMPCatalogOrBanner(r, dir)
		if !ok {
			return nil
		}
		delete(c.AuthProfiles, id)
		banner, _ := saveSNMPCatalogOrBanner(dir, c)
		return pushSNMPAuthProfilesMenu(r, dir, banner)
	})
}
