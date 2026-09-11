package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/tui"
	"github.com/kjelly/pilot/internal/vaultfile"
)

const (
	alertmanagerReceiverModeKey    = "alertmanager_receiver_mode"
	alertmanagerTeamsWebhookURLKey = "alertmanager_teams_webhook_url"
	alertmanagerCustomConfigKey    = "alertmanager_config"
	alertmanagerReceiverModeNull   = "null"
	alertmanagerReceiverModeTeams  = "teams"
	alertmanagerReceiverModeCustom = "custom"
)

func validateAlertmanagerReceiver(mode, value string) error {
	switch mode {
	case alertmanagerReceiverModeNull:
		if strings.TrimSpace(value) != "" {
			return fmt.Errorf("null receiver mode does not accept a value")
		}
		return nil
	case alertmanagerReceiverModeTeams:
		u, err := url.ParseRequestURI(strings.TrimSpace(value))
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("Teams webhook must be a valid HTTPS URL")
		}
		return nil
	case alertmanagerReceiverModeCustom:
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("custom receiver mode requires a complete Alertmanager configuration")
		}
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(value), &node); err != nil || len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
			return fmt.Errorf("custom receiver configuration must be a YAML mapping")
		}
		return nil
	default:
		return fmt.Errorf("receiver mode must be null, teams, or custom")
	}
}

func alertmanagerReceiverStatus(doc *vaultfile.Doc) string {
	mode := alertmanagerReceiverModeNull
	for _, entry := range doc.ScalarEntries() {
		if entry.Key == alertmanagerReceiverModeKey && strings.TrimSpace(entry.Value.Value) != "" {
			mode = strings.TrimSpace(entry.Value.Value)
			break
		}
	}
	if mode == alertmanagerReceiverModeNull && doc.HasKey(alertmanagerCustomConfigKey) {
		// Old workspaces used alertmanager_config without a mode. Keep that
		// established configuration active until an operator explicitly picks a
		// mode in this screen.
		mode = alertmanagerReceiverModeCustom + "（legacy）"
	}
	return mode
}

func saveAlertmanagerReceiver(dir, mode, value string) error {
	if err := validateAlertmanagerReceiver(mode, value); err != nil {
		return err
	}
	path := filepath.Join(dir, ".vault", "main.yaml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read Alertmanager vault: %w", err)
	}
	if os.IsNotExist(err) {
		data = []byte("---\n")
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		return fmt.Errorf("parse Alertmanager vault: %w", err)
	}
	if !doc.EditableWithPreservedNestedMappings(monitoring.SNMPCredentialsKey) {
		return fmt.Errorf("Alertmanager vault has unsupported nested YAML")
	}
	doc.Set(alertmanagerReceiverModeKey, mode)
	switch mode {
	case alertmanagerReceiverModeTeams:
		doc.Set(alertmanagerTeamsWebhookURLKey, strings.TrimSpace(value))
	case alertmanagerReceiverModeCustom:
		doc.Set(alertmanagerCustomConfigKey, value)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir Alertmanager vault: %w", err)
	}
	if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write Alertmanager vault: %w", err)
	}
	return nil
}

func pushAlertmanagerReceiverManager(r *editRouterModel, dir, banner string) tea.Cmd {
	path := filepath.Join(dir, ".vault", "main.yaml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return pushTopMenu(r, dir, fmt.Sprintf("⚠️  無法讀取 Alertmanager vault：%v", err))
	}
	if os.IsNotExist(err) {
		data = []byte("---\n")
	}
	doc, err := vaultfile.Parse(data)
	if err != nil || !doc.EditableWithPreservedNestedMappings(monitoring.SNMPCredentialsKey) {
		return pushTopMenu(r, dir, "⚠️  Alertmanager vault 必須是可編輯的 top-level scalar YAML。")
	}
	status := alertmanagerReceiverStatus(doc)
	choices := []tui.Choice{
		{ID: "alertmanager.receiver.teams", Label: "設定 Teams webhook（單一 receiver）"},
		{ID: "alertmanager.receiver.custom", Label: "設定 custom Alertmanager YAML"},
		{ID: "alertmanager.receiver.null", Label: "使用 null receiver（不送通知）"},
		{ID: "alertmanager.receiver.back", Label: "↩  返回"},
	}
	title := fmt.Sprintf("Alertmanager 通知 receiver（目前：%s）", status)
	return r.transitionTo(r.uiFactory().Select(tui.SelectSpec{ScreenID: "alertmanager.receiver", Title: title, Choices: choices}), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 3 {
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushAlertmanagerReceiverValue(r, dir, alertmanagerReceiverModeTeams)
		case 1:
			return pushAlertmanagerReceiverValue(r, dir, alertmanagerReceiverModeCustom)
		case 2:
			if err := saveAlertmanagerReceiver(dir, alertmanagerReceiverModeNull, ""); err != nil {
				return pushAlertmanagerReceiverManager(r, dir, fmt.Sprintf("⚠️  無法儲存：%v", err))
			}
			return pushAlertmanagerReceiverManager(r, dir, "✅ 已切換為 null receiver；既有 secret 會保留但不會生效。")
		}
		return nil
	})
}

func pushAlertmanagerReceiverValue(r *editRouterModel, dir, mode string) tea.Cmd {
	title := "Teams webhook URL（只接受 HTTPS；值會遮罩）"
	if mode == alertmanagerReceiverModeCustom {
		title = "完整 Alertmanager YAML（多行請直接輸入 \\n；值會遮罩）"
	}
	return r.transitionTo(r.uiFactory().Input(tui.InputSpec{ScreenID: "alertmanager.receiver.value", Title: title, Secret: true}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAlertmanagerReceiverManager(r, dir, "")
		}
		value := strings.ReplaceAll(m.Value(), `\n`, "\n")
		if err := saveAlertmanagerReceiver(dir, mode, value); err != nil {
			return pushAlertmanagerReceiverManager(r, dir, fmt.Sprintf("⚠️  無法儲存：%v", err))
		}
		return pushAlertmanagerReceiverManager(r, dir, "✅ Alertmanager receiver 已更新；請執行 pilot deploy 套用。")
	})
}
