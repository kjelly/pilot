package cmd

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushAnnotationsMenu lists a host's descriptive metadata (spec.md §13.1) —
// a completely separate CRUD flow and screen-ID namespace from
// pushExtraVarsMenu, deliberately mirroring its shape (list -> add -> action
// -> edit/delete) so the two stay familiar to operate, while the underlying
// domain field (h.Annotations, not h.Extra) and validation (inventory.
// ValidateAnnotationKey/Value, not "anything goes") stay distinct.
func pushAnnotationsMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, banner string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	if h.Annotations == nil {
		h.Annotations = map[string]string{}
	}
	keys := sortedKeysOf(h.Annotations)
	choices := make([]tui.Choice, 0, len(keys)+2)
	for _, k := range keys {
		choices = append(choices, tui.Choice{ID: k, Label: fmt.Sprintf("%s = %s", k, h.Annotations[k])})
	}
	choices = append(choices,
		tui.Choice{ID: "hosts.annotations.add", Label: "➕ 新增註解"},
		tui.Choice{ID: "hosts.annotations.back", Label: "↩  返回"},
	)
	title := fmt.Sprintf("主機 %q 的註解 / 資產資訊 —— 只供人員／Portal／FreeIPA 查閱，不影響部署角色或權限；禁止存放 password、token、key 等秘密資料", name)
	spec := tui.SelectSpec{ScreenID: "hosts.annotations", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushHostMenu(r, dir, path, hf, name)
		}
		idx := m.Selected()
		switch {
		case idx == len(choices)-1:
			return pushHostMenu(r, dir, path, hf, name)
		case idx == len(choices)-2:
			return pushAddAnnotation(r, dir, path, hf, name)
		default:
			return pushAnnotationActionMenu(r, dir, path, hf, name, keys[idx])
		}
	})
}

func pushAddAnnotation(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if h != nil {
			if _, ok := h.Annotations[s]; ok {
				return fmt.Errorf("註解 %q 已存在，請從清單選它來修改", s)
			}
			if len(h.Annotations) >= inventory.MaxAnnotationsPerHost {
				return fmt.Errorf("已達每台主機最多 %d 筆註解上限", inventory.MaxAnnotationsPerHost)
			}
		}
		return inventory.ValidateAnnotationKey(s)
	}
	return r.transitionTo(r.uiFactory().Input(tui.InputSpec{Title: "註解 key(僅小寫字母/數字/._-，例如 location、project、asset_tag)", Validate: validate}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAnnotationsMenu(r, dir, path, hf, name, "")
		}
		return pushAddAnnotationValue(r, dir, path, hf, name, strings.TrimSpace(m.Value()))
	})
}

func pushAddAnnotationValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	validate := func(s string) error {
		if err := inventory.ValidateAnnotationValue(s); err != nil {
			return err
		}
		_, err := inventory.SerializeAnnotation(key, s)
		return err
	}
	return r.transitionTo(r.uiFactory().Input(tui.InputSpec{Title: "註解值(禁止 password/token/key 等秘密資料)", Validate: validate}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAnnotationsMenu(r, dir, path, hf, name, "")
		}
		if h := findHost(hf, name); h != nil {
			if h.Annotations == nil {
				h.Annotations = map[string]string{}
			}
			h.Annotations[key] = m.Value()
		}
		return pushAnnotationsMenu(r, dir, path, hf, name, "")
	})
}

func pushAnnotationActionMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	h := findHost(hf, name)
	val := ""
	if h != nil {
		val = h.Annotations[key]
	}
	title := fmt.Sprintf("註解 %s = %s", key, val)
	choices := []tui.Choice{
		{ID: "hosts.annotation_action.edit", Label: "修改值"},
		{ID: "hosts.annotation_action.delete", Label: "刪除"},
		{ID: "hosts.annotation_action.back", Label: "返回"},
	}
	spec := tui.SelectSpec{ScreenID: "hosts.annotation_action", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushAnnotationsMenu(r, dir, path, hf, name, "")
		}
		switch m.Selected() {
		case 0:
			return pushEditAnnotationValue(r, dir, path, hf, name, key)
		case 1:
			if h := findHost(hf, name); h != nil {
				delete(h.Annotations, key)
			}
			return pushAnnotationsMenu(r, dir, path, hf, name, "")
		case 2:
			return pushAnnotationsMenu(r, dir, path, hf, name, "")
		}
		return nil
	})
}

func pushEditAnnotationValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	h := findHost(hf, name)
	cur := ""
	if h != nil {
		cur = h.Annotations[key]
	}
	label := fmt.Sprintf("%s 的新值", key)
	validate := func(s string) error {
		if err := inventory.ValidateAnnotationValue(s); err != nil {
			return err
		}
		_, err := inventory.SerializeAnnotation(key, s)
		return err
	}
	return r.transitionTo(r.uiFactory().Input(tui.InputSpec{Title: label, Default: cur, Validate: validate}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAnnotationActionMenu(r, dir, path, hf, name, key)
		}
		if h := findHost(hf, name); h != nil {
			h.Annotations[key] = m.Value()
		}
		return pushAnnotationsMenu(r, dir, path, hf, name, "")
	})
}
