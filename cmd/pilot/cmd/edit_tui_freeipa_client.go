// edit_tui_freeipa_client.go implements the `pilot edit` Day-2 IP
// replacement acknowledgement UX for freeipa-client hosts
// (docs/superpowers/specs/2026-09-02-freeipa-client-host-dns-ip-replacement-spec.md
// §11). Changing a freeipa-client host's ansible_host between two IP
// literals is the one host-field edit that can silently reopen the
// authoritative-DNS "no implicit takeover" gate
// (playbooks/apply/tasks/freeipa-client-host-dns.yml) on the very next
// deploy, so it detours through an explicit confirm screen instead of
// pushHostFieldEdit's plain text input — every other host field keeps
// using pushHostFieldEdit unchanged.
package cmd

import (
	"fmt"
	"net"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// freeipaClientDNSReplaceFromKey is the contract var
// freeipa-client-host-dns.yml reads as the CAS "expected old address"
// acknowledgement (spec.md §4.1/§4.2). It lives in Host.Extra, the same
// scalar passthrough map every other unmodeled host var already uses —
// V1 deliberately does not give it a typed field (spec.md §11.3).
const freeipaClientDNSReplaceFromKey = "freeipa_client_dns_replace_from_address"

// freeipaClientRole is the role name that gates this confirmation
// (spec.md §11.1's "host roles 包含 freeipa-client").
const freeipaClientRole = "freeipa-client"

// isIPLiteral reports whether s parses as an IPv4 or IPv6 literal — the
// same "is this an address, not a hostname" test spec.md §11.1/§11.6
// requires on both the old and new ansible_host values before this
// flow may trigger at all.
func isIPLiteral(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// freeipaClientDNSReplaceCandidate reports whether changing h's
// ansible_host from oldValue to newValue is a Day-2 IP migration this
// flow should ask about: both sides are IP literals, they differ, and
// h carries the freeipa-client role (spec.md §11.1/§11.6). oldValue
// being empty (a first-time set) already fails isIPLiteral, so that
// case is excluded without a separate check.
func freeipaClientDNSReplaceCandidate(h *inventory.Host, oldValue, newValue string) bool {
	if h == nil || oldValue == newValue {
		return false
	}
	if !hasRole(h.Roles, freeipaClientRole) {
		return false
	}
	return isIPLiteral(oldValue) && isIPLiteral(newValue)
}

// pushAnsibleHostFieldEdit replaces pushHostFieldEdit for the
// ansible_host menu item only: it evaluates
// freeipaClientDNSReplaceCandidate on the submitted value before
// applying it, and detours through pushFreeipaClientDNSReplaceConfirm
// when the edit qualifies.
func pushAnsibleHostFieldEdit(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	current := ""
	if h := findHost(hf, name); h != nil {
		current = h.AnsibleHost
	}
	spec := tui.InputSpec{Title: "ansible_host(可路由的 IP 或主機名)", Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushHostMenu(r, dir, path, hf, name)
		}
		newValue := strings.TrimSpace(m.Value())
		h := findHost(hf, name)
		if h == nil {
			return pushHostMenu(r, dir, path, hf, name)
		}
		oldValue := h.AnsibleHost
		if freeipaClientDNSReplaceCandidate(h, oldValue, newValue) {
			return pushFreeipaClientDNSReplaceConfirm(r, dir, path, hf, name, oldValue, newValue)
		}
		h.AnsibleHost = newValue
		return pushHostMenu(r, dir, path, hf, name)
	})
}

// pushFreeipaClientDNSReplaceConfirm shows the explicit
// expected-old-address authorization prompt (spec.md §11.2's example
// wording) and applies its answer:
//
//   - Yes: ansible_host=newValue AND
//     Extra[freeipaClientDNSReplaceFromKey]=oldValue — overwriting any
//     acknowledgement left over from an earlier IP change (spec.md
//     §11.5: the CAS token must always name the immediately-previous
//     address, never an older one).
//   - No: ansible_host=newValue only; the acknowledgement key is left
//     exactly as it was (spec.md §11.4 — this screen never writes it,
//     and clearing an unrelated prior value is not part of "No").
func pushFreeipaClientDNSReplaceConfirm(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, oldValue, newValue string) tea.Cmd {
	question := fmt.Sprintf(
		"此主機啟用了 freeipa-client。\n"+
			"是否授權 Pilot 只在 authoritative DNS 目前的 stale 位址精確等於\n"+
			"%s 時，才將它替換為新位址？\n\n"+
			"主機：%s\n"+
			"連線 IP：%s -> %s\n"+
			"預期的 stale DNS：%s",
		oldValue, name, oldValue, newValue, oldValue,
	)
	spec := tui.ConfirmSpec{Title: question, Default: false}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if h := findHost(hf, name); h != nil {
			h.AnsibleHost = newValue
			if m.Value() {
				if h.Extra == nil {
					h.Extra = map[string]string{}
				}
				h.Extra[freeipaClientDNSReplaceFromKey] = oldValue
			}
		}
		return pushHostMenu(r, dir, path, hf, name)
	})
}
