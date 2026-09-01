package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// rosterHostChoices builds the choices for every roster field that stores a
// list of host FQDNs. hosts.yml is the workspace's source of managed hosts;
// its short inventory aliases are expanded with the roster's FreeIPA domain.
// Existing roster references are included as well because direct HBAC/grant
// targets are intentionally allowed to name an enrolled host that is not in
// this workspace's hosts.yml.
func rosterHostChoices(dir, path string, current []string) ([]tui.MultiSelectChoice, error) {
	seen := make(map[string]bool)
	var names []string
	add := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		names = append(names, host)
	}

	for _, host := range current {
		add(host)
	}

	// Keep all existing roster host references available when a different
	// relationship field is opened. This is important for a newly-created
	// hostgroup and for direct targets that are not represented in hosts.yml.
	hostgroups, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		return nil, err
	}
	for _, name := range hostgroups {
		fields, found, err := inventory.RosterHostgroup(path, name)
		if err != nil {
			return nil, err
		}
		if found {
			for _, host := range rosterStringSlice(rosterSubmap(fields, "membership"), "hosts") {
				add(host)
			}
		}
	}

	hbacRules, err := inventory.RosterHBACRuleNames(path)
	if err != nil {
		return nil, err
	}
	for _, name := range hbacRules {
		fields, found, err := inventory.RosterHBACRule(path, name)
		if err != nil {
			return nil, err
		}
		if found {
			for _, host := range rosterStringSlice(rosterSubmap(fields, "targets"), "hosts") {
				add(host)
			}
		}
	}

	grants, err := inventory.RosterGrantNames(path)
	if err != nil {
		return nil, err
	}
	for _, name := range grants {
		fields, found, err := inventory.RosterGrant(path, name)
		if err != nil {
			return nil, err
		}
		if found {
			for _, host := range rosterStringSlice(rosterSubmap(fields, "targets"), "hosts") {
				add(host)
			}
		}
	}

	domain, _ := inventory.RosterDomain(path)
	if strings.TrimSpace(domain) == "" {
		domain, _ = inventory.FreeIPADomain(dir)
	}
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read hosts.yml: %w", err)
	}
	if err == nil {
		hf, err := inventory.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parse hosts.yml: %w", err)
		}
		for _, host := range hf.Hosts {
			if inventory.ValidRosterHostFQDN(host.Name) {
				add(host.Name)
				continue
			}
			if strings.TrimSpace(domain) != "" {
				add(inventory.RosterHostFQDN(host.Name, strings.TrimSpace(domain)))
			}
		}
	}

	sort.Strings(names)
	choices := make([]tui.MultiSelectChoice, len(names))
	for i, name := range names {
		choices[i] = tui.MultiSelectChoice{
			Choice:  tui.Choice{ID: name, Label: name},
			Checked: hasRole(current, name),
		}
	}
	return choices, nil
}

func rosterHostChecklist(r *editRouterModel, dir, path, screenID, title string, current []string, next func(*editRouterModel, []string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	choices, err := rosterHostChoices(dir, path, current)
	if err != nil {
		r.err = err
		return nil
	}
	return checklistIDs(r, screenID, title, choices, next, cancel)
}
