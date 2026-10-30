package cmd

import (
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/accessgrants"
)

type identityDriftOutputItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

type identityDriftOutput struct {
	SchemaVersion int                       `json:"schema_version"`
	Complete      bool                      `json:"complete"`
	Covered       []string                  `json:"covered"`
	Uncovered     []string                  `json:"uncovered"`
	Items         []identityDriftOutputItem `json:"items"`
}

func identityDriftJSON(report accessgrants.DriftReport, objects bool) identityDriftOutput {
	v := identityDriftOutput{SchemaVersion: 1, Complete: false,
		Covered:   []string{"account_expiration", "auth_indicator", "compiled_rule_existence", "password_policy", "static_hbac_absence", "user_auth_type"},
		Uncovered: []string{"hbac_sudo_attachments", "hosts_hostgroups_netgroups", "password_actions"},
		Items:     []identityDriftOutputItem{}}
	if objects {
		v.Covered = append(v.Covered, "users_groups")
	} else {
		v.Uncovered = append(v.Uncovered, "users_groups")
	}
	sort.Strings(v.Covered)
	sort.Strings(v.Uncovered)
	for _, item := range report.Items {
		v.Items = append(v.Items, identityDriftOutputItem{item.Category, item.Name, driftItemAction(item), item.Detail})
	}
	sort.Slice(v.Items, func(i, j int) bool {
		a, b := v.Items[i], v.Items[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Detail < b.Detail
	})
	return v
}

func driftItemAction(item accessgrants.DriftItem) string {
	if item.Action != "" {
		return item.Action
	}
	if strings.HasSuffix(item.Category, "_orphan") || strings.HasSuffix(item.Category, "_should_be_absent") {
		return "delete"
	}
	if strings.HasSuffix(item.Category, "_missing") {
		return "create"
	}
	return "update"
}

type identityDriftExit struct{ code int }

func (e identityDriftExit) Error() string { return "identity drift CI status (see report)" }
func (e identityDriftExit) ExitCode() int { return e.code }

func identityDriftStatus(report accessgrants.DriftReport) error {
	for _, item := range report.Items {
		if driftItemAction(item) != "report" {
			return identityDriftExit{2}
		}
	}
	// Coverage is intentionally incomplete until all staged vm-target gates pass.
	return identityDriftExit{3}
}
