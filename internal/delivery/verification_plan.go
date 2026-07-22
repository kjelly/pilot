package delivery

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/spec"
)

// VerificationPlan is the exact v2 acceptance scope for one selected
// component/spec pair. Rows are resolved before any deployment mutation.
type VerificationPlan struct {
	Component string
	Role      string
	SpecPath  string
	Rows      []spec.Row
}

// PlanVerification resolves contract row selectors for selected components.
// It accepts only autoDeploy contracts and Spec v2; ambiguity is an error,
// never an implicit full-spec verification fallback.
func PlanVerification(root string, catalog contract.Catalog, componentIDs []string) ([]VerificationPlan, error) {
	seenComponents := make(map[string]struct{}, len(componentIDs))
	plans := make([]VerificationPlan, 0)
	for _, id := range componentIDs {
		if _, seen := seenComponents[id]; seen {
			return nil, fmt.Errorf("duplicate selected component %q", id)
		}
		seenComponents[id] = struct{}{}
		component, ok := catalog.Component(id)
		if !ok {
			return nil, fmt.Errorf("selected component %q is not in the contract catalog", id)
		}
		if component.Verification.AutoDeploy == nil || !*component.Verification.AutoDeploy {
			return nil, fmt.Errorf("component %q does not permit auto-deploy verification", id)
		}
		for _, entry := range component.Specs {
			path := filepath.Join(root, entry.Path)
			parsed, err := spec.Parse(path)
			if err != nil {
				return nil, fmt.Errorf("component %q parse spec %s: %w", id, entry.Path, err)
			}
			if parsed.SchemaVersion != 2 {
				return nil, fmt.Errorf("component %q auto-deploy spec %s is not Spec v2", id, entry.Path)
			}
			rows, err := selectRows(parsed.Rows, entry.Rows)
			if err != nil {
				return nil, fmt.Errorf("component %q spec %s: %w", id, entry.Path, err)
			}
			plans = append(plans, VerificationPlan{Component: id, Role: component.Role, SpecPath: entry.Path, Rows: rows})
		}
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].Component == plans[j].Component {
			return plans[i].SpecPath < plans[j].SpecPath
		}
		return plans[i].Component < plans[j].Component
	})
	return plans, nil
}

func selectRows(rows []spec.Row, selector contract.RowSelector) ([]spec.Row, error) {
	modes := 0
	if selector.All {
		modes++
	}
	if len(selector.IDs) > 0 {
		modes++
	}
	if len(selector.Categories) > 0 {
		modes++
	}
	if modes != 1 {
		return nil, fmt.Errorf("row selector must set exactly one of all, ids, categories")
	}
	selected := make([]spec.Row, 0, len(rows))
	ids := make(map[string]struct{}, len(selector.IDs))
	for _, id := range selector.IDs {
		ids[id] = struct{}{}
	}
	categories := make(map[string]struct{}, len(selector.Categories))
	for _, category := range selector.Categories {
		categories[category] = struct{}{}
	}
	for _, row := range rows {
		if selector.All {
			selected = append(selected, row)
			continue
		}
		if _, ok := ids[row.ID]; ok {
			selected = append(selected, row)
			continue
		}
		if _, ok := categories[row.Category]; ok {
			selected = append(selected, row)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("row selector resolved no rows")
	}
	if len(ids) > 0 {
		resolved := make(map[string]struct{}, len(selected))
		for _, row := range selected {
			resolved[row.ID] = struct{}{}
		}
		for id := range ids {
			if _, ok := resolved[id]; !ok {
				return nil, fmt.Errorf("row id %q does not exist", id)
			}
		}
	}
	return selected, nil
}
