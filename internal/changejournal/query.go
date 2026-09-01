package changejournal

// QueryRecentChanges merges QueryEditApplyChanges and QueryDeployChanges
// into one canonically-sorted, bounded list — pilot_diagnose_recent_
// changes' actual query path (Agent Monitoring Phase 2 §6). deployStore
// may be nil (no deploy history db available yet); auditDir may not
// exist (no edit-apply session has ever run) — both are handled as
// "this source has nothing", never a hard error, matching Phase 2 §9's
// "missing optional source returns partial evidence, not panic".
//
// host/component filter deploy-sourced records only (internal/store's
// own ListRuns filter) — edit-apply sessions carry no host/component
// scoping of their own (Agent Monitoring Phase 2 §6: MCP edit-apply is
// local-workspace-file mutation, not a host-targeted operation), so they
// are never excluded by a host/component filter.
func QueryRecentChanges(deployStore DeployRunSource, auditDir, host, component string, window TimeWindow, limit int) ([]ChangeRecord, error) {
	editApply, err := QueryEditApplyChanges(auditDir, window)
	if err != nil {
		return nil, err
	}

	var deploy []ChangeRecord
	if deployStore != nil {
		deploy, err = QueryDeployChanges(deployStore, host, component, window, limit)
		if err != nil {
			return nil, err
		}
	}

	merged := make([]ChangeRecord, 0, len(editApply)+len(deploy))
	merged = append(merged, editApply...)
	merged = append(merged, deploy...)
	sortByStartedAtDesc(merged)

	if limit > 0 && len(merged) > limit {
		merged = merged[:limit]
	}
	return merged, nil
}
