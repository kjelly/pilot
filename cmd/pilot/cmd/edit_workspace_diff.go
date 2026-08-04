// edit_workspace_diff.go produces a plan/apply's unified diff, limited
// to managed files — see the spec's "diff.patch" audit artifact
// section.
package cmd

import (
	"sort"

	"github.com/aymanbagabas/go-udiff"
)

// diffManagedFiles compares managedFileEntries(beforeDir) against
// managedFileEntries(afterDir) — see diffEntries for the comparison
// itself; this is just the two-directory convenience wrapper plan uses.
func diffManagedFiles(beforeDir, afterDir string) (patch string, affected []string, err error) {
	before, err := managedFileEntries(beforeDir)
	if err != nil {
		return "", nil, err
	}
	after, err := managedFileEntries(afterDir)
	if err != nil {
		return "", nil, err
	}
	patch, affected = diffEntries(before, after)
	return patch, affected, nil
}

// diffEntries returns a unified diff plus the sorted list of relative
// paths that actually changed between before and after. A path present
// on only one side diffs against empty content, so both a
// newly-created file (e.g. create_host making hosts.yml for the first
// time) and a removed one (e.g. restore_role_presets deleting
// role-presets.yml) are represented correctly. Apply's engine calls
// this directly with an in-memory before-snapshot (there's no second
// directory to diff against once a scenario has run for real);
// diffManagedFiles is the two-directory convenience wrapper plan uses.
func diffEntries(before, after []managedFileEntry) (patch string, affected []string) {
	beforeByPath := make(map[string][]byte, len(before))
	for _, e := range before {
		beforeByPath[e.RelPath] = e.Content
	}
	afterByPath := make(map[string][]byte, len(after))
	for _, e := range after {
		afterByPath[e.RelPath] = e.Content
	}

	paths := make(map[string]bool, len(before)+len(after))
	for path := range beforeByPath {
		paths[path] = true
	}
	for path := range afterByPath {
		paths[path] = true
	}
	sortedPaths := make([]string, 0, len(paths))
	for path := range paths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	var patchOut string
	for _, path := range sortedPaths {
		beforeContent, afterContent := string(beforeByPath[path]), string(afterByPath[path])
		if beforeContent == afterContent {
			continue
		}
		affected = append(affected, path)
		patchOut += udiff.Unified("a/"+path, "b/"+path, beforeContent, afterContent)
	}
	return patchOut, affected
}
