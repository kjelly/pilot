// edit_workspace_diff.go produces a plan/apply's unified diff, limited
// to managed files — see the spec's "diff.patch" audit artifact
// section.
package cmd

import (
	"sort"

	"github.com/aymanbagabas/go-udiff"
)

// diffManagedFiles compares managedFileEntries(beforeDir) against
// managedFileEntries(afterDir) and returns a unified diff plus the
// sorted list of relative paths that actually changed. A path present
// on only one side diffs against empty content, so both a
// newly-created file (e.g. create_host making hosts.yml for the first
// time) and a removed one (e.g. restore_role_presets deleting
// role-presets.yml) are represented correctly.
func diffManagedFiles(beforeDir, afterDir string) (patch string, affected []string, err error) {
	before, err := managedFileEntries(beforeDir)
	if err != nil {
		return "", nil, err
	}
	after, err := managedFileEntries(afterDir)
	if err != nil {
		return "", nil, err
	}

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
	return patchOut, affected, nil
}
