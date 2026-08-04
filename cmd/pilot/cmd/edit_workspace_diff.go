// edit_workspace_diff.go produces a plan/apply's unified diff, limited
// to managed files — see the spec's "diff.patch" audit artifact
// section.
package cmd

import (
	"fmt"
	"sort"

	"github.com/aymanbagabas/go-udiff"
)

// diffManagedFiles compares managedFileEntries(beforeDir) against
// managedFileEntries(afterDir) — see diffEntries for the comparison
// itself; this is just the two-directory convenience wrapper plan uses.
func diffManagedFiles(beforeDir, afterDir string) (patch string, affected []string, redacted bool, err error) {
	before, err := managedFileEntries(beforeDir)
	if err != nil {
		return "", nil, false, err
	}
	after, err := managedFileEntries(afterDir)
	if err != nil {
		return "", nil, false, err
	}
	patch, affected, redacted = diffEntries(before, after)
	return patch, affected, redacted, nil
}

// diffEntries returns a unified diff, the sorted list of relative paths
// that actually changed, and whether any changed path was a secret
// file (managedFileEntry.IsSecret). A path present on only one side
// diffs against empty content, so both a newly-created file (e.g.
// create_host making hosts.yml for the first time) and a removed one
// (e.g. restore_role_presets deleting role-presets.yml) are
// represented correctly. A secret path never gets a real content diff
// — spec's "若受管理檔案可能含秘密，該檔案的 diff 必須省略 value" — its
// patch entry is a fixed placeholder instead, regardless of what the
// actual before/after content is. Apply's engine calls this directly
// with an in-memory before-snapshot (there's no second directory to
// diff against once a scenario has run for real); diffManagedFiles is
// the two-directory convenience wrapper plan uses.
func diffEntries(before, after []managedFileEntry) (patch string, affected []string, redacted bool) {
	type pathInfo struct {
		before, after []byte
		haveBefore    bool
		haveAfter     bool
		isSecret      bool
	}
	byPath := make(map[string]*pathInfo)
	get := func(path string) *pathInfo {
		info, ok := byPath[path]
		if !ok {
			info = &pathInfo{}
			byPath[path] = info
		}
		return info
	}
	for _, e := range before {
		info := get(e.RelPath)
		info.before, info.haveBefore = e.Content, true
		info.isSecret = info.isSecret || e.IsSecret
	}
	for _, e := range after {
		info := get(e.RelPath)
		info.after, info.haveAfter = e.Content, true
		info.isSecret = info.isSecret || e.IsSecret
	}

	sortedPaths := make([]string, 0, len(byPath))
	for path := range byPath {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	var patchOut string
	for _, path := range sortedPaths {
		info := byPath[path]
		beforeContent, afterContent := string(info.before), string(info.after)
		if beforeContent == afterContent {
			continue
		}
		affected = append(affected, path)
		if info.isSecret {
			redacted = true
			patchOut += fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ redacted: secret file changed @@\n", path, path)
			continue
		}
		patchOut += udiff.Unified("a/"+path, "b/"+path, beforeContent, afterContent)
	}
	return patchOut, affected, redacted
}
