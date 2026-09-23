package spec

// Regression lock: `delegate_to` is templated BEFORE the task's `when` is
// evaluated (ansible-core 2.19, verified on a real run), so a `when:
// groups.get('g', []) | length > 0` guard does not protect a delegate_to
// expression that can evaluate to `[] | first`. `pilot inventory generate`
// always emits every role group, empty ones as `hosts: {}`, so
// `groups.get('seaweedfs-s3', [inventory_hostname]) | first` hits the
// present-but-empty group (the default never applies) and fails with
// "No first item, sequence was empty." — found 2026-09-23 applying
// prometheus-apply.yml against a generated inventory with no seaweedfs-s3
// host. The safe form appends the fallback instead of defaulting to it:
// `(groups.get('g', []) + [inventory_hostname]) | first`.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var unsafeDelegateToGroupFirst = regexp.MustCompile(`delegate_to:.*groups(\.get\('[^']+',\s*\[[^\]]*\]\)|\[['"][^'"]+['"]\])\s*\|\s*first`)

func TestRegression_DelegateToNeverFirstOfPossiblyEmptyGroup(t *testing.T) {
	files, err := filepath.Glob("../../playbooks/apply/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob apply playbooks: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if unsafeDelegateToGroupFirst.MatchString(line) {
				t.Errorf("%s:%d: delegate_to takes `| first` of a group that may be present but empty (delegate_to is templated before `when`); use `(groups.get('<g>', []) + [inventory_hostname]) | first`:\n  %s",
					filepath.Base(f), i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestRegression_DelegateToEmptyGroupPatternCatchesTheOriginalBug(t *testing.T) {
	bad := `delegate_to: "{{ groups.get('seaweedfs-s3', [inventory_hostname]) | first }}"`
	good := `delegate_to: "{{ (groups.get('seaweedfs-s3', []) + [inventory_hostname]) | first }}"`
	if !unsafeDelegateToGroupFirst.MatchString(bad) {
		t.Error("lint must flag the original 2026-09-23 pattern")
	}
	if unsafeDelegateToGroupFirst.MatchString(good) {
		t.Error("lint must accept the appended-fallback form")
	}
}
