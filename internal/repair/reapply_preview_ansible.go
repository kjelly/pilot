package repair

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
)

// hasRecapLine reports whether stdout contains a PLAY RECAP block — a
// nonzero exit WITH a recap usually means "some hosts failed" (still a
// real preview for the others), while a nonzero exit with NO recap at
// all usually means the run never got that far (syntax error, bad
// connection) and produced no usable diff at all.
func hasRecapLine(stdout string) bool {
	return strings.Contains(stdout, "PLAY RECAP")
}

// previewSkippedRe matches the skipped= field in an ansible PLAY RECAP
// line, e.g. "host : ok=3 changed=0 unreachable=0 failed=0 skipped=8".
var previewSkippedRe = regexp.MustCompile(`skipped=(\d+)`)

// previewSkippedCount extracts the FIRST skipped= count found in
// stdout's PLAY RECAP block, or -1 if none is found.
//
// Found via a real check-mode run against a real component (2026-09-01,
// alertmanager on a disposable vm-target): its own canonical apply
// playbook gates the config-rendering/container tasks behind `when: not
// ansible_check_mode` (a legitimate, common pattern — those same tasks
// would otherwise fail on a genuinely fresh host with no parent
// directory yet). Under --check, ansible SKIPS them entirely rather than
// diffing, so a real, injected config drift produced `changed=0` with
// NO error — a preview that would have silently told a human approver
// "no changes" while real drift sat unfixed. Any nonzero skipped= count
// during a check-mode run means the diff is structurally incomplete, so
// runPreview treats it as unsupported rather than trustworthy zero
// changes — the same "do not silently treat check-mode failure as skip
// preview" principle (design doc §9) extended to a within-run skip, not
// just a hard failure.
func previewSkippedCount(stdout string) int {
	idx := strings.Index(stdout, "PLAY RECAP")
	if idx < 0 {
		return -1
	}
	m := previewSkippedRe.FindStringSubmatch(stdout[idx:])
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

type diffText struct {
	text    string
	changed int
}

// renderDiffSummary wraps internal/ansible's own `--check --diff`
// parser (already sanitizes sensitive paths and caps file bodies —
// design doc §9's "sanitized preview" requirement, reused rather than
// reimplemented) into the plain text+count shape BuildReapplyPlan hashes
// and displays.
func renderDiffSummary(stdout string) diffText {
	s := ansible.ParseDiff(stdout)
	return diffText{text: s.RenderMarkdown(), changed: s.FilesChanged}
}
