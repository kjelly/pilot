package repair

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ReapplyResult taxonomy (design doc §11). "Do not claim rollback unless
// the component's real transaction restored previous state" — no
// component in this codebase has an explicit rollback contract wired up
// yet, so ReapplyExecute never returns APPLY_FAILED_ROLLED_BACK; it is
// declared here (matching the design doc's full result vocabulary
// verbatim, so a caller's switch statement is exhaustive against the
// SPEC's taxonomy, not just against what this version happens to emit)
// but is unreachable from this package until a future phase adds real
// rollback support for a specific, separately-evidenced component.
const (
	ReapplyPreviewBlocked            = "PREVIEW_BLOCKED"
	ReapplyPlanStale                 = "PLAN_STALE"
	ReapplyApplyFailedRolledBack     = "APPLY_FAILED_ROLLED_BACK" // unreachable in this phase — see doc comment above
	ReapplyApplyFailedPartial        = "APPLY_FAILED_PARTIAL"
	ReapplyAppliedVerified           = "APPLIED_VERIFIED"
	ReapplyAppliedVerificationFailed = "APPLIED_VERIFICATION_FAILED"
	ReapplyAppliedAlertStillFiring   = "APPLIED_ALERT_STILL_FIRING"
)

// ReapplyExecuteResult is the structured outcome of one canonical-apply
// run (design doc §20: "record true Ansible recap/changed count").
type ReapplyExecuteResult struct {
	Result   string // one of the Reapply* taxonomy constants above
	ExitCode int
	Changed  int // PLAY RECAP changed= count for the target host, -1 if unparseable
	Stdout   string
	Error    string
}

// reapplyRecapChangedRe matches one ansible PLAY RECAP host line and
// captures its changed count, e.g. "web-1 : ok=5 changed=1 ...".
// Mirrors cmd/pilot/cmd/vm_target.go's own recapChangedRe — internal/repair
// cannot import a cmd package, so this is a deliberate small duplicate
// of an already-proven regex, not a new invention.
var reapplyRecapChangedRe = regexp.MustCompile(`(?m)^(\S+)\s*:\s+ok=\d+\s+changed=(\d+)`)

// parseRecapChanged returns the changed= count for host from stdout's
// PLAY RECAP block, or -1 if no matching line was found (ambiguous —
// the caller must not assume 0 in that case).
func parseRecapChanged(stdout, host string) int {
	idx := strings.Index(stdout, "PLAY RECAP")
	if idx < 0 {
		return -1
	}
	recap := stdout[idx:]
	for _, m := range reapplyRecapChangedRe.FindAllStringSubmatch(recap, -1) {
		if m[1] != host {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			return -1
		}
		return n
	}
	return -1
}

// ReapplyExecute runs plan's canonical apply playbook scoped to EXACTLY
// plan.Host (design doc §8: "execute canonical apply with exact host
// scope") via the caller-supplied PlaybookRunner (no --check — the
// caller's own closure distinguishes preview from real execution; see
// BuildReapplyPlan's PreviewRunner for the check-mode counterpart) —
// reusing the SAME collaborator SHAPE, never a generic playbook-runner
// API the caller could point at an arbitrary path (the playbook path
// passed here is ALWAYS plan.Resolved.PlaybookPath, resolved server-side
// at plan time, never caller input).
func ReapplyExecute(ctx context.Context, run PreviewRunner, inventory string, plan ReapplyPlan) ReapplyExecuteResult {
	stdout, exitCode, err := run(ctx, plan.Resolved.PlaybookPath, inventory, plan.Host, plan.Resolved.Stage)
	if err != nil {
		return ReapplyExecuteResult{Result: ReapplyApplyFailedPartial, ExitCode: exitCode, Changed: -1, Stdout: stdout, Error: err.Error()}
	}
	changed := parseRecapChanged(stdout, plan.Host)
	if exitCode != 0 {
		return ReapplyExecuteResult{Result: ReapplyApplyFailedPartial, ExitCode: exitCode, Changed: changed, Stdout: stdout,
			Error: "canonical apply exited non-zero"}
	}
	return ReapplyExecuteResult{Result: "", ExitCode: exitCode, Changed: changed, Stdout: stdout}
}
