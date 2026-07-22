package cmd

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/kjelly/pilot/internal/ansible"
)

// syntaxCheckAndLint runs `ansible-playbook --syntax-check` over
// ansibleArgs (which must already start with the playbook path, followed
// by whatever -i/-l/extra flags the real run will use) and, unless
// skipLint, `ansible-lint <playbook>`.
//
// lintIssues is non-empty (and non-fatal — the caller decides what to do
// with it) when ansible-lint reported problems. err is non-nil only when
// the syntax check itself failed or could not run.
func syntaxCheckAndLint(ctx context.Context, runner *ansible.Runner, playbook string, ansibleArgs []string, skipSyntax, skipLint bool) (lintIssues string, err error) {
	if !skipSyntax {
		syntaxArgs := append([]string{"--syntax-check"}, ansibleArgs...)
		sres, rerr := runner.Run(ctx, syntaxArgs...)
		if rerr != nil {
			return "", fmt.Errorf("syntax check error: %w", rerr)
		}
		if sres.ExitCode != 0 {
			return "", fmt.Errorf("syntax check failed (exit=%d): %s", sres.ExitCode, trimForErr(sres.Stderr))
		}
	}
	if !skipLint {
		lintPath, lerr := exec.LookPath("ansible-lint")
		if lerr == nil {
			c := exec.CommandContext(ctx, lintPath, playbook)
			out, _ := c.CombinedOutput()
			if len(out) > 0 && c.ProcessState != nil && !c.ProcessState.Success() {
				lintIssues = string(out)
			}
		}
	}
	return lintIssues, nil
}
