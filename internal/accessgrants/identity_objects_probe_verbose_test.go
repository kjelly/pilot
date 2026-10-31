package accessgrants

import (
	"context"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// verboseRunner runs the real ansible-playbook with -vvv and keeps everything
// it printed, so a test can read what an operator who adds -v sees.
type verboseRunner struct {
	inner  *ansible.Runner
	output strings.Builder
}

func (r *verboseRunner) Run(ctx context.Context, args ...string) (*ansible.Result, error) {
	return r.RunWithExtraEnv(ctx, nil, args...)
}

func (r *verboseRunner) RunWithExtraEnv(ctx context.Context, extraEnv []string, args ...string) (*ansible.Result, error) {
	res, err := r.inner.RunWithExtraEnv(ctx, extraEnv, append(append([]string{}, args...), "-vvv")...)
	if res != nil {
		r.output.WriteString(res.Stdout)
		r.output.WriteString("\n")
		r.output.WriteString(res.Stderr)
	}
	return res, err
}

// taskOutput is the part of ansible's output that belongs to the task named
// name: from its "TASK [name]" banner to the next banner.
func taskOutput(output, name string) (string, bool) {
	start := strings.Index(output, "TASK ["+name+"]")
	if start < 0 {
		return "", false
	}
	rest := output[start+len("TASK ["+name+"]"):]
	if end := strings.Index(rest, "\nTASK ["); end >= 0 {
		rest = rest[:end]
	}
	return rest, true
}

// TestRegression_IdentitySecretDriftProbeResultFactIsHiddenFromVerboseOutput:
// the task that assembles the probe result holds the observed and desired
// users and groups. It is a set_fact, which -v (or a JSON/YAML stdout callback)
// prints in full, so it is no_log. pilot reads the result from the file the next
// task writes, so the report must be unchanged: this runs the real probe under
// -vvv, requires the report to carry the perturbed user's drift, and requires
// the desired display name of that user to appear nowhere in what ansible
// printed. (Control: with no_log removed from the task, the value is in its
// ansible_facts output and this test fails.)
func TestRegression_IdentitySecretDriftProbeResultFactIsHiddenFromVerboseOutput(t *testing.T) {
	const sentinel = "Pr204DisplayNameSentinel-63"
	roster := strings.Replace(objectsRoster(t, capturedKeys(t)[:1]), "  - name: p1-nokeys\n", "  - name: p1-nokeys\n    display_name: "+sentinel+"\n", 1)
	env := newObjectsEnv(t, roster, capturedScenario(t))
	runner := &verboseRunner{inner: ansible.NewRunner()}
	opts := env.opts(t, true)
	opts.Runner = runner

	report, err := DriftOnce(context.Background(), opts)
	if err != nil {
		t.Fatalf("drift failed: %v", err)
	}

	// The result still reaches Go, with the difference the sentinel causes
	// (reported by attribute name; the value never is).
	got := strings.Join(itemKeys(report, true), "\n")
	if !strings.Contains(got, "user_attribute:p1-nokeys:update:managed attribute differs: displayname") {
		t.Fatalf("the drift report lost the users/groups result:\n%s", got)
	}
	if strings.Contains(got, sentinel) {
		t.Errorf("the report carries the attribute value:\n%s", got)
	}

	output := runner.output.String()
	if !strings.Contains(output, "TASK [Read the complete users/groups object model for identity drift]") {
		t.Fatalf("-vvv output is not what this test reads (no observer task banner):\n%.2000s", output)
	}
	section, ok := taskOutput(output, "Build machine-readable drift-probe result")
	if !ok {
		t.Fatalf("the result task did not run under -vvv:\n%.2000s", output)
	}
	if !strings.Contains(section, "the output has been hidden due to the fact that 'no_log: true' was specified for this result") {
		t.Errorf("the result task's output is not censored:\n%s", section)
	}
	if strings.Contains(output, sentinel) {
		t.Errorf("-vvv output carries a desired user attribute:\n%s", output)
	}
}
