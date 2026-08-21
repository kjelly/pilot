// Package freeipa wraps the read-only "has this roster user/group ever
// entered the FreeIPA lifecycle" probes (spec.md §8, §10) that back
// `pilot roster remove-user`/`remove-group`'s historical guard. It never
// mutates FreeIPA — every function here runs a check-only playbook under
// playbooks/check/ and parses its machine-readable JSON result.
//
// probe.go holds the shared plumbing (temp extra-vars/output files,
// ansible-playbook invocation, fail-closed error handling) both
// identity_probe.go (users) and group_history.go (groups) build on.
package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
)

// ErrFreeIPAHistoryUnknown is returned whenever a probe cannot
// authoritatively prove a user/group's FreeIPA history: an Ansible
// failure, a missing/malformed result file, or a self-inconsistent
// result. Callers must treat this exactly like ever_applied=true —
// refuse to hard-remove anything (spec.md §2.5, §12) — never reinterpret
// it as "not found".
var ErrFreeIPAHistoryUnknown = errors.New("freeipa: unable to determine FreeIPA history")

// playbookRunner is the seam ProbeUserHistory/ProbeGroupHistory run
// through — satisfied by *ansible.Runner in production, and by a fake in
// tests that have no real FreeIPA server to talk to.
type playbookRunner interface {
	Run(ctx context.Context, args ...string) (*ansible.Result, error)
}

// ProbeOptions configures a single ever-applied probe invocation.
type ProbeOptions struct {
	// Inventory and RosterFile are required.
	Inventory  string
	RosterFile string

	// VaultPasswordFile is required when RosterFile is ansible-vault
	// encrypted.
	VaultPasswordFile string

	// TargetGroup overrides the probe playbook's default host-targeting
	// group ("freeipa-server" — see spec.md §8.1/§10).
	TargetGroup string

	// Timeout overrides ansible.NewRunner's default when Runner is nil.
	Timeout time.Duration

	// Runner overrides the ansible.Runner used to execute the probe
	// playbook. nil selects a production ansible.NewRunner() — tests
	// inject a fake here instead of talking to a real FreeIPA server.
	Runner playbookRunner
}

func (o ProbeOptions) runner() playbookRunner {
	if o.Runner != nil {
		return o.Runner
	}
	r := ansible.NewRunner()
	if o.Timeout > 0 {
		r.Timeout = o.Timeout
	}
	return r
}

// runEverAppliedProbe runs playbook against name, decoding its
// machine-readable JSON result into out. It never treats an Ansible
// failure, or a missing/malformed result file, as "not found" — every
// such case returns a wrapped ErrFreeIPAHistoryUnknown instead.
func runEverAppliedProbe(ctx context.Context, playbook, kind, name string, opts ProbeOptions, out any) error {
	if opts.Inventory == "" {
		return fmt.Errorf("freeipa: inventory is required")
	}
	if opts.RosterFile == "" {
		return fmt.Errorf("freeipa: roster file is required")
	}
	if name == "" {
		return fmt.Errorf("freeipa: %s name is required", kind)
	}

	outputFile, err := os.CreateTemp("", "pilot-freeipa-probe-*.json")
	if err != nil {
		return fmt.Errorf("freeipa: create probe output file: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer os.Remove(outputPath)

	extraVars := map[string]string{
		"freeipa_roster_file":         opts.RosterFile,
		"pilot_identity_name":         name,
		"pilot_identity_probe_output": outputPath,
	}
	if opts.TargetGroup != "" {
		extraVars["target_group"] = opts.TargetGroup
	}
	// Extra-vars go through a JSON @file, never a bare `-e k=v` command
	// line: a value containing whitespace (a roster path with a space in
	// it, say) silently truncates at the first space under `-e k=v k2=v2`
	// — a real gotcha hit elsewhere in this repo (internal-endpoint Phase
	// 5). A @file sidesteps the whole class of bug.
	extraVarsFile, err := os.CreateTemp("", "pilot-freeipa-probe-vars-*.json")
	if err != nil {
		return fmt.Errorf("freeipa: create probe extra-vars file: %w", err)
	}
	extraVarsPath := extraVarsFile.Name()
	defer os.Remove(extraVarsPath)
	if err := json.NewEncoder(extraVarsFile).Encode(extraVars); err != nil {
		_ = extraVarsFile.Close()
		return fmt.Errorf("freeipa: encode probe extra-vars: %w", err)
	}
	if err := extraVarsFile.Close(); err != nil {
		return fmt.Errorf("freeipa: write probe extra-vars: %w", err)
	}

	args := []string{playbook, "-i", opts.Inventory, "-e", "@" + extraVarsPath}
	if opts.VaultPasswordFile != "" {
		args = append(args, "--vault-password-file", opts.VaultPasswordFile)
	}

	result, err := opts.runner().Run(ctx, args...)
	if err != nil {
		return fmt.Errorf("%w: ansible-playbook did not run: %v", ErrFreeIPAHistoryUnknown, err)
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		return fmt.Errorf("%w: probe playbook %s exited %d: %s", ErrFreeIPAHistoryUnknown, filepath.Base(playbook), result.ExitCode, detail)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return fmt.Errorf("%w: read probe result: %v", ErrFreeIPAHistoryUnknown, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: malformed probe result JSON: %v", ErrFreeIPAHistoryUnknown, err)
	}
	return nil
}
