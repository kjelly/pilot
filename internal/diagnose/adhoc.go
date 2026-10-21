package diagnose

import (
	"encoding/json"
	"fmt"
)

// AdHocResult is one ad-hoc command's decoded, single-host outcome. RC and
// Stdout are meaningful even when nonzero/Failed — for most checks here a
// nonzero rc (e.g. "systemctl is-active sssd" on a stopped service) is the
// informative signal itself, not a probe failure, so callers should branch
// on RC/Stdout rather than treat Failed as "this step didn't work."
type AdHocResult struct {
	RC     int
	Stdout string
	// Stderr is the module's stderr. Some tools put their verdict there
	// (sssctl user-checks prints "pam_acct_mgmt: <result>" on stderr and
	// exits 0 even on a denial — captured 2026-10-13).
	Stderr string
	// Message is Ansible's module/transport message, never command stdout.
	Message string
	// RCKnown distinguishes a real rc=0 from a module result without rc.
	RCKnown     bool
	Failed      bool
	Unreachable bool
	// RunErr is set when the step itself could not be run or its output
	// could not be decoded (ansible missing/timeout/malformed callback
	// JSON) — distinct from a clean nonzero RC, which is a normal result.
	RunErr error
}

// adHocCallbackDoc is the (partial) shape of the document
// ANSIBLE_STDOUT_CALLBACK=ansible.posix.json writes for a single-task
// ad-hoc run: each targeted host's module result, keyed by inventory
// hostname. Mirrors cmd/pilot/cmd/deploy_facts.go's adHocCallbackDoc —
// duplicated rather than shared for a single other consumer; extract a
// shared internal/ansiblejson package if a third consumer appears.
type adHocCallbackDoc struct {
	Plays []struct {
		Tasks []struct {
			Hosts map[string]struct {
				Stdout      string `json:"stdout"`
				Stderr      string `json:"stderr"`
				RC          *int   `json:"rc"`
				Failed      bool   `json:"failed"`
				Unreachable bool   `json:"unreachable"`
				Msg         string `json:"msg"`
			} `json:"hosts"`
		} `json:"tasks"`
	} `json:"plays"`
}

// DecodeAdHocResult parses one ansible.posix.json callback document and
// extracts host's single-task result. Unlike
// cmd/pilot/cmd/deploy_facts.go's extractAdHocStdout (which collapses
// Failed/nonzero-RC into a returned error, since its one caller only ever
// expects rc=0), this preserves RC/Stdout/Failed/Unreachable as data —
// diagnose checks need to see *which* step failed and how, not just that
// something did.
func DecodeAdHocResult(rawJSON, host string) (AdHocResult, error) {
	var doc adHocCallbackDoc
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return AdHocResult{}, fmt.Errorf("parse ansible callback output for %s: %w", host, err)
	}
	for _, play := range doc.Plays {
		for _, task := range play.Tasks {
			result, ok := task.Hosts[host]
			if !ok {
				continue
			}
			rc := 0
			if result.RC != nil {
				rc = *result.RC
			}
			return AdHocResult{
				RC:          rc,
				RCKnown:     result.RC != nil,
				Stdout:      result.Stdout,
				Message:     result.Msg,
				Stderr:      result.Stderr,
				Failed:      result.Failed,
				Unreachable: result.Unreachable,
			}, nil
		}
	}
	return AdHocResult{}, fmt.Errorf("no ansible callback result for host %s", host)
}

// HasCommandResult reports whether RC is usable command evidence. A transport
// failure, absent RC, runner error or failed module with zero RC proves nothing
// about the requested command. A real nonzero command RC remains usable data.
func (r AdHocResult) HasCommandResult() bool {
	return r.RCKnown && r.RunErr == nil && !r.Unreachable && (!r.Failed || r.RC != 0)
}

// CommandSucceeded requires affirmative, known success rather than a zero value.
func (r AdHocResult) CommandSucceeded() bool {
	return r.HasCommandResult() && r.RC == 0 && !r.Failed
}

// UnavailableReason explains why the command did not produce usable evidence.
func (r AdHocResult) UnavailableReason() string {
	if r.RunErr != nil {
		return r.RunErr.Error()
	}
	if r.Message != "" {
		return r.Message
	}
	if r.Unreachable {
		return "host unreachable"
	}
	if !r.RCKnown {
		return "Ansible result did not include a command return code"
	}
	return "Ansible module reported failure without a usable command result"
}

func unavailableStepReason(results []StepResult, ids ...string) string {
	for _, id := range ids {
		found := false
		for _, r := range results {
			if r.Step.ID != id {
				continue
			}
			found = true
			if !r.Result.HasCommandResult() {
				return fmt.Sprintf("%s: %s", id, r.Result.UnavailableReason())
			}
			break
		}
		if !found {
			return id + ": no result was returned"
		}
	}
	return ""
}
