package diagnose

import (
	"encoding/json"
	"fmt"
)

// AdHocResult separates a requested command's observations from Ansible's
// execution-layer diagnostics. RC is the command's exit only when RCKnown is
// true; a known nonzero command exit remains informative diagnostic data.
type AdHocResult struct {
	RC     int
	Stdout string
	// Stderr is the module's stderr. Some tools put their verdict there
	// (sssctl user-checks prints "pam_acct_mgmt: <result>" on stderr and
	// exits 0 even on a denial — captured 2026-10-13).
	Stderr string
	// Message is Ansible's module/transport message, never command stdout.
	Message string
	// ModuleStdout and ModuleStderr belong to Ansible's module launcher,
	// not the requested command. Presence in a callback marks module failure.
	ModuleStdout string
	ModuleStderr string
	// ModuleFailed marks Ansible's module-wrapper failure envelope.
	ModuleFailed bool
	// CommandStartFailed marks a launcher error before command execution.
	CommandStartFailed bool
	// LauncherRC is Ansible's execution-layer status: a wrapper exit status
	// or a command-spawn errno. It is never the requested command's exit code.
	LauncherRC int
	// LauncherRCKnown says Ansible supplied an execution-layer status.
	LauncherRCKnown bool
	// RCKnown says RC belongs to the requested command, not its launcher.
	RCKnown     bool
	Failed      bool
	Unreachable bool
	// RunErr is set when the step itself could not be run or its output
	// could not be decoded (ansible missing/timeout/malformed callback
	// JSON) — distinct from a clean nonzero RC, which is a normal result.
	RunErr error
}

// callbackString retains field presence even when a wrapper emits null or an
// empty diagnostic stream. Either still identifies the execution-layer envelope.
type callbackString struct {
	Value   string
	Present bool
}

func (s *callbackString) UnmarshalJSON(data []byte) error {
	s.Present = true
	return json.Unmarshal(data, &s.Value)
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
				ModuleStdout callbackString  `json:"module_stdout"`
				ModuleStderr callbackString  `json:"module_stderr"`
				Command      json.RawMessage `json:"cmd"`
				Start        *string         `json:"start"`
				End          *string         `json:"end"`
				Stdout       string          `json:"stdout"`
				Stderr       string          `json:"stderr"`
				RC           *int            `json:"rc"`
				Failed       bool            `json:"failed"`
				Unreachable  bool            `json:"unreachable"`
				Msg          string          `json:"msg"`
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
			moduleFailed := result.ModuleStdout.Present || result.ModuleStderr.Present
			// run_command's spawn-error result contains cmd and errno but
			// no execution timing. A genuine nonzero command retains timing.
			commandPresent := len(result.Command) != 0 && string(result.Command) != "null"
			commandStartFailed := !moduleFailed && result.Failed && commandPresent && result.Start == nil && result.End == nil
			out := AdHocResult{
				RC:                 rc,
				RCKnown:            result.RC != nil,
				ModuleFailed:       moduleFailed,
				CommandStartFailed: commandStartFailed,
				Stdout:             result.Stdout,
				Message:            result.Msg,
				Stderr:             result.Stderr,
				Failed:             result.Failed,
				Unreachable:        result.Unreachable,
			}
			out.ModuleStdout, out.ModuleStderr = result.ModuleStdout.Value, result.ModuleStderr.Value
			if moduleFailed || commandStartFailed {
				out.LauncherRC, out.LauncherRCKnown = rc, result.RC != nil
				out.RC, out.RCKnown = 0, false
			}
			return out, nil
		}
	}
	return AdHocResult{}, fmt.Errorf("no ansible callback result for host %s", host)
}

// HasCommandResult reports whether RC is usable command evidence. A transport
// failure, absent RC, runner error or failed module with zero RC proves nothing
// about the requested command. A real nonzero command RC remains usable data.
func (r AdHocResult) HasCommandResult() bool {
	return r.RCKnown && r.RunErr == nil && !r.Unreachable && !r.ModuleFailed && !r.CommandStartFailed && (!r.Failed || r.RC != 0)
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
	if r.ModuleFailed {
		return "Ansible module execution failed; requested-command outcome is unknown"
	}
	if r.CommandStartFailed {
		return "Ansible could not start the requested command; its outcome is unknown"
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
