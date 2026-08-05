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
	RC          int
	Stdout      string
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
				RC          int    `json:"rc"`
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
			stdout := result.Stdout
			if stdout == "" {
				stdout = result.Msg
			}
			return AdHocResult{
				RC:          result.RC,
				Stdout:      stdout,
				Failed:      result.Failed,
				Unreachable: result.Unreachable,
			}, nil
		}
	}
	return AdHocResult{}, fmt.Errorf("no ansible callback result for host %s", host)
}
