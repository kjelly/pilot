package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// AnsibleHostStats mirrors one host's entry in the "stats" object emitted
// by ansible-playbook's built-in `json` stdout callback
// (ANSIBLE_STDOUT_CALLBACK=json).
type AnsibleHostStats struct {
	Ok          int `json:"ok"`
	Changed     int `json:"changed"`
	Failures    int `json:"failures"`
	Unreachable int `json:"unreachable"`
	Skipped     int `json:"skipped"`
	Rescued     int `json:"rescued"`
	Ignored     int `json:"ignored"`
}

// ansibleJSONResult is the (partial) shape of the document ansible-playbook
// writes to stdout under the `json` callback. We only care about the
// per-host recap, so everything else in the real document (plays, stats
// per task, custom_stats) is ignored by omission.
type ansibleJSONResult struct {
	Stats map[string]AnsibleHostStats `json:"stats"`
}

// parseAnsibleJSONResult extracts the JSON document emitted by
// ANSIBLE_STDOUT_CALLBACK=json from raw process output. It scans for the
// first '{' because ansible sometimes prints deprecation/config warnings
// to stdout ahead of the JSON body.
func parseAnsibleJSONResult(raw string) (*ansibleJSONResult, error) {
	idx := strings.IndexByte(raw, '{')
	if idx < 0 {
		return nil, fmt.Errorf("no JSON object found in ansible-playbook output")
	}
	var res ansibleJSONResult
	if err := json.Unmarshal([]byte(raw[idx:]), &res); err != nil {
		return nil, fmt.Errorf("parse ansible-playbook json output: %w", err)
	}
	return &res, nil
}

// summarizeAnsibleJSONResult renders a compact, deterministic (hosts
// sorted alphabetically) one-line-per-host recap — meant to replace
// scrollback-parsing of ansible's human PLAY RECAP text with something
// an agent can read precisely.
func summarizeAnsibleJSONResult(res *ansibleJSONResult) string {
	hosts := make([]string, 0, len(res.Stats))
	for h := range res.Stats {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var b strings.Builder
	for _, h := range hosts {
		s := res.Stats[h]
		fmt.Fprintf(&b, "  %s: ok=%d changed=%d failed=%d unreachable=%d skipped=%d\n",
			h, s.Ok, s.Changed, s.Failures, s.Unreachable, s.Skipped)
	}
	return b.String()
}

// execAnsiblePlaybookCaptured runs ansible-playbook with additional
// environment variables (e.g. ANSIBLE_STDOUT_CALLBACK=json) and returns
// its captured stdout alongside the run error. If teeTo is non-nil, the
// same bytes are also streamed there as they arrive (e.g. so a transcript
// file gets written without blocking on the whole run finishing first).
func execAnsiblePlaybookCaptured(ctx context.Context, teeTo io.Writer, extraEnv []string, args ...string) (string, error) {
	var buf bytes.Buffer
	var out io.Writer = &buf
	if teeTo != nil {
		out = io.MultiWriter(&buf, teeTo)
	}
	c := newCmd(ctx, "ansible-playbook", args...)
	c.Stdout = out
	c.Stderr = os.Stderr
	if len(extraEnv) > 0 {
		c.Env = append(os.Environ(), extraEnv...)
	}
	err := c.Run()
	return buf.String(), err
}
