package freeiparpc

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

type kind int

const (
	read kind = iota
	write
)

// allowlist holds the commands the users/groups engine needs. Writes are
// marked so a failure after sending is reported as an unknown outcome.
var allowlist = map[string]kind{
	"ping":                read,
	"user_show":           read,
	"user_find":           read,
	"group_show":          read,
	"group_find":          read,
	"user_add":            write,
	"user_mod":            write,
	"user_del":            write,
	"user_enable":         write,
	"user_disable":        write,
	"passwd":              write,
	"group_add":           write,
	"group_mod":           write,
	"group_del":           write,
	"group_add_member":    write,
	"group_remove_member": write,
}

// ServerInfo is what ping reports.
type ServerInfo struct {
	ServerVersion string // e.g. 4.13.4
	APIVersion    string // e.g. 2.257
}

var pingSummaryRe = regexp.MustCompile(`^IPA server version (\S+)\. API version (\S+)$`)

// Ping returns the server and API version.
func (c *Client) Ping(ctx context.Context) (ServerInfo, error) {
	raw, err := c.Call(ctx, Command{Method: "ping"})
	if err != nil {
		return ServerInfo{}, err
	}
	var r struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return ServerInfo{}, fmt.Errorf("freeiparpc: decode ping: %w", err)
	}
	m := pingSummaryRe.FindStringSubmatch(r.Summary)
	if m == nil {
		return ServerInfo{}, fmt.Errorf("freeiparpc: unexpected ping summary %q", r.Summary)
	}
	return ServerInfo{ServerVersion: m[1], APIVersion: m[2]}, nil
}

// CheckServer pings and fails unless the API version is supported. The
// server does not refuse a mismatched client, so run this before any write.
func (c *Client) CheckServer(ctx context.Context) (ServerInfo, error) {
	info, err := c.Ping(ctx)
	if err != nil {
		return info, err
	}
	if !slices.Contains(c.cfg.SupportedAPIVersions, info.APIVersion) {
		return info, fmt.Errorf("freeiparpc: FreeIPA %s has API version %s; supported: %v",
			info.ServerVersion, info.APIVersion, c.cfg.SupportedAPIVersions)
	}
	return info, nil
}

// ErrTruncated is a find whose result FreeIPA cut short.
var ErrTruncated = fmt.Errorf("freeiparpc: the search result was truncated")

// Find runs an allowlisted *_find command with no size or time limit and
// returns its entries; a truncated result is an error, never a partial
// answer.
func (c *Client) Find(ctx context.Context, method string, args []any, opts map[string]any) ([]map[string]any, error) {
	o := map[string]any{"sizelimit": 0, "timelimit": 0}
	for k, v := range opts {
		o[k] = v
	}
	raw, err := c.Call(ctx, Command{Method: method, Args: args, Options: o})
	if err != nil {
		return nil, err
	}
	var r struct {
		Count     int              `json:"count"`
		Truncated bool             `json:"truncated"`
		Result    []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("freeiparpc: decode %s: %w", method, err)
	}
	if r.Truncated {
		return nil, fmt.Errorf("%s: %w", method, ErrTruncated)
	}
	if r.Count != len(r.Result) {
		return nil, fmt.Errorf("freeiparpc: %s reported %d entries but returned %d", method, r.Count, len(r.Result))
	}
	return r.Result, nil
}

// BatchItem is one command's outcome in a batch: Result or Err.
type BatchItem struct {
	Result json.RawMessage // the item object: result/value/summary
	Err    *RPCError
}

// Batch sends commands in one request. It is not a transaction: each item
// succeeds or fails on its own, in order. A batch with any write is a write.
func (c *Client) Batch(ctx context.Context, cmds []Command) ([]BatchItem, error) {
	isWrite := false
	items := make([]map[string]any, 0, len(cmds))
	for _, cmd := range cmds {
		k, ok := allowlist[cmd.Method]
		if !ok {
			return nil, &ErrMethodNotAllowed{Method: cmd.Method}
		}
		isWrite = isWrite || k == write
		items = append(items, map[string]any{"method": cmd.Method, "params": cmd.params()})
	}
	body, err := json.Marshal(request{Method: "batch", Params: [2]any{items, map[string]any{"version": apiVersion}}})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, "batch", isWrite, len(cmds), body)
	if err != nil {
		return nil, err
	}
	var r struct {
		Count   int               `json:"count"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("freeiparpc: decode batch: %w", err)
	}
	if r.Count != len(cmds) || len(r.Results) != len(cmds) {
		return nil, fmt.Errorf("freeiparpc: batch of %d returned %d results", len(cmds), len(r.Results))
	}
	out := make([]BatchItem, len(r.Results))
	for i, item := range r.Results {
		// A failed item carries the message in "error" and the name and
		// code beside it, unlike the top-level error object (captured).
		var e struct {
			Error     *string `json:"error"`
			ErrorName string  `json:"error_name"`
			ErrorCode int     `json:"error_code"`
		}
		if err := json.Unmarshal(item, &e); err != nil {
			return nil, fmt.Errorf("freeiparpc: decode batch item %d: %w", i, err)
		}
		if e.Error != nil {
			out[i].Err = &RPCError{Code: e.ErrorCode, Name: e.ErrorName, Message: *e.Error}
			continue
		}
		out[i].Result = item
	}
	return out, nil
}

// MemberFailure is one member a *_add_member or *_remove_member did not
// change, with FreeIPA's reason ("This entry is already a member", "no such
// entry", "This entry is not a member").
type MemberFailure struct {
	Type   string // user, group, …
	Name   string
	Reason string
}

// MemberResult is the outcome of a membership command, which FreeIPA
// reports as success even when no member changed (captured).
type MemberResult struct {
	Completed int
	Failed    []MemberFailure
}

// DecodeMemberResult reads a group_add_member or group_remove_member
// result and checks that every requested member is accounted for.
func DecodeMemberResult(raw json.RawMessage, requested int) (MemberResult, error) {
	var r struct {
		Completed *int `json:"completed"`
		Failed    struct {
			Member map[string][][]string `json:"member"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return MemberResult{}, fmt.Errorf("freeiparpc: decode member result: %w", err)
	}
	if r.Completed == nil {
		return MemberResult{}, fmt.Errorf("freeiparpc: member result has no completed count")
	}
	res := MemberResult{Completed: *r.Completed}
	types := make([]string, 0, len(r.Failed.Member))
	for t := range r.Failed.Member {
		types = append(types, t)
	}
	slices.Sort(types)
	for _, t := range types {
		for _, f := range r.Failed.Member[t] {
			if len(f) != 2 {
				return MemberResult{}, fmt.Errorf("freeiparpc: unexpected failed member entry %q", f)
			}
			res.Failed = append(res.Failed, MemberFailure{Type: t, Name: f[0], Reason: f[1]})
		}
	}
	if res.Completed+len(res.Failed) != requested {
		return res, fmt.Errorf("freeiparpc: %d members requested, %d completed and %d failed", requested, res.Completed, len(res.Failed))
	}
	return res, nil
}
