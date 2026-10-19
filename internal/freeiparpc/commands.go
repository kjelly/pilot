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
	return decodePing(raw)
}

// validateCommandResult applies the same success contract to single calls
// and batch items. Ping has a summary instead of an inner result.
func validateCommandResult(method string, raw json.RawMessage) error {
	if method == "ping" {
		_, err := decodePing(raw)
		return err
	}
	return requireField(raw, "result")
}

func decodePing(raw json.RawMessage) (ServerInfo, error) {
	var r struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return ServerInfo{}, fmt.Errorf("freeiparpc: decode ping: %w", ErrIncompleteResponse)
	}
	m := pingSummaryRe.FindStringSubmatch(r.Summary)
	if m == nil {
		return ServerInfo{}, fmt.Errorf("freeiparpc: invalid ping summary: %w", ErrIncompleteResponse)
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
	// count, truncated and result must all be there: a missing truncated
	// flag cannot prove the read complete, and a missing result is not an
	// empty set. A real empty answer has all three (captured:
	// count 0, truncated false, result []).
	var r struct {
		Count     *int              `json:"count"`
		Truncated *bool             `json:"truncated"`
		Result    *[]map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("freeiparpc: decode %s: %w (%w)", method, ErrIncompleteResponse, err)
	}
	if r.Count == nil || r.Truncated == nil || r.Result == nil {
		return nil, fmt.Errorf("freeiparpc: %s answer lacks count, truncated or result: %w", method, ErrIncompleteResponse)
	}
	if *r.Truncated {
		return nil, fmt.Errorf("%s: %w", method, ErrTruncated)
	}
	if *r.Count != len(*r.Result) {
		return nil, fmt.Errorf("freeiparpc: %s reported %d entries but returned %d: %w", method, *r.Count, len(*r.Result), ErrIncompleteResponse)
	}
	for i, e := range *r.Result {
		if e == nil {
			return nil, fmt.Errorf("freeiparpc: %s entry %d is not an object: %w", method, i, ErrIncompleteResponse)
		}
	}
	return *r.Result, nil
}

// BatchItem is one command's outcome in a batch: Result or Err.
type BatchItem struct {
	Result json.RawMessage // the item object: result/value/summary
	Err    *RPCError
}

// Batch sends commands in one request. It is not a transaction: each item
// succeeds or fails on its own, in order. A batch with any write is a write.
func (c *Client) Batch(ctx context.Context, cmds []Command) ([]BatchItem, error) {
	reads, writes := 0, 0
	items := make([]map[string]any, 0, len(cmds))
	for _, cmd := range cmds {
		k, ok := allowlist[cmd.Method]
		if !ok {
			return nil, &ErrMethodNotAllowed{Method: cmd.Method}
		}
		if k == write {
			writes++
		} else {
			reads++
		}
		items = append(items, map[string]any{"method": cmd.Method, "params": cmd.params()})
	}
	body, err := json.Marshal(request{Method: "batch", Params: [2]any{items, map[string]any{"version": apiVersion}}})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, "batch", reads, writes, body)
	if err != nil {
		return nil, err
	}
	out, err := decodeBatch(raw, cmds)
	if err != nil {
		// The batch was sent and answered, but the answer does not say
		// what each write did: some may have been applied.
		if writes > 0 {
			return nil, c.unknown("batch", err)
		}
		return nil, err
	}
	return out, nil
}

// decodeBatch reads a batch answer that must account for each command.
func decodeBatch(raw json.RawMessage, cmds []Command) ([]BatchItem, error) {
	want := len(cmds)
	var r struct {
		Count   *int               `json:"count"`
		Results *[]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("freeiparpc: decode batch: %w (%w)", ErrIncompleteResponse, err)
	}
	if r.Count == nil || r.Results == nil {
		return nil, fmt.Errorf("freeiparpc: batch answer lacks count or results: %w", ErrIncompleteResponse)
	}
	if *r.Count != want || len(*r.Results) != want {
		return nil, fmt.Errorf("freeiparpc: batch of %d answered with count %d and %d results: %w", want, *r.Count, len(*r.Results), ErrIncompleteResponse)
	}
	out := make([]BatchItem, want)
	for i, item := range *r.Results {
		// A failed item carries the message in "error" and the name and
		// code beside it, unlike the top-level error object (captured). A
		// succeeded item has "error": null and a non-null "result".
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || fields == nil {
			return nil, fmt.Errorf("freeiparpc: batch item %d is not an object: %w", i, ErrIncompleteResponse)
		}
		if _, ok := fields["error"]; !ok {
			return nil, fmt.Errorf("freeiparpc: batch item %d lacks error field: %w", i, ErrIncompleteResponse)
		}
		var e struct {
			Error     *string `json:"error"`
			ErrorName string  `json:"error_name"`
			ErrorCode int     `json:"error_code"`
		}
		if err := json.Unmarshal(item, &e); err != nil {
			return nil, fmt.Errorf("freeiparpc: decode batch item %d: %w (%w)", i, ErrIncompleteResponse, err)
		}
		if e.Error != nil {
			if e.ErrorName == "" {
				return nil, fmt.Errorf("freeiparpc: batch item %d failed without an error name: %w", i, ErrIncompleteResponse)
			}
			out[i].Err = &RPCError{Code: e.ErrorCode, Name: e.ErrorName, Message: *e.Error}
			continue
		}
		if err := validateCommandResult(cmds[i].Method, item); err != nil {
			return nil, fmt.Errorf("freeiparpc: batch item %d: %w", i, err)
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
	// FreeIPA always sends completed and failed.member with one list per
	// member type (captured); a missing one cannot account for the members.
	var r struct {
		Completed *int `json:"completed"`
		Failed    *struct {
			Member map[string]*[][]string `json:"member"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return MemberResult{}, fmt.Errorf("freeiparpc: decode member result: %w (%w)", ErrIncompleteResponse, err)
	}
	if r.Completed == nil || r.Failed == nil || r.Failed.Member == nil {
		return MemberResult{}, fmt.Errorf("freeiparpc: member result lacks completed or failed.member: %w", ErrIncompleteResponse)
	}
	res := MemberResult{Completed: *r.Completed}
	types := make([]string, 0, len(r.Failed.Member))
	for t, list := range r.Failed.Member {
		if list == nil {
			return MemberResult{}, fmt.Errorf("freeiparpc: member result failed.member.%s is null: %w", t, ErrIncompleteResponse)
		}
		types = append(types, t)
	}
	slices.Sort(types)
	for _, t := range types {
		for _, f := range *r.Failed.Member[t] {
			if len(f) != 2 {
				return MemberResult{}, fmt.Errorf("freeiparpc: unexpected failed member entry %q", f)
			}
			res.Failed = append(res.Failed, MemberFailure{Type: t, Name: f[0], Reason: f[1]})
		}
	}
	if res.Completed+len(res.Failed) != requested {
		return res, fmt.Errorf("freeiparpc: %d members requested, %d completed and %d failed: %w", requested, res.Completed, len(res.Failed), ErrIncompleteResponse)
	}
	return res, nil
}
