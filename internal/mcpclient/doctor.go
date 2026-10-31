package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Check is one doctor step.
type Check struct {
	ID         string `json:"check_id"`
	Status     string `json:"status"` // pass | fail | skip
	ReasonCode string `json:"reason_code,omitempty"`
	Detail     string `json:"detail,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms"`
}

// Report is doctor's result.
type Report struct {
	Profile           string  `json:"profile"`
	Env               string  `json:"env"`
	Image             string  `json:"image"`
	Mode              string  `json:"mode"`
	CommitSHA         string  `json:"commit_sha,omitempty"`
	ContentDigest     string  `json:"content_digest,omitempty"`
	PilotBinarySHA256 string  `json:"pilot_binary_sha256,omitempty"`
	Checks            []Check `json:"checks"`
}

// OK reports whether every check passed.
func (r *Report) OK() bool {
	for _, c := range r.Checks {
		if c.Status != "pass" {
			return false
		}
	}
	return len(r.Checks) > 0
}

type readCloser struct{ *bufio.Reader }

func (readCloser) Close() error { return nil }

// Doctor runs the layered checks of spec §5.5 without calling any tool.
// Once a step fails, the rest are skipped.
func Doctor(ctx context.Context, o *Options) *Report {
	img, _ := o.image()
	rep := &Report{Profile: o.ProfileName, Env: o.Profile.Target.Env, Image: img, Mode: o.Profile.Mode}
	failed := false
	step := func(id string, fn func() (string, error)) {
		if failed {
			rep.Checks = append(rep.Checks, Check{ID: id, Status: "skip"})
			return
		}
		start := time.Now()
		detail, err := fn()
		c := Check{ID: id, Status: "pass", Detail: detail, ElapsedMS: time.Since(start).Milliseconds()}
		if err != nil {
			failed = true
			c.Status, c.Detail = "fail", err.Error()
			var e *Error
			if errors.As(err, &e) {
				c.ReasonCode = e.Code
				if e.RemoteCode != "" {
					c.ReasonCode += "/" + e.RemoteCode
				}
			}
		}
		rep.Checks = append(rep.Checks, c)
	}

	step("profile", func() (string, error) {
		if _, err := o.image(); err != nil {
			return "", err
		}
		return "valid", o.Profile.Validate()
	})
	var repo *gitRepo
	var commit string
	step("git", func() (string, error) {
		var err error
		if repo, err = openGitCache(ctx, o.CacheDir, o.Profile.Source.URL, o.Profile.gitTimeout()); err != nil {
			return "", &Error{Code: CodeGitFailed, Msg: err.Error()}
		}
		if commit, err = repo.resolve(ctx, o.Profile.Source.Ref); err != nil {
			return "", err
		}
		rep.CommitSHA = commit
		return o.Profile.Source.Ref + " is " + commit, nil
	})
	step("snapshot", func() (string, error) {
		snap, err := buildSnapshot(ctx, repo, o.Profile.Source, commit, o.Profile.Target.Env, o.ClientVersion, o.ClientUser)
		if err != nil {
			return "", err
		}
		rep.ContentDigest = snap.Manifest.ContentDigest
		return fmt.Sprintf("%d files, %d bytes", len(snap.Manifest.Files), len(snap.Framed)), nil
	})
	step("remote-version", func() (string, error) {
		v, err := remoteVersion(ctx, o, img)
		if err != nil {
			return "", err
		}
		rep.PilotBinarySHA256 = v.PilotBinarySHA256
		return "pilot " + v.PilotBinarySHA256[:12] + " speaks " + v.Protocol, nil
	})
	var proc *sshProc
	step("session", func() (string, error) {
		p, ready, _, err := startSession(ctx, o)
		if err != nil {
			return "", err
		}
		proc = p
		return "session " + ready.SessionID, nil
	})
	step("mcp-tools", func() (string, error) {
		defer proc.stop()
		client := mcp.NewClient(&mcp.Implementation{Name: "pilot-mcp-doctor", Version: o.ClientVersion}, nil)
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		session, err := client.Connect(cctx, &mcp.IOTransport{Reader: readCloser{proc.stdout}, Writer: proc.stdin}, nil)
		if err != nil {
			return "", &Error{Code: CodeRemoteRuntime, Msg: "MCP initialize: " + err.Error()}
		}
		defer session.Close() //nolint:errcheck
		result, err := session.ListTools(cctx, nil)
		if err != nil {
			return "", &Error{Code: CodeRemoteRuntime, Msg: "MCP tools/list: " + err.Error()}
		}
		names := map[string]bool{}
		for _, t := range result.Tools {
			names[t.Name] = true
		}
		if err := mcpwire.CheckTools(o.Profile.Mode, names); err != nil {
			return "", &Error{Code: CodeRemoteRejected, Msg: err.Error()}
		}
		return fmt.Sprintf("%d tools, as expected for %s", len(names), o.Profile.Mode), nil
	})
	return rep
}

func remoteVersion(ctx context.Context, o *Options, image string) (mcpwire.Version, error) {
	proc, err := startSSH(o, versionCommand(o.Profile.Target, image), false)
	if err != nil {
		return mcpwire.Version{}, err
	}
	const maxVersionBytes = 64 << 10
	data, _ := proc.readAll(ctx, maxVersionBytes+1)
	if err := ctx.Err(); err != nil {
		proc.kill()
		return mcpwire.Version{}, err
	}
	if len(data) > maxVersionBytes {
		proc.kill() // still writing; waiting would never return
		return mcpwire.Version{}, &Error{Code: CodeRemoteRuntime, Msg: "version output is larger than 64 KiB"}
	}
	out := bytes.NewBuffer(data)
	exit, err := proc.waitCtx(ctx)
	if err != nil {
		return mcpwire.Version{}, err
	}
	if exit != 0 {
		return mcpwire.Version{}, remoteFailure(exit, proc.stderr.String())
	}
	var v mcpwire.Version
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &v); err != nil || v.Protocol != mcpwire.Protocol || len(v.PilotBinarySHA256) < 12 {
		return mcpwire.Version{}, &Error{Code: CodeRemoteRuntime, Msg: "unexpected version output: " + strings.TrimSpace(out.String())}
	}
	return v, nil
}
