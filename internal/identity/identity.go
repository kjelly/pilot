// Package identity maps a kernel-verified UID (from peercred) to a
// username, via `getent passwd <uid>` — never Go's os/user package.
//
// Why: pilot-access-gateway builds with CGO_ENABLED=0 (spec.md §54). Go's
// os/user, without cgo, only parses /etc/passwd/​/etc/group directly and
// cannot resolve users served by an NSS module such as SSSD. FreeIPA users
// are exactly that case — verified live against the Phase 0/1/2 vm-target:
// `grep alice /etc/passwd` finds nothing there at all, while
// `getent passwd alice` (and `getent passwd <uid>`) resolve her correctly
// through SSSD. Shelling out to getent is therefore not a workaround, it
// is the only correct option under this binary's own build constraints.
package identity

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// LookupUsername resolves uid to a username via `getent passwd <uid>`
// (fixed argv, no shell — spec.md §11.1's subprocess discipline applies
// here too). Returns an error if the UID has no NSS entry.
func LookupUsername(ctx context.Context, uid uint32) (string, error) {
	cmd := exec.CommandContext(ctx, "getent", "passwd", strconv.FormatUint(uint64(uid), 10))
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("identity: getent passwd %d: %w", uid, err)
	}
	line := strings.TrimSpace(stdout.String())
	fields := strings.SplitN(line, ":", 2)
	if len(fields) == 0 || fields[0] == "" {
		return "", fmt.Errorf("identity: getent passwd %d: empty/unparseable output %q", uid, line)
	}
	return fields[0], nil
}

// LookupGroupGID resolves a group name to its GID via `getent group
// <group>` (fixed argv, no shell). Only the GID is used — never the
// group's member list, which SSSD serves from a separately cached entry
// that can lag real membership by its whole cache lifetime (see
// PeerInGroup).
func LookupGroupGID(ctx context.Context, group string) (uint32, error) {
	cmd := exec.CommandContext(ctx, "getent", "group", group)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("identity: getent group %s: %w", group, err)
	}
	line := strings.TrimSpace(stdout.String())
	fields := strings.SplitN(line, ":", 4)
	if len(fields) < 3 {
		return 0, fmt.Errorf("identity: getent group %s: unparseable output %q", group, line)
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("identity: getent group %s: bad gid in %q: %w", group, line, err)
	}
	return uint32(gid), nil
}

// procRoot is /proc, overridable in tests.
var procRoot = "/proc"

// ProcCreds is the credential part of /proc/<pid>/status: the real,
// effective, saved and filesystem IDs, plus the supplementary groups.
type ProcCreds struct {
	UIDs   []uint32
	GIDs   []uint32
	Groups []uint32
}

// parseProcStatusCreds extracts the Uid:, Gid: and Groups: lines from a
// /proc/<pid>/status body. Uid/Gid must each carry four IDs; Groups may be
// empty.
func parseProcStatusCreds(data []byte) (ProcCreds, error) {
	var c ProcCreds
	var sawUID, sawGID, sawGroups bool
	for _, line := range strings.Split(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		var dst *[]uint32
		switch key {
		case "Uid":
			dst, sawUID = &c.UIDs, true
		case "Gid":
			dst, sawGID = &c.GIDs, true
		case "Groups":
			dst, sawGroups = &c.Groups, true
		default:
			continue
		}
		for _, f := range strings.Fields(rest) {
			v, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return ProcCreds{}, fmt.Errorf("identity: /proc status %s: bad id %q", key, f)
			}
			*dst = append(*dst, uint32(v))
		}
	}
	if !sawUID || !sawGID || !sawGroups || len(c.UIDs) != 4 || len(c.GIDs) != 4 {
		return ProcCreds{}, fmt.Errorf("identity: /proc status: missing or malformed Uid/Gid/Groups lines")
	}
	return c, nil
}

// PeerInGroup reports whether the connected peer process — pid and uid as
// reported by SO_PEERCRED — currently holds group among its kernel
// credentials: its real/effective GID or one of its supplementary groups,
// read from /proc/<pid>/status. This is the same fact the kernel checks for
// a group-owned socket file (systemd SocketGroup=), fixed at login by
// initgroups (which SSSD refreshes online during authentication).
//
// It replaces a check against `getent group`'s member list (2026-09-23,
// captive-transport Phase 0): SSSD caches that list per group
// (entry_cache_timeout, 5400 s by default), so a user added to the group
// kept getting "unauthorized" for up to 90 minutes, and a user removed
// from it kept passing for as long, while `id <user>` was already right.
//
// The /proc entry must still belong to uid, which guards against the pid
// having been reused by another process. A same-named local group
// shadowing the FreeIPA one (nsswitch "files" before "sss") resolves to
// the local GID, which the FreeIPA user does not hold, so that hazard
// still fails closed.
func PeerInGroup(ctx context.Context, pid int32, uid uint32, group string) (bool, error) {
	gid, err := LookupGroupGID(ctx, group)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatInt(int64(pid), 10), "status"))
	if err != nil {
		return false, fmt.Errorf("identity: read credentials of pid %d: %w", pid, err)
	}
	creds, err := parseProcStatusCreds(data)
	if err != nil {
		return false, err
	}
	if creds.UIDs[0] != uid {
		return false, fmt.Errorf("identity: pid %d now runs as uid %d, not peer uid %d", pid, creds.UIDs[0], uid)
	}
	for _, list := range [][]uint32{creds.GIDs[:2], creds.Groups} {
		for _, g := range list {
			if g == gid {
				return true, nil
			}
		}
	}
	return false, nil
}
