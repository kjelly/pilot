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
	"os/exec"
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

// IsMemberOfGroup reports whether username is a member of group, via
// `getent group <group>` (fixed argv, no shell).
//
// This is a defense-in-depth check for the application layer, alongside
// (not instead of) the Unix socket's own SocketGroup= filesystem
// permission (spec.md §29). Live vm-target testing found a real, if
// narrower, hazard motivating it: a host-install step that creates a
// local fallback group with the same name as an FreeIPA-managed one
// permanently shadows the real group for every NSS lookup (nsswitch's
// "files" source is checked before "sss", so the empty local group wins
// silently) — see
// docs/evidence/pilot-access-gateway/2026-09-14-phase7-deployment-integration.md.
// Once that local group is removed, systemd's SocketGroup= DOES resolve
// an SSSD/FreeIPA-backed group correctly and reliably (verified across
// repeated socket restarts) — this is not compensating for a fundamental
// systemd/SSSD timing limitation. It still earns its place as a second
// layer: any future local `groupadd` with a colliding name (a plausible
// operational mistake) would silently reopen the same hole at the
// filesystem-permission layer alone.
func IsMemberOfGroup(ctx context.Context, username, group string) (bool, error) {
	cmd := exec.CommandContext(ctx, "getent", "group", group)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("identity: getent group %s: %w", group, err)
	}
	line := strings.TrimSpace(stdout.String())
	fields := strings.SplitN(line, ":", 4)
	if len(fields) < 4 {
		return false, nil
	}
	for _, member := range strings.Split(fields[3], ",") {
		if member == username {
			return true, nil
		}
	}
	return false, nil
}
