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
