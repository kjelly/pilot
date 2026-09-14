// Package peercred extracts the kernel-verified UID/GID/PID of the process
// on the other end of a Unix domain socket connection (spec.md §10.1).
// This is the ONLY trusted source of caller identity for
// pilot-access-gateway — never $USER, $LOGNAME, or any value the client
// process could set itself.
package peercred

import (
	"fmt"
	"net"
	"syscall"
)

// Peer is the kernel-reported identity of a Unix socket's peer.
type Peer struct {
	PID int32
	UID uint32
	GID uint32
}

// FromConn extracts the peer credential from a *net.UnixConn using
// SO_PEERCRED. It operates on the connection's raw file descriptor via
// SyscallConn — never conn.File(), which would duplicate the fd and
// require separate cleanup.
func FromConn(conn *net.UnixConn) (Peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("peercred: get raw conn: %w", err)
	}
	var ucred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("peercred: control raw conn: %w", err)
	}
	if sockErr != nil {
		return Peer{}, fmt.Errorf("peercred: SO_PEERCRED: %w", sockErr)
	}
	return Peer{PID: ucred.Pid, UID: ucred.Uid, GID: ucred.Gid}, nil
}
