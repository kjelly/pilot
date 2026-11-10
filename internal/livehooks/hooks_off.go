//go:build !identity_live_hooks

package livehooks

import (
	"context"
	"net"
)

// Enabled reports whether this binary has the injection points: it has not.
const Enabled = false

// Pause does nothing in a binary built without the identity_live_hooks tag.
func Pause(context.Context, string) {}

// Arm does nothing in a binary built without the identity_live_hooks tag.
func Arm(string) {}

// WrapConn returns c: there is nothing to wrap in a binary built without the tag.
func WrapConn(c net.Conn) net.Conn { return c }

// RequestContext returns ctx: there is no trace to attach without the tag.
func RequestContext(ctx context.Context) context.Context { return ctx }

// Armed is what the next request is armed for: nothing without the tag.
func Armed() string { return "" }
