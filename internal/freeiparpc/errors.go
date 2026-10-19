package freeiparpc

import (
	"errors"
	"fmt"
)

// RPCError is FreeIPA's answer that a command failed (HTTP 200 with an
// error object, or a failed batch item). The command was handled; Name says
// how, for example NotFound, DuplicateEntry, EmptyModlist, AlreadyActive,
// AlreadyInactive or ACIError.
type RPCError struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("freeipa %s (%d): %s", e.Name, e.Code, e.Message)
}

// IsRPC reports whether err is an *RPCError named name.
func IsRPC(err error, name string) bool {
	var e *RPCError
	return errors.As(err, &e) && e.Name == name
}

// LoginError is a rejected login_password. Reason is FreeIPA's
// X-IPA-Rejection-Reason (invalid-password, password-expired, …).
type LoginError struct {
	User   string
	Status int
	Reason string
}

func (e *LoginError) Error() string {
	return fmt.Sprintf("freeiparpc: login as %s rejected (HTTP %d, reason %q)", e.User, e.Status, e.Reason)
}

// ErrSessionRejected is the server rejecting the session again right after
// a new login.
var ErrSessionRejected = errors.New("the server rejected the session")

// HTTPError is a status other than 200 and 401 from /ipa/session/json.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d", e.Status) }

// TransportError is a failure below HTTP. Sent is false only when the
// request certainly never left: the tunnel could not be opened, or TLS
// rejected the server before anything was sent.
type TransportError struct {
	Err  error
	Sent bool
}

func (e *TransportError) Error() string {
	if !e.Sent {
		return fmt.Sprintf("not sent: %v", e.Err)
	}
	return e.Err.Error()
}

func (e *TransportError) Unwrap() error { return e.Err }

// OutcomeUnknownError is a write that may or may not have been applied: it
// left Pilot, and no answer came back. It is never re-sent automatically;
// read the object to find out.
type OutcomeUnknownError struct {
	Method string
	Err    error
}

func (e *OutcomeUnknownError) Error() string {
	return fmt.Sprintf("freeiparpc: %s: outcome unknown: %v", e.Method, e.Err)
}

func (e *OutcomeUnknownError) Unwrap() error { return e.Err }

// ErrMethodNotAllowed is a command outside the allowlist; nothing is sent.
type ErrMethodNotAllowed struct{ Method string }

func (e *ErrMethodNotAllowed) Error() string {
	return fmt.Sprintf("freeiparpc: command %q is not in the allowlist", e.Method)
}

// notSentError marks a dial failure: the request never left.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

// classifyTransport turns an http.Client error into a *TransportError,
// marking the failures that happen before any byte of the request is sent:
// opening the tunnel and the TLS handshake (see New).
func classifyTransport(err error) error {
	var ns *notSentError
	if errors.As(err, &ns) {
		return &TransportError{Err: ns.err, Sent: false}
	}
	return &TransportError{Err: err, Sent: true}
}
