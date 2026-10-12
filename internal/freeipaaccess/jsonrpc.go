package freeipaaccess

import (
	"encoding/json"
	"errors"
	"fmt"
)

// allowedMethods is the read-only RPC allowlist (spec.md §11.2/§10.3). Any
// method not listed here is rejected locally before a request is ever
// built — never sent to the server and then merely hoped to be denied.
var allowedMethods = map[string]bool{
	"ping":              true,
	"user_show":         true,
	"group_show":        true,
	"host_show":         true,
	"hostgroup_show":    true,
	"hostgroup_find":    true,
	"hbacrule_find":     true,
	"hbacrule_show":     true,
	"hbacsvcgroup_show": true,
	"sudorule_find":     true,
	"sudorule_show":     true,
	"sudocmd_show":      true,
	"sudocmdgroup_show": true,
	"hbactest":          true,
}

// ErrMethodNotAllowed is returned when calling code (a bug, not user input —
// method names are never caller-supplied at runtime) requests an RPC
// method outside allowedMethods.
type ErrMethodNotAllowed struct {
	Method string
}

func (e *ErrMethodNotAllowed) Error() string {
	return fmt.Sprintf("freeipaaccess: method %q is not in the read-only allowlist", e.Method)
}

// rpcRequest is the FreeIPA JSON-RPC request envelope. Params is always
// [positional_args, named_args] — FreeIPA's JSON-RPC calling convention,
// not a generic two-element list.
type rpcRequest struct {
	Method string `json:"method"`
	Params [2]any `json:"params"`
	ID     int    `json:"id"`
}

func newRPCRequest(method string, positional []any, named map[string]any) ([]byte, error) {
	if !allowedMethods[method] {
		return nil, &ErrMethodNotAllowed{Method: method}
	}
	if positional == nil {
		positional = []any{}
	}
	if named == nil {
		named = map[string]any{}
	}
	req := rpcRequest{Method: method, Params: [2]any{positional, named}, ID: 0}
	return json.Marshal(req)
}

// RPCError is a FreeIPA JSON-RPC application-level error (HTTP 200, with a
// populated "error" field) — distinct from a transport-level failure. Per
// spec.md §12, an RPCError is a definitive answer and must never be
// retried against another configured server as if it might resolve
// differently.
type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Name    string         `json:"name"`
	Data    map[string]any `json:"data"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("freeipa %s (code %d): %s", e.Name, e.Code, e.Message)
}

// IsNotFound reports whether err is FreeIPA's NotFound error (the object
// asked for does not exist).
func IsNotFound(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr) && rpcErr.Name == "NotFound"
}

// rpcEnvelope is the outer JSON-RPC response shape common to every method.
type rpcEnvelope struct {
	Result    json.RawMessage `json:"result"`
	Error     *RPCError       `json:"error"`
	ID        int             `json:"id"`
	Principal string          `json:"principal"`
	Version   string          `json:"version"`
}

func decodeEnvelope(body []byte) (rpcEnvelope, error) {
	var env rpcEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return rpcEnvelope{}, fmt.Errorf("decode freeipa json-rpc envelope: %w", err)
	}
	if env.Error != nil {
		return env, env.Error
	}
	return env, nil
}

// showResult is the common "result" shape for a *_show call: a single
// object of resolved (non-raw) LDAP attributes, each either a []any or a
// bare scalar (FreeIPA is inconsistent about this per-attribute — see
// normalize.go's attrStrings/attrBool).
type showResult struct {
	Result map[string]any `json:"result"`
}

// findResult is the common "result" shape for a *_find call: a list of the
// same per-object attribute maps as showResult.
type findResult struct {
	Result    []map[string]any `json:"result"`
	Count     int              `json:"count"`
	Truncated bool             `json:"truncated"`
}

func decodeShow(env rpcEnvelope) (map[string]any, error) {
	var sr showResult
	if err := json.Unmarshal(env.Result, &sr); err != nil {
		return nil, fmt.Errorf("decode freeipa show result: %w", err)
	}
	return sr.Result, nil
}

func decodeFind(env rpcEnvelope) ([]map[string]any, error) {
	var fr findResult
	if err := json.Unmarshal(env.Result, &fr); err != nil {
		return nil, fmt.Errorf("decode freeipa find result: %w", err)
	}
	return fr.Result, nil
}
